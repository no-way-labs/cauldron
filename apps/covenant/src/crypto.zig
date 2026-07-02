const std = @import("std");

pub const EncryptedData = struct {
    nonce: [24]u8,
    ciphertext: []u8,
    tag: [16]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *EncryptedData) void {
        self.allocator.free(self.ciphertext);
    }
};

pub fn deriveKey(io: std.Io, password: []const u8) [32]u8 {
    var key: [32]u8 = undefined;
    const salt = "covenant-v1-salt";
    var salt_bytes: [16]u8 = undefined;
    @memcpy(&salt_bytes, salt);

    std.crypto.pwhash.argon2.kdf(
        std.heap.page_allocator,
        &key,
        password,
        &salt_bytes,
        .{ .t = 3, .m = 65536, .p = 4 },
        .argon2id,
        io,
    ) catch |err| {
        // Fail closed. Argon2id only fails on allocation failure (it needs
        // 64 MiB); never silently downgrade to a weak, unsalted hash that
        // both peers would still accept as a valid key.
        std.debug.print("Fatal: key derivation failed ({}). Free some memory and retry.\n", .{err});
        std.process.exit(1);
    };

    return key;
}

pub fn generatePassword(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    const id_module = @import("id.zig");
    return try id_module.generate(allocator, io);
}

pub fn encrypt(allocator: std.mem.Allocator, io: std.Io, plaintext: []const u8, key: [32]u8) !EncryptedData {
    var nonce: [24]u8 = undefined;
    io.random(&nonce);

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    var tag: [16]u8 = undefined;

    std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(
        ciphertext,
        &tag,
        plaintext,
        "",
        nonce,
        key,
    );

    return EncryptedData{
        .nonce = nonce,
        .ciphertext = ciphertext,
        .tag = tag,
        .allocator = allocator,
    };
}

pub fn decrypt(allocator: std.mem.Allocator, encrypted: EncryptedData, key: [32]u8) ![]u8 {
    const plaintext = try allocator.alloc(u8, encrypted.ciphertext.len);
    errdefer allocator.free(plaintext);

    std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(
        plaintext,
        encrypted.ciphertext,
        encrypted.tag,
        "",
        encrypted.nonce,
        key,
    ) catch {
        return error.DecryptionFailed;
    };

    return plaintext;
}

pub fn decryptRaw(allocator: std.mem.Allocator, nonce: [24]u8, tag: [16]u8, ciphertext: []const u8, key: [32]u8) ![]u8 {
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(
        plaintext,
        ciphertext,
        tag,
        "",
        nonce,
        key,
    ) catch {
        return error.DecryptionFailed;
    };

    return plaintext;
}

// --- Covenant-specific crypto ---

const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const Ed25519 = std.crypto.sign.Ed25519;

pub const KeyPair = Ed25519.KeyPair;

/// Derive a deterministic Ed25519 keypair from a passphrase.
/// Same passphrase always yields the same keypair.
pub fn deriveIdentity(io: std.Io, passphrase: []const u8) KeyPair {
    // Stretch the passphrase with Argon2id before seeding Ed25519, so a weak
    // identity phrase can't be brute-forced offline into someone's signing
    // key. The salt is a fixed domain string (the identity must be
    // deterministic across machines, so it cannot be random). Bumped to v2
    // with this change — identities derived by older builds will not match.
    var seed: [32]u8 = undefined;
    const salt = "covenant-id-v2!!"; // exactly 16 bytes
    std.crypto.pwhash.argon2.kdf(
        std.heap.page_allocator,
        &seed,
        passphrase,
        salt,
        .{ .t = 3, .m = 65536, .p = 4 },
        .argon2id,
        io,
    ) catch |err| {
        std.debug.print("Fatal: identity derivation failed ({}). Free some memory and retry.\n", .{err});
        std.process.exit(1);
    };
    return Ed25519.KeyPair.generateDeterministic(seed) catch {
        // Identity element is astronomically unlikely from the KDF output
        @panic("identity element hit in key derivation");
    };
}

/// Generate an ephemeral Ed25519 keypair for this session.
pub fn generateKeyPair(io: std.Io) KeyPair {
    return Ed25519.KeyPair.generate(io);
}

/// Get public key bytes from a KeyPair
pub fn publicKeyBytes(key_pair: KeyPair) [32]u8 {
    return key_pair.public_key.toBytes();
}

/// Sign data with Ed25519.
pub fn sign(message: []const u8, key_pair: KeyPair) [64]u8 {
    // Signing our own message with a valid key does not fail in practice; if
    // it ever did, fail loudly rather than emit a silent all-zero signature
    // that would later just read as "unsigned".
    const sig = key_pair.sign(message, null) catch @panic("Ed25519 signing failed");
    return sig.toBytes();
}

/// Verify Ed25519 signature
pub fn verify(sig_bytes: [64]u8, message: []const u8, public_key_bytes: [32]u8) bool {
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    const pk = Ed25519.PublicKey.fromBytes(public_key_bytes) catch return false;
    sig.verify(message, pk) catch return false;
    return true;
}

/// Compute roster hash: BLAKE2b(sorted members by pubkey)
pub fn computeRosterHash(members: []const @import("protocol.zig").MemberInfo) [32]u8 {
    var hasher = Blake2b256.init(.{});
    for (members) |m| {
        hasher.update(&m.pubkey);
        hasher.update(&[_]u8{@intCast(m.nick.len)});
        hasher.update(m.nick);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Sign a roster hash with identity key
pub fn signRoster(roster_hash: [32]u8, key_pair: KeyPair) [64]u8 {
    return sign(&roster_hash, key_pair);
}

/// Verify a roster hash signature
pub fn verifyRosterSig(roster_hash: [32]u8, sig: [64]u8, public_key: [32]u8) bool {
    return verify(sig, &roster_hash, public_key);
}

test "encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const password = "test-password-123";
    const key = deriveKey(io, password);
    const plaintext = "Hello, World!";

    var encrypted_data = try encrypt(allocator, io, plaintext, key);
    defer encrypted_data.deinit();

    const decrypted = try decrypt(allocator, encrypted_data, key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "deriveIdentity is deterministic" {
    const io = std.testing.io;
    const kp1 = deriveIdentity(io, "my secret phrase");
    const kp2 = deriveIdentity(io, "my secret phrase");
    try std.testing.expectEqual(publicKeyBytes(kp1), publicKeyBytes(kp2));

    // Different passphrase gives different key
    const kp3 = deriveIdentity(io, "different phrase");
    try std.testing.expect(!std.mem.eql(u8, &publicKeyBytes(kp1), &publicKeyBytes(kp3)));
}

test "Ed25519 sign and verify" {
    const kp = deriveIdentity(std.testing.io, "test");
    const msg = "test message";
    const sig = sign(msg, kp);
    try std.testing.expect(verify(sig, msg, publicKeyBytes(kp)));
    try std.testing.expect(!verify(sig, "wrong", publicKeyBytes(kp)));
}
