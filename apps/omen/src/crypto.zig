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

pub fn deriveKey(password: []const u8) [32]u8 {
    var key: [32]u8 = undefined;
    const salt = "omen-v1-salt---!";
    var salt_bytes: [16]u8 = undefined;
    @memcpy(&salt_bytes, salt);

    std.crypto.pwhash.argon2.kdf(
        std.heap.page_allocator,
        &key,
        password,
        &salt_bytes,
        .{ .t = 3, .m = 65536, .p = 4 },
        .argon2id,
    ) catch |err| {
        std.debug.print("Warning: Argon2 KDF failed: {}, using SHA-256 fallback\n", .{err});
        std.crypto.hash.sha2.Sha256.hash(password, &key, .{});
    };

    return key;
}

pub fn generatePassword(allocator: std.mem.Allocator) ![]const u8 {
    const id_module = @import("id.zig");
    return try id_module.generate(allocator);
}

pub fn encrypt(allocator: std.mem.Allocator, plaintext: []const u8, key: [32]u8) !EncryptedData {
    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);

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

// --- Omen-specific crypto ---

const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const Ed25519 = std.crypto.sign.Ed25519;

pub const KeyPair = Ed25519.KeyPair;

/// Generate an ephemeral Ed25519 keypair for this session.
pub fn generateKeyPair() KeyPair {
    return Ed25519.KeyPair.generate();
}

/// Compute BLAKE2b commitment: H(vote_index || blinding_factor)
pub fn makeCommitment(vote_index: u8, blinding_factor: [32]u8) [32]u8 {
    var hasher = Blake2b256.init(.{});
    hasher.update(&[_]u8{vote_index});
    hasher.update(&blinding_factor);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Compute roster hash: BLAKE2b(sorted(slot_id || nick_len || nick || pubkey) for each peer)
pub fn computeRosterHash(peers: []const @import("protocol.zig").PeerInfo) [32]u8 {
    var hasher = Blake2b256.init(.{});
    for (peers) |peer| {
        hasher.update(&[_]u8{peer.slot_id});
        hasher.update(&[_]u8{@intCast(peer.nick.len)});
        hasher.update(peer.nick);
        hasher.update(&peer.pubkey);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Compute commit set hash: BLAKE2b(sorted commitments)
pub fn computeCommitSetHash(commitments: []const @import("protocol.zig").Commitment) [32]u8 {
    var hasher = Blake2b256.init(.{});
    for (commitments) |c| {
        hasher.update(&[_]u8{c.slot_id});
        hasher.update(&c.commitment);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Sign data with Ed25519. Returns signature as [64]u8.
pub fn sign(message: []const u8, key_pair: KeyPair) [64]u8 {
    const sig = key_pair.sign(message, null) catch return [_]u8{0} ** 64;
    return sig.toBytes();
}

/// Verify Ed25519 signature
pub fn verify(sig_bytes: [64]u8, message: []const u8, public_key_bytes: [32]u8) bool {
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    const pk = Ed25519.PublicKey.fromBytes(public_key_bytes) catch return false;
    sig.verify(message, pk) catch return false;
    return true;
}

/// Sign a commitment: Ed25519.sign(roster_hash || commitment)
pub fn signCommitment(roster_hash: [32]u8, commitment_val: [32]u8, key_pair: KeyPair) [64]u8 {
    var msg: [64]u8 = undefined;
    @memcpy(msg[0..32], &roster_hash);
    @memcpy(msg[32..64], &commitment_val);
    return sign(&msg, key_pair);
}

/// Verify a commitment signature
pub fn verifyCommitmentSig(roster_hash: [32]u8, commitment_val: [32]u8, sig: [64]u8, public_key: [32]u8) bool {
    var msg: [64]u8 = undefined;
    @memcpy(msg[0..32], &roster_hash);
    @memcpy(msg[32..64], &commitment_val);
    return verify(sig, &msg, public_key);
}

/// Get public key bytes from a KeyPair
pub fn publicKeyBytes(key_pair: KeyPair) [32]u8 {
    return key_pair.public_key.toBytes();
}

test "encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const password = "test-password-123";
    const key = deriveKey(password);
    const plaintext = "Hello, World!";

    var encrypted_data = try encrypt(allocator, plaintext, key);
    defer encrypted_data.deinit();

    const decrypted = try decrypt(allocator, encrypted_data, key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "commitment scheme" {
    const vote_index: u8 = 2;
    var blinding: [32]u8 = undefined;
    std.crypto.random.bytes(&blinding);

    const commitment_val = makeCommitment(vote_index, blinding);

    // Same inputs produce same commitment
    const commitment2 = makeCommitment(vote_index, blinding);
    try std.testing.expectEqual(commitment_val, commitment2);

    // Different inputs produce different commitment
    const commitment3 = makeCommitment(1, blinding);
    try std.testing.expect(!std.mem.eql(u8, &commitment_val, &commitment3));
}

test "Ed25519 sign and verify" {
    const kp = generateKeyPair();
    const msg = "test message";
    const sig = sign(msg, kp);
    try std.testing.expect(verify(sig, msg, publicKeyBytes(kp)));

    // Wrong message fails
    try std.testing.expect(!verify(sig, "wrong", publicKeyBytes(kp)));
}
