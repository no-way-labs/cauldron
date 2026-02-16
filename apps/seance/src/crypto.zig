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
    const salt = "seance-v1-salt!!";
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

test "encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const password = "test-password-123";
    const key = deriveKey(password);
    const plaintext = "Hello, World!";

    var encrypted = try encrypt(allocator, plaintext, key);
    defer encrypted.deinit();

    const decrypted = try decrypt(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}
