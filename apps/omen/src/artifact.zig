const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");

const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const Ed25519 = std.crypto.sign.Ed25519;

fn hexEncode(bytes: []const u8, buf: []u8) []const u8 {
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        buf[i * 2] = charset[b >> 4];
        buf[i * 2 + 1] = charset[b & 0x0f];
    }
    return buf[0 .. bytes.len * 2];
}

/// Build the JSON artifact and sign it with the host's keypair.
/// Returns owned JSON string.
pub fn buildArtifact(
    allocator: std.mem.Allocator,
    session_id: [32]u8,
    question: []const u8,
    options: []const []const u8,
    roster: []const protocol.PeerInfo,
    roster_hash: [32]u8,
    commitments: []const protocol.Commitment,
    reveals: []const protocol.Reveal,
    counts: []const u32,
    host_keypair: crypto.KeyPair,
) ![]u8 {
    var json = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer json.deinit(allocator);

    // We'll build JSON manually to avoid dependency on std.json writer quirks
    try json.appendSlice(allocator, "{");

    // omen_version
    try json.appendSlice(allocator, "\"omen_version\":\"0.1.0\",");

    // session_id
    var sid_hex: [64]u8 = undefined;
    try json.appendSlice(allocator, "\"session_id\":\"");
    try json.appendSlice(allocator, hexEncode(&session_id, &sid_hex));
    try json.appendSlice(allocator, "\",");

    // timestamp
    const ts = @as(u64, @intCast(std.time.timestamp()));
    try appendFmt(allocator, &json, "\"timestamp\":{d},", .{ts});

    // question
    try json.appendSlice(allocator, "\"question\":\"");
    try appendJsonEscaped(allocator, &json, question);
    try json.appendSlice(allocator, "\",");

    // options
    try json.appendSlice(allocator, "\"options\":[");
    for (options, 0..) |opt, i| {
        if (i > 0) try json.append(allocator, ',');
        try json.append(allocator, '"');
        try appendJsonEscaped(allocator, &json, opt);
        try json.append(allocator, '"');
    }
    try json.appendSlice(allocator, "],");

    // voter_count
    try appendFmt(allocator, &json, "\"voter_count\":{d},", .{roster.len});

    // roster_hash
    var rh_hex: [64]u8 = undefined;
    try json.appendSlice(allocator, "\"roster_hash\":\"");
    try json.appendSlice(allocator, hexEncode(&roster_hash, &rh_hex));
    try json.appendSlice(allocator, "\",");

    // commitments
    try json.appendSlice(allocator, "\"commitments\":[");
    for (commitments, 0..) |c, i| {
        if (i > 0) try json.append(allocator, ',');
        var c_hex: [64]u8 = undefined;
        var s_hex: [128]u8 = undefined;
        try appendFmt(allocator, &json, "{{\"slot\":{d},\"commitment\":\"", .{c.slot_id});
        try json.appendSlice(allocator, hexEncode(&c.commitment, &c_hex));
        try json.appendSlice(allocator, "\",\"signature\":\"");
        try json.appendSlice(allocator, hexEncode(&c.signature, &s_hex));
        try json.appendSlice(allocator, "\"}");
    }
    try json.appendSlice(allocator, "],");

    // reveals (shuffled, no slot IDs)
    try json.appendSlice(allocator, "\"reveals\":[");
    for (reveals, 0..) |r, i| {
        if (i > 0) try json.append(allocator, ',');
        var b_hex: [64]u8 = undefined;
        try appendFmt(allocator, &json, "{{\"vote\":{d},\"blinding\":\"", .{r.vote_index});
        try json.appendSlice(allocator, hexEncode(&r.blinding_factor, &b_hex));
        try json.appendSlice(allocator, "\"}");
    }
    try json.appendSlice(allocator, "],");

    // tally
    try json.appendSlice(allocator, "\"tally\":{");
    for (options, 0..) |opt, i| {
        if (i > 0) try json.append(allocator, ',');
        try json.append(allocator, '"');
        try appendJsonEscaped(allocator, &json, opt);
        try appendFmt(allocator, &json, "\":{d}", .{if (i < counts.len) counts[i] else 0});
    }
    try json.appendSlice(allocator, "},");

    // winner
    var max_count: u32 = 0;
    var winner_idx: usize = 0;
    for (counts, 0..) |c, i| {
        if (c > max_count) {
            max_count = c;
            winner_idx = i;
        }
    }
    try json.appendSlice(allocator, "\"winner\":\"");
    if (winner_idx < options.len and max_count > 0) {
        try appendJsonEscaped(allocator, &json, options[winner_idx]);
    }
    try json.appendSlice(allocator, "\",");

    // host_pubkey
    var pk_hex: [64]u8 = undefined;
    try json.appendSlice(allocator, "\"host_pubkey\":\"");
    const pk_bytes = host_keypair.public_key.toBytes();
    try json.appendSlice(allocator, hexEncode(&pk_bytes, &pk_hex));
    try json.appendSlice(allocator, "\",");

    // Compute signature over everything so far
    var content_hash: [32]u8 = undefined;
    Blake2b256.hash(json.items, &content_hash, .{});

    const sig_obj = host_keypair.sign(&content_hash, null) catch {
        try json.appendSlice(allocator, "\"host_signature\":\"\"}\n");
        return try allocator.dupe(u8, json.items);
    };
    const sig = sig_obj.toBytes();
    var sig_hex: [128]u8 = undefined;
    try json.appendSlice(allocator, "\"host_signature\":\"");
    try json.appendSlice(allocator, hexEncode(&sig, &sig_hex));
    try json.appendSlice(allocator, "\"}");

    return try allocator.dupe(u8, json.items);
}

fn appendFmt(allocator: std.mem.Allocator, list: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(s);
    try list.appendSlice(allocator, s);
}

fn appendJsonEscaped(allocator: std.mem.Allocator, list: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    const hex_str = try std.fmt.allocPrint(allocator, "\\u{x:0>4}", .{c});
                    defer allocator.free(hex_str);
                    try list.appendSlice(allocator, hex_str);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
}
