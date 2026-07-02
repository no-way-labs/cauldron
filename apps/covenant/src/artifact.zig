const std = @import("std");
const protocol = @import("protocol.zig");

fn hexEncode(bytes: []const u8, buf: []u8) []const u8 {
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        buf[i * 2] = charset[b >> 4];
        buf[i * 2 + 1] = charset[b & 0x0f];
    }
    return buf[0 .. bytes.len * 2];
}

pub const SignedMember = struct {
    nick: []const u8,
    pubkey: [32]u8,
    signature: [64]u8,
};

/// Build the JSON covenant artifact.
pub fn buildCovenant(
    allocator: std.mem.Allocator,
    io: std.Io,
    group_name: []const u8,
    session_id: [32]u8,
    roster_hash: [32]u8,
    members: []const SignedMember,
) ![]u8 {
    var json = try std.ArrayList(u8).initCapacity(allocator, 0);
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "{");

    // covenant_version
    try json.appendSlice(allocator, "\"covenant_version\":\"0.1.0\",");

    // group_name
    try json.appendSlice(allocator, "\"group_name\":\"");
    try appendJsonEscaped(allocator, &json, group_name);
    try json.appendSlice(allocator, "\",");

    // created_at
    const ts = @as(u64, @intCast(std.Io.Clock.real.now(io).toSeconds()));
    try appendFmt(allocator, &json, "\"created_at\":{d},", .{ts});

    // session_id
    var sid_hex: [64]u8 = undefined;
    try json.appendSlice(allocator, "\"session_id\":\"");
    try json.appendSlice(allocator, hexEncode(&session_id, &sid_hex));
    try json.appendSlice(allocator, "\",");

    // roster_hash
    var rh_hex: [64]u8 = undefined;
    try json.appendSlice(allocator, "\"roster_hash\":\"");
    try json.appendSlice(allocator, hexEncode(&roster_hash, &rh_hex));
    try json.appendSlice(allocator, "\",");

    // members
    try json.appendSlice(allocator, "\"members\":[");
    for (members, 0..) |m, i| {
        if (i > 0) try json.append(allocator, ',');
        var pk_hex: [64]u8 = undefined;
        var sig_hex: [128]u8 = undefined;
        try json.appendSlice(allocator, "{\"nick\":\"");
        try appendJsonEscaped(allocator, &json, m.nick);
        try json.appendSlice(allocator, "\",\"pubkey\":\"");
        try json.appendSlice(allocator, hexEncode(&m.pubkey, &pk_hex));
        try json.appendSlice(allocator, "\",\"signature\":\"");
        try json.appendSlice(allocator, hexEncode(&m.signature, &sig_hex));
        try json.appendSlice(allocator, "\"}");
    }
    try json.appendSlice(allocator, "],");

    // member_count
    try appendFmt(allocator, &json, "\"member_count\":{d}", .{members.len});

    try json.append(allocator, '}');

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

/// Parse a hex string into bytes. Returns error if invalid.
pub fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        out[i] = @as(u8, try hexDigit(hex[i * 2])) << 4 | @as(u8, try hexDigit(hex[i * 2 + 1]));
    }
    return out;
}

fn hexDigit(c: u8) !u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => error.InvalidHexChar,
    };
}
