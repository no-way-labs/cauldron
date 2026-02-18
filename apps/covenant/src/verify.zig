const std = @import("std");
const crypto = @import("crypto.zig");
const artifact = @import("artifact.zig");

/// Verify a covenant: check every member's signature against the roster hash.
/// Returns error if any signature is invalid or the roster hash doesn't match.
pub fn verifyCovenant(
    allocator: std.mem.Allocator,
    json: []const u8,
) !VerifyResult {
    // Simple JSON field extraction (no full parser needed)
    const roster_hash_hex = extractField(json, "roster_hash") orelse return error.MissingRosterHash;
    if (roster_hash_hex.len != 64) return error.InvalidRosterHash;

    var roster_hash: [32]u8 = undefined;
    const rh_bytes = try artifact.hexDecode(allocator, roster_hash_hex);
    defer allocator.free(rh_bytes);
    @memcpy(&roster_hash, rh_bytes[0..32]);

    // Extract members array
    var members = std.ArrayList(MemberResult).initCapacity(allocator, 0) catch return error.OutOfMemory;
    defer {
        for (members.items) |m| {
            allocator.free(m.nick);
        }
        members.deinit(allocator);
    }

    // Find members array
    const members_start = std.mem.indexOf(u8, json, "\"members\":[") orelse return error.MissingMembers;
    var pos = members_start + "\"members\":[".len;

    while (pos < json.len) {
        // Skip whitespace and commas
        while (pos < json.len and (json[pos] == ' ' or json[pos] == ',' or json[pos] == '\n' or json[pos] == '\r')) : (pos += 1) {}
        if (pos >= json.len or json[pos] == ']') break;
        if (json[pos] != '{') break;

        // Find end of this member object
        const obj_start = pos;
        var depth: usize = 0;
        while (pos < json.len) : (pos += 1) {
            if (json[pos] == '{') depth += 1;
            if (json[pos] == '}') {
                depth -= 1;
                if (depth == 0) {
                    pos += 1;
                    break;
                }
            }
        }
        const obj = json[obj_start..pos];

        const nick = extractField(obj, "nick") orelse continue;
        const pubkey_hex = extractField(obj, "pubkey") orelse continue;
        const sig_hex = extractField(obj, "signature") orelse continue;

        if (pubkey_hex.len != 64 or sig_hex.len != 128) continue;

        const pk_bytes = artifact.hexDecode(allocator, pubkey_hex) catch continue;
        defer allocator.free(pk_bytes);
        const sig_bytes = artifact.hexDecode(allocator, sig_hex) catch continue;
        defer allocator.free(sig_bytes);

        var pubkey: [32]u8 = undefined;
        @memcpy(&pubkey, pk_bytes[0..32]);
        var sig: [64]u8 = undefined;
        @memcpy(&sig, sig_bytes[0..64]);

        const valid = crypto.verifyRosterSig(roster_hash, sig, pubkey);

        members.append(allocator, .{
            .nick = try allocator.dupe(u8, nick),
            .pubkey = pubkey,
            .valid = valid,
        }) catch continue;
    }

    if (members.items.len == 0) return error.NoMembers;

    // Check all valid
    var all_valid = true;
    for (members.items) |m| {
        if (!m.valid) {
            all_valid = false;
            break;
        }
    }

    // Transfer ownership
    const result_members = try allocator.alloc(MemberResult, members.items.len);
    @memcpy(result_members, members.items);
    // Clear the list without freeing items (ownership transferred)
    members.shrinkRetainingCapacity(0);

    return VerifyResult{
        .valid = all_valid,
        .member_count = result_members.len,
        .members = result_members,
        .roster_hash = roster_hash,
        .group_name = extractField(json, "group_name"),
    };
}

pub const MemberResult = struct {
    nick: []const u8,
    pubkey: [32]u8,
    valid: bool,
};

pub const VerifyResult = struct {
    valid: bool,
    member_count: usize,
    members: []MemberResult,
    roster_hash: [32]u8,
    group_name: ?[]const u8,
};

pub fn freeVerifyResult(allocator: std.mem.Allocator, result: *VerifyResult) void {
    for (result.members) |m| {
        allocator.free(m.nick);
    }
    allocator.free(result.members);
}

/// Extract a JSON string field value (simple, no nesting support needed)
fn extractField(json: []const u8, field: []const u8) ?[]const u8 {
    // Look for "field":"value"
    var search_buf: [128]u8 = undefined;
    if (field.len + 4 > search_buf.len) return null;
    @memcpy(search_buf[0..1], "\"");
    @memcpy(search_buf[1..][0..field.len], field);
    @memcpy(search_buf[1 + field.len ..][0..3], "\":\"");
    const needle = search_buf[0 .. field.len + 4];

    const start = (std.mem.indexOf(u8, json, needle) orelse return null) + needle.len;
    // Find closing quote (handle escaped quotes)
    var end = start;
    while (end < json.len) : (end += 1) {
        if (json[end] == '"' and (end == start or json[end - 1] != '\\')) break;
    }
    if (end >= json.len) return null;
    return json[start..end];
}
