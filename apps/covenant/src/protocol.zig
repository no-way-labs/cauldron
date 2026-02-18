const std = @import("std");

pub const MAX_NICK_LEN: u8 = 32;
pub const MAX_PAYLOAD_LEN: u32 = 65536;
pub const MAGIC: []const u8 = "COVENANT_HELLO";

pub const MessageType = enum(u8) {
    join = 1, // Client -> Host: join request (MAGIC in ciphertext)
    leave = 3, // Client -> Host: graceful disconnect
    pubkey = 10, // Client -> Host: identity Ed25519 public key [32 bytes]
    roster = 11, // Host -> All: finalized roster for signing
    phase = 12, // Host -> All: phase transition
    signature = 13, // Client -> Host: roster_hash signature [64 bytes]
    covenant = 14, // Host -> All: complete signed covenant (JSON)
    abort = 19, // Any -> All: protocol violation
};

pub const Phase = enum(u8) {
    lobby = 0,
    seal = 1,
    done = 2,
};

pub const MemberInfo = struct {
    nick: []const u8,
    pubkey: [32]u8,
};

pub const Frame = struct {
    msg_type: MessageType,
    timestamp: u64,
    sender: []const u8,
    nonce: [24]u8,
    tag: [16]u8,
    ciphertext: []const u8,
};

pub fn writeFrame(stream: std.net.Stream, frame: Frame) !void {
    var type_buf: [1]u8 = .{@intFromEnum(frame.msg_type)};
    try stream.writeAll(&type_buf);

    var timestamp_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &timestamp_buf, frame.timestamp, .big);
    try stream.writeAll(&timestamp_buf);

    const sender_len: u8 = @min(@as(u8, @intCast(frame.sender.len)), MAX_NICK_LEN);
    var sender_len_buf: [1]u8 = .{sender_len};
    try stream.writeAll(&sender_len_buf);
    try stream.writeAll(frame.sender[0..sender_len]);

    var payload_len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload_len_buf, @intCast(frame.ciphertext.len), .big);
    try stream.writeAll(&payload_len_buf);

    try stream.writeAll(&frame.nonce);
    try stream.writeAll(&frame.tag);
    try stream.writeAll(frame.ciphertext);
}

pub fn readFrame(allocator: std.mem.Allocator, stream: std.net.Stream) !Frame {
    var type_buf: [1]u8 = undefined;
    const n0 = try stream.readAtLeast(&type_buf, 1);
    if (n0 < 1) return error.UnexpectedEOF;
    const msg_type = std.meta.intToEnum(MessageType, type_buf[0]) catch {
        return error.InvalidMessageType;
    };

    var timestamp_buf: [8]u8 = undefined;
    const n1 = try stream.readAtLeast(&timestamp_buf, 8);
    if (n1 < 8) return error.UnexpectedEOF;
    const timestamp = std.mem.readInt(u64, &timestamp_buf, .big);

    var sender_len_buf: [1]u8 = undefined;
    const n2 = try stream.readAtLeast(&sender_len_buf, 1);
    if (n2 < 1) return error.UnexpectedEOF;
    const sender_len = sender_len_buf[0];
    if (sender_len > MAX_NICK_LEN) return error.SenderTooLong;

    const sender = try allocator.alloc(u8, sender_len);
    errdefer allocator.free(sender);
    const n3 = try stream.readAtLeast(sender, sender_len);
    if (n3 < sender_len) return error.UnexpectedEOF;

    var payload_len_buf: [4]u8 = undefined;
    const n4 = try stream.readAtLeast(&payload_len_buf, 4);
    if (n4 < 4) return error.UnexpectedEOF;
    const payload_len = std.mem.readInt(u32, &payload_len_buf, .big);
    if (payload_len > MAX_PAYLOAD_LEN) return error.PayloadTooLarge;

    var nonce: [24]u8 = undefined;
    const n5 = try stream.readAtLeast(&nonce, 24);
    if (n5 < 24) return error.UnexpectedEOF;

    var tag: [16]u8 = undefined;
    const n6 = try stream.readAtLeast(&tag, 16);
    if (n6 < 16) return error.UnexpectedEOF;

    const ciphertext = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(ciphertext);
    const n7 = try stream.readAtLeast(ciphertext, payload_len);
    if (n7 < payload_len) return error.UnexpectedEOF;

    return Frame{
        .msg_type = msg_type,
        .timestamp = timestamp,
        .sender = sender,
        .nonce = nonce,
        .tag = tag,
        .ciphertext = ciphertext,
    };
}

pub fn freeFrame(allocator: std.mem.Allocator, frame: *Frame) void {
    allocator.free(frame.sender);
    allocator.free(frame.ciphertext);
}

// --- Payload serialization helpers ---

/// Serialize roster: count [1] + (nick_len [1] + nick [N] + pubkey [32]) per member
pub fn serializeRoster(allocator: std.mem.Allocator, members: []const MemberInfo) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer buf.deinit(allocator);

    try buf.append(allocator, @intCast(members.len));
    for (members) |m| {
        try buf.append(allocator, @intCast(m.nick.len));
        try buf.appendSlice(allocator, m.nick);
        try buf.appendSlice(allocator, &m.pubkey);
    }

    return try buf.toOwnedSlice(allocator);
}

/// Deserialize roster
pub fn deserializeRoster(allocator: std.mem.Allocator, data: []const u8) ![]MemberInfo {
    if (data.len < 1) return error.InvalidPayload;
    const count = data[0];
    var pos: usize = 1;

    var members = try allocator.alloc(MemberInfo, count);
    errdefer allocator.free(members);
    var parsed: usize = 0;

    while (parsed < count) : (parsed += 1) {
        if (pos + 1 > data.len) return error.InvalidPayload;
        const nick_len = data[pos];
        pos += 1;
        if (pos + nick_len + 32 > data.len) return error.InvalidPayload;
        const nick = try allocator.dupe(u8, data[pos..][0..nick_len]);
        pos += nick_len;
        var pubkey: [32]u8 = undefined;
        @memcpy(&pubkey, data[pos..][0..32]);
        pos += 32;
        members[parsed] = .{ .nick = nick, .pubkey = pubkey };
    }

    return members;
}

/// Serialize phase transition: phase_id [1]
pub fn serializePhase(phase: Phase) [1]u8 {
    return .{@intFromEnum(phase)};
}
