const std = @import("std");

pub const MAX_NICK_LEN: u8 = 32;
pub const MAX_PAYLOAD_LEN: u32 = 65536; // 64KB max message
pub const MAGIC: []const u8 = "SEANCE_HELLO";

pub const MessageType = enum(u8) {
    join = 1, // Client -> Server: request to join room
    msg = 2, // Bidirectional: encrypted chat message
    leave = 3, // Client -> Server: graceful disconnect
    announce = 4, // Server -> Client: system announcement (join/leave)
    nick_list = 5, // Server -> Client: participant list (sent on join)
};

pub const Frame = struct {
    msg_type: MessageType,
    timestamp: u64,
    sender: []const u8, // max 32 bytes, plaintext for routing
    nonce: [24]u8,
    tag: [16]u8,
    ciphertext: []const u8,
};

pub fn writeFrame(stream: std.net.Stream, frame: Frame) !void {
    // Write msg_type
    var type_buf: [1]u8 = .{@intFromEnum(frame.msg_type)};
    try stream.writeAll(&type_buf);

    // Write timestamp (u64 big-endian)
    var timestamp_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &timestamp_buf, frame.timestamp, .big);
    try stream.writeAll(&timestamp_buf);

    // Write sender_len and sender (clamped to MAX_NICK_LEN)
    const sender_len: u8 = @min(@as(u8, @intCast(frame.sender.len)), MAX_NICK_LEN);
    var sender_len_buf: [1]u8 = .{sender_len};
    try stream.writeAll(&sender_len_buf);
    try stream.writeAll(frame.sender[0..sender_len]);

    // Write payload_len (u32 big-endian)
    var payload_len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload_len_buf, @intCast(frame.ciphertext.len), .big);
    try stream.writeAll(&payload_len_buf);

    // Write nonce
    try stream.writeAll(&frame.nonce);

    // Write tag
    try stream.writeAll(&frame.tag);

    // Write ciphertext
    try stream.writeAll(frame.ciphertext);
}

pub fn readFrame(allocator: std.mem.Allocator, stream: std.net.Stream) !Frame {
    // Read msg_type
    var type_buf: [1]u8 = undefined;
    const n0 = try stream.readAtLeast(&type_buf, 1);
    if (n0 < 1) return error.UnexpectedEOF;
    const msg_type = std.meta.intToEnum(MessageType, type_buf[0]) catch {
        return error.InvalidMessageType;
    };

    // Read timestamp (u64 big-endian)
    var timestamp_buf: [8]u8 = undefined;
    const n1 = try stream.readAtLeast(&timestamp_buf, 8);
    if (n1 < 8) return error.UnexpectedEOF;
    const timestamp = std.mem.readInt(u64, &timestamp_buf, .big);

    // Read sender_len
    var sender_len_buf: [1]u8 = undefined;
    const n2 = try stream.readAtLeast(&sender_len_buf, 1);
    if (n2 < 1) return error.UnexpectedEOF;
    const sender_len = sender_len_buf[0];
    if (sender_len > MAX_NICK_LEN) return error.SenderTooLong;

    // Read sender
    const sender = try allocator.alloc(u8, sender_len);
    errdefer allocator.free(sender);
    const n3 = try stream.readAtLeast(sender, sender_len);
    if (n3 < sender_len) return error.UnexpectedEOF;

    // Read payload_len (u32 big-endian)
    var payload_len_buf: [4]u8 = undefined;
    const n4 = try stream.readAtLeast(&payload_len_buf, 4);
    if (n4 < 4) return error.UnexpectedEOF;
    const payload_len = std.mem.readInt(u32, &payload_len_buf, .big);
    if (payload_len > MAX_PAYLOAD_LEN) return error.PayloadTooLarge;

    // Read nonce
    var nonce: [24]u8 = undefined;
    const n5 = try stream.readAtLeast(&nonce, 24);
    if (n5 < 24) return error.UnexpectedEOF;

    // Read tag
    var tag: [16]u8 = undefined;
    const n6 = try stream.readAtLeast(&tag, 16);
    if (n6 < 16) return error.UnexpectedEOF;

    // Read ciphertext
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
