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

/// Write a frame to a buffered writer. Does NOT flush; the caller flushes after
/// possibly batching so the whole frame lands in one syscall where possible.
pub fn writeFrame(out: *std.Io.Writer, frame: Frame) !void {
    // Write msg_type
    try out.writeByte(@intFromEnum(frame.msg_type));

    // Write timestamp (u64 big-endian)
    try out.writeInt(u64, frame.timestamp, .big);

    // Write sender_len and sender (clamped to MAX_NICK_LEN)
    const sender_len: u8 = @min(@as(u8, @intCast(frame.sender.len)), MAX_NICK_LEN);
    try out.writeByte(sender_len);
    try out.writeAll(frame.sender[0..sender_len]);

    // Write payload_len (u32 big-endian)
    try out.writeInt(u32, @intCast(frame.ciphertext.len), .big);

    // Write nonce
    try out.writeAll(&frame.nonce);

    // Write tag
    try out.writeAll(&frame.tag);

    // Write ciphertext
    try out.writeAll(frame.ciphertext);
}

/// Convenience: write one frame to a stream with a transient buffered writer and
/// flush it. Keeps the many one-shot send sites DRY; the read side still uses a
/// single persistent reader per connection.
pub fn sendFrame(io: std.Io, stream: std.Io.net.Stream, frame: Frame) !void {
    var write_buf: [8192]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);
    try writeFrame(&stream_writer.interface, frame);
    try stream_writer.interface.flush();
}

/// Read a frame from a persistent, buffered stream reader. Reads error on EOF,
/// so the manual short-read checks of the pre-0.16 socket API are gone.
pub fn readFrame(allocator: std.mem.Allocator, in: *std.Io.Reader) !Frame {
    // Read msg_type
    const type_byte = try in.takeByte();
    const msg_type = std.enums.fromInt(MessageType, type_byte) orelse return error.InvalidMessageType;

    // Read timestamp (u64 big-endian)
    const timestamp = try in.takeInt(u64, .big);

    // Read sender_len
    const sender_len = try in.takeByte();
    if (sender_len > MAX_NICK_LEN) return error.SenderTooLong;

    // Read sender
    const sender = try allocator.alloc(u8, sender_len);
    errdefer allocator.free(sender);
    try in.readSliceAll(sender);

    // Read payload_len (u32 big-endian)
    const payload_len = try in.takeInt(u32, .big);
    if (payload_len > MAX_PAYLOAD_LEN) return error.PayloadTooLarge;

    // Read nonce
    var nonce: [24]u8 = undefined;
    try in.readSliceAll(&nonce);

    // Read tag
    var tag: [16]u8 = undefined;
    try in.readSliceAll(&tag);

    // Read ciphertext
    const ciphertext = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(ciphertext);
    try in.readSliceAll(ciphertext);

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
