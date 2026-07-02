const std = @import("std");
const Io = std.Io;

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

/// Serialize a frame onto a writer interface. Does NOT flush — the caller
/// flushes after (possibly batching several frames). Fuzzable via a fixed
/// writer.
pub fn writeFrame(out: *Io.Writer, frame: Frame) !void {
    try out.writeByte(@intFromEnum(frame.msg_type));
    try out.writeInt(u64, frame.timestamp, .big);

    const sender_len: u8 = @min(@as(u8, @intCast(frame.sender.len)), MAX_NICK_LEN);
    try out.writeByte(sender_len);
    try out.writeAll(frame.sender[0..sender_len]);

    try out.writeInt(u32, @intCast(frame.ciphertext.len), .big);

    try out.writeAll(&frame.nonce);
    try out.writeAll(&frame.tag);
    try out.writeAll(frame.ciphertext);
}

/// Convenience for one-shot sends: write a single frame to a stream with a
/// transient writer and flush. Per-connection read loops keep a persistent
/// reader (see server/client), but writes are stateless so a fresh writer per
/// frame is fine — and safe to call while holding the members mutex.
pub fn sendFrame(io: Io, stream: Io.net.Stream, frame: Frame) !void {
    var write_buf: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);
    try writeFrame(&stream_writer.interface, frame);
    try stream_writer.interface.flush();
}

/// Parse a frame from a reader interface. Callers pass the persistent
/// per-connection reader's `&reader.interface` so buffered bytes survive across
/// frames. Fuzzable via `Io.Reader.fixed`.
pub fn readFrame(allocator: std.mem.Allocator, in: *Io.Reader) !Frame {
    const msg_type = std.enums.fromInt(MessageType, try in.takeByte()) orelse
        return error.InvalidMessageType;

    const timestamp = try in.takeInt(u64, .big);

    const sender_len = try in.takeByte();
    if (sender_len > MAX_NICK_LEN) return error.SenderTooLong;

    const sender = try allocator.alloc(u8, sender_len);
    errdefer allocator.free(sender);
    try in.readSliceAll(sender);

    const payload_len = try in.takeInt(u32, .big);
    if (payload_len > MAX_PAYLOAD_LEN) return error.PayloadTooLarge;

    var nonce: [24]u8 = undefined;
    try in.readSliceAll(&nonce);

    var tag: [16]u8 = undefined;
    try in.readSliceAll(&tag);

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
    // `parsed` counts only fully-initialized entries (a nick is duped and the
    // slot assigned before it is incremented), so on a mid-parse error the
    // errdefer frees exactly those nicks — the truncated slot in progress has
    // no allocation yet — plus the backing array.
    var parsed: usize = 0;
    errdefer {
        for (members[0..parsed]) |m| allocator.free(m.nick);
        allocator.free(members);
    }

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

// --- Fuzz tests for the untrusted-input parsers ---
//
// In 0.16 `std.testing.fuzz` hands the callback a `*std.testing.Smith` value
// generator rather than a raw `[]const u8`. A plain `zig test` replays each
// corpus entry (fed as `Smith.in`) plus one empty input, so these double as
// regression tests; `zig build test --fuzz` drives them with real fuzzer input.
// `smith.slice(&buf)` yields a variable-length byte slice — it first reads a
// little-endian u32 length prefix, so `seed` wraps each raw corpus payload with
// that prefix.

/// Wrap raw parser bytes as a `Smith.slice` seed (LE u32 length prefix + bytes).
fn seed(comptime payload: []const u8) []const u8 {
    const out = comptime blk: {
        var buf: [4 + payload.len]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], @intCast(payload.len), .little);
        @memcpy(buf[4..], payload);
        break :blk buf;
    };
    return &out;
}

fn fuzzDeserializeRoster(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);
    const members = deserializeRoster(std.testing.allocator, buf[0..n]) catch return;
    defer {
        for (members) |m| std.testing.allocator.free(m.nick);
        std.testing.allocator.free(members);
    }
}

test "fuzz deserializeRoster" {
    try std.testing.fuzz({}, fuzzDeserializeRoster, .{
        .corpus = &.{
            seed("\x01\x01a" ++ ("\x00" ** 32)), // valid 1-member roster
            seed("\x01\x01a"), // truncated: nick but no pubkey
            seed("\xff\x01a"), // count 255 >> available data
            // Two members where the second is truncated: the first nick is duped
            // before the parse fails, so this catches the error-path nick leak.
            seed("\x02" ++ "\x01a" ++ ("\x00" ** 32) ++ "\x01b"),
        },
    });
}

fn fuzzReadFrame(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);
    var r = Io.Reader.fixed(buf[0..n]);
    const frame = readFrame(std.testing.allocator, &r) catch return;
    var mutable = frame;
    freeFrame(std.testing.allocator, &mutable);
}

test "fuzz readFrame" {
    // Wire format: type[1] ts[8] sender_len[1] sender[N] payload_len[4 BE]
    // nonce[24] tag[16] ciphertext[payload_len].
    try std.testing.fuzz({}, fuzzReadFrame, .{
        .corpus = &.{
            // Valid join frame, empty payload: sender "a", payload_len 0, then
            // 4-byte length + 24-byte nonce + 16-byte tag = 44 trailing zeros.
            seed("\x01" ++ ("\x00" ** 8) ++ "\x01a" ++ ("\x00" ** 44)),
            seed("\x01\x00"), // truncated before the timestamp
            // sender_len 0, payload_len 0xffffffff -> PayloadTooLarge before alloc.
            seed("\x01" ++ ("\x00" ** 8) ++ "\x00" ++ "\xff\xff\xff\xff"),
        },
    });
}
