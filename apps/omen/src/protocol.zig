const std = @import("std");

pub const MAX_NICK_LEN: u8 = 32;
pub const MAX_PAYLOAD_LEN: u32 = 65536; // 64KB max
pub const MAGIC: []const u8 = "OMEN_HELLO";

pub const MessageType = enum(u8) {
    join = 1, // Client -> Host: join request (MAGIC in ciphertext)
    leave = 3, // Client -> Host: graceful disconnect
    pubkey = 10, // Client -> Host: Ed25519 public key [32 bytes]
    ballot = 11, // Host -> All: question + options
    peer_list = 12, // Host -> All: [(slot_id, nick, pubkey), ...]
    phase = 13, // Host -> All: phase transition + roster_hash
    commitment = 14, // Client -> Host: commitment [32] + signature [64]
    commit_set = 15, // Host -> All: all signed commitments
    reveal = 16, // Client -> Host (NOT relayed): vote_index + blinding_factor
    reveal_set = 17, // Host -> All: shuffled [(vote_index, blinding_factor), ...]
    tally = 18, // Host -> All: JSON artifact
    abort = 19, // Any -> All: protocol violation
};

pub const Phase = enum(u8) {
    lobby = 0,
    commit = 1,
    reveal = 2,
    tally = 3,
    done = 4,
};

pub const Frame = struct {
    msg_type: MessageType,
    timestamp: u64,
    sender: []const u8, // max 32 bytes, plaintext for routing
    nonce: [24]u8,
    tag: [16]u8,
    ciphertext: []const u8,
};

/// Write a frame to a buffered writer. Does NOT flush — the caller flushes
/// after (possibly batching). Kept interface-based so it is directly fuzzable
/// via `std.Io.Writer.fixed`; `sendFrame` wraps it for stream senders.
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

/// Send a single frame over a stream: transient buffered writer + flush. Safe
/// to call under a mutex; the small buffer drains as needed for large frames.
pub fn sendFrame(io: std.Io, stream: std.Io.net.Stream, frame: Frame) !void {
    var write_buf: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);
    try writeFrame(&stream_writer.interface, frame);
    try stream_writer.interface.flush();
}

/// Read a frame from a persistent per-connection reader. The reader buffers
/// ahead, so callers must create ONE reader per connection and reuse it.
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

// --- Payload serialization helpers ---

pub const Commitment = struct {
    slot_id: u8,
    commitment: [32]u8,
    signature: [64]u8,
};

pub const Reveal = struct {
    vote_index: u8,
    blinding_factor: [32]u8,
};

pub const PeerInfo = struct {
    slot_id: u8,
    nick: []const u8,
    pubkey: [32]u8,
};

/// Serialize ballot payload: question + options
pub fn serializeBallot(allocator: std.mem.Allocator, session_id: [32]u8, question: []const u8, options: []const []const u8) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer buf.deinit(allocator);

    // session_id [32]
    try buf.appendSlice(allocator, &session_id);

    // question_len [2 BE] + question
    var qlen_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &qlen_buf, @intCast(question.len), .big);
    try buf.appendSlice(allocator, &qlen_buf);
    try buf.appendSlice(allocator, question);

    // option_count [1]
    try buf.append(allocator, @intCast(options.len));

    // each option: len [2 BE] + data
    for (options) |opt| {
        var olen_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &olen_buf, @intCast(opt.len), .big);
        try buf.appendSlice(allocator, &olen_buf);
        try buf.appendSlice(allocator, opt);
    }

    return try buf.toOwnedSlice(allocator);
}

/// Deserialize ballot payload
pub fn deserializeBallot(allocator: std.mem.Allocator, data: []const u8) !struct { session_id: [32]u8, question: []const u8, options: []const []const u8 } {
    if (data.len < 35) return error.InvalidPayload; // 32 + 2 + 1 minimum

    var session_id: [32]u8 = undefined;
    @memcpy(&session_id, data[0..32]);
    var pos: usize = 32;

    const qlen = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;
    if (pos + qlen > data.len) return error.InvalidPayload;
    const question = try allocator.dupe(u8, data[pos..][0..qlen]);
    errdefer allocator.free(question);
    pos += qlen;

    if (pos >= data.len) return error.InvalidPayload;
    const option_count = data[pos];
    pos += 1;

    var options = try allocator.alloc([]const u8, option_count);
    var parsed: usize = 0;
    // Only options[0..parsed] have been duped; the rest are undefined, so a
    // mid-parse error must free only what was actually allocated.
    errdefer {
        for (options[0..parsed]) |opt| allocator.free(opt);
        allocator.free(options);
    }

    while (parsed < option_count) : (parsed += 1) {
        if (pos + 2 > data.len) return error.InvalidPayload;
        const olen = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        if (pos + olen > data.len) return error.InvalidPayload;
        options[parsed] = try allocator.dupe(u8, data[pos..][0..olen]);
        pos += olen;
    }

    return .{ .session_id = session_id, .question = question, .options = options };
}

/// Serialize peer list
pub fn serializePeerList(allocator: std.mem.Allocator, peers: []const PeerInfo) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer buf.deinit(allocator);

    try buf.append(allocator, @intCast(peers.len));
    for (peers) |peer| {
        try buf.append(allocator, peer.slot_id);
        try buf.append(allocator, @intCast(peer.nick.len));
        try buf.appendSlice(allocator, peer.nick);
        try buf.appendSlice(allocator, &peer.pubkey);
    }

    return try buf.toOwnedSlice(allocator);
}

/// Deserialize peer list
pub fn deserializePeerList(allocator: std.mem.Allocator, data: []const u8) ![]PeerInfo {
    if (data.len < 1) return error.InvalidPayload;
    const count = data[0];
    var pos: usize = 1;

    var peers = try allocator.alloc(PeerInfo, count);
    var parsed: usize = 0;
    // Each parsed peer owns a duped nick; free those too on a mid-parse error,
    // not just the array, or they leak.
    errdefer {
        for (peers[0..parsed]) |peer| allocator.free(peer.nick);
        allocator.free(peers);
    }

    while (parsed < count) : (parsed += 1) {
        if (pos + 2 > data.len) return error.InvalidPayload;
        const slot_id = data[pos];
        pos += 1;
        const nick_len = data[pos];
        pos += 1;
        if (pos + nick_len + 32 > data.len) return error.InvalidPayload;
        const nick = try allocator.dupe(u8, data[pos..][0..nick_len]);
        pos += nick_len;
        var pubkey: [32]u8 = undefined;
        @memcpy(&pubkey, data[pos..][0..32]);
        pos += 32;
        peers[parsed] = .{ .slot_id = slot_id, .nick = nick, .pubkey = pubkey };
    }

    return peers;
}

/// Serialize phase transition: phase_id [1] + roster_hash [32]
pub fn serializePhase(phase: Phase, roster_hash: [32]u8) [33]u8 {
    var buf: [33]u8 = undefined;
    buf[0] = @intFromEnum(phase);
    @memcpy(buf[1..33], &roster_hash);
    return buf;
}

/// Serialize commitment set
pub fn serializeCommitSet(allocator: std.mem.Allocator, commitments: []const Commitment, set_hash: [32]u8) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer buf.deinit(allocator);

    try buf.append(allocator, @intCast(commitments.len));
    for (commitments) |c| {
        try buf.append(allocator, c.slot_id);
        try buf.appendSlice(allocator, &c.commitment);
        try buf.appendSlice(allocator, &c.signature);
    }
    try buf.appendSlice(allocator, &set_hash);

    return try buf.toOwnedSlice(allocator);
}

/// Deserialize commitment set
pub fn deserializeCommitSet(allocator: std.mem.Allocator, data: []const u8) !struct { commitments: []Commitment, set_hash: [32]u8 } {
    if (data.len < 1) return error.InvalidPayload;
    const count = data[0];
    var pos: usize = 1;

    var commitments = try allocator.alloc(Commitment, count);
    errdefer allocator.free(commitments);
    var parsed: usize = 0;

    while (parsed < count) : (parsed += 1) {
        if (pos + 1 + 32 + 64 > data.len) return error.InvalidPayload;
        const slot_id = data[pos];
        pos += 1;
        var commitment_val: [32]u8 = undefined;
        @memcpy(&commitment_val, data[pos..][0..32]);
        pos += 32;
        var sig: [64]u8 = undefined;
        @memcpy(&sig, data[pos..][0..64]);
        pos += 64;
        commitments[parsed] = .{ .slot_id = slot_id, .commitment = commitment_val, .signature = sig };
    }

    if (pos + 32 > data.len) return error.InvalidPayload;
    var set_hash: [32]u8 = undefined;
    @memcpy(&set_hash, data[pos..][0..32]);

    return .{ .commitments = commitments, .set_hash = set_hash };
}

/// Serialize reveal set (shuffled, no slot IDs)
pub fn serializeRevealSet(allocator: std.mem.Allocator, reveals: []const Reveal) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer buf.deinit(allocator);

    try buf.append(allocator, @intCast(reveals.len));
    for (reveals) |r| {
        try buf.append(allocator, r.vote_index);
        try buf.appendSlice(allocator, &r.blinding_factor);
    }

    return try buf.toOwnedSlice(allocator);
}

/// Deserialize reveal set
pub fn deserializeRevealSet(allocator: std.mem.Allocator, data: []const u8) ![]Reveal {
    if (data.len < 1) return error.InvalidPayload;
    const count = data[0];
    var pos: usize = 1;

    var reveals = try allocator.alloc(Reveal, count);
    errdefer allocator.free(reveals);
    var parsed: usize = 0;

    while (parsed < count) : (parsed += 1) {
        if (pos + 1 + 32 > data.len) return error.InvalidPayload;
        const vote_index = data[pos];
        pos += 1;
        var blinding: [32]u8 = undefined;
        @memcpy(&blinding, data[pos..][0..32]);
        pos += 32;
        reveals[parsed] = .{ .vote_index = vote_index, .blinding_factor = blinding };
    }

    return reveals;
}

// --- Fuzz harnesses ---
//
// In 0.16 `std.testing.fuzz` hands the callback a `*std.testing.Smith` value
// generator rather than a raw `[]const u8`. A plain `zig test` replays each
// corpus entry (fed as `Smith.in`) plus one empty input, so these double as
// regression tests; `zig build test --fuzz` drives them with real fuzzer input.
// `smith.slice(&buf)` yields a variable-length byte slice — it first reads a
// little-endian u32 length prefix, so `seed` wraps each raw payload with it.
// A panic or a leak (checked by the testing allocator) is the failure signal.

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

fn fuzzDeserializers(_: void, smith: *std.testing.Smith) anyerror!void {
    const a = std.testing.allocator;
    var buf: [4096]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];

    if (deserializeBallot(a, input)) |b| {
        a.free(b.question);
        for (b.options) |o| a.free(o);
        a.free(b.options);
    } else |_| {}

    if (deserializePeerList(a, input)) |peers| {
        for (peers) |p| a.free(p.nick);
        a.free(peers);
    } else |_| {}

    if (deserializeCommitSet(a, input)) |cs| {
        a.free(cs.commitments);
    } else |_| {}

    if (deserializeRevealSet(a, input)) |rs| {
        a.free(rs);
    } else |_| {}
}

test "fuzz payload deserializers" {
    try std.testing.fuzz({}, fuzzDeserializers, .{
        .corpus = &.{
            // One valid encoding of each payload type.
            seed(("\x00" ** 32) ++ "\x00\x01?" ++ "\x02" ++ "\x00\x03yes" ++ "\x00\x02no"), // ballot
            seed("\x01\x00\x04host" ++ ("\x00" ** 32)), // peer list
            seed("\x01\x00" ++ ("\x00" ** 32) ++ ("\x00" ** 64) ++ ("\x00" ** 32)), // commit set
            seed("\x01\x00" ++ ("\x00" ** 32)), // reveal set
            // Ballot claiming 2 options but only 1 present: option[0] is duped
            // before the parse fails — exercises the ballot error-path free.
            seed(("\x00" ** 32) ++ "\x00\x01?" ++ "\x02" ++ "\x00\x03yes"),
            // Peer list claiming 2 peers, the second truncated: peer[0].nick is
            // duped before the parse fails — exercises the nick error-path free.
            seed("\x02" ++ "\x00\x04host" ++ ("\x00" ** 32) ++ "\x01\x03bob"),
        },
    });
}

fn fuzzReadFrame(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    var r = std.Io.Reader.fixed(buf[0..smith.slice(&buf)]);
    var frame = readFrame(std.testing.allocator, &r) catch return;
    freeFrame(std.testing.allocator, &frame);
}

test "fuzz readFrame" {
    // Wire: type[1] ts[8] sender_len[1] sender[N] payload_len[4 BE] nonce[24]
    // tag[16] ciphertext[payload_len].
    try std.testing.fuzz({}, fuzzReadFrame, .{
        .corpus = &.{
            // Valid join frame, sender "a", empty payload (4+24+16 = 44 zeros).
            seed("\x01" ++ ("\x00" ** 8) ++ "\x01a" ++ ("\x00" ** 44)),
            seed("\x01\x00"), // truncated before the timestamp
            // sender_len 0, payload_len 0xffffffff -> PayloadTooLarge before alloc.
            seed("\x01" ++ ("\x00" ** 8) ++ "\x00" ++ "\xff\xff\xff\xff"),
        },
    });
}
