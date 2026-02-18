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
    errdefer {
        for (options) |opt| allocator.free(opt);
        allocator.free(options);
    }
    var parsed: usize = 0;

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
    errdefer allocator.free(peers);
    var parsed: usize = 0;

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
