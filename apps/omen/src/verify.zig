const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");

/// Verify that a commit set is valid:
/// - All signatures match the roster's public keys
/// - The set hash is correct
/// - If my_slot_id is provided, my commitment is present and matches
pub fn verifyCommitSet(
    commitments: []const protocol.Commitment,
    set_hash: [32]u8,
    roster: []const protocol.PeerInfo,
    roster_hash: [32]u8,
    my_slot_id: ?u8,
    my_commitment: ?[32]u8,
) !void {
    // Verify set hash
    const computed_hash = crypto.computeCommitSetHash(commitments);
    if (!std.mem.eql(u8, &computed_hash, &set_hash)) {
        return error.CommitSetHashMismatch;
    }

    // Verify each commitment signature
    for (commitments) |c| {
        // Find the peer's public key
        const pubkey = findPubkey(roster, c.slot_id) orelse return error.UnknownSlotId;
        if (!crypto.verifyCommitmentSig(roster_hash, c.commitment, c.signature, pubkey)) {
            return error.InvalidCommitmentSignature;
        }
    }

    // Verify my own commitment is present and unmodified
    if (my_slot_id) |slot| {
        if (my_commitment) |expected| {
            for (commitments) |c| {
                if (c.slot_id == slot) {
                    if (!std.mem.eql(u8, &c.commitment, &expected)) {
                        return error.MyCommitmentTampered;
                    }
                    return; // Found and verified
                }
            }
            return error.MyCommitmentMissing;
        }
    }
}

/// Verify reveal set: every reveal opens exactly one commitment (bijection check)
pub fn verifyRevealSet(
    reveals: []const protocol.Reveal,
    commitments: []const protocol.Commitment,
) !void {
    if (reveals.len != commitments.len) {
        return error.RevealCountMismatch;
    }
    if (commitments.len > 256) return error.TooManyCommitments; // matched[] bound

    // Track which commitments have been matched
    var matched = [_]bool{false} ** 256; // max 256 voters

    for (reveals) |r| {
        const computed = crypto.makeCommitment(r.vote_index, r.blinding_factor);

        var found = false;
        for (commitments, 0..) |c, i| {
            if (std.mem.eql(u8, &computed, &c.commitment) and !matched[i]) {
                matched[i] = true;
                found = true;
                break;
            }
        }

        if (!found) {
            return error.RevealDoesNotMatchCommitment;
        }
    }

    // All commitments should be matched
    for (0..commitments.len) |i| {
        if (!matched[i]) {
            return error.UnmatchedCommitment;
        }
    }
}

/// Tally votes from verified reveals. Writes results into caller-provided buffer.
pub fn computeTally(reveals: []const protocol.Reveal, option_count: u8, out: []u32) void {
    for (out) |*c| c.* = 0;
    for (reveals) |r| {
        if (r.vote_index < option_count and r.vote_index < out.len) {
            out[r.vote_index] += 1;
        }
    }
}

fn findPubkey(roster: []const protocol.PeerInfo, slot_id: u8) ?[32]u8 {
    for (roster) |peer| {
        if (peer.slot_id == slot_id) return peer.pubkey;
    }
    return null;
}

// --- Standalone artifact verification (`omen verify`) ---

const Blake2b256 = std.crypto.hash.blake2.Blake2b256;

pub const ArtifactResult = struct {
    all_valid: bool,
    host_sig_valid: bool,
    roster_hash_valid: bool,
    commit_sigs_valid: bool,
    roster_complete: bool,
    bijection_valid: bool,
    tally_matches: bool,
    winner_valid: bool,
    voter_count: usize,
    question: []u8,
    options: [][]u8,
    counts: []u32,
    winner: []u8,

    pub fn deinit(self: *ArtifactResult, allocator: std.mem.Allocator) void {
        allocator.free(self.question);
        for (self.options) |o| allocator.free(o);
        allocator.free(self.options);
        allocator.free(self.counts);
        allocator.free(self.winner);
    }
};

/// Independently verify a saved omen artifact:
///   - the roster hashes to the recorded roster_hash
///   - every commitment is signed by the roster key for its slot
///   - every roster member has a commitment (no silently dropped votes)
///   - every reveal opens exactly one commitment (bijection)
///   - the recomputed tally matches the recorded tally
///   - the stated winner is a top-tallied option
///   - the host signature covers the whole artifact
/// Proves the host did not forge, alter, add, or drop recorded votes. Does not
/// prove voter eligibility unless the vote was run with a covenant roster.
pub fn verifyArtifact(allocator: std.mem.Allocator, json_raw: []const u8) !ArtifactResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidArtifact;
    const obj = parsed.value.object;

    // Roster (nicks borrowed from the parsed tree; used only within this fn).
    const roster_items = try getArray(obj, "roster");
    var roster = try allocator.alloc(protocol.PeerInfo, roster_items.len);
    defer allocator.free(roster);
    for (roster_items, 0..) |it, i| {
        if (it != .object) return error.BadRoster;
        const ro = it.object;
        const slot = std.math.cast(u8, try getInt(ro, "slot")) orelse return error.BadRoster;
        const nick = try getStr(ro, "nick");
        var pk: [32]u8 = undefined;
        try hexInto(try getStr(ro, "pubkey"), &pk);
        roster[i] = .{ .slot_id = slot, .nick = nick, .pubkey = pk };
    }

    // Recompute the roster hash and compare to what the artifact claims.
    const computed_roster_hash = crypto.computeRosterHash(roster);
    var stated_roster_hash: [32]u8 = undefined;
    try hexInto(try getStr(obj, "roster_hash"), &stated_roster_hash);
    const roster_hash_valid = std.mem.eql(u8, &computed_roster_hash, &stated_roster_hash);

    // Commitments + per-commitment signature check against the roster key.
    // slot_id is a u8, so >256 entries can never be a valid artifact — and the
    // cap keeps verifyRevealSet's fixed matched[256] in bounds.
    const commit_items = try getArray(obj, "commitments");
    if (commit_items.len > 256) return error.TooManyCommitments;
    var commitments = try allocator.alloc(protocol.Commitment, commit_items.len);
    defer allocator.free(commitments);
    for (commit_items, 0..) |it, i| {
        if (it != .object) return error.BadCommitment;
        const co = it.object;
        const slot = std.math.cast(u8, try getInt(co, "slot")) orelse return error.BadCommitment;
        var c: [32]u8 = undefined;
        var s: [64]u8 = undefined;
        try hexInto(try getStr(co, "commitment"), &c);
        try hexInto(try getStr(co, "signature"), &s);
        commitments[i] = .{ .slot_id = slot, .commitment = c, .signature = s };
    }
    var commit_sigs_valid = true;
    for (commitments) |c| {
        const pk = findPubkey(roster, c.slot_id) orelse {
            commit_sigs_valid = false;
            break;
        };
        if (!crypto.verifyCommitmentSig(computed_roster_hash, c.commitment, c.signature, pk)) {
            commit_sigs_valid = false;
            break;
        }
    }

    // Reveals + bijection against the commitments.
    const reveal_items = try getArray(obj, "reveals");
    if (reveal_items.len > 256) return error.TooManyReveals;
    var reveals = try allocator.alloc(protocol.Reveal, reveal_items.len);
    defer allocator.free(reveals);
    for (reveal_items, 0..) |it, i| {
        if (it != .object) return error.BadReveal;
        const ro = it.object;
        const vote = std.math.cast(u8, try getInt(ro, "vote")) orelse return error.BadReveal;
        var b: [32]u8 = undefined;
        try hexInto(try getStr(ro, "blinding"), &b);
        reveals[i] = .{ .vote_index = vote, .blinding_factor = b };
    }
    const bijection_valid = if (verifyRevealSet(reveals, commitments)) |_| true else |_| false;

    // Options (owned) + recomputed tally.
    const option_items = try getArray(obj, "options");
    const option_count = std.math.cast(u8, option_items.len) orelse return error.TooManyOptions;
    var options = try allocator.alloc([]u8, option_items.len);
    var opt_filled: usize = 0;
    errdefer {
        for (options[0..opt_filled]) |o| allocator.free(o);
        allocator.free(options);
    }
    for (option_items) |it| {
        if (it != .string) return error.BadOption;
        options[opt_filled] = try allocator.dupe(u8, it.string);
        opt_filled += 1;
    }

    const counts = try allocator.alloc(u32, options.len);
    errdefer allocator.free(counts);
    computeTally(reveals, option_count, counts);

    // Compare recomputed tally to the recorded tally object.
    var tally_matches = true;
    if (obj.get("tally")) |tv| {
        if (tv == .object) {
            for (options, 0..) |opt, i| {
                const stated = tv.object.get(opt) orelse {
                    tally_matches = false;
                    break;
                };
                if (stated != .integer or stated.integer != @as(i64, counts[i])) {
                    tally_matches = false;
                    break;
                }
            }
        } else tally_matches = false;
    } else tally_matches = false;

    // The stated winner must be one of the top-tallied options — otherwise a
    // host could sign a correct tally but name the loser as winner.
    var winner_valid = true;
    const stated_winner = optStr(obj, "winner");
    if (stated_winner.len > 0) {
        var max_count: u32 = 0;
        for (counts) |c| max_count = @max(max_count, c);
        winner_valid = false;
        for (options, 0..) |opt, i| {
            if (counts[i] == max_count and std.mem.eql(u8, opt, stated_winner)) {
                winner_valid = true;
                break;
            }
        }
    }

    // Every roster member must have a commitment: the protocol only completes
    // once all participants commit, so a missing one means the host dropped a
    // recorded vote after the fact. (reveals.len is bound to commitments.len
    // by the bijection check.)
    const roster_complete = commitments.len == roster.len;

    // Host signature covers every byte before the "host_signature" field —
    // the exact prefix the artifact hashed and signed at build time.
    var host_sig_valid = false;
    sig: {
        const hp = optStr(obj, "host_pubkey");
        const hs = optStr(obj, "host_signature");
        if (hp.len != 64 or hs.len != 128) break :sig;
        var host_pk: [32]u8 = undefined;
        var host_sig: [64]u8 = undefined;
        // Both decodes must succeed before we verify — a bad-hex field would
        // otherwise leave the buffer partially undefined and we'd run Ed25519
        // against undefined bytes. On any decode failure, host_sig_valid stays
        // false.
        hexInto(hp, &host_pk) catch break :sig;
        hexInto(hs, &host_sig) catch break :sig;
        const idx = std.mem.indexOf(u8, json_raw, "\"host_signature\"") orelse break :sig;
        var content_hash: [32]u8 = undefined;
        Blake2b256.hash(json_raw[0..idx], &content_hash, .{});
        host_sig_valid = crypto.verify(host_sig, &content_hash, host_pk);
    }

    const voter_count: usize = blk: {
        const v = obj.get("voter_count") orelse break :blk roster.len;
        if (v != .integer) break :blk roster.len;
        break :blk std.math.cast(usize, v.integer) orelse roster.len;
    };

    const all_valid = host_sig_valid and roster_hash_valid and
        commit_sigs_valid and roster_complete and bijection_valid and
        tally_matches and winner_valid;

    return ArtifactResult{
        .all_valid = all_valid,
        .host_sig_valid = host_sig_valid,
        .roster_hash_valid = roster_hash_valid,
        .commit_sigs_valid = commit_sigs_valid,
        .roster_complete = roster_complete,
        .bijection_valid = bijection_valid,
        .tally_matches = tally_matches,
        .winner_valid = winner_valid,
        .voter_count = voter_count,
        .question = try allocator.dupe(u8, optStr(obj, "question")),
        .options = options,
        .counts = counts,
        .winner = try allocator.dupe(u8, optStr(obj, "winner")),
    };
}

fn getArray(obj: anytype, key: []const u8) ![]std.json.Value {
    const v = obj.get(key) orelse return error.MissingField;
    if (v != .array) return error.BadField;
    return v.array.items;
}

fn getInt(obj: anytype, key: []const u8) !i64 {
    const v = obj.get(key) orelse return error.MissingField;
    if (v != .integer) return error.BadField;
    return v.integer;
}

fn getStr(obj: anytype, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return error.MissingField;
    if (v != .string) return error.BadField;
    return v.string;
}

fn optStr(obj: anytype, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    if (v != .string) return "";
    return v.string;
}

fn hexInto(hex: []const u8, out: []u8) !void {
    if (hex.len != out.len * 2) return error.BadHex;
    for (out, 0..) |*b, i| {
        b.* = (try hexNibble(hex[i * 2]) << 4) | try hexNibble(hex[i * 2 + 1]);
    }
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.BadHex,
    };
}

test "bijection check passes for valid reveal set" {
    const blinding1 = [_]u8{1} ** 32;
    const blinding2 = [_]u8{2} ** 32;

    const c1 = crypto.makeCommitment(0, blinding1);
    const c2 = crypto.makeCommitment(1, blinding2);

    const commitments = [_]protocol.Commitment{
        .{ .slot_id = 0, .commitment = c1, .signature = [_]u8{0} ** 64 },
        .{ .slot_id = 1, .commitment = c2, .signature = [_]u8{0} ** 64 },
    };

    const reveals = [_]protocol.Reveal{
        .{ .vote_index = 1, .blinding_factor = blinding2 }, // shuffled order
        .{ .vote_index = 0, .blinding_factor = blinding1 },
    };

    try verifyRevealSet(&reveals, &commitments);
}

test "bijection check fails for tampered reveal" {
    const blinding1 = [_]u8{1} ** 32;
    const blinding2 = [_]u8{2} ** 32;

    const c1 = crypto.makeCommitment(0, blinding1);
    const c2 = crypto.makeCommitment(1, blinding2);

    const commitments = [_]protocol.Commitment{
        .{ .slot_id = 0, .commitment = c1, .signature = [_]u8{0} ** 64 },
        .{ .slot_id = 1, .commitment = c2, .signature = [_]u8{0} ** 64 },
    };

    // Tampered: changed vote_index from 1 to 0
    const reveals = [_]protocol.Reveal{
        .{ .vote_index = 0, .blinding_factor = blinding2 },
        .{ .vote_index = 0, .blinding_factor = blinding1 },
    };

    try std.testing.expectError(error.RevealDoesNotMatchCommitment, verifyRevealSet(&reveals, &commitments));
}

test "tally counts correctly" {
    const reveals = [_]protocol.Reveal{
        .{ .vote_index = 0, .blinding_factor = [_]u8{0} ** 32 },
        .{ .vote_index = 1, .blinding_factor = [_]u8{0} ** 32 },
        .{ .vote_index = 1, .blinding_factor = [_]u8{0} ** 32 },
        .{ .vote_index = 2, .blinding_factor = [_]u8{0} ** 32 },
    };

    var counts: [3]u32 = undefined;
    computeTally(&reveals, 3, &counts);
    try std.testing.expectEqual(@as(u32, 1), counts[0]);
    try std.testing.expectEqual(@as(u32, 2), counts[1]);
    try std.testing.expectEqual(@as(u32, 1), counts[2]);
}

test "verifyArtifact accepts a valid artifact and rejects tampering" {
    const allocator = std.testing.allocator;
    const artifact = @import("artifact.zig");

    // Two participants: host (slot 0) and one voter (slot 1).
    const host_kp = crypto.generateKeyPair(std.testing.io);
    const voter_kp = crypto.generateKeyPair(std.testing.io);

    const roster = [_]protocol.PeerInfo{
        .{ .slot_id = 0, .nick = "host", .pubkey = crypto.publicKeyBytes(host_kp) },
        .{ .slot_id = 1, .nick = "voter", .pubkey = crypto.publicKeyBytes(voter_kp) },
    };
    const roster_hash = crypto.computeRosterHash(&roster);

    // Host votes option 0, voter votes option 1.
    const b0 = [_]u8{7} ** 32;
    const b1 = [_]u8{9} ** 32;
    const c0 = crypto.makeCommitment(0, b0);
    const c1 = crypto.makeCommitment(1, b1);

    const commitments = [_]protocol.Commitment{
        .{ .slot_id = 0, .commitment = c0, .signature = crypto.signCommitment(roster_hash, c0, host_kp) },
        .{ .slot_id = 1, .commitment = c1, .signature = crypto.signCommitment(roster_hash, c1, voter_kp) },
    };
    const reveals = [_]protocol.Reveal{
        .{ .vote_index = 0, .blinding_factor = b0 },
        .{ .vote_index = 1, .blinding_factor = b1 },
    };
    const options = [_][]const u8{ "yes", "no" };
    const counts = [_]u32{ 1, 1 };
    const session_id = [_]u8{0} ** 32;

    const json = try artifact.buildArtifact(
        allocator,
        std.testing.io,
        session_id,
        "Ship it?",
        &options,
        &roster,
        roster_hash,
        &commitments,
        &reveals,
        &counts,
        host_kp,
    );
    defer allocator.free(json);

    // A well-formed, untampered artifact verifies on every axis.
    var ok = try verifyArtifact(allocator, json);
    defer ok.deinit(allocator);
    try std.testing.expect(ok.host_sig_valid);
    try std.testing.expect(ok.roster_hash_valid);
    try std.testing.expect(ok.commit_sigs_valid);
    try std.testing.expect(ok.roster_complete);
    try std.testing.expect(ok.bijection_valid);
    try std.testing.expect(ok.tally_matches);
    try std.testing.expect(ok.winner_valid);
    try std.testing.expect(ok.all_valid);

    // Flip a recorded vote: the reveal no longer opens its commitment and the
    // bytes no longer match the host signature — verification must fail.
    const tampered = try allocator.dupe(u8, json);
    defer allocator.free(tampered);
    const at = std.mem.indexOf(u8, tampered, "\"vote\":0").?;
    tampered[at + 7] = '1';
    var bad = try verifyArtifact(allocator, tampered);
    defer bad.deinit(allocator);
    try std.testing.expect(!bad.all_valid);

    // A host that drops one voter's commitment+reveal pair (keeping the roster
    // intact and re-signing) must be caught by the roster-completeness check:
    // every other axis still verifies, so this check is the only defense.
    const dropped_json = try artifact.buildArtifact(
        allocator,
        std.testing.io,
        session_id,
        "Ship it?",
        &options,
        &roster,
        roster_hash,
        commitments[0..1],
        reveals[0..1],
        &[_]u32{ 1, 0 },
        host_kp,
    );
    defer allocator.free(dropped_json);
    var dropped = try verifyArtifact(allocator, dropped_json);
    defer dropped.deinit(allocator);
    try std.testing.expect(dropped.host_sig_valid);
    try std.testing.expect(dropped.commit_sigs_valid);
    try std.testing.expect(dropped.bijection_valid);
    try std.testing.expect(dropped.tally_matches);
    try std.testing.expect(!dropped.roster_complete);
    try std.testing.expect(!dropped.all_valid);
}

test "verifyArtifact rejects a winner that does not match the tally" {
    const allocator = std.testing.allocator;

    // winner_valid is computed from reveals + options alone, so a minimal
    // unsigned artifact isolates it: reveals tally a=2, b=1.
    const template =
        \\{{"roster":[],"roster_hash":"{s}","commitments":[],
        \\"reveals":[{{"vote":0,"blinding":"{s}"}},{{"vote":0,"blinding":"{s}"}},{{"vote":1,"blinding":"{s}"}}],
        \\"options":["a","b"],"tally":{{"a":2,"b":1}},"winner":"{s}"}}
    ;
    const zeros = "00" ** 32;

    const losing = try std.fmt.allocPrint(allocator, template, .{ zeros, zeros, zeros, zeros, "b" });
    defer allocator.free(losing);
    var forged = try verifyArtifact(allocator, losing);
    defer forged.deinit(allocator);
    try std.testing.expect(!forged.winner_valid);
    try std.testing.expect(!forged.all_valid);

    const winning = try std.fmt.allocPrint(allocator, template, .{ zeros, zeros, zeros, zeros, "a" });
    defer allocator.free(winning);
    var honest = try verifyArtifact(allocator, winning);
    defer honest.deinit(allocator);
    try std.testing.expect(honest.winner_valid);
}

// 0.16 `std.testing.fuzz` passes a `*std.testing.Smith`; a plain `zig test`
// replays the corpus (fed as `Smith.in`) plus one empty input, and
// `zig build test --fuzz` drives it with real fuzzer input. `smith.slice` reads
// a little-endian u32 length prefix first, so `seed` wraps each raw payload.

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

fn fuzzVerifyArtifact(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [8192]u8 = undefined;
    var result = verifyArtifact(std.testing.allocator, buf[0..smith.slice(&buf)]) catch return;
    result.deinit(std.testing.allocator);
}

test "fuzz verifyArtifact" {
    const hex64 = "0" ** 64;
    try std.testing.fuzz({}, fuzzVerifyArtifact, .{
        .corpus = &.{
            // Well-formed minimal artifact: no host signature, so all_valid is
            // false, but parsing succeeds and returns an owned result to free.
            seed("{\"roster\":[],\"roster_hash\":\"" ++ hex64 ++
                "\",\"commitments\":[],\"reveals\":[],\"options\":[\"a\"]," ++
                "\"tally\":{\"a\":0},\"winner\":\"\"}"),
            // Malformed roster_hash hex (right length, bad digit) -> hexInto error.
            seed("{\"roster\":[],\"roster_hash\":\"" ++ ("0" ** 63) ++ "z\"," ++
                "\"commitments\":[],\"reveals\":[],\"options\":[\"a\"]," ++
                "\"tally\":{\"a\":0},\"winner\":\"\"}"),
            seed("{\"roster\":[],\"roster_hash\":\"00"), // truncated JSON
        },
    });
}
