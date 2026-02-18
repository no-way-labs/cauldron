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
