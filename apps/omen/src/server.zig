const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const verify_mod = @import("verify.zig");
const artifact = @import("artifact.zig");

/// getsockname is absent from std.posix in 0.16.0 (getpeername survived);
/// wrap the OS-specific call until it returns.
fn getsockname(handle: std.posix.socket_t, addr: *std.posix.sockaddr, len: *std.posix.socklen_t) !void {
    switch (builtin.os.tag) {
        .linux => {
            const rc = std.os.linux.getsockname(handle, addr, len);
            if (std.posix.errno(rc) != .SUCCESS) return error.GetSockNameFailed;
        },
        else => {
            if (std.c.getsockname(handle, addr, len) != 0) return error.GetSockNameFailed;
        },
    }
}

/// Reads the locally bound port, for servers listening on port 0.
fn boundPort(handle: std.posix.socket_t) ?u16 {
    var addr: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    getsockname(handle, @ptrCast(&addr), &len) catch return null;
    const sa: *const std.posix.sockaddr = @ptrCast(@alignCast(&addr));
    return switch (sa.family) {
        std.posix.AF.INET => blk: {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(sa));
            break :blk std.mem.bigToNative(u16, in.port);
        },
        std.posix.AF.INET6 => blk: {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            break :blk std.mem.bigToNative(u16, in6.port);
        },
        else => null,
    };
}

const Voter = struct {
    stream: Io.net.Stream,
    nick: []const u8,
    slot_id: u8,
    pubkey: [32]u8,
    has_pubkey: bool,
    commitment: ?[32]u8,
    signature: ?[64]u8,
    reveal: ?protocol.Reveal,
};

pub const ServerConfig = struct {
    port: u16,
    max_voters: u8 = 32,
    local_only: bool = false,
    timeout_secs: u64 = 120,
    output_path: ?[]const u8 = null,
    allowed_pubkeys: ?[][32]u8 = null,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: Io,
    port: u16,
    listener: Io.net.Server,
    config: ServerConfig,
    key: [32]u8,
    host_nick: []const u8,
    question: []const u8,
    options: []const []const u8,
    session_id: [32]u8,
    host_keypair: crypto.KeyPair,
    voters: std.ArrayList(Voter),
    voters_mutex: Io.Mutex,
    phase: std.atomic.Value(u8),
    running: std.atomic.Value(bool),
    // Host's own vote data
    host_commitment: ?[32]u8,
    host_commitment_sig: ?[64]u8,
    host_blinding: ?[32]u8,
    host_vote_index: ?u8,
    roster_hash: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        config: ServerConfig,
        key: [32]u8,
        host_nick: []const u8,
        question: []const u8,
        options: []const []const u8,
        keypair: crypto.KeyPair,
    ) !Server {
        const address = Io.net.IpAddress.parse("127.0.0.1", config.port) catch unreachable;
        var listener = try address.listen(io, .{
            .reuse_address = true,
        });
        errdefer listener.deinit(io);

        // When asked for port 0 the kernel picks one; report the real port.
        const actual_port = if (config.port != 0) config.port else boundPort(listener.socket.handle) orelse
            return error.PortDiscoveryFailed;

        var session_id: [32]u8 = undefined;
        io.random(&session_id);

        return Server{
            .allocator = allocator,
            .io = io,
            .port = actual_port,
            .listener = listener,
            .config = config,
            .key = key,
            .host_nick = host_nick,
            .question = question,
            .options = options,
            .session_id = session_id,
            .host_keypair = keypair,
            .voters = try std.ArrayList(Voter).initCapacity(allocator, 0),
            .voters_mutex = .init,
            .phase = std.atomic.Value(u8).init(@intFromEnum(protocol.Phase.lobby)),
            .running = std.atomic.Value(bool).init(true),
            .host_commitment = null,
            .host_commitment_sig = null,
            .host_blinding = null,
            .host_vote_index = null,
            .roster_hash = [_]u8{0} ** 32,
        };
    }

    pub fn run(self: *Server) !void {
        display.printStatus("Waiting for voters... (/start to begin, /abort to cancel)");

        const stdin_thread = std.Thread.spawn(.{}, Server.readHostStdin, .{self}) catch |err| {
            std.debug.print("Failed to spawn stdin thread: {}\n", .{err});
            return err;
        };
        defer stdin_thread.detach();

        while (self.running.load(.monotonic)) {
            const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
            if (current_phase != .lobby) break;

            const stream = self.listener.accept(self.io) catch |err| {
                if (!self.running.load(.monotonic)) break;
                std.debug.print("Accept error: {}\n", .{err});
                continue;
            };

            const conn_thread = std.Thread.spawn(.{}, Server.handleConnection, .{ self, stream }) catch |err| {
                std.debug.print("Failed to spawn connection thread: {}\n", .{err});
                stream.close(self.io);
                continue;
            };
            conn_thread.detach();
        }

        // Wait for protocol to complete
        while (self.running.load(.monotonic)) {
            const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
            if (current_phase == .done) break;
            self.io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
    }

    fn handleConnection(self: *Server, stream: Io.net.Stream) void {
        const io = self.io;

        // Slow-loris guard: bound the handshake read so a connection that never
        // sends a valid JOIN can't pin this thread indefinitely. Cleared once the
        // voter is admitted (see below) so idle lobby voters aren't dropped.
        const handshake_tv = std.posix.timeval{ .sec = 30, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&handshake_tv)) catch {};

        // ONE persistent reader for the whole connection: the interface buffers
        // ahead, so every readFrame on this connection must share it.
        var read_buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(io, &read_buf);
        const in = &stream_reader.interface;

        // Read JOIN frame
        const join_frame = protocol.readFrame(self.allocator, in) catch {
            stream.close(io);
            return;
        };
        defer {
            var mutable_frame = join_frame;
            protocol.freeFrame(self.allocator, &mutable_frame);
        }

        if (join_frame.msg_type != .join) {
            stream.close(io);
            return;
        }

        // Decrypt and verify MAGIC
        const plaintext = crypto.decryptRaw(
            self.allocator,
            join_frame.nonce,
            join_frame.tag,
            join_frame.ciphertext,
            self.key,
        ) catch {
            stream.close(io);
            return;
        };
        defer self.allocator.free(plaintext);

        if (plaintext.len != protocol.MAGIC.len or !std.crypto.timing_safe.eql([protocol.MAGIC.len]u8, plaintext[0..protocol.MAGIC.len].*, protocol.MAGIC[0..protocol.MAGIC.len].*)) {
            stream.close(io);
            return;
        }

        // Only accept during lobby
        const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
        if (current_phase != .lobby) {
            stream.close(io);
            return;
        }

        // Resolve nick collision
        const nick = self.resolveNickCollision(join_frame.sender) catch {
            stream.close(io);
            return;
        };

        // Assign slot. The cap check shares the lock with the append so it is
        // atomic: this both enforces max_voters and keeps slot_id (u8) from
        // overflowing (len < max_voters <= 255, so slot_id = len + 1 <= 255).
        self.voters_mutex.lockUncancelable(io);
        if (self.voters.items.len >= self.config.max_voters) {
            self.voters_mutex.unlock(io);
            self.allocator.free(nick);
            display.printStatus("Voter limit reached, rejecting connection.");
            stream.close(io);
            return;
        }
        const slot_id: u8 = @intCast(self.voters.items.len + 1); // host is slot 0
        self.voters.append(self.allocator, .{
            .stream = stream,
            .nick = nick,
            .slot_id = slot_id,
            .pubkey = [_]u8{0} ** 32,
            .has_pubkey = false,
            .commitment = null,
            .signature = null,
            .reveal = null,
        }) catch {
            self.voters_mutex.unlock(io);
            self.allocator.free(nick);
            stream.close(io);
            return;
        };
        const voter_count = self.voters.items.len + 1; // +1 for host
        self.voters_mutex.unlock(io);

        // Handshake complete: clear the recv timeout so an admitted voter isn't
        // dropped while idling in the lobby waiting for the host to /start.
        const clear_tv = std.posix.timeval{ .sec = 0, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&clear_tv)) catch {};

        display.printVoterJoined(nick, voter_count);

        // Send ballot to new joiner
        self.sendBallot(stream);

        // Enter voter read loop (reuses the persistent reader)
        self.voterReadLoop(in, slot_id);

        // Cleanup on disconnect
        self.removeVoter(stream);
    }

    fn voterReadLoop(self: *Server, in: *Io.Reader, slot_id: u8) void {
        const io = self.io;
        while (self.running.load(.monotonic)) {
            const frame = protocol.readFrame(self.allocator, in) catch {
                return;
            };
            defer {
                var mutable_frame = frame;
                protocol.freeFrame(self.allocator, &mutable_frame);
            }

            const plaintext = crypto.decryptRaw(
                self.allocator,
                frame.nonce,
                frame.tag,
                frame.ciphertext,
                self.key,
            ) catch continue;
            defer self.allocator.free(plaintext);

            switch (frame.msg_type) {
                .pubkey => {
                    if (plaintext.len == 32) {
                        // Check against covenant roster if restricted
                        if (self.config.allowed_pubkeys) |allowed| {
                            var found = false;
                            for (allowed) |pk| {
                                if (std.mem.eql(u8, plaintext[0..32], &pk)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                display.printStatus("Rejected voter: not in covenant roster.");
                                return; // disconnect
                            }
                        }
                        self.voters_mutex.lockUncancelable(io);
                        for (self.voters.items) |*voter| {
                            if (voter.slot_id == slot_id) {
                                @memcpy(&voter.pubkey, plaintext[0..32]);
                                voter.has_pubkey = true;
                                break;
                            }
                        }
                        self.voters_mutex.unlock(io);
                    }
                },
                .commitment => {
                    if (plaintext.len == 96) { // 32 commitment + 64 signature
                        self.voters_mutex.lockUncancelable(io);
                        for (self.voters.items) |*voter| {
                            if (voter.slot_id == slot_id) {
                                var commitment_val: [32]u8 = undefined;
                                @memcpy(&commitment_val, plaintext[0..32]);
                                var sig: [64]u8 = undefined;
                                @memcpy(&sig, plaintext[32..96]);

                                // Verify signature
                                if (crypto.verifyCommitmentSig(self.roster_hash, commitment_val, sig, voter.pubkey)) {
                                    voter.commitment = commitment_val;
                                    voter.signature = sig;
                                }
                                break;
                            }
                        }
                        const received = self.countCommitments();
                        const total = self.voters.items.len + 1;
                        self.voters_mutex.unlock(io);

                        display.printProgress("Waiting for commitments", received, total);

                        if (received == total) {
                            self.broadcastCommitSet();
                            self.startRevealPhase();
                        }
                    }
                },
                .reveal => {
                    if (plaintext.len == 33) { // 1 vote_index + 32 blinding
                        self.voters_mutex.lockUncancelable(io);
                        for (self.voters.items) |*voter| {
                            if (voter.slot_id == slot_id) {
                                const vote_index = plaintext[0];
                                var blinding: [32]u8 = undefined;
                                @memcpy(&blinding, plaintext[1..33]);

                                // Verify it opens the commitment
                                if (voter.commitment) |expected| {
                                    const computed = crypto.makeCommitment(vote_index, blinding);
                                    if (std.mem.eql(u8, &computed, &expected)) {
                                        voter.reveal = .{ .vote_index = vote_index, .blinding_factor = blinding };
                                    }
                                }
                                break;
                            }
                        }
                        const received = self.countReveals();
                        const total = self.voters.items.len + 1;
                        self.voters_mutex.unlock(io);

                        display.printProgress("Waiting for reveals", received, total);

                        if (received == total) {
                            self.finishVote();
                        }
                    }
                },
                .leave => return,
                else => {},
            }
        }
    }

    fn countCommitments(self: *Server) usize {
        // Must hold voters_mutex
        var count: usize = if (self.host_commitment != null) @as(usize, 1) else 0;
        for (self.voters.items) |voter| {
            if (voter.commitment != null) count += 1;
        }
        return count;
    }

    fn countReveals(self: *Server) usize {
        // Must hold voters_mutex
        var count: usize = if (self.host_vote_index != null) @as(usize, 1) else 0;
        for (self.voters.items) |voter| {
            if (voter.reveal != null) count += 1;
        }
        return count;
    }

    fn startCommitPhase(self: *Server) void {
        // Build roster and compute hash
        const roster = self.buildRoster() catch return;
        defer self.allocator.free(roster);

        self.roster_hash = crypto.computeRosterHash(roster);
        self.phase.store(@intFromEnum(protocol.Phase.commit), .monotonic);

        // Broadcast peer list then phase transition
        self.broadcastPeerList(roster);
        self.broadcastPhase(.commit);

        const voter_count = roster.len;
        display.printPhaseStart("Vote started", voter_count);
        display.printVotePrompt(self.options);

        // Host votes via stdin (handled in readHostStdin)
    }

    fn startRevealPhase(self: *Server) void {
        display.printStatus("All commitments verified. Broadcasting...");
        self.phase.store(@intFromEnum(protocol.Phase.reveal), .monotonic);
        self.broadcastPhase(.reveal);
        display.printStatus("Reveal phase started.");

        // Host sends its reveal automatically
        if (self.host_vote_index) |vi| {
            if (self.host_blinding) |bl| {
                _ = vi;
                _ = bl;
                // Host reveal is already stored, count it
                self.voters_mutex.lockUncancelable(self.io);
                const received = self.countReveals();
                const total = self.voters.items.len + 1;
                self.voters_mutex.unlock(self.io);

                display.printProgress("Waiting for reveals", received, total);

                if (received == total) {
                    self.finishVote();
                }
            }
        }
    }

    fn finishVote(self: *Server) void {
        const io = self.io;
        display.printStatus("All reveals verified.");

        self.voters_mutex.lockUncancelable(io);

        // Collect all reveals including host's
        var all_reveals = std.ArrayList(protocol.Reveal).initCapacity(self.allocator, 0) catch {
            self.voters_mutex.unlock(io);
            return;
        };
        defer all_reveals.deinit(self.allocator);

        // Add host reveal
        if (self.host_vote_index) |vi| {
            if (self.host_blinding) |bl| {
                all_reveals.append(self.allocator, .{ .vote_index = vi, .blinding_factor = bl }) catch {};
            }
        }

        // Add voter reveals
        for (self.voters.items) |voter| {
            if (voter.reveal) |r| {
                all_reveals.append(self.allocator, r) catch {};
            }
        }

        // Fisher-Yates shuffle
        self.shuffleReveals(all_reveals.items);

        // Broadcast reveal set
        self.broadcastRevealSetLocked(all_reveals.items);

        // Compute tally
        const option_count = self.options.len;
        const counts_owned = self.allocator.alloc(u32, option_count) catch {
            self.voters_mutex.unlock(io);
            return;
        };
        defer self.allocator.free(counts_owned);
        verify_mod.computeTally(all_reveals.items, @intCast(self.options.len), counts_owned);

        // Build roster for artifact
        const roster = self.buildRosterLocked() catch {
            self.voters_mutex.unlock(io);
            return;
        };
        defer self.allocator.free(roster);

        // Build commitments list
        const all_commitments = self.allocator.alloc(protocol.Commitment, self.voters.items.len + 1) catch {
            self.voters_mutex.unlock(io);
            return;
        };
        defer self.allocator.free(all_commitments);

        all_commitments[0] = .{
            .slot_id = 0,
            .commitment = self.host_commitment orelse [_]u8{0} ** 32,
            .signature = self.host_commitment_sig orelse [_]u8{0} ** 64,
        };
        for (self.voters.items, 0..) |voter, i| {
            all_commitments[i + 1] = .{
                .slot_id = voter.slot_id,
                .commitment = voter.commitment orelse [_]u8{0} ** 32,
                .signature = voter.signature orelse [_]u8{0} ** 64,
            };
        }

        self.voters_mutex.unlock(io);

        display.printResults(self.question, self.options, counts_owned, all_reveals.items.len);

        // Build and output artifact
        const json = artifact.buildArtifact(
            self.allocator,
            io,
            self.session_id,
            self.question,
            self.options,
            roster,
            self.roster_hash,
            all_commitments,
            all_reveals.items,
            counts_owned,
            self.host_keypair,
        ) catch |err| {
            std.debug.print("Failed to build artifact: {}\n", .{err});
            self.phase.store(@intFromEnum(protocol.Phase.done), .monotonic);
            self.running.store(false, .monotonic);
            return;
        };
        defer self.allocator.free(json);

        // Broadcast tally (artifact JSON)
        self.broadcastTally(json);

        // Output artifact
        if (self.config.output_path) |path| {
            const file = Io.Dir.cwd().createFile(io, path, .{}) catch |err| {
                std.debug.print("Error: cannot write {s}: {}\n", .{ path, err });
                self.phase.store(@intFromEnum(protocol.Phase.done), .monotonic);
                self.running.store(false, .monotonic);
                return;
            };
            defer file.close(io);
            file.writeStreamingAll(io, json) catch {};
            file.writeStreamingAll(io, "\n") catch {};
            std.debug.print("\x1b[38;5;245mArtifact saved to:\x1b[0m {s}\n", .{path});
        } else {
            Io.File.stdout().writeStreamingAll(io, json) catch {};
            Io.File.stdout().writeStreamingAll(io, "\n") catch {};
        }

        self.phase.store(@intFromEnum(protocol.Phase.done), .monotonic);
        self.running.store(false, .monotonic);
    }

    fn shuffleReveals(self: *Server, reveals: []protocol.Reveal) void {
        if (reveals.len <= 1) return;
        // Seed a CSPRNG from the Io entropy source; the shuffle unlinks reveals
        // from the slot order they arrived in, so it must not be predictable.
        var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
        self.io.random(&seed);
        var csprng = std.Random.ChaCha.init(seed);
        const random = csprng.random();
        var i = reveals.len - 1;
        while (i > 0) : (i -= 1) {
            const j = random.uintLessThan(usize, i + 1);
            const tmp = reveals[i];
            reveals[i] = reveals[j];
            reveals[j] = tmp;
        }
    }

    fn buildRoster(self: *Server) ![]protocol.PeerInfo {
        self.voters_mutex.lockUncancelable(self.io);
        defer self.voters_mutex.unlock(self.io);
        return self.buildRosterLocked();
    }

    fn buildRosterLocked(self: *Server) ![]protocol.PeerInfo {
        // Must hold voters_mutex
        const roster = try self.allocator.alloc(protocol.PeerInfo, self.voters.items.len + 1);
        errdefer self.allocator.free(roster);

        roster[0] = .{
            .slot_id = 0,
            .nick = self.host_nick,
            .pubkey = crypto.publicKeyBytes(self.host_keypair),
        };

        for (self.voters.items, 0..) |voter, i| {
            roster[i + 1] = .{
                .slot_id = voter.slot_id,
                .nick = voter.nick,
                .pubkey = voter.pubkey,
            };
        }

        return roster;
    }

    fn broadcastPeerList(self: *Server, roster: []const protocol.PeerInfo) void {
        const payload = protocol.serializePeerList(self.allocator, roster) catch return;
        defer self.allocator.free(payload);
        self.broadcastEncrypted(.peer_list, payload);
    }

    fn broadcastPhase(self: *Server, phase: protocol.Phase) void {
        const payload = protocol.serializePhase(phase, self.roster_hash);
        self.broadcastEncrypted(.phase, &payload);
    }

    fn broadcastCommitSet(self: *Server) void {
        self.voters_mutex.lockUncancelable(self.io);
        const commitments = self.allocator.alloc(protocol.Commitment, self.voters.items.len + 1) catch {
            self.voters_mutex.unlock(self.io);
            return;
        };
        defer self.allocator.free(commitments);

        commitments[0] = .{
            .slot_id = 0,
            .commitment = self.host_commitment orelse [_]u8{0} ** 32,
            .signature = self.host_commitment_sig orelse [_]u8{0} ** 64,
        };
        for (self.voters.items, 0..) |voter, i| {
            commitments[i + 1] = .{
                .slot_id = voter.slot_id,
                .commitment = voter.commitment orelse [_]u8{0} ** 32,
                .signature = voter.signature orelse [_]u8{0} ** 64,
            };
        }
        self.voters_mutex.unlock(self.io);

        const set_hash = crypto.computeCommitSetHash(commitments);
        const payload = protocol.serializeCommitSet(self.allocator, commitments, set_hash) catch return;
        defer self.allocator.free(payload);
        self.broadcastEncrypted(.commit_set, payload);
    }

    fn broadcastRevealSetLocked(self: *Server, reveals: []const protocol.Reveal) void {
        // Must hold voters_mutex
        const io = self.io;
        const payload = protocol.serializeRevealSet(self.allocator, reveals) catch return;
        defer self.allocator.free(payload);

        var encrypted = crypto.encrypt(self.allocator, io, payload, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .reveal_set,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        for (self.voters.items) |voter| {
            protocol.sendFrame(io, voter.stream, frame) catch {};
        }
    }

    fn broadcastTally(self: *Server, json: []const u8) void {
        self.broadcastEncrypted(.tally, json);
    }

    fn broadcastEncrypted(self: *Server, msg_type: protocol.MessageType, payload: []const u8) void {
        const io = self.io;
        var encrypted = crypto.encrypt(self.allocator, io, payload, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = msg_type,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        self.voters_mutex.lockUncancelable(io);
        for (self.voters.items) |voter| {
            protocol.sendFrame(io, voter.stream, frame) catch {};
        }
        self.voters_mutex.unlock(io);
    }

    fn sendBallot(self: *Server, stream: Io.net.Stream) void {
        const io = self.io;
        const payload = protocol.serializeBallot(self.allocator, self.session_id, self.question, self.options) catch return;
        defer self.allocator.free(payload);

        var encrypted = crypto.encrypt(self.allocator, io, payload, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .ballot,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        protocol.sendFrame(io, stream, frame) catch {};
    }

    fn removeVoter(self: *Server, stream: Io.net.Stream) void {
        self.voters_mutex.lockUncancelable(self.io);
        defer self.voters_mutex.unlock(self.io);

        for (self.voters.items, 0..) |voter, i| {
            if (voter.stream.socket.handle == stream.socket.handle) {
                const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
                if (current_phase == .lobby) {
                    display.printVoterLeft(voter.nick, self.voters.items.len); // -1 after remove + host
                }
                self.allocator.free(voter.nick);
                _ = self.voters.orderedRemove(i);
                return;
            }
        }
    }

    fn resolveNickCollision(self: *Server, nick: []const u8) ![]const u8 {
        self.voters_mutex.lockUncancelable(self.io);
        defer self.voters_mutex.unlock(self.io);

        var has_collision = std.mem.eql(u8, nick, self.host_nick);
        if (!has_collision) {
            for (self.voters.items) |voter| {
                if (std.mem.eql(u8, nick, voter.nick)) {
                    has_collision = true;
                    break;
                }
            }
        }

        if (!has_collision) {
            return try self.allocator.dupe(u8, nick);
        }

        var suffix: u8 = 2;
        while (suffix < 100) : (suffix += 1) {
            const new_nick = try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ nick, suffix });
            var collision = std.mem.eql(u8, new_nick, self.host_nick);

            if (!collision) {
                for (self.voters.items) |voter| {
                    if (std.mem.eql(u8, new_nick, voter.nick)) {
                        collision = true;
                        break;
                    }
                }
            }

            if (!collision) return new_nick;
            self.allocator.free(new_nick);
        }
        return error.TooManyCollisions;
    }

    fn readHostStdin(self: *Server) void {
        const io = self.io;
        var buffer: [4096]u8 = undefined;

        while (self.running.load(.monotonic)) {
            const bytes_read = std.posix.read(std.posix.STDIN_FILENO, &buffer) catch break;
            if (bytes_read == 0) break;
            const line = std.mem.trimEnd(u8, buffer[0..bytes_read], "\n\r");
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) continue;

            const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));

            if (std.mem.eql(u8, trimmed, "/abort")) {
                display.printStatus("Vote aborted.");
                self.running.store(false, .monotonic);
                self.pokeListener();
                break;
            }

            switch (current_phase) {
                .lobby => {
                    if (std.mem.eql(u8, trimmed, "/start")) {
                        self.voters_mutex.lockUncancelable(io);
                        const count = self.voters.items.len;
                        self.voters_mutex.unlock(io);
                        if (count == 0) {
                            display.printError("Need at least one other voter to start.");
                            continue;
                        }
                        self.startCommitPhase();
                        // Unblock accept() in the main thread
                        self.pokeListener();
                    }
                },
                .commit => {
                    // Host votes by entering a number
                    const choice = std.fmt.parseInt(u8, trimmed, 10) catch continue;
                    if (choice < 1 or choice > self.options.len) {
                        display.printError("Invalid choice.");
                        continue;
                    }
                    const vote_index = choice - 1;

                    // Generate commitment
                    var blinding: [32]u8 = undefined;
                    io.random(&blinding);
                    const commitment_val = crypto.makeCommitment(vote_index, blinding);
                    const sig = crypto.signCommitment(self.roster_hash, commitment_val, self.host_keypair);

                    self.host_vote_index = vote_index;
                    self.host_blinding = blinding;
                    self.host_commitment = commitment_val;
                    self.host_commitment_sig = sig;

                    display.printStatus("Vote sealed.");

                    // Check if all commitments received
                    self.voters_mutex.lockUncancelable(io);
                    const received = self.countCommitments();
                    const total = self.voters.items.len + 1;
                    self.voters_mutex.unlock(io);

                    display.printProgress("Waiting for commitments", received, total);

                    if (received == total) {
                        self.broadcastCommitSet();
                        self.startRevealPhase();
                    }
                },
                else => {},
            }
        }
    }

    fn pokeListener(self: *Server) void {
        // Make a dummy connection to unblock accept() in the main thread
        const io = self.io;
        const addr = Io.net.IpAddress.parse("127.0.0.1", self.port) catch return;
        if (addr.connect(io, .{ .mode = .stream, .timeout = .none })) |stream| {
            stream.close(io);
        } else |_| {}
    }

    pub fn shutdown(self: *Server) void {
        const io = self.io;
        self.running.store(false, .monotonic);

        self.voters_mutex.lockUncancelable(io);
        for (self.voters.items) |voter| {
            voter.stream.close(io);
            self.allocator.free(voter.nick);
        }
        self.voters.deinit(self.allocator);
        self.voters_mutex.unlock(io);

        self.listener.deinit(io);

        std.crypto.secureZero(u8, &self.key);
    }
};
