const std = @import("std");
const Io = std.Io;
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const verify_mod = @import("verify.zig");

pub const ClientConfig = struct {
    nick: []const u8,
    timeout_secs: u64 = 30,
    output_path: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: Io.net.Stream,
    key: [32]u8,
    nick: []const u8,
    keypair: crypto.KeyPair,
    running: std.atomic.Value(bool),
    // Ballot info (received from host)
    session_id: [32]u8,
    question: ?[]const u8,
    options: ?[]const []const u8,
    // Protocol state
    roster: ?[]protocol.PeerInfo,
    roster_hash: [32]u8,
    my_slot_id: u8,
    // Vote data
    vote_index: ?u8,
    blinding_factor: ?[32]u8,
    my_commitment: ?[32]u8,
    // Received data
    commitments: ?[]protocol.Commitment,
    reveals: ?[]protocol.Reveal,
    // Output
    output_path: ?[]const u8,

    pub fn connect(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16, key: [32]u8, keypair: crypto.KeyPair, config: ClientConfig) !Client {
        // Do NOT pass a connect timeout: Io.Threaded in Zig 0.16.0 panics
        // "TODO implement netConnectIpPosix with timeout".
        const stream = try connectToHost(io, host, port, .none);

        // Send JOIN frame with MAGIC
        var encrypted = try crypto.encrypt(allocator, io, protocol.MAGIC, key);
        defer encrypted.deinit();

        const join_frame = protocol.Frame{
            .msg_type = .join,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = config.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        try protocol.sendFrame(io, stream, join_frame);

        var client = Client{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .key = key,
            .nick = config.nick,
            .keypair = keypair,
            .running = std.atomic.Value(bool).init(true),
            .session_id = [_]u8{0} ** 32,
            .question = null,
            .options = null,
            .roster = null,
            .roster_hash = [_]u8{0} ** 32,
            .my_slot_id = 0,
            .vote_index = null,
            .blinding_factor = null,
            .my_commitment = null,
            .commitments = null,
            .reveals = null,
            .output_path = config.output_path,
        };

        // Send pubkey
        client.sendPubkey();

        return client;
    }

    fn sendPubkey(self: *Client) void {
        const io = self.io;
        const pk_bytes = crypto.publicKeyBytes(self.keypair);
        var encrypted = crypto.encrypt(self.allocator, io, &pk_bytes, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .pubkey,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.sendFrame(io, self.stream, frame) catch {};
    }

    pub fn run(self: *Client) !void {
        const io = self.io;

        // ONE persistent reader for the connection: the interface buffers ahead,
        // so every readFrame must share it.
        var read_buf: [8192]u8 = undefined;
        var stream_reader = self.stream.reader(io, &read_buf);
        const in = &stream_reader.interface;

        // Read loop - process messages from server
        while (self.running.load(.monotonic)) {
            const frame = protocol.readFrame(self.allocator, in) catch {
                break;
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
                .ballot => self.handleBallot(plaintext),
                .peer_list => self.handlePeerList(plaintext),
                .phase => self.handlePhase(plaintext),
                .commit_set => self.handleCommitSet(plaintext),
                .reveal_set => self.handleRevealSet(plaintext),
                .tally => self.handleTally(plaintext),
                .abort => {
                    display.printError("Vote aborted by host.");
                    self.running.store(false, .monotonic);
                },
                else => {},
            }
        }
    }

    fn handleBallot(self: *Client, data: []const u8) void {
        const ballot = protocol.deserializeBallot(self.allocator, data) catch return;

        self.session_id = ballot.session_id;
        self.question = ballot.question;
        self.options = ballot.options;

        std.debug.print("\n", .{});
        display.printBallot(ballot.question, ballot.options);
        display.printStatus("\nWaiting for host to start...");
    }

    fn handlePeerList(self: *Client, data: []const u8) void {
        const peers = protocol.deserializePeerList(self.allocator, data) catch return;

        // Find my slot ID
        for (peers) |peer| {
            if (std.mem.eql(u8, peer.nick, self.nick)) {
                self.my_slot_id = peer.slot_id;
                break;
            }
        }

        self.roster = peers;
        self.roster_hash = crypto.computeRosterHash(peers);
    }

    fn handlePhase(self: *Client, data: []const u8) void {
        if (data.len < 33) return;
        const phase: protocol.Phase = @enumFromInt(data[0]);
        var received_hash: [32]u8 = undefined;
        @memcpy(&received_hash, data[1..33]);

        // Verify roster hash matches
        if (!std.mem.eql(u8, &received_hash, &self.roster_hash)) {
            display.printError("Roster hash mismatch! Possible tampering.");
            self.running.store(false, .monotonic);
            return;
        }

        switch (phase) {
            .commit => {
                const voter_count = if (self.roster) |r| r.len else 0;
                display.printPhaseStart("Vote started", voter_count);
                self.promptAndCommit();
            },
            .reveal => {
                display.printStatus("Sending reveal...");
                self.sendReveal();
                display.printStatus("Waiting for results...");
            },
            else => {},
        }
    }

    fn promptAndCommit(self: *Client) void {
        const io = self.io;
        const opts = self.options orelse return;
        display.printVotePrompt(opts);

        // Read vote from stdin
        var buffer: [64]u8 = undefined;
        const bytes_read = std.posix.read(std.posix.STDIN_FILENO, &buffer) catch return;
        if (bytes_read == 0) return;
        const line = std.mem.trimEnd(u8, buffer[0..bytes_read], "\n\r");
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);

        const choice = std.fmt.parseInt(u8, trimmed, 10) catch {
            display.printError("Invalid choice.");
            return;
        };
        if (choice < 1 or choice > opts.len) {
            display.printError("Invalid choice.");
            return;
        }
        const vote_index = choice - 1;

        // Generate commitment
        var blinding: [32]u8 = undefined;
        io.random(&blinding);
        const commitment_val = crypto.makeCommitment(vote_index, blinding);
        const sig = crypto.signCommitment(self.roster_hash, commitment_val, self.keypair);

        self.vote_index = vote_index;
        self.blinding_factor = blinding;
        self.my_commitment = commitment_val;

        // Send commitment
        var payload: [96]u8 = undefined;
        @memcpy(payload[0..32], &commitment_val);
        @memcpy(payload[32..96], &sig);

        var encrypted = crypto.encrypt(self.allocator, io, &payload, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .commitment,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.sendFrame(io, self.stream, frame) catch return;

        display.printStatus("Vote sealed. Waiting for all commitments...");
    }

    fn handleCommitSet(self: *Client, data: []const u8) void {
        const result = protocol.deserializeCommitSet(self.allocator, data) catch return;

        // Verify the commit set
        verify_mod.verifyCommitSet(
            result.commitments,
            result.set_hash,
            self.roster orelse return,
            self.roster_hash,
            self.my_slot_id,
            self.my_commitment,
        ) catch |err| {
            std.debug.print("Commit set verification failed: {}\n", .{err});
            display.printError("Commitment verification failed! Possible tampering.");
            self.running.store(false, .monotonic);
            return;
        };

        self.commitments = result.commitments;
        display.printStatus("Verified.");
    }

    fn sendReveal(self: *Client) void {
        const io = self.io;
        const vi = self.vote_index orelse return;
        const bl = self.blinding_factor orelse return;

        var payload: [33]u8 = undefined;
        payload[0] = vi;
        @memcpy(payload[1..33], &bl);

        var encrypted = crypto.encrypt(self.allocator, io, &payload, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .reveal,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(io).toSeconds())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.sendFrame(io, self.stream, frame) catch return;
    }

    fn handleRevealSet(self: *Client, data: []const u8) void {
        const reveals = protocol.deserializeRevealSet(self.allocator, data) catch return;

        // Refuse to tally reveals we cannot check against a verified commit set.
        // A malicious host that withholds/corrupts the commit_set from a targeted
        // client must not be able to make it display an unverified tally.
        const commitments = self.commitments orelse {
            self.allocator.free(reveals);
            display.printError("No verified commit set — refusing to tally (possible tampering).");
            self.running.store(false, .monotonic);
            return;
        };

        // Verify bijection
        verify_mod.verifyRevealSet(reveals, commitments) catch |err| {
            std.debug.print("Reveal set verification failed: {}\n", .{err});
            display.printError("Reveal verification failed! Possible tampering.");
            self.allocator.free(reveals);
            self.running.store(false, .monotonic);
            return;
        };

        self.reveals = reveals;

        // Compute local tally
        const opts = self.options orelse return;
        const counts_owned = self.allocator.alloc(u32, opts.len) catch return;
        defer self.allocator.free(counts_owned);
        verify_mod.computeTally(reveals, @intCast(opts.len), counts_owned);

        display.printResults(self.question orelse "?", opts, counts_owned, reveals.len);
    }

    fn handleTally(self: *Client, data: []const u8) void {
        const io = self.io;
        if (self.output_path) |path| {
            const file = Io.Dir.cwd().createFile(io, path, .{}) catch |err| {
                std.debug.print("Error: cannot write {s}: {}\n", .{ path, err });
                self.running.store(false, .monotonic);
                return;
            };
            defer file.close(io);
            file.writeStreamingAll(io, data) catch {};
            file.writeStreamingAll(io, "\n") catch {};
            std.debug.print("\x1b[38;5;245mArtifact saved to:\x1b[0m {s}\n", .{path});
        } else {
            Io.File.stdout().writeStreamingAll(io, data) catch {};
            Io.File.stdout().writeStreamingAll(io, "\n") catch {};
        }

        self.running.store(false, .monotonic);
    }

    pub fn disconnect(self: *Client) void {
        self.running.store(false, .monotonic);
        self.stream.close(self.io);

        // Free allocated data
        if (self.question) |q| self.allocator.free(q);
        if (self.options) |opts| {
            for (opts) |opt| self.allocator.free(opt);
            self.allocator.free(opts);
        }
        if (self.roster) |r| {
            for (r) |peer| self.allocator.free(peer.nick);
            self.allocator.free(r);
        }
        if (self.commitments) |c| self.allocator.free(c);
        if (self.reveals) |r| self.allocator.free(r);

        std.crypto.secureZero(u8, &self.key);
    }
};

fn connectToHost(io: Io, host: []const u8, port: u16, timeout: Io.Timeout) !Io.net.Stream {
    if (Io.net.IpAddress.parse(host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream, .timeout = timeout });
    } else |_| {
        const host_name = try Io.net.HostName.init(host);
        return host_name.connect(io, port, .{ .mode = .stream, .timeout = timeout });
    }
}
