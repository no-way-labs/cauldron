const std = @import("std");
const Io = std.Io;
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");

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
    identity: crypto.KeyPair,
    running: std.atomic.Value(bool),
    // Protocol state
    roster: ?[]protocol.MemberInfo,
    roster_hash: [32]u8,
    group_name: ?[]const u8,
    // Output
    output_path: ?[]const u8,

    pub fn connect(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16, key: [32]u8, identity: crypto.KeyPair, config: ClientConfig) !Client {
        const stream = try connectToHost(io, host, port);

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
            .identity = identity,
            .running = std.atomic.Value(bool).init(true),
            .roster = null,
            .roster_hash = [_]u8{0} ** 32,
            .group_name = null,
            .output_path = config.output_path,
        };

        // Send identity pubkey
        client.sendPubkey();

        return client;
    }

    fn sendPubkey(self: *Client) void {
        const pk_bytes = crypto.publicKeyBytes(self.identity);
        var encrypted = crypto.encrypt(self.allocator, self.io, &pk_bytes, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .pubkey,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.sendFrame(self.io, self.stream, frame) catch {};
    }

    pub fn run(self: *Client) !void {
        // One persistent reader for the whole connection: the interface buffers
        // ahead, so a transient reader per frame would drop bytes.
        var read_buf: [8192]u8 = undefined;
        var stream_reader = self.stream.reader(self.io, &read_buf);
        const in = &stream_reader.interface;

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
                .phase => {
                    // During lobby, first phase message is group info
                    if (self.group_name == null and self.roster == null) {
                        self.group_name = self.allocator.dupe(u8, plaintext) catch null;
                        if (self.group_name) |name| {
                            display.printGroupName(name);
                        }
                        display.printStatus("Waiting for host to seal...");
                    } else {
                        self.handlePhase(plaintext);
                    }
                },
                .roster => self.handleRoster(plaintext),
                .covenant => self.handleCovenant(plaintext),
                .abort => {
                    display.printError("Ceremony aborted by host.");
                    self.running.store(false, .monotonic);
                },
                else => {},
            }
        }
    }

    fn handleRoster(self: *Client, data: []const u8) void {
        const members = protocol.deserializeRoster(self.allocator, data) catch return;
        self.roster = members;
        self.roster_hash = crypto.computeRosterHash(members);

        // Display roster
        std.debug.print("\n\x1b[38;5;245mRoster ({d} members):\x1b[0m\n", .{members.len});
        for (members) |m| {
            // Show first 8 hex chars of pubkey
            const pk = m.pubkey;
            std.debug.print("  \x1b[38;5;45m*\x1b[0m {s}  \x1b[38;5;240m{x:0>2}{x:0>2}{x:0>2}{x:0>2}...\x1b[0m\n", .{
                m.nick, pk[0], pk[1], pk[2], pk[3],
            });
        }
    }

    fn handlePhase(self: *Client, data: []const u8) void {
        if (data.len < 1) return;
        const phase: protocol.Phase = @enumFromInt(data[0]);

        switch (phase) {
            .seal => {
                display.printStatus("Signing roster...");
                self.signAndSend();
                display.printStatus("Signature sent. Waiting for all signatures...");
            },
            else => {},
        }
    }

    fn signAndSend(self: *Client) void {
        // Sign the roster hash with our identity key
        const sig = crypto.signRoster(self.roster_hash, self.identity);

        var encrypted = crypto.encrypt(self.allocator, self.io, &sig, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .signature,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.sendFrame(self.io, self.stream, frame) catch return;
    }

    fn handleCovenant(self: *Client, data: []const u8) void {
        display.printCovenantComplete(if (self.roster) |r| r.len else 0);

        if (self.output_path) |path| {
            const file = Io.Dir.cwd().createFile(self.io, path, .{}) catch |err| {
                std.debug.print("Error: cannot write {s}: {}\n", .{ path, err });
                self.running.store(false, .monotonic);
                return;
            };
            defer file.close(self.io);
            file.writeStreamingAll(self.io, data) catch {};
            file.writeStreamingAll(self.io, "\n") catch {};
            std.debug.print("\x1b[38;5;245mCovenant saved to:\x1b[0m {s}\n", .{path});
        } else {
            const stdout = Io.File.stdout();
            stdout.writeStreamingAll(self.io, data) catch {};
            stdout.writeStreamingAll(self.io, "\n") catch {};
        }

        self.running.store(false, .monotonic);
    }

    pub fn disconnect(self: *Client) void {
        self.running.store(false, .monotonic);
        self.stream.close(self.io);

        if (self.group_name) |name| self.allocator.free(name);
        if (self.roster) |r| {
            for (r) |m| self.allocator.free(m.nick);
            self.allocator.free(r);
        }

        std.crypto.secureZero(u8, &self.key);
    }
};

/// Connect to host:port. Do NOT pass a connect timeout: Io.Threaded in Zig
/// 0.16.0 panics "TODO implement netConnectIpPosix with timeout", so the
/// connect is bounded only by the OS default (matching pre-0.16 behavior).
fn connectToHost(io: Io, host: []const u8, port: u16) !Io.net.Stream {
    if (Io.net.IpAddress.parse(host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream, .timeout = .none });
    } else |_| {
        const host_name = try Io.net.HostName.init(host);
        return host_name.connect(io, port, .{ .mode = .stream, .timeout = .none });
    }
}
