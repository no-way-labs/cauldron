const std = @import("std");
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
    stream: std.net.Stream,
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

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16, key: [32]u8, identity: crypto.KeyPair, config: ClientConfig) !Client {
        const stream = try std.net.tcpConnectToHost(allocator, host, port);

        // Send JOIN frame with MAGIC
        var encrypted = try crypto.encrypt(allocator, protocol.MAGIC, key);
        defer encrypted.deinit();

        const join_frame = protocol.Frame{
            .msg_type = .join,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .sender = config.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        try protocol.writeFrame(stream, join_frame);

        var client = Client{
            .allocator = allocator,
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
        var encrypted = crypto.encrypt(self.allocator, &pk_bytes, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .pubkey,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.writeFrame(self.stream, frame) catch {};
    }

    pub fn run(self: *Client) !void {
        while (self.running.load(.monotonic)) {
            const frame = protocol.readFrame(self.allocator, self.stream) catch {
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

        var encrypted = crypto.encrypt(self.allocator, &sig, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .signature,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };
        protocol.writeFrame(self.stream, frame) catch return;
    }

    fn handleCovenant(self: *Client, data: []const u8) void {
        display.printCovenantComplete(if (self.roster) |r| r.len else 0);

        if (self.output_path) |path| {
            const file = std.fs.cwd().createFile(path, .{}) catch |err| {
                std.debug.print("Error: cannot write {s}: {}\n", .{ path, err });
                self.running.store(false, .monotonic);
                return;
            };
            defer file.close();
            file.writeAll(data) catch {};
            file.writeAll("\n") catch {};
            std.debug.print("\x1b[38;5;245mCovenant saved to:\x1b[0m {s}\n", .{path});
        } else {
            const stdout = std.fs.File.stdout();
            stdout.writeAll(data) catch {};
            stdout.writeAll("\n") catch {};
        }

        self.running.store(false, .monotonic);
    }

    pub fn disconnect(self: *Client) void {
        self.running.store(false, .monotonic);
        self.stream.close();

        if (self.group_name) |name| self.allocator.free(name);
        if (self.roster) |r| {
            for (r) |m| self.allocator.free(m.nick);
            self.allocator.free(r);
        }

        std.crypto.secureZero(u8, &self.key);
    }
};
