const std = @import("std");
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");

pub const ClientConfig = struct {
    nick: []const u8,
    timeout_secs: u64 = 30,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    key: [32]u8,
    nick: []const u8,
    running: std.atomic.Value(bool),

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16, key: [32]u8, config: ClientConfig) !Client {
        const stream = try std.net.tcpConnectToHost(allocator, host, port);
        errdefer stream.close();

        // Set socket timeouts for handshake
        const timeout = std.posix.timeval{ .sec = @intCast(config.timeout_secs), .usec = 0 };
        try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));

        // Send JOIN frame
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

        // Clear socket timeout after handshake
        const no_timeout = std.posix.timeval{ .sec = 0, .usec = 0 };
        try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&no_timeout));
        try std.posix.setsockopt(stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&no_timeout));

        return Client{
            .allocator = allocator,
            .stream = stream,
            .key = key,
            .nick = config.nick,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    pub fn run(self: *Client) !void {
        const reader_thread = try std.Thread.spawn(.{}, Client.readerLoop, .{self});
        defer reader_thread.join();

        self.stdinLoop();

        self.sendLeave() catch {};
        self.running.store(false, .monotonic);
    }

    fn readerLoop(self: *Client) void {
        while (self.running.load(.monotonic)) {
            var frame = protocol.readFrame(self.allocator, self.stream) catch break;
            defer protocol.freeFrame(self.allocator, &frame);

            switch (frame.msg_type) {
                .msg => {
                    const plaintext = crypto.decryptRaw(self.allocator, frame.nonce, frame.tag, frame.ciphertext, self.key) catch continue;
                    defer {
                        std.crypto.secureZero(u8, plaintext);
                        self.allocator.free(plaintext);
                    }
                    display.printMessage(frame.timestamp, frame.sender, plaintext);
                },
                .announce => {
                    const plaintext = crypto.decryptRaw(self.allocator, frame.nonce, frame.tag, frame.ciphertext, self.key) catch continue;
                    defer {
                        std.crypto.secureZero(u8, plaintext);
                        self.allocator.free(plaintext);
                    }
                    display.printAnnouncement(frame.timestamp, plaintext);
                },
                .nick_list => {
                    const plaintext = crypto.decryptRaw(self.allocator, frame.nonce, frame.tag, frame.ciphertext, self.key) catch continue;
                    defer {
                        std.crypto.secureZero(u8, plaintext);
                        self.allocator.free(plaintext);
                    }

                    var nicks = std.ArrayList([]const u8).initCapacity(self.allocator, 0) catch continue;
                    defer nicks.deinit(self.allocator);

                    var iter = std.mem.tokenizeScalar(u8, plaintext, '\n');
                    while (iter.next()) |nick| {
                        nicks.append(self.allocator, nick) catch continue;
                    }

                    display.printNickList(nicks.items);
                },
                else => {},
            }
        }

        self.running.store(false, .monotonic);
    }

    fn stdinLoop(self: *Client) void {
        const stdin = std.fs.File.stdin();
        var buffer: [4096]u8 = undefined;

        while (self.running.load(.monotonic)) {
            const bytes_read = stdin.read(&buffer) catch break;
            if (bytes_read == 0) break;

            const line = std.mem.trimRight(u8, buffer[0..bytes_read], "\n\r");

            if (line.len == 0) continue;
            if (std.mem.eql(u8, line, "/quit")) break;

            var encrypted = crypto.encrypt(self.allocator, line, self.key) catch {
                display.printStatus("Failed to encrypt message");
                continue;
            };
            defer encrypted.deinit();

            const msg_frame = protocol.Frame{
                .msg_type = .msg,
                .timestamp = @as(u64, @intCast(std.time.timestamp())),
                .sender = self.nick,
                .nonce = encrypted.nonce,
                .tag = encrypted.tag,
                .ciphertext = encrypted.ciphertext,
            };

            protocol.writeFrame(self.stream, msg_frame) catch {
                display.printStatus("Connection lost.");
                break;
            };

            display.printMessage(msg_frame.timestamp, self.nick, line);
        }
    }

    fn sendLeave(self: *Client) !void {
        var encrypted = try crypto.encrypt(self.allocator, "goodbye", self.key);
        defer encrypted.deinit();

        const leave_frame = protocol.Frame{
            .msg_type = .leave,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        try protocol.writeFrame(self.stream, leave_frame);
    }

    pub fn disconnect(self: *Client) void {
        self.running.store(false, .monotonic);
        self.stream.close();
        std.crypto.secureZero(u8, &self.key);
    }
};
