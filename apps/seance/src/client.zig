const std = @import("std");
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const bot_mod = @import("bot.zig");

pub const BufferedMessage = struct {
    id: u64,
    timestamp: u64,
    sender: []const u8,
    content: []const u8,
    msg_type: []const u8,
};

pub const MessageBuffer = struct {
    messages: std.ArrayListUnmanaged(BufferedMessage),
    mutex: std.Thread.Mutex,
    next_id: u64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MessageBuffer {
        return .{
            .messages = .{},
            .mutex = .{},
            .next_id = 1,
            .allocator = allocator,
        };
    }

    pub fn append(self: *MessageBuffer, timestamp: u64, sender: []const u8, content: []const u8, msg_type: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const owned_sender = self.allocator.dupe(u8, sender) catch return;
        const owned_content = self.allocator.dupe(u8, content) catch {
            self.allocator.free(owned_sender);
            return;
        };
        const owned_type = self.allocator.dupe(u8, msg_type) catch {
            self.allocator.free(owned_sender);
            self.allocator.free(owned_content);
            return;
        };

        self.messages.append(self.allocator, .{
            .id = self.next_id,
            .timestamp = timestamp,
            .sender = owned_sender,
            .content = owned_content,
            .msg_type = owned_type,
        }) catch {
            self.allocator.free(owned_sender);
            self.allocator.free(owned_content);
            self.allocator.free(owned_type);
            return;
        };
        self.next_id += 1;
    }

    pub fn hasMessagesSince(self: *MessageBuffer, since_id: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.next_id > since_id + 1;
    }

    pub fn getSince(self: *MessageBuffer, since_id: u64, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var json = try std.ArrayList(u8).initCapacity(allocator, 0);
        errdefer json.deinit(allocator);

        try json.append(allocator, '[');
        var first = true;
        for (self.messages.items) |msg| {
            if (msg.id <= since_id) continue;
            if (!first) try json.append(allocator, ',');
            first = false;

            try json.appendSlice(allocator, "{\"id\":");
            var id_buf: [20]u8 = undefined;
            const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{msg.id}) catch continue;
            try json.appendSlice(allocator, id_str);

            try json.appendSlice(allocator, ",\"timestamp\":");
            var ts_buf: [20]u8 = undefined;
            const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{msg.timestamp}) catch continue;
            try json.appendSlice(allocator, ts_str);

            try json.appendSlice(allocator, ",\"sender\":\"");
            try appendJsonEscaped(&json, allocator, msg.sender);
            try json.appendSlice(allocator, "\",\"content\":\"");
            try appendJsonEscaped(&json, allocator, msg.content);
            try json.appendSlice(allocator, "\",\"type\":\"");
            try json.appendSlice(allocator, msg.msg_type);
            try json.appendSlice(allocator, "\"}");
        }
        try json.append(allocator, ']');

        return json.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *MessageBuffer) void {
        for (self.messages.items) |msg| {
            self.allocator.free(msg.sender);
            self.allocator.free(msg.content);
            self.allocator.free(msg.msg_type);
        }
        self.messages.deinit(self.allocator);
    }
};

fn appendJsonEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, input: []const u8) !void {
    for (input) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const s = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch continue;
                    try list.appendSlice(allocator, s);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
}

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
    msg_buffer: ?*MessageBuffer,
    peers: std.ArrayListUnmanaged([]const u8),
    peers_mutex: std.Thread.Mutex,
    stream_mutex: std.Thread.Mutex,

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
            .msg_buffer = null,
            .peers = .{},
            .peers_mutex = .{},
            .stream_mutex = .{},
        };
    }

    pub fn run(self: *Client) !void {
        const reader_thread = try std.Thread.spawn(.{}, Client.readerLoop, .{self});
        defer reader_thread.join();

        self.stdinLoop();

        self.sendLeave() catch {};
        self.running.store(false, .monotonic);
    }

    pub fn runBot(self: *Client, api_port: u16, run_familiar: bool) !void {
        var buffer = MessageBuffer.init(self.allocator);
        self.msg_buffer = &buffer;
        defer {
            buffer.deinit();
            self.msg_buffer = null;
        }

        const reader_thread = try std.Thread.spawn(.{}, Client.readerLoop, .{self});
        defer reader_thread.join();

        var api_server = bot_mod.ApiServer.init(self, api_port) catch |err| {
            std.debug.print("Failed to start bot API: {}\n", .{err});
            return err;
        };
        defer api_server.deinit();

        const api_thread = try std.Thread.spawn(.{}, bot_mod.ApiServer.run, .{&api_server});
        _ = api_thread;

        // Spawn familiar process if requested
        var familiar_proc: ?std.process.Child = null;
        if (run_familiar) {
            // Find familiar binary next to our own executable
            var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
            const familiar_path = blk: {
                const exe_path = std.fs.selfExePath(&exe_buf) catch break :blk null;
                // Replace trailing "seance" with "familiar"
                if (std.mem.lastIndexOfScalar(u8, exe_path, '/')) |sep| {
                    const dir = exe_path[0 .. sep + 1];
                    const familiar_name = "familiar";
                    if (dir.len + familiar_name.len <= exe_buf.len) {
                        @memcpy(exe_buf[dir.len .. dir.len + familiar_name.len], familiar_name);
                        break :blk exe_buf[0 .. dir.len + familiar_name.len];
                    }
                }
                break :blk null;
            };

            var port_buf: [8]u8 = undefined;
            const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{api_port}) catch unreachable;
            const argv_path: []const u8 = familiar_path orelse "familiar";
            var proc = std.process.Child.init(
                &.{ argv_path, "--api-port", port_str },
                self.allocator,
            );
            proc.stdout_behavior = .Inherit;
            proc.stderr_behavior = .Inherit;
            if (proc.spawn()) {
                familiar_proc = proc;
            } else |err| {
                std.debug.print("Failed to start familiar: {}\n", .{err});
                if (familiar_path) |p| {
                    std.debug.print("Tried: {s}\n", .{p});
                } else {
                    std.debug.print("Make sure 'familiar' is in your PATH\n", .{});
                }
            }
        }
        defer {
            if (familiar_proc) |*proc| {
                std.posix.kill(proc.id, std.posix.SIG.TERM) catch {};
                _ = proc.wait() catch {};
            }
        }

        // Block until shutdown
        while (self.running.load(.monotonic)) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }

        self.sendLeave() catch {};
        api_server.stop();
    }

    pub fn sendMessage(self: *Client, text: []const u8) !void {
        var encrypted = try crypto.encrypt(self.allocator, text, self.key);
        defer encrypted.deinit();

        const msg_frame = protocol.Frame{
            .msg_type = .msg,
            .timestamp = @as(u64, @intCast(std.time.timestamp())),
            .sender = self.nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        self.stream_mutex.lock();
        defer self.stream_mutex.unlock();
        try protocol.writeFrame(self.stream, msg_frame);

        display.printMessage(msg_frame.timestamp, self.nick, text);
    }

    pub fn getPeers(self: *Client, allocator: std.mem.Allocator) ![]u8 {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        var json = try std.ArrayList(u8).initCapacity(allocator, 0);
        errdefer json.deinit(allocator);

        try json.append(allocator, '[');
        for (self.peers.items, 0..) |peer, i| {
            if (i > 0) try json.append(allocator, ',');
            try json.append(allocator, '"');
            try appendJsonEscaped(&json, allocator, peer);
            try json.append(allocator, '"');
        }
        try json.append(allocator, ']');

        return json.toOwnedSlice(allocator);
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

                    if (self.msg_buffer) |buf| {
                        buf.append(frame.timestamp, frame.sender, plaintext, "msg");
                    }
                },
                .announce => {
                    const plaintext = crypto.decryptRaw(self.allocator, frame.nonce, frame.tag, frame.ciphertext, self.key) catch continue;
                    defer {
                        std.crypto.secureZero(u8, plaintext);
                        self.allocator.free(plaintext);
                    }
                    display.printAnnouncement(frame.timestamp, plaintext);

                    if (self.msg_buffer) |buf| {
                        const msg_type: []const u8 = if (std.mem.endsWith(u8, plaintext, " joined"))
                            "join"
                        else if (std.mem.endsWith(u8, plaintext, " left"))
                            "leave"
                        else
                            "announce";
                        buf.append(frame.timestamp, frame.sender, plaintext, msg_type);
                    }

                    self.updatePeersFromAnnouncement(plaintext);
                },
                .nick_list => {
                    const plaintext = crypto.decryptRaw(self.allocator, frame.nonce, frame.tag, frame.ciphertext, self.key) catch continue;
                    defer {
                        std.crypto.secureZero(u8, plaintext);
                        self.allocator.free(plaintext);
                    }

                    var nicks = std.ArrayListUnmanaged([]const u8){};
                    defer nicks.deinit(self.allocator);

                    var iter = std.mem.tokenizeScalar(u8, plaintext, '\n');
                    while (iter.next()) |nick| {
                        nicks.append(self.allocator, nick) catch continue;
                    }

                    display.printNickList(nicks.items);
                    self.setPeers(nicks.items);
                },
                else => {},
            }
        }

        self.running.store(false, .monotonic);
    }

    fn stdinLoop(self: *Client) void {
        const stdin = std.fs.File.stdin();

        // Enable raw mode so we own the input buffer
        var original_termios: std.posix.termios = undefined;
        const raw_mode = if (std.posix.isatty(stdin.handle)) blk: {
            original_termios = std.posix.tcgetattr(stdin.handle) catch break :blk false;
            var raw = original_termios;
            raw.lflag.ECHO = false;
            raw.lflag.ICANON = false;
            raw.lflag.ISIG = false;
            raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
            raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
            std.posix.tcsetattr(stdin.handle, .FLUSH, raw) catch break :blk false;
            break :blk true;
        } else false;
        defer if (raw_mode) {
            std.posix.tcsetattr(stdin.handle, .FLUSH, original_termios) catch {};
        };

        if (raw_mode) {
            var submit_buf: [4096]u8 = undefined;
            while (self.running.load(.monotonic)) {
                var byte_buf: [1]u8 = undefined;
                const n = stdin.read(&byte_buf) catch break;
                if (n == 0) break;
                const byte = byte_buf[0];

                switch (byte) {
                    3, 4 => break, // Ctrl+C, Ctrl+D
                    '\r', '\n' => {
                        const line = display.inputSubmit(&submit_buf);
                        if (line.len == 0) continue;
                        if (std.mem.eql(u8, line, "/quit")) break;
                        self.sendMessage(line) catch {
                            display.printStatus("Connection lost.");
                            break;
                        };
                    },
                    127, 8 => display.inputBackspace(),
                    21 => display.inputClear(), // Ctrl+U
                    1 => display.inputHome(), // Ctrl+A
                    5 => display.inputEnd(), // Ctrl+E
                    27 => display.handleEscapeSeq(stdin), // ESC
                    else => {
                        if (byte >= 32) display.inputChar(byte);
                    },
                }
            }
        } else {
            var buffer: [4096]u8 = undefined;
            while (self.running.load(.monotonic)) {
                const bytes_read = stdin.read(&buffer) catch break;
                if (bytes_read == 0) break;
                const line = std.mem.trimRight(u8, buffer[0..bytes_read], "\n\r");
                if (line.len == 0) continue;
                if (std.mem.eql(u8, line, "/quit")) break;
                self.sendMessage(line) catch {
                    display.printStatus("Connection lost.");
                    break;
                };
            }
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

        self.stream_mutex.lock();
        defer self.stream_mutex.unlock();
        try protocol.writeFrame(self.stream, leave_frame);
    }

    fn setPeers(self: *Client, nicks: []const []const u8) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        for (self.peers.items) |p| {
            self.allocator.free(p);
        }
        self.peers.clearRetainingCapacity();

        for (nicks) |nick| {
            const owned = self.allocator.dupe(u8, nick) catch continue;
            self.peers.append(self.allocator, owned) catch {
                self.allocator.free(owned);
                continue;
            };
        }
    }

    fn updatePeersFromAnnouncement(self: *Client, text: []const u8) void {
        if (std.mem.endsWith(u8, text, " joined")) {
            const nick = text[0 .. text.len - " joined".len];
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            // Check for duplicate (nick_list may have already added this peer)
            for (self.peers.items) |peer| {
                if (std.mem.eql(u8, peer, nick)) return;
            }
            const owned = self.allocator.dupe(u8, nick) catch return;
            self.peers.append(self.allocator, owned) catch {
                self.allocator.free(owned);
            };
        } else if (std.mem.endsWith(u8, text, " left")) {
            const nick = text[0 .. text.len - " left".len];
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            for (self.peers.items, 0..) |peer, i| {
                if (std.mem.eql(u8, peer, nick)) {
                    self.allocator.free(peer);
                    _ = self.peers.orderedRemove(i);
                    return;
                }
            }
        }
    }

    pub fn disconnect(self: *Client) void {
        self.running.store(false, .monotonic);
        self.stream.close();
        std.crypto.secureZero(u8, &self.key);

        self.peers_mutex.lock();
        for (self.peers.items) |p| {
            self.allocator.free(p);
        }
        self.peers.deinit(self.allocator);
        self.peers_mutex.unlock();
    }
};
