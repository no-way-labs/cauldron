const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");

const Peer = struct {
    stream: Io.net.Stream,
    nick: []const u8,
    join_time: i64,
    message_count: u32,
    rate_window_start: i64,
};

pub const ServerConfig = struct {
    port: u16,
    max_peers: u8 = 8,
    local_only: bool = false,
};

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

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    port: u16,
    config: ServerConfig,
    key: [32]u8,
    host_nick: []const u8,
    peers: std.ArrayList(Peer),
    peers_mutex: std.Io.Mutex,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, io: Io, config: ServerConfig, key: [32]u8, host_nick: []const u8) !Server {
        const address = Io.net.IpAddress.parse("127.0.0.1", config.port) catch unreachable;
        var listener = try address.listen(io, .{
            .reuse_address = true,
        });
        errdefer listener.deinit(io);

        // When asked for port 0 the kernel picks one; report the real port.
        const actual_port = if (config.port != 0) config.port else boundPort(listener.socket.handle) orelse
            return error.PortDiscoveryFailed;

        return Server{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .port = actual_port,
            .config = config,
            .key = key,
            .host_nick = host_nick,
            .peers = try std.ArrayList(Peer).initCapacity(allocator, 0),
            .peers_mutex = .init,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    pub fn run(self: *Server) !void {
        display.printStatus("Server started. Type messages or /quit to exit.");

        const stdin_thread = std.Thread.spawn(.{}, Server.readHostStdin, .{self}) catch |err| {
            std.debug.print("Failed to spawn stdin thread: {}\n", .{err});
            return err;
        };
        defer stdin_thread.detach();

        while (self.running.load(.monotonic)) {
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
    }

    fn handleConnection(self: *Server, stream: Io.net.Stream) void {
        const io = self.io;
        defer stream.close(io);

        // Slow-loris guard: bound the handshake read so a connection that never
        // sends a valid JOIN can't pin this thread indefinitely. Cleared once the
        // peer is admitted (see below) so idle-but-connected chatters aren't dropped.
        const handshake_tv = std.posix.timeval{ .sec = 30, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&handshake_tv)) catch {};

        // One persistent reader per connection: the interface buffers ahead, so a
        // fresh reader per frame would drop already-received bytes.
        var read_buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(io, &read_buf);
        const in = &stream_reader.interface;

        // Read JOIN frame
        const join_frame = protocol.readFrame(self.allocator, in) catch |err| {
            std.debug.print("Failed to read JOIN frame: {}\n", .{err});
            return;
        };
        defer {
            var mutable_frame = join_frame;
            protocol.freeFrame(self.allocator, &mutable_frame);
        }

        if (join_frame.msg_type != .join) {
            std.debug.print("Expected JOIN frame, got {}\n", .{join_frame.msg_type});
            return;
        }

        // Decrypt and verify MAGIC
        const plaintext = crypto.decryptRaw(
            self.allocator,
            join_frame.nonce,
            join_frame.tag,
            join_frame.ciphertext,
            self.key,
        ) catch |err| {
            std.debug.print("Failed to decrypt JOIN: {}\n", .{err});
            return;
        };
        defer self.allocator.free(plaintext);

        if (plaintext.len != protocol.MAGIC.len or !std.crypto.timing_safe.eql([protocol.MAGIC.len]u8, plaintext[0..protocol.MAGIC.len].*, protocol.MAGIC[0..protocol.MAGIC.len].*)) {
            std.debug.print("Invalid magic in JOIN frame\n", .{});
            return;
        }

        // Check peer limit
        self.peers_mutex.lockUncancelable(io);
        const peer_count = self.peers.items.len;
        self.peers_mutex.unlock(io);

        if (peer_count >= self.config.max_peers) {
            std.debug.print("Peer limit reached, rejecting connection\n", .{});
            return;
        }

        // Resolve nickname collision - always returns an owned copy
        const nick = self.resolveNickCollision(join_frame.sender) catch |err| {
            std.debug.print("Failed to resolve nick collision: {}\n", .{err});
            return;
        };

        // Add peer to list
        const now = Io.Clock.real.now(io).toSeconds();
        const peer = Peer{
            .stream = stream,
            .nick = nick,
            .join_time = now,
            .message_count = 0,
            .rate_window_start = now,
        };

        self.peers_mutex.lockUncancelable(io);
        self.peers.append(self.allocator, peer) catch |err| {
            self.peers_mutex.unlock(io);
            self.allocator.free(nick);
            std.debug.print("Failed to add peer: {}\n", .{err});
            return;
        };
        self.peers_mutex.unlock(io);

        // Handshake complete: clear the recv timeout so an idle-but-connected
        // peer isn't disconnected while simply waiting for others to talk.
        const clear_tv = std.posix.timeval{ .sec = 0, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&clear_tv)) catch {};

        // Send nick list to new joiner
        self.sendNickList(stream);

        // Broadcast join announcement
        self.broadcastAnnounce(nick, " joined");
        display.printAnnouncement(@as(u64, @intCast(now)), nick);

        // Enter peer read loop
        self.peerReadLoop(in, stream, nick);

        // Cleanup: remove peer and announce departure
        self.removePeer(stream);
        self.broadcastAnnounce(nick, " left");
        display.printAnnouncement(@as(u64, @intCast(Io.Clock.real.now(io).toSeconds())), nick);
    }

    fn peerReadLoop(self: *Server, in: *Io.Reader, stream: Io.net.Stream, nick: []const u8) void {
        while (self.running.load(.monotonic)) {
            const frame = protocol.readFrame(self.allocator, in) catch {
                return;
            };
            defer {
                var mutable_frame = frame;
                protocol.freeFrame(self.allocator, &mutable_frame);
            }

            switch (frame.msg_type) {
                .msg => {
                    if (!self.checkPeerRateLimit(stream)) {
                        continue;
                    }

                    // Relay to all other peers
                    self.relayMessage(frame, stream);

                    // Decrypt and display on host terminal
                    const msg_plaintext = crypto.decryptRaw(
                        self.allocator,
                        frame.nonce,
                        frame.tag,
                        frame.ciphertext,
                        self.key,
                    ) catch {
                        continue;
                    };
                    defer self.allocator.free(msg_plaintext);

                    display.printMessage(frame.timestamp, nick, msg_plaintext);
                },
                .leave => {
                    return;
                },
                else => {},
            }
        }
    }

    fn relayMessage(self: *Server, frame: protocol.Frame, sender_stream: Io.net.Stream) void {
        self.peers_mutex.lockUncancelable(self.io);
        defer self.peers_mutex.unlock(self.io);

        for (self.peers.items) |peer| {
            if (peer.stream.socket.handle == sender_stream.socket.handle) continue;

            protocol.sendFrame(self.io, peer.stream, frame) catch continue;
        }
    }

    fn broadcastAnnounce(self: *Server, nick: []const u8, suffix: []const u8) void {
        const message = std.fmt.allocPrint(self.allocator, "{s}{s}", .{ nick, suffix }) catch return;
        defer self.allocator.free(message);

        var encrypted = crypto.encrypt(self.allocator, self.io, message, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .announce,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        self.peers_mutex.lockUncancelable(self.io);
        defer self.peers_mutex.unlock(self.io);

        for (self.peers.items) |peer| {
            protocol.sendFrame(self.io, peer.stream, frame) catch continue;
        }
    }

    fn sendNickList(self: *Server, stream: Io.net.Stream) void {
        var nick_list = std.ArrayList(u8).initCapacity(self.allocator, 0) catch return;
        defer nick_list.deinit(self.allocator);

        // Add host nick first
        nick_list.appendSlice(self.allocator, self.host_nick) catch return;
        nick_list.append(self.allocator, '\n') catch return;

        // Add all peer nicks
        self.peers_mutex.lockUncancelable(self.io);
        for (self.peers.items) |peer| {
            nick_list.appendSlice(self.allocator, peer.nick) catch {
                self.peers_mutex.unlock(self.io);
                return;
            };
            nick_list.append(self.allocator, '\n') catch {
                self.peers_mutex.unlock(self.io);
                return;
            };
        }
        self.peers_mutex.unlock(self.io);

        var encrypted = crypto.encrypt(self.allocator, self.io, nick_list.items, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .nick_list,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        protocol.sendFrame(self.io, stream, frame) catch {};
    }

    fn removePeer(self: *Server, stream: Io.net.Stream) void {
        self.peers_mutex.lockUncancelable(self.io);
        defer self.peers_mutex.unlock(self.io);

        for (self.peers.items, 0..) |peer, i| {
            if (peer.stream.socket.handle == stream.socket.handle) {
                self.allocator.free(peer.nick);
                _ = self.peers.orderedRemove(i);
                return;
            }
        }
    }

    fn checkPeerRateLimit(self: *Server, stream: Io.net.Stream) bool {
        self.peers_mutex.lockUncancelable(self.io);
        defer self.peers_mutex.unlock(self.io);

        const now = Io.Clock.real.now(self.io).toSeconds();

        for (self.peers.items) |*peer| {
            if (peer.stream.socket.handle == stream.socket.handle) {
                if (now - peer.rate_window_start >= 1) {
                    peer.message_count = 0;
                    peer.rate_window_start = now;
                }

                if (peer.message_count >= 10) {
                    return false;
                }

                peer.message_count += 1;
                return true;
            }
        }

        return false;
    }

    fn resolveNickCollision(self: *Server, nick: []const u8) ![]const u8 {
        self.peers_mutex.lockUncancelable(self.io);
        defer self.peers_mutex.unlock(self.io);

        // Check if nick collides with host or any peer
        var has_collision = std.mem.eql(u8, nick, self.host_nick);
        if (!has_collision) {
            for (self.peers.items) |peer| {
                if (std.mem.eql(u8, nick, peer.nick)) {
                    has_collision = true;
                    break;
                }
            }
        }

        if (!has_collision) {
            // No collision - return an owned copy
            return try self.allocator.dupe(u8, nick);
        }

        // Collision - try nick_2, nick_3, etc.
        var suffix: u8 = 2;
        while (suffix < 100) : (suffix += 1) {
            const new_nick = try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ nick, suffix });
            var collision = std.mem.eql(u8, new_nick, self.host_nick);

            if (!collision) {
                for (self.peers.items) |peer| {
                    if (std.mem.eql(u8, new_nick, peer.nick)) {
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
        const stdin = Io.File.stdin();
        const handle = stdin.handle;

        // Enable raw mode so we own the input buffer
        var original_termios: std.posix.termios = undefined;
        const raw_mode = if (stdin.isTty(self.io) catch false) blk: {
            original_termios = std.posix.tcgetattr(handle) catch break :blk false;
            var raw = original_termios;
            raw.lflag.ECHO = false;
            raw.lflag.ICANON = false;
            raw.lflag.ISIG = false;
            raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
            raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
            std.posix.tcsetattr(handle, .FLUSH, raw) catch break :blk false;
            break :blk true;
        } else false;
        defer if (raw_mode) {
            std.posix.tcsetattr(handle, .FLUSH, original_termios) catch {};
        };

        if (raw_mode) {
            self.rawStdinLoop(handle);
        } else {
            self.lineStdinLoop(handle);
        }
    }

    fn rawStdinLoop(self: *Server, handle: std.posix.fd_t) void {
        var submit_buf: [4096]u8 = undefined;
        while (self.running.load(.monotonic)) {
            var byte_buf: [1]u8 = undefined;
            const n = std.posix.read(handle, &byte_buf) catch break;
            if (n == 0) break;
            const byte = byte_buf[0];

            switch (byte) {
                3, 4 => { // Ctrl+C, Ctrl+D
                    self.running.store(false, .monotonic);
                    break;
                },
                '\r', '\n' => {
                    const line = display.inputSubmit(&submit_buf);
                    if (line.len == 0) continue;
                    if (std.mem.eql(u8, line, "/quit")) {
                        self.running.store(false, .monotonic);
                        break;
                    }
                    self.sendHostMessage(line);
                },
                127, 8 => display.inputBackspace(),
                21 => display.inputClear(), // Ctrl+U
                1 => display.inputHome(), // Ctrl+A
                5 => display.inputEnd(), // Ctrl+E
                27 => display.handleEscapeSeq(handle), // ESC
                else => {
                    if (byte >= 32) display.inputChar(byte);
                },
            }
        }
    }

    fn lineStdinLoop(self: *Server, handle: std.posix.fd_t) void {
        var buffer: [4096]u8 = undefined;
        while (self.running.load(.monotonic)) {
            const bytes_read = std.posix.read(handle, &buffer) catch break;
            if (bytes_read == 0) break;
            const line = std.mem.trimEnd(u8, buffer[0..bytes_read], "\n\r");
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) continue;
            if (std.mem.eql(u8, trimmed, "/quit")) {
                self.running.store(false, .monotonic);
                break;
            }
            self.sendHostMessage(trimmed);
        }
    }

    fn sendHostMessage(self: *Server, text: []const u8) void {
        var encrypted = crypto.encrypt(self.allocator, self.io, text, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .msg,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = self.host_nick,
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        self.peers_mutex.lockUncancelable(self.io);
        for (self.peers.items) |peer| {
            protocol.sendFrame(self.io, peer.stream, frame) catch continue;
        }
        self.peers_mutex.unlock(self.io);

        display.printMessage(frame.timestamp, self.host_nick, text);
    }

    pub fn shutdown(self: *Server) void {
        self.running.store(false, .monotonic);

        self.peers_mutex.lockUncancelable(self.io);
        for (self.peers.items) |peer| {
            peer.stream.close(self.io);
            self.allocator.free(peer.nick);
        }
        self.peers.deinit(self.allocator);
        self.peers_mutex.unlock(self.io);

        self.listener.deinit(self.io);

        std.crypto.secureZero(u8, &self.key);
    }
};
