const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const filter = @import("filter.zig");
const storage = @import("storage.zig");
const config = @import("config.zig");
const crypto = @import("crypto.zig");

// TCP Protocol:
// [filename_len: u16][filename: bytes][encrypted_size: u64][nonce: 24 bytes][tag: 16 bytes][encrypted_data: bytes]

/// Simple rate limiter to prevent abuse
const RateLimiter = struct {
    const ConnectionRecord = struct {
        count: u32,
        last_reset: i64,
    };

    connections: std.StringHashMap(ConnectionRecord),
    allocator: std.mem.Allocator,
    max_per_minute: u32,
    window_seconds: i64,

    fn init(allocator: std.mem.Allocator) RateLimiter {
        return .{
            .connections = std.StringHashMap(ConnectionRecord).init(allocator),
            .allocator = allocator,
            .max_per_minute = 10, // Max 10 connections per minute per IP
            .window_seconds = 60,
        };
    }

    fn deinit(self: *RateLimiter) void {
        var iter = self.connections.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.connections.deinit();
    }

    fn checkAndUpdate(self: *RateLimiter, ip: []const u8, now: i64) !bool {
        if (self.connections.get(ip)) |record| {
            const elapsed = now - record.last_reset;

            if (elapsed < self.window_seconds) {
                // Within the time window
                if (record.count >= self.max_per_minute) {
                    return false; // Rate limit exceeded
                }
                // Update count
                try self.connections.put(ip, .{
                    .count = record.count + 1,
                    .last_reset = record.last_reset,
                });
            } else {
                // Time window expired, reset counter
                try self.connections.put(ip, .{
                    .count = 1,
                    .last_reset = now,
                });
            }
        } else {
            // New IP
            const ip_copy = try self.allocator.dupe(u8, ip);
            try self.connections.put(ip_copy, .{
                .count = 1,
                .last_reset = now,
            });
        }

        return true; // Allowed
    }
};

/// Formats the peer's IP (without port) as the rate-limiting key. IPv4 is
/// rendered dotted-quad for readable logs; IPv6 uses the raw address bytes
/// (the key only feeds a hash map). Behind the shared bore relay every sender
/// appears as one source IP, so this is best-effort there.
fn peerIpKey(buf: []u8, handle: std.posix.socket_t) []const u8 {
    var addr: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(handle, @ptrCast(&addr), &len) catch return "unknown";
    const sa: *const std.posix.sockaddr = @ptrCast(@alignCast(&addr));
    switch (sa.family) {
        std.posix.AF.INET => {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(sa));
            const bytes: *const [4]u8 = @ptrCast(&in.addr);
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch "unknown";
        },
        std.posix.AF.INET6 => {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            const n = @min(buf.len, in6.addr.len);
            @memcpy(buf[0..n], in6.addr[0..n]);
            return buf[0..n];
        },
        else => return "unknown",
    }
}

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
pub fn boundPort(handle: std.posix.socket_t) ?u16 {
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

/// Sanitizes a filename to prevent directory traversal attacks
/// Removes path separators and only keeps the base filename
fn sanitizeFilename(allocator: std.mem.Allocator, filename: []const u8) ![]const u8 {
    // Extract just the basename (everything after the last path separator)
    var basename = filename;

    // Find the last occurrence of / or \
    var i: usize = filename.len;
    while (i > 0) {
        i -= 1;
        if (filename[i] == '/' or filename[i] == '\\') {
            basename = filename[i + 1 ..];
            break;
        }
    }

    // Additional safety: reject filenames with .. or that start with .
    if (std.mem.indexOf(u8, basename, "..") != null) {
        return allocator.dupe(u8, "");
    }

    // Reject empty or hidden files (starting with .)
    if (basename.len == 0 or basename[0] == '.') {
        return allocator.dupe(u8, "");
    }

    // Only allow safe characters: alphanumeric, dash, underscore, dot
    for (basename) |c| {
        const is_safe = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.';

        if (!is_safe) {
            // Replace unsafe characters with underscore
            // For now, just reject the file
            return allocator.dupe(u8, "");
        }
    }

    return allocator.dupe(u8, basename);
}

pub const Server = struct {
    port: u16,
    config: ServerConfig,
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    encryption_key: [32]u8,
    rate_limiter: RateLimiter,
    active_connections: std.atomic.Value(u32),

    pub fn init(allocator: std.mem.Allocator, io: Io, port: u16, server_config: ServerConfig, key: [32]u8) !Server {
        const address = Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
        var listener = try address.listen(io, .{
            .reuse_address = true,
        });
        errdefer listener.deinit(io);

        // When asked for port 0 the kernel picks one; report the real port.
        const actual_port = if (port != 0) port else boundPort(listener.socket.handle) orelse
            return error.PortDiscoveryFailed;

        return Server{
            .port = actual_port,
            .config = server_config,
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .encryption_key = key,
            .rate_limiter = RateLimiter.init(allocator),
            .active_connections = std.atomic.Value(u32).init(0),
        };
    }

    pub fn run(self: *Server) !void {
        std.debug.print("Server listening on port {d}\n", .{self.port});

        while (true) {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);

            // Check connection limit (max 5 concurrent connections)
            const current = self.active_connections.load(.monotonic);
            if (current >= 5) {
                std.debug.print("Connection limit reached, rejecting connection\n", .{});
                continue;
            }

            // Get IP address (without port) for rate limiting
            var ip_buf: [64]u8 = undefined;
            const ip_str = peerIpKey(&ip_buf, stream.socket.handle);

            // Check rate limit
            const now = Io.Clock.real.now(self.io).toSeconds();
            const allowed = self.rate_limiter.checkAndUpdate(ip_str, now) catch false;
            if (!allowed) {
                std.debug.print("Rate limit exceeded for {s}\n", .{ip_str});
                continue;
            }

            // Increment connection counter
            _ = self.active_connections.fetchAdd(1, .monotonic);
            defer _ = self.active_connections.fetchSub(1, .monotonic);

            self.handleConnection(stream) catch |err| {
                std.debug.print("Error handling connection: {}\n", .{err});
            };
        }
    }

    pub fn shutdown(self: *Server) void {
        self.rate_limiter.deinit();
        self.listener.deinit(self.io);
    }

    fn handleConnection(self: *Server, stream: Io.net.Stream) !void {
        const io = self.io;

        // Per-recv timeout so a stalled sender can't wedge the single-threaded
        // accept loop indefinitely (Slowloris). mitt transfers are one-shot.
        // Unlike the chat apps, this stays set for the whole connection: a mitt
        // sender streams continuously, so any recv stalling this long is dead.
        // 120s (not 30s) so a flaky-but-alive link survives.
        const tv = std.posix.timeval{ .sec = 120, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

        var read_buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(io, &read_buf);
        const in = &stream_reader.interface;

        // Read filename length (u16)
        const filename_len = try in.takeInt(u16, .big);
        if (filename_len == 0 or filename_len > 1024) {
            return error.InvalidFilename;
        }

        // Read filename
        const filename = try self.allocator.alloc(u8, filename_len);
        defer self.allocator.free(filename);
        try in.readSliceAll(filename);

        // Sanitize filename to prevent directory traversal attacks
        const sanitized_filename = try sanitizeFilename(self.allocator, filename);
        defer self.allocator.free(sanitized_filename);

        if (sanitized_filename.len == 0) {
            std.debug.print("Rejected: invalid filename\n", .{});
            return error.InvalidFilename;
        }

        // Read encrypted data size (u64)
        const encrypted_size = try in.takeInt(u64, .big);

        // Validate encrypted_size before any allocation to prevent DoS
        // Absolute maximum: 5GB to prevent memory exhaustion
        const ABSOLUTE_MAX_SIZE: u64 = 5 * 1024 * 1024 * 1024;
        if (encrypted_size == 0 or encrypted_size > ABSOLUTE_MAX_SIZE) {
            std.debug.print("Rejected: invalid size {d} bytes (max: {d} bytes)\n", .{ encrypted_size, ABSOLUTE_MAX_SIZE });
            return error.InvalidSize;
        }

        // Check size limits before allocating
        const file_filter = filter.Filter{
            .accept_globs = self.config.accept,
            .reject_globs = self.config.reject,
            .max_size = self.config.max_size,
        };

        const filter_result = file_filter.check(sanitized_filename, encrypted_size, "application/octet-stream");

        switch (filter_result) {
            .ok => {},
            .rejected_extension => |pattern| {
                std.debug.print("Rejected: file type not accepted: {s}\n", .{pattern});
                return;
            },
            .rejected_size => |info| {
                std.debug.print("Rejected: max size {d}mb, got {d}mb\n", .{ info.max / (1024 * 1024), info.got / (1024 * 1024) });
                return;
            },
            .rejected_type => |type_name| {
                std.debug.print("Rejected: content type not accepted: {s}\n", .{type_name});
                return;
            },
        }

        // Read nonce
        var nonce: [24]u8 = undefined;
        try in.readSliceAll(&nonce);

        // Read tag
        var tag: [16]u8 = undefined;
        try in.readSliceAll(&tag);

        // Read encrypted data
        const ciphertext = try self.allocator.alloc(u8, encrypted_size);
        defer self.allocator.free(ciphertext);
        try in.readSliceAll(ciphertext);

        // Decrypt
        const encrypted_data = crypto.EncryptedData{
            .nonce = nonce,
            .ciphertext = ciphertext,
            .tag = tag,
            .allocator = self.allocator,
        };

        const plaintext = crypto.decrypt(self.allocator, encrypted_data, self.encryption_key) catch {
            // Add constant-time delay to prevent timing attacks
            // Attackers can't distinguish wrong password from network delay
            io.sleep(.fromMilliseconds(100), .awake) catch {};
            std.debug.print("Authentication failed\n", .{});
            return error.AuthenticationFailed;
        };
        defer self.allocator.free(plaintext);

        // Zero plaintext memory before freeing (security best practice)
        defer std.crypto.secureZero(u8, plaintext);

        // Save or output
        if (self.config.to_stdout) {
            try Io.File.stdout().writeStreamingAll(io, plaintext);
        } else {
            var plaintext_reader = Io.Reader.fixed(plaintext);
            const result = try storage.save(self.allocator, io, self.config.dir, sanitized_filename, &plaintext_reader);
            defer self.allocator.free(result.path);

            std.debug.print("Received: {s} ({d} bytes) -> {s}\n", .{ sanitized_filename, result.bytes, result.path });
        }

        // Send acknowledgment (single byte: 0 = success)
        var write_buf: [8]u8 = undefined;
        var stream_writer = stream.writer(io, &write_buf);
        try stream_writer.interface.writeAll(&.{0});
        try stream_writer.interface.flush();
    }
};

pub const ServerConfig = struct {
    dir: []const u8,
    to_stdout: bool,
    accept: ?[]const []const u8,
    reject: ?[]const []const u8,
    max_size: u64,
};

/// Wraps a raw corpus payload in the LE32 length prefix Smith.slice() expects.
fn seed(comptime payload: []const u8) []const u8 {
    const out = comptime blk: {
        var buf: [4 + payload.len]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], @intCast(payload.len), .little);
        @memcpy(buf[4..], payload);
        break :blk buf;
    };
    return &out;
}

// sanitizeFilename guards against directory traversal from untrusted senders;
// whatever bytes come in, the result must be empty (rejected) or a safe
// basename. Run `zig build test --fuzz` to fuzz beyond the corpus.
fn fuzzSanitizeFilename(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    const out = try sanitizeFilename(std.testing.allocator, buf[0..n]);
    defer std.testing.allocator.free(out);
    if (out.len > 0) {
        try std.testing.expect(out[0] != '.');
        try std.testing.expect(std.mem.indexOf(u8, out, "..") == null);
        for (out) |c| {
            const is_safe = (c >= 'a' and c <= 'z') or
                (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9') or
                c == '-' or c == '_' or c == '.';
            try std.testing.expect(is_safe);
        }
    }
}

test "fuzz sanitizeFilename" {
    try std.testing.fuzz({}, fuzzSanitizeFilename, .{ .corpus = &.{
        seed("../../etc/passwd"),
        seed("normal.txt"),
        seed("dir/sub\\..\\up.txt"),
        seed(".hidden"),
        seed("weird\x00name?.txt"),
    } });
}
