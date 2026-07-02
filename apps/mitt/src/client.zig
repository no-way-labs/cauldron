const std = @import("std");
const Io = std.Io;
const crypto = @import("crypto.zig");

pub const SendResult = union(enum) {
    delivered,
    failed: struct { err: []const u8 },
    timeout,
};

pub const Payload = union(enum) {
    file: []const u8,
    stdin,
    text: []const u8,
};

const PayloadData = struct {
    data: []const u8,
    filename: []const u8,
};

const max_payload_bytes = 1024 * 1024 * 1024;

pub fn send(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16, payload: Payload, key: [32]u8, timeout_ms: u64) !SendResult {
    // Load payload
    const payload_data = switch (payload) {
        .file => |path| blk: {
            const content = Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_payload_bytes)) catch |err| {
                const err_msg = try std.fmt.allocPrint(allocator, "Failed to read file: {}", .{err});
                return SendResult{ .failed = .{ .err = err_msg } };
            };
            break :blk PayloadData{ .data = content, .filename = std.fs.path.basename(path) };
        },
        .stdin => blk: {
            var stdin_buf: [4096]u8 = undefined;
            var stdin_reader = Io.File.stdin().readerStreaming(io, &stdin_buf);
            const content = stdin_reader.interface.allocRemaining(allocator, .limited(max_payload_bytes)) catch |err| {
                const err_msg = try std.fmt.allocPrint(allocator, "Failed to read stdin: {}", .{err});
                return SendResult{ .failed = .{ .err = err_msg } };
            };
            break :blk PayloadData{ .data = content, .filename = "stdin" };
        },
        .text => |text| blk: {
            const content = try allocator.dupe(u8, text);
            break :blk PayloadData{ .data = content, .filename = "text.txt" };
        },
    };
    defer allocator.free(payload_data.data);

    // Encrypt the data
    var encrypted = try crypto.encrypt(allocator, io, payload_data.data, key);
    defer encrypted.deinit();

    // Connect to server. Do NOT pass a connect timeout: Io.Threaded in Zig
    // 0.16.0 panics "TODO implement netConnectIpPosix with timeout", so the
    // connect is bounded only by the OS default (same as pre-0.16 behavior);
    // the send/recv timeouts below bound the transfer itself.
    const stream = connectToHost(io, host, port, .none) catch |err| {
        const err_msg = try std.fmt.allocPrint(allocator, "Connection failed to {s}:{d}: {}", .{ host, port, err });
        return SendResult{ .failed = .{ .err = err_msg } };
    };
    defer stream.close(io);

    // Bound each send/recv so a dead server can't hang the transfer.
    if (timeout_ms > 0) {
        const timeout = std.posix.timeval{
            .sec = @intCast(@min(timeout_ms / 1000, std.math.maxInt(u32))),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        for ([_]u32{ std.posix.SO.RCVTIMEO, std.posix.SO.SNDTIMEO }) |opt| {
            std.posix.setsockopt(
                stream.socket.handle,
                std.posix.SOL.SOCKET,
                opt,
                std.mem.asBytes(&timeout),
            ) catch |err| {
                std.debug.print("Warning: Failed to set socket timeout: {}\n", .{err});
            };
        }
    }

    if (payload_data.filename.len > std.math.maxInt(u16)) {
        const err_msg = try std.fmt.allocPrint(allocator, "Filename too long", .{});
        return SendResult{ .failed = .{ .err = err_msg } };
    }

    // Protocol: [filename_len: u16][filename][encrypted_size: u64][nonce: 24][tag: 16][ciphertext]
    var write_buf: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);
    const out = &stream_writer.interface;

    try out.writeInt(u16, @intCast(payload_data.filename.len), .big);
    try out.writeAll(payload_data.filename);
    try out.writeInt(u64, encrypted.ciphertext.len, .big);
    try out.writeAll(&encrypted.nonce);
    try out.writeAll(&encrypted.tag);
    try out.writeAll(encrypted.ciphertext);
    try out.flush();

    // Read acknowledgment (single byte: 0 = success)
    var read_buf: [16]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    const ack = stream_reader.interface.takeByte() catch {
        const err_msg = try std.fmt.allocPrint(allocator, "No acknowledgment from server", .{});
        return SendResult{ .failed = .{ .err = err_msg } };
    };

    if (ack == 0) {
        return SendResult.delivered;
    } else {
        const err_msg = try std.fmt.allocPrint(allocator, "Server rejected transfer", .{});
        return SendResult{ .failed = .{ .err = err_msg } };
    }
}

fn connectToHost(io: Io, host: []const u8, port: u16, timeout: Io.Timeout) !Io.net.Stream {
    if (Io.net.IpAddress.parse(host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream, .timeout = timeout });
    } else |_| {
        const host_name = try Io.net.HostName.init(host);
        return host_name.connect(io, port, .{ .mode = .stream, .timeout = timeout });
    }
}
