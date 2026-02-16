const std = @import("std");
const server = @import("server.zig");
const client = @import("client.zig");
const tunnel = @import("tunnel.zig");
const crypto = @import("crypto.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "open")) {
        try handleOpen(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "send")) {
        try handleSend(allocator, args[2..]);
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        try printUsage();
        std.process.exit(1);
    }
}

fn printUsage() !void {
    std.debug.print(
        \\Usage: mitt <command> [options]
        \\
        \\Commands:
        \\  open              Start a server to receive files
        \\  send <host:port> <payload>  Send a file to an open mitt
        \\
        \\Open options:
        \\  --port <port>     Local port (default: random)
        \\  --bore-port <port> Remote bore port to request (default: random)
        \\  --local           Local only, no tunnel (for testing)
        \\  --quiet           Don't display password in output
        \\  --dir <path>      Save directory (default: ./inbox)
        \\  --stdout          Print to stdout instead of saving
        \\  --accept <globs>  Whitelist (e.g., *.txt,*.csv)
        \\  --reject <globs>  Blacklist (e.g., *.exe)
        \\  --max-size <bytes> Max file size (default: 100mb)
        \\  --password <pass> Encryption password (default: auto-generated)
        \\
        \\Send options:
        \\  --text <string>   Send literal text
        \\  --timeout <seconds> Wait time (default: 30)
        \\  --password <pass> Encryption password (required)
        \\
    , .{});
}

fn handleOpen(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var port: u16 = 0;
    var bore_port: u16 = 0;
    var dir: []const u8 = "./inbox";
    var to_stdout = false;
    var local_only = false;
    var quiet = false;
    var accept: ?[]const []const u8 = null;
    var reject: ?[]const []const u8 = null;
    var max_size: u64 = 100 * 1024 * 1024;
    var password_opt: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--port") and i + 1 < args.len) {
            i += 1;
            port = try std.fmt.parseInt(u16, args[i], 10);
            // Validate port number
            if (port == 0) {
                std.debug.print("Error: Port must be between 1-65535\n", .{});
                std.process.exit(1);
            }
            if (port < 1024) {
                std.debug.print("Warning: Port {d} requires root/admin privileges\n", .{port});
            }
        } else if (std.mem.eql(u8, arg, "--bore-port") and i + 1 < args.len) {
            i += 1;
            bore_port = std.fmt.parseInt(u16, args[i], 10) catch {
                std.debug.print("Error: Bore port must be between 0-65535\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--dir") and i + 1 < args.len) {
            i += 1;
            dir = args[i];
        } else if (std.mem.eql(u8, arg, "--stdout")) {
            to_stdout = true;
        } else if (std.mem.eql(u8, arg, "--local")) {
            local_only = true;
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "--accept") and i + 1 < args.len) {
            i += 1;
            accept = try parseGlobs(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "--reject") and i + 1 < args.len) {
            i += 1;
            reject = try parseGlobs(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "--max-size") and i + 1 < args.len) {
            i += 1;
            max_size = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--password") and i + 1 < args.len) {
            i += 1;
            password_opt = args[i];
        }
    }

    // Generate or use password
    const password = if (password_opt) |p|
        try allocator.dupe(u8, p)
    else
        try crypto.generatePassword(allocator);
    defer if (password_opt == null) allocator.free(password);

    const key = crypto.deriveKey(password);

    // Get port if not specified
    if (port == 0) {
        const address = try std.net.Address.parseIp4("127.0.0.1", 0);
        const socket = try std.posix.socket(address.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
        defer std.posix.close(socket);

        try std.posix.bind(socket, &address.any, address.getOsSockLen());
        try std.posix.listen(socket, 1);

        var sock_addr: std.posix.sockaddr.storage = undefined;
        var sock_len: std.posix.socklen_t = @sizeOf(@TypeOf(sock_addr));
        try std.posix.getsockname(socket, @ptrCast(&sock_addr), &sock_len);

        const addr = std.net.Address.initPosix(@alignCast(@ptrCast(&sock_addr)));
        port = addr.getPort();
    }

    var srv = try server.Server.init(allocator, port, .{
        .dir = dir,
        .to_stdout = to_stdout,
        .accept = accept,
        .reject = reject,
        .max_size = max_size,
    }, key);
    defer srv.shutdown();

    if (!quiet) {
        std.debug.print("\n🔐 Password: {s}\n", .{password});
    }
    std.debug.print("Local: localhost:{d}\n\n", .{port});

    var tun_opt: ?tunnel.Tunnel = null;
    defer if (tun_opt) |*tun| tun.shutdown();

    if (!local_only) {
        if (tunnel.Tunnel.establish(allocator, port, bore_port)) |tun| {
            tun_opt = tun;
            tun_opt.?.startMonitor();
            std.debug.print("Public: {s}:{d}", .{ tun.public_host, tun.public_port });

            // Check if we got a different port than requested
            if (tun.requested_port > 0 and tun.requested_port != tun.public_port) {
                std.debug.print(" (requested {d} but port was unavailable)", .{tun.requested_port});
            }
            std.debug.print("\n", .{});

            if (!quiet) {
                std.debug.print("\nTo send a file:\n", .{});
                std.debug.print("  mitt send {s}:{d} <file> --password {s}\n\n", .{ tun.public_host, tun.public_port, password });
            }
        } else |err| {
            // If a specific port was requested but is in use, retry with random port
            if (err == error.PortInUse and bore_port > 0) {
                std.debug.print("Bore port {d} is already in use, trying random port...\n", .{bore_port});
                if (tunnel.Tunnel.establish(allocator, port, 0)) |tun| {
                    tun_opt = tun;
                    tun_opt.?.startMonitor();
                    std.debug.print("Public: {s}:{d}\n", .{ tun.public_host, tun.public_port });

                    if (!quiet) {
                        std.debug.print("\nTo send a file:\n", .{});
                        std.debug.print("  mitt send {s}:{d} <file> --password {s}\n\n", .{ tun.public_host, tun.public_port, password });
                    }
                } else |retry_err| {
                    std.debug.print("Warning: Could not establish tunnel ({any})\n", .{retry_err});
                    std.debug.print("Running in local-only mode.\n\n", .{});
                    if (!quiet) {
                        std.debug.print("To send a file:\n", .{});
                        std.debug.print("  mitt send localhost:{d} <file> --password {s}\n\n", .{ port, password });
                    }
                }
            } else {
                std.debug.print("Warning: Could not establish tunnel ({any})\n", .{err});
                std.debug.print("Running in local-only mode.\n\n", .{});
                if (!quiet) {
                    std.debug.print("To send a file:\n", .{});
                    std.debug.print("  mitt send localhost:{d} <file> --password {s}\n\n", .{ port, password });
                }
            }
        }
    } else {
        if (!quiet) {
            std.debug.print("To send a file:\n", .{});
            std.debug.print("  mitt send localhost:{d} <file> --password {s}\n\n", .{ port, password });
        }
    }

    std.debug.print("Waiting for files...\n\n", .{});
    try srv.run();
}

fn handleSend(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: mitt send <host:port> [<payload>] --password <pass> [--text <text>]\n", .{});
        std.process.exit(1);
    }

    const target = args[0];

    var payload_arg: ?[]const u8 = null;
    var text_payload: ?[]const u8 = null;
    var timeout_seconds: u64 = 30;
    var password_opt: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--text") and i + 1 < args.len) {
            i += 1;
            text_payload = args[i];
        } else if (std.mem.eql(u8, arg, "--timeout") and i + 1 < args.len) {
            i += 1;
            timeout_seconds = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--password") and i + 1 < args.len) {
            i += 1;
            password_opt = args[i];
        } else if (!std.mem.startsWith(u8, arg, "--") and payload_arg == null) {
            // First non-flag argument is the payload
            payload_arg = arg;
        }
    }

    if (password_opt == null) {
        std.debug.print("Error: --password is required\n", .{});
        std.process.exit(1);
    }

    const password = password_opt.?;
    const key = crypto.deriveKey(password);

    // Parse target (host:port)
    const colon_pos = std.mem.indexOf(u8, target, ":") orelse {
        std.debug.print("Error: target must be in format host:port\n", .{});
        std.process.exit(1);
    };

    const host = target[0..colon_pos];
    const port = try std.fmt.parseInt(u16, target[colon_pos + 1 ..], 10);

    // Validate port number
    if (port == 0) {
        std.debug.print("Error: Port must be between 1-65535\n", .{});
        std.process.exit(1);
    }

    const payload = if (text_payload) |text|
        client.Payload{ .text = text }
    else if (payload_arg) |arg|
        if (std.mem.eql(u8, arg, "-"))
            client.Payload.stdin
        else
            client.Payload{ .file = arg }
    else {
        std.debug.print("Error: Must provide either a file path or --text flag\n", .{});
        std.process.exit(1);
    };

    const result = try client.send(allocator, host, port, payload, key, timeout_seconds * 1000);

    switch (result) {
        .delivered => {
            std.debug.print("Delivered.\n", .{});
            std.process.exit(0);
        },
        .failed => |info| {
            std.debug.print("Failed: {s}\n", .{info.err});
            allocator.free(info.err);
            std.process.exit(2);
        },
        .timeout => {
            std.debug.print("Timeout: server did not respond\n", .{});
            std.process.exit(2);
        },
    }
}

fn parseGlobs(allocator: std.mem.Allocator, input: []const u8) ![]const []const u8 {
    var list = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    errdefer list.deinit(allocator);

    var iter = std.mem.tokenizeScalar(u8, input, ',');
    while (iter.next()) |glob| {
        try list.append(allocator, glob);
    }

    return try list.toOwnedSlice(allocator);
}

test "simple test" {
    try std.testing.expect(true);
}
