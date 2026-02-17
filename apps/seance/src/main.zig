const std = @import("std");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const tunnel = @import("tunnel.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const id = @import("id.zig");

pub const version = "0.2.3";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        std.debug.print("seance {s}\n", .{version});
        return;
    } else if (std.mem.eql(u8, command, "host")) {
        try handleHost(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "join")) {
        try handleJoin(allocator, args[2..]);
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: seance <command> [options]
        \\
        \\Commands:
        \\  host              Create a chat room
        \\  join <host:port>  Join a chat room
        \\
        \\Host options:
        \\  --port <port>        Local port (default: auto)
        \\  --bore-port <port>   Request specific bore port
        \\  --local              Skip tunnel, local only
        \\  --password <pass>    Room password (default: auto-generated)
        \\  --nick <name>        Your display name (default: auto-generated)
        \\  --max-peers <n>      Max participants (default: 8)
        \\
        \\Join options:
        \\  --password <pass>    Room password (required)
        \\  --nick <name>        Your display name (default: auto-generated)
        \\  --timeout <secs>     Connection timeout (default: 30)
        \\  --bot                Bot mode: HTTP API instead of stdin
        \\  --api-port <port>    Bot API port (default: 9999)
        \\  --familiar           Bot mode + auto-start familiar daemon
        \\
    , .{});
}

fn handleHost(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var port: u16 = 0;
    var bore_port: u16 = 0;
    var local_only = false;
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var max_peers: u8 = 8;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch {
                std.debug.print("Error: port must be a valid number\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--bore-port") and i + 1 < args.len) {
            i += 1;
            bore_port = std.fmt.parseInt(u16, args[i], 10) catch {
                std.debug.print("Error: bore port must be a valid number\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--local")) {
            local_only = true;
        } else if (std.mem.eql(u8, arg, "--password") and i + 1 < args.len) {
            i += 1;
            password_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--nick") and i + 1 < args.len) {
            i += 1;
            nick_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--max-peers") and i + 1 < args.len) {
            i += 1;
            max_peers = std.fmt.parseInt(u8, args[i], 10) catch {
                std.debug.print("Error: max-peers must be a valid number\n", .{});
                std.process.exit(1);
            };
        }
    }

    // Generate or use password
    const password = if (password_opt) |p|
        try allocator.dupe(u8, p)
    else
        try crypto.generatePassword(allocator);
    defer allocator.free(password);

    const key = crypto.deriveKey(password);

    // Generate or use nick
    const nick = if (nick_opt) |n|
        try allocator.dupe(u8, n)
    else
        try id.generate(allocator);
    defer allocator.free(nick);

    var srv = try server_mod.Server.init(allocator, .{
        .port = port,
        .max_peers = max_peers,
        .local_only = local_only,
    }, key, nick);
    defer srv.shutdown();

    // Get the actual port the server bound to
    const actual_port = srv.listener.listen_address.getPort();

    // Print room info
    std.debug.print("\n\x1b[35mseance\x1b[0m v{s} - ephemeral encrypted chat\n\n", .{version});
    std.debug.print("Password: {s}\n", .{password});
    std.debug.print("Nick: {s}\n", .{nick});
    std.debug.print("Local: localhost:{d}\n", .{actual_port});

    // Establish tunnel
    var tun_opt: ?tunnel.Tunnel = null;
    defer if (tun_opt) |*tun| tun.shutdown();

    if (!local_only) {
        if (tunnel.Tunnel.establish(allocator, actual_port, bore_port)) |tun| {
            tun_opt = tun;
            tun_opt.?.startMonitor();
            std.debug.print("Public: {s}:{d}", .{ tun.public_host, tun.public_port });
            if (tun.requested_port > 0 and tun.requested_port != tun.public_port) {
                std.debug.print(" (requested {d} but unavailable)", .{tun.requested_port});
            }
            std.debug.print("\n", .{});

            std.debug.print("\nTo join:\n", .{});
            std.debug.print("  seance join {s}:{d} --password {s}\n\n", .{
                tun.public_host, tun.public_port, password,
            });
        } else |err| {
            if (err == error.PortInUse and bore_port > 0) {
                std.debug.print("Bore port {d} in use, trying random...\n", .{bore_port});
                if (tunnel.Tunnel.establish(allocator, actual_port, 0)) |tun| {
                    tun_opt = tun;
                    tun_opt.?.startMonitor();
                    std.debug.print("Public: {s}:{d}\n", .{ tun.public_host, tun.public_port });
                    std.debug.print("\nTo join:\n", .{});
                    std.debug.print("  seance join {s}:{d} --password {s}\n\n", .{
                        tun.public_host, tun.public_port, password,
                    });
                } else |retry_err| {
                    std.debug.print("Warning: tunnel failed ({any}), local only.\n", .{retry_err});
                    std.debug.print("\nTo join:\n", .{});
                    std.debug.print("  seance join localhost:{d} --password {s}\n\n", .{ actual_port, password });
                }
            } else {
                std.debug.print("Warning: tunnel failed ({any}), local only.\n", .{err});
                std.debug.print("\nTo join:\n", .{});
                std.debug.print("  seance join localhost:{d} --password {s}\n\n", .{ actual_port, password });
            }
        }
    } else {
        std.debug.print("\nTo join:\n", .{});
        std.debug.print("  seance join localhost:{d} --password {s}\n\n", .{ actual_port, password });
    }

    std.debug.print("Waiting for participants... (type /quit to exit)\n\n", .{});
    try srv.run();
}

fn handleJoin(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: seance join <host:port> --password <pass>\n", .{});
        std.process.exit(1);
    }

    const target = args[0];
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var timeout_secs: u64 = 30;
    var bot_mode = false;
    var api_port: u16 = 9999;
    var run_familiar = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--password") and i + 1 < args.len) {
            i += 1;
            password_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--nick") and i + 1 < args.len) {
            i += 1;
            nick_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--timeout") and i + 1 < args.len) {
            i += 1;
            timeout_secs = std.fmt.parseInt(u64, args[i], 10) catch {
                std.debug.print("Error: timeout must be a valid number\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--bot")) {
            bot_mode = true;
        } else if (std.mem.eql(u8, arg, "--familiar")) {
            bot_mode = true;
            run_familiar = true;
        } else if (std.mem.eql(u8, arg, "--api-port") and i + 1 < args.len) {
            i += 1;
            api_port = std.fmt.parseInt(u16, args[i], 10) catch {
                std.debug.print("Error: api-port must be a valid number\n", .{});
                std.process.exit(1);
            };
        }
    }

    if (password_opt == null) {
        std.debug.print("Error: --password is required\n", .{});
        std.process.exit(1);
    }

    const password = password_opt.?;
    const key = crypto.deriveKey(password);

    // Parse target host:port
    const colon_pos = std.mem.lastIndexOfScalar(u8, target, ':') orelse {
        std.debug.print("Error: target must be host:port\n", .{});
        std.process.exit(1);
    };
    const host = target[0..colon_pos];
    const port = std.fmt.parseInt(u16, target[colon_pos + 1 ..], 10) catch {
        std.debug.print("Error: invalid port in target address\n", .{});
        std.process.exit(1);
    };

    // Generate or use nick
    const nick = if (nick_opt) |n|
        try allocator.dupe(u8, n)
    else
        try id.generate(allocator);
    defer allocator.free(nick);

    std.debug.print("\n\x1b[35mseance\x1b[0m v{s} - joining room...\n", .{version});
    std.debug.print("Nick: {s}\n\n", .{nick});

    var client = client_mod.Client.connect(allocator, host, port, key, .{
        .nick = nick,
        .timeout_secs = timeout_secs,
    }) catch |err| {
        std.debug.print("Failed to join room: {}\n", .{err});
        std.process.exit(2);
    };
    defer client.disconnect();

    if (bot_mode) {
        std.debug.print("Bot mode: HTTP API on http://127.0.0.1:{d}\n", .{api_port});
        std.debug.print("  POST /send       - send a message\n", .{});
        std.debug.print("  GET  /messages   - get new messages\n", .{});
        std.debug.print("  GET  /peers      - list participants\n", .{});
        std.debug.print("  GET  /nick       - get bot's nick\n", .{});
        std.debug.print("  POST /quit       - disconnect\n\n", .{});
        try client.runBot(api_port, run_familiar);
    } else {
        std.debug.print("Connected! Type /quit to leave.\n\n", .{});
        try client.run();
    }

    std.debug.print("\nDisconnected.\n", .{});
}
