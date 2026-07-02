const std = @import("std");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const tunnel = @import("tunnel.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const id = @import("id.zig");

pub const version = "0.2.8";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_list: std.ArrayList([:0]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_it = std.process.Args.Iterator.init(init.minimal.args);
    while (args_it.next()) |arg| try args_list.append(allocator, arg);
    const args = args_list.items;

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        std.debug.print("seance {s}\n", .{version});
        return;
    } else if (std.mem.eql(u8, command, "host")) {
        try handleHost(allocator, io, init.environ_map, args[2..]);
    } else if (std.mem.eql(u8, command, "join")) {
        try handleJoin(allocator, io, init.environ_map, args[2..]);
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn printBanner() void {
    std.debug.print("\n\x1b[38;5;54m                \xc2\xb7  \x1b[38;5;183m\xe2\x9c\xa6\x1b[38;5;54m  \xc2\xb7\x1b[0m\n\n", .{});
    std.debug.print("\x1b[38;5;91m        \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x97\xe2\x95\x94 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;128m        \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x91\xe2\x95\xa3  \xe2\x95\xa0\xe2\x95\x90\xe2\x95\xa3 \xe2\x95\x91\xe2\x95\x91\xe2\x95\x91 \xe2\x95\x91   \xe2\x95\x91\xe2\x95\xa3\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;177m        \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\xa9 \xe2\x95\xa9 \xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;245m\n       ephemeral encrypted chat\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;240m                v{s}\x1b[0m\n\n", .{version});
    std.debug.print("\x1b[38;5;54m                \xc2\xb7  \x1b[38;5;183m\xe2\x9c\xa7\x1b[38;5;54m  \xc2\xb7\x1b[0m\n\n", .{});
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

fn handleHost(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, args: []const [:0]const u8) !void {
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

    // Password: --password flag, else SEANCE_PASSWORD env var, else auto-generate.
    const password = (try resolveSecret(allocator, environ, password_opt, "SEANCE_PASSWORD")) orelse
        try crypto.generatePassword(allocator, io);
    defer allocator.free(password);

    const key = crypto.deriveKey(io, password);

    // Generate or use nick
    const nick = if (nick_opt) |n|
        try allocator.dupe(u8, n)
    else
        try id.generate(allocator, io);
    defer allocator.free(nick);

    var srv = try server_mod.Server.init(allocator, io, .{
        .port = port,
        .max_peers = max_peers,
        .local_only = local_only,
    }, key, nick);
    defer srv.shutdown();

    // Get the actual port the server bound to
    const actual_port = srv.port;

    // Print room info
    printBanner();
    std.debug.print("\x1b[38;5;245mPassword:\x1b[0m {s}\n", .{password});
    std.debug.print("\x1b[38;5;245mNick:\x1b[0m {s}\n", .{nick});
    std.debug.print("\x1b[38;5;245mLocal:\x1b[0m localhost:{d}\n", .{actual_port});

    // Establish tunnel
    var tun_opt: ?tunnel.Tunnel = null;
    defer if (tun_opt) |*tun| tun.shutdown();

    if (!local_only) {
        if (tunnel.Tunnel.establish(allocator, io, actual_port, bore_port)) |tun| {
            tun_opt = tun;
            tun_opt.?.startMonitor();
            std.debug.print("\x1b[38;5;245mPublic:\x1b[0m {s}:{d}", .{ tun.public_host, tun.public_port });
            if (tun.requested_port > 0 and tun.requested_port != tun.public_port) {
                std.debug.print(" (requested {d} but unavailable)", .{tun.requested_port});
            }
            std.debug.print("\n", .{});

            std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
            std.debug.print("  \x1b[38;5;240mseance join {s}:{d} --password {s}\x1b[0m\n", .{
                tun.public_host, tun.public_port, password,
            });
            std.debug.print("  \x1b[38;5;240mseance join {s}:{d} --password {s} --familiar\x1b[0m\n\n", .{
                tun.public_host, tun.public_port, password,
            });
        } else |err| {
            if (err == error.PortInUse and bore_port > 0) {
                std.debug.print("Bore port {d} in use, trying random...\n", .{bore_port});
                if (tunnel.Tunnel.establish(allocator, io, actual_port, 0)) |tun| {
                    tun_opt = tun;
                    tun_opt.?.startMonitor();
                    std.debug.print("\x1b[38;5;245mPublic:\x1b[0m {s}:{d}\n", .{ tun.public_host, tun.public_port });
                    std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                    std.debug.print("  \x1b[38;5;240mseance join {s}:{d} --password {s}\x1b[0m\n", .{
                        tun.public_host, tun.public_port, password,
                    });
                    std.debug.print("  \x1b[38;5;240mseance join {s}:{d} --password {s} --familiar\x1b[0m\n\n", .{
                        tun.public_host, tun.public_port, password,
                    });
                } else |retry_err| {
                    std.debug.print("\x1b[38;5;240mWarning: tunnel failed ({any}), local only.\x1b[0m\n", .{retry_err});
                    std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                    std.debug.print("  \x1b[38;5;240mseance join localhost:{d} --password {s}\x1b[0m\n", .{ actual_port, password });
                    std.debug.print("  \x1b[38;5;240mseance join localhost:{d} --password {s} --familiar\x1b[0m\n\n", .{ actual_port, password });
                }
            } else {
                std.debug.print("\x1b[38;5;240mWarning: tunnel failed ({any}), local only.\x1b[0m\n", .{err});
                std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                std.debug.print("  \x1b[38;5;240mseance join localhost:{d} --password {s}\x1b[0m\n", .{ actual_port, password });
                std.debug.print("  \x1b[38;5;240mseance join localhost:{d} --password {s} --familiar\x1b[0m\n\n", .{ actual_port, password });
            }
        }
    } else {
        std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
        std.debug.print("  \x1b[38;5;240mseance join localhost:{d} --password {s}\x1b[0m\n", .{ actual_port, password });
        std.debug.print("  \x1b[38;5;240mseance join localhost:{d} --password {s} --familiar\x1b[0m\n\n", .{ actual_port, password });
    }

    std.debug.print("\x1b[38;5;245mWaiting for participants...\x1b[38;5;240m (type /quit to exit)\x1b[0m\n\n", .{});
    try srv.run();
}

fn handleJoin(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, args: []const [:0]const u8) !void {
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

    // Password: --password flag, else SEANCE_PASSWORD env var, else error.
    const password = (try resolveSecret(allocator, environ, password_opt, "SEANCE_PASSWORD")) orelse {
        std.debug.print("Error: --password or SEANCE_PASSWORD is required\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(password);
    const key = crypto.deriveKey(io, password);

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
        try id.generate(allocator, io);
    defer allocator.free(nick);

    printBanner();
    std.debug.print("\x1b[38;5;245mNick:\x1b[0m {s}\n\n", .{nick});

    var client = client_mod.Client.connect(allocator, io, host, port, key, .{
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
        try client.runBot(api_port, run_familiar, environ);
    } else {
        std.debug.print("\x1b[38;5;141mConnected!\x1b[38;5;240m Type /quit to leave.\x1b[0m\n\n", .{});
        try client.run();
    }

    std.debug.print("\nDisconnected.\n", .{});
}

/// Resolve a secret from an explicit flag, else an environment variable, so it
/// need not appear in argv (visible in `ps`) or shell history. An exported-but-
/// empty variable is treated as unset — deriving a key from "" would produce a
/// deterministic, publicly reproducible secret. Returns owned memory the caller
/// frees, or null if neither source provided a non-empty value.
fn resolveSecret(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map, flag: ?[]const u8, env_name: []const u8) !?[]u8 {
    if (flag) |f| return try allocator.dupe(u8, f);
    const value = environ.get(env_name) orelse return null;
    if (value.len == 0) return null; // exported-but-empty == unset
    return try allocator.dupe(u8, value);
}

// 0.16 `zig test <root>` only runs the root file's own tests; pull in every
// sibling module so their test blocks are discovered by the gate command.
test {
    _ = @import("crypto.zig");
    _ = @import("id.zig");
    _ = @import("protocol.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
    _ = @import("bot.zig");
    _ = @import("display.zig");
    _ = @import("tunnel.zig");
}
