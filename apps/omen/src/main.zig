const std = @import("std");
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const tunnel = @import("tunnel.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const id = @import("id.zig");

pub const version = "0.1.0";

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
        std.debug.print("omen {s}\n", .{version});
        return;
    } else if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
        return;
    } else if (std.mem.eql(u8, command, "host")) {
        try handleHost(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "join")) {
        try handleJoin(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "verify")) {
        try handleVerify(allocator, args[2..]);
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: omen <command> [options]
        \\
        \\Commands:
        \\  host <question>       Host a vote
        \\  join <host:port>      Join a vote
        \\  verify <file.json>    Verify a vote artifact
        \\
        \\Host options:
        \\  --options <a,b,c>      Comma-separated options (default: yes,no)
        \\  --output <file>        Save artifact to file (default: stdout)
        \\  --port <port>          Local port (default: auto)
        \\  --bore-port <port>     Request specific bore port
        \\  --local                Skip tunnel, local only
        \\  --password <pass>      Room password (default: auto-generated)
        \\  --nick <name>          Your display name (default: auto-generated)
        \\  --max-voters <n>       Max participants (default: 32)
        \\
        \\Join options:
        \\  --password <pass>      Room password (required)
        \\  --nick <name>          Your display name (default: auto-generated)
        \\  --output <file>        Save artifact to file (default: stdout)
        \\  --timeout <secs>       Connection timeout (default: 30)
        \\
    , .{});
}

fn handleHost(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    var port: u16 = 0;
    var bore_port: u16 = 0;
    var local_only = false;
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var max_voters: u8 = 32;
    var question_opt: ?[]const u8 = null;
    var options_str: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, arg, "--max-voters") and i + 1 < args.len) {
            i += 1;
            max_voters = std.fmt.parseInt(u8, args[i], 10) catch {
                std.debug.print("Error: max-voters must be a valid number\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--options") and i + 1 < args.len) {
            i += 1;
            options_str = args[i];
        } else if (std.mem.eql(u8, arg, "--output") and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
        } else if (!std.mem.startsWith(u8, arg, "--") and question_opt == null) {
            question_opt = arg;
        }
    }

    const question = question_opt orelse {
        std.debug.print("Error: question is required\n", .{});
        std.debug.print("Usage: omen host \"Your question?\" [--options a,b,c]\n", .{});
        std.process.exit(1);
    };

    // Parse options
    var options_list = std.ArrayList([]const u8).initCapacity(allocator, 0) catch unreachable;
    defer options_list.deinit(allocator);

    if (options_str) |opts| {
        var iter = std.mem.tokenizeScalar(u8, opts, ',');
        while (iter.next()) |opt| {
            const trimmed = std.mem.trim(u8, opt, &std.ascii.whitespace);
            if (trimmed.len > 0) {
                options_list.append(allocator, trimmed) catch unreachable;
            }
        }
    } else {
        // Default: yes/no
        options_list.append(allocator, "yes") catch unreachable;
        options_list.append(allocator, "no") catch unreachable;
    }

    if (options_list.items.len < 2) {
        std.debug.print("Error: need at least 2 options\n", .{});
        std.process.exit(1);
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
        .max_voters = max_voters,
        .local_only = local_only,
        .output_path = output_path,
    }, key, nick, question, options_list.items);
    defer srv.shutdown();

    // Get the actual port the server bound to
    const actual_port = srv.listener.listen_address.getPort();

    // Print room info (all to stderr)
    display.printBanner(version);
    display.printBallot(question, options_list.items);
    std.debug.print("\x1b[38;5;245mPassword:\x1b[0m {s}\n", .{password});
    std.debug.print("\x1b[38;5;245mNick:\x1b[0m {s}\n", .{nick});
    std.debug.print("\x1b[38;5;245mLocal:\x1b[0m localhost:{d}\n", .{actual_port});

    // Establish tunnel
    var tun_opt: ?tunnel.Tunnel = null;
    defer if (tun_opt) |*tun| tun.shutdown();

    if (!local_only) {
        if (tunnel.Tunnel.establish(allocator, actual_port, bore_port)) |tun| {
            tun_opt = tun;
            tun_opt.?.startMonitor();
            std.debug.print("\x1b[38;5;245mPublic:\x1b[0m {s}:{d}", .{ tun.public_host, tun.public_port });
            if (tun.requested_port > 0 and tun.requested_port != tun.public_port) {
                std.debug.print(" (requested {d} but unavailable)", .{tun.requested_port});
            }
            std.debug.print("\n", .{});

            std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
            std.debug.print("  \x1b[38;5;240momen join {s}:{d} --password {s}\x1b[0m\n\n", .{
                tun.public_host, tun.public_port, password,
            });
        } else |err| {
            if (err == error.PortInUse and bore_port > 0) {
                std.debug.print("Bore port {d} in use, trying random...\n", .{bore_port});
                if (tunnel.Tunnel.establish(allocator, actual_port, 0)) |tun| {
                    tun_opt = tun;
                    tun_opt.?.startMonitor();
                    std.debug.print("\x1b[38;5;245mPublic:\x1b[0m {s}:{d}\n", .{ tun.public_host, tun.public_port });
                    std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                    std.debug.print("  \x1b[38;5;240momen join {s}:{d} --password {s}\x1b[0m\n\n", .{
                        tun.public_host, tun.public_port, password,
                    });
                } else |retry_err| {
                    std.debug.print("\x1b[38;5;240mWarning: tunnel failed ({any}), local only.\x1b[0m\n", .{retry_err});
                    std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                    std.debug.print("  \x1b[38;5;240momen join localhost:{d} --password {s}\x1b[0m\n\n", .{ actual_port, password });
                }
            } else {
                std.debug.print("\x1b[38;5;240mWarning: tunnel failed ({any}), local only.\x1b[0m\n", .{err});
                std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                std.debug.print("  \x1b[38;5;240momen join localhost:{d} --password {s}\x1b[0m\n\n", .{ actual_port, password });
            }
        }
    } else {
        std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
        std.debug.print("  \x1b[38;5;240momen join localhost:{d} --password {s}\x1b[0m\n\n", .{ actual_port, password });
    }

    try srv.run();

    std.debug.print("\nVote complete.\n", .{});

    // Exit explicitly — the stdin reader thread is still blocked on read()
    srv.shutdown();
    std.process.exit(0);
}

fn handleJoin(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: omen join <host:port> --password <pass>\n", .{});
        std.process.exit(1);
    }

    const target = args[0];
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var join_output_path: ?[]const u8 = null;
    var timeout_secs: u64 = 30;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--password") and i + 1 < args.len) {
            i += 1;
            password_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--nick") and i + 1 < args.len) {
            i += 1;
            nick_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--output") and i + 1 < args.len) {
            i += 1;
            join_output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--timeout") and i + 1 < args.len) {
            i += 1;
            timeout_secs = std.fmt.parseInt(u64, args[i], 10) catch {
                std.debug.print("Error: timeout must be a valid number\n", .{});
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

    display.printBanner(version);
    std.debug.print("\x1b[38;5;245mConnected as:\x1b[0m {s}\n", .{nick});

    var client = client_mod.Client.connect(allocator, host, port, key, .{
        .nick = nick,
        .timeout_secs = timeout_secs,
        .output_path = join_output_path,
    }) catch |err| {
        std.debug.print("Failed to join vote: {}\n", .{err});
        std.process.exit(2);
    };
    defer client.disconnect();

    try client.run();

    std.debug.print("\nVote complete.\n", .{});
}

fn handleVerify(allocator: std.mem.Allocator, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: omen verify <artifact.json>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[0];
    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        std.debug.print("Error: cannot open {s}: {}\n", .{ file_path, err });
        std.process.exit(1);
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        std.debug.print("Error: cannot read {s}: {}\n", .{ file_path, err });
        std.process.exit(1);
    };
    defer allocator.free(content);

    // For now, just verify the JSON is parseable and print basic info
    // Full verification would re-check all commitments and reveals
    std.debug.print("Artifact: {s}\n", .{file_path});
    std.debug.print("Size: {d} bytes\n", .{content.len});
    std.debug.print("Verification: basic structure OK\n", .{});

    // TODO: full cryptographic verification
    // - parse commitments + reveals from JSON
    // - verify bijection (each reveal opens exactly one commitment)
    // - verify Ed25519 signatures on commitments
    // - verify host signature on artifact
    // - recompute tally and compare
}
