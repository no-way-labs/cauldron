const std = @import("std");
const Io = std.Io;
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const tunnel = @import("tunnel.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const id = @import("id.zig");
const verify_mod = @import("verify.zig");
const artifact_mod = @import("artifact.zig");

pub const version = "0.1.0";

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
        std.debug.print("covenant {s}\n", .{version});
        return;
    } else if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
        return;
    } else if (std.mem.eql(u8, command, "host")) {
        try handleHost(allocator, io, init.environ_map, args[2..]);
    } else if (std.mem.eql(u8, command, "join")) {
        try handleJoin(allocator, io, init.environ_map, args[2..]);
    } else if (std.mem.eql(u8, command, "verify")) {
        try handleVerify(allocator, io, args[2..]);
    } else if (std.mem.eql(u8, command, "members")) {
        try handleMembers(allocator, io, args[2..]);
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: covenant <command> [options]
        \\
        \\Commands:
        \\  host <group-name>     Host a signing ceremony
        \\  join <host:port>      Join a signing ceremony
        \\  verify <file.json>    Verify a covenant artifact
        \\  members <file.json>   List members in a covenant
        \\
        \\Host options:
        \\  --identity <phrase>    Identity passphrase (required)
        \\  --output <file>        Save artifact to file (default: stdout)
        \\  --port <port>          Local port (default: auto)
        \\  --bore-port <port>     Request specific bore port
        \\  --local                Skip tunnel, local only
        \\  --password <pass>      Room password (default: auto-generated)
        \\  --nick <name>          Your display name (default: auto-generated)
        \\  --max-members <n>      Max participants (default: 32)
        \\
        \\Join options:
        \\  --password <pass>      Room password (required)
        \\  --identity <phrase>    Identity passphrase (required)
        \\  --nick <name>          Your display name (default: auto-generated)
        \\  --output <file>        Save artifact to file (default: stdout)
        \\  --timeout <secs>       Connection timeout (default: 30)
        \\
    , .{});
}

fn handleHost(allocator: std.mem.Allocator, io: Io, environ: *const std.process.Environ.Map, args: []const [:0]const u8) !void {
    var port: u16 = 0;
    var bore_port: u16 = 0;
    var local_only = false;
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var identity_opt: ?[]const u8 = null;
    var max_members: u8 = 32;
    var group_name_opt: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, arg, "--identity") and i + 1 < args.len) {
            i += 1;
            identity_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--max-members") and i + 1 < args.len) {
            i += 1;
            max_members = std.fmt.parseInt(u8, args[i], 10) catch {
                std.debug.print("Error: max-members must be a valid number\n", .{});
                std.process.exit(1);
            };
            if (max_members == 0 or max_members > 254) {
                std.debug.print("Error: max-members must be between 1 and 254 " ++
                    "(the host occupies one roster slot)\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--output") and i + 1 < args.len) {
            i += 1;
            output_path = args[i];
        } else if (!std.mem.startsWith(u8, arg, "--") and group_name_opt == null) {
            group_name_opt = arg;
        }
    }

    const group_name = group_name_opt orelse {
        std.debug.print("Error: group name is required\n", .{});
        std.debug.print("Usage: covenant host \"Group Name\" --identity \"my passphrase\"\n", .{});
        std.process.exit(1);
    };

    // Identity: --identity flag, else COVENANT_IDENTITY env var, else error.
    const identity_owned = try resolveSecret(allocator, environ, identity_opt, "COVENANT_IDENTITY");
    defer if (identity_owned) |e| allocator.free(e);
    const identity_phrase = identity_owned orelse {
        std.debug.print("Error: --identity or COVENANT_IDENTITY is required\n", .{});
        std.debug.print("Usage: covenant host \"Group Name\" --identity \"my passphrase\"\n", .{});
        std.process.exit(1);
    };

    const identity = crypto.deriveIdentity(io, identity_phrase);

    // Password: --password flag, else COVENANT_PASSWORD env var, else auto-generate.
    const password = (try resolveSecret(allocator, environ, password_opt, "COVENANT_PASSWORD")) orelse
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
        .max_members = max_members,
        .local_only = local_only,
        .output_path = output_path,
    }, key, nick, group_name, identity);
    defer srv.shutdown();

    const actual_port = srv.port;

    // Print room info
    display.printBanner(version);
    display.printGroupName(group_name);

    // Show identity pubkey
    const pk = crypto.publicKeyBytes(identity);
    std.debug.print("\x1b[38;5;245mIdentity:\x1b[0m {x:0>2}{x:0>2}{x:0>2}{x:0>2}...\n", .{ pk[0], pk[1], pk[2], pk[3] });
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
            std.debug.print("  \x1b[38;5;240mcovenant join {s}:{d} --password {s} --identity \"<passphrase>\"\x1b[0m\n\n", .{
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
                    std.debug.print("  \x1b[38;5;240mcovenant join {s}:{d} --password {s} --identity \"<passphrase>\"\x1b[0m\n\n", .{
                        tun.public_host, tun.public_port, password,
                    });
                } else |retry_err| {
                    std.debug.print("\x1b[38;5;240mWarning: tunnel failed ({any}), local only.\x1b[0m\n", .{retry_err});
                    std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                    std.debug.print("  \x1b[38;5;240mcovenant join localhost:{d} --password {s} --identity \"<passphrase>\"\x1b[0m\n\n", .{ actual_port, password });
                }
            } else {
                std.debug.print("\x1b[38;5;240mWarning: tunnel failed ({any}), local only.\x1b[0m\n", .{err});
                std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
                std.debug.print("  \x1b[38;5;240mcovenant join localhost:{d} --password {s} --identity \"<passphrase>\"\x1b[0m\n\n", .{ actual_port, password });
            }
        }
    } else {
        std.debug.print("\n\x1b[38;5;245mTo join:\x1b[0m\n", .{});
        std.debug.print("  \x1b[38;5;240mcovenant join localhost:{d} --password {s} --identity \"<passphrase>\"\x1b[0m\n\n", .{ actual_port, password });
    }

    try srv.run();

    std.debug.print("\nCeremony complete.\n", .{});

    srv.shutdown();
    std.process.exit(0);
}

fn handleJoin(allocator: std.mem.Allocator, io: Io, environ: *const std.process.Environ.Map, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: covenant join <host:port> --password <pass> --identity \"<passphrase>\"\n", .{});
        std.process.exit(1);
    }

    const target = args[0];
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var identity_opt: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, arg, "--identity") and i + 1 < args.len) {
            i += 1;
            identity_opt = args[i];
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

    // Password: --password flag, else COVENANT_PASSWORD env var, else error.
    const password = (try resolveSecret(allocator, environ, password_opt, "COVENANT_PASSWORD")) orelse {
        std.debug.print("Error: --password or COVENANT_PASSWORD is required\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(password);

    // Identity: --identity flag, else COVENANT_IDENTITY env var, else error.
    const identity_owned = try resolveSecret(allocator, environ, identity_opt, "COVENANT_IDENTITY");
    defer if (identity_owned) |e| allocator.free(e);
    const identity_phrase = identity_owned orelse {
        std.debug.print("Error: --identity or COVENANT_IDENTITY is required\n", .{});
        std.process.exit(1);
    };

    const key = crypto.deriveKey(io, password);
    const identity = crypto.deriveIdentity(io, identity_phrase);

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

    display.printBanner(version);

    const pk = crypto.publicKeyBytes(identity);
    std.debug.print("\x1b[38;5;245mIdentity:\x1b[0m {x:0>2}{x:0>2}{x:0>2}{x:0>2}...\n", .{ pk[0], pk[1], pk[2], pk[3] });
    std.debug.print("\x1b[38;5;245mNick:\x1b[0m {s}\n", .{nick});

    var client = client_mod.Client.connect(allocator, io, host, port, key, identity, .{
        .nick = nick,
        .timeout_secs = timeout_secs,
        .output_path = join_output_path,
    }) catch |err| {
        std.debug.print("Failed to join ceremony: {}\n", .{err});
        std.process.exit(2);
    };
    defer client.disconnect();

    try client.run();

    std.debug.print("\nCeremony complete.\n", .{});
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

fn handleVerify(allocator: std.mem.Allocator, io: Io, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: covenant verify <artifact.json>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[0];
    const content = Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(1024 * 1024)) catch |err| {
        std.debug.print("Error: cannot read {s}: {}\n", .{ file_path, err });
        std.process.exit(1);
    };
    defer allocator.free(content);

    var result = verify_mod.verifyCovenant(allocator, content) catch |err| {
        std.debug.print("\x1b[38;5;196mVerification FAILED: {}\x1b[0m\n", .{err});
        std.process.exit(1);
    };
    defer verify_mod.freeVerifyResult(allocator, &result);

    std.debug.print("\n\x1b[38;5;45mCovenant Verification\x1b[0m\n\n", .{});
    std.debug.print("\x1b[38;5;245mFile:\x1b[0m      {s}\n", .{file_path});
    if (result.group_name) |name| {
        std.debug.print("\x1b[38;5;245mGroup:\x1b[0m     {s}\n", .{name});
    }
    std.debug.print("\x1b[38;5;245mMembers:\x1b[0m   {d}\n", .{result.member_count});

    // Show each member's verification status
    for (result.members) |m| {
        const status = if (m.valid) "\x1b[38;5;82m\xe2\x9c\x93\x1b[0m" else "\x1b[38;5;196m\xe2\x9c\x97\x1b[0m";
        std.debug.print("  {s} {s}  \x1b[38;5;240m{x:0>2}{x:0>2}{x:0>2}{x:0>2}...\x1b[0m\n", .{
            status, m.nick, m.pubkey[0], m.pubkey[1], m.pubkey[2], m.pubkey[3],
        });
    }

    std.debug.print("\n", .{});
    if (result.valid) {
        std.debug.print("\x1b[38;5;82mAll signatures valid.\x1b[0m\n\n", .{});
    } else {
        std.debug.print("\x1b[38;5;196mSome signatures INVALID.\x1b[0m\n\n", .{});
        std.process.exit(1);
    }
}

fn handleMembers(allocator: std.mem.Allocator, io: Io, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: covenant members <artifact.json>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[0];
    const content = Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(1024 * 1024)) catch |err| {
        std.debug.print("Error: cannot read {s}: {}\n", .{ file_path, err });
        std.process.exit(1);
    };
    defer allocator.free(content);

    var result = verify_mod.verifyCovenant(allocator, content) catch |err| {
        std.debug.print("Error: cannot parse covenant: {}\n", .{err});
        std.process.exit(1);
    };
    defer verify_mod.freeVerifyResult(allocator, &result);

    if (result.group_name) |name| {
        std.debug.print("\n\x1b[38;5;45m{s}\x1b[0m  ({d} members)\n\n", .{ name, result.member_count });
    } else {
        std.debug.print("\nCovenant ({d} members)\n\n", .{result.member_count});
    }

    for (result.members) |m| {
        // Full pubkey hex
        var pk_hex: [64]u8 = undefined;
        const charset = "0123456789abcdef";
        for (0..32) |j| {
            pk_hex[j * 2] = charset[m.pubkey[j] >> 4];
            pk_hex[j * 2 + 1] = charset[m.pubkey[j] & 0x0f];
        }
        std.debug.print("  {s}  \x1b[38;5;240m{s}\x1b[0m\n", .{ m.nick, &pk_hex });
    }
    std.debug.print("\n", .{});
}

test {
    // Pull in the unit tests from the sibling modules so `zig test main.zig`
    // exercises them all.
    _ = crypto;
    _ = id;
    _ = protocol;
    _ = artifact_mod;
    _ = verify_mod;
}

const protocol = @import("protocol.zig");
