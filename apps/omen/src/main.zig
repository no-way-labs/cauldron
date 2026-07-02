const std = @import("std");
const Io = std.Io;
const server_mod = @import("server.zig");
const client_mod = @import("client.zig");
const tunnel = @import("tunnel.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const id = @import("id.zig");
const verify_mod = @import("verify.zig");

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
        std.debug.print("omen {s}\n", .{version});
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
        \\  --roster <file.json>   Restrict to covenant members
        \\  --identity <phrase>    Identity passphrase (required with --roster)
        \\
        \\Join options:
        \\  --password <pass>      Room password (required)
        \\  --nick <name>          Your display name (default: auto-generated)
        \\  --output <file>        Save artifact to file (default: stdout)
        \\  --timeout <secs>       Connection timeout (default: 30)
        \\  --identity <phrase>    Identity passphrase (required for restricted votes)
        \\
    , .{});
}

fn handleHost(allocator: std.mem.Allocator, io: Io, environ: *const std.process.Environ.Map, args: []const [:0]const u8) !void {
    var port: u16 = 0;
    var bore_port: u16 = 0;
    var local_only = false;
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var max_voters: u8 = 32;
    var question_opt: ?[]const u8 = null;
    var options_str: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var roster_path: ?[]const u8 = null;
    var identity_opt: ?[]const u8 = null;

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
        } else if (std.mem.eql(u8, arg, "--roster") and i + 1 < args.len) {
            i += 1;
            roster_path = args[i];
        } else if (std.mem.eql(u8, arg, "--identity") and i + 1 < args.len) {
            i += 1;
            identity_opt = args[i];
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

    // Resolve identity phrase: --identity flag, else OMEN_IDENTITY env.
    const identity_phrase = try resolveSecret(allocator, environ, identity_opt, "OMEN_IDENTITY");
    defer if (identity_phrase) |p| allocator.free(p);

    // Load covenant roster if provided
    var allowed_pubkeys: ?[][32]u8 = null;
    defer if (allowed_pubkeys) |keys| allocator.free(keys);

    if (roster_path) |rpath| {
        if (identity_phrase == null) {
            std.debug.print("Error: --identity (or OMEN_IDENTITY) is required when using --roster\n", .{});
            std.process.exit(1);
        }
        allowed_pubkeys = loadCovenantPubkeys(allocator, io, rpath) catch |err| {
            std.debug.print("Error: cannot load roster {s}: {}\n", .{ rpath, err });
            std.process.exit(1);
        };
    }

    // Derive identity keypair or generate ephemeral
    const host_keypair = if (identity_phrase) |phrase|
        crypto.deriveIdentity(io, phrase)
    else
        crypto.generateKeyPair(io);

    // Password: --password flag, else OMEN_PASSWORD env, else auto-generate.
    const password = (try resolveSecret(allocator, environ, password_opt, "OMEN_PASSWORD")) orelse
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
        .max_voters = max_voters,
        .local_only = local_only,
        .output_path = output_path,
        .allowed_pubkeys = allowed_pubkeys,
    }, key, nick, question, options_list.items, host_keypair);
    defer srv.shutdown();

    // Get the actual port the server bound to
    const actual_port = srv.port;

    // Print room info (all to stderr)
    display.printBanner(version);
    display.printBallot(question, options_list.items);
    if (roster_path) |rpath| {
        std.debug.print("\x1b[38;5;245mRoster:\x1b[0m {s} ({d} members)\n", .{ rpath, if (allowed_pubkeys) |k| k.len else 0 });
    }
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
            std.debug.print("  \x1b[38;5;240momen join {s}:{d} --password {s}\x1b[0m\n\n", .{
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

fn handleJoin(allocator: std.mem.Allocator, io: Io, environ: *const std.process.Environ.Map, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: omen join <host:port> --password <pass>\n", .{});
        std.process.exit(1);
    }

    const target = args[0];
    var password_opt: ?[]const u8 = null;
    var nick_opt: ?[]const u8 = null;
    var join_output_path: ?[]const u8 = null;
    var join_identity_opt: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, arg, "--identity") and i + 1 < args.len) {
            i += 1;
            join_identity_opt = args[i];
        } else if (std.mem.eql(u8, arg, "--timeout") and i + 1 < args.len) {
            i += 1;
            timeout_secs = std.fmt.parseInt(u64, args[i], 10) catch {
                std.debug.print("Error: timeout must be a valid number\n", .{});
                std.process.exit(1);
            };
        }
    }

    const password = (try resolveSecret(allocator, environ, password_opt, "OMEN_PASSWORD")) orelse {
        std.debug.print("Error: --password (or OMEN_PASSWORD) is required\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(password);
    const key = crypto.deriveKey(io, password);

    // Identity phrase: --identity flag, else OMEN_IDENTITY env.
    const join_identity_phrase = try resolveSecret(allocator, environ, join_identity_opt, "OMEN_IDENTITY");
    defer if (join_identity_phrase) |p| allocator.free(p);
    const join_keypair = if (join_identity_phrase) |phrase|
        crypto.deriveIdentity(io, phrase)
    else
        crypto.generateKeyPair(io);

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
    std.debug.print("\x1b[38;5;245mConnected as:\x1b[0m {s}\n", .{nick});

    var client = client_mod.Client.connect(allocator, io, host, port, key, join_keypair, .{
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

fn handleVerify(allocator: std.mem.Allocator, io: Io, args: []const [:0]const u8) !void {
    if (args.len < 1) {
        std.debug.print("Usage: omen verify <artifact.json>\n", .{});
        std.process.exit(1);
    }

    const file_path = args[0];
    const content = Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(1024 * 1024)) catch |err| {
        std.debug.print("Error: cannot read {s}: {}\n", .{ file_path, err });
        std.process.exit(1);
    };
    defer allocator.free(content);

    var result = verify_mod.verifyArtifact(allocator, content) catch |err| {
        std.debug.print("\x1b[38;5;196mVerification FAILED: cannot parse artifact ({})\x1b[0m\n", .{err});
        std.process.exit(1);
    };
    defer result.deinit(allocator);

    std.debug.print("\n\x1b[38;5;45mOmen Artifact Verification\x1b[0m\n\n", .{});
    std.debug.print("\x1b[38;5;245mFile:\x1b[0m     {s}\n", .{file_path});
    std.debug.print("\x1b[38;5;245mQuestion:\x1b[0m {s}\n", .{result.question});
    std.debug.print("\x1b[38;5;245mVoters:\x1b[0m   {d}\n\n", .{result.voter_count});

    printCheck("Host signature", result.host_sig_valid);
    printCheck("Roster hash", result.roster_hash_valid);
    printCheck("Commitment signatures", result.commit_sigs_valid);
    printCheck("One commitment per roster member", result.roster_complete);
    printCheck("Reveal bijection", result.bijection_valid);
    printCheck("Tally recomputation", result.tally_matches);
    printCheck("Winner matches tally", result.winner_valid);

    std.debug.print("\n\x1b[38;5;245mTally:\x1b[0m\n", .{});
    for (result.options, 0..) |opt, i| {
        std.debug.print("  {s}: {d}\n", .{ opt, result.counts[i] });
    }
    if (result.winner.len > 0) {
        std.debug.print("\x1b[38;5;245mWinner:\x1b[0m {s}\n", .{result.winner});
    }

    std.debug.print("\n", .{});
    if (result.all_valid) {
        std.debug.print("\x1b[38;5;82mArtifact is authentic and internally consistent.\x1b[0m\n", .{});
        std.debug.print("\x1b[38;5;245m(Proves the host did not alter the recorded votes. Voter eligibility\n", .{});
        std.debug.print(" is only guaranteed if the vote was run with --roster.)\x1b[0m\n\n", .{});
    } else {
        std.debug.print("\x1b[38;5;196mVerification FAILED — artifact is tampered or inconsistent.\x1b[0m\n\n", .{});
        std.process.exit(1);
    }
}

fn printCheck(label: []const u8, ok: bool) void {
    const mark = if (ok) "\x1b[38;5;82m\xe2\x9c\x93\x1b[0m" else "\x1b[38;5;196m\xe2\x9c\x97\x1b[0m";
    std.debug.print("  {s} {s}\n", .{ mark, label });
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

/// Read a covenant JSON artifact from disk and return its member pubkeys.
fn loadCovenantPubkeys(allocator: std.mem.Allocator, io: Io, path: []const u8) ![][32]u8 {
    const content = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(content);
    return parseCovenantPubkeys(allocator, content);
}

/// Parse the covenant member pubkeys (the voter-eligibility allowlist) from a
/// covenant JSON artifact using std.json, so whitespace/pretty-printed layouts
/// parse identically. A malformed member — missing, non-hex, or wrong-length
/// pubkey — is a HARD error, never a skip: silently dropping an entry would
/// silently disenfranchise that member. An empty roster is `NoPubkeysFound`.
fn parseCovenantPubkeys(allocator: std.mem.Allocator, json: []const u8) ![][32]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidCovenant;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidCovenant;

    const members_val = parsed.value.object.get("members") orelse return error.InvalidCovenant;
    if (members_val != .array) return error.InvalidCovenant;
    const members = members_val.array.items;

    if (members.len == 0) return error.NoPubkeysFound;

    var pubkeys = try allocator.alloc([32]u8, members.len);
    errdefer allocator.free(pubkeys);

    for (members, 0..) |member, i| {
        if (member != .object) return error.InvalidCovenant;
        const pk_val = member.object.get("pubkey") orelse return error.InvalidCovenant;
        if (pk_val != .string or pk_val.string.len != 64) return error.InvalidCovenant;
        _ = std.fmt.hexToBytes(&pubkeys[i], pk_val.string) catch return error.InvalidCovenant;
    }

    return pubkeys;
}

// In Zig 0.16 `zig test main.zig` only discovers tests declared in the root
// file; pull in the module tests (protocol framing/fuzz, verify's artifact and
// security checks, crypto, id) so a single `zig test` on this entrypoint
// exercises the whole suite.
test {
    _ = @import("crypto.zig");
    _ = @import("protocol.zig");
    _ = @import("verify.zig");
    _ = @import("id.zig");
}

test "parseCovenantPubkeys parses pretty-printed JSON" {
    const allocator = std.testing.allocator;
    const json =
        "{\n" ++
        "  \"members\": [\n" ++
        "    { \"nick\": \"alice\", \"pubkey\": \"" ++ ("aa" ** 32) ++ "\" },\n" ++
        "    { \"nick\": \"bob\",   \"pubkey\": \"" ++ ("bb" ** 32) ++ "\" }\n" ++
        "  ]\n" ++
        "}";
    const keys = try parseCovenantPubkeys(allocator, json);
    defer allocator.free(keys);
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqual(@as(u8, 0xaa), keys[0][0]);
    try std.testing.expectEqual(@as(u8, 0xbb), keys[1][31]);
}

test "parseCovenantPubkeys rejects malformed pubkey hex" {
    const allocator = std.testing.allocator;
    // 'zz' is not valid hex — a hard error, not a silently dropped member.
    const json = "{\"members\":[{\"pubkey\":\"" ++ ("zz" ** 32) ++ "\"}]}";
    try std.testing.expectError(error.InvalidCovenant, parseCovenantPubkeys(allocator, json));
}

test "parseCovenantPubkeys rejects wrong-length pubkey" {
    const allocator = std.testing.allocator;
    const json = "{\"members\":[{\"pubkey\":\"abcd\"}]}";
    try std.testing.expectError(error.InvalidCovenant, parseCovenantPubkeys(allocator, json));
}

test "parseCovenantPubkeys rejects a member missing its pubkey" {
    const allocator = std.testing.allocator;
    const json = "{\"members\":[{\"nick\":\"alice\"}]}";
    try std.testing.expectError(error.InvalidCovenant, parseCovenantPubkeys(allocator, json));
}

test "parseCovenantPubkeys rejects empty members" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NoPubkeysFound, parseCovenantPubkeys(allocator, "{\"members\":[]}"));
}
