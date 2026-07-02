const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const display = @import("display.zig");
const artifact_mod = @import("artifact.zig");

const Member = struct {
    stream: Io.net.Stream,
    nick: []const u8,
    pubkey: [32]u8,
    has_pubkey: bool,
    signature: ?[64]u8,
};

pub const ServerConfig = struct {
    port: u16,
    max_members: u8 = 32,
    local_only: bool = false,
    output_path: ?[]const u8 = null,
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
    port: u16,
    listener: Io.net.Server,
    config: ServerConfig,
    key: [32]u8,
    host_nick: []const u8,
    group_name: []const u8,
    session_id: [32]u8,
    host_identity: crypto.KeyPair,
    members: std.ArrayList(Member),
    members_mutex: Io.Mutex,
    phase: std.atomic.Value(u8),
    running: std.atomic.Value(bool),
    // Host's own signature
    host_signature: ?[64]u8,
    roster_hash: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        config: ServerConfig,
        key: [32]u8,
        host_nick: []const u8,
        group_name: []const u8,
        identity: crypto.KeyPair,
    ) !Server {
        const address = Io.net.IpAddress.parse("127.0.0.1", config.port) catch unreachable;
        var listener = try address.listen(io, .{
            .reuse_address = true,
        });
        errdefer listener.deinit(io);

        // When asked for port 0 the kernel picks one; report the real port.
        const actual_port = if (config.port != 0) config.port else boundPort(listener.socket.handle) orelse
            return error.PortDiscoveryFailed;

        var session_id: [32]u8 = undefined;
        io.random(&session_id);

        return Server{
            .allocator = allocator,
            .io = io,
            .port = actual_port,
            .listener = listener,
            .config = config,
            .key = key,
            .host_nick = host_nick,
            .group_name = group_name,
            .session_id = session_id,
            .host_identity = identity,
            .members = try std.ArrayList(Member).initCapacity(allocator, 0),
            .members_mutex = .init,
            .phase = std.atomic.Value(u8).init(@intFromEnum(protocol.Phase.lobby)),
            .running = std.atomic.Value(bool).init(true),
            .host_signature = null,
            .roster_hash = [_]u8{0} ** 32,
        };
    }

    pub fn run(self: *Server) !void {
        display.printStatus("Waiting for members... (/seal to sign, /abort to cancel)");

        const stdin_thread = std.Thread.spawn(.{}, Server.readHostStdin, .{self}) catch |err| {
            std.debug.print("Failed to spawn stdin thread: {}\n", .{err});
            return err;
        };
        defer stdin_thread.detach();

        while (self.running.load(.monotonic)) {
            const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
            if (current_phase != .lobby) break;

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

        // Wait for protocol to complete
        while (self.running.load(.monotonic)) {
            const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
            if (current_phase == .done) break;
            self.io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
    }

    fn handleConnection(self: *Server, stream: Io.net.Stream) void {
        const io = self.io;

        // Slow-loris guard: bound the handshake read so a connection that never
        // sends a valid JOIN can't pin this thread indefinitely. Cleared once the
        // member is admitted (see below) so idle lobby members aren't dropped.
        const handshake_tv = std.posix.timeval{ .sec = 30, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&handshake_tv)) catch {};

        // One persistent reader for the whole connection: the interface buffers
        // ahead, so a transient reader per frame would drop bytes.
        var read_buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(io, &read_buf);
        const in = &stream_reader.interface;

        // Read JOIN frame
        const join_frame = protocol.readFrame(self.allocator, in) catch {
            stream.close(io);
            return;
        };
        defer {
            var mutable_frame = join_frame;
            protocol.freeFrame(self.allocator, &mutable_frame);
        }

        if (join_frame.msg_type != .join) {
            stream.close(io);
            return;
        }

        // Decrypt and verify MAGIC
        const plaintext = crypto.decryptRaw(
            self.allocator,
            join_frame.nonce,
            join_frame.tag,
            join_frame.ciphertext,
            self.key,
        ) catch {
            stream.close(io);
            return;
        };
        defer self.allocator.free(plaintext);

        if (plaintext.len != protocol.MAGIC.len or !std.crypto.timing_safe.eql([protocol.MAGIC.len]u8, plaintext[0..protocol.MAGIC.len].*, protocol.MAGIC[0..protocol.MAGIC.len].*)) {
            stream.close(io);
            return;
        }

        // Only accept during lobby
        const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
        if (current_phase != .lobby) {
            stream.close(io);
            return;
        }

        // Resolve nick collision
        const nick = self.resolveNickCollision(join_frame.sender) catch {
            stream.close(io);
            return;
        };

        // Add member. The cap check shares the lock with the append so it is
        // atomic: this enforces max_members and keeps the u8 member count used
        // by serializeRoster from overflowing — the serialized roster is
        // members.len + 1 (host in slot 0), and max_members is clamped to 254
        // at parse time, so len + 1 <= 255.
        self.members_mutex.lockUncancelable(io);
        if (self.members.items.len >= self.config.max_members) {
            self.members_mutex.unlock(io);
            self.allocator.free(nick);
            display.printStatus("Member limit reached, rejecting connection.");
            stream.close(io);
            return;
        }
        self.members.append(self.allocator, .{
            .stream = stream,
            .nick = nick,
            .pubkey = [_]u8{0} ** 32,
            .has_pubkey = false,
            .signature = null,
        }) catch {
            self.members_mutex.unlock(io);
            self.allocator.free(nick);
            stream.close(io);
            return;
        };
        const member_count = self.members.items.len + 1; // +1 for host
        self.members_mutex.unlock(io);

        // Handshake complete: clear the recv timeout so an admitted member isn't
        // dropped while idling in the lobby waiting for the host to /seal.
        const clear_tv = std.posix.timeval{ .sec = 0, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&clear_tv)) catch {};

        display.printMemberJoined(nick, member_count);

        // Send group name to joiner
        self.sendGroupInfo(stream);

        // Enter member read loop
        self.memberReadLoop(stream, in);

        // Cleanup on disconnect
        self.removeMember(stream);
    }

    fn memberReadLoop(self: *Server, stream: Io.net.Stream, in: *Io.Reader) void {
        while (self.running.load(.monotonic)) {
            const frame = protocol.readFrame(self.allocator, in) catch {
                return;
            };
            defer {
                var mutable_frame = frame;
                protocol.freeFrame(self.allocator, &mutable_frame);
            }

            const plaintext = crypto.decryptRaw(
                self.allocator,
                frame.nonce,
                frame.tag,
                frame.ciphertext,
                self.key,
            ) catch continue;
            defer self.allocator.free(plaintext);

            switch (frame.msg_type) {
                .pubkey => {
                    if (plaintext.len == 32) {
                        self.members_mutex.lockUncancelable(self.io);
                        for (self.members.items) |*member| {
                            if (member.stream.socket.handle == stream.socket.handle) {
                                @memcpy(&member.pubkey, plaintext[0..32]);
                                member.has_pubkey = true;
                                break;
                            }
                        }
                        self.members_mutex.unlock(self.io);
                    }
                },
                .signature => {
                    if (plaintext.len == 64) {
                        self.members_mutex.lockUncancelable(self.io);
                        for (self.members.items) |*member| {
                            if (member.stream.socket.handle == stream.socket.handle) {
                                var sig: [64]u8 = undefined;
                                @memcpy(&sig, plaintext[0..64]);

                                // Verify signature against member's pubkey
                                if (crypto.verifyRosterSig(self.roster_hash, sig, member.pubkey)) {
                                    member.signature = sig;
                                }
                                break;
                            }
                        }
                        const received = self.countSignatures();
                        const total = self.members.items.len + 1;
                        self.members_mutex.unlock(self.io);

                        display.printProgress("Collecting signatures", received, total);

                        if (received == total) {
                            self.finishCovenant();
                        }
                    }
                },
                .leave => return,
                else => {},
            }
        }
    }

    fn countSignatures(self: *Server) usize {
        // Must hold members_mutex
        var count: usize = if (self.host_signature != null) @as(usize, 1) else 0;
        for (self.members.items) |member| {
            if (member.signature != null) count += 1;
        }
        return count;
    }

    fn startSeal(self: *Server) void {
        // Build roster sorted by pubkey
        const roster = self.buildSortedRoster() catch return;
        defer self.allocator.free(roster);

        self.roster_hash = crypto.computeRosterHash(roster);
        self.phase.store(@intFromEnum(protocol.Phase.seal), .monotonic);

        // Broadcast roster then phase
        self.broadcastRoster(roster);
        self.broadcastPhase(.seal);

        display.printSealStart(roster.len);

        // Host signs immediately
        const sig = crypto.signRoster(self.roster_hash, self.host_identity);
        self.host_signature = sig;

        self.members_mutex.lockUncancelable(self.io);
        const received = self.countSignatures();
        const total = self.members.items.len + 1;
        self.members_mutex.unlock(self.io);

        display.printProgress("Collecting signatures", received, total);

        if (received == total) {
            self.finishCovenant();
        }
    }

    fn finishCovenant(self: *Server) void {
        self.members_mutex.lockUncancelable(self.io);

        // Build signed members list (sorted by pubkey, same as roster)
        var signed = std.ArrayList(artifact_mod.SignedMember).initCapacity(self.allocator, 0) catch {
            self.members_mutex.unlock(self.io);
            return;
        };
        defer signed.deinit(self.allocator);

        // Collect all members including host
        const MemberEntry = struct {
            nick: []const u8,
            pubkey: [32]u8,
            signature: [64]u8,
        };
        var all_entries = std.ArrayList(MemberEntry).initCapacity(self.allocator, 0) catch {
            self.members_mutex.unlock(self.io);
            return;
        };
        defer all_entries.deinit(self.allocator);

        // Host entry
        all_entries.append(self.allocator, .{
            .nick = self.host_nick,
            .pubkey = crypto.publicKeyBytes(self.host_identity),
            .signature = self.host_signature orelse [_]u8{0} ** 64,
        }) catch {};

        // Member entries
        for (self.members.items) |member| {
            all_entries.append(self.allocator, .{
                .nick = member.nick,
                .pubkey = member.pubkey,
                .signature = member.signature orelse [_]u8{0} ** 64,
            }) catch {};
        }

        self.members_mutex.unlock(self.io);

        // Sort by pubkey
        std.mem.sort(MemberEntry, all_entries.items, {}, struct {
            fn lessThan(_: void, a: MemberEntry, b: MemberEntry) bool {
                return std.mem.order(u8, &a.pubkey, &b.pubkey) == .lt;
            }
        }.lessThan);

        // Convert to SignedMember
        for (all_entries.items) |entry| {
            signed.append(self.allocator, .{
                .nick = entry.nick,
                .pubkey = entry.pubkey,
                .signature = entry.signature,
            }) catch {};
        }

        display.printCovenantComplete(signed.items.len);

        // Build artifact
        const json = artifact_mod.buildCovenant(
            self.allocator,
            self.io,
            self.group_name,
            self.session_id,
            self.roster_hash,
            signed.items,
        ) catch |err| {
            std.debug.print("Failed to build covenant: {}\n", .{err});
            self.phase.store(@intFromEnum(protocol.Phase.done), .monotonic);
            self.running.store(false, .monotonic);
            return;
        };
        defer self.allocator.free(json);

        // Broadcast covenant to all members
        self.broadcastEncrypted(.covenant, json);

        // Output artifact
        if (self.config.output_path) |path| {
            const file = Io.Dir.cwd().createFile(self.io, path, .{}) catch |err| {
                std.debug.print("Error: cannot write {s}: {}\n", .{ path, err });
                self.phase.store(@intFromEnum(protocol.Phase.done), .monotonic);
                self.running.store(false, .monotonic);
                return;
            };
            defer file.close(self.io);
            file.writeStreamingAll(self.io, json) catch {};
            file.writeStreamingAll(self.io, "\n") catch {};
            std.debug.print("\x1b[38;5;245mCovenant saved to:\x1b[0m {s}\n", .{path});
        } else {
            const stdout = Io.File.stdout();
            stdout.writeStreamingAll(self.io, json) catch {};
            stdout.writeStreamingAll(self.io, "\n") catch {};
        }

        self.phase.store(@intFromEnum(protocol.Phase.done), .monotonic);
        self.running.store(false, .monotonic);
    }

    fn buildSortedRoster(self: *Server) ![]protocol.MemberInfo {
        self.members_mutex.lockUncancelable(self.io);
        defer self.members_mutex.unlock(self.io);

        var roster = try self.allocator.alloc(protocol.MemberInfo, self.members.items.len + 1);
        errdefer self.allocator.free(roster);

        // Host
        roster[0] = .{
            .nick = self.host_nick,
            .pubkey = crypto.publicKeyBytes(self.host_identity),
        };

        // Members
        for (self.members.items, 0..) |member, i| {
            roster[i + 1] = .{
                .nick = member.nick,
                .pubkey = member.pubkey,
            };
        }

        // Sort by pubkey for determinism
        std.mem.sort(protocol.MemberInfo, roster, {}, struct {
            fn lessThan(_: void, a: protocol.MemberInfo, b: protocol.MemberInfo) bool {
                return std.mem.order(u8, &a.pubkey, &b.pubkey) == .lt;
            }
        }.lessThan);

        return roster;
    }

    fn broadcastRoster(self: *Server, roster: []const protocol.MemberInfo) void {
        const payload = protocol.serializeRoster(self.allocator, roster) catch return;
        defer self.allocator.free(payload);
        self.broadcastEncrypted(.roster, payload);
    }

    fn broadcastPhase(self: *Server, phase: protocol.Phase) void {
        const payload = protocol.serializePhase(phase);
        self.broadcastEncrypted(.phase, &payload);
    }

    fn broadcastEncrypted(self: *Server, msg_type: protocol.MessageType, payload: []const u8) void {
        var encrypted = crypto.encrypt(self.allocator, self.io, payload, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = msg_type,
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        self.members_mutex.lockUncancelable(self.io);
        for (self.members.items) |member| {
            protocol.sendFrame(self.io, member.stream, frame) catch {};
        }
        self.members_mutex.unlock(self.io);
    }

    fn sendGroupInfo(self: *Server, stream: Io.net.Stream) void {
        // Send group name as a roster message with just the name
        var encrypted = crypto.encrypt(self.allocator, self.io, self.group_name, self.key) catch return;
        defer encrypted.deinit();

        const frame = protocol.Frame{
            .msg_type = .phase, // reuse phase msg to send group info during lobby
            .timestamp = @as(u64, @intCast(Io.Clock.real.now(self.io).toSeconds())),
            .sender = "system",
            .nonce = encrypted.nonce,
            .tag = encrypted.tag,
            .ciphertext = encrypted.ciphertext,
        };

        protocol.sendFrame(self.io, stream, frame) catch {};
    }

    fn removeMember(self: *Server, stream: Io.net.Stream) void {
        self.members_mutex.lockUncancelable(self.io);
        defer self.members_mutex.unlock(self.io);

        for (self.members.items, 0..) |member, i| {
            if (member.stream.socket.handle == stream.socket.handle) {
                const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));
                if (current_phase == .lobby) {
                    display.printMemberLeft(member.nick, self.members.items.len);
                }
                self.allocator.free(member.nick);
                _ = self.members.orderedRemove(i);
                return;
            }
        }
    }

    fn resolveNickCollision(self: *Server, nick: []const u8) ![]const u8 {
        self.members_mutex.lockUncancelable(self.io);
        defer self.members_mutex.unlock(self.io);

        var has_collision = std.mem.eql(u8, nick, self.host_nick);
        if (!has_collision) {
            for (self.members.items) |member| {
                if (std.mem.eql(u8, nick, member.nick)) {
                    has_collision = true;
                    break;
                }
            }
        }

        if (!has_collision) {
            return try self.allocator.dupe(u8, nick);
        }

        var suffix: u8 = 2;
        while (suffix < 100) : (suffix += 1) {
            const new_nick = try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ nick, suffix });
            var collision = std.mem.eql(u8, new_nick, self.host_nick);

            if (!collision) {
                for (self.members.items) |member| {
                    if (std.mem.eql(u8, new_nick, member.nick)) {
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
        var buffer: [4096]u8 = undefined;

        while (self.running.load(.monotonic)) {
            const bytes_read = std.posix.read(std.posix.STDIN_FILENO, &buffer) catch break;
            if (bytes_read == 0) break;
            const line = std.mem.trimEnd(u8, buffer[0..bytes_read], "\n\r");
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) continue;

            const current_phase: protocol.Phase = @enumFromInt(self.phase.load(.monotonic));

            if (std.mem.eql(u8, trimmed, "/abort")) {
                display.printStatus("Ceremony aborted.");
                self.running.store(false, .monotonic);
                self.pokeListener();
                break;
            }

            switch (current_phase) {
                .lobby => {
                    if (std.mem.eql(u8, trimmed, "/seal")) {
                        self.members_mutex.lockUncancelable(self.io);
                        const count = self.members.items.len;
                        // Check all members have pubkeys
                        var all_ready = true;
                        for (self.members.items) |member| {
                            if (!member.has_pubkey) {
                                all_ready = false;
                                break;
                            }
                        }
                        self.members_mutex.unlock(self.io);

                        if (count == 0) {
                            display.printError("Need at least one other member to seal.");
                            continue;
                        }
                        if (!all_ready) {
                            display.printError("Not all members have exchanged keys yet. Wait a moment.");
                            continue;
                        }
                        self.startSeal();
                        self.pokeListener();
                    }
                },
                else => {},
            }
        }
    }

    fn pokeListener(self: *Server) void {
        const addr = Io.net.IpAddress.parse("127.0.0.1", self.port) catch return;
        if (addr.connect(self.io, .{ .mode = .stream, .timeout = .none })) |conn| {
            conn.close(self.io);
        } else |_| {}
    }

    pub fn shutdown(self: *Server) void {
        self.running.store(false, .monotonic);

        self.members_mutex.lockUncancelable(self.io);
        for (self.members.items) |member| {
            member.stream.close(self.io);
            self.allocator.free(member.nick);
        }
        self.members.deinit(self.allocator);
        self.members_mutex.unlock(self.io);

        self.listener.deinit(self.io);

        std.crypto.secureZero(u8, &self.key);
    }
};
