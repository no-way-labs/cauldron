const std = @import("std");
const claude = @import("claude.zig");

pub const version = "0.1.1";

const Config = struct {
    api_host: []const u8,
    api_port: u16,
    system_prompt: ?[]const u8,
    context_size: usize,
    model: []const u8,
    cooldown_secs: u64,
};

const SeanceMessage = struct {
    id: u64,
    sender: []const u8,
    content: []const u8,
    msg_type: []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var config = Config{
        .api_host = "127.0.0.1",
        .api_port = 9999,
        .system_prompt = null,
        .context_size = 50,
        .model = "claude-sonnet-4-5-20250929",
        .cooldown_secs = 2,
    };

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--help") or eql(args[i], "-h")) {
            printUsage();
            return;
        } else if (eql(args[i], "--version") or eql(args[i], "-v")) {
            std.debug.print("familiar {s}\n", .{version});
            return;
        } else if (eql(args[i], "--api-port")) {
            i += 1;
            if (i >= args.len) fatal("--api-port requires a port number");
            config.api_port = std.fmt.parseInt(u16, args[i], 10) catch
                fatal("invalid --api-port value");
        } else if (eql(args[i], "--api-host")) {
            i += 1;
            if (i >= args.len) fatal("--api-host requires a hostname");
            config.api_host = args[i];
        } else if (eql(args[i], "--system")) {
            i += 1;
            if (i >= args.len) fatal("--system requires a prompt");
            config.system_prompt = args[i];
        } else if (eql(args[i], "--context")) {
            i += 1;
            if (i >= args.len) fatal("--context requires a number");
            config.context_size = std.fmt.parseInt(usize, args[i], 10) catch
                fatal("invalid --context value");
        } else if (eql(args[i], "--model")) {
            i += 1;
            if (i >= args.len) fatal("--model requires a model name");
            config.model = args[i];
        } else if (eql(args[i], "--cooldown")) {
            i += 1;
            if (i >= args.len) fatal("--cooldown requires seconds");
            config.cooldown_secs = std.fmt.parseInt(u64, args[i], 10) catch
                fatal("invalid --cooldown value");
        } else {
            std.debug.print("Unknown option: {s}\n", .{args[i]});
            printUsage();
            std.process.exit(1);
        }
    }

    logTs();
    std.debug.print("familiar {s}\n", .{version});
    logTs();
    std.debug.print("Connecting to seance bot at {s}:{d}\n", .{ config.api_host, config.api_port });

    // Get OAuth token
    const token = claude.getToken(allocator) catch |err| {
        std.debug.print("Failed to get token: {}\n", .{err});
        std.debug.print("Set CLAUDE_CODE_OAUTH_TOKEN or run 'claude setup-token'\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(token);
    logTs();
    std.debug.print("Claude token acquired.\n", .{});

    // Initialize HTTP client (only used for Claude HTTPS API)
    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    // Check seance bot health
    const health = rawHttpGet(allocator, config.api_host, config.api_port, "/health") catch |err| {
        std.debug.print("Seance bot not reachable at {s}:{d}: {}\n", .{ config.api_host, config.api_port, err });
        std.debug.print("Make sure seance is running with --bot --api-port <port>\n", .{});
        std.process.exit(1);
    };
    allocator.free(health);
    logTs();
    std.debug.print("Seance bot connected.\n", .{});

    // Detect our nick
    const my_nick = detectNick(allocator, config.api_host, config.api_port) catch |err| {
        std.debug.print("Failed to detect nick: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(my_nick);
    logTs();
    std.debug.print("Joined as: {s}\n", .{my_nick});
    logTs();
    std.debug.print("Listening for messages...\n", .{});

    // Message history for Claude context
    var history: std.ArrayList(ChatMessage) = .{};
    defer {
        for (history.items) |msg| {
            allocator.free(msg.content);
        }
        history.deinit(allocator);
    }

    // Main poll loop
    var last_id: u64 = 0;
    while (true) {
        const path = std.fmt.allocPrint(allocator, "/messages?since={d}&wait=30", .{last_id}) catch continue;
        defer allocator.free(path);

        const body = rawHttpGet(allocator, config.api_host, config.api_port, path) catch {
            std.Thread.sleep(5 * std.time.ns_per_s);
            continue;
        };
        defer allocator.free(body);

        const messages = parseMessages(allocator, body) catch continue;
        defer {
            for (messages) |msg| {
                allocator.free(msg.sender);
                allocator.free(msg.content);
                allocator.free(msg.msg_type);
            }
            allocator.free(messages);
        }

        var needs_response = false;
        for (messages) |msg| {
            if (msg.id > last_id) last_id = msg.id;

            if (!eql(msg.msg_type, "msg")) continue;

            // Add to history
            const role: ChatRole = if (eql(msg.sender, my_nick)) .assistant else .user;
            const content = if (role == .user)
                std.fmt.allocPrint(allocator, "{s}: {s}", .{ msg.sender, msg.content }) catch continue
            else
                allocator.dupe(u8, msg.content) catch continue;

            history.append(allocator, .{ .role = role, .content = content }) catch {
                allocator.free(content);
                continue;
            };

            // Trim history to context size
            while (history.items.len > config.context_size) {
                allocator.free(history.items[0].content);
                _ = history.orderedRemove(0);
            }

            if (role == .user) needs_response = true;
        }

        if (needs_response) {
            logTs();
            std.debug.print("Calling Claude API...\n", .{});
            const response = claude.chat(
                allocator,
                &http_client,
                token,
                config.model,
                config.system_prompt,
                history.items,
            ) catch |err| {
                logTs();
                std.debug.print("Claude API error: {}\n", .{err});
                continue;
            };
            defer allocator.free(response);

            // Send response to seance
            rawHttpPost(allocator, config.api_host, config.api_port, "/send", response) catch |err| {
                logTs();
                std.debug.print("Failed to send message: {}\n", .{err});
                continue;
            };

            logTs();
            std.debug.print("[familiar] {s}\n", .{response});

            // Add our response to history
            const owned = allocator.dupe(u8, response) catch continue;
            history.append(allocator, .{ .role = .assistant, .content = owned }) catch {
                allocator.free(owned);
                continue;
            };
            while (history.items.len > config.context_size) {
                allocator.free(history.items[0].content);
                _ = history.orderedRemove(0);
            }

            std.Thread.sleep(config.cooldown_secs * std.time.ns_per_s);
        }
    }
}

// --- Chat types ---

pub const ChatRole = enum { user, assistant };

pub const ChatMessage = struct {
    role: ChatRole,
    content: []const u8,
};

// --- Seance bot API ---

fn detectNick(allocator: std.mem.Allocator, host: []const u8, port: u16) ![]u8 {
    const body = try rawHttpGet(allocator, host, port, "/nick");
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const nick = parsed.value.object.get("nick") orelse return error.NoNickField;
    return try allocator.dupe(u8, nick.string);
}

fn parseMessages(allocator: std.mem.Allocator, body: []const u8) ![]SeanceMessage {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const array = parsed.value.array;
    var messages = try allocator.alloc(SeanceMessage, array.items.len);
    errdefer allocator.free(messages);

    for (array.items, 0..) |item, idx| {
        const obj = item.object;
        messages[idx] = .{
            .id = @intCast(obj.get("id").?.integer),
            .sender = try allocator.dupe(u8, obj.get("sender").?.string),
            .content = try allocator.dupe(u8, obj.get("content").?.string),
            .msg_type = try allocator.dupe(u8, obj.get("type").?.string),
        };
    }

    return messages;
}

// --- Raw HTTP (for localhost seance bot API) ---

fn rawHttpGet(allocator: std.mem.Allocator, host: []const u8, port: u16, path: []const u8) ![]u8 {
    const addr = try std.net.Address.parseIp(host, port);
    const stream = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(stream);

    try std.posix.connect(stream, &addr.any, addr.getOsSockLen());

    // Send GET request
    var req_buf: [1024]u8 = undefined;
    const req = std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n\r\n", .{ path, host, port }) catch return error.RequestTooLong;

    var sent: usize = 0;
    while (sent < req.len) {
        const n = std.posix.send(stream, req[sent..], 0) catch return error.SendFailed;
        sent += n;
    }

    // Read response
    return readHttpBody(allocator, stream);
}

fn rawHttpPost(allocator: std.mem.Allocator, host: []const u8, port: u16, path: []const u8, body: []const u8) !void {
    const addr = try std.net.Address.parseIp(host, port);
    const stream = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0);
    defer std.posix.close(stream);

    try std.posix.connect(stream, &addr.any, addr.getOsSockLen());

    // Send POST request with body in a single write where possible
    var req_buf: [1024]u8 = undefined;
    const header = std.fmt.bufPrint(&req_buf, "POST {s} HTTP/1.1\r\nHost: {s}:{d}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ path, host, port, body.len }) catch return error.RequestTooLong;

    // Combine header and body into one send to avoid TCP framing issues
    const combined = try allocator.alloc(u8, header.len + body.len);
    defer allocator.free(combined);
    @memcpy(combined[0..header.len], header);
    @memcpy(combined[header.len..], body);

    var sent: usize = 0;
    while (sent < combined.len) {
        const n = std.posix.send(stream, combined[sent..], 0) catch return error.SendFailed;
        sent += n;
    }

    // Read response and check status
    const resp = try readHttpResponse(allocator, stream);
    defer allocator.free(resp.body);
    if (resp.status != 200) {
        std.debug.print("POST {s} returned {d}: {s}\n", .{ path, resp.status, resp.body });
        return error.SendFailed;
    }
}

const HttpResponse = struct {
    status: u16,
    body: []u8,
};

fn readHttpResponse(allocator: std.mem.Allocator, stream: std.posix.socket_t) !HttpResponse {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);

    var tmp: [4096]u8 = undefined;

    // Read until we have the full headers
    while (std.mem.indexOf(u8, buf.items, "\r\n\r\n") == null) {
        const n = std.posix.recv(stream, &tmp, 0) catch break;
        if (n == 0) break;
        try buf.appendSlice(allocator, tmp[0..n]);
    }

    const data = buf.items;
    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return error.NoBody;
    const body_start = header_end + 4;

    // Parse status code from first line (e.g. "HTTP/1.1 200 OK\r\n")
    var status: u16 = 0;
    if (std.mem.indexOf(u8, data[0..header_end], " ")) |sp| {
        const after_sp = sp + 1;
        const status_end = std.mem.indexOfScalarPos(u8, data[0..header_end], after_sp, ' ') orelse
            std.mem.indexOfScalarPos(u8, data[0..header_end], after_sp, '\r') orelse header_end;
        status = std.fmt.parseInt(u16, data[after_sp..status_end], 10) catch 0;
    }

    // Parse Content-Length from headers
    const headers = data[0..header_end];
    var content_length: usize = 0;
    if (std.mem.indexOf(u8, headers, "Content-Length: ")) |cl_pos| {
        const val_start = cl_pos + "Content-Length: ".len;
        const val_end = std.mem.indexOfScalarPos(u8, headers, val_start, '\r') orelse headers.len;
        content_length = std.fmt.parseInt(usize, headers[val_start..val_end], 10) catch 0;
    }

    // Read remaining body bytes if needed
    while (buf.items.len - body_start < content_length) {
        const n = std.posix.recv(stream, &tmp, 0) catch break;
        if (n == 0) break;
        try buf.appendSlice(allocator, tmp[0..n]);
    }

    return .{
        .status = status,
        .body = try allocator.dupe(u8, buf.items[body_start..]),
    };
}

fn readHttpBody(allocator: std.mem.Allocator, stream: std.posix.socket_t) ![]u8 {
    const resp = try readHttpResponse(allocator, stream);
    return resp.body;
}

// --- Utilities ---

fn logTs() void {
    const ts: u64 = @intCast(std.time.timestamp());
    const s = ts % 86400;
    std.debug.print("[{d:0>2}:{d:0>2}:{d:0>2}] ", .{ s / 3600, (s % 3600) / 60, s % 60 });
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn fatal(msg: []const u8) noreturn {
    std.debug.print("Error: {s}\n", .{msg});
    std.process.exit(1);
}

fn printUsage() void {
    std.debug.print(
        \\familiar {s} - Claude chat bot for seance rooms
        \\
        \\Usage: familiar [options]
        \\
        \\Options:
        \\  --api-port PORT  Seance bot API port (default: 9999)
        \\  --api-host HOST  Seance bot API host (default: 127.0.0.1)
        \\  --system PROMPT  Additional system prompt / personality
        \\  --context N      Messages to keep as context (default: 50)
        \\  --model MODEL    Claude model (default: claude-sonnet-4-5-20250929)
        \\  --cooldown SECS  Seconds between responses (default: 2)
        \\  -h, --help       Show this help
        \\  -v, --version    Show version
        \\
    , .{version});
}
