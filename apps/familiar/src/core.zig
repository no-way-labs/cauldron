const std = @import("std");
const Io = std.Io;

// --- Types ---

pub const ChatRole = enum { user, assistant };

pub const ChatMessage = struct {
    role: ChatRole,
    content: []const u8,
};

pub const Config = struct {
    api_host: []const u8 = "127.0.0.1",
    api_port: u16 = 9999,
    system_prompt: ?[]const u8 = null,
    context_size: usize = 50,
    model: []const u8 = "claude-sonnet-4-5-20250929",
    cooldown_secs: u64 = 2,
};

const SeanceMessage = struct {
    id: u64,
    sender: []const u8,
    content: []const u8,
    msg_type: []const u8,
};

// --- Main loop ---

/// Run the familiar bot loop. Blocks until `running` is set to false or an unrecoverable error.
/// Designed to be called from a thread (e.g. from seance --familiar) or directly from main().
pub fn run(allocator: std.mem.Allocator, io: Io, config: Config, environ: *const std.process.Environ.Map, running: ?*std.atomic.Value(bool)) void {
    runInner(allocator, io, config, environ, running) catch |err| {
        logTs(io);
        std.debug.print("familiar fatal: {}\n", .{err});
    };
}

fn runInner(allocator: std.mem.Allocator, io: Io, config: Config, environ: *const std.process.Environ.Map, running: ?*std.atomic.Value(bool)) !void {
    logTs(io);
    std.debug.print("familiar starting\n", .{});
    logTs(io);
    std.debug.print("Connecting to seance bot at {s}:{d}\n", .{ config.api_host, config.api_port });

    // Get API key
    var token = getToken(allocator, environ) catch |err| {
        logTs(io);
        std.debug.print("Failed to get token: {}\n", .{err});
        std.debug.print("Set ANTHROPIC_API_KEY env var\n", .{});
        return err;
    };
    defer allocator.free(token);
    logTs(io);
    std.debug.print("API key loaded.\n", .{});

    // Initialize HTTP client (only used for Claude HTTPS API)
    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    // Wait for seance bot to be ready (retry a few times)
    var health_attempts: u8 = 0;
    while (health_attempts < 10) : (health_attempts += 1) {
        if (running) |r| {
            if (!r.load(.monotonic)) return;
        }
        const health = rawHttpGet(allocator, io, config.api_host, config.api_port, "/health") catch {
            if (health_attempts == 0) {
                logTs(io);
                std.debug.print("Waiting for seance bot...\n", .{});
            }
            io.sleep(.fromSeconds(1), .awake) catch {};
            continue;
        };
        allocator.free(health);
        break;
    } else {
        logTs(io);
        std.debug.print("Seance bot not reachable at {s}:{d}\n", .{ config.api_host, config.api_port });
        return error.BotUnreachable;
    }
    logTs(io);
    std.debug.print("Seance bot connected.\n", .{});

    // Detect our nick
    const my_nick = try detectNick(allocator, io, config.api_host, config.api_port);
    defer allocator.free(my_nick);
    logTs(io);
    std.debug.print("Joined as: {s}\n", .{my_nick});
    logTs(io);
    std.debug.print("Listening for messages...\n", .{});

    // Message history for Claude context
    var history: std.ArrayList(ChatMessage) = .empty;
    defer {
        for (history.items) |msg| {
            allocator.free(msg.content);
        }
        history.deinit(allocator);
    }

    // Main poll loop
    var last_id: u64 = 0;
    while (true) {
        if (running) |r| {
            if (!r.load(.monotonic)) break;
        }

        const path = std.fmt.allocPrint(allocator, "/messages?since={d}&wait=30", .{last_id}) catch continue;
        defer allocator.free(path);

        const body = rawHttpGet(allocator, io, config.api_host, config.api_port, path) catch {
            io.sleep(.fromSeconds(5), .awake) catch {};
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

            if (!std.mem.eql(u8, msg.msg_type, "msg")) continue;

            // Add to history
            const role: ChatRole = if (std.mem.eql(u8, msg.sender, my_nick)) .assistant else .user;
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
            logTs(io);
            std.debug.print("Calling Claude API...\n", .{});
            const response = chat(
                allocator,
                &http_client,
                token,
                config.model,
                config.system_prompt,
                history.items,
            ) catch |err| {
                if (err == error.TokenExpired) {
                    logTs(io);
                    std.debug.print("Token expired, refreshing...\n", .{});
                    const new_token = getToken(allocator, environ) catch |te| {
                        logTs(io);
                        std.debug.print("Token refresh failed: {}\n", .{te});
                        continue;
                    };
                    allocator.free(token);
                    token = new_token;
                    logTs(io);
                    std.debug.print("Token refreshed.\n", .{});
                } else {
                    logTs(io);
                    std.debug.print("Claude API error: {}\n", .{err});
                }
                continue;
            };
            defer allocator.free(response);

            // Send response to seance
            rawHttpPost(allocator, io, config.api_host, config.api_port, "/send", response) catch |err| {
                logTs(io);
                std.debug.print("Failed to send message: {}\n", .{err});
                continue;
            };

            logTs(io);
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

            io.sleep(.fromSeconds(@intCast(config.cooldown_secs)), .awake) catch {};
        }
    }
}

// --- Claude API ---

const api_endpoint = "https://api.anthropic.com/v1/messages";
const anthropic_version = "2023-06-01";

/// Retrieve API key from ANTHROPIC_API_KEY env var.
pub fn getToken(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]u8 {
    const value = environ.get("ANTHROPIC_API_KEY") orelse return error.NoCredentials;
    if (value.len == 0) return error.NoCredentials;
    return try allocator.dupe(u8, value);
}

/// Call Claude API with conversation history. Returns the response text.
fn chat(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    token: []const u8,
    model: []const u8,
    system_prompt: ?[]const u8,
    messages: []const ChatMessage,
) ![]u8 {
    // Retry once on stale connection (server closed keep-alive after idle)
    var attempt: u8 = 0;
    while (attempt < 2) : (attempt += 1) {
        if (chatOnce(allocator, http_client, token, model, system_prompt, messages)) |response| {
            return response;
        } else |err| {
            if (err == error.HttpConnectionClosing and attempt == 0) continue;
            return err;
        }
    }
    unreachable;
}

fn chatOnce(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    token: []const u8,
    model: []const u8,
    system_prompt: ?[]const u8,
    messages: []const ChatMessage,
) ![]u8 {
    // Build JSON request body
    const body = try buildRequestBody(allocator, model, system_prompt, messages);
    defer allocator.free(body);

    const uri = try std.Uri.parse(api_endpoint);
    var req = try http_client.request(.POST, uri, .{
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = &.{
            .{ .name = "anthropic-version", .value = anthropic_version },
            .{ .name = "x-api-key", .value = token },
        },
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = body.len };
    var send_buf: [8192]u8 = undefined;
    var bw = try req.sendBodyUnflushed(&send_buf);
    try bw.writer.writeAll(body);
    try bw.end();
    try req.connection.?.flush();

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    if (response.head.status == .unauthorized) return error.TokenExpired;
    if (response.head.status != .ok) {
        // Read error body for debugging
        var transfer_buf: [16384]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        const err_body = reader.allocRemaining(allocator, .unlimited) catch null;
        if (err_body) |eb| {
            std.debug.print("Claude API {}: {s}\n", .{ response.head.status, eb });
            allocator.free(eb);
        }
        return error.ApiError;
    }

    var transfer_buf: [16384]u8 = undefined;
    const reader = response.reader(&transfer_buf);
    const response_body = try reader.allocRemaining(allocator, .unlimited);
    defer allocator.free(response_body);

    return try parseResponseText(allocator, response_body);
}

fn parseResponseText(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const content_array = parsed.value.object.get("content") orelse return error.NoContent;
    for (content_array.array.items) |block| {
        const obj = block.object;
        const block_type = obj.get("type") orelse continue;
        if (std.mem.eql(u8, block_type.string, "text")) {
            const text = obj.get("text") orelse continue;
            return try allocator.dupe(u8, text.string);
        }
    }
    return error.NoTextContent;
}

fn buildRequestBody(
    allocator: std.mem.Allocator,
    model: []const u8,
    system_prompt: ?[]const u8,
    messages: []const ChatMessage,
) ![]u8 {
    var json = std.ArrayList(u8).initCapacity(allocator, 0) catch unreachable;
    errdefer json.deinit(allocator);

    try json.appendSlice(allocator, "{\"model\":\"");
    try appendJsonEscaped(&json, allocator, model);
    const default_personality =
        "You are familiar, a chat bot in a seance room. " ++
        "You are friendly, concise, and conversational. Messages from others are formatted as 'nick: message'. " ++
        "Respond naturally without prefixing your nick. Keep responses brief unless asked for detail.";

    try json.appendSlice(allocator, "\",\"max_tokens\":4096,\"system\":[{\"type\":\"text\",\"text\":\"");
    try appendJsonEscaped(&json, allocator, system_prompt orelse default_personality);
    try json.appendSlice(allocator, "\"}],\"messages\":[");

    // Build messages array with strict role alternation
    var last_role: ?ChatRole = null;
    var first = true;
    for (messages) |msg| {
        if (last_role != null and last_role.? == msg.role) {
            // Same role - merge content with newline
            const trim_len: usize = 2; // "}
            json.shrinkRetainingCapacity(json.items.len - trim_len);
            try json.appendSlice(allocator, "\\n");
            try appendJsonEscaped(&json, allocator, msg.content);
            try json.appendSlice(allocator, "\"}");
        } else {
            if (!first) try json.append(allocator, ',');
            first = false;
            const role_str: []const u8 = if (msg.role == .user) "user" else "assistant";
            try json.appendSlice(allocator, "{\"role\":\"");
            try json.appendSlice(allocator, role_str);
            try json.appendSlice(allocator, "\",\"content\":\"");
            try appendJsonEscaped(&json, allocator, msg.content);
            try json.appendSlice(allocator, "\"}");
        }
        last_role = msg.role;
    }

    try json.appendSlice(allocator, "]}");

    return json.toOwnedSlice(allocator);
}

fn appendJsonEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, input: []const u8) !void {
    for (input) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const s = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch continue;
                    try list.appendSlice(allocator, s);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
}

// --- Seance bot API ---

// Tag-checked accessors: the bot API response is untrusted input, so never
// assert a JSON value's type with `.string`/`.integer` (those panic on a
// mismatch). Return null instead and let callers fail gracefully.
fn jsonString(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonInteger(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |n| n,
        else => null,
    };
}

fn detectNick(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16) ![]u8 {
    const body = try rawHttpGet(allocator, io, host, port, "/nick");
    defer allocator.free(body);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.BadMessage,
    };
    const nick_val = obj.get("nick") orelse return error.NoNickField;
    const nick = jsonString(nick_val) orelse return error.BadMessage;
    return try allocator.dupe(u8, nick);
}

fn parseMessages(allocator: std.mem.Allocator, body: []const u8) ![]SeanceMessage {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const array = switch (parsed.value) {
        .array => |a| a,
        else => return error.BadMessage,
    };

    var messages = try allocator.alloc(SeanceMessage, array.items.len);
    var built: usize = 0;
    errdefer {
        for (messages[0..built]) |m| {
            allocator.free(m.sender);
            allocator.free(m.content);
            allocator.free(m.msg_type);
        }
        allocator.free(messages);
    }

    for (array.items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.BadMessage,
        };

        const id = jsonInteger(obj.get("id") orelse return error.BadMessage) orelse return error.BadMessage;
        if (id < 0) return error.BadMessage;
        const sender_s = jsonString(obj.get("sender") orelse return error.BadMessage) orelse return error.BadMessage;
        const content_s = jsonString(obj.get("content") orelse return error.BadMessage) orelse return error.BadMessage;
        const type_s = jsonString(obj.get("type") orelse return error.BadMessage) orelse return error.BadMessage;

        const sender = try allocator.dupe(u8, sender_s);
        errdefer allocator.free(sender);
        const content = try allocator.dupe(u8, content_s);
        errdefer allocator.free(content);
        const msg_type = try allocator.dupe(u8, type_s);

        messages[built] = .{
            .id = @intCast(id),
            .sender = sender,
            .content = content,
            .msg_type = msg_type,
        };
        built += 1;
    }

    return messages;
}

// --- Raw HTTP (for localhost seance bot API) ---
//
// std.posix's socket/connect/send/recv/close were removed in Zig 0.16, so these
// talk to the localhost bot over std.Io.net. Every bot response sets
// `Connection: close` and the server half-closes after writing, so the whole
// response body ends at EOF — we read to EOF and split off the headers.

fn rawHttpGet(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16, path: []const u8) ![]u8 {
    const addr = Io.net.IpAddress.parse(host, port) catch return error.BadHost;
    const stream = try addr.connect(io, .{ .mode = .stream, .timeout = .none });
    defer stream.close(io);

    var req_buf: [1024]u8 = undefined;
    const req = std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n\r\n", .{ path, host, port }) catch return error.RequestTooLong;

    var write_buf: [1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);
    try stream_writer.interface.writeAll(req);
    try stream_writer.interface.flush();

    return readHttpBody(allocator, io, stream);
}

fn rawHttpPost(allocator: std.mem.Allocator, io: Io, host: []const u8, port: u16, path: []const u8, body: []const u8) !void {
    const addr = Io.net.IpAddress.parse(host, port) catch return error.BadHost;
    const stream = try addr.connect(io, .{ .mode = .stream, .timeout = .none });
    defer stream.close(io);

    var req_buf: [1024]u8 = undefined;
    const header = std.fmt.bufPrint(&req_buf, "POST {s} HTTP/1.1\r\nHost: {s}:{d}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ path, host, port, body.len }) catch return error.RequestTooLong;

    var write_buf: [4096]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buf);
    const out = &stream_writer.interface;
    try out.writeAll(header);
    try out.writeAll(body);
    try out.flush();

    const resp = try readHttpResponse(allocator, io, stream);
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

fn readHttpResponse(allocator: std.mem.Allocator, io: Io, stream: Io.net.Stream) !HttpResponse {
    // Connection: close means the body ends at EOF; read the whole response.
    var read_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    const data = try stream_reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(data);

    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return error.NoBody;
    const body_start = header_end + 4;

    var status: u16 = 0;
    if (std.mem.indexOf(u8, data[0..header_end], " ")) |sp| {
        const after_sp = sp + 1;
        const status_end = std.mem.indexOfScalarPos(u8, data[0..header_end], after_sp, ' ') orelse
            std.mem.indexOfScalarPos(u8, data[0..header_end], after_sp, '\r') orelse header_end;
        status = std.fmt.parseInt(u16, data[after_sp..status_end], 10) catch 0;
    }

    return .{
        .status = status,
        .body = try allocator.dupe(u8, data[body_start..]),
    };
}

fn readHttpBody(allocator: std.mem.Allocator, io: Io, stream: Io.net.Stream) ![]u8 {
    const resp = try readHttpResponse(allocator, io, stream);
    return resp.body;
}

// --- Utilities ---

fn logTs(io: Io) void {
    const ts: u64 = @intCast(Io.Clock.real.now(io).toSeconds());
    const s = ts % 86400;
    std.debug.print("[{d:0>2}:{d:0>2}:{d:0>2}] ", .{ s / 3600, (s % 3600) / 60, s % 60 });
}
