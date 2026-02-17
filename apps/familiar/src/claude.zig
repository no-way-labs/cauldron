const std = @import("std");
const main_mod = @import("main.zig");

const api_endpoint = "https://api.anthropic.com/v1/messages";
const anthropic_version = "2023-06-01";
const anthropic_beta = "oauth-2025-04-20,claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14";
const mandatory_system = "You are Claude Code, Anthropic's official CLI for Claude.";
const refresh_url = "https://console.anthropic.com/v1/oauth/token";
const client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// Retrieve OAuth token from env var or macOS keychain.
pub fn getToken(allocator: std.mem.Allocator) ![]u8 {
    // Try env var first
    if (std.process.getEnvVarOwned(allocator, "CLAUDE_CODE_OAUTH_TOKEN")) |token| {
        return token;
    } else |_| {}

    // Try macOS keychain
    return getTokenFromKeychain(allocator);
}

fn getTokenFromKeychain(allocator: std.mem.Allocator) ![]u8 {
    var process = std.process.Child.init(
        &.{ "security", "find-generic-password", "-s", "Claude Code-credentials", "-w" },
        allocator,
    );
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;
    try process.spawn();

    const stdout = process.stdout.?;
    var buf: [65536]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = stdout.read(buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    _ = try process.wait();

    const raw = std.mem.trimRight(u8, buf[0..total], &std.ascii.whitespace);
    if (raw.len == 0) return error.NoCredentials;

    // Parse JSON to extract claudeAiOauth.accessToken
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();

    const oauth_obj = parsed.value.object.get("claudeAiOauth") orelse return error.NoOauthField;
    const token_val = oauth_obj.object.get("accessToken") orelse return error.NoAccessToken;

    return try allocator.dupe(u8, token_val.string);
}

/// Call Claude API with conversation history. Returns the response text.
pub fn chat(
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    token: []const u8,
    model: []const u8,
    system_prompt: ?[]const u8,
    messages: []const main_mod.ChatMessage,
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
    messages: []const main_mod.ChatMessage,
) ![]u8 {
    // Build JSON request body
    const body = try buildRequestBody(allocator, model, system_prompt, messages);
    defer allocator.free(body);

    // Build auth header value
    const auth_value = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    defer allocator.free(auth_value);

    const uri = try std.Uri.parse(api_endpoint);
    var req = try http_client.request(.POST, uri, .{
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .authorization = .{ .override = auth_value },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = &.{
            .{ .name = "anthropic-version", .value = anthropic_version },
            .{ .name = "anthropic-beta", .value = anthropic_beta },
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
    messages: []const main_mod.ChatMessage,
) ![]u8 {
    var json = std.ArrayList(u8).initCapacity(allocator, 0) catch unreachable;
    errdefer json.deinit(allocator);

    try json.appendSlice(allocator, "{\"model\":\"");
    try appendJsonEscaped(&json, allocator, model);
    try json.appendSlice(allocator, "\",\"max_tokens\":4096,\"system\":[{\"type\":\"text\",\"text\":\"");
    try appendJsonEscaped(&json, allocator, mandatory_system);
    try json.appendSlice(allocator, "\"}");

    if (system_prompt) |sp| {
        try json.appendSlice(allocator, ",{\"type\":\"text\",\"text\":\"");
        try appendJsonEscaped(&json, allocator, sp);
        try json.appendSlice(allocator, "\"}");
    }

    // Default personality if no custom system prompt
    if (system_prompt == null) {
        try json.appendSlice(allocator,
            ",{\"type\":\"text\",\"text\":\"You are familiar, a chat bot in a seance room. " ++
            "You are friendly, concise, and conversational. Messages from others are formatted as 'nick: message'. " ++
            "Respond naturally without prefixing your nick. Keep responses brief unless asked for detail.\"}");
    }

    try json.appendSlice(allocator, "],\"messages\":[");

    // Build messages array with strict role alternation
    var last_role: ?main_mod.ChatRole = null;
    var first = true;
    for (messages) |msg| {
        if (last_role != null and last_role.? == msg.role) {
            // Same role - append to previous with newline separator
            // Remove trailing "} or "}
            // Actually, we need to merge. Pop the closing and re-append.
            // Simpler: just skip strict alternation enforcement for consecutive same-role,
            // and merge content with newline.
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
