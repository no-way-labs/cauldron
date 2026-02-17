const std = @import("std");
const client_mod = @import("client.zig");

pub const ApiServer = struct {
    client: *client_mod.Client,
    listener: std.net.Server,
    running: std.atomic.Value(bool),

    pub fn init(client: *client_mod.Client, port: u16) !ApiServer {
        const address = try std.net.Address.parseIp("127.0.0.1", port);
        const listener = try address.listen(.{
            .reuse_address = true,
        });

        return ApiServer{
            .client = client,
            .listener = listener,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    pub fn run(self: *ApiServer) void {
        while (self.running.load(.monotonic)) {
            const conn = self.listener.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                std.debug.print("API accept error: {}\n", .{err});
                continue;
            };

            self.handleConnection(conn.stream);
        }
    }

    pub fn stop(self: *ApiServer) void {
        self.running.store(false, .monotonic);
        self.listener.deinit();
    }

    pub fn deinit(self: *ApiServer) void {
        if (self.running.load(.monotonic)) {
            self.stop();
        }
    }

    fn handleConnection(self: *ApiServer, stream: std.net.Stream) void {
        defer stream.close();

        std.debug.print("[bot-api] connection accepted\n", .{});

        var buffer: [8192]u8 = undefined;
        const bytes_read = stream.read(&buffer) catch return;
        if (bytes_read == 0) return;

        std.debug.print("[bot-api] read {d} bytes\n", .{bytes_read});

        const request = parseRequest(buffer[0..bytes_read]) orelse {
            writeResponse(stream, 400, "Bad Request", "text/plain", "Invalid HTTP request");
            return;
        };

        std.debug.print("[bot-api] {s} {s}\n", .{if (request.method == .GET) "GET" else "POST", request.path});

        self.routeRequest(stream, request);

        std.debug.print("[bot-api] response sent\n", .{});
    }

    fn routeRequest(self: *ApiServer, stream: std.net.Stream, request: HttpRequest) void {
        if (request.method == .POST and std.mem.eql(u8, request.path, "/send")) {
            self.handleSend(stream, request.body);
        } else if (request.method == .GET and std.mem.eql(u8, request.path, "/messages")) {
            self.handleMessages(stream, request.query);
        } else if (request.method == .GET and std.mem.eql(u8, request.path, "/peers")) {
            self.handlePeers(stream);
        } else if (request.method == .POST and std.mem.eql(u8, request.path, "/quit")) {
            self.handleQuit(stream);
        } else if (request.method == .GET and std.mem.eql(u8, request.path, "/nick")) {
            self.handleNick(stream);
        } else if (request.method == .GET and std.mem.eql(u8, request.path, "/health")) {
            writeResponse(stream, 200, "OK", "application/json", "{\"status\":\"ok\"}");
        } else {
            writeResponse(stream, 404, "Not Found", "text/plain", "Not found");
        }
    }

    fn handleSend(self: *ApiServer, stream: std.net.Stream, body: []const u8) void {
        if (body.len == 0) {
            writeResponse(stream, 400, "Bad Request", "text/plain", "Empty message");
            return;
        }

        const trimmed = std.mem.trimRight(u8, body, "\n\r");
        if (trimmed.len == 0) {
            writeResponse(stream, 400, "Bad Request", "text/plain", "Empty message");
            return;
        }

        self.client.sendMessage(trimmed) catch {
            writeResponse(stream, 500, "Internal Server Error", "text/plain", "Failed to send");
            return;
        };

        writeResponse(stream, 200, "OK", "application/json", "{\"status\":\"sent\"}");
    }

    fn handleMessages(self: *ApiServer, stream: std.net.Stream, query: []const u8) void {
        var since_id: u64 = 0;
        var wait_secs: u64 = 0;
        if (query.len > 0) {
            if (std.mem.indexOf(u8, query, "since=")) |pos| {
                const val_start = pos + "since=".len;
                const val_end = std.mem.indexOfScalarPos(u8, query, val_start, '&') orelse query.len;
                since_id = std.fmt.parseInt(u64, query[val_start..val_end], 10) catch 0;
            }
            if (std.mem.indexOf(u8, query, "wait=")) |pos| {
                const val_start = pos + "wait=".len;
                const val_end = std.mem.indexOfScalarPos(u8, query, val_start, '&') orelse query.len;
                wait_secs = @min(std.fmt.parseInt(u64, query[val_start..val_end], 10) catch 0, 120);
            }
        }

        const buf = self.client.msg_buffer orelse {
            writeResponse(stream, 500, "Internal Server Error", "text/plain", "No message buffer");
            return;
        };

        // Long poll: wait up to wait_secs for new messages
        if (wait_secs > 0) {
            const deadline = @as(u64, @intCast(std.time.timestamp())) + wait_secs;
            while (@as(u64, @intCast(std.time.timestamp())) < deadline and self.running.load(.monotonic)) {
                if (buf.hasMessagesSince(since_id)) break;
                std.Thread.sleep(200 * std.time.ns_per_ms);
            }
        }

        const json = buf.getSince(since_id, self.client.allocator) catch {
            writeResponse(stream, 500, "Internal Server Error", "text/plain", "Failed to get messages");
            return;
        };
        defer self.client.allocator.free(json);

        writeResponse(stream, 200, "OK", "application/json", json);
    }

    fn handlePeers(self: *ApiServer, stream: std.net.Stream) void {
        const json = self.client.getPeers(self.client.allocator) catch {
            writeResponse(stream, 500, "Internal Server Error", "text/plain", "Failed to get peers");
            return;
        };
        defer self.client.allocator.free(json);

        writeResponse(stream, 200, "OK", "application/json", json);
    }

    fn handleQuit(self: *ApiServer, stream: std.net.Stream) void {
        writeResponse(stream, 200, "OK", "application/json", "{\"status\":\"disconnecting\"}");
        self.client.running.store(false, .monotonic);
    }

    fn handleNick(self: *ApiServer, stream: std.net.Stream) void {
        var buf: [256]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"nick\":\"{s}\"}}", .{self.client.nick}) catch {
            writeResponse(stream, 500, "Internal Server Error", "text/plain", "Failed to format nick");
            return;
        };
        writeResponse(stream, 200, "OK", "application/json", json);
    }
};

const Method = enum { GET, POST };

const HttpRequest = struct {
    method: Method,
    path: []const u8,
    query: []const u8,
    body: []const u8,
};

fn parseRequest(buffer: []const u8) ?HttpRequest {
    const line_end = std.mem.indexOf(u8, buffer, "\r\n") orelse return null;
    const request_line = buffer[0..line_end];

    var method: Method = undefined;
    var path_start: usize = 0;
    if (std.mem.startsWith(u8, request_line, "GET ")) {
        method = .GET;
        path_start = 4;
    } else if (std.mem.startsWith(u8, request_line, "POST ")) {
        method = .POST;
        path_start = 5;
    } else {
        return null;
    }

    const path_end = std.mem.indexOfScalarPos(u8, request_line, path_start, ' ') orelse return null;
    const full_path = request_line[path_start..path_end];

    var path = full_path;
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, full_path, '?')) |q_pos| {
        path = full_path[0..q_pos];
        query = full_path[q_pos + 1 ..];
    }

    const headers_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return null;

    var content_length: usize = 0;
    if (std.mem.indexOf(u8, buffer[0..headers_end], "Content-Length: ")) |cl_pos| {
        const cl_start = cl_pos + "Content-Length: ".len;
        const cl_end = std.mem.indexOfScalarPos(u8, buffer, cl_start, '\r') orelse headers_end;
        content_length = std.fmt.parseInt(usize, buffer[cl_start..cl_end], 10) catch 0;
    }

    const body_start = headers_end + 4;
    const body = if (body_start < buffer.len)
        buffer[body_start..@min(body_start + content_length, buffer.len)]
    else
        "";

    return HttpRequest{
        .method = method,
        .path = path,
        .query = query,
        .body = body,
    };
}

fn writeResponse(stream: std.net.Stream, status: u16, status_text: []const u8, content_type: []const u8, body: []const u8) void {
    var header_buf: [512]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, status_text, content_type, body.len }) catch return;

    stream.writeAll(header) catch return;
    if (body.len > 0) {
        stream.writeAll(body) catch return;
    }

    // Shutdown write side to send FIN immediately
    const sock: std.posix.socket_t = stream.handle;
    std.posix.shutdown(sock, .send) catch {};
}
