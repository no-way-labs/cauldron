const std = @import("std");

const BoreResult = struct {
    process: std.process.Child,
    public_port: u16,
    public_host: []const u8,
};

pub const Tunnel = struct {
    public_host: []const u8,
    public_port: u16,
    requested_port: u16,
    local_port: u16,
    process: std.process.Child,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),
    monitor_thread: ?std.Thread,

    pub fn establish(allocator: std.mem.Allocator, local_port: u16, bore_port: u16) !Tunnel {
        const result = try spawnBore(allocator, local_port, bore_port);
        return Tunnel{
            .public_host = result.public_host,
            .public_port = result.public_port,
            .requested_port = bore_port,
            .local_port = local_port,
            .process = result.process,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(true),
            .monitor_thread = null,
        };
    }

    pub fn startMonitor(self: *Tunnel) void {
        self.monitor_thread = std.Thread.spawn(.{}, monitorLoop, .{self}) catch null;
    }

    fn monitorLoop(self: *Tunnel) void {
        var drain_buf: [256]u8 = undefined;

        while (self.running.load(.monotonic)) {
            // Drain stdout until EOF (bore process death)
            if (self.process.stdout) |stdout| {
                while (self.running.load(.monotonic)) {
                    const n = stdout.read(&drain_buf) catch break;
                    if (n == 0) break; // EOF - process died
                }
            } else {
                // No stdout pipe, fall back to polling
                while (self.running.load(.monotonic)) {
                    std.Thread.sleep(std.time.ns_per_s);
                    _ = self.process.wait() catch break;
                }
            }

            if (!self.running.load(.monotonic)) break;

            std.debug.print("\nTunnel dropped, reconnecting...\n", .{});

            var attempt: u32 = 0;
            const max_attempts: u32 = 10;
            var reconnected = false;

            while (attempt < max_attempts and self.running.load(.monotonic)) : (attempt += 1) {
                // Exponential backoff: 1s, 2s, 4s, ... capped at 30s
                const delay_secs = @min(@as(u64, 1) << @intCast(attempt), 30);
                var waited: u64 = 0;
                while (waited < delay_secs and self.running.load(.monotonic)) : (waited += 1) {
                    std.Thread.sleep(std.time.ns_per_s);
                }

                if (!self.running.load(.monotonic)) break;

                // Try to reclaim the same port
                if (spawnBore(self.allocator, self.local_port, self.public_port)) |result| {
                    self.process = result.process;
                    self.allocator.free(result.public_host);
                    if (result.public_port != self.public_port) {
                        self.public_port = result.public_port;
                        std.debug.print("Tunnel reconnected on new port: bore.pub:{d}\n", .{result.public_port});
                    } else {
                        std.debug.print("Tunnel reconnected: bore.pub:{d}\n", .{self.public_port});
                    }
                    reconnected = true;
                    break;
                } else |_| {
                    std.debug.print("Reconnect attempt {d}/{d} failed\n", .{ attempt + 1, max_attempts });
                }
            }

            if (!reconnected) {
                std.debug.print("Could not reconnect tunnel after {d} attempts. Running local-only.\n", .{max_attempts});
                break;
            }
        }
    }

    pub fn shutdown(self: *Tunnel) void {
        self.running.store(false, .monotonic);
        _ = self.process.kill() catch {};
        if (self.monitor_thread) |thread| {
            thread.join();
        }
        self.allocator.free(self.public_host);
    }
};

fn spawnBore(allocator: std.mem.Allocator, local_port: u16, bore_port: u16) !BoreResult {
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{local_port});
    defer allocator.free(port_str);

    const bore_port_str = try std.fmt.allocPrint(allocator, "{d}", .{bore_port});
    defer allocator.free(bore_port_str);

    const args = if (bore_port > 0)
        &[_][]const u8{
            "bore",
            "local",
            port_str,
            "--to",
            "bore.pub",
            "--port",
            bore_port_str,
        }
    else
        &[_][]const u8{
            "bore",
            "local",
            port_str,
            "--to",
            "bore.pub",
        };

    var process = std.process.Child.init(args, allocator);

    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Pipe;

    try process.spawn();

    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdout_read: usize = 0;
    var stderr_read: usize = 0;

    const stdout = process.stdout.?;
    const stderr = process.stderr.?;
    var timeout_counter: u32 = 0;
    const max_timeout: u32 = 100;

    while (timeout_counter < max_timeout) : (timeout_counter += 1) {
        // Read from stdout
        const stdout_bytes = stdout.read(stdout_buffer[stdout_read..]) catch |err| {
            _ = process.kill() catch {};
            return err;
        };

        if (stdout_bytes > 0) {
            stdout_read += stdout_bytes;
            const output = stdout_buffer[0..stdout_read];

            // Look for "listening at bore.pub:PORT"
            if (std.mem.indexOf(u8, output, "listening at bore.pub:")) |pos| {
                const port_start = pos + "listening at bore.pub:".len;
                const port_end_opt = std.mem.indexOfScalarPos(u8, output, port_start, '\n');
                const port_end = port_end_opt orelse output.len;

                const port_str_extracted = std.mem.trim(u8, output[port_start..port_end], &std.ascii.whitespace);
                const public_port = try std.fmt.parseInt(u16, port_str_extracted, 10);

                const public_host = try allocator.dupe(u8, "bore.pub");

                return BoreResult{
                    .process = process,
                    .public_port = public_port,
                    .public_host = public_host,
                };
            }
        }

        // Check stderr for errors
        const stderr_bytes = stderr.read(stderr_buffer[stderr_read..]) catch 0;
        if (stderr_bytes > 0) {
            stderr_read += stderr_bytes;
            const stderr_output = stderr_buffer[0..stderr_read];

            // Check for port already in use error
            if (std.mem.indexOf(u8, stderr_output, "address already in use") != null or
                std.mem.indexOf(u8, stderr_output, "port") != null and std.mem.indexOf(u8, stderr_output, "in use") != null)
            {
                _ = process.kill() catch {};
                return error.PortInUse;
            }
        }

        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    _ = process.kill() catch {};
    return error.TunnelTimeout;
}
