const std = @import("std");

pub const Color = enum(u8) {
    red = 31,
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    bright_red = 91,
    bright_green = 92,
    bright_yellow = 93,
    bright_blue = 94,
    bright_magenta = 95,
    bright_cyan = 96,

    pub fn code(self: Color) u8 {
        return @intFromEnum(self);
    }
};

const all_colors = [_]Color{
    .red,
    .green,
    .yellow,
    .blue,
    .magenta,
    .cyan,
    .bright_red,
    .bright_green,
    .bright_yellow,
    .bright_blue,
    .bright_magenta,
    .bright_cyan,
};

pub fn colorForNick(nick: []const u8) Color {
    var hash: u32 = 0;
    for (nick) |c| {
        hash = hash *% 31 +% c;
    }
    return all_colors[hash % all_colors.len];
}

pub fn formatTime(buf: *[5]u8, timestamp: u64) []const u8 {
    const secs = timestamp % 86400;
    const hours = secs / 3600;
    const minutes = (secs % 3600) / 60;
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}", .{ hours, minutes }) catch unreachable;
}

// --- Shared input line state for raw mode ---
// The stdin thread updates this; display functions save/restore it
// around output so incoming messages don't clobber partial input.

var input_mutex: std.Thread.Mutex = .{};
var input_buf: [4096]u8 = undefined;
var input_len: usize = 0;

/// Add a printable character and echo it.
pub fn inputChar(c: u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_len < input_buf.len) {
        input_buf[input_len] = c;
        input_len += 1;
        std.debug.print("{c}", .{c});
    }
}

/// Delete the last character.
pub fn inputBackspace() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_len > 0) {
        input_len -= 1;
        std.debug.print("\x08 \x08", .{});
    }
}

/// Clear the entire input line.
pub fn inputClear() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_len > 0) {
        std.debug.print("\r\x1b[2K", .{});
        input_len = 0;
    }
}

/// Take the current input, clear the buffer, return the text.
pub fn inputSubmit(out: []u8) []const u8 {
    input_mutex.lock();
    defer input_mutex.unlock();
    const len = @min(input_len, out.len);
    @memcpy(out[0..len], input_buf[0..len]);
    input_len = 0;
    return out[0..len];
}

// --- Display functions ---
// All acquire input_mutex, clear partial input, print, then restore it.

pub fn printMessage(timestamp: u64, nick: []const u8, message: []const u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();

    var time_buf: [5]u8 = undefined;
    const time_str = formatTime(&time_buf, timestamp);
    const color = colorForNick(nick);
    std.debug.print("\r\x1b[2K\x1b[90m[{s}]\x1b[0m \x1b[{d}m{s}\x1b[0m: {s}\n", .{ time_str, color.code(), nick, message });
    if (input_len > 0) {
        std.debug.print("{s}", .{input_buf[0..input_len]});
    }
}

pub fn printAnnouncement(timestamp: u64, message: []const u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();

    var time_buf: [5]u8 = undefined;
    const time_str = formatTime(&time_buf, timestamp);
    std.debug.print("\r\x1b[2K\x1b[90m\x1b[3m[{s}] * {s}\x1b[0m\n", .{ time_str, message });
    if (input_len > 0) {
        std.debug.print("{s}", .{input_buf[0..input_len]});
    }
}

pub fn printNickList(nicks: []const []const u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();

    std.debug.print("\r\x1b[2K\x1b[90m--- participants ({d}) ---\x1b[0m\n", .{nicks.len});
    for (nicks) |nick| {
        const color = colorForNick(nick);
        std.debug.print("  \x1b[{d}m{s}\x1b[0m\n", .{ color.code(), nick });
    }
    std.debug.print("\x1b[90m-----------------------\x1b[0m\n", .{});
    if (input_len > 0) {
        std.debug.print("{s}", .{input_buf[0..input_len]});
    }
}

pub fn printStatus(message: []const u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();

    std.debug.print("\r\x1b[2K\x1b[90m{s}\x1b[0m\n", .{message});
    if (input_len > 0) {
        std.debug.print("{s}", .{input_buf[0..input_len]});
    }
}
