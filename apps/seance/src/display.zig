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

pub fn printMessage(timestamp: u64, nick: []const u8, message: []const u8) void {
    var time_buf: [5]u8 = undefined;
    const time_str = formatTime(&time_buf, timestamp);
    const color = colorForNick(nick);
    std.debug.print("\x1b[90m[{s}]\x1b[0m \x1b[{d}m{s}\x1b[0m: {s}\n", .{ time_str, color.code(), nick, message });
}

pub fn printAnnouncement(timestamp: u64, message: []const u8) void {
    var time_buf: [5]u8 = undefined;
    const time_str = formatTime(&time_buf, timestamp);
    std.debug.print("\x1b[90m\x1b[3m[{s}] * {s}\x1b[0m\n", .{ time_str, message });
}

pub fn printNickList(nicks: []const []const u8) void {
    std.debug.print("\x1b[90m--- participants ({d}) ---\x1b[0m\n", .{nicks.len});
    for (nicks) |nick| {
        const color = colorForNick(nick);
        std.debug.print("  \x1b[{d}m{s}\x1b[0m\n", .{ color.code(), nick });
    }
    std.debug.print("\x1b[90m-----------------------\x1b[0m\n", .{});
}

pub fn printStatus(message: []const u8) void {
    std.debug.print("\x1b[90m{s}\x1b[0m\n", .{message});
}
