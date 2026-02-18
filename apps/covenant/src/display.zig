const std = @import("std");

pub fn printBanner(version_str: []const u8) void {
    std.debug.print("\n\x1b[38;5;33m                \xc2\xb7  \x1b[38;5;45m\xe2\x9c\xa6\x1b[38;5;33m  \xc2\xb7\x1b[0m\n\n", .{});
    // COVENANT in box-drawing chars
    // C       O       V       E       N       A       N       T
    // ╔═╗ ╔═╗ ╦  ╦ ╔═╗ ╔╗╔ ╔═╗ ╔╗╔ ╔╦╗
    // ║   ║ ║ ╚╗╔╝ ║╣  ║║║ ╠═╣ ║║║  ║
    // ╚═╝ ╚═╝  ╚╝  ╚═╝ ╝╚╝ ╩ ╩ ╝╚╝  ╩
    std.debug.print("\x1b[38;5;39m    \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\xa6  \xe2\x95\xa6 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x97\xe2\x95\x94 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x97\xe2\x95\x94 \xe2\x95\x94\xe2\x95\xa6\xe2\x95\x97\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;45m    \xe2\x95\x91   \xe2\x95\x91 \xe2\x95\x91 \xe2\x95\x9a\xe2\x95\x97\xe2\x95\x94\xe2\x95\x9d \xe2\x95\x91\xe2\x95\xa3  \xe2\x95\x91\xe2\x95\x91\xe2\x95\x91 \xe2\x95\xa0\xe2\x95\x90\xe2\x95\xa3 \xe2\x95\x91\xe2\x95\x91\xe2\x95\x91  \xe2\x95\x91\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;51m    \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x9d  \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x9d \xe2\x95\xa9 \xe2\x95\xa9 \xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x9d  \xe2\x95\xa9\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;245m\n     membership signing ceremony\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;240m                v{s}\x1b[0m\n\n", .{version_str});
    std.debug.print("\x1b[38;5;33m                \xc2\xb7  \x1b[38;5;45m\xe2\x9c\xa7\x1b[38;5;33m  \xc2\xb7\x1b[0m\n\n", .{});
}

pub fn printGroupName(name: []const u8) void {
    std.debug.print("\x1b[38;5;245mGroup:\x1b[0m    {s}\n", .{name});
}

pub fn printMemberJoined(nick: []const u8, count: usize) void {
    std.debug.print("\x1b[38;5;45m*\x1b[0m \x1b[38;5;245m{s} joined\x1b[0m ({d} members)\n", .{ nick, count });
}

pub fn printMemberLeft(nick: []const u8, count: usize) void {
    std.debug.print("\x1b[38;5;45m*\x1b[0m \x1b[38;5;245m{s} left\x1b[0m ({d} members)\n", .{ nick, count });
}

pub fn printProgress(label: []const u8, current: usize, total: usize) void {
    std.debug.print("\x1b[38;5;245m{s}... ({d}/{d})\x1b[0m\n", .{ label, current, total });
}

pub fn printStatus(message: []const u8) void {
    std.debug.print("\x1b[38;5;245m{s}\x1b[0m\n", .{message});
}

pub fn printError(message: []const u8) void {
    std.debug.print("\x1b[38;5;196mError: {s}\x1b[0m\n", .{message});
}

pub fn printSealStart(member_count: usize) void {
    std.debug.print("\n\x1b[38;5;45m--- Sealing covenant ({d} members) ---\x1b[0m\n", .{member_count});
}

pub fn printCovenantComplete(member_count: usize) void {
    std.debug.print("\n\x1b[38;5;45m  COVENANT SEALED\x1b[0m  {d} members signed\n\n", .{member_count});
}
