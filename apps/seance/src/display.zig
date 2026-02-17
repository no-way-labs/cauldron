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

// Input prompt: purple "› "
const prompt_str = "\x1b[38;5;141m\xe2\x80\xba \x1b[0m";

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
// Tracks both content and cursor position so display functions can
// save/restore partial input around incoming messages.

var input_mutex: std.Thread.Mutex = .{};
var input_buf: [4096]u8 = undefined;
var input_len: usize = 0;
var input_cursor: usize = 0;

/// Add a printable character at the cursor position.
pub fn inputChar(c: u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_len >= input_buf.len) return;

    if (input_cursor == input_len) {
        // Append at end (common case)
        input_buf[input_len] = c;
        input_len += 1;
        input_cursor += 1;
        std.debug.print("{c}", .{c});
    } else {
        // Insert in middle: shift right
        std.mem.copyBackwards(u8, input_buf[input_cursor + 1 .. input_len + 1], input_buf[input_cursor..input_len]);
        input_buf[input_cursor] = c;
        input_len += 1;
        input_cursor += 1;
        // Redraw from inserted char to end, then move cursor back
        std.debug.print("{s}", .{input_buf[input_cursor - 1 .. input_len]});
        const back = input_len - input_cursor;
        if (back > 0) std.debug.print("\x1b[{d}D", .{back});
    }
}

/// Delete the character before the cursor.
pub fn inputBackspace() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_cursor == 0) return;

    if (input_cursor == input_len) {
        // Delete at end (common case)
        input_len -= 1;
        input_cursor -= 1;
        std.debug.print("\x08 \x08", .{});
    } else {
        // Delete in middle: shift left
        std.mem.copyForwards(u8, input_buf[input_cursor - 1 .. input_len - 1], input_buf[input_cursor..input_len]);
        input_len -= 1;
        input_cursor -= 1;
        // Move back, redraw remainder + space to clear last char, move cursor back
        std.debug.print("\x08{s} ", .{input_buf[input_cursor..input_len]});
        const back = input_len - input_cursor + 1;
        std.debug.print("\x1b[{d}D", .{back});
    }
}

/// Delete the character at the cursor (forward delete).
pub fn inputDelete() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_cursor >= input_len) return;

    std.mem.copyForwards(u8, input_buf[input_cursor .. input_len - 1], input_buf[input_cursor + 1 .. input_len]);
    input_len -= 1;
    // Redraw remainder + space, move cursor back
    std.debug.print("{s} ", .{input_buf[input_cursor..input_len]});
    const back = input_len - input_cursor + 1;
    std.debug.print("\x1b[{d}D", .{back});
}

/// Move cursor left.
pub fn inputLeft() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_cursor > 0) {
        input_cursor -= 1;
        std.debug.print("\x1b[D", .{});
    }
}

/// Move cursor right.
pub fn inputRight() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_cursor < input_len) {
        input_cursor += 1;
        std.debug.print("\x1b[C", .{});
    }
}

/// Move cursor to start of line.
pub fn inputHome() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_cursor > 0) {
        std.debug.print("\x1b[{d}D", .{input_cursor});
        input_cursor = 0;
    }
}

/// Move cursor to end of line.
pub fn inputEnd() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    if (input_cursor < input_len) {
        std.debug.print("\x1b[{d}C", .{input_len - input_cursor});
        input_cursor = input_len;
    }
}

/// Clear the entire input line.
pub fn inputClear() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    std.debug.print("\r\x1b[2K" ++ prompt_str, .{});
    input_len = 0;
    input_cursor = 0;
}

/// Take the current input, clear the buffer, return the text.
pub fn inputSubmit(out: []u8) []const u8 {
    input_mutex.lock();
    defer input_mutex.unlock();
    const len = @min(input_len, out.len);
    @memcpy(out[0..len], input_buf[0..len]);
    input_len = 0;
    input_cursor = 0;
    return out[0..len];
}

/// Read and handle an escape sequence (arrow keys, home, end, delete).
/// Call after reading ESC (byte 27).
pub fn handleEscapeSeq(stdin: std.fs.File) void {
    var buf: [1]u8 = undefined;
    const n = stdin.read(&buf) catch return;
    if (n == 0) return;
    if (buf[0] != '[') return;

    const n2 = stdin.read(&buf) catch return;
    if (n2 == 0) return;
    switch (buf[0]) {
        'D' => inputLeft(),
        'C' => inputRight(),
        'H' => inputHome(),
        'F' => inputEnd(),
        '3' => {
            // Delete key: ESC[3~
            const n3 = stdin.read(&buf) catch return;
            if (n3 > 0 and buf[0] == '~') inputDelete();
        },
        else => {},
    }
}

// Restore partial input after printing (must hold input_mutex).
fn restoreInput() void {
    std.debug.print(prompt_str, .{});
    if (input_len > 0) {
        std.debug.print("{s}", .{input_buf[0..input_len]});
        const back = input_len - input_cursor;
        if (back > 0) std.debug.print("\x1b[{d}D", .{back});
    }
}

/// Show the input prompt (call once when entering interactive mode).
pub fn showPrompt() void {
    input_mutex.lock();
    defer input_mutex.unlock();
    std.debug.print(prompt_str, .{});
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
    restoreInput();
}

pub fn printAnnouncement(timestamp: u64, message: []const u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();

    var time_buf: [5]u8 = undefined;
    const time_str = formatTime(&time_buf, timestamp);
    std.debug.print("\r\x1b[2K\x1b[90m\x1b[3m[{s}] * {s}\x1b[0m\n", .{ time_str, message });
    restoreInput();
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
    restoreInput();
}

pub fn printStatus(message: []const u8) void {
    input_mutex.lock();
    defer input_mutex.unlock();

    std.debug.print("\r\x1b[2K\x1b[90m{s}\x1b[0m\n", .{message});
    restoreInput();
}
