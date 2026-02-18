const std = @import("std");

pub fn printBanner(version_str: []const u8) void {
    std.debug.print("\n\x1b[38;5;202m                \xc2\xb7  \x1b[38;5;214m\xe2\x9c\xa6\x1b[38;5;202m  \xc2\xb7\x1b[0m\n\n", .{});
    std.debug.print("\x1b[38;5;166m          \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x97\xe2\x95\x94\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x90\xe2\x95\x97 \xe2\x95\x94\xe2\x95\x97\xe2\x95\x94\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;208m          \xe2\x95\x91 \xe2\x95\x91 \xe2\x95\x91\xe2\x95\x9a\xe2\x95\x9d\xe2\x95\x91 \xe2\x95\x91\xe2\x95\xa3  \xe2\x95\x91\xe2\x95\x91\xe2\x95\x91\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;214m          \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\xa9  \xe2\x95\xa9 \xe2\x95\x9a\xe2\x95\x90\xe2\x95\x9d \xe2\x95\x9d\xe2\x95\x9a\xe2\x95\x9d\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;245m\n       anonymous encrypted vote\x1b[0m\n", .{});
    std.debug.print("\x1b[38;5;240m                v{s}\x1b[0m\n\n", .{version_str});
    std.debug.print("\x1b[38;5;202m                \xc2\xb7  \x1b[38;5;214m\xe2\x9c\xa7\x1b[38;5;202m  \xc2\xb7\x1b[0m\n\n", .{});
}

pub fn printBallot(question: []const u8, options: []const []const u8) void {
    std.debug.print("\x1b[38;5;245mQuestion:\x1b[0m {s}\n", .{question});
    std.debug.print("\x1b[38;5;245mOptions:\x1b[0m  ", .{});
    for (options, 0..) |opt, i| {
        if (i > 0) std.debug.print("  ", .{});
        std.debug.print("\x1b[38;5;214m[{d}]\x1b[0m {s}", .{ i + 1, opt });
    }
    std.debug.print("\n", .{});
}

pub fn printVoterJoined(nick: []const u8, count: usize) void {
    std.debug.print("\x1b[38;5;208m*\x1b[0m \x1b[38;5;245m{s} joined\x1b[0m ({d} voters)\n", .{ nick, count });
}

pub fn printVoterLeft(nick: []const u8, count: usize) void {
    std.debug.print("\x1b[38;5;208m*\x1b[0m \x1b[38;5;245m{s} left\x1b[0m ({d} voters)\n", .{ nick, count });
}

pub fn printPhaseStart(phase_name: []const u8, voter_count: usize) void {
    std.debug.print("\n\x1b[38;5;214m--- {s} ({d} voters) ---\x1b[0m\n", .{ phase_name, voter_count });
}

pub fn printVotePrompt(options: []const []const u8) void {
    std.debug.print("\nSelect: ", .{});
    for (options, 0..) |opt, i| {
        if (i > 0) std.debug.print("  ", .{});
        std.debug.print("\x1b[38;5;214m[{d}]\x1b[0m {s}", .{ i + 1, opt });
    }
    std.debug.print("\nYour choice: ", .{});
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

pub fn printResults(question: []const u8, options: []const []const u8, counts: []const u32, total_voters: usize) void {
    std.debug.print("\n\x1b[38;5;214m  RESULTS:\x1b[0m {s}\n\n", .{question});

    // Find max count for bar scaling
    var max_count: u32 = 1;
    for (counts) |c| {
        if (c > max_count) max_count = c;
    }

    // Find winner (first option with max votes)
    var winner_count: u32 = 0;
    for (counts) |c| {
        if (c > winner_count) winner_count = c;
    }

    const bar_width: u32 = 20;

    for (options, 0..) |opt, i| {
        if (i >= counts.len) break;
        const count = counts[i];
        const filled: u32 = if (max_count > 0) @intCast((@as(u64, count) * bar_width) / max_count) else 0;
        const empty = bar_width - filled;
        const pct: u32 = if (total_voters > 0) @intCast((@as(u64, count) * 100) / @as(u64, @intCast(total_voters))) else 0;

        // Pad option name to 12 chars
        std.debug.print("  {s}", .{opt});
        const pad = if (opt.len < 12) 12 - opt.len else 0;
        for (0..pad) |_| std.debug.print(" ", .{});

        // Bar
        for (0..filled) |_| std.debug.print("\x1b[38;5;214m\xe2\x96\x88\x1b[0m", .{});
        for (0..empty) |_| std.debug.print("\x1b[38;5;240m\xe2\x96\x91\x1b[0m", .{});

        // Count and percentage
        std.debug.print("  {d}  ({d}%)", .{ count, pct });
        if (count == winner_count and count > 0) {
            std.debug.print("  \x1b[38;5;214m*\x1b[0m", .{});
        }
        std.debug.print("\n", .{});
    }

    std.debug.print("\n  {d} voters, {d} votes cast\n\n", .{ total_voters, total_voters });
}
