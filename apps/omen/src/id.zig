const std = @import("std");

const wordlist_data = @embedFile("wordlist.txt");

pub fn generate(allocator: std.mem.Allocator) ![]const u8 {
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const random = prng.random();

    var words = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    defer words.deinit(allocator);

    var lines = std.mem.tokenizeScalar(u8, wordlist_data, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
        if (trimmed.len > 0) {
            try words.append(allocator, trimmed);
        }
    }

    if (words.items.len < 2) {
        return error.InsufficientWords;
    }

    const word1 = words.items[random.uintLessThan(usize, words.items.len)];
    const word2 = words.items[random.uintLessThan(usize, words.items.len)];
    const number = random.uintLessThan(u16, 100);

    return std.fmt.allocPrint(allocator, "{s}-{s}-{d}", .{ word1, word2, number });
}

pub const ParsedId = struct {
    words: []const []const u8,
    number: u16,
};

pub fn parse(allocator: std.mem.Allocator, id: []const u8) !ParsedId {
    var parts = try std.ArrayList([]const u8).initCapacity(allocator, 0);
    errdefer parts.deinit(allocator);

    var iter = std.mem.tokenizeScalar(u8, id, '-');
    while (iter.next()) |part| {
        try parts.append(allocator, part);
    }

    if (parts.items.len < 3) {
        return error.InvalidIdFormat;
    }

    const number_str = parts.pop() orelse return error.InvalidIdFormat;
    const number = std.fmt.parseInt(u16, number_str, 10) catch return error.InvalidNumber;

    return ParsedId{
        .words = try parts.toOwnedSlice(allocator),
        .number = number,
    };
}

test "generate creates valid ID format" {
    const allocator = std.testing.allocator;
    const id = try generate(allocator);
    defer allocator.free(id);

    var count: usize = 0;
    var iter = std.mem.tokenizeScalar(u8, id, '-');
    while (iter.next()) |_| {
        count += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), count);
}

test "parse extracts words and number" {
    const allocator = std.testing.allocator;
    const parsed = try parse(allocator, "blue-fox-42");
    defer allocator.free(parsed.words);

    try std.testing.expectEqual(@as(usize, 2), parsed.words.len);
    try std.testing.expectEqualStrings("blue", parsed.words[0]);
    try std.testing.expectEqualStrings("fox", parsed.words[1]);
    try std.testing.expectEqual(@as(u16, 42), parsed.number);
}
