const std = @import("std");
const testing = std.testing;
const server = @import("server.zig");
const client = @import("client.zig");
const storage = @import("storage.zig");
const filter = @import("filter.zig");
const id = @import("id.zig");

test "server accepts valid file" {
    // We'll test the filter and storage components directly
    const file_filter = filter.Filter{
        .accept_globs = null,
        .reject_globs = null,
        .max_size = 1024 * 1024,
    };

    const result = file_filter.check("test.txt", 100, "text/plain");
    try testing.expect(result == .ok);
}

test "server rejects oversized file" {
    const file_filter = filter.Filter{
        .accept_globs = null,
        .reject_globs = null,
        .max_size = 100,
    };

    const result = file_filter.check("large.txt", 200, "text/plain");
    try testing.expect(result == .rejected_size);
    try testing.expectEqual(@as(u64, 100), result.rejected_size.max);
    try testing.expectEqual(@as(u64, 200), result.rejected_size.got);
}

test "server rejects blacklisted extension" {
    const reject = [_][]const u8{"*.exe"};
    const file_filter = filter.Filter{
        .accept_globs = null,
        .reject_globs = &reject,
        .max_size = 1024 * 1024,
    };

    const result = file_filter.check("malware.exe", 100, "application/exe");
    try testing.expect(result == .rejected_extension);
}

test "server accepts whitelisted extension" {
    const accept = [_][]const u8{"*.txt"};
    const file_filter = filter.Filter{
        .accept_globs = &accept,
        .reject_globs = null,
        .max_size = 1024 * 1024,
    };

    const result = file_filter.check("document.txt", 100, "text/plain");
    try testing.expect(result == .ok);
}

test "server rejects non-whitelisted extension" {
    const accept = [_][]const u8{"*.txt"};
    const file_filter = filter.Filter{
        .accept_globs = &accept,
        .reject_globs = null,
        .max_size = 1024 * 1024,
    };

    const result = file_filter.check("document.pdf", 100, "application/pdf");
    try testing.expect(result == .rejected_extension);
}

test "storage saves file correctly" {
    const allocator = testing.allocator;
    const io = testing.io;
    const test_dir = "test_storage_inbox";
    defer std.Io.Dir.cwd().deleteTree(io, test_dir) catch {};

    const data = "Hello, World!";
    var reader = std.Io.Reader.fixed(data);

    const result = try storage.save(allocator, io, test_dir, "test.txt", &reader);
    defer allocator.free(result.path);

    try testing.expectEqual(@as(u64, data.len), result.bytes);

    // Verify file contents
    const content = try std.Io.Dir.cwd().readFileAlloc(io, result.path, allocator, .limited(1024));
    defer allocator.free(content);

    try testing.expectEqualStrings(data, content);
}

test "storage handles filename collisions" {
    const allocator = testing.allocator;
    const io = testing.io;
    const test_dir = "test_collision_inbox";
    defer std.Io.Dir.cwd().deleteTree(io, test_dir) catch {};

    // Save first file
    const data1 = "First file";
    var reader1 = std.Io.Reader.fixed(data1);
    const result1 = try storage.save(allocator, io, test_dir, "test.txt", &reader1);
    defer allocator.free(result1.path);

    // Save second file with same name
    const data2 = "Second file";
    var reader2 = std.Io.Reader.fixed(data2);
    const result2 = try storage.save(allocator, io, test_dir, "test.txt", &reader2);
    defer allocator.free(result2.path);

    // Paths should be different
    try testing.expect(!std.mem.eql(u8, result1.path, result2.path));

    // Second file should have _1 suffix
    try testing.expect(std.mem.indexOf(u8, result2.path, "test_1.txt") != null);

    // Verify both files exist with correct contents
    const content2 = try std.Io.Dir.cwd().readFileAlloc(io, result2.path, allocator, .limited(1024));
    defer allocator.free(content2);

    try testing.expectEqualStrings(data2, content2);
}

test "id generation produces valid format" {
    const allocator = testing.allocator;

    const generated_id = try id.generate(allocator, testing.io);
    defer allocator.free(generated_id);

    // Should have at least 2 hyphens (word-word-number)
    var hyphen_count: usize = 0;
    for (generated_id) |c| {
        if (c == '-') hyphen_count += 1;
    }

    try testing.expect(hyphen_count >= 2);

    // Should be parseable
    const parsed = try id.parse(allocator, generated_id);
    defer allocator.free(parsed.words);

    try testing.expect(parsed.words.len >= 2);
    try testing.expect(parsed.number < 100);
}

test "id parsing extracts components correctly" {
    const allocator = testing.allocator;

    const parsed = try id.parse(allocator, "blue-fox-42");
    defer allocator.free(parsed.words);

    try testing.expectEqual(@as(usize, 2), parsed.words.len);
    try testing.expectEqualStrings("blue", parsed.words[0]);
    try testing.expectEqualStrings("fox", parsed.words[1]);
    try testing.expectEqual(@as(u16, 42), parsed.number);
}

test "multiple file types filter" {
    const accept = [_][]const u8{ "*.txt", "*.json", "*.csv" };
    const file_filter = filter.Filter{
        .accept_globs = &accept,
        .reject_globs = null,
        .max_size = 1024 * 1024,
    };

    try testing.expect(file_filter.check("data.txt", 100, "text/plain") == .ok);
    try testing.expect(file_filter.check("config.json", 100, "application/json") == .ok);
    try testing.expect(file_filter.check("data.csv", 100, "text/csv") == .ok);
    try testing.expect(file_filter.check("script.sh", 100, "text/plain") == .rejected_extension);
}

test "storage creates directory if not exists" {
    const allocator = testing.allocator;
    const io = testing.io;
    const test_dir = "test_new_dir/subdir/inbox";
    defer std.Io.Dir.cwd().deleteTree(io, "test_new_dir") catch {};

    const data = "Test content";
    var reader = std.Io.Reader.fixed(data);

    const result = try storage.save(allocator, io, test_dir, "file.txt", &reader);
    defer allocator.free(result.path);

    // Verify directory was created and file exists
    var file = try std.Io.Dir.cwd().openFile(io, result.path, .{});
    file.close(io);
}

test "client payload data handling" {
    const allocator = testing.allocator;
    const io = testing.io;

    // Create a test file
    const test_file_path = "test_client_file.txt";
    {
        var file = try std.Io.Dir.cwd().createFile(io, test_file_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "Test data for client");
    }
    defer std.Io.Dir.cwd().deleteFile(io, test_file_path) catch {};

    // Test that we can read the file (simulating what the client does)
    const content = try std.Io.Dir.cwd().readFileAlloc(io, test_file_path, allocator, .limited(1024));
    defer allocator.free(content);

    try testing.expectEqualStrings("Test data for client", content);
    try testing.expectEqual(@as(usize, 20), content.len);
}

test "reject filter takes precedence over accept" {
    const accept = [_][]const u8{"*.txt"};
    const reject = [_][]const u8{"*.txt"};
    const file_filter = filter.Filter{
        .accept_globs = &accept,
        .reject_globs = &reject,
        .max_size = 1024 * 1024,
    };

    // Reject should be checked first
    const result = file_filter.check("test.txt", 100, "text/plain");
    try testing.expect(result == .rejected_extension);
}
