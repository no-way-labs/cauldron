const std = @import("std");
const Io = std.Io;

pub const SaveResult = struct {
    path: []const u8,
    bytes: u64,
};

pub fn save(allocator: std.mem.Allocator, io: Io, dir: []const u8, filename: []const u8, reader: *Io.Reader) !SaveResult {
    try makePath(io, dir);

    var dir_handle = try Io.Dir.cwd().openDir(io, dir, .{});
    defer dir_handle.close(io);

    const final_filename = try findAvailableFilename(allocator, io, dir_handle, filename);
    defer allocator.free(final_filename);

    var file = try dir_handle.createFile(io, final_filename, .{});
    defer file.close(io);

    var write_buf: [8192]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    const bytes_written = try reader.streamRemaining(&file_writer.interface);
    try file_writer.interface.flush();

    const full_path = try std.fs.path.join(allocator, &[_][]const u8{ dir, final_filename });

    return SaveResult{
        .path = full_path,
        .bytes = bytes_written,
    };
}

/// Recursively create a directory path (0.16's Io.Dir has no makePath).
fn makePath(io: Io, path: []const u8) !void {
    var it = std.mem.tokenizeScalar(u8, path, '/');
    while (it.next()) |component| {
        const end = @intFromPtr(component.ptr) - @intFromPtr(path.ptr) + component.len;
        Io.Dir.cwd().createDir(io, path[0..end], .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
}

fn findAvailableFilename(allocator: std.mem.Allocator, io: Io, dir: Io.Dir, filename: []const u8) ![]const u8 {
    dir.access(io, filename, .{}) catch {
        return try allocator.dupe(u8, filename);
    };

    const ext_index = std.mem.lastIndexOfScalar(u8, filename, '.');
    const base = if (ext_index) |idx| filename[0..idx] else filename;
    const ext = if (ext_index) |idx| filename[idx..] else "";

    var counter: u32 = 1;
    while (counter < 10000) : (counter += 1) {
        const candidate = try std.fmt.allocPrint(allocator, "{s}_{d}{s}", .{ base, counter, ext });
        errdefer allocator.free(candidate);

        dir.access(io, candidate, .{}) catch {
            return candidate;
        };

        allocator.free(candidate);
    }

    return error.TooManyCollisions;
}

test "save writes file to disk" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const test_dir = "test_inbox";
    defer Io.Dir.cwd().deleteTree(io, test_dir) catch {};

    const data = "Hello, World!";
    var reader = Io.Reader.fixed(data);

    const result = try save(allocator, io, test_dir, "test.txt", &reader);
    defer allocator.free(result.path);

    try std.testing.expectEqual(@as(u64, data.len), result.bytes);

    const content = try Io.Dir.cwd().readFileAlloc(io, result.path, allocator, .limited(1024));
    defer allocator.free(content);

    try std.testing.expectEqualStrings(data, content);
}

test "save handles filename collisions" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const test_dir = "test_inbox_collision";
    defer Io.Dir.cwd().deleteTree(io, test_dir) catch {};

    const data1 = "First file";
    var reader1 = Io.Reader.fixed(data1);
    const result1 = try save(allocator, io, test_dir, "test.txt", &reader1);
    defer allocator.free(result1.path);

    const data2 = "Second file";
    var reader2 = Io.Reader.fixed(data2);
    const result2 = try save(allocator, io, test_dir, "test.txt", &reader2);
    defer allocator.free(result2.path);

    try std.testing.expect(!std.mem.eql(u8, result1.path, result2.path));

    const content2 = try Io.Dir.cwd().readFileAlloc(io, result2.path, allocator, .limited(1024));
    defer allocator.free(content2);

    try std.testing.expectEqualStrings(data2, content2);
}
