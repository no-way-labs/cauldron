const std = @import("std");
const core = @import("familiar_core");

pub const version = "0.1.3";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var config = core.Config{};

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (eql(args[i], "--help") or eql(args[i], "-h")) {
            printUsage();
            return;
        } else if (eql(args[i], "--version") or eql(args[i], "-v")) {
            std.debug.print("familiar {s}\n", .{version});
            return;
        } else if (eql(args[i], "--api-port")) {
            i += 1;
            if (i >= args.len) fatal("--api-port requires a port number");
            config.api_port = std.fmt.parseInt(u16, args[i], 10) catch
                fatal("invalid --api-port value");
        } else if (eql(args[i], "--api-host")) {
            i += 1;
            if (i >= args.len) fatal("--api-host requires a hostname");
            config.api_host = args[i];
        } else if (eql(args[i], "--system")) {
            i += 1;
            if (i >= args.len) fatal("--system requires a prompt");
            config.system_prompt = args[i];
        } else if (eql(args[i], "--context")) {
            i += 1;
            if (i >= args.len) fatal("--context requires a number");
            config.context_size = std.fmt.parseInt(usize, args[i], 10) catch
                fatal("invalid --context value");
        } else if (eql(args[i], "--model")) {
            i += 1;
            if (i >= args.len) fatal("--model requires a model name");
            config.model = args[i];
        } else if (eql(args[i], "--cooldown")) {
            i += 1;
            if (i >= args.len) fatal("--cooldown requires seconds");
            config.cooldown_secs = std.fmt.parseInt(u64, args[i], 10) catch
                fatal("invalid --cooldown value");
        } else {
            std.debug.print("Unknown option: {s}\n", .{args[i]});
            printUsage();
            std.process.exit(1);
        }
    }

    core.run(allocator, config, null);
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn fatal(msg: []const u8) noreturn {
    std.debug.print("Error: {s}\n", .{msg});
    std.process.exit(1);
}

fn printUsage() void {
    std.debug.print(
        \\familiar {s} - Claude chat bot for seance rooms
        \\
        \\Usage: familiar [options]
        \\
        \\Options:
        \\  --api-port PORT  Seance bot API port (default: 9999)
        \\  --api-host HOST  Seance bot API host (default: 127.0.0.1)
        \\  --system PROMPT  Additional system prompt / personality
        \\  --context N      Messages to keep as context (default: 50)
        \\  --model MODEL    Claude model (default: claude-sonnet-4-5-20250929)
        \\  --cooldown SECS  Seconds between responses (default: 2)
        \\  -h, --help       Show this help
        \\  -v, --version    Show version
        \\
    , .{version});
}
