const std = @import("std");
const core = @import("familiar_core");

pub const version = "0.2.0";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var config = core.Config{};

    var args_list: std.ArrayList([:0]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_it = std.process.Args.Iterator.init(init.minimal.args);
    while (args_it.next()) |arg| try args_list.append(allocator, arg);
    const args = args_list.items;

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

    core.run(allocator, io, config, init.environ_map, null);
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
        \\familiar {s} - AI chat bot for seance rooms
        \\
        \\Usage: familiar [options]
        \\
        \\Requires ANTHROPIC_API_KEY environment variable.
        \\
        \\Options:
        \\  --api-port PORT  Seance bot API port (default: 9999)
        \\  --api-host HOST  Seance bot API host (default: 127.0.0.1)
        \\  --system PROMPT  System prompt / personality
        \\  --context N      Messages to keep as context (default: 50)
        \\  --model MODEL    Claude model (default: claude-sonnet-4-5-20250929)
        \\  --cooldown SECS  Seconds between responses (default: 2)
        \\  -h, --help       Show this help
        \\  -v, --version    Show version
        \\
    , .{version});
}

// 0.16 `zig test <root>` only runs the root file's own tests; pull in the core
// module so any of its test blocks are discovered by the gate command.
test {
    _ = @import("familiar_core");
}
