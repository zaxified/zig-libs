// SPDX-License-Identifier: MIT

//! mls-chat — end-to-end encrypted group chat over RFC 9420 (MLS).
//!
//! One binary, two roles: `relay` is the Delivery Service, `join` is a
//! participant. Run one relay and two or more participants, all on loopback.
//!
//! What the demo is FOR: the relay forwards ciphertext it holds no key for,
//! and every member ends each epoch agreeing on a secret nobody sent.

const std = @import("std");
const client = @import("client.zig");
const relay = @import("relay.zig");

const usage =
    \\mls-chat — end-to-end encrypted group chat (RFC 9420 / MLS)
    \\
    \\  mls-chat relay [--listen <addr>] [--port <n>]
    \\  mls-chat join  --name <name> [--group <id>] [--create]
    \\                 [--host <addr>] [--port <n>]
    \\
    \\Options:
    \\  --listen <addr>   relay bind address        (default 127.0.0.1)
    \\  --host <addr>     relay address to reach    (default 127.0.0.1)
    \\  --port <n>        relay port                (default 7711)
    \\  --name <name>     this member's nickname, published in the leaf
    \\                    credential (default anon)
    \\  --group <id>      group id                  (default ops-room)
    \\  --create          create the group instead of waiting for a Welcome
    \\
    \\A three-terminal session:
    \\
    \\  mls-chat relay
    \\  mls-chat join --name alice --create
    \\  mls-chat join --name bob
    \\
    \\then in alice's terminal:  /invite bob
    \\
;

/// Exit status for a usage or setup error, distinct from a clean exit.
const failure_exit: u8 = 1;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the app a leak detector for
    // the module's ownership contract — every `deinit`/`free` here is
    // load-bearing, not decoration.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse {
        std.debug.print("{s}", .{usage});
        return failure_exit;
    };

    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage});
        return 0;
    }

    if (std.mem.eql(u8, mode, "relay")) {
        var opts: relay.Options = .{};
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--listen")) {
                opts.host = try nextValue(&args, "--listen");
            } else if (std.mem.eql(u8, arg, "--port")) {
                opts.port = try parsePort(try nextValue(&args, "--port"));
            } else return unknown(arg);
        }
        relay.serve(gpa, io, opts) catch |err| {
            std.debug.print("mls-chat: relay stopped: {t}\n", .{err});
            return failure_exit;
        };
        return 0;
    }

    if (std.mem.eql(u8, mode, "join")) {
        var opts: client.Options = .{};
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--host")) {
                opts.host = try nextValue(&args, "--host");
            } else if (std.mem.eql(u8, arg, "--port")) {
                opts.port = try parsePort(try nextValue(&args, "--port"));
            } else if (std.mem.eql(u8, arg, "--name")) {
                opts.name = try nextValue(&args, "--name");
            } else if (std.mem.eql(u8, arg, "--group")) {
                opts.group = try nextValue(&args, "--group");
            } else if (std.mem.eql(u8, arg, "--create")) {
                opts.create = true;
            } else return unknown(arg);
        }

        var c = client.init(gpa, io, opts) catch |err| {
            // `RelayUnreachable` has already said which address failed and
            // why; anything else has not.
            if (err != error.RelayUnreachable) {
                std.debug.print("mls-chat: cannot start: {t}\n", .{err});
            }
            return failure_exit;
        };
        defer client.deinit(&c);

        client.run(&c) catch |err| {
            std.debug.print("mls-chat: session ended: {t}\n", .{err});
            return failure_exit;
        };
        return 0;
    }

    std.debug.print("{s}", .{usage});
    return failure_exit;
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) ![]const u8 {
    return args.next() orelse {
        std.debug.print("mls-chat: {s} needs a value\n", .{flag});
        return error.BadUsage;
    };
}

fn parsePort(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10) catch {
        std.debug.print("mls-chat: '{s}' is not a port number\n", .{text});
        return error.BadUsage;
    };
}

fn unknown(arg: []const u8) u8 {
    std.debug.print("mls-chat: unknown argument '{s}'\n\n{s}", .{ arg, usage });
    return failure_exit;
}
