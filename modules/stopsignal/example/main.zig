// SPDX-License-Identifier: MIT

//! What a daemon does with `stopsignal`: take SIGTERM/SIGINT over BEFORE it
//! starts any worker thread, run its work loop checking `poll` between units
//! of work, and on a stop signal flush its state and exit 0. A second phase
//! blocks in `wait`, the shape of a main thread that has nothing else to do.
//!
//! The signals are sent by the example itself to its own thread (`tgkill`),
//! so `zig build run-example-stopsignal` finishes on its own; a real service
//! receives them from its service manager or a terminal.
//!
//! This is an example in the gate sense: it is built against the PUBLISHED
//! module (`deps` only), so a type or error the API needs but does not export
//! stops it compiling.

const std = @import("std");
const builtin = @import("builtin");
const stopsignal = @import("stopsignal");

const linux = std.os.linux;

fn sendSelf(sig: linux.SIG) void {
    _ = linux.tgkill(linux.getpid(), linux.gettid(), sig);
}

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .linux) {
        std.debug.print("stopsignal: Linux only (init would return error.Unsupported)\n", .{});
        return;
    }
    const io = init.io;

    // 1. Take the stop signals over first: threads started after this inherit
    //    the blocked mask, so a SIGTERM can only arrive through the signalfd.
    var stop = try stopsignal.StopSignals.init(.{}); // SIGTERM + SIGINT
    defer stop.deinit();

    // 2. A work loop that checks for a stop between units of work.
    var done: u32 = 0;
    const units = 10;
    while (done < units) : (done += 1) {
        if (done == 3) sendSelf(.TERM); // "systemctl stop" arrives mid-run
        if (try stop.poll()) |sig| {
            std.debug.print("work loop: got {t} after {d} of {d} units, flushing and stopping\n", .{ sig, done, units });
            break;
        }
    } else std.debug.print("work loop: finished all {d} units\n", .{units});
    if (done != 3) return error.StopNotSeen;

    // 3. A main thread with nothing else to do blocks in `wait` instead.
    sendSelf(.INT); // Ctrl-C
    const sig = try stop.wait(io);
    std.debug.print("wait: got {t}\n", .{sig});
    if (sig != .int) return error.WrongSignal;

    // 4. Nothing is left queued.
    if (try stop.poll()) |extra| {
        std.debug.print("unexpected extra signal {t}\n", .{extra});
        return error.UnexpectedSignal;
    }
    std.debug.print("clean exit\n", .{});
}
