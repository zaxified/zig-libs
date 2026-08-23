// SPDX-License-Identifier: MIT

//! What a consumer running short-lived child processes does with `procrun`:
//! capture a successful command's stdout, distinguish a non-zero exit from a
//! zero one, keep stdout and stderr separated, drain output far larger than
//! one 8 KiB pump read under a tight cap (proving truncate-not-discard),
//! round-trip stdin bigger than a pipe buffer, kill a child that outlives a
//! deadline, stream a child's output in real time under backpressure, and
//! reject an attacker-shaped argv element through the opt-in `argsafe`
//! integration before anything is spawned at all.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). `argsafe`
//! is imported directly too: it is `procrun`'s own declared `deps`, so an
//! outside consumer wiring `runValidated` gets it the same way this file does.

const std = @import("std");
const procrun = @import("procrun");
const argsafe = @import("argsafe");

pub fn main() !void {
    // A DebugAllocator that panics on leak makes this example a leak
    // detector for the module's ownership contract (CONVENTIONS.md §7.2) —
    // every capture path below (blocking run, timeout kill, streaming,
    // validated-argv build/reject) allocates, and several return early on
    // error, exactly where a leak likes to hide.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 1. A plain success: stdout captured, exit 0.
    {
        var out = try procrun.run(gpa, io, .{ .argv = &.{ "/bin/echo", "hello from procrun" } }, "");
        defer out.deinit(gpa);
        std.debug.assert(out.term == .exited and out.term.exited == 0);
        std.debug.assert(std.mem.indexOf(u8, out.stdout, "hello from procrun") != null);
        std.debug.print("echo: exited 0, captured {d} stdout bytes\n", .{out.stdout.len});
    }

    // 2. Non-zero exit — a command that exists on every POSIX box for
    // exactly this purpose.
    {
        var out = try procrun.run(gpa, io, .{ .argv = &.{"/bin/false"} }, "");
        defer out.deinit(gpa);
        std.debug.assert(out.term == .exited and out.term.exited == 1);
        std.debug.print("false: exited {d} (expected non-zero)\n", .{out.term.exited});
    }

    // 3. stdout and stderr stay separated across a non-zero exit.
    {
        var out = try procrun.run(gpa, io, .{
            .argv = &.{ "/bin/sh", "-c", "echo to-stdout; echo to-stderr 1>&2; exit 7" },
        }, "");
        defer out.deinit(gpa);
        std.debug.assert(out.term == .exited and out.term.exited == 7);
        std.debug.assert(std.mem.eql(u8, out.stdout, "to-stdout\n"));
        std.debug.assert(std.mem.eql(u8, out.stderr, "to-stderr\n"));
        std.debug.print("sh: streams stayed separated, exit code 7\n", .{});
    }

    // 4. Output far bigger than one 8 KiB drain read, under a tight cap:
    // proves the prefix is KEPT and draining continues past the cap (not
    // `std.process.run`'s discard-everything StreamTooLong).
    {
        var out = try procrun.run(gpa, io, .{
            .argv = &.{ "/bin/sh", "-c", "head -c 300000 /dev/zero" },
            .max_output_bytes = 4096,
        }, "");
        defer out.deinit(gpa);
        std.debug.assert(out.term == .exited and out.term.exited == 0);
        std.debug.assert(out.stdout.len == 4096);
        std.debug.assert(out.truncated_stdout);
        std.debug.print("300000-byte child stdout capped at {d}, truncated=true\n", .{out.stdout.len});
    }

    // 5. stdin larger than a pipe buffer, round-tripped through `cat` without
    // deadlocking (separate writer/drainer threads is the whole point).
    {
        const body = try gpa.alloc(u8, 200 * 1024);
        defer gpa.free(body);
        for (body, 0..) |*b, i| b.* = @intCast(i % 251);

        var out = try procrun.run(gpa, io, .{ .argv = &.{"cat"}, .stdin = .pipe }, body);
        defer out.deinit(gpa);
        std.debug.assert(std.mem.eql(u8, body, out.stdout));
        std.debug.print("cat round-tripped {d} bytes of stdin without deadlock\n", .{out.stdout.len});
    }

    // 6. A child that outlives its deadline gets SIGKILL'd and reaped.
    {
        var out = try procrun.runTimeout(gpa, io, .{ .argv = &.{ "sleep", "2" } }, "", 50 * std.time.ns_per_ms);
        defer out.deinit(gpa);
        std.debug.assert(out.term == .signal);
        std.debug.print("sleep 2 under a 50ms deadline: killed by signal {d}\n", .{out.term.signal});
    }

    // 7. Streaming: real-time callbacks under tight backpressure, plus
    // on_exit firing exactly once.
    {
        const Sink = struct {
            gpa: std.mem.Allocator,
            out: std.ArrayList(u8) = .empty,
            saw_exit: bool = false,
            exit_code: u8 = 255,
            h: ?procrun.Handle = null,

            fn onOut(ctx: ?*anyopaque, chunk: []const u8) void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                self.out.appendSlice(self.gpa, chunk) catch {};
                if (self.h) |h| h.ack();
            }
            fn onExit(ctx: ?*anyopaque, term: procrun.Term) void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                self.saw_exit = true;
                if (term == .exited) self.exit_code = term.exited;
            }
        };
        var sink: Sink = .{ .gpa = gpa };
        defer sink.out.deinit(gpa);

        const h = try procrun.spawnStreaming(gpa, io, .{
            .argv = &.{ "/bin/sh", "-c", "for i in 1 2 3; do echo line$i; done; exit 0" },
            .stream_permits = 1, // one outstanding chunk at a time: backpressure actually engages
        }, .{ .ctx = &sink, .on_stdout = Sink.onOut, .on_exit = Sink.onExit });
        sink.h = h;

        const term = h.wait();
        std.debug.assert(term == .exited and term.exited == 0);
        std.debug.assert(sink.saw_exit and sink.exit_code == 0);
        std.debug.assert(std.mem.indexOf(u8, sink.out.items, "line1") != null);
        std.debug.assert(std.mem.indexOf(u8, sink.out.items, "line3") != null);
        std.debug.print("spawnStreaming: {d} bytes streamed under 1-permit backpressure, on_exit fired\n", .{sink.out.items.len});
    }

    // 8. runValidated: a flag-injection-shaped arg is rejected by `argsafe`
    // BEFORE anything is spawned — named error, not a blanket catch.
    {
        const res = procrun.runValidated(
            gpa,
            io,
            "/bin/echo",
            argsafe.isSafePath,
            &.{"--evil-flag"},
            argsafe.isSafeIdentifier,
            .{ .argv = &.{} }, // ignored: runValidated builds argv itself
            "",
        );
        if (res) |_| {
            unreachable;
        } else |err| switch (err) {
            error.Rejected => std.debug.print("runValidated: flag-injection-shaped arg rejected before spawn (expected)\n", .{}),
            else => return err,
        }
    }

    // ...and the accept-and-actually-run case through the same entry point.
    {
        var out = try procrun.runValidated(
            gpa,
            io,
            "/bin/echo",
            argsafe.isSafePath,
            &.{"safe-arg"},
            argsafe.isSafeIdentifier,
            .{ .argv = &.{} }, // ignored: runValidated builds argv itself
            "",
        );
        defer out.deinit(gpa);
        std.debug.assert(out.term == .exited and out.term.exited == 0);
        std.debug.assert(std.mem.indexOf(u8, out.stdout, "safe-arg") != null);
        std.debug.print("runValidated: safe args accepted and run\n", .{});
    }

    // 9. A spawn failure that has nothing to do with argv content: the
    // program itself does not exist. Must fail by name, not panic.
    {
        const res = procrun.run(gpa, io, .{ .argv = &.{"/nonexistent/procrun-example-binary"} }, "");
        if (res) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FileNotFound => std.debug.print("spawning a nonexistent program: FileNotFound (expected)\n", .{}),
            else => return err,
        }
    }
}
