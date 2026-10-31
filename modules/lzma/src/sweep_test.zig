// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GZ). Findings LZ-1 .. LZ-7, see
//! ~/CML/20261029-panic-sweep/lzma-sweep.report.md.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const lzma = @import("root.zig");

const Child = struct { died: bool, len: usize };

/// Run `body` in a forked child with stderr captured into `buf`. A child past
/// five seconds counts as hung.
fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needles live in consts, never inline (a forked child's trace prints the caller's source line).
const needle_props = "lzma: invalid Lzma1Props";
const needle_empty = "lzma: input reader needs a non-empty buffer";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// ── LZ-1: StreamWriter.err held only OutOfMemory; AlreadyFinished was @errorCast into it ──

test "StreamWriter: finish twice is WriteFailed with err AlreadyFinished (sweep LZ-1)" {
    const gpa = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var buf: [64]u8 = undefined;
    var sw = try lzma.StreamWriter.init(gpa, &out.writer, &buf, .lzma2, .{});
    defer sw.deinit();
    try sw.writer.writeAll("hello hello hello");
    try sw.finish();
    try testing.expectError(error.WriteFailed, sw.finish());
    try testing.expectEqual(@as(?@TypeOf(sw.err.?), error.AlreadyFinished), sw.err);
}

test "StreamWriter: a write after a failed finish is WriteFailed with err AlreadyFinished (sweep LZ-1)" {
    const gpa = testing.allocator;
    var small: [1]u8 = undefined;
    var out: std.Io.Writer = .fixed(&small);
    var buf: [16]u8 = undefined;
    var sw = try lzma.StreamWriter.init(gpa, &out, &buf, .lzma2, .{});
    defer sw.deinit();
    try sw.writer.writeAll("hello");
    try testing.expectError(error.WriteFailed, sw.finish());
    try testing.expect(sw.err == null); // the output failed
    // Longer than the buffer: forces a drain into the finished encoder.
    try testing.expectError(error.WriteFailed, sw.writer.writeAll("0123456789abcdef0123456789"));
    try testing.expectEqual(@as(?@TypeOf(sw.err.?), error.AlreadyFinished), sw.err);
}

// ── LZ-3: preset level above 9 ──

test "preset: a level above 9 is 9, no assert and no table overrun (sweep LZ-3)" {
    var lv: u4 = 10;
    while (true) : (lv += 1) {
        try testing.expectEqual(lzma.preset(9, false), lzma.preset(lv, false));
        try testing.expectEqual(lzma.preset(9, true), lzma.preset(lv, true));
        if (lv == 15) break;
    }
}

// ── LZ-4: Lzma1Props.toBytes with props fromBytes would refuse ──

fn propsLcLp() void {
    _ = (lzma.Lzma1Props{ .lc = 3, .lp = 2, .pb = 0, .dict_size = 4096 }).toBytes();
}
fn propsPb() void {
    _ = (lzma.Lzma1Props{ .lc = 3, .lp = 0, .pb = 5, .dict_size = 4096 }).toBytes();
}
fn propsHuge() void {
    _ = (lzma.Lzma1Props{ .lc = 255, .lp = 255, .pb = 255, .dict_size = 4096 }).toBytes();
}

test "Lzma1Props.toBytes: out-of-range props are a checked lzma panic (sweep LZ-4)" {
    const ok = (lzma.Lzma1Props{ .lc = 4, .lp = 0, .pb = 4, .dict_size = 4096 }).toBytes();
    _ = try lzma.Lzma1Props.fromBytes(&ok);
    const ok2 = (lzma.Lzma1Props{ .lc = 0, .lp = 4, .pb = 0, .dict_size = 4096 }).toBytes();
    _ = try lzma.Lzma1Props.fromBytes(&ok2);
    try expectPanicMessage(propsLcLp, needle_props);
    try expectPanicMessage(propsPb, needle_props);
    try expectPanicMessage(propsHuge, needle_props);
}

// ── LZ-5: input reader with no buffer ──

fn nullStream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
    return error.EndOfStream;
}

fn initOnEmptyBufferReader() void {
    var r: std.Io.Reader = .{ .vtable = &.{ .stream = nullStream }, .buffer = &.{}, .seek = 0, .end = 0 };
    var d = lzma.Decoder.init(testing.allocator, &r, .xz, .{}) catch return;
    d.deinit();
}

test "Decoder.init: a zero-capacity stream reader is a checked lzma panic, an empty fixed reader is not (sweep LZ-5)" {
    try expectPanicMessage(initOnEmptyBufferReader, needle_empty);
    try testing.expectError(error.TruncatedInput, lzma.decompress(testing.allocator, "", .xz, .{}));
}

// ── LZ-6 (default one-shot output cap) is tested at the end of decoder.zig ──
// ── LZ-2 (Mf.normalize wrap) is tested at the end of lz_enc.zig: the Mf offset cannot be reached from here ──

// ── LZ-7: the tools' spec parser ──

test "interop_spec.parse: an empty spec is BadSpec, a level above 9 does not crash (sweep LZ-7)" {
    try testing.expectError(error.BadSpec, lzma.interop_spec.parse(""));
    _ = try lzma.interop_spec.parse("15");
}

// ── GZ audit: survivors of the delta mutants ──

fn propsWrap() void {
    // 250 + 10 wraps to 4 in u8 arithmetic: the sum must be taken wide.
    _ = (lzma.Lzma1Props{ .lc = 250, .lp = 10, .pb = 0, .dict_size = 4096 }).toBytes();
}

test "Lzma1Props.toBytes: lc + lp is summed wide, a u8 wrap does not pass the check (sweep audit GZ-A2)" {
    try expectPanicMessage(propsWrap, needle_props);
}

test "max_output: the room left caps a stored chunk read, a truncated input after the cap is OutputTooLarge (sweep audit GZ-A3)" {
    const gpa = testing.allocator;
    const f: lzma.Format = .{ .lzma2 = .{ .dict_size = 4096 } };
    // Chunk 1 fills the 4096-byte ring exactly (dictionary reset); chunk 2 declares
    // 2000 bytes but only 1000 follow. With max_output 5000 only 904 of them fit
    // under the cap, so the cap must trip before the truncation is read.
    var input: [3 + 4096 + 3 + 1000]u8 = undefined;
    input[0] = 1;
    input[1] = 0x0F;
    input[2] = 0xFF;
    @memset(input[3..][0..4096], 'a');
    input[3 + 4096] = 2;
    input[3 + 4096 + 1] = 0x07;
    input[3 + 4096 + 2] = 0xCF;
    @memset(input[3 + 4096 + 3 ..], 'b');
    try testing.expectError(error.OutputTooLarge, lzma.decompress(gpa, &input, f, .{ .max_output = 5000 }));
    try testing.expectError(error.TruncatedInput, lzma.decompress(gpa, &input, f, .{ .max_output = null }));
}
