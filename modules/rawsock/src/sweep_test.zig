// SPDX-License-Identifier: MIT
//! No-panic sweep tests for rawsock (wave GS). Findings RS1 .. RS4 (the tests of the private
//! helpers behind RS2/RS3 sit in filter.zig / root.zig and use `expectSurvives`), see
//! ~/CML/20261029-panic-sweep/rawsock-sweep.report.md.
//!
//! Every body runs in a forked child: a panic, an overflow trap or a stack
//! overflow kills the child, not the test binary, and the parent asserts it
//! exited cleanly.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const rawsock = @import("root.zig");
const pcap = rawsock.pcap;
const filter = rawsock.filter;

/// Run `body` in a forked child; the child must exit 0. A child past ten
/// seconds counts as hung. Used by the tests of private functions in
/// `root.zig` / `filter.zig` too.
pub fn expectSurvives(comptime body: fn () void) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        body();
        linux.exit_group(0);
    }
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 10_000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    try testing.expect(!linux.W.IFSIGNALED(status));
    try testing.expect(linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 0);
}

// ── RS1: filter.compile, a left-deep chain of terms ─────────────────────────

fn chainBody() void {
    const gpa = std.heap.page_allocator;
    const unit = " and ip";
    const n = 300_000;
    const src = gpa.alloc(u8, 2 + unit.len * n) catch @panic("oom");
    @memcpy(src[0..2], "ip");
    for (0..n) |i| @memcpy(src[2 + i * unit.len ..][0..unit.len], unit);
    if (filter.compile(gpa, src)) |prog| {
        gpa.free(prog);
        @panic("a 300000-term chain compiled");
    } else |e| if (e != error.FilterTooComplex) @panic("wrong error");
}

test "filter.compile: a 300000-term 'and' chain is FilterTooComplex, not a stack overflow (sweep RS1)" {
    try expectSurvives(chainBody);
}

test "filter.compile: the chain bound sits at max_insns terms, and short chains still compile (sweep RS1)" {
    const gpa = testing.allocator;
    // 4096 terms is accepted by the parser (depth 4096 in gen) and refused for
    // length/jump distance; 4097 is refused by the parser itself.
    inline for (.{ 4096, 4097 }) |n| {
        const src = try gpa.alloc(u8, 2 + 7 * (n - 1));
        defer gpa.free(src);
        @memcpy(src[0..2], "ip");
        for (0..n - 1) |i| @memcpy(src[2 + i * 7 ..][0..7], " and ip");
        try testing.expectError(error.FilterTooComplex, filter.compile(gpa, src));
    }
    const ok = try filter.compile(gpa, "ip and ip and ip and ip and ip");
    defer gpa.free(ok);
    var frame: [22]u8 = @splat(0);
    frame[12] = 0x08; // EtherType 0x0800
    try testing.expect(filter.run(ok, &frame) != 0);
}

// ── RS2: run(), a ja offset that overflows a 32-bit pc ──────────────────────

test "filter.run: a huge ja offset drops the frame (sweep RS2)" {
    // On every target a huge `ja` drops the frame.
    const prog = [_]rawsock.BpfInsn{
        .{ .code = filter.op.jmp | filter.op.ja, .jt = 0, .jf = 0, .k = std.math.maxInt(u32) },
        .{ .code = filter.op.ret | filter.op.k, .jt = 0, .jf = 0, .k = 1 },
    };
    try testing.expectEqual(@as(u32, 0), filter.run(&prog, ""));
}

// ── RS4: pcap.Reader with its public `pos` moved past the end ───────────────

fn posBody() void {
    var file: [pcap.header_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&file);
    pcap.writeHeader(&w, .{}) catch @panic("header");
    var r = pcap.Reader.init(&file) catch @panic("init");
    r.pos = file.len + 5;
    const rec = r.next() catch @panic("error instead of end");
    if (rec != null) @panic("record from nowhere");
}

test "pcap.Reader.next: pos past the end is end-of-file, not an underflow (sweep RS4)" {
    try expectSurvives(posBody);
}
