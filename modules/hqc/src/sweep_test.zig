// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GT, findings HQ-1 .. HQ-4), see
//! ~/CML/20261029-panic-sweep/hqc-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const params = @import("params.zig");
const gf2x = @import("gf2x.zig");
const prng = @import("prng.zig");

const R = gf2x.Ring(params.hqc128.n);

const Child = struct { died: bool, len: usize };

/// Run `body` in a forked child, stderr captured into `buf`; `died` = killed by
/// a signal (a panic aborts). Past five seconds the child counts as hung.
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

// Needles live in consts, never inline at the call: the child's stack trace
// prints the caller's source line, so an inline needle matches ANY panic.
fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

const needle_bit = R.bit_range_msg;
const needle_bytes = R.to_bytes_msg;
const needle_vect = prng.sample_vect_msg;

var runtime_len: usize = 0; // keeps lengths/positions out of the optimizer's sight

// ── HQ-1: Ring.toBytes output length ────────────────────────────────────────

fn toBytesShort() void {
    var out: [R.n_bytes]u8 = undefined;
    runtime_len = R.n_bytes - 1;
    R.toBytes(R.zero, out[0..runtime_len]);
}

test "Ring.toBytes: a short output is a checked panic, an exact or longer one works (sweep HQ-1)" {
    var big: [R.n_bytes + 3]u8 = @splat(0xAA);
    R.toBytes(R.zero, &big);
    try testing.expectEqual(@as(u8, 0), big[R.n_bytes - 1]);
    try testing.expectEqual(@as(u8, 0xAA), big[R.n_bytes]); // untouched tail
    try expectPanicMessage(toBytesShort, needle_bytes);
}

// ── HQ-2: Ring.truncate ─────────────────────────────────────────────────────

test "Ring.truncate: n1n2 >= n keeps the (canonical) vector instead of indexing past it (sweep HQ-2)" {
    var v = R.zero;
    R.setBit(&v, 0);
    R.setBit(&v, R.bit_len - 1);
    const want = v;
    R.truncate(&v, R.bit_len); // == n: used to be allowed, must stay a no-op
    try testing.expectEqualSlices(u64, &want, &v);
    runtime_len = R.bit_len + 64 * R.words; // far past the vector
    R.truncate(&v, @intCast(runtime_len));
    try testing.expectEqualSlices(u64, &want, &v);
}

// ── HQ-3: setBit / getBit ───────────────────────────────────────────────────

fn setBitAtN() void {
    var v = R.zero;
    runtime_len = R.bit_len;
    R.setBit(&v, @intCast(runtime_len));
}
fn getBitPastWords() void {
    const v = R.zero;
    runtime_len = 64 * R.words + 5;
    _ = R.getBit(v, @intCast(runtime_len));
}

test "Ring.setBit / getBit: pos >= n is a checked panic (sweep HQ-3)" {
    var v = R.zero;
    R.setBit(&v, R.bit_len - 1);
    try testing.expectEqual(@as(u1, 1), R.getBit(v, R.bit_len - 1));
    try expectPanicMessage(setBitAtN, needle_bit);
    try expectPanicMessage(getBitPastWords, needle_bit);
}

// ── HQ-4: sampleVect output length ──────────────────────────────────────────

fn sampleShort() void {
    var xof = prng.Xof.init("seed");
    var out: [R.words]u64 = undefined;
    runtime_len = R.words - 1;
    prng.sampleVect(&xof, params.hqc128.n, out[0..runtime_len]);
}

test "sampleVect: an output shorter than ceil(n/64) words is a checked panic (sweep HQ-4)" {
    var xof = prng.Xof.init("seed");
    var out: [R.words]u64 = undefined;
    prng.sampleVect(&xof, params.hqc128.n, &out);
    try testing.expectEqual(@as(u64, 0), out[R.words - 1] >> @intCast(params.hqc128.n % 64)); // masked
    try expectPanicMessage(sampleShort, needle_vect);
}
