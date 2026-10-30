// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GS), findings HD-1, HD-2, round 2.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const hd = @import("root.zig");

const all_algos = std.enums.values(hd.Algorithm);

test "file hashing: a hostile path is null, never a panic (sweep HD-1)" {
    var out: [hd.max_hex_len]u8 = undefined;
    const long: [5000]u8 = @splat('a');
    const paths = [_][]const u8{ "", "a\x00b", "\x00", &long, "/", "/proc", ".", "..", "/nonexistent/x/y" };
    for (paths) |p| {
        var h256: [hd.hex_len]u8 = undefined;
        try testing.expect(hd.sha256File(testing.io, p, &h256) == null);
        for (all_algos) |a| {
            try testing.expect((try hd.hashFile(a, testing.io, p, &out)) == null);
        }
    }
}

/// Run `body` in a forked child; true iff it was killed by a signal (a panic
/// aborts) or ran past five seconds.
fn childDies(comptime body: fn () void) !bool {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(@intCast(linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0)), 2);
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
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return true;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    return linux.W.IFSIGNALED(status) or linux.W.EXITSTATUS(status) != 0;
}

fn updateAfterFinal() void {
    var out: [hd.max_hex_len]u8 = undefined;
    for (all_algos) |a| {
        var h = hd.MultiHasher.init(a);
        h.update("abc");
        const first = h.finalHex(&out) catch std.process.exit(2);
        var keep: [hd.max_hex_len]u8 = undefined;
        @memcpy(keep[0..first.len], first);
        // the second finalHex repeats the first digest
        var out2: [hd.max_hex_len]u8 = undefined;
        const again = h.finalHex(&out2) catch std.process.exit(3);
        if (!std.mem.eql(u8, keep[0..first.len], again)) std.process.exit(4);
        // feeding on continues the stream: digest of "abcmore"
        h.update("more");
        const cont = h.finalHex(&out2) catch std.process.exit(5);
        var whole: [hd.max_hex_len]u8 = undefined;
        const want = hd.hex(a, "abcmore", &whole) catch std.process.exit(6);
        if (!std.mem.eql(u8, want, cont)) std.process.exit(7);
    }
    var h = hd.Hasher.init();
    var o: [hd.hex_len]u8 = undefined;
    h.update("abc");
    h.finalHex(&o);
    h.update("more");
    h.finalHex(&o);
    if (!std.mem.eql(u8, &o, &hd.sha256HexBuf("abcmore"))) std.process.exit(8);
}

test "an incremental hasher survives finalHex: update after it and a second finalHex are defined (sweep HD-2)" {
    try testing.expect(!try childDies(updateAfterFinal));
}
