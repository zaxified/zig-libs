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

test "new pub inputs: xof/blake3 with empty and long outputs, checksum parser on hostile text, verify on hostile names (sweep HD-3)" {
    var big: [5000]u8 = undefined;
    @memset(&big, 0x5a);
    for ([_]hd.Xof{ .shake128, .shake256, .blake3 }) |k| {
        hd.xof(k, "", big[0..0]);
        hd.xof(k, "", &big);
        hd.xof(k, &big, big[0..1]);
    }
    const key: [32]u8 = @splat(0);
    hd.blake3Keyed(&key, &big, big[0..0]);
    hd.blake3Keyed(&key, "", &big);
    hd.blake3DeriveKey("", "", big[0..0]);
    var ctx: [300]u8 = @splat('c');
    hd.blake3DeriveKey(&ctx, &big, &big);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const junk = [_][]const u8{
        "",               "\n",            "\r\n\r\n",   "\\",                  "\\\\\n",           "  ",       "ab",
        "ab ",            "ab  ",          "ab  \x00",   "ab (",                "ab ) = ",          "A (b) = ", " ( ) = ",
        "SHA256 () = ab", "SHA256 (x) = ", "\xff\xfe\n", "(((((((( ) = ) = \n", "# only a comment",
    };
    for (junk) |t| {
        var it = hd.checksum.Iterator.init(t);
        while (true) {
            const e = (it.next() catch continue) orelse break;
            var nb: [4]u8 = undefined;
            _ = e.unescapeName(&nb) catch {};
        }
        for (all_algos) |a| {
            const s = hd.checksum.verifyAll(testing.io, tmp.dir, a, t, .{});
            try testing.expectEqual(@as(usize, 0), s.ok);
        }
    }
    // an 8 KiB name is a status or an error, not a panic; so is one climbing out of the directory
    var long: [8300]u8 = undefined;
    @memset(&long, 'a');
    @memcpy(long[0..64], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    long[64] = ' ';
    long[65] = ' ';
    _ = hd.checksum.verifyAll(testing.io, tmp.dir, .sha256, &long, .{});
    const up = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  ../../../../../../../../nonexistent-hd-sweep\n";
    try testing.expectEqual(@as(usize, 1), hd.checksum.verifyAll(testing.io, tmp.dir, .sha256, up, .{ .allow_unsafe_names = true }).unreadable);
}
