// SPDX-License-Identifier: MIT
//! BOLT#8 interop harness: drives THIS module's public API as a live peer
//! over stdin/stdout, so it can be paired back-to-back with lnd's `brontide`
//! (`oracle_main.go`, fetched by `fetch-oracle.sh`) -- CONVENTIONS.md §9
//! differential oracle, the Zig half.
//!
//! Talks to `bolt8` ONLY through `@import("bolt8")`'s public exports
//! (`Secp256k1DH`, `Initiator`/`Responder`, `Transport`, `act.Act1/2/3`) --
//! no module source is copied here.
//!
//! Raw fd I/O on purpose (`std.os.linux.read/write`) -- no `std.Io` surface,
//! so the harness cannot itself become the thing under test.
//!
//! Build (against the LIVE module):
//!   zig build-exe -O ReleaseFast --dep bolt8 --dep noise --dep k256 --dep chachapoly \
//!       -Mmain=peer.zig -Mbolt8=../src/root.zig \
//!       -Mnoise=<repo>/modules/noise/src/root.zig \
//!       -Mk256=<repo>/modules/k256/src/root.zig \
//!       -Mchachapoly=<repo>/modules/chachapoly/src/root.zig \
//!       --cache-dir <scratch>/zc -femit-bin=<scratch>/interop
//! Run: see `pair.sh` in this directory.

const std = @import("std");
const bolt8 = @import("bolt8");
const Sha256 = std.crypto.hash.sha2.Sha256;

const payload_lens = [_]usize{ 0, 1, 5, 17, 64, 255, 1366, 65535, 32, 3 };

/// Byte-identical to the Go side's `payload()`.
fn payload(tag: []const u8, i: usize, out: *[65535]u8) []u8 {
    const n = payload_lens[i % payload_lens.len];
    var ctr: [8]u8 = undefined;
    std.mem.writeInt(u64, &ctr, @intCast(i), .little);
    var h = Sha256.init(.{});
    h.update(tag);
    h.update(&ctr);
    var blk: [32]u8 = undefined;
    h.final(&blk);
    var off: usize = 0;
    while (off < n) {
        Sha256.hash(&blk, &blk, .{});
        const c = @min(32, n - off);
        @memcpy(out[off..][0..c], blk[0..c]);
        off += c;
    }
    return out[0..n];
}

const linux = std.os.linux;

fn errnoOf(r: usize) linux.E {
    const signed: isize = @bitCast(r);
    if (signed > -4096 and signed < 0) return @enumFromInt(@as(u16, @intCast(-signed)));
    return .SUCCESS;
}

fn rawRead(fd: i32, buf: []u8) !usize {
    while (true) {
        const r = linux.read(fd, buf.ptr, buf.len);
        switch (errnoOf(r)) {
            .SUCCESS => return r,
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
}

fn rawWrite(fd: i32, buf: []const u8) !usize {
    while (true) {
        const r = linux.write(fd, buf.ptr, buf.len);
        switch (errnoOf(r)) {
            .SUCCESS => return r,
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

fn readExact(buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try rawRead(0, buf[off..]);
        if (n == 0) return error.Eof;
        off += n;
    }
}

fn writeAll(buf: []const u8) !void {
    var off: usize = 0;
    while (off < buf.len) off += try rawWrite(1, buf[off..]);
}

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    var b: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&b, "zig: FATAL " ++ fmt ++ "\n", args) catch "zig: FATAL\n";
    _ = rawWrite(2, s) catch {};
    linux.exit_group(4);
    unreachable;
}

fn note(comptime fmt: []const u8, args: anytype) void {
    var b: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&b, "zig: " ++ fmt ++ "\n", args) catch return;
    _ = rawWrite(2, s) catch {};
}

const frame_max = 18 + 65535 + 16;
var wire_buf: [frame_max]u8 = undefined;
var plain_buf: [65535]u8 = undefined;
var want_buf: [65535]u8 = undefined;

pub fn main(init: std.process.Init.Minimal) !void {
    var argbuf: [8][]const u8 = undefined;
    var argn: usize = 0;
    var it = init.args.iterate();
    while (it.next()) |a| {
        if (argn == argbuf.len) break;
        argbuf[argn] = a;
        argn += 1;
    }
    const args = argbuf[0..argn];

    if (args.len < 4) die("usage: interop <init|resp> <priv-hex> <remote-pub-hex|-> [n]", .{});
    const is_init = std.mem.eql(u8, args[1], "init");
    var priv: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&priv, args[2]);
    var remote_pub: [33]u8 = undefined;
    if (is_init) _ = try std.fmt.hexToBytes(&remote_pub, args[3]);
    const n: usize = if (args.len > 4) try std.fmt.parseInt(usize, args[4], 10) else 1100;

    const ls = try bolt8.Secp256k1DH.KeyPair.generateDeterministic(priv);

    var seed: [32]u8 = undefined;
    if (errnoOf(linux.getrandom(&seed, seed.len, 0)) != .SUCCESS) return error.NoEntropy;
    var csprng = std.Random.DefaultCsprng.init(seed);
    const entropy: bolt8.handshake.Ephemeral = .{ .csprng = csprng.random() };

    var t: bolt8.Transport = undefined;

    if (is_init) {
        var initiator = bolt8.Initiator.init(ls, remote_pub);
        const a1 = try initiator.genAct1(entropy);
        try writeAll(&a1.toBytes());
        var a2b: [50]u8 = undefined;
        try readExact(&a2b);
        try initiator.readAct2(try bolt8.act.Act2.fromBytes(&a2b));
        const fin = try initiator.genAct3();
        try writeAll(&fin.msg.toBytes());
        t = bolt8.Transport.init(fin.result);
    } else {
        var responder = bolt8.Responder.init(ls);
        var a1b: [50]u8 = undefined;
        try readExact(&a1b);
        try responder.readAct1(try bolt8.act.Act1.fromBytes(&a1b));
        const a2 = try responder.genAct2(entropy);
        try writeAll(&a2.toBytes());
        var a3b: [66]u8 = undefined;
        try readExact(&a3b);
        const res = try responder.readAct3(try bolt8.act.Act3.fromBytes(&a3b));
        t = bolt8.Transport.init(res);
    }
    note("handshake ok (initiator={})", .{is_init});

    const send_tag = if (is_init) "i2r" else "r2i";
    const recv_tag = if (is_init) "r2i" else "i2r";

    var wire_hash = Sha256.init(.{});

    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (is_init) {
            try doSend(&t, send_tag, i, &wire_hash);
            try doRecv(&t, recv_tag, i);
        } else {
            try doRecv(&t, recv_tag, i);
            try doSend(&t, send_tag, i, &wire_hash);
        }
    }
    var d: [32]u8 = undefined;
    wire_hash.final(&d);
    note("OK {d} msgs each way; wire-out sha256={x}", .{ n, &d });
}

fn doSend(t: *bolt8.Transport, tag: []const u8, i: usize, wh: *Sha256) !void {
    const p = payload(tag, i, &plain_buf);
    const frame = wire_buf[0 .. 18 + p.len + 16];
    try t.sendMessage(p, frame);
    wh.update(frame);
    try writeAll(frame);
}

fn doRecv(t: *bolt8.Transport, tag: []const u8, i: usize) !void {
    const want = payload(tag, i, &want_buf);
    var lc: [18]u8 = undefined;
    try readExact(&lc);
    const l = try t.recvLength(&lc);
    if (l != want.len) die("msg {d}: length {d}, want {d}", .{ i, l, want.len });
    const c = wire_buf[0 .. @as(usize, l) + 16];
    try readExact(c);
    const got = plain_buf[0..l];
    try t.recvMessage(c, got);
    if (!std.mem.eql(u8, got, want)) die("msg {d}: body mismatch ({d} bytes)", .{ i, l });
}
