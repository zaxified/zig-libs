// SPDX-License-Identifier: MIT

//! Comparative benchmark: `bolt8` against lnd's `brontide` (v0.21.3-beta, the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-bolt8` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Run from the
//! repository root. Needs `go` and `python3` plus network access to the Go
//! module proxy for the two modules brontide imports (btcec/v2, x/crypto), and
//! lnd's `brontide/noise.go` and `keychain/ecdh.go` at the pinned tag in the
//! directory `LND_BRONTIDE_SRC` (default `.zig-cache/foreign/lnd`); missing
//! files print the fetch recipe and exit 2. `go_bench/prepare.sh` adapts them
//! into `.zig-cache/bench-bolt8/go`, next to `go_bench/main.go`.
//!
//! Workloads, all in memory (no sockets):
//!   handshake  both sides of acts 1-3 from fixed static and ephemeral keys,
//!              from fresh Initiator/Responder (Machine) objects
//!   xfer_1k    one 1 KiB message encrypted on one side and decrypted on the
//!   xfer_64k   other (65535 bytes for xfer_64k, the protocol maximum), over
//!              established transports, key rotation included
//! Both sides double the batch until it takes over 100 ms and keep the best of
//! five. Before timing ours, what brontide produced from the same fixed keys
//! must match byte for byte: the 166 act bytes, and the first transport frame
//! of each size, which we must also decrypt to the message.
//!
//! Known asymmetries: our `KeyPair` caches the static public key while
//! brontide's `PrivKeyECDH.PubKey()` recomputes it (that cost is part of its
//! handshake); the Go side allocates per message (`ReadMessage` returns a new
//! slice) where ours writes into caller buffers. Both are API differences,
//! not benchmark choices.

const std = @import("std");
const bolt8 = @import("bolt8");

const work_dir = ".zig-cache/bench-bolt8";
const default_src = ".zig-cache/foreign/lnd";

const Row = struct { ns: f64, count: u64 };

/// A "random" source that returns the same 32 bytes on every draw: the
/// `seeded_for_test` ephemeral arm, so the acts are reproducible.
const Fixed = struct {
    key: [32]u8,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const s: *Fixed = @ptrCast(@alignCast(ptr));
        std.debug.assert(buf.len == s.key.len);
        @memcpy(buf, &s.key);
    }
    fn random(s: *Fixed) std.Random {
        return .{ .ptr = s, .fillFn = fill };
    }
};

const Keys = struct {
    ls_i: bolt8.Secp256k1DH.KeyPair,
    ls_r: bolt8.Secp256k1DH.KeyPair,
    e_i: Fixed,
    e_r: Fixed,
};

const Both = struct { ini: bolt8.HandshakeResult, rsp: bolt8.HandshakeResult };

fn handshake(k: *Keys, acts: *[166]u8) !Both {
    var ini = bolt8.Initiator.init(k.ls_i, k.ls_r.public_key);
    var rsp = bolt8.Responder.init(k.ls_r);
    const a1 = (try ini.genAct1(.{ .seeded_for_test = k.e_i.random() })).toBytes();
    try rsp.readAct1(try bolt8.act.Act1.fromBytes(&a1));
    const a2 = (try rsp.genAct2(.{ .seeded_for_test = k.e_r.random() })).toBytes();
    try ini.readAct2(try bolt8.act.Act2.fromBytes(&a2));
    const fin = try ini.genAct3();
    const a3 = fin.msg.toBytes();
    const rr = try rsp.readAct3(try bolt8.act.Act3.fromBytes(&a3));
    @memcpy(acts[0..50], &a1);
    @memcpy(acts[50..100], &a2);
    @memcpy(acts[100..166], &a3);
    return .{ .ini = fin.result, .rsp = rr };
}

const HsCtx = struct {
    keys: *Keys,
    acts: [166]u8 = undefined,
    fn op(c: *HsCtx) usize {
        const r = handshake(c.keys, &c.acts) catch unreachable;
        std.mem.doNotOptimizeAway(r);
        return c.acts.len;
    }
};

const XferCtx = struct {
    ini: bolt8.Transport,
    rsp: bolt8.Transport,
    msg: []const u8,
    wire: []u8,
    out: []u8,
    fn op(c: *XferCtx) usize {
        const frame = c.wire[0 .. bolt8.transport.length_frame_len + c.msg.len + 16];
        c.ini.sendMessage(c.msg, frame) catch unreachable;
        const l = c.rsp.recvLength(frame[0..bolt8.transport.length_frame_len]) catch unreachable;
        c.rsp.recvMessage(frame[bolt8.transport.length_frame_len..][0 .. @as(usize, l) + 16], c.out[0..l]) catch unreachable;
        std.mem.doNotOptimizeAway(c.out[0]);
        return frame.len;
    }
};

fn timeIt(io: std.Io, ctx: anytype, comptime f: fn (@TypeOf(ctx)) usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(f(ctx));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = f(ctx);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

fn recipe(src: []const u8) void {
    std.debug.print(
        \\bench-bolt8: lnd sources not found in {s} (set LND_BRONTIDE_SRC to another directory).
        \\Fetch them (reference tag v0.21.3-beta), then check the sums:
        \\  B=https://raw.githubusercontent.com/lightningnetwork/lnd/v0.21.3-beta
        \\  mkdir -p {s}/brontide {s}/keychain
        \\  curl -sfL -o {s}/brontide/noise.go $B/brontide/noise.go
        \\  curl -sfL -o {s}/keychain/ecdh.go  $B/keychain/ecdh.go
        \\  sha256 brontide/noise.go = 15fea7c6f6fe58c40da054269b6ff70187fdfc5e8da8366a8251816ae5427ec3
        \\  sha256 keychain/ecdh.go  = 5048abe2df13c495d2a10560b8cfd35e4f9881f36fb0135fd6b534f0bac46c11
        \\
    , .{ src, src, src, src, src });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();

    const src = init.environ_map.get("LND_BRONTIDE_SRC") orelse default_src;
    for ([_][]const u8{ "brontide/noise.go", "keychain/ecdh.go" }) |rel| {
        const p = try std.fmt.allocPrint(arena, "{s}/{s}", .{ src, rel });
        cwd.access(io, p, .{}) catch {
            recipe(src);
            return 2;
        };
    }

    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const abs_src = try cwd.realPathFileAlloc(io, src, arena);

    var prng = std.Random.DefaultPrng.init(0x0b5e_55ed_b017);
    const msg_1k = try arena.alloc(u8, 1024);
    const msg_64k = try arena.alloc(u8, 65535);
    prng.random().bytes(msg_1k);
    prng.random().bytes(msg_64k);
    try dir.writeFile(io, .{ .sub_path = "msg_1k.bin", .data = msg_1k });
    try dir.writeFile(io, .{ .sub_path = "msg_64k.bin", .data = msg_64k });

    std.debug.print("bench-bolt8: building the brontide side (needs the Go module proxy) ...\n", .{});
    const go_dir = try std.fmt.allocPrint(arena, "{s}/go", .{abs});
    const prep = try std.process.run(arena, io, .{ .argv = &.{ "bash", "modules/bolt8/tools/go_bench/prepare.sh", abs_src, go_dir } });
    if (prep.term != .exited or prep.term.exited != 0) {
        std.debug.print("bench-bolt8: prepare.sh failed:\n{s}\n", .{prep.stderr});
        return 1;
    }
    const exe = try std.fmt.allocPrint(arena, "{s}/gobench", .{go_dir});
    std.debug.print("bench-bolt8: lnd brontide ({s}) ...\n", .{std.mem.trim(u8, prep.stderr, "\n")});
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-bolt8: brontide side failed:\n{s}\n", .{res.stderr});
        return 1;
    }
    var rows: std.StringHashMapUnmanaged(Row) = .empty;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, '\t');
        const name = f.next() orelse continue;
        const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
        const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
        try rows.put(arena, name, .{ .ns = ns, .count = count });
    }

    var keys: Keys = .{
        .ls_i = try bolt8.Secp256k1DH.KeyPair.generateDeterministic(@splat(0x11)),
        .ls_r = try bolt8.Secp256k1DH.KeyPair.generateDeterministic(@splat(0x21)),
        .e_i = .{ .key = @splat(0x12) },
        .e_r = .{ .key = @splat(0x22) },
    };

    // Interop before timing: the same keys must give the same bytes.
    var acts: [166]u8 = undefined;
    _ = try handshake(&keys, &acts);
    const go_acts = try dir.readFileAlloc(io, "go_acts.bin", arena, .limited(4096));
    if (!std.mem.eql(u8, &acts, go_acts)) {
        std.debug.print("bench-bolt8: FAILED -- the handshake acts differ from brontide's\n", .{});
        return 1;
    }
    const wire = try arena.alloc(u8, bolt8.transport.length_frame_len + 65535 + 16);
    const out = try arena.alloc(u8, 65535);
    const W = struct { name: []const u8, frame_file: []const u8, msg: []const u8 };
    const ws = [_]W{
        .{ .name = "xfer_1k", .frame_file = "go_frame_1k.bin", .msg = msg_1k },
        .{ .name = "xfer_64k", .frame_file = "go_frame_64k.bin", .msg = msg_64k },
    };
    for (ws) |x| {
        const theirs = try dir.readFileAlloc(io, x.frame_file, arena, .limited(1 << 20));
        var a: [166]u8 = undefined;
        const p = try handshake(&keys, &a);
        var ti = bolt8.Transport.init(p.ini);
        var tr = bolt8.Transport.init(p.rsp);
        const mine = wire[0..theirs.len];
        try ti.sendMessage(x.msg, mine);
        if (!std.mem.eql(u8, mine, theirs)) {
            std.debug.print("bench-bolt8: FAILED -- the {s} frame differs from brontide's\n", .{x.name});
            return 1;
        }
        // And our receiver must open brontide's frame.
        const l = try tr.recvLength(theirs[0..bolt8.transport.length_frame_len]);
        try tr.recvMessage(theirs[bolt8.transport.length_frame_len..], out[0..l]);
        if (!std.mem.eql(u8, out[0..l], x.msg)) {
            std.debug.print("bench-bolt8: FAILED -- brontide's {s} frame opens to a different message\n", .{x.name});
            return 1;
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<9} {s:>13} {s:>13} {s:>10}  bytes on the wire\n", .{ "workload", "ours ns/op", "brontide ns", "ours/lnd" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var mismatch = false;
    {
        var c: HsCtx = .{ .keys = &keys };
        const ours = timeIt(io, &c, HsCtx.op);
        const t = rows.get("handshake") orelse return error.MissingRow;
        const ratio = ours.ns / t.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const same = ours.count == t.count;
        if (!same) mismatch = true;
        try w.print("{s:<9} {d:>13.0} {d:>13.0} {d:>10.2}  {d}{s}\n", .{ "handshake", ours.ns, t.ns, ratio, ours.count, if (same) "" else " ≠" });
        try w.flush();
    }
    for (ws) |x| {
        var a: [166]u8 = undefined;
        const p = try handshake(&keys, &a);
        var c: XferCtx = .{ .ini = bolt8.Transport.init(p.ini), .rsp = bolt8.Transport.init(p.rsp), .msg = x.msg, .wire = wire, .out = out };
        const ours = timeIt(io, &c, XferCtx.op);
        const t = rows.get(x.name) orelse return error.MissingRow;
        const ratio = ours.ns / t.ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        const same = ours.count == t.count;
        if (!same) mismatch = true;
        try w.print("{s:<9} {d:>13.0} {d:>13.0} {d:>10.2}  {d}{s}\n", .{ x.name, ours.ns, t.ns, ratio, ours.count, if (same) "" else " ≠" });
        try w.flush();
    }
    if (mismatch) return 1;
    try w.print("\nworst ours/lnd = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× lnd brontide v0.21.3-beta · fastest ? (measured 2026-10-07)\n", .{ best, worst });
    try w.flush();
    return 0;
}
