// SPDX-License-Identifier: MIT

//! Comparative benchmark: `hpke` against Go 1.26's standard-library
//! `crypto/hpke` (the reference), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-hpke` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` on PATH;
//! the Go side is standard library only (no module is fetched). The Go side,
//! `tools/go_bench/main.go`, is built in place by `testkit.bench.goBuild`
//! (offline, `GOPROXY=off`). Run from the repository root.
//!
//! Suites (RFC 9180 pairing of KEM and KDF, base mode):
//!   x25519    DHKEM(X25519, HKDF-SHA256),  HKDF-SHA256, AES-128-GCM
//!   p256      DHKEM(P-256, HKDF-SHA256),   HKDF-SHA256, AES-128-GCM
//!   p384      DHKEM(P-384, HKDF-SHA384),   HKDF-SHA384, AES-128-GCM
//!   p521      DHKEM(P-521, HKDF-SHA512),   HKDF-SHA512, AES-128-GCM
//!   x25519cc  DHKEM(X25519, HKDF-SHA256),  HKDF-SHA256, ChaCha20Poly1305
//! Workloads per suite, same keys, info and messages on both sides:
//!   keygen    the KEM's key generation (`Kem.generateKeyPair` vs
//!             `KEM.GenerateKey`; ours draws a seed and runs the RFC's
//!             DeriveKeyPair, Go draws the scalar directly)
//!   setupS    `setupBaseS` vs `NewSender` (ephemeral key, encap, schedule)
//!   setupR    `setupBaseR` vs `NewRecipient` (decap, schedule)
//!   seal64, seal16k   `Context.seal` / `Sender.Seal` of 64 B and 16 KiB on an
//!             established context (ours into a preallocated buffer, Go
//!             allocates the result: it has no other API)
//!   open64, open16k   `Context.open` / `Recipient.Open`; ours rewinds `seq`
//!             to 0 for each call, Go's side cannot rewind, so it opens chunks
//!             sealed untimed by a fresh Sender (only Open is on the clock)
//!   export    `exportSecret` (32 B) vs `Sender.Export`
//! Every suite but x25519cc runs keygen .. open16k; x25519cc, the
//! ChaCha20Poly1305 suite, carries only seal16k and export.
//!
//! Round 2: the draft-ietf-hpke-pq KEMs, rows keygen/setupS/setupR only, with
//! HKDF-SHA256 and AES-128-GCM:
//!   mlkem768, mlkem1024, xwing (MLKEM768-X25519), mlkem768p256, mlkem1024p384
//! and xwingshake (X-Wing, SHAKE256 one-stage KDF), which adds seal64.
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over
//! 100 ms and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best; spread =
//! (worst round − best round) / best round. The Go side has no cycle counter,
//! so ratios are by wall time. Before timing anything, for every suite Go must
//! open what we seal (two messages with aad and an export) and we must open
//! and export what Go seals; the public key Go derives from our secret key
//! must equal ours. Arguments filter workloads by substring.

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const hpke = @import("hpke");
const aesgcm = @import("aesgcm");

const bench_name = "bench-hpke";
const work_dir = ".zig-cache/bench-hpke";
const go_dir = "modules/hpke/tools/go_bench";
const info = "bench info";
const aad = "interop-aad";
const exporter_cx = "interop-export";

const Kind = enum { keygen, setupS, setupR, seal64, open64, seal16k, open16k, @"export" };
const Op = struct { suite: usize, kind: Kind };

var g_io: std.Io = undefined;

fn Suite(comptime Kem: type, comptime Aead: type, comptime Nh: anytype, comptime label: []const u8, comptime kinds_: []const Kind) type {
    const HCtx = hpke.Context(Aead, Nh);
    const Setup = hpke.Setup(Kem, Aead, Nh);
    const aead_id: u16 = if (Aead == hpke.ChaCha20Poly1305) @backingInt(hpke.AeadId.chacha20poly1305) else @backingInt(hpke.AeadId.aes128gcm);
    const suite_id = hpke.suite.suiteId(Kem.kem_id, hpke.kdf.Of(Nh).kdf_id, aead_id);
    return struct {
        const name = label;
        const kinds = kinds_;
        const is_pq = @hasDecl(Kem, "Ephemeral");
        const Enc = Kem.EncappedKey;
        var kp: Kem.KeyPair = undefined;
        var snd: Setup = undefined; // sender side, for seal / export
        var snd_open: Setup = undefined; // a fresh sender, to make the ciphertexts
        var rcv: HCtx = undefined; // for open (seq rewound each call)
        var rcv_setup: HCtx = undefined;
        var pt_short: [64]u8 = undefined;
        var pt_long: [16384]u8 = undefined;
        var ct_short: [64 + Aead.tag_length]u8 = undefined;
        var ct_long: [16384 + Aead.tag_length]u8 = undefined;
        var out_short: [64]u8 = undefined;
        var out_long: [16384]u8 = undefined;
        var seal_short: [64 + Aead.tag_length]u8 = undefined;
        var seal_long: [16384 + Aead.tag_length]u8 = undefined;
        var exp_out: [32]u8 = undefined;
        var scratch_kp: Kem.KeyPair = undefined;
        var scratch: Setup = undefined;

        fn fillPlain() void {
            for (&pt_short, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
            for (&pt_long, 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);
        }

        /// A fixed recipient key pair, and the contexts the workloads reuse.
        fn init(seed: u8) !void {
            fillPlain();
            var ikm: [Kem.Nsk]u8 = undefined;
            @memset(&ikm, seed);
            Kem.deriveKeyPair(&kp, &ikm);
            try hpke.setupBaseS(Kem, Aead, Nh, &snd, kp.public_key, g_io, info);
            try hpke.setupBaseR(Kem, Aead, Nh, &rcv, snd.enc, &kp, info);
            rcv_setup = rcv;
            // The ciphertexts `open` is fed, from a context at seq 0.
            snd_open = snd;
            try snd_open.context.seal("", &pt_short, &ct_short);
            try snd_open.context.seal("", &pt_long, &ct_long);
        }

        fn run(kind: Kind) usize {
            switch (kind) {
                .keygen => {
                    Kem.generateKeyPair(&scratch_kp, g_io);
                    return scratch_kp.public_key.len;
                },
                .setupS => {
                    hpke.setupBaseS(Kem, Aead, Nh, &scratch, kp.public_key, g_io, info) catch unreachable;
                    return scratch.enc.len;
                },
                .setupR => {
                    hpke.setupBaseR(Kem, Aead, Nh, &rcv_setup, snd.enc, &kp, info) catch unreachable;
                    return 1;
                },
                .seal64 => {
                    snd.context.seal("", &pt_short, &seal_short) catch unreachable;
                    return seal_short.len;
                },
                .seal16k => {
                    snd.context.seal("", &pt_long, &seal_long) catch unreachable;
                    return seal_long.len;
                },
                .open64 => {
                    rcv.seq = 0;
                    rcv.open("", &ct_short, &out_short) catch unreachable;
                    return out_short.len;
                },
                .open16k => {
                    rcv.seq = 0;
                    rcv.open("", &ct_long, &out_long) catch unreachable;
                    return out_long.len;
                },
                .@"export" => {
                    snd.context.exportSecret(&suite_id, exporter_cx, &exp_out) catch unreachable;
                    return exp_out.len;
                },
            }
        }

        /// Interop, our half one: write what Go must open.
        fn writeOurs(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator) !void {
            try dir.writeFile(io, .{ .sub_path = name ++ ".sk", .data = if (is_pq) &kp.seed else &kp.secret_key });
            try dir.writeFile(io, .{ .sub_path = name ++ ".pk", .data = &kp.public_key });
            var s: Setup = undefined;
            try hpke.setupBaseS(Kem, Aead, Nh, &s, kp.public_key, io, info);
            const ct0 = try arena.alloc(u8, pt_short.len + Aead.tag_length);
            const ct1 = try arena.alloc(u8, pt_long.len + Aead.tag_length);
            try s.context.seal(aad, &pt_short, ct0);
            try s.context.seal(aad, &pt_long, ct1);
            var e: [32]u8 = undefined;
            try s.context.exportSecret(&suite_id, exporter_cx, &e);
            try dir.writeFile(io, .{ .sub_path = "zig_" ++ name ++ ".enc", .data = &s.enc });
            try dir.writeFile(io, .{ .sub_path = "zig_" ++ name ++ ".ct0", .data = ct0 });
            try dir.writeFile(io, .{ .sub_path = "zig_" ++ name ++ ".ct1", .data = ct1 });
            try dir.writeFile(io, .{ .sub_path = "zig_" ++ name ++ ".exp", .data = &e });
        }

        /// Interop, half two: open what Go sealed. Returns false on a mismatch.
        fn checkTheirs(dir: std.Io.Dir, io: std.Io, arena: std.mem.Allocator) !bool {
            const enc_b = try dir.readFileAlloc(io, "go_" ++ name ++ ".enc", arena, .limited(1 << 12));
            if (enc_b.len != @sizeOf(Enc)) return false;
            var ctx: HCtx = undefined;
            try hpke.setupBaseR(Kem, Aead, Nh, &ctx, enc_b[0..@sizeOf(Enc)].*, &kp, info);
            const ct0 = try dir.readFileAlloc(io, "go_" ++ name ++ ".ct0", arena, .limited(1 << 20));
            const ct1 = try dir.readFileAlloc(io, "go_" ++ name ++ ".ct1", arena, .limited(1 << 20));
            if (ct0.len != pt_short.len + Aead.tag_length or ct1.len != pt_long.len + Aead.tag_length) return false;
            var o0: [64]u8 = undefined;
            var o1: [16384]u8 = undefined;
            ctx.open(aad, ct0, &o0) catch return false;
            ctx.open(aad, ct1, &o1) catch return false;
            if (!std.mem.eql(u8, &o0, &pt_short) or !std.mem.eql(u8, &o1, &pt_long)) return false;
            var e: [32]u8 = undefined;
            try ctx.exportSecret(&suite_id, exporter_cx, &e);
            const theirs = try dir.readFileAlloc(io, "go_" ++ name ++ ".exp", arena, .limited(64));
            return std.mem.eql(u8, &e, theirs);
        }
    };
}

const all_kinds = [_]Kind{ .keygen, .setupS, .setupR, .seal64, .open64, .seal16k, .open16k };
const kem_kinds = [_]Kind{ .keygen, .setupS, .setupR };
const suites = .{
    Suite(hpke.X25519Kem, aesgcm.Aes128Gcm, 32, "x25519", &all_kinds),
    Suite(hpke.P256Kem, aesgcm.Aes128Gcm, 32, "p256", &all_kinds),
    Suite(hpke.P384Kem, aesgcm.Aes128Gcm, 48, "p384", &all_kinds),
    Suite(hpke.P521Kem, aesgcm.Aes128Gcm, 64, "p521", &all_kinds),
    Suite(hpke.X25519Kem, hpke.ChaCha20Poly1305, 32, "x25519cc", &.{ .seal16k, .@"export" }),
    // draft-ietf-hpke-pq KEMs, HKDF-SHA256 + AES-128-GCM; X-Wing again over SHAKE256.
    Suite(hpke.MlKem768Kem, aesgcm.Aes128Gcm, 32, "mlkem768", &kem_kinds),
    Suite(hpke.MlKem1024Kem, aesgcm.Aes128Gcm, 32, "mlkem1024", &kem_kinds),
    Suite(hpke.MlKem768X25519Kem, aesgcm.Aes128Gcm, 32, "xwing", &kem_kinds),
    Suite(hpke.MlKem768P256Kem, aesgcm.Aes128Gcm, 32, "mlkem768p256", &kem_kinds),
    Suite(hpke.MlKem1024P384Kem, aesgcm.Aes128Gcm, 32, "mlkem1024p384", &kem_kinds),
    Suite(hpke.MlKem768X25519Kem, aesgcm.Aes128Gcm, hpke.kdf.Shake256, "xwingshake", &.{ .keygen, .setupS, .setupR, .seal64 }),
};

const Ctx = struct { op: Op = .{ .suite = 0, .kind = .keygen } };

fn once(x: *Ctx) usize {
    inline for (suites, 0..) |S, i| {
        if (x.op.suite == i) return S.run(x.op.kind);
    }
    unreachable;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    g_io = io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    inline for (suites, 0..) |S, i| {
        try S.init(@intCast(0x41 + i));
        try S.writeOurs(dir, io, arena);
    }

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });

    // Interop before timing: Go opens ours inside `interop`; now we open Go's.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    inline for (suites) |S| {
        if (!try S.checkTheirs(dir, io, arena)) {
            std.debug.print("{s}: FAILED -- Go's {s} messages do not open here\n", .{ bench_name, S.name });
            return 1;
        }
    }
    std.debug.print("{s}: interop OK (Go opens ours and we open Go's, {d} suites)\n", .{ bench_name, suites.len });

    var ws: std.ArrayList(Work) = .empty;
    inline for (suites, 0..) |S, i| {
        for (S.kinds) |k| try ws.append(arena, .{
            .name = try arena.print("{s}_{s}", .{ S.name, @tagName(k) }),
            .op = .{ .suite = i, .kind = k },
            .ref = try arena.print("go.{s}_{s}", .{ S.name, @tagName(k) }),
        });
    }

    var ctx: Ctx = .{};
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/Go = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go crypto/hpke (Go <version>) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
