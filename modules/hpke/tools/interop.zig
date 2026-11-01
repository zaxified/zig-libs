// SPDX-License-Identifier: MIT

//! Live oracle for `hpke`: Go 1.26 `crypto/hpke` (the card's scope reference)
//! as a peer, over every KEM, KDF and AEAD Go offers, base mode.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-hpke` runs it and
//! `zig build check-interop` compiles it. Needs `go` on PATH (standard library
//! only, nothing is fetched; GOPROXY=off); no network. Run from the repository
//! root.
//!
//!   zig build interop-hpke                          # random run, seed printed
//!   zig build interop-hpke -- --seed 7 --cases 90   # reproducible; 90 scenarios
//!   zig build interop-hpke -- --write               # also rewrite src/go_oracle_vectors.zig
//!
//! The matrix: DHKEM(X25519, P-256, P-384, P-521), ML-KEM-768/1024, X-Wing,
//! MLKEM768-P256, MLKEM1024-P384 (9 KEMs) x HKDF-SHA256/384/512, SHAKE128/256
//! (5 KDFs), the AEAD rotating through AES-128-GCM, AES-256-GCM,
//! ChaCha20-Poly1305 and export-only so that every KEM and every KDF meets
//! every AEAD: 45 suites, `--cases` scenarios dealt over them round-robin.
//!
//! One scenario = a recipient key pair (derived here from random IKM, handed
//! to Go as its secret key), an `info`, 1-5 messages (random aad, empty ones
//! included; none for export-only) and 1-3 exports (random exporter context
//! and length). It becomes rows judged by BOTH sides, where a verdict is what
//! a recipient makes of (enc, ciphertexts, aad): context not set up, each
//! message refused or opened to these bytes, each export's bytes.
//!
//!   go sealed   Go is the sender: its ephemeral key and encapsulation are
//!               foreign to us. Both sides open it; the plaintexts and Go's
//!               exports are expected.
//!   zig sealed  this module is the sender (setupBaseS); Go and we open it;
//!               our plaintexts and exports are expected.
//!   negatives   one bit of enc / ciphertext / aad flipped, or the ciphertext
//!               cut by a byte, on both kinds above. The two verdicts must be
//!               EQUAL -- including, for a flipped enc, the exports of the
//!               context both sides derive from it (implicit rejection and
//!               X25519 give the same garbage on both).
//!
//! A row passes when Go's verdict equals ours and, for the two positive kinds,
//! equals the expected one. `cases` counts rows; any disagreement exits 1. The
//! whole run is reproducible from `--seed` on Go's side (Go's own randomness
//! is pinned with testing/cryptotest, which is why the Go peer is a test
//! binary built with `go test -c`); only OUR ephemeral keys are drawn fresh.
//!
//! `--write` freezes the first scenario of every suite -- Go's sealed bytes
//! (enc, ciphertexts, exports) and Go's verdict on each negative -- into
//! `src/go_oracle_vectors.zig`, which `src/go_oracle_test.zig` replays in
//! `test-hpke` without Go. Without `--seed`, `--write` uses a fixed seed, so
//! two runs give the same file.

const std = @import("std");
const hpke = @import("hpke");
const aesgcm = @import("aesgcm");

const work_dir = ".zig-cache/interop-hpke";
const go_dir = "modules/hpke/tools/go_oracle";
const vectors_path = "modules/hpke/src/go_oracle_vectors.zig";
const frozen_seed: u64 = 0x6870_6b65_0001;
const default_cases: usize = 270;

var g_io: std.Io = undefined;

// ── the suite matrix ────────────────────────────────────────────────────────

const kems = .{
    .{ hpke.X25519Kem, "x25519" },
    .{ hpke.P256Kem, "p256" },
    .{ hpke.P384Kem, "p384" },
    .{ hpke.P521Kem, "p521" },
    .{ hpke.MlKem768Kem, "mlkem768" },
    .{ hpke.MlKem1024Kem, "mlkem1024" },
    .{ hpke.MlKem768X25519Kem, "xwing" },
    .{ hpke.MlKem768P256Kem, "mlkem768p256" },
    .{ hpke.MlKem1024P384Kem, "mlkem1024p384" },
};
const kdfs = .{
    .{ hpke.kdf.HkdfSha256, "hkdf-sha256" },
    .{ hpke.kdf.HkdfSha384, "hkdf-sha384" },
    .{ hpke.kdf.HkdfSha512, "hkdf-sha512" },
    .{ hpke.kdf.Shake128, "shake128" },
    .{ hpke.kdf.Shake256, "shake256" },
};
const aeads = .{
    .{ aesgcm.Aes128Gcm, "aes128gcm", 0x0001 },
    .{ aesgcm.Aes256Gcm, "aes256gcm", 0x0002 },
    .{ hpke.ChaCha20Poly1305, "chacha20poly1305", 0x0003 },
    .{ hpke.ExportOnly, "exportonly", 0xffff },
};

const exp_cap = 400;

fn Suite(comptime Kem: type, comptime Kdf: type, comptime Aead: type, comptime aead_id: u16, comptime label: []const u8) type {
    const HCtx = hpke.Context(Aead, Kdf);
    const Setup = hpke.Setup(Kem, Aead, Kdf);
    const suite_id = hpke.suite.suiteId(Kem.kem_id, Kdf.kdf_id, aead_id);
    return struct {
        const name = label;
        const nsk = Kem.Nsk;
        const has_aead = Aead != hpke.ExportOnly;
        const is_pq = @hasDecl(Kem, "Ephemeral");

        fn keyPair(ikm: []const u8) Kem.KeyPair {
            var kp: Kem.KeyPair = undefined;
            Kem.deriveKeyPair(&kp, ikm);
            return kp;
        }

        /// The secret key Go is given: the scalar, or the KEM's seed.
        fn secretKey(arena: std.mem.Allocator, ikm: []const u8) ![]u8 {
            const kp = keyPair(ikm);
            return arena.dupe(u8, if (is_pq) &kp.seed else &kp.secret_key);
        }

        /// This module as the sender.
        fn seal(arena: std.mem.Allocator, ikm: []const u8, info: []const u8, msgs: []const Msg, exps: []const Exp) !Sealed {
            const kp = keyPair(ikm);
            var s: Setup = undefined;
            try hpke.setupBaseS(Kem, Aead, Kdf, &s, kp.public_key, g_io, info);
            const cts = try arena.alloc([]u8, msgs.len);
            for (msgs, cts) |m, *c| {
                if (comptime has_aead) {
                    c.* = try arena.alloc(u8, m.data.len + Aead.tag_length);
                    try s.context.seal(m.aad, m.data, c.*);
                } else unreachable;
            }
            const outs = try arena.alloc([]u8, exps.len);
            for (exps, outs) |e, *o| {
                o.* = try arena.alloc(u8, e.len);
                try s.context.exportSecret(&suite_id, e.cx, o.*);
            }
            return .{ .enc = try arena.dupe(u8, &s.enc), .cts = cts, .exports = outs };
        }

        /// This module as the recipient: the same verdict string Go prints.
        fn judge(arena: std.mem.Allocator, r: *const Row) ![]const u8 {
            const kp = keyPair(r.ikm);
            if (r.enc.len != @sizeOf(Kem.EncappedKey)) return "E";
            var ctx: HCtx = undefined;
            hpke.setupBaseR(Kem, Aead, Kdf, &ctx, r.enc[0..@sizeOf(Kem.EncappedKey)].*, &kp, r.info) catch return "E";
            var out: std.Io.Writer.Allocating = .init(arena);
            const w = &out.writer;
            try w.writeAll("K|");
            for (r.msgs, 0..) |m, i| {
                if (i != 0) try w.writeAll(",");
                if (comptime has_aead) {
                    if (m.data.len < Aead.tag_length) {
                        try w.writeAll("x");
                        continue;
                    }
                    const pt = try arena.alloc(u8, m.data.len - Aead.tag_length);
                    if (ctx.open(m.aad, m.data, pt)) |_| try w.print("o{x}", .{pt}) else |_| try w.writeAll("x");
                } else try w.writeAll("x");
            }
            try w.writeAll("|");
            for (r.exps, 0..) |e, i| {
                if (i != 0) try w.writeAll(",");
                const o = try arena.alloc(u8, e.len);
                if (ctx.exportSecret(&suite_id, e.cx, o)) |_| try w.print("{x}", .{o}) else |_| try w.writeAll("x");
            }
            return out.written();
        }
    };
}

const suites = blk: {
    var out: [kems.len * kdfs.len]type = undefined;
    for (kems, 0..) |k, ki| {
        for (kdfs, 0..) |d, di| {
            const a = aeads[(ki + di) % aeads.len];
            out[ki * kdfs.len + di] = Suite(k[0], d[0], a[0], a[2], k[1] ++ "/" ++ d[1] ++ "/" ++ a[1]);
        }
    }
    break :blk out;
};

const Meta = struct { name: []const u8, nsk: usize, has_aead: bool };
const metas = blk: {
    var m: [suites.len]Meta = undefined;
    for (suites, 0..) |S, i| m[i] = .{ .name = S.name, .nsk = S.nsk, .has_aead = S.has_aead };
    break :blk m;
};

// ── data ────────────────────────────────────────────────────────────────────

/// A message: its aad and its plaintext (a plan, a sealing) or ciphertext (a row).
const Msg = struct { aad: []const u8, data: []const u8 };
/// An export request: exporter context and output length.
const Exp = struct { cx: []const u8, len: usize };
const Sealed = struct { enc: []const u8, cts: []const []const u8, exports: []const []const u8 };

const Plan = struct { suite: usize, ikm: []const u8, sk: []const u8, info: []const u8, msgs: []const Msg, exps: []const Exp };

const Origin = enum { go, zig };
const Neg = enum { enc, ct, aad, trunc };

const Row = struct {
    suite: usize,
    scen: usize,
    origin: Origin,
    /// null: a positive row (the sealed bytes as sealed).
    neg: ?Neg,
    pos: u32 = 0,
    ikm: []const u8,
    sk: []const u8,
    info: []const u8,
    enc: []const u8,
    msgs: []const Msg,
    exps: []const Exp,
    /// The verdict a positive row must get.
    expect: []const u8 = "",
};

fn judgeOurs(arena: std.mem.Allocator, r: *const Row) ![]const u8 {
    inline for (suites, 0..) |S, i| {
        if (r.suite == i) return S.judge(arena, r);
    }
    unreachable;
}

fn sealOurs(arena: std.mem.Allocator, p: *const Plan) !Sealed {
    inline for (suites, 0..) |S, i| {
        if (p.suite == i) return S.seal(arena, p.ikm, p.info, p.msgs, p.exps);
    }
    unreachable;
}

fn secretKeyOf(arena: std.mem.Allocator, suite: usize, ikm: []const u8) ![]u8 {
    inline for (suites, 0..) |S, i| {
        if (suite == i) return S.secretKey(arena, ikm);
    }
    unreachable;
}

fn flipped(arena: std.mem.Allocator, b: []const u8, pos: u32) ![]u8 {
    const out = try arena.dupe(u8, b);
    const bit = pos % (b.len * 8);
    out[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
    return out;
}

/// The negative row `k` makes of positive row `base` (null when the row has no
/// message to mutate). Only message 0 is kept, so a refused message cannot
/// shift the sequence number under a later one; only the enc mutation keeps
/// the exports (the context it derives is what is compared there).
fn negative(arena: std.mem.Allocator, base: Row, k: Neg, pos: u32) !?Row {
    var r = base;
    r.neg = k;
    r.pos = pos;
    r.expect = "";
    r.msgs = base.msgs[0..@min(1, base.msgs.len)];
    if (k != .enc) r.exps = &.{};
    switch (k) {
        .enc => r.enc = try flipped(arena, base.enc, pos),
        .ct, .aad, .trunc => {
            if (base.msgs.len == 0) return null;
            const m = base.msgs[0];
            const msg = try arena.alloc(Msg, 1);
            msg[0] = switch (k) {
                .ct => .{ .aad = m.aad, .data = try flipped(arena, m.data, pos) },
                .aad => .{ .aad = if (m.aad.len == 0) try arena.dupe(u8, &.{@as(u8, @truncate(pos))}) else try flipped(arena, m.aad, pos), .data = m.data },
                .trunc => .{ .aad = m.aad, .data = m.data[0 .. m.data.len - 1] },
                .enc => unreachable,
            };
            r.msgs = msg;
        },
    }
    return r;
}

// ── hex and the wire ────────────────────────────────────────────────────────

fn unhex(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn msgList(w: *std.Io.Writer, msgs: []const Msg) !void {
    for (msgs, 0..) |m, i| try w.print("{s}{x}:{x}", .{ if (i == 0) "" else ",", m.aad, m.data });
}

fn expList(w: *std.Io.Writer, exps: []const Exp) !void {
    for (exps, 0..) |e, i| try w.print("{s}{x}:{d}", .{ if (i == 0) "" else ",", e.cx, e.len });
}

fn hexList(w: *std.Io.Writer, items: []const []const u8) !void {
    for (items, 0..) |m, i| try w.print("{s}{x}", .{ if (i == 0) "" else ",", m });
}

/// The verdict a positive row expects: every message opens to its plaintext,
/// every export is the sealer's.
fn expected(arena: std.mem.Allocator, pts: []const Msg, outs: []const []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("K|");
    for (pts, 0..) |m, i| try w.print("{s}o{x}", .{ if (i == 0) "" else ",", m.data });
    try w.writeAll("|");
    try hexList(w, outs);
    return out.written();
}

fn splitList(arena: std.mem.Allocator, s: []const u8) ![][]const u8 {
    var l: std.ArrayList([]const u8) = .empty;
    if (s.len == 0) return l.items;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |x| try l.append(arena, x);
    return l.items;
}

/// Like `splitList`, but the empty field is ONE empty item (an export list is
/// never empty, and its one item may be a zero-length output).
fn splitAll(arena: std.mem.Allocator, s: []const u8) ![][]const u8 {
    var l: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |x| try l.append(arena, x);
    return l.items;
}

// ── the Go peer ─────────────────────────────────────────────────────────────

const Go = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    env: std.process.Environ.Map,
    abs: []const u8,
    exe: []const u8 = "",

    fn build(g: *Go) !void {
        g.exe = try g.arena.print("{s}/hpke_oracle.test", .{g.abs});
        try g.env.put("GOTOOLCHAIN", "local");
        try g.env.put("GOPROXY", "off");
        try g.env.put("GOFLAGS", "-mod=readonly");
        std.debug.print("interop-hpke: building the Go side ...\n", .{});
        const res = std.process.run(g.arena, g.io, .{
            .argv = &.{ "go", "test", "-c", "-o", g.exe, "." },
            .environ_map = &g.env,
            .cwd = .{ .path = go_dir },
            .timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } },
        }) catch |e| {
            std.debug.print("interop-hpke: could not run go ({t}) -- the oracle needs it\n", .{e});
            return error.GoBuildFailed;
        };
        if (res.term != .exited or res.term.exited != 0) {
            std.debug.print("interop-hpke: go test -c failed:\n{s}\n", .{res.stderr});
            return error.GoBuildFailed;
        }
    }

    fn run(g: *Go, mode: []const u8, seed: u64) !void {
        try g.env.put("HPKE_ORACLE_MODE", mode);
        try g.env.put("HPKE_ORACLE_DIR", g.abs);
        try g.env.put("HPKE_ORACLE_SEED", try g.arena.print("{d}", .{seed}));
        const res = try std.process.run(g.arena, g.io, .{
            .argv = &.{ g.exe, "-test.run", "^TestOracle$", "-test.count=1" },
            .environ_map = &g.env,
            .cwd = .{ .path = g.abs },
            .stdout_limit = .limited(1 << 24),
            .stderr_limit = .limited(1 << 24),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(300), .clock = .awake } },
        });
        if (res.term != .exited or res.term.exited != 0) {
            std.debug.print("interop-hpke: the Go side failed in {s}:\n{s}\n{s}\n", .{ mode, res.stdout, res.stderr });
            return error.GoFailed;
        }
    }
};

// ── main ────────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    g_io = io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var write = false;
    var seed_arg: ?u64 = null;
    var cases: usize = default_cases;
    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const a = args[ai];
        if (std.mem.eql(u8, a, "--write")) {
            write = true;
        } else if (std.mem.eql(u8, a, "--seed") and ai + 1 < args.len) {
            ai += 1;
            seed_arg = try std.fmt.parseInt(u64, args[ai], 0);
        } else if (std.mem.eql(u8, a, "--cases") and ai + 1 < args.len) {
            ai += 1;
            cases = try std.fmt.parseInt(usize, args[ai], 10);
        } else {
            std.debug.print("usage: zig build interop-hpke [-- [--seed N] [--cases N] [--write]]\n", .{});
            return 2;
        }
    }
    if (cases < suites.len) {
        std.debug.print("interop-hpke: --cases must be at least {d}, one scenario per suite\n", .{suites.len});
        return 2;
    }
    var seed: u64 = undefined;
    if (seed_arg) |s| {
        seed = s;
    } else if (write) {
        seed = frozen_seed;
    } else {
        var b: [8]u8 = undefined;
        io.random(&b);
        seed = std.mem.readInt(u64, &b, .little) & 0xffff_ffff_ffff;
    }
    std.debug.print("interop-hpke: seed={d} scenarios={d} suites={d}\n", .{ seed, cases, suites.len });
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    // 1. The scenarios.
    const plans = try arena.alloc(Plan, cases);
    for (plans, 0..) |*p, i| {
        const si = i % suites.len;
        const m = metas[si];
        const ikm = try arena.alloc(u8, m.nsk);
        rnd.bytes(ikm);
        const info = try arena.alloc(u8, if (rnd.uintLessThan(u8, 10) < 3) 0 else rnd.uintLessThan(usize, 33));
        rnd.bytes(info);
        const nmsg: usize = if (m.has_aead) 1 + rnd.uintLessThan(usize, 5) else 0;
        const msgs = try arena.alloc(Msg, nmsg);
        for (msgs) |*x| {
            const aad = try arena.alloc(u8, if (rnd.boolean()) 0 else 1 + rnd.uintLessThan(usize, 32));
            rnd.bytes(aad);
            const pt_len: usize = if (rnd.uintLessThan(u8, 5) == 0) 0 else if (rnd.uintLessThan(u8, 50) == 0) 2000 else 1 + rnd.uintLessThan(usize, 96);
            const pt = try arena.alloc(u8, pt_len);
            rnd.bytes(pt);
            x.* = .{ .aad = aad, .data = pt };
        }
        const exps = try arena.alloc(Exp, 1 + rnd.uintLessThan(usize, 3));
        for (exps) |*e| {
            const cx = try arena.alloc(u8, if (rnd.uintLessThan(u8, 5) == 0) 0 else rnd.uintLessThan(usize, 25));
            rnd.bytes(cx);
            const lens = [_]usize{ 0, 1, 2, 16, 32, 33, 64, 100 };
            e.* = .{ .cx = cx, .len = if (rnd.uintLessThan(u8, 10) == 0) 1 + rnd.uintLessThan(usize, exp_cap) else lens[rnd.uintLessThan(usize, lens.len)] };
        }
        p.* = .{ .suite = si, .ikm = ikm, .sk = try secretKeyOf(arena, si, ikm), .info = info, .msgs = msgs, .exps = exps };
    }

    // 2. Go seals.
    var plan_tsv: std.Io.Writer.Allocating = .init(arena);
    for (plans, 0..) |p, i| {
        const w = &plan_tsv.writer;
        try w.print("{d}\t{s}\t{x}\t{x}\t", .{ i, metas[p.suite].name, p.sk, p.info });
        try msgList(w, p.msgs);
        try w.writeAll("\t");
        try expList(w, p.exps);
        try w.writeAll("\n");
    }
    try dir.writeFile(io, .{ .sub_path = "plan.tsv", .data = plan_tsv.written() });
    var go: Go = .{ .arena = arena, .io = io, .env = try init.environ_map.clone(arena), .abs = abs };
    go.build() catch return 1;
    go.run("seal", seed) catch return 1;
    const banner = try dir.readFileAlloc(io, "go_banner.txt", arena, .limited(1 << 12));
    const go_sealed = try dir.readFileAlloc(io, "go_sealed.tsv", arena, .limited(1 << 28));

    // 3. Rows: Go's sealing, ours, and the mutations of both.
    var rows: std.ArrayList(Row) = .empty;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, go_sealed, "\n"), '\n');
    for (plans, 0..) |p, i| {
        const line = lines.next() orelse {
            std.debug.print("interop-hpke: the Go side stopped before scenario {d}\n", .{i});
            return 1;
        };
        var cols = std.mem.splitScalar(u8, line, '\t');
        _ = cols.next();
        const g_enc = try unhex(arena, cols.next().?);
        const g_cts = try splitList(arena, cols.next().?);
        const g_exps = try splitAll(arena, cols.next().?);

        // Go as the sender.
        const g_msgs = try arena.alloc(Msg, p.msgs.len);
        for (g_msgs, p.msgs, g_cts) |*gm, pm, ct| gm.* = .{ .aad = pm.aad, .data = try unhex(arena, ct) };
        const g_outs = try arena.alloc([]const u8, g_exps.len);
        for (g_outs, g_exps) |*o, h| o.* = try unhex(arena, h);
        const go_row: Row = .{
            .suite = p.suite,
            .scen = i,
            .origin = .go,
            .neg = null,
            .ikm = p.ikm,
            .sk = p.sk,
            .info = p.info,
            .enc = g_enc,
            .msgs = g_msgs,
            .exps = p.exps,
            .expect = try expected(arena, p.msgs, g_outs),
        };
        try rows.append(arena, go_row);

        // This module as the sender.
        const z = sealOurs(arena, &p) catch |e| {
            std.debug.print("interop-hpke: scenario {d} ({s}): this side could not seal: {t}\n", .{ i, metas[p.suite].name, e });
            return 1;
        };
        const z_msgs = try arena.alloc(Msg, p.msgs.len);
        for (z_msgs, p.msgs, z.cts) |*zm, pm, ct| zm.* = .{ .aad = pm.aad, .data = ct };
        const zig_row: Row = .{
            .suite = p.suite,
            .scen = i,
            .origin = .zig,
            .neg = null,
            .ikm = p.ikm,
            .sk = p.sk,
            .info = p.info,
            .enc = z.enc,
            .msgs = z_msgs,
            .exps = p.exps,
            .expect = try expected(arena, p.msgs, z.exports),
        };
        try rows.append(arena, zig_row);

        for ([_]Row{ go_row, zig_row }) |base| {
            for ([_]Neg{ .enc, .ct, .aad, .trunc }) |k| {
                if (try negative(arena, base, k, rnd.int(u32))) |r| try rows.append(arena, r);
            }
        }
    }

    // 4. Go judges every row.
    var judge_tsv: std.Io.Writer.Allocating = .init(arena);
    for (rows.items, 0..) |r, i| {
        const w = &judge_tsv.writer;
        try w.print("{d}\t{s}\t{x}\t{x}\t{x}\t", .{ i, metas[r.suite].name, r.sk, r.info, r.enc });
        try msgList(w, r.msgs);
        try w.writeAll("\t");
        try expList(w, r.exps);
        try w.writeAll("\n");
    }
    try dir.writeFile(io, .{ .sub_path = "judge.tsv", .data = judge_tsv.written() });
    go.run("judge", seed) catch return 1;
    const go_verdicts = try dir.readFileAlloc(io, "go_verdicts.tsv", arena, .limited(1 << 28));

    // 5. Compare.
    const verdicts = try arena.alloc([]const u8, rows.items.len);
    const suite_rows = try arena.alloc(usize, suites.len);
    const suite_ok = try arena.alloc(usize, suites.len);
    @memset(suite_rows, 0);
    @memset(suite_ok, 0);
    var agree: usize = 0;
    var vlines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, go_verdicts, "\n"), '\n');
    for (rows.items, verdicts, 0..) |r, *gv, i| {
        const line = vlines.next() orelse {
            std.debug.print("interop-hpke: the Go side stopped before row {d}\n", .{i});
            return 1;
        };
        const tab = std.mem.findScalar(u8, line, '\t') orelse return 1;
        gv.* = line[tab + 1 ..];
        const ours = try judgeOurs(arena, &r);
        const same = std.mem.eql(u8, ours, gv.*);
        const as_expected = r.neg != null or std.mem.eql(u8, ours, r.expect);
        suite_rows[r.suite] += 1;
        if (same and as_expected) {
            agree += 1;
            suite_ok[r.suite] += 1;
        } else {
            std.debug.print("DISAGREE row {d} scenario {d} {s} origin={t} neg={s} pos={d}\n  go:     {s}\n  ours:   {s}\n  expect: {s}\n", .{ i, r.scen, metas[r.suite].name, r.origin, if (r.neg) |n| @tagName(n) else "-", r.pos, clip(gv.*), clip(ours), clip(r.expect) });
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    for (metas, suite_rows, suite_ok) |m, n, ok| try w.print("{s:<44} rows={d:<4} agree={d}\n", .{ m.name, n, ok });
    try w.print("peer: {s}\ncases={d} agree={d} scenarios={d} suites={d} seed={d}\n", .{ banner, rows.items.len, agree, cases, suites.len, seed });
    try w.flush();

    if (write and agree == rows.items.len) try writeVectors(io, arena, plans, rows.items, verdicts, banner, seed);
    return if (agree == rows.items.len) 0 else 1;
}

fn clip(s: []const u8) []const u8 {
    return s[0..@min(s.len, 240)];
}

// ── the frozen subset ───────────────────────────────────────────────────────

fn writeVectors(io: std.Io, arena: std.mem.Allocator, plans: []const Plan, rows: []const Row, verdicts: []const []const u8, banner: []const u8, seed: u64) !void {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("// SPDX-License-Identifier: MIT\n// GENERATED by `zig build interop-hpke -- --write` (modules/hpke/tools/interop.zig)\n");
    try w.print("// against {s}, seed {d}. Do not edit: re-take it.\n\n", .{ banner, seed });
    try w.writeAll(
        \\//! Go's own sealing, one scenario per suite, and Go's verdict on each
        \\//! mutation of it, replayed by `go_oracle_test.zig` without Go.
        \\//! Everything is lowercase hex.
        \\
        \\pub const Kind = enum { enc, ct, aad, trunc };
        \\pub const Msg = struct { aad: []const u8, pt: []const u8, ct: []const u8 };
        \\pub const Export = struct { cx: []const u8, len: usize, out: []const u8 };
        \\/// `go` is Go's verdict on the mutated row: `E`, or `K|<messages>|<exports>`.
        \\pub const Neg = struct { kind: Kind, pos: u32, go: []const u8 };
        \\pub const Scenario = struct {
        \\    suite: []const u8,
        \\    ikm: []const u8,
        \\    info: []const u8,
        \\    enc: []const u8,
        \\    msgs: []const Msg,
        \\    exports: []const Export,
        \\    negs: []const Neg,
        \\};
        \\
        \\pub const scenarios = [_]Scenario{
        \\
    );
    for (plans[0..suites.len], 0..) |p, si| {
        var base: ?Row = null;
        for (rows) |r| {
            if (r.scen == si and r.origin == .go and r.neg == null) base = r;
        }
        const b = base.?;
        // Go's export outputs are inside `expect`: K|..|out,out.
        const bar = std.mem.findScalarLast(u8, b.expect, '|').?;
        const outs = try splitAll(arena, b.expect[bar + 1 ..]);
        try w.print("    .{{ .suite = \"{s}\", .ikm = \"{x}\", .info = \"{x}\", .enc = \"{x}\", .msgs = &.{{\n", .{ metas[p.suite].name, p.ikm, p.info, b.enc });
        for (p.msgs, b.msgs) |pm, bm| try w.print("        .{{ .aad = \"{x}\", .pt = \"{x}\", .ct = \"{x}\" }},\n", .{ pm.aad, pm.data, bm.data });
        try w.writeAll("    }, .exports = &.{\n");
        for (p.exps, outs) |e, o| try w.print("        .{{ .cx = \"{x}\", .len = {d}, .out = \"{s}\" }},\n", .{ e.cx, e.len, o });
        try w.writeAll("    }, .negs = &.{\n");
        for (rows, verdicts) |r, v| {
            if (r.scen != si or r.origin != .go or r.neg == null) continue;
            try w.print("        .{{ .kind = .{t}, .pos = {d}, .go = \"{s}\" }},\n", .{ r.neg.?, r.pos, v });
        }
        try w.writeAll("    } },\n");
    }
    try w.writeAll("};\n");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = vectors_path, .data = out.written() });
    try fmtFrozen(arena, io, vectors_path);
    std.debug.print("interop-hpke: wrote {s} ({d} bytes, {d} scenarios)\n", .{ vectors_path, out.written().len, suites.len });
}

/// `zig fmt` the frozen file, so `--write` leaves it as `scripts/test.sh
/// checks-fast`'s fmt check wants it (the writer does not lay out empty
/// lists or long lines the way zig fmt does).
fn fmtFrozen(arena: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ "zig", "fmt", path } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("zig fmt {s} failed:\n{s}\n", .{ path, res.stderr });
        return error.FmtFailed;
    }
}
