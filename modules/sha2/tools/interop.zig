// SPDX-License-Identifier: MIT

//! Live differential oracle: sha2 against OpenSSL 3's libcrypto -- every
//! digest, HMAC and HKDF the module offers that OpenSSL also has, over about
//! 290 000 cases from a fixed seed.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-sha2` runs it and
//! `zig build check-interop` compiles it. Needs `zig` on PATH (it builds
//! `tools/openssl_oracle.c` with `zig cc`, no OpenSSL headers required) and the
//! system OpenSSL 3 shared library, `/usr/lib/x86_64-linux-gnu/libcrypto.so.3`
//! or the path in `LIBCRYPTO_SO`. No network. Run from the repository root.
//! Exit 0 = every case agrees; 1 = a mismatch (the first is printed in full:
//! family, algorithm, lengths, cut points, both digests in hex) or an oracle
//! failure; 2 = libcrypto not found.
//!
//! Families, each a batch of a few thousand records answered by one run of the
//! C side (the EVP names SHA224 SHA256 SHA384 SHA512 SHA512-224 SHA512-256):
//!   digest   random message, lengths weighted to the padding edges (55/56/63/
//!            64/65, 111/112/127/128/129 and their block multiples, 0, up to
//!            20 KiB); ours fed in 0..8 `update()` pieces (empty pieces and
//!            block-edge cuts included) AND one-shot, both against EVP_Digest;
//!   peek     `peek()` after a prefix against the digest of that prefix, then
//!            the stream continued and finalised against the whole message
//!            (peek must not disturb the state);
//!   trunc    Sha256T192 / Sha512T224 / Sha512T256 against the leftmost bytes
//!            of OpenSSL's SHA-256 / SHA-512 (plain truncation, the SHA-512/t
//!            IVs are not involved);
//!   hmac     HMAC-SHA-224/256/384/512 and HMAC-SHA-512/256 (std `Hmac` over
//!            our hashes), keys 0..300 bytes weighted at 0, block-1, block,
//!            block+1, 2*block, against OpenSSL's one-shot `HMAC()`;
//!   hkdf     HKDF-SHA-256/384 extract+expand (std `Hkdf`) against OpenSSL's
//!            EVP_PKEY HKDF in extract-and-expand mode, outputs up to
//!            255 * hash length. IKM is never empty: OpenSSL's HKDF refuses a
//!            zero-length key, so that corner has no oracle here.

const std = @import("std");
const sha2 = @import("sha2");
const Hmac = std.crypto.auth.hmac.Hmac;
const Hkdf = std.crypto.kdf.hkdf.Hkdf;

const work_dir = ".zig-cache/interop-sha2";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const c_source = "modules/sha2/tools/openssl_oracle.c";
const max_len = 20480;
const batch_max = 8000;

// Records per algorithm in each family.
const n_digest = 28_000;
const n_peek = 3_000; // two oracle records each
const n_trunc = 6_000; // per truncated variant
const n_hmac = 14_000;
const n_hkdf = 5_000;

/// Index = the oracle's algorithm number (C `names`).
const Alg = enum(u8) { sha224, sha256, sha384, sha512, sha512_224, sha512_256 };
const alg_names = [_][]const u8{ "SHA224", "SHA256", "SHA384", "SHA512", "SHA512-224", "SHA512-256" };

fn HashOf(comptime a: Alg) type {
    return switch (a) {
        .sha224 => sha2.Sha224,
        .sha256 => sha2.Sha256,
        .sha384 => sha2.Sha384,
        .sha512 => sha2.Sha512,
        .sha512_224 => sha2.Sha512_224,
        .sha512_256 => sha2.Sha512_256,
    };
}

const Kind = enum { digest, peek_prefix, peek_final, trunc, hmac, hkdf };
const family_names = [_][]const u8{ "digest", "peek (prefix)", "peek (continued)", "trunc", "hmac", "hkdf" };

const Cuts = struct {
    n: u8 = 0,
    v: [8]u32 = @splat(0),
    fn slice(c: *const Cuts) []const u32 {
        return c.v[0..c.n];
    }
};

/// One comparison: what the oracle was asked, and what we answered.
const Rec = struct {
    kind: Kind,
    alg: Alg,
    /// Truncated variant (trunc family): its name and digest length.
    tname: []const u8 = "",
    len: u32 = 0, // message / prefix / IKM length
    keylen: u32 = 0, // HMAC key / HKDF salt length
    infolen: u32 = 0,
    cuts: Cuts = .{},
    olen: u16, // bytes the oracle returns
    cmp: u16, // bytes compared (trunc: leftmost)
    ours: [64]u8 = undefined,
    /// HKDF output (up to 255 * 48 bytes) lives in the batch arena instead.
    big: []u8 = &.{},
    ours2: [64]u8 = undefined, // one-shot result (digest family)
    has2: bool = false,
};

const Counts = struct { n: [family_names.len]usize = @splat(0) };

fn blockOf(a: Alg) usize {
    return switch (a) {
        .sha224, .sha256 => 64,
        else => 128,
    };
}

fn genLen(r: std.Random, bs: usize) usize {
    const edge = [_]usize{ 0, 1, bs - 1, bs - 9, bs - 8, bs - 17, bs - 16 };
    const roll = r.uintLessThan(u8, 100);
    const n: usize = if (roll < 35) blk: {
        const k = r.uintAtMost(usize, if (r.boolean()) 3 else 160);
        break :blk k * bs + edge[r.uintLessThan(usize, edge.len)];
    } else if (roll < 50) r.uintAtMost(usize, 300) else if (roll < 90) r.uintAtMost(usize, 1023) else r.uintAtMost(usize, max_len);
    return @min(n, max_len);
}

fn genCuts(r: std.Random, bs: usize, len: usize) Cuts {
    var c: Cuts = .{ .n = r.uintAtMost(u8, 8) };
    for (c.v[0..c.n]) |*x| {
        if (r.boolean()) {
            x.* = @intCast(r.uintAtMost(usize, len));
        } else {
            const base = r.uintAtMost(usize, len / bs) * bs;
            const at = switch (r.uintLessThan(u8, 3)) {
                0 => base,
                1 => base -| 1,
                else => base + 1,
            };
            x.* = @intCast(@min(at, len));
        }
    }
    std.mem.sort(u32, c.v[0..c.n], {}, std.sort.asc(u32));
    return c;
}

/// Feed `msg` to `d` in pieces ending at each cut (those past the end are
/// clamped), then the rest. Empty pieces are intentional.
fn feed(d: anytype, msg: []const u8, cuts: []const u32) void {
    var p: usize = 0;
    for (cuts) |c| {
        const e = @min(c, msg.len);
        d.update(msg[p..@max(p, e)]);
        p = @max(p, e);
    }
    d.update(msg[p..]);
}

fn oursDigest(alg: Alg, msg: []const u8, cuts: []const u32, out: []u8, out2: []u8) void {
    switch (alg) {
        inline else => |a| {
            const H = HashOf(a);
            var d = H.init(.{});
            feed(&d, msg, cuts);
            var o: [H.digest_length]u8 = undefined;
            d.final(&o);
            @memcpy(out[0..o.len], &o);
            H.hash(msg, out2[0..H.digest_length], .{});
        },
    }
}

/// Our peek of the prefix, then the stream continued to the end.
fn oursPeek(alg: Alg, msg: []const u8, at: usize, cuts: []const u32, peeked: []u8, fin: []u8) void {
    switch (alg) {
        inline else => |a| {
            const H = HashOf(a);
            var d = H.init(.{});
            feed(&d, msg[0..at], cuts);
            const p = d.peek();
            @memcpy(peeked[0..p.len], &p);
            d.update(msg[at..]);
            var o: [H.digest_length]u8 = undefined;
            d.final(&o);
            @memcpy(fin[0..o.len], &o);
        },
    }
}

fn oursTrunc(which: u8, msg: []const u8, cuts: []const u32, out: []u8) void {
    switch (which) {
        inline 0, 1, 2 => |w| {
            const H = switch (w) {
                0 => sha2.Sha256T192,
                1 => sha2.Sha512T224,
                else => sha2.Sha512T256,
            };
            var d = H.init(.{});
            feed(&d, msg, cuts);
            var o: [H.digest_length]u8 = undefined;
            d.final(&o);
            @memcpy(out[0..o.len], &o);
        },
        else => unreachable,
    }
}

fn oursHmac(alg: Alg, key: []const u8, msg: []const u8, out: []u8) void {
    switch (alg) {
        inline .sha224, .sha256, .sha384, .sha512, .sha512_256 => |a| {
            const M = Hmac(HashOf(a));
            var o: [M.mac_length]u8 = undefined;
            M.create(&o, msg, key);
            @memcpy(out[0..o.len], &o);
        },
        else => unreachable,
    }
}

fn oursHkdf(alg: Alg, salt: []const u8, ikm: []const u8, info: []const u8, out: []u8) void {
    switch (alg) {
        inline .sha256, .sha384 => |a| {
            const K = Hkdf(Hmac(HashOf(a)));
            K.expand(out, info, K.extract(salt, ikm));
        },
        else => unreachable,
    }
}

fn putU32(w: *std.Io.Writer, v: usize) !void {
    try w.writeInt(u32, @intCast(v), .little);
}

fn hex(arena: std.mem.Allocator, b: []const u8) []const u8 {
    if (b.len == 0) return "-";
    return arena.print("{x}", .{b}) catch @panic("OOM");
}

fn cutsText(arena: std.mem.Allocator, c: *const Cuts) []const u8 {
    return arena.print("{any}", .{c.slice()}) catch @panic("OOM");
}

const Ctx = struct {
    io: std.Io,
    cwd: std.Io.Dir,
    abs: []const u8,
    exe: []const u8,
    gpa: std.mem.Allocator,
    r: std.Random,
    msg: []u8,
    counts: Counts = .{},
    mismatches: usize = 0,
    reported: bool = false,
};

/// Generate `n` cases of one family/algorithm (`variant` picks the truncated
/// type), ask the oracle in batches, compare.
fn runFamily(c: *Ctx, kind: Kind, alg: Alg, variant: u8, n: usize) !void {
    var done: usize = 0;
    while (done < n) {
        var arena_state = std.heap.ArenaAllocator.init(c.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const take = @min(batch_max, n - done);
        done += take;

        var recs: std.ArrayList(Rec) = .empty;
        var cases: std.Io.Writer.Allocating = .init(arena);
        const w = &cases.writer;
        const bs = blockOf(alg);
        const r = c.r;

        for (0..take) |_| {
            switch (kind) {
                .digest, .trunc => {
                    const len = genLen(r, bs);
                    const msg = c.msg[0..len];
                    r.bytes(msg);
                    var rec: Rec = .{ .kind = kind, .alg = alg, .len = @intCast(len), .cuts = genCuts(r, bs, len), .olen = 0, .cmp = 0 };
                    if (kind == .digest) {
                        oursDigest(alg, msg, rec.cuts.slice(), &rec.ours, &rec.ours2);
                        rec.has2 = true;
                        rec.olen = switch (alg) {
                            .sha224, .sha512_224 => 28,
                            .sha256, .sha512_256 => 32,
                            .sha384 => 48,
                            .sha512 => 64,
                        };
                        rec.cmp = rec.olen;
                    } else {
                        oursTrunc(variant, msg, rec.cuts.slice(), &rec.ours);
                        rec.tname = (&[_][]const u8{ "Sha256T192", "Sha512T224", "Sha512T256" })[variant];
                        rec.olen = if (variant == 0) 32 else 64;
                        rec.cmp = (&[_]u16{ 24, 28, 32 })[variant];
                    }
                    try w.writeAll(&.{ 0, @backingInt(alg) });
                    try putU32(w, len);
                    try w.writeAll(msg);
                    try recs.append(arena, rec);
                },
                .peek_prefix, .peek_final => {
                    const len = genLen(r, bs);
                    const msg = c.msg[0..len];
                    r.bytes(msg);
                    const at = if (r.boolean()) r.uintAtMost(usize, len) else @min(len, r.uintAtMost(usize, len / bs) * bs + r.uintAtMost(usize, 2));
                    const cuts = genCuts(r, bs, at);
                    var a: Rec = .{ .kind = .peek_prefix, .alg = alg, .len = @intCast(at), .cuts = cuts, .olen = 0, .cmp = 0 };
                    var b: Rec = .{ .kind = .peek_final, .alg = alg, .len = @intCast(len), .cuts = cuts, .olen = 0, .cmp = 0 };
                    oursPeek(alg, msg, at, cuts.slice(), &a.ours, &b.ours);
                    a.olen = switch (alg) {
                        .sha224, .sha512_224 => 28,
                        .sha256, .sha512_256 => 32,
                        .sha384 => 48,
                        .sha512 => 64,
                    };
                    a.cmp = a.olen;
                    b.olen = a.olen;
                    b.cmp = a.olen;
                    b.infolen = @intCast(at); // where the peek happened
                    for ([_]struct { rec: Rec, m: []const u8 }{ .{ .rec = a, .m = msg[0..at] }, .{ .rec = b, .m = msg } }) |x| {
                        try w.writeAll(&.{ 0, @backingInt(alg) });
                        try putU32(w, x.m.len);
                        try w.writeAll(x.m);
                        try recs.append(arena, x.rec);
                    }
                },
                .hmac => {
                    const kl: usize = switch (r.uintLessThan(u8, 10)) {
                        0 => 0,
                        1 => bs - 1,
                        2 => bs,
                        3 => bs + 1,
                        4 => 2 * bs,
                        else => r.uintAtMost(usize, 300),
                    };
                    const ml = @min(genLen(r, bs), r.uintAtMost(usize, 4096));
                    const key = try arena.alloc(u8, kl);
                    r.bytes(key);
                    const msg = c.msg[0..ml];
                    r.bytes(msg);
                    var rec: Rec = .{ .kind = .hmac, .alg = alg, .len = @intCast(ml), .keylen = @intCast(kl), .olen = 0, .cmp = 0 };
                    oursHmac(alg, key, msg, &rec.ours);
                    rec.olen = if (alg == .sha224) 28 else if (alg == .sha256 or alg == .sha512_256) 32 else if (alg == .sha384) 48 else 64;
                    rec.cmp = rec.olen;
                    try w.writeAll(&.{ 1, @backingInt(alg) });
                    try putU32(w, kl);
                    try putU32(w, ml);
                    try w.writeAll(key);
                    try w.writeAll(msg);
                    try recs.append(arena, rec);
                },
                .hkdf => {
                    const dl: usize = if (alg == .sha256) 32 else 48;
                    const sl: usize = switch (r.uintLessThan(u8, 6)) {
                        0 => 0,
                        1 => bs,
                        2 => bs + 1,
                        else => r.uintAtMost(usize, 2 * bs),
                    };
                    const il = 1 + r.uintAtMost(usize, 100);
                    const nl = if (r.boolean()) r.uintAtMost(usize, 40) else r.uintAtMost(usize, 300);
                    const ol: usize = switch (r.uintLessThan(u8, 8)) {
                        0 => dl,
                        1 => dl - 1,
                        2 => dl + 1,
                        3 => 255 * dl,
                        4 => 1 + r.uintAtMost(usize, 255 * dl - 1),
                        else => 1 + r.uintAtMost(usize, 100),
                    };
                    const salt = try arena.alloc(u8, sl);
                    const ikm = try arena.alloc(u8, il);
                    const info = try arena.alloc(u8, nl);
                    r.bytes(salt);
                    r.bytes(ikm);
                    r.bytes(info);
                    var rec: Rec = .{ .kind = .hkdf, .alg = alg, .len = @intCast(il), .keylen = @intCast(sl), .infolen = @intCast(nl), .olen = @intCast(ol), .cmp = @intCast(ol) };
                    rec.big = try arena.alloc(u8, ol);
                    oursHkdf(alg, salt, ikm, info, rec.big);
                    try w.writeAll(&.{ 2, @backingInt(alg) });
                    try putU32(w, sl);
                    try putU32(w, il);
                    try putU32(w, nl);
                    try putU32(w, ol);
                    try w.writeAll(salt);
                    try w.writeAll(ikm);
                    try w.writeAll(info);
                    try recs.append(arena, rec);
                },
            }
        }

        const cases_path = try arena.print("{s}/cases.bin", .{c.abs});
        const results_path = try arena.print("{s}/results.bin", .{c.abs});
        try c.cwd.writeFile(c.io, .{ .sub_path = cases_path, .data = cases.written() });
        const res = try std.process.run(arena, c.io, .{ .argv = &.{ c.exe, cases_path, results_path } });
        if (res.term != .exited or res.term.exited != 0) {
            std.debug.print("interop-sha2: OpenSSL side failed:\n{s}\n", .{res.stderr});
            return error.OracleFailed;
        }
        const theirs = try c.cwd.readFileAlloc(c.io, results_path, arena, .limited(1 << 30));

        var off: usize = 0;
        for (recs.items) |*rec| {
            if (off + rec.olen > theirs.len) return error.ShortResults;
            const t = theirs[off..][0..rec.olen];
            off += rec.olen;
            c.counts.n[@backingInt(rec.kind)] += 1;
            const mine = if (rec.big.len > 0) rec.big else rec.ours[0..rec.cmp];
            const bad1 = !std.mem.eql(u8, t[0..rec.cmp], mine);
            const bad2 = rec.has2 and !std.mem.eql(u8, t[0..rec.cmp], rec.ours2[0..rec.cmp]);
            if (!bad1 and !bad2) continue;
            c.mismatches += 1;
            if (c.reported) continue;
            c.reported = true;
            std.debug.print(
                "MISMATCH family={s} alg={s}{s}{s} len={d} keylen/saltlen={d} infolen/peek-at={d} cuts={s}\n  openssl: {s}\n  sha2:    {s}{s}\n",
                .{
                    family_names[@backingInt(rec.kind)],
                    alg_names[@backingInt(rec.alg)],
                    if (rec.tname.len > 0) " vs " else "",
                    rec.tname,
                    rec.len,
                    rec.keylen,
                    rec.infolen,
                    cutsText(arena, &rec.cuts),
                    hex(arena, t[0..rec.cmp]),
                    hex(arena, mine),
                    if (bad2) arena.print("\n  sha2 one-shot: {s}", .{hex(arena, rec.ours2[0..rec.cmp])}) catch "" else "",
                },
            );
        }
        if (off != theirs.len) return error.TrailingResults;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    const so = init.environ_map.get("LIBCRYPTO_SO") orelse default_so;
    cwd.access(io, so, .{}) catch {
        std.debug.print("interop-sha2: libcrypto not found at {s} (set LIBCRYPTO_SO to the OpenSSL 3 libcrypto.so.3)\n", .{so});
        return 2;
    };
    const exe = try arena.print("{s}/openssl_oracle", .{abs});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O2", c_source, so, "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("interop-sha2: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const ver_run = try std.process.run(arena, io, .{ .argv = &.{ exe, "--version" } });
    const version = std.mem.trimEnd(u8, ver_run.stdout, "\n");

    var prng = std.Random.DefaultPrng.init(0x7368_6132_6f73_736c);
    var ctx: Ctx = .{
        .io = io,
        .cwd = cwd,
        .abs = abs,
        .exe = exe,
        .gpa = init.gpa,
        .r = prng.random(),
        .msg = try arena.alloc(u8, max_len),
    };

    for (std.enums.values(Alg)) |a| try runFamily(&ctx, .digest, a, 0, n_digest);
    for (std.enums.values(Alg)) |a| try runFamily(&ctx, .peek_prefix, a, 0, n_peek);
    for (0..3) |v| try runFamily(&ctx, .trunc, if (v == 0) .sha256 else .sha512, @intCast(v), n_trunc);
    for ([_]Alg{ .sha224, .sha256, .sha384, .sha512, .sha512_256 }) |a| try runFamily(&ctx, .hmac, a, 0, n_hmac);
    for ([_]Alg{ .sha256, .sha384 }) |a| try runFamily(&ctx, .hkdf, a, 0, n_hkdf);

    var total: usize = 0;
    for (family_names, ctx.counts.n) |name, n| {
        std.debug.print("  {s}: {d}\n", .{ name, n });
        total += n;
    }
    if (ctx.mismatches != 0) {
        std.debug.print("interop-sha2: {d} of {d} cases DISAGREE with {s}\n", .{ ctx.mismatches, total, version });
        return 1;
    }
    std.debug.print("interop-sha2: {d} cases agree with {s}\n", .{ total, version });
    return 0;
}
