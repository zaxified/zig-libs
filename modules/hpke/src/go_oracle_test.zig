// SPDX-License-Identifier: MIT

//! Replays `go_oracle_vectors.zig` -- what `zig build interop-hpke -- --write`
//! froze from Go 1.26 `crypto/hpke` -- without Go (CONVENTIONS.md §9: the
//! program takes the anchor, the module's tests replay its transcript). One
//! scenario per suite of the 9 KEM x 5 KDF x 4 AEAD matrix the program runs
//! (`tools/interop.zig` explains the pairing):
//!
//! - Go is the sender: its encapsulation, ciphertexts (seq 0..n, with and
//!   without aad, empty plaintexts included) and exports must open and match
//!   here, byte for byte;
//! - the same bytes with one bit of enc / ciphertext / aad flipped, or the
//!   ciphertext cut by a byte: this module's verdict must still be Go's
//!   recorded one -- refused, or for a flipped enc the same exports out of
//!   the same (implicitly rejected or garbage) shared secret.

const std = @import("std");
const testing = std.testing;
const hpke = @import("root.zig");
const aesgcm = @import("aesgcm");
const v = @import("go_oracle_vectors.zig");

const Msg = struct { aad: []const u8, data: []const u8 };
const Exp = struct { cx: []const u8, len: usize };

const Row = struct {
    ikm: []const u8,
    info: []const u8,
    enc: []const u8,
    msgs: []const Msg,
    exps: []const Exp,
};

fn Suite(comptime Kem: type, comptime Kdf: type, comptime Aead: type, comptime aead_id: u16, comptime label: []const u8) type {
    const HCtx = hpke.Context(Aead, Kdf);
    const suite_id = hpke.suite.suiteId(Kem.kem_id, Kdf.kdf_id, aead_id);
    return struct {
        const name = label;
        const has_aead = Aead != hpke.ExportOnly;

        /// The verdict Go prints for a recipient: `E`, or `K|<messages>|<exports>`.
        fn judge(arena: std.mem.Allocator, r: Row) ![]const u8 {
            var kp: Kem.KeyPair = undefined;
            Kem.deriveKeyPair(&kp, r.ikm);
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

/// Same pairing as the program: the AEAD rotates, so every KEM and every KDF
/// meets every AEAD.
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

fn judgeByName(arena: std.mem.Allocator, suite: []const u8, r: Row) ![]const u8 {
    inline for (suites) |S| {
        if (std.mem.eql(u8, suite, S.name)) return S.judge(arena, r);
    }
    return error.UnknownSuite;
}

fn unhex(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn flipped(arena: std.mem.Allocator, b: []const u8, pos: u32) ![]u8 {
    const out = try arena.dupe(u8, b);
    const bit = pos % (b.len * 8);
    out[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
    return out;
}

/// Go's sealed bytes as a positive row, and the verdict a recipient must give.
fn positive(arena: std.mem.Allocator, s: v.Scenario) !struct { row: Row, expect: []const u8 } {
    const msgs = try arena.alloc(Msg, s.msgs.len);
    const exps = try arena.alloc(Exp, s.exports.len);
    var want: std.Io.Writer.Allocating = .init(arena);
    try want.writer.writeAll("K|");
    for (s.msgs, msgs, 0..) |m, *o, i| {
        o.* = .{ .aad = try unhex(arena, m.aad), .data = try unhex(arena, m.ct) };
        try want.writer.print("{s}o{s}", .{ if (i == 0) "" else ",", m.pt });
    }
    try want.writer.writeAll("|");
    for (s.exports, exps, 0..) |e, *o, i| {
        o.* = .{ .cx = try unhex(arena, e.cx), .len = e.len };
        try want.writer.print("{s}{s}", .{ if (i == 0) "" else ",", e.out });
    }
    return .{
        .row = .{ .ikm = try unhex(arena, s.ikm), .info = try unhex(arena, s.info), .enc = try unhex(arena, s.enc), .msgs = msgs, .exps = exps },
        .expect = want.written(),
    };
}

/// The mutated row `n` makes of `base` (the same construction as the program's
/// `negative`): message 0 only; only a flipped enc keeps the exports.
fn mutated(arena: std.mem.Allocator, base: Row, n: v.Neg) !Row {
    var r = base;
    r.msgs = base.msgs[0..@min(1, base.msgs.len)];
    if (n.kind != .enc) r.exps = &.{};
    switch (n.kind) {
        .enc => r.enc = try flipped(arena, base.enc, n.pos),
        .ct, .aad, .trunc => {
            const m = base.msgs[0];
            const msg = try arena.alloc(Msg, 1);
            msg[0] = switch (n.kind) {
                .ct => .{ .aad = m.aad, .data = try flipped(arena, m.data, n.pos) },
                .aad => .{ .aad = if (m.aad.len == 0) try arena.dupe(u8, &.{@as(u8, @truncate(n.pos))}) else try flipped(arena, m.aad, n.pos), .data = m.data },
                .trunc => .{ .aad = m.aad, .data = m.data[0 .. m.data.len - 1] },
                .enc => unreachable,
            };
            r.msgs = msg;
        },
    }
    return r;
}

test "go oracle: the matrix is every KEM x KDF x AEAD Go offers, one frozen scenario per suite" {
    try testing.expectEqual(suites.len, v.scenarios.len);
    inline for (suites, 0..) |S, i| try testing.expectEqualStrings(S.name, v.scenarios[i].suite);
    // Every KEM meets every KDF once; the rotation gives each AEAD to every KEM.
    inline for (kems) |k| {
        inline for (kdfs) |d| {
            var n: usize = 0;
            for (v.scenarios) |s| {
                if (std.mem.startsWith(u8, s.suite, k[1] ++ "/" ++ d[1] ++ "/")) n += 1;
            }
            try testing.expectEqual(1, n);
        }
        inline for (aeads) |a| {
            var n: usize = 0;
            for (v.scenarios) |s| {
                if (std.mem.startsWith(u8, s.suite, k[1] ++ "/") and std.mem.endsWith(u8, s.suite, "/" ++ a[1])) n += 1;
            }
            try testing.expect(n >= 1);
        }
    }
}

test "go oracle: what Go sealed opens here and its exports are ours, in every suite" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var messages: usize = 0;
    for (v.scenarios) |s| {
        const p = try positive(arena, s);
        const got = try judgeByName(arena, s.suite, p.row);
        testing.expectEqualStrings(p.expect, got) catch |e| {
            std.debug.print("suite {s}\n", .{s.suite});
            return e;
        };
        messages += s.msgs.len;
    }
    try testing.expect(messages >= 60); // seq > 0 is covered: scenarios carry 1..5 messages
}

test "go oracle: a flipped enc / ciphertext / aad bit or a short ciphertext gets Go's recorded verdict" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var per_kind: [4]usize = @splat(0);
    var refused: usize = 0;
    for (v.scenarios) |s| {
        const p = try positive(arena, s);
        for (s.negs) |n| {
            const got = try judgeByName(arena, s.suite, try mutated(arena, p.row, n));
            testing.expectEqualStrings(n.go, got) catch |e| {
                std.debug.print("suite {s} kind {t} pos {d}\n", .{ s.suite, n.kind, n.pos });
                return e;
            };
            per_kind[@backingInt(n.kind)] += 1;
            if (std.mem.eql(u8, n.go, "E") or std.mem.indexOf(u8, n.go, "|x") != null) refused += 1;
        }
    }
    // The ciphertext/aad/trunc kinds exist for every suite that has an AEAD;
    // the enc kind for all 45.
    try testing.expectEqual(v.scenarios.len, per_kind[@backingInt(v.Kind.enc)]);
    for (per_kind[1..]) |n| try testing.expect(n >= 30);
    // And Go refused a good share of them (the flips are not no-ops).
    try testing.expect(refused >= 100);
}
