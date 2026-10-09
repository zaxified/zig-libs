// SPDX-License-Identifier: MIT

//! Shared plumbing for x509's deterministic fuzz driver (added 2026-10-09),
//! and the chain-verification harness (`x509-chain-verify`).
//!
//! The parser harness BODIES stay in the files whose private items they
//! exercise (`safe.zig`, `extensions.zig`, `chain.zig`); each is generic over
//! its source of choices, `fn(comptime S, *S, gpa)`, and `testing.fuzz` hands
//! it a `std.testing.Smith` directly (every harness begins with one `slice`,
//! so corpus seeds replay as before). This file holds what they share with the
//! driver: the reach counters with the N-seed in-suite check, and the input
//! draw (under the driver's `Rng`, half of the inputs are a corpus certificate
//! with 0-3 octets damaged and maybe truncated).
//!
//! Driver: `X509_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `x509-spki`, `x509-validate`, `x509-extensions`,
//! `x509-pss`, `x509-chain-verify`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

const chain_mod = @import("chain.zig");
const Certificate = std.crypto.Certificate;
const fx = @import("fixtures_test.zig");

const ChainMark = Marker(enum { rsa, ec256, ec384, ed25519, genuine_accepted, damaged_leaf_refused, damaged_intermediate_refused, outside_validity_refused });

const now_valid: i64 = 1798761600; // 2027-01-01T00:00:00Z, inside every fixture's validity
const now_before: i64 = 1262304000; // 2010-01-01T00:00:00Z
const now_after: i64 = 2208988800; // 2040-01-01T00:00:00Z

test "fuzz driver: X509_FUZZ (chain verification)" {
    try fuzz_driver.run(chainHarness, .{ .prefix = "X509_FUZZ", .name = "x509-chain-verify", .scale = 4 });
}

test "fuzz harness: chain verification, 120 seeds, reaches every outcome" {
    try ChainMark.reach(chainHarness, "x509-chain-verify", 120);
}

/// A chain this repo's OpenSSL oracle signed is ACCEPTED by `verifyChain`; the
/// same chain with one octet of the leaf (or of the intermediate) changed, or
/// checked at a time outside its validity, is REFUSED.
fn chainHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const Set = struct { leaf: []const u8, inter: []const u8, root: []const u8 };
    const set: Set = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => blk: {
            ChainMark.mark(.rsa);
            break :blk .{ .leaf = &fx.leaf_rsa, .inter = &fx.inter_rsa, .root = &fx.root_rsa };
        },
        1 => blk: {
            ChainMark.mark(.ec256);
            break :blk .{ .leaf = &fx.leaf_ec256, .inter = &fx.inter_ec256, .root = &fx.root_ec256 };
        },
        2 => blk: {
            ChainMark.mark(.ec384);
            break :blk .{ .leaf = &fx.leaf_ec384, .inter = &fx.inter_ec384, .root = &fx.root_ec384 };
        },
        else => blk: {
            ChainMark.mark(.ed25519);
            break :blk .{ .leaf = &fx.leaf_ed, .inter = &fx.inter_ed, .root = &fx.root_ed };
        },
    };
    const anchors = [_]chain_mod.CertDer{set.root};

    const good = [_]chain_mod.CertDer{ set.leaf, set.inter };
    _ = chain_mod.verifyChain(gpa, &good, &anchors, .{ .now_sec = now_valid }) catch return error.GenuineChainRefused;
    ChainMark.mark(.genuine_accepted);

    var buf: [1024]u8 = undefined;
    std.debug.assert(set.leaf.len <= buf.len and set.inter.len <= buf.len);

    // One octet of the leaf changed.
    @memcpy(buf[0..set.leaf.len], set.leaf);
    const leaf_at = damageAt(S, src, set.leaf);
    const leaf_xor = src.valueRangeAtMost(u8, 1, 255);
    buf[leaf_at] ^= leaf_xor;
    const bad_leaf = [_]chain_mod.CertDer{ buf[0..set.leaf.len], set.inter };
    if (chain_mod.verifyChain(gpa, &bad_leaf, &anchors, .{ .now_sec = now_valid })) |_| {
        std.debug.print("damaged leaf accepted: leaf len {d}, octet {d} ^= 0x{x}\n", .{ set.leaf.len, leaf_at, leaf_xor });
        return error.DamagedLeafAccepted;
    } else |_| {}
    ChainMark.mark(.damaged_leaf_refused);

    // ...and of the intermediate.
    @memcpy(buf[0..set.inter.len], set.inter);
    const inter_at = damageAt(S, src, set.inter);
    const inter_xor = src.valueRangeAtMost(u8, 1, 255);
    buf[inter_at] ^= inter_xor;
    const bad_inter = [_]chain_mod.CertDer{ set.leaf, buf[0..set.inter.len] };
    if (chain_mod.verifyChain(gpa, &bad_inter, &anchors, .{ .now_sec = now_valid })) |_| {
        std.debug.print("damaged intermediate accepted: len {d}, octet {d} ^= 0x{x}; around: {x}\n", .{ set.inter.len, inter_at, inter_xor, set.inter[inter_at -| 12..@min(set.inter.len, inter_at + 12)] });
        return error.DamagedIntermediateAccepted;
    } else |_| {}
    ChainMark.mark(.damaged_intermediate_refused);

    // Outside the validity window, either side.
    const t = if (src.value(bool)) now_before else now_after;
    if (chain_mod.verifyChain(gpa, &good, &anchors, .{ .now_sec = t })) |_| return error.ExpiredChainAccepted else |_| {}
    ChainMark.mark(.outside_validity_refused);
}

// ── regressions for what the chain driver found (2026-10-10) ───────────────

/// `verifyChain` over `leaf` + `inter` up to `root`, `leaf`/`inter` damaged by
/// `edit` first. Must be refused (any error), never accepted or a panic.
fn expectChainRefused(leaf: []const u8, inter: []const u8, root: []const u8, which: enum { leaf, inter }, edit: *const fn ([]u8) void) !void {
    var buf: [1024]u8 = undefined;
    const target = if (which == .leaf) leaf else inter;
    @memcpy(buf[0..target.len], target);
    edit(buf[0..target.len]);
    const chain = if (which == .leaf)
        [_]chain_mod.CertDer{ buf[0..target.len], inter }
    else
        [_]chain_mod.CertDer{ leaf, buf[0..target.len] };
    const anchors = [_]chain_mod.CertDer{root};
    if (chain_mod.verifyChain(std.testing.allocator, &chain, &anchors, .{ .now_sec = now_valid })) |_| {
        return error.DamagedChainAccepted;
    } else |_| {}
}

/// The outer Certificate SEQUENCE's element, and the elements after the TBS.
const Outer = struct { cert: Certificate.der.Element, sig_alg: Certificate.der.Element, sig_alg_at: u32, sig_at: u32 };
fn outerOf(c: []const u8) Outer {
    const ext = @import("extensions.zig");
    const cert = ext.parseElement(c, 0) catch unreachable;
    const tbs = ext.parseElement(c, cert.slice.start) catch unreachable;
    const sig_alg = ext.parseElement(c, tbs.slice.end) catch unreachable;
    return .{ .cert = cert, .sig_alg = sig_alg, .sig_alg_at = tbs.slice.end, .sig_at = sig_alg.slice.end };
}

test "verifyChain REJECT: unsigned outer encoding changed (tag, length, signatureAlgorithm, BIT STRING tag)" {
    const sets = [_][3][]const u8{
        .{ &fx.leaf_rsa, &fx.inter_rsa, &fx.root_rsa },
        .{ &fx.leaf_ec256, &fx.inter_ec256, &fx.root_ec256 },
        .{ &fx.leaf_ed, &fx.inter_ed, &fx.root_ed },
    };
    const edits = [_]*const fn ([]u8) void{
        // Outer SEQUENCE tag 30 -> 0e (seed 87).
        struct {
            fn f(c: []u8) void {
                c[0] ^= 0x3e;
            }
        }.f,
        // Signature BIT STRING tag 03 -> c3 (seed 10).
        struct {
            fn f(c: []u8) void {
                c[outerOf(c).sig_at] ^= 0xc0;
            }
        }.f,
        // Outer length shortened (seed 377: last length octet 68 -> 1a).
        struct {
            fn f(c: []u8) void {
                c[outerOf(c).cert.slice.start - 1] ^= 0x72;
            }
        }.f,
        // Last octet of signatureAlgorithm (RSA: its NULL's length; EC/Ed:
        // the OID) changed: no longer the signed tbsCertificate.signature.
        struct {
            fn f(c: []u8) void {
                c[outerOf(c).sig_alg.slice.end - 1] ^= 0x01;
            }
        }.f,
    };
    for (sets) |set| for (edits) |edit| {
        try expectChainRefused(set[0], set[1], set[2], .leaf, edit);
        try expectChainRefused(set[0], set[1], set[2], .inter, edit);
    };
}

test "verifyChain REJECT: an RSA intermediate whose key interior lies is refused, not a panic in std" {
    // std's `rsa.PublicKey.parseDer` reads the RSAPublicKey inside the
    // subjectPublicKey BIT STRING unchecked (fuzz driver: index 278 of 270).
    const edit = struct {
        fn f(c: []u8) void {
            const spki = @import("safe.zig").spkiOf(c) catch unreachable;
            const at = @intFromPtr(spki.key_bits.ptr) - @intFromPtr(c.ptr);
            // modulus INTEGER: its first length octet becomes a 4-octet long
            // form, the next four octets a huge length.
            const mod_len_at = at + (if (c[at + 1] & 0x80 != 0) 2 + @as(usize, c[at + 1] & 0x7f) else 2) + 1;
            c[mod_len_at] = 0x84;
            @memset(c[mod_len_at + 1 ..][0..4], 0x7f);
        }
    }.f;
    try expectChainRefused(&fx.leaf_rsa, &fx.inter_rsa, &fx.root_rsa, .inter, edit);
}

/// Any octet of the certificate. (Until 2026-10-10 the range stopped at the
/// signed TBSCertificate plus the signature's tail: `chain.parseShape` did not
/// check the outer SEQUENCE or the signature BIT STRING tag, and a damaged one
/// still verified. Fixed by `expectTag`.)
fn damageAt(comptime S: type, src: *S, cert: []const u8) usize {
    return src.index(cert.len);
}
