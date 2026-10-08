// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the client-certificate signature
//! (`Client.signCertificateVerify`, all three key types). Kept in the module
//! per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in:
//! - ECDSA P-256 / P-384: `d`, and the nonce `k` solved from the signature
//!   the call produced (`k = s⁻¹·(e + r·d)`), `k⁻¹`, `r·d`, `e + r·d`;
//! - Ed25519: the seed, the clamped and unclamped scalar, the nonce prefix and
//!   the nonce (`SHA-512(prefix ‖ M)`, raw and reduced).
//! Windows with fewer than 8 distinct bytes are skipped.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const Client = @import("Client.zig");

const PrivateKey = Client.ClientAuth.PrivateKey;
const Ed = std.crypto.ecc.Edwards25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Es384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 4096;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,
    names: [32][]const u8 = undefined,
    n_names: usize = 0,

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += 1) {
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    /// `image` and its byte reversal.
    fn addBoth(self: *Needles, name: []const u8, image: []const u8) void {
        self.addImage(name, image);
        var r: [128]u8 = undefined;
        @memcpy(r[0..image.len], image);
        std.mem.reverse(u8, r[0..image.len]);
        self.addImage(name, r[0..image.len]);
    }

    fn distinct(w: *const [W]u8) usize {
        var seen: [256]bool = @splat(false);
        var c: usize = 0;
        for (w) |b| {
            if (!seen[b]) c += 1;
            seen[b] = true;
        }
        return c;
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    fn addScalar(self: *Needles, name: []const u8, s: anytype) void {
        self.addBoth(name, &s.toBytes(.big));
        self.addImage(name, std.mem.asBytes(&s));
    }

    fn sort(self: *Needles) void {
        const Ctx = struct {
            n: *Needles,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                return c.n.win[a] < c.n.win[b];
            }
            pub fn swap(c: @This(), a: usize, b: usize) void {
                std.mem.swap(u128, &c.n.win[a], &c.n.win[b]);
                std.mem.swap(u8, &c.n.owner[a], &c.n.owner[b]);
            }
        };
        std.sort.pdqContext(0, self.len, Ctx{ .n = self });
    }

    fn find(self: *const Needles, v: u128) ?u8 {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (self.win[mid] < v) lo = mid + 1 else hi = mid;
        }
        return if (lo < self.len and self.win[lo] == v) self.owner[lo] else null;
    }
};

const Hits = [32]usize;

// ── the measured region ─────────────────────────────────────────────────────
//
// The region is addressed directly, below a fixed distance (`PAD`) under the
// probe's own stack position, and the measured call runs under a `PAD`-deep
// frame (`shim`), so its frames start inside the region. `paint` and
// `snapshot` run at the probe's own depth with frames far smaller than `PAD`:
// no instrument frame overlaps the region, so even the call's shallowest
// frames (a wrapper's by-value copies) are seen.
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe, so its frames lie inside the
/// region. `pad` is touched after the call too, so it cannot be a tail call.
noinline fn shim(call: *const fn () void) void {
    var pad: [PAD]u8 = undefined;
    std.mem.doNotOptimizeAway(&pad);
    call();
    std.mem.doNotOptimizeAway(&pad);
}

noinline fn snapshot() void {
    const p: [*]const volatile u8 = @ptrFromInt(region_lo);
    for (&snap, 0..) |*d, i| d.* = p[i];
}

var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn scan(needles: *const Needles) Hits {
    var hits: Hits = @splat(0);
    hit_min_depth = 0;
    hit_max_depth = 0;
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= WINDOW) : (i += 1) {
        if (i < skip_until) continue;
        if (needles.find(std.mem.readInt(u128, snap[i..][0..W], .little))) |id| {
            hits[id] += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
            skip_until = i + W;
        }
    }
    return hits;
}

fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks a secret in a stack local and returns.
var leak_src: [LEAK]u8 = undefined;
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..][0..LEAK].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

/// Zero the callee-saved registers before a measured call: they still hold
/// the TEST's values — needles it just computed — and the call's prologue
/// spills them into its frame, where the scan credits them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// `inline`: as its own frame it ran the call deeper than the region top
/// `runProbe` computed (acme, 2026-10-08).
inline fn measure(call: *const fn () void, n: *const Needles) Hits {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    return scan(n);
}

fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles) !usize {
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;

    const neg = measure(callInnocent, n);
    const pos = measure(callLeaky, n);

    var total: Hits = @splat(0);
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        for (&total, measure(call, n)) |*t, x| t.* += x;
        if (hit_min_depth != 0 and (shallowest == 0 or hit_min_depth < shallowest)) shallowest = hit_min_depth;
        if (hit_max_depth > deepest) deepest = hit_max_depth;
    }
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    const depth = dirtyDepth();

    var sum: usize = 0;
    for (total) |h| sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE tlsclient: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── needles ─────────────────────────────────────────────────────────────────

/// ECDSA needles for a signature `der` over `msg` made with the big-endian
/// scalar `d_bytes` (`Scheme` = std's `EcdsaP256Sha256` over `Curve`/`Hash`, or
/// the P-384 one).
fn ecdsaNeedles(comptime Scheme: type, comptime Curve: type, comptime Hash: type, n: *Needles, d_bytes: []const u8, msg: []const u8, der: []const u8) !void {
    const S = Curve.scalar.Scalar;
    const L = Curve.scalar.encoded_length;
    const sig = try Scheme.Signature.fromDer(der);
    var h: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &h, .{});
    const e = if (h.len >= 48) blk: {
        var xs: [64]u8 = @splat(0);
        @memcpy(xs[64 - h.len ..], &h);
        break :blk S.fromBytes64(xs, .big);
    } else blk: {
        var xs: [48]u8 = @splat(0);
        @memcpy(xs[48 - h.len ..], &h);
        break :blk S.fromBytes48(xs, .big);
    };
    const d = try S.fromBytes(d_bytes[0..L].*, .big);
    const r = try S.fromBytes(sig.r, .big);
    const s = try S.fromBytes(sig.s, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

/// std signs without noise: nonce = reduce64(SHA-512(prefix ‖ msg)).
fn ed25519Needles(n: *Needles, seed: [32]u8, msg: []const u8) void {
    n.addBoth("seed", &seed);
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    n.addBoth("a (unclamped)", az[0..32]);
    var a = az[0..32].*;
    Ed.scalar.clamp(&a);
    n.addBoth("a", &a);
    n.addBoth("prefix", az[32..64]);
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(msg);
    var nonce64: [64]u8 = undefined;
    h.final(&nonce64);
    n.addBoth("nonce64", &nonce64);
    n.addBoth("r", &Ed.scalar.reduce64(nonce64));
}

// ── the probed call (`noinline`, the key read from static memory) ───────────

/// The caller's own storage for the key, as `ClientAuth.key` points at it.
var cur_key: PrivateKey = undefined;
var sig_buf: [160]u8 = undefined;
var sig_sink: []const u8 = &.{};

/// TLS 1.3 CertificateVerify content shape: 64 spaces, the context string, a
/// zero byte, the transcript hash (RFC 8446 §4.4.3).
const signed_msg = "\x20" ** 64 ++ "TLS 1.3, client CertificateVerify\x00" ++ "\x5a" ** 48;

noinline fn callSign() void {
    sig_sink = Client.signCertificateVerify(&sig_buf, &cur_key, signed_msg) catch unreachable;
    std.mem.doNotOptimizeAway(sig_sink.ptr);
}

fn caseSeed(comptime len: usize, i: u8) [len]u8 {
    var out: [64]u8 = undefined;
    Sha512.hash(&[_]u8{ 't', 'l', 's', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out[0..len].*;
}

test "STACKPROBE: no key or nonce residue on the dead stack after the client CertificateVerify signature" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..2) |ci| {
        const i: u8 = @intCast(ci);
        {
            cur_key = .{ .ecdsa_secp256r1_sha256 = caseSeed(32, i) };
            leak_src = cur_key.ecdsa_secp256r1_sha256;
            callSign();
            var n: Needles = .{};
            try ecdsaNeedles(Es256, std.crypto.ecc.P256, Sha256, &n, &cur_key.ecdsa_secp256r1_sha256, signed_msg, sig_sink);
            n.sort();
            bad += try runProbe("signCertificateVerify P-256", callSign, &n);
        }
        {
            cur_key = .{ .ecdsa_secp384r1_sha384 = caseSeed(48, 0x10 + i) };
            leak_src = cur_key.ecdsa_secp384r1_sha384[0..LEAK].*;
            callSign();
            var n: Needles = .{};
            try ecdsaNeedles(Es384, std.crypto.ecc.P384, Sha384, &n, &cur_key.ecdsa_secp384r1_sha384, signed_msg, sig_sink);
            n.sort();
            bad += try runProbe("signCertificateVerify P-384", callSign, &n);
        }
        {
            cur_key = .{ .ed25519 = caseSeed(32, 0x20 + i) };
            leak_src = cur_key.ed25519;
            var n: Needles = .{};
            ed25519Needles(&n, cur_key.ed25519, signed_msg);
            n.sort();
            bad += try runProbe("signCertificateVerify Ed25519", callSign, &n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
