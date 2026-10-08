// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the secret-touching entry points of ctap2pin:
//! the ECDH key agreement (`publicKeyFromScalar`, `ecdhZ`, `encapsulate`), both
//! protocols' `kdf`, AES-256-CBC `encrypt`/`decrypt` and `authenticate`/`verify`.
//! Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `p256`'s probe: paint a stack window, run the call `PAD` bytes
//! deeper than the probe, snapshot, and look for secrets. ReleaseFast/
//! ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with 0xaa, so the
//! scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in
//! (big-endian, little-endian, the in-memory form of the scalar / field
//! element / AES key schedule), so a half copy or a limb pair counts too.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks the secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const p256 = @import("p256");
const ctap2pin = @import("root.zig");

const P256 = p256.P256;
const Scalar = p256.Scalar;
const One = ctap2pin.One;
const Two = ctap2pin.Two;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes256 = std.crypto.core.aes.Aes256;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 2048;

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
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    fn addBytes32(self: *Needles, name: []const u8, b: [32]u8) void {
        self.addImage(name, &b);
        var r = b;
        std.mem.reverse(u8, &r);
        self.addImage(name, &r);
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
// frames (a wrapper's by-value copies) are seen. The earlier form claimed an
// uninitialised buffer at the call's depth instead, and the claiming frame's
// own header and locals hid the top few hundred bytes (2026-10-08: a stale
// negative-control hit there, and a positive control that went blind when
// the scan function grew a local).
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe — below the probe's
/// own frame, at the depth `paint`/`shim`/`snapshot` start at.
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

/// Count needle windows in the last snapshot, one per run of overlapping
/// windows. `hit_min_depth`/`hit_max_depth`: bytes below the region's top.
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

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
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
/// spills them into its frame, where the scan credits them to the call
/// (2026-10-08: a negative-control "hit" of `x mod q` between two saved stack
/// pointers in `callInnocent`'s frame, gone when the setup code changed). The
/// compiler saves and restores the probe's own values around the asm.
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
/// `runProbe` computed (2026-10-08).
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
    // Summed over every needle: images that share a window (a scalar and its
    // zero-extended form) report a hit under whichever name sorts first.
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE ctap2pin: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<10} {d} (5 calls)\n", .{ name, total[i] });
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

/// Audit-local keys (not from any vector): hashes of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn caseKey(i: u8, tag: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'c', 't', 'a', 'p', '2', 'p', 'i', 'n', '-', tag, i }, &out, .{});
    return out;
}
const n_cases = 2;

fn addScalarImages(n: *Needles, name: []const u8, d: [32]u8) !void {
    n.addBytes32(name, d);
    const s = try Scalar.fromBytes(d, .big);
    n.addImage(name, std.mem.asBytes(&s));
}

/// The scalar plus the shared point `d·peer` in every form the code holds it in.
fn ecdhNeedles(n: *Needles, d: [32]u8, peer: ctap2pin.PublicKey) !void {
    try addScalarImages(n, "d", d);
    const shared = (try (try peer.toPoint()).mul(d, .big)).affineCoordinates();
    n.addBytes32("shared x", shared.x.toBytes(.big));
    n.addBytes32("shared y", shared.y.toBytes(.big));
    n.addImage("shared x fe", std.mem.asBytes(&shared.x));
    n.addImage("shared y fe", std.mem.asBytes(&shared.y));
}

fn kdfNeedles(n: *Needles, z: [32]u8, comptime two: bool) void {
    n.addBytes32("Z", z);
    if (!two) {
        var s1: One.SharedSecret = undefined;
        One.kdf(&s1, &z);
        n.addBytes32("secret1", s1);
    } else {
        const salt: [32]u8 = @splat(0);
        const prk = HkdfSha256.extract(&salt, &z);
        n.addBytes32("prk", prk);
        var s: Two.SharedSecret = undefined;
        Two.kdf(&s, &z);
        n.addBytes32("hmacKey", s[0..32].*);
        n.addBytes32("aesKey", s[32..64].*);
    }
}

fn aesNeedles(n: *Needles, key: [32]u8) void {
    n.addBytes32("aes key", key);
    const e1 = Aes256.initEnc(key);
    n.addImage("aes enc sched", std.mem.asBytes(&e1));
    const d1 = Aes256.initDec(key);
    n.addImage("aes dec sched", std.mem.asBytes(&d1));
}

fn hmacNeedles(n: *Needles, key: [32]u8) void {
    n.addBytes32("mac key", key);
    var ip: [32]u8 = undefined;
    var op: [32]u8 = undefined;
    for (key, &ip, &op) |k, *i, *o| {
        i.* = k ^ 0x36;
        o.* = k ^ 0x5c;
    }
    n.addBytes32("mac ipad", ip);
    n.addBytes32("mac opad", op);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var cur_d: [32]u8 = undefined;
var cur_peer: ctap2pin.PublicKey = undefined;
var cur_z: [32]u8 = undefined;
var cur_s1: One.SharedSecret = undefined;
var cur_s2: Two.SharedSecret = undefined;
var cur_plain: [32]u8 = undefined;
var cur_ct1: [32]u8 = undefined;
var cur_ct2: [48]u8 = undefined;
var cur_iv: [16]u8 = undefined;
var cur_msg: [24]u8 = undefined;
var cur_mac1: [16]u8 = undefined;
var cur_mac2: [32]u8 = undefined;
// Results land in static memory: the caller's own storage is not the probe's concern.
var pk_sink: ctap2pin.PublicKey = undefined;
var z_sink: [32]u8 = undefined;
var enc1_sink: One.Encaps = undefined;
var enc2_sink: Two.Encaps = undefined;
var s1_sink: One.SharedSecret = undefined;
var s2_sink: Two.SharedSecret = undefined;
var ct_sink: [48]u8 = undefined;
var pt_sink: [32]u8 = undefined;
var mac_sink: [32]u8 = undefined;
var ok_sink: bool = false;

noinline fn callPublicKey() void {
    pk_sink = ctap2pin.publicKeyFromScalar(&cur_d) catch unreachable;
}
noinline fn callEcdhZ() void {
    ctap2pin.ecdhZ(&z_sink, &cur_d, cur_peer) catch unreachable;
}
noinline fn callEncaps1() void {
    One.encapsulate(&enc1_sink, &cur_d, cur_peer) catch unreachable;
}
noinline fn callEncaps2() void {
    Two.encapsulate(&enc2_sink, &cur_d, cur_peer) catch unreachable;
}
noinline fn callKdf1() void {
    One.kdf(&s1_sink, &cur_z);
}
noinline fn callKdf2() void {
    Two.kdf(&s2_sink, &cur_z);
}
noinline fn callEnc1() void {
    One.encrypt(&cur_s1, ct_sink[0..32], &cur_plain) catch unreachable;
}
noinline fn callDec1() void {
    One.decrypt(&cur_s1, &pt_sink, &cur_ct1) catch unreachable;
}
noinline fn callEnc2() void {
    Two.encrypt(&cur_s2, cur_iv, &ct_sink, &cur_plain) catch unreachable;
}
noinline fn callDec2() void {
    Two.decrypt(&cur_s2, &pt_sink, &cur_ct2) catch unreachable;
}
noinline fn callAuth1() void {
    const m = One.authenticate(cur_s1[0..32], &cur_msg) catch unreachable;
    mac_sink[0..16].* = m;
}
noinline fn callVerify1() void {
    ok_sink = One.verify(cur_s1[0..32], &cur_msg, &cur_mac1);
}
noinline fn callAuth2() void {
    mac_sink = Two.authenticate(cur_s2[0..32], &cur_msg);
}
noinline fn callVerify2() void {
    ok_sink = Two.verify(cur_s2[0..32], &cur_msg, &cur_mac2);
}

fn setup(ci: usize) !void {
    cur_d = caseKey(@intCast(ci), 'd');
    const peer_scalar = caseKey(@intCast(ci), 'p');
    cur_peer = try ctap2pin.publicKeyFromScalar(&peer_scalar);
    leak_src = cur_d;
    const shared = (try (try cur_peer.toPoint()).mul(cur_d, .big)).affineCoordinates();
    cur_z = shared.x.toBytes(.big);
    One.kdf(&cur_s1, &cur_z);
    Two.kdf(&cur_s2, &cur_z);
    cur_plain = caseKey(@intCast(ci), 'm');
    cur_iv = caseKey(@intCast(ci), 'i')[0..16].*;
    try One.encrypt(&cur_s1, &cur_ct1, &cur_plain);
    try Two.encrypt(&cur_s2, cur_iv, &cur_ct2, &cur_plain);
    cur_msg = caseKey(@intCast(ci), 'g')[0..24].*;
    cur_mac1 = (try One.authenticate(cur_s1[0..32], &cur_msg));
    cur_mac2 = Two.authenticate(cur_s2[0..32], &cur_msg);
}

test "STACKPROBE: no scalar or shared-secret residue after the ECDH key agreement" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setup(ci);
        var n: Needles = .{};
        try addScalarImages(&n, "d", cur_d);
        n.sort();
        leak_src = cur_d;
        bad += try runProbe("publicKeyFromScalar", callPublicKey, &n);

        n = .{};
        try ecdhNeedles(&n, cur_d, cur_peer);
        n.sort();
        bad += try runProbe("ecdhZ", callEcdhZ, &n);

        n = .{};
        try ecdhNeedles(&n, cur_d, cur_peer);
        kdfNeedles(&n, cur_z, false);
        n.sort();
        bad += try runProbe("One.encapsulate", callEncaps1, &n);

        n = .{};
        try ecdhNeedles(&n, cur_d, cur_peer);
        kdfNeedles(&n, cur_z, true);
        n.sort();
        bad += try runProbe("Two.encapsulate", callEncaps2, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no Z or key residue after the protocol kdf" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setup(ci);
        var n: Needles = .{};
        kdfNeedles(&n, cur_z, false);
        n.sort();
        leak_src = cur_z;
        bad += try runProbe("One.kdf", callKdf1, &n);

        n = .{};
        kdfNeedles(&n, cur_z, true);
        n.sort();
        leak_src = cur_z;
        bad += try runProbe("Two.kdf", callKdf2, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no key or plaintext residue after encrypt / decrypt" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setup(ci);
        leak_src = cur_s1[0..32].*;
        var n: Needles = .{};
        aesNeedles(&n, cur_s1[0..32].*);
        n.addBytes32("plain", cur_plain);
        n.sort();
        bad += try runProbe("One.encrypt", callEnc1, &n);
        bad += try runProbe("One.decrypt", callDec1, &n);

        n = .{};
        aesNeedles(&n, cur_s2[32..64].*);
        n.addBytes32("hmacKey", cur_s2[0..32].*);
        n.addBytes32("plain", cur_plain);
        n.sort();
        leak_src = cur_s2[32..64].*;
        bad += try runProbe("Two.encrypt", callEnc2, &n);
        bad += try runProbe("Two.decrypt", callDec2, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no key residue after authenticate / verify" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setup(ci);
        leak_src = cur_s1[0..32].*;
        var n: Needles = .{};
        hmacNeedles(&n, cur_s1[0..32].*);
        n.sort();
        bad += try runProbe("One.authenticate", callAuth1, &n);
        bad += try runProbe("One.verify", callVerify1, &n);

        n = .{};
        hmacNeedles(&n, cur_s2[0..32].*);
        n.sort();
        leak_src = cur_s2[0..32].*;
        bad += try runProbe("Two.authenticate", callAuth2, &n);
        bad += try runProbe("Two.verify", callVerify2, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
