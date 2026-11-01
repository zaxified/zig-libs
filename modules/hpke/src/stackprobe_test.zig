// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module (the pq / hybrid
//! KEMs and the one-stage setup are the last test of this file): the three
//! DHKEMs (`deriveKeyPair`, `encap`/`decap`, `authEncap`/`authDecap`), the key
//! schedule (`setup*`), `Context.seal`/`open`/`exportSecret` and the single-shot
//! `seal*`/`open*`. Kept in the module per `CONVENTIONS.md` §9.
//!
//! Engine as `p256`'s probe (2026-10-08 form): the measured region is
//! addressed directly `PAD` below the probe and the call runs under a
//! `PAD`-deep `shim`, so even the caller-side frames of the call (a by-value
//! key copy, a returned secret's temporary) are seen. ReleaseFast/ReleaseSmall
//! only — Debug and ReleaseSafe fill `undefined` with 0xaa.
//!
//! Needles are every 16-byte window of every image a secret is held in: the
//! private keys, the DH output (both coordinates for the NIST curves, as bytes
//! and as field elements), `eae_prk`, the KEM shared secret, the key
//! schedule's `secret`, the AEAD key, its AES round keys and GHASH key, the
//! exporter secret.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const hpke = @import("root.zig");
const suite = @import("suite.zig");
const P256 = @import("p256").P256;
const aesgcm = @import("aesgcm");
const P384 = std.crypto.ecc.P384;

const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
const X = hpke.X25519Kem;
const P = hpke.P256Kem;
const Q = hpke.P384Kem;
const Aes = aesgcm.Aes128Gcm;
const Cc = hpke.ChaCha20Poly1305;
const AesCtx = hpke.Context(Aes, 32);

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

pub const msg = "p256 dead-stack probe message";

/// Audit-local keys (not from any vector): hashes of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn caseKey(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'p', '2', '5', '6', '-', 'k', 'e', 'y', i }, &out, .{});
    return out;
}
const n_cases = 2;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 8192;

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

    /// The image and its byte reversal (a big-endian value is often held
    /// little-endian, and the reverse).
    fn addBytes(self: *Needles, name: []const u8, b: []const u8) void {
        self.addImage(name, b);
        var r: [256]u8 = undefined;
        @memcpy(r[0..b.len], b);
        std.mem.reverse(u8, r[0..b.len]);
        self.addImage(name, r[0..b.len]);
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
        std.debug.print("\n=== STACKPROBE hpke: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
}

// ── needle helpers ──────────────────────────────────────────────────────────

const info = "hpke dead-stack probe info";
const aad = "hpke probe aad";
const pt = "hpke dead-stack probe plaintext, two AES blocks+";

fn suiteId(comptime Kem: type, aead_id: suite.AeadId) [10]u8 {
    return suite.suiteId(Kem.kem_id, @backingInt(suite.KdfId.hkdf_sha256), @backingInt(aead_id));
}

/// `eae_prk` and the shared secret are recomputed from `dh` with the KEM's
/// own KDF; `kem_context` is whatever the KEM hashes beside it.
fn addKem(n: *Needles, comptime Hkdf: type, comptime kem_id: u16, dh: []const u8, ss: []const u8) void {
    const ksid = suite.kemSuiteId(kem_id);
    var prk: [Hkdf.prk_length]u8 = undefined;
    suite.labeledExtract(Hkdf, &prk, &ksid, "", "eae_prk", dh);
    n.addBytes("eae_prk", &prk);
    n.addBytes("shared_secret", ss);
}

fn addP256Dh(n: *Needles, pk: [65]u8, sk: [32]u8) ![32]u8 {
    const a = (try (try P256.fromSec1(&pk)).mul(sk, .big)).affineCoordinates();
    n.addBytes("dh x", &a.x.toBytes(.big));
    n.addBytes("dh y", &a.y.toBytes(.big));
    n.addImage("dh x fe", std.mem.asBytes(&a.x));
    n.addImage("dh y fe", std.mem.asBytes(&a.y));
    return a.x.toBytes(.big);
}

fn addP384Dh(n: *Needles, pk: [97]u8, sk: [48]u8) ![48]u8 {
    const a = (try (try P384.fromSec1(&pk)).mul(sk, .big)).affineCoordinates();
    n.addBytes("dh x", &a.x.toBytes(.big));
    n.addBytes("dh y", &a.y.toBytes(.big));
    n.addImage("dh x fe", std.mem.asBytes(&a.x));
    n.addImage("dh y fe", std.mem.asBytes(&a.y));
    return a.x.toBytes(.big);
}

/// The key schedule's `secret` and its three outputs, and the AES-128 round
/// keys + GHASH key when the AEAD is AES-GCM.
fn addSchedule(n: *Needles, comptime Kem: type, comptime Aead: type, aead_id: suite.AeadId, ss: []const u8) void {
    const sid = suiteId(Kem, aead_id);
    var secret: [HkdfSha256.prk_length]u8 = undefined;
    suite.labeledExtract(HkdfSha256, &secret, &sid, ss, "secret", "");
    n.addBytes("secret", &secret);
    var psk_id_hash: [HkdfSha256.prk_length]u8 = undefined;
    suite.labeledExtract(HkdfSha256, &psk_id_hash, &sid, "", "psk_id_hash", "");
    var info_hash: [HkdfSha256.prk_length]u8 = undefined;
    suite.labeledExtract(HkdfSha256, &info_hash, &sid, "", "info_hash", info);
    var ksc: [65]u8 = undefined;
    ksc[0] = 0;
    ksc[1..33].* = psk_id_hash;
    ksc[33..].* = info_hash;
    var key: [Aead.key_length]u8 = undefined;
    suite.labeledExpand(HkdfSha256, &sid, &secret, "key", &ksc, &key) catch unreachable;
    var exp: [32]u8 = undefined;
    suite.labeledExpand(HkdfSha256, &sid, &secret, "exp", &ksc, &exp) catch unreachable;
    n.addBytes("exporter_secret", &exp);
    addAeadKey(n, Aead, key);
}

fn addAeadKey(n: *Needles, comptime Aead: type, key: [Aead.key_length]u8) void {
    n.addBytes("aead key", &key);
    if (Aead == Aes) {
        const aes = std.crypto.core.aes.Aes128.initEnc(key);
        n.addImage("aes round keys", std.mem.asBytes(&aes));
        var h: [16]u8 = undefined;
        aes.encrypt(&h, &@as([16]u8, @splat(0)));
        n.addBytes("ghash H", &h);
    }
}

// ── the probed calls (all `noinline`, inputs and results in static memory) ──

var x_eph: X.KeyPair = undefined;
var x_r: X.KeyPair = undefined;
var x_s: X.KeyPair = undefined;
var p_eph: P.KeyPair = undefined;
var p_r: P.KeyPair = undefined;
var p_s: P.KeyPair = undefined;
var q_eph: Q.KeyPair = undefined;
var q_r: Q.KeyPair = undefined;
var ikm: [32]u8 = undefined;
var x_enc: X.EncappedKey = undefined;
var p_enc: P.EncappedKey = undefined;
var q_enc: Q.EncappedKey = undefined;
var p_ct: [pt.len + Cc.tag_length]u8 = undefined;
var aes_ctx: AesCtx = undefined;

var x_kp_sink: X.KeyPair = undefined;
var p_kp_sink: P.KeyPair = undefined;
var q_kp_sink: Q.KeyPair = undefined;
var x_encapped_sink: X.Encapped = undefined;
var p_encapped_sink: P.Encapped = undefined;
var q_encapped_sink: Q.Encapped = undefined;
var ss32_sink: [32]u8 = undefined;
var ss48_sink: [48]u8 = undefined;
var ctx_sink: AesCtx = undefined;
var ct_sink: [pt.len + Cc.tag_length]u8 = undefined;
var pt_sink: [pt.len]u8 = undefined;
var exp_sink: [32]u8 = undefined;
var enc_sink: P.EncappedKey = undefined;

noinline fn callXDerive() void {
    X.deriveKeyPair(&x_kp_sink, &ikm);
}
noinline fn callPDerive() void {
    P.deriveKeyPair(&p_kp_sink, &ikm);
}
noinline fn callQDerive() void {
    Q.deriveKeyPair(&q_kp_sink, &ikm);
}
noinline fn callXEncap() void {
    X.encapDeterministic(&x_encapped_sink, x_r.public_key, &x_eph) catch unreachable;
}
noinline fn callPEncap() void {
    P.encapDeterministic(&p_encapped_sink, p_r.public_key, &p_eph) catch unreachable;
}
noinline fn callQEncap() void {
    Q.encapDeterministic(&q_encapped_sink, q_r.public_key, &q_eph) catch unreachable;
}
noinline fn callXDecap() void {
    X.decap(&ss32_sink, x_enc, &x_r) catch unreachable;
}
noinline fn callPDecap() void {
    P.decap(&ss32_sink, p_enc, &p_r) catch unreachable;
}
noinline fn callQDecap() void {
    Q.decap(&ss48_sink, q_enc, &q_r) catch unreachable;
}
noinline fn callXAuthEncap() void {
    X.authEncapDeterministic(&x_encapped_sink, x_r.public_key, &x_s, &x_eph) catch unreachable;
}
noinline fn callPAuthEncap() void {
    P.authEncapDeterministic(&p_encapped_sink, p_r.public_key, &p_s, &p_eph) catch unreachable;
}
noinline fn callXAuthDecap() void {
    X.authDecap(&ss32_sink, x_enc, &x_r, x_s.public_key) catch unreachable;
}
noinline fn callPAuthDecap() void {
    P.authDecap(&ss32_sink, p_enc, &p_r, p_s.public_key) catch unreachable;
}
noinline fn callSetupBaseR() void {
    hpke.setupBaseR(X, Aes, 32, &ctx_sink, x_enc, &x_r, info) catch unreachable;
}
noinline fn callContextSeal() void {
    aes_ctx.seq = 0;
    aes_ctx.seal(aad, pt, ct_sink[0 .. pt.len + Aes.tag_length]) catch unreachable;
}
noinline fn callContextExport() void {
    aes_ctx.exportSecret(&suiteId(X, .aes128gcm), "probe export", &exp_sink) catch unreachable;
}
noinline fn callSealBase() void {
    enc_sink = (hpke.schedule.sealBaseDeterministic(P, Cc, 32, p_r.public_key, &p_eph, info, aad, pt, &ct_sink) catch unreachable).enc;
}
noinline fn callOpenBase() void {
    hpke.openBase(P, Cc, 32, p_enc, &p_r, info, aad, &p_ct, &pt_sink) catch unreachable;
}

fn setUp(ci: u8) !void {
    ikm = caseKey(ci);
    const k1 = caseKey(ci + 10);
    const k2 = caseKey(ci + 20);
    const k3 = caseKey(ci + 30);
    X.deriveKeyPair(&x_eph, &k1);
    X.deriveKeyPair(&x_r, &k2);
    X.deriveKeyPair(&x_s, &k3);
    P.deriveKeyPair(&p_eph, &k1);
    P.deriveKeyPair(&p_r, &k2);
    P.deriveKeyPair(&p_s, &k3);
    Q.deriveKeyPair(&q_eph, &k1);
    Q.deriveKeyPair(&q_r, &k2);
    x_enc = x_eph.public_key;
    p_enc = p_eph.public_key;
    q_enc = q_eph.public_key;
    _ = try hpke.schedule.sealBaseDeterministic(P, Cc, 32, p_r.public_key, &p_eph, info, aad, pt, &p_ct);
    try hpke.setupBaseR(X, Aes, 32, &aes_ctx, x_enc, &x_r, info);
    leak_src = x_r.secret_key;
}

test "STACKPROBE: no key or DH residue on the dead stack after the DHKEMs" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        // DeriveKeyPair: ikm, dkp_prk and the derived key.
        inline for (.{ .{ X, HkdfSha256, callXDerive, "X25519 deriveKeyPair" }, .{ P, HkdfSha256, callPDerive, "P-256 deriveKeyPair" }, .{ Q, HkdfSha384, callQDerive, "P-384 deriveKeyPair" } }) |c| {
            n = .{};
            const ksid = suite.kemSuiteId(c[0].kem_id);
            n.addBytes("ikm", &ikm);
            var dkp_prk: [c[1].prk_length]u8 = undefined;
            suite.labeledExtract(c[1], &dkp_prk, &ksid, "", "dkp_prk", &ikm);
            n.addBytes("dkp_prk", &dkp_prk);
            var kp: c[0].KeyPair = undefined;
            c[0].deriveKeyPair(&kp, &ikm);
            n.addBytes("sk", &kp.secret_key);
            n.addBytes("control", &leak_src);
            n.sort();
            bad += try runProbe(c[3], c[2], &n);
        }

        // X25519 encap / decap (dh is the same either side).
        const x_dh = try std.crypto.dh.X25519.scalarmult(x_eph.secret_key, x_r.public_key);
        var x_ss: [X.Nsecret]u8 = undefined;
        try X.decap(&x_ss, x_enc, &x_r);
        n = .{};
        n.addBytes("skE", &x_eph.secret_key);
        n.addBytes("dh", &x_dh);
        addKem(&n, HkdfSha256, X.kem_id, &x_dh, &x_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("X25519 encapDeterministic", callXEncap, &n);
        n = .{};
        n.addBytes("skR", &x_r.secret_key);
        n.addBytes("dh", &x_dh);
        addKem(&n, HkdfSha256, X.kem_id, &x_dh, &x_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("X25519 decap", callXDecap, &n);

        // P-256.
        var p_ss: [P.Nsecret]u8 = undefined;
        try P.decap(&p_ss, p_enc, &p_r);
        n = .{};
        n.addBytes("skE", &p_eph.secret_key);
        var p_dh = try addP256Dh(&n, p_r.public_key, p_eph.secret_key);
        addKem(&n, HkdfSha256, P.kem_id, &p_dh, &p_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("P-256 encapDeterministic", callPEncap, &n);
        n = .{};
        n.addBytes("skR", &p_r.secret_key);
        p_dh = try addP256Dh(&n, p_enc, p_r.secret_key);
        addKem(&n, HkdfSha256, P.kem_id, &p_dh, &p_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("P-256 decap", callPDecap, &n);

        // P-384.
        var q_ss: [Q.Nsecret]u8 = undefined;
        try Q.decap(&q_ss, q_enc, &q_r);
        n = .{};
        n.addBytes("skE", &q_eph.secret_key);
        var q_dh = try addP384Dh(&n, q_r.public_key, q_eph.secret_key);
        addKem(&n, HkdfSha384, Q.kem_id, &q_dh, &q_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("P-384 encapDeterministic", callQEncap, &n);
        n = .{};
        n.addBytes("skR", &q_r.secret_key);
        q_dh = try addP384Dh(&n, q_enc, q_r.secret_key);
        addKem(&n, HkdfSha384, Q.kem_id, &q_dh, &q_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("P-384 decap", callQDecap, &n);

        // Auth modes: both DH outputs, the shared secret over dh || dh2.
        var xa_ss: [X.Nsecret]u8 = undefined;
        try X.authDecap(&xa_ss, x_enc, &x_r, x_s.public_key);
        var xa_dh: [64]u8 = undefined;
        xa_dh[0..32].* = x_dh;
        xa_dh[32..].* = try std.crypto.dh.X25519.scalarmult(x_s.secret_key, x_r.public_key);
        n = .{};
        n.addBytes("skE", &x_eph.secret_key);
        n.addBytes("skS", &x_s.secret_key);
        n.addBytes("dh", xa_dh[0..32]);
        n.addBytes("dh2", xa_dh[32..]);
        addKem(&n, HkdfSha256, X.kem_id, &xa_dh, &xa_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("X25519 authEncapDeterministic", callXAuthEncap, &n);
        n = .{};
        n.addBytes("skR", &x_r.secret_key);
        n.addBytes("dh", xa_dh[0..32]);
        n.addBytes("dh2", xa_dh[32..]);
        addKem(&n, HkdfSha256, X.kem_id, &xa_dh, &xa_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("X25519 authDecap", callXAuthDecap, &n);

        var pa_ss: [P.Nsecret]u8 = undefined;
        try P.authDecap(&pa_ss, p_enc, &p_r, p_s.public_key);
        var pa_dh: [64]u8 = undefined;
        n = .{};
        n.addBytes("skE", &p_eph.secret_key);
        n.addBytes("skS", &p_s.secret_key);
        pa_dh[0..32].* = try addP256Dh(&n, p_r.public_key, p_eph.secret_key);
        pa_dh[32..].* = try addP256Dh(&n, p_r.public_key, p_s.secret_key);
        addKem(&n, HkdfSha256, P.kem_id, &pa_dh, &pa_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("P-256 authEncapDeterministic", callPAuthEncap, &n);
        n = .{};
        n.addBytes("skR", &p_r.secret_key);
        _ = try addP256Dh(&n, p_enc, p_r.secret_key);
        _ = try addP256Dh(&n, p_s.public_key, p_r.secret_key);
        addKem(&n, HkdfSha256, P.kem_id, &pa_dh, &pa_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("P-256 authDecap", callPAuthDecap, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no key-schedule or AEAD-key residue on the dead stack after setup, seal/open, export" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        const x_dh = try std.crypto.dh.X25519.scalarmult(x_r.secret_key, x_enc);
        var x_ss: [X.Nsecret]u8 = undefined;
        try X.decap(&x_ss, x_enc, &x_r);
        n.addBytes("skR", &x_r.secret_key);
        n.addBytes("dh", &x_dh);
        addKem(&n, HkdfSha256, X.kem_id, &x_dh, &x_ss);
        addSchedule(&n, X, Aes, .aes128gcm, &x_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("setupBaseR (X25519, AES-128-GCM)", callSetupBaseR, &n);

        n = .{};
        addAeadKey(&n, Aes, aes_ctx.key);
        n.addBytes("exporter_secret", &aes_ctx.exporter_secret);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("Context.seal (AES-128-GCM)", callContextSeal, &n);

        n = .{};
        n.addBytes("exporter_secret", &aes_ctx.exporter_secret);
        var exp: [32]u8 = undefined;
        try aes_ctx.exportSecret(&suiteId(X, .aes128gcm), "probe export", &exp);
        n.addBytes("exported", &exp);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("Context.exportSecret", callContextExport, &n);

        var p_ss: [P.Nsecret]u8 = undefined;
        try P.decap(&p_ss, p_enc, &p_r);
        n = .{};
        n.addBytes("skE", &p_eph.secret_key);
        const p_dh = try addP256Dh(&n, p_r.public_key, p_eph.secret_key);
        addKem(&n, HkdfSha256, P.kem_id, &p_dh, &p_ss);
        addSchedule(&n, P, Cc, .chacha20poly1305, &p_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("sealBaseDeterministic (P-256, ChaCha20-Poly1305)", callSealBase, &n);

        n = .{};
        n.addBytes("skR", &p_r.secret_key);
        _ = try addP256Dh(&n, p_enc, p_r.secret_key);
        addKem(&n, HkdfSha256, P.kem_id, &p_dh, &p_ss);
        addSchedule(&n, P, Cc, .chacha20poly1305, &p_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("openBase (P-256, ChaCha20-Poly1305)", callOpenBase, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// ── draft-ietf-hpke-pq: the pq / hybrid KEMs and the one-stage key schedule ──
//
// One group of probes per KEM family (ML-KEM-768, ML-KEM-1024, X-Wing,
// MLKEM768-P256, MLKEM1024-P384; ML-KEM-512 shares ML-KEM-768's burn and
// frames of the same shape): `fromSeed`, `deriveKeyPair`, `encapDeterministic`,
// `decap`. Needles: the seed (and the SHAKE256 stream it expands into, the
// ML-KEM seed `G(d || k)`), the encapsulation randomness `m` and `G(m || H(ek))`,
// the ML-KEM shared secret, the curve scalar (the hybrids' `t_secret` /
// ephemeral candidates), the curve DH output (both coordinates and the field
// elements for the NIST curves), the combined secret. Then `setupBaseR` over
// X-Wing + SHAKE256: the same plus the one-stage `secret`, the AEAD key, its AES
// round keys and GHASH key, the exporter secret.

const mlkem = @import("mlkem");
const Shake256 = std.crypto.hash.sha3.Shake256;
const Sha3_256 = std.crypto.hash.sha3.Sha3_256;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;
const M768 = hpke.MlKem768Kem;
const M1024 = hpke.MlKem1024Kem;
const XW = hpke.MlKem768X25519Kem;
const H256 = hpke.MlKem768P256Kem;
const H384 = hpke.MlKem1024P384Kem;

fn PqProbe(comptime Kem: type) type {
    return struct {
        var ikm_in: [32]u8 = undefined;
        var seed_in: [Kem.Nsk]u8 = undefined;
        var eph: Kem.Ephemeral = undefined;
        var kp: Kem.KeyPair = undefined;
        var full: Kem.Encapped = undefined;
        var enc: Kem.EncappedKey = undefined;
        var kp_sink: Kem.KeyPair = undefined;
        var encapped_sink: Kem.Encapped = undefined;
        var ss_sink: [32]u8 = undefined;

        noinline fn callFromSeed() void {
            Kem.fromSeed(&kp_sink, &seed_in);
        }
        noinline fn callDerive() void {
            Kem.deriveKeyPair(&kp_sink, &ikm_in);
        }
        noinline fn callEncap() void {
            Kem.encapDeterministic(&encapped_sink, kp.public_key, &eph) catch unreachable;
        }
        noinline fn callDecap() void {
            Kem.decap(&ss_sink, enc, &kp) catch unreachable;
        }

        /// The probes' inputs for case `ci`, in static memory.
        fn prepare(ci: u8) !void {
            ikm_in = caseKey(ci + 40);
            Shake256.hash(&caseKey(ci + 50), &seed_in, .{});
            Shake256.hash(&caseKey(ci + 60), &eph, .{});
            Kem.fromSeed(&kp, &seed_in);
            try Kem.encapDeterministic(&full, kp.public_key, &eph);
            enc = full.enc;
            var ss: [32]u8 = undefined;
            try Kem.decap(&ss, enc, &kp);
            try std.testing.expectEqualSlices(u8, &full.shared_secret, &ss);
            leak_src = kp.seed[0..LEAK].*;
        }
    };
}

fn isHybrid(comptime Kem: type) bool {
    return @hasField(Kem.KeyPair, "t_secret");
}

/// The key pair `kp`'s secrets: the seed, the SHAKE256 stream a hybrid seed
/// expands into (the ML-KEM seed, then the curve-scalar candidates), the
/// ML-KEM `G(d || k)` (rho || sigma) and the hybrid's curve scalar.
fn addKeyNeedles(n: *Needles, comptime Kem: type, comptime K: type, kp: *const Kem.KeyPair) void {
    n.addBytes("seed", &kp.seed);
    const k: u8 = (K.PublicKey.encoded_length - 32) / 384;
    var pq_seed: [64]u8 = undefined;
    if (comptime isHybrid(Kem)) {
        var stream: [64 + 3 * 48]u8 = undefined;
        Shake256.hash(&kp.seed, &stream, .{});
        n.addBytes("shake stream", &stream);
        pq_seed = stream[0..64].*;
        n.addBytes("t_secret", &kp.t_secret);
    } else pq_seed = kp.seed;
    var g: [64]u8 = undefined;
    var h = Sha3_512.init(.{});
    h.update(pq_seed[0..32]);
    h.update(&[1]u8{k});
    h.final(&g);
    n.addBytes("G(d||k)", &g);
}

/// The curve DH of the hybrids: `sk` against the point / u-coordinate `ek_t`.
fn addHybridDh(n: *Needles, comptime Kem: type, ek_t: []const u8, sk: []const u8) void {
    if (Kem == XW) {
        const dh = std.crypto.dh.X25519.scalarmult(sk[0..32].*, ek_t[0..32].*) catch return;
        n.addBytes("dh", &dh);
    } else if (Kem == H256) {
        _ = addP256Dh(n, ek_t[0..65].*, sk[0..32].*) catch return;
    } else {
        _ = addP384Dh(n, ek_t[0..97].*, sk[0..48].*) catch return;
    }
}

/// The encapsulation side: `m`, the ephemeral curve-scalar candidates, `G(m ||
/// H(ek))`, the ML-KEM and combined shared secrets, the curve DH output.
fn addEncapNeedles(n: *Needles, comptime Kem: type, comptime K: type, comptime PC: type) void {
    const pq_pk = PC.kp.public_key[0..K.PublicKey.encoded_length];
    const m = PC.eph[0..K.encaps_seed_length];
    n.addBytes("m", m);
    var hek: [32]u8 = undefined;
    Sha3_256.hash(pq_pk, &hek, .{});
    var g: [64]u8 = undefined;
    var h = Sha3_512.init(.{});
    h.update(m);
    h.update(&hek);
    h.final(&g);
    n.addBytes("G(m||H(ek))", &g);
    n.addBytes("shared_secret", &PC.full.shared_secret);
    if (comptime isHybrid(Kem)) {
        const ek_t = PC.kp.public_key[K.PublicKey.encoded_length..];
        const pk = K.PublicKey.fromBytes(pq_pk) catch unreachable;
        const es = pk.encapsDeterministic(m);
        n.addBytes("ss_pq", &es.shared_secret);
        const cands = PC.eph[K.encaps_seed_length..];
        const w = cands.len / (if (Kem == H256) 3 else 1);
        var i: usize = 0;
        while (i + w <= cands.len) : (i += w) {
            n.addBytes("skE", cands[i..][0..w]);
            addHybridDh(n, Kem, ek_t, cands[i..][0..w]);
        }
    }
}

/// The decapsulation side: the seed material, `m`, `G(m || H(ek))` (the
/// re-encryption's inputs), the ML-KEM and combined secrets, the curve DH.
fn addDecapNeedles(n: *Needles, comptime Kem: type, comptime K: type, comptime PC: type) void {
    addKeyNeedles(n, Kem, K, &PC.kp);
    addEncapNeedles(n, Kem, K, PC);
    if (comptime isHybrid(Kem)) {
        const ct_t = PC.enc[K.ciphertext_length..];
        addHybridDh(n, Kem, ct_t, &PC.kp.t_secret);
    }
}

fn probePq(comptime Kem: type, comptime K: type, comptime name: []const u8, ci: u8) !usize {
    const PC = PqProbe(Kem);
    try PC.prepare(ci);
    var bad: usize = 0;
    var n: Needles = .{};

    // fromSeed: the seed and everything it expands into.
    n.addBytes("seed", &PC.seed_in);
    addKeyNeedles(&n, Kem, K, &PC.kp);
    n.addBytes("control", &leak_src);
    n.sort();
    bad += try runProbe(name ++ " fromSeed", PC.callFromSeed, &n);

    // deriveKeyPair: the ikm and the key it derives.
    var dkp: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&dkp, &PC.ikm_in);
    n = .{};
    n.addBytes("ikm", &PC.ikm_in);
    addKeyNeedles(&n, Kem, K, &dkp);
    n.addBytes("control", &leak_src);
    n.sort();
    bad += try runProbe(name ++ " deriveKeyPair", PC.callDerive, &n);

    n = .{};
    addEncapNeedles(&n, Kem, K, PC);
    n.addBytes("control", &leak_src);
    n.sort();
    bad += try runProbe(name ++ " encapDeterministic", PC.callEncap, &n);

    n = .{};
    addDecapNeedles(&n, Kem, K, PC);
    n.addBytes("control", &leak_src);
    n.sort();
    bad += try runProbe(name ++ " decap", PC.callDecap, &n);
    return bad;
}

const XwP = PqProbe(XW);
const Shake = hpke.kdf.Shake256;
const XwCtx = hpke.Context(Aes, Shake);
var xw_ctx_sink: XwCtx = undefined;

noinline fn callXwSetupBaseR() void {
    hpke.setupBaseR(XW, Aes, Shake, &xw_ctx_sink, XwP.enc, &XwP.kp, info) catch unreachable;
}

fn probeXwSetup(ci: u8) !usize {
    try XwP.prepare(ci);
    var ctx: XwCtx = undefined;
    try hpke.setupBaseR(XW, Aes, Shake, &ctx, XwP.enc, &XwP.kp, info);
    var n: Needles = .{};
    addDecapNeedles(&n, XW, mlkem.MLKem768, XwP);
    // The one-stage `secret` = key || base_nonce || exporter_secret.
    var secret: [Aes.key_length + Aes.nonce_length + Shake.Nh]u8 = undefined;
    secret[0..Aes.key_length].* = ctx.key;
    secret[Aes.key_length..][0..Aes.nonce_length].* = ctx.base_nonce;
    secret[Aes.key_length + Aes.nonce_length ..].* = ctx.exporter_secret;
    n.addBytes("secret", &secret);
    addAeadKey(&n, Aes, ctx.key);
    n.addBytes("exporter_secret", &ctx.exporter_secret);
    n.addBytes("control", &leak_src);
    n.sort();
    return runProbe("setupBaseR (X-Wing, SHAKE256, AES-128-GCM)", callXwSetupBaseR, &n);
}

test "STACKPROBE: no pq key, ML-KEM or combined-secret residue on the dead stack after the pq KEMs and the one-stage setup" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        const c: u8 = @intCast(ci);
        bad += try probePq(M768, mlkem.MLKem768, "ML-KEM-768", c);
        bad += try probePq(M1024, mlkem.MLKem1024, "ML-KEM-1024", c);
        bad += try probePq(XW, mlkem.MLKem768, "X-Wing", c);
        bad += try probePq(H256, mlkem.MLKem768, "MLKEM768-P256", c);
        bad += try probePq(H384, mlkem.MLKem1024, "MLKEM1024-P384", c);
        bad += try probeXwSetup(c);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
