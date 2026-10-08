// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module: the three
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
const P384 = std.crypto.ecc.P384;

const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
const X = hpke.X25519Kem;
const P = hpke.P256Kem;
const Q = hpke.P384Kem;
const Aes = std.crypto.aead.aes_gcm.Aes128Gcm;
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
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── needle helpers ──────────────────────────────────────────────────────────

const info = "hpke dead-stack probe info";
const aad = "hpke probe aad";
const pt = "hpke dead-stack probe plaintext, two AES blocks+";

fn suiteId(comptime Kem: type, aead_id: suite.AeadId) [10]u8 {
    return suite.suiteId(Kem.kem_id, @intFromEnum(suite.KdfId.hkdf_sha256), @intFromEnum(aead_id));
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
