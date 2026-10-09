// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `noise` (wave 9, 2026-10-09; SPEC § "Secret
//! residue on the dead stack"). Method as `bolt8`'s and `p256`'s probes: a
//! painted region below the probe, one call run under a `PAD`-deep shim, the
//! region scanned for 32-byte needles. ReleaseFast/ReleaseSmall only — Debug
//! and ReleaseSafe fill `undefined` with 0xaa.
//!
//! The handshake is `XXpsk3` on `DefaultSuite` (X25519, ChaChaPoly, SHA-256):
//! it exercises `e`, `s`, `ee`, `es`, `se`, `psk` (so `mixKey`, `mixKeyAndHash`
//! and `split`) and the transport `CipherState` calls. Every step works on
//! GLOBAL state, so what a `HandshakeState` legitimately holds is never in the
//! scanned window; a hit is a copy left in a dead frame. Needles: both static
//! and ephemeral private keys (raw and as X25519 clamps them), the DH outputs,
//! the PSK, every HKDF `temp_key`, the chaining key and cipher key after every
//! `MixKey`, and the two transport keys. Everything is recomputed in the test
//! from the observed states, with std's HMAC.
//!
//! ⛔ A zero is only readable next to the two controls: NEG (a call that never
//! sees a secret finds 0) and POS (a call that parks the control needle in a
//! local finds it).

const std = @import("std");
const builtin = @import("builtin");
const noise = @import("root.zig");

const Suite = noise.DefaultSuite;
const HS = Suite.HandshakeState;
const CS = Suite.CipherState;
const SS = Suite.SymmetricState;
const X25519 = std.crypto.dh.X25519;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const pattern = noise.withPsk(noise.patterns.XX, &.{3});

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

const WINDOW = 256 * 1024;
const PAD = 2048;

const Needle = struct { name: []const u8, bytes: [32]u8 };
const max_needles = 64;

const Needles = struct {
    items: [max_needles]Needle = undefined,
    len: usize = 0,

    fn add(self: *Needles, name: []const u8, bytes: [32]u8) void {
        self.items[self.len] = .{ .name = name, .bytes = bytes };
        self.len += 1;
    }

    /// A private key raw and as X25519 clamps it.
    fn addKey(self: *Needles, comptime name: []const u8, k: [32]u8) void {
        self.add(name, k);
        var c = k;
        c[0] &= 248;
        c[31] = (c[31] & 127) | 64;
        self.add(name ++ " (clamped)", c);
    }

    fn slice(self: *const Needles) []const Needle {
        return self.items[0..self.len];
    }
};

// ── the measured region (engine as bolt8's probe) ────────────────────────────

var region_lo: usize = 0;
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

/// The callee-saved registers still hold the test's own needles; the call's
/// prologue would spill them into its frame and be blamed for them.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

inline fn measure(call: *const fn () void) void {
    region_lo = stackHere() - PAD - WINDOW;
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
}

fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn resetDepths() void {
    hit_min_depth = 0;
    hit_max_depth = 0;
}

fn countIn(needle: *const [32]u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        if (snap[i] == needle[0] and std.mem.eql(u8, snap[i..][0..32], needle)) {
            hits += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
        }
    }
    return hits;
}

fn countAll(needles: []const Needle, hits: []usize) void {
    for (needles, hits) |*nd, *h| h.* += countIn(&nd.bytes);
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks the control needle in a stack local and returns.
var control: [32]u8 = undefined;
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = control;
    std.mem.doNotOptimizeAway(&local);
}

// ── API adapter: the ONLY block that changes with the noise API ──────────────

fn apiInit(hs: *HS, initiator: bool, s: *const Suite.KeyPair) void {
    hs.init(pattern, initiator, "", &.{ .s = s, .psks = &psk_list }) catch unreachable;
}
fn apiWrite(hs: *HS, random: std.Random, payload: []const u8, out: []u8, tp: *[2]CS) usize {
    return (hs.writeMessage(random, payload, out, tp) catch unreachable).len;
}
fn apiRead(hs: *HS, msg: []const u8, out: []u8, tp: *[2]CS) usize {
    return (hs.readMessage(msg, out, tp) catch unreachable).len;
}
fn apiSplit(ss: *SS, tp: *[2]CS) void {
    ss.split(tp);
}
fn apiInitKey(cs: *CS, key: *const [32]u8) void {
    cs.initializeKey(key);
}

// ── global state and the probed calls ───────────────────────────────────────

var s_i: Suite.KeyPair = undefined;
var s_r: Suite.KeyPair = undefined;
var psk_list: [1][32]u8 = undefined;
var hs_i: HS = undefined;
var hs_r: HS = undefined;
var prng_i: std.Random.DefaultPrng = undefined;
var prng_r: std.Random.DefaultPrng = undefined;
var wire: [256]u8 = undefined;
var wire_len: usize = 0;
var pl: [64]u8 = undefined;
var tp_i: [2]CS = undefined;
var tp_r: [2]CS = undefined;
const plaintext = "noise dead-stack probe message";
var ct: [plaintext.len + 16]u8 = undefined;
var back: [plaintext.len]u8 = undefined;
// Stand-alone SymmetricState / CipherState for the direct calls.
var ss_x: SS = undefined;
var ikm_x: [32]u8 = undefined;
var key_x: [32]u8 = undefined;
var cs_x: CS = undefined;
var tp_x: [2]CS = undefined;

fn reset() void {
    prng_i = .init(0x7015_0001);
    prng_r = .init(0x7015_0002);
    hs_i = undefined;
    hs_r = undefined;
    ss_x = .{};
    ss_x.ck = hash("probe ck");
    cs_x = .{};
    cs_x.initializeKey(&key_x);
    wire_len = 0;
}

fn hash(comptime label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("noise-probe/" ++ label, &out, .{});
    return out;
}

noinline fn stepInitI() void {
    apiInit(&hs_i, true, &s_i);
}
noinline fn stepInitR() void {
    apiInit(&hs_r, false, &s_r);
}
noinline fn stepWrite1() void {
    wire_len = apiWrite(&hs_i, prng_i.random(), "", &wire, &tp_i);
}
noinline fn stepRead1() void {
    _ = apiRead(&hs_r, wire[0..wire_len], &pl, &tp_r);
}
noinline fn stepWrite2() void {
    wire_len = apiWrite(&hs_r, prng_r.random(), "", &wire, &tp_r);
}
noinline fn stepRead2() void {
    _ = apiRead(&hs_i, wire[0..wire_len], &pl, &tp_i);
}
noinline fn stepWrite3() void {
    wire_len = apiWrite(&hs_i, prng_i.random(), "", &wire, &tp_i);
}
noinline fn stepRead3() void {
    _ = apiRead(&hs_r, wire[0..wire_len], &pl, &tp_r);
}
noinline fn stepEncrypt() void {
    tp_i[0].encryptWithAd("", plaintext, &ct) catch unreachable;
}
noinline fn stepDecrypt() void {
    tp_r[0].decryptWithAd("", &ct, &back) catch unreachable;
}
noinline fn stepRekey() void {
    tp_i[1].rekey();
}
noinline fn stepInitKey() void {
    apiInitKey(&cs_x, &key_x);
}
noinline fn stepMixKey() void {
    ss_x.mixKey(&ikm_x);
}
noinline fn stepMixKeyAndHash() void {
    ss_x.mixKeyAndHash(&ikm_x);
}
noinline fn stepSplit() void {
    apiSplit(&ss_x, &tp_x);
}

const steps = [_]struct { name: []const u8, call: *const fn () void }{
    .{ .name = "HandshakeState.init (I)", .call = stepInitI },
    .{ .name = "HandshakeState.init (R)", .call = stepInitR },
    .{ .name = "writeMessage 1 (I: e)", .call = stepWrite1 },
    .{ .name = "readMessage 1 (R)", .call = stepRead1 },
    .{ .name = "writeMessage 2 (R: e ee s es)", .call = stepWrite2 },
    .{ .name = "readMessage 2 (I)", .call = stepRead2 },
    .{ .name = "writeMessage 3 (I: s se psk + split)", .call = stepWrite3 },
    .{ .name = "readMessage 3 (R + split)", .call = stepRead3 },
    .{ .name = "encryptWithAd", .call = stepEncrypt },
    .{ .name = "decryptWithAd", .call = stepDecrypt },
    .{ .name = "rekey", .call = stepRekey },
    .{ .name = "CipherState.initializeKey", .call = stepInitKey },
    .{ .name = "SymmetricState.mixKey", .call = stepMixKey },
    .{ .name = "SymmetricState.mixKeyAndHash", .call = stepMixKeyAndHash },
    .{ .name = "SymmetricState.split", .call = stepSplit },
};

// ── the needles, recomputed from observed states ─────────────────────────────

const Hk = struct { temp: [32]u8, o1: [32]u8, o2: [32]u8, o3: [32]u8 };

fn hkdf3(ck: [32]u8, ikm: []const u8) Hk {
    var r: Hk = undefined;
    Hmac.create(&r.temp, ikm, &ck);
    Hmac.create(&r.o1, &[_]u8{1}, &r.temp);
    var m: [33]u8 = undefined;
    m[0..32].* = r.o1;
    m[32] = 2;
    Hmac.create(&r.o2, &m, &r.temp);
    m[0..32].* = r.o2;
    m[32] = 3;
    Hmac.create(&r.o3, &m, &r.temp);
    return r;
}

fn seedOf(prng: std.Random.DefaultPrng) [32]u8 {
    var p = prng;
    var s: [32]u8 = undefined;
    p.random().bytes(&s);
    return s;
}

fn buildNeedles(n: *Needles) !void {
    reset();
    n.addKey("static key I", s_i.secret_key);
    n.addKey("static key R", s_r.secret_key);
    n.add("psk", psk_list[0]);
    const e_i = try Suite.KeyPair.generateDeterministic(seedOf(prng_i));
    const e_r = try Suite.KeyPair.generateDeterministic(seedOf(prng_r));
    n.addKey("ephemeral key I", e_i.secret_key);
    n.addKey("ephemeral key R", e_r.secret_key);
    const ee = try X25519.scalarmult(e_r.secret_key, e_i.public_key);
    const es = try X25519.scalarmult(e_i.secret_key, s_r.public_key);
    const se = try X25519.scalarmult(s_i.secret_key, e_r.public_key);
    n.add("ee", ee);
    n.add("es", es);
    n.add("se", se);

    // Walk the handshake once to learn ck after message 1.
    stepInitI();
    stepInitR();
    stepWrite1();
    stepRead1();
    const ck_a = hs_r.symmetric_state.ck;
    try std.testing.expectEqualSlices(u8, &hs_i.symmetric_state.ck, &ck_a);
    // Message 2: e (has_psk: MixKey(e.pub)), ee, es.
    const m_e = hkdf3(ck_a, &e_r.public_key);
    const m_ee = hkdf3(m_e.o1, &ee);
    const m_es = hkdf3(m_ee.o1, &es);
    n.add("temp_key (ee)", m_ee.temp);
    n.add("ck after ee", m_ee.o1);
    n.add("k after ee", m_ee.o2);
    n.add("temp_key (es)", m_es.temp);
    n.add("ck after es", m_es.o1);
    n.add("k after es", m_es.o2);
    stepWrite2();
    stepRead2();
    try std.testing.expectEqualSlices(u8, &hs_i.symmetric_state.ck, &m_es.o1);
    // Message 3: s, se, psk.
    const m_se = hkdf3(m_es.o1, &se);
    const m_psk = hkdf3(m_se.o1, &psk_list[0]);
    const m_sp = hkdf3(m_psk.o1, "");
    n.add("temp_key (se)", m_se.temp);
    n.add("ck after se", m_se.o1);
    n.add("k after se", m_se.o2);
    n.add("temp_key (psk)", m_psk.temp);
    n.add("ck after psk", m_psk.o1);
    n.add("MixKeyAndHash h-input", m_psk.o2);
    n.add("k after psk", m_psk.o3);
    n.add("temp_key (split)", m_sp.temp);
    n.add("transport key i2r", m_sp.o1);
    n.add("transport key r2i", m_sp.o2);
    stepWrite3();
    stepRead3();
    try std.testing.expectEqualSlices(u8, &tp_i[0].k, &m_sp.o1);
    try std.testing.expectEqualSlices(u8, &tp_r[1].k, &m_sp.o2);

    // The direct SymmetricState / CipherState calls.
    n.add("direct ikm", ikm_x);
    n.add("direct key", key_x);
    const d1 = hkdf3(hash("probe ck"), &ikm_x);
    n.add("direct temp_key (mixKey)", d1.temp);
    n.add("direct ck after mixKey", d1.o1);
    n.add("direct k after mixKey", d1.o2);
    const d2 = hkdf3(d1.o1, &ikm_x);
    n.add("direct temp_key (mixKeyAndHash)", d2.temp);
    n.add("direct ck after mixKeyAndHash", d2.o1);
    n.add("direct k after mixKeyAndHash", d2.o3);
    const d3 = hkdf3(d2.o1, "");
    n.add("direct temp_key (split)", d3.temp);
    n.add("direct split key 0", d3.o1);
    n.add("direct split key 1", d3.o2);
    n.add("rekey result k", rekeyed(tp_i[1].k));
    n.add("control", control);
}

/// What `rekey` leaves: ENCRYPT(k, 2^64-1, "", zeros)[0..32].
fn rekeyed(k: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    var tag: [16]u8 = undefined;
    var nonce = [_]u8{0} ** 12;
    std.mem.writeInt(u64, nonce[4..12], std.math.maxInt(u64), .little);
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(&out, &tag, &([_]u8{0} ** 32), "", nonce, k);
    return out;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

test "STACKPROBE noise (wave 9): no key, DH or HKDF residue on the dead stack after any entry point" {
    try skipUnlessOptimized();

    s_i = try Suite.KeyPair.generateDeterministic(hash("static I"));
    s_r = try Suite.KeyPair.generateDeterministic(hash("static R"));
    psk_list[0] = hash("psk");
    ikm_x = hash("direct ikm");
    key_x = hash("direct key");
    control = hash("control");

    var needles: Needles = .{};
    try buildNeedles(&needles);
    const nd = needles.slice();
    const ctl = nd.len - 1;

    var neg: [max_needles]usize = @splat(0);
    measure(callInnocent);
    countAll(nd, neg[0..nd.len]);

    var pos: [max_needles]usize = @splat(0);
    measure(callLeaky);
    countAll(nd, pos[0..nd.len]);

    var hits: [steps.len][max_needles]usize = @splat(@splat(0));
    var depth: [steps.len]usize = @splat(0);
    var shallow: [steps.len]usize = @splat(0);
    var deep: [steps.len]usize = @splat(0);
    for (0..3) |_| {
        reset();
        // The direct calls need a keyed transport pair from the handshake.
        for (steps, &hits, &depth, &shallow, &deep) |st, *h, *d, *s, *dp| {
            resetDepths();
            measure(st.call);
            d.* = @max(d.*, dirtyDepth());
            countAll(nd, h[0..nd.len]);
            if (hit_min_depth != 0 and (s.* == 0 or hit_min_depth < s.*)) s.* = hit_min_depth;
            dp.* = @max(dp.*, hit_max_depth);
        }
    }

    var bad = pos[ctl] < 1;
    for (neg[0..nd.len]) |x| bad = bad or x != 0;
    var total: usize = 0;
    for (&hits) |*h| for (h[0..nd.len]) |x| {
        total += x;
    };
    bad = bad or total != 0;
    if (verbose or bad) {
        std.debug.print("\n=== STACKPROBE noise ({t}, window {d} KiB) NEG={any} POS(control)={d} needles={d} total residue={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg[0..nd.len], pos[ctl], nd.len, total });
        for (steps, &hits, depth, shallow, deep) |st, *h, d, s, dp| {
            std.debug.print("  {s:<40} dirty={d} B, hits {d}..{d} B\n", .{ st.name, d, s, dp });
            for (nd, h[0..nd.len]) |n, x| {
                if (x != 0) std.debug.print("    RESIDUE {s:<34} {d} (3 runs)\n", .{ n.name, x });
            }
        }
    }
    if (bad) return error.TestUnexpectedResult;
}

// ── burn sizes per suite (2026-10-09) ────────────────────────────────────────
//
// The needle probe above runs the default suite only. The burns are sized per
// suite (`burn.Sizes`, from `state.stack_bytes`), so this part checks the
// sizing itself, on every std suite plus a P-384 adapter: (1) each std
// primitive dirties no more than `stack_bytes` claims; (2) each burned entry
// point's dirty depth stays within its burn. (2) cannot tell zeros the burn
// wrote from bytes the body wrote, so it compares depths: the burn starts
// `burn_offset` below the region top (calibrated with a known burn under the
// same step/shim frames) and the body may not reach more than `burn_slack`
// below its end — the entry point's own frame sits between the two.

const state = @import("state.zig");
const burn_mod = @import("burn.zig");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const StdChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const sha2 = std.crypto.hash.sha2;
const blake2 = std.crypto.hash.blake2;

const burn_slack = 512;

/// A P-384 DH in the Noise DH shape (test-only, not a spec name): the deeper
/// pluggable DH the fixed 8 KiB handshake burn could not cover.
fn P384Dh(comptime declared: usize) type {
    return struct {
        const P384 = std.crypto.ecc.P384;
        pub const noise_name = "P384";
        pub const noise_stack_bytes = declared;
        pub const public_length = 49;
        pub const seed_length = 48;
        pub const KeyPair = struct {
            public_key: [49]u8,
            secret_key: [48]u8,
            pub fn generateDeterministic(seed: [48]u8) !KeyPair {
                const p = try P384.basePoint.mul(seed, .big);
                return .{ .public_key = p.toCompressedSec1(), .secret_key = seed };
            }
        };
        pub fn scalarmult(secret: [48]u8, public: [49]u8) ![49]u8 {
            const p = try P384.fromSec1(&public);
            return (try p.mul(secret, .big)).toCompressedSec1();
        }
    };
}

/// The same DH with no `noise_stack_bytes`: the burn falls back to
/// `unknown_dh_stack`.
const P384Undeclared = struct {
    const D = P384Dh(0);
    pub const noise_name = D.noise_name;
    pub const public_length = D.public_length;
    pub const seed_length = D.seed_length;
    pub const KeyPair = D.KeyPair;
    pub const scalarmult = D.scalarmult;
};

/// AES-256-GCM under a declared name and no `noise_stack_bytes`: the
/// fallback cipher size.
const AesUndeclared = struct {
    pub const noise_name = "AESGCM";
    pub const key_length = Aes256Gcm.key_length;
    pub const nonce_length = Aes256Gcm.nonce_length;
    pub const tag_length = Aes256Gcm.tag_length;
    pub const encrypt = Aes256Gcm.encrypt;
    pub const decrypt = Aes256Gcm.decrypt;
};

var cal_offset: usize = 0;
var chachapoly_depth: usize = 0;
noinline fn calBody() void {
    var x: [64]u8 = undefined;
    std.mem.doNotOptimizeAway(&x);
}
noinline fn calEntry() void {
    burn_mod.run(4096, void, calBody, .{});
}
noinline fn stepCal() void {
    calEntry();
}

/// The depth the burns start at under `measure` + a step function.
fn calibrate() void {
    measure(stepCal);
    cal_offset = dirtyDepth() - 4096;
}

fn Coverage(comptime S: type) type {
    return struct {
        const HSs = S.HandshakeState;
        const CSs = S.CipherState;
        const SSs = S.SymmetricState;
        const B = S.burns;

        var si: S.KeyPair = undefined;
        var sr: S.KeyPair = undefined;
        var psks: [1][32]u8 = undefined;
        var hi: HSs = undefined;
        var hr: HSs = undefined;
        var ri: std.Random.DefaultPrng = undefined;
        var rr: std.Random.DefaultPrng = undefined;
        var w: [512]u8 = undefined;
        var wl: usize = 0;
        var p: [128]u8 = undefined;
        var ti: [2]CSs = undefined;
        var tr: [2]CSs = undefined;
        var c: [plaintext.len + 16]u8 = undefined;
        var b: [plaintext.len]u8 = undefined;
        var ssx: SSs = undefined;
        var tx: [2]CSs = undefined;

        fn seed(comptime label: []const u8) [S.Dh.seed_length]u8 {
            var out: [S.Dh.seed_length]u8 = undefined;
            std.crypto.hash.sha3.Shake256.hash("noise-probe/" ++ label, &out, .{});
            return out;
        }

        noinline fn initI() void {
            hi.init(pattern, true, "", &.{ .s = &si, .psks = &psks }) catch unreachable;
        }
        noinline fn initR() void {
            hr.init(pattern, false, "", &.{ .s = &sr, .psks = &psks }) catch unreachable;
        }
        noinline fn writeI() void {
            wl = (hi.writeMessage(ri.random(), "", &w, &ti) catch unreachable).len;
        }
        noinline fn readR() void {
            _ = hr.readMessage(w[0..wl], &p, &tr) catch unreachable;
        }
        noinline fn writeR() void {
            wl = (hr.writeMessage(rr.random(), "", &w, &tr) catch unreachable).len;
        }
        noinline fn readI() void {
            _ = hi.readMessage(w[0..wl], &p, &ti) catch unreachable;
        }
        noinline fn encrypt() void {
            ti[0].encryptWithAd("", plaintext, &c) catch unreachable;
        }
        noinline fn decrypt() void {
            tr[0].decryptWithAd("", &c, &b) catch unreachable;
        }
        noinline fn rekey() void {
            ti[1].rekey();
        }
        noinline fn mixKey() void {
            ssx.mixKey("probe ikm");
        }
        noinline fn mixKeyAndHash() void {
            ssx.mixKeyAndHash("probe ikm");
        }
        noinline fn split() void {
            ssx.split(&tx);
        }

        const Step = struct { name: []const u8, call: *const fn () void, burn: usize };
        const cov_steps = [_]Step{
            .{ .name = "init (I)", .call = initI, .burn = B.init },
            .{ .name = "init (R)", .call = initR, .burn = B.init },
            .{ .name = "writeMessage 1 (I)", .call = writeI, .burn = B.hs },
            .{ .name = "readMessage 1 (R)", .call = readR, .burn = B.hs },
            .{ .name = "writeMessage 2 (R)", .call = writeR, .burn = B.hs },
            .{ .name = "readMessage 2 (I)", .call = readI, .burn = B.hs },
            .{ .name = "writeMessage 3 (I)", .call = writeI, .burn = B.hs },
            .{ .name = "readMessage 3 (R)", .call = readR, .burn = B.hs },
            .{ .name = "encryptWithAd", .call = encrypt, .burn = B.cipher },
            .{ .name = "decryptWithAd", .call = decrypt, .burn = B.cipher },
            .{ .name = "rekey", .call = rekey, .burn = B.cipher },
            .{ .name = "mixKey", .call = mixKey, .burn = B.hkdf },
            .{ .name = "mixKeyAndHash", .call = mixKeyAndHash, .burn = B.hkdf },
            .{ .name = "split", .call = split, .burn = B.hkdf },
        };

        /// Returns the number of steps whose body outgrew its burn.
        fn check() !usize {
            si = try S.KeyPair.generateDeterministic(seed("static I"));
            sr = try S.KeyPair.generateDeterministic(seed("static R"));
            psks[0] = hash("psk");
            ri = .init(0x7015_0011);
            rr = .init(0x7015_0012);
            ssx = .{};
            var over: usize = 0;
            const name = "Noise_XXpsk3" ++ S.name_suffix;
            if (verbose) std.debug.print("  {s}: burns cipher {d} hkdf {d} init {d} hs {d}\n", .{ name, B.cipher, B.hkdf, B.init, B.hs });
            for (cov_steps) |st| {
                measure(st.call);
                const d = dirtyDepth();
                // `chachapoly` zeroes its own tree (its own probe checks
                // that), so under a cipher step the deepest bytes are its
                // burn, not this module's.
                const own = if (st.burn == B.cipher and S.AeadCipher == noise.ChaCha20Poly1305) @max(st.burn, chachapoly_depth) else st.burn;
                const limit = cal_offset + own + burn_slack;
                if (verbose or d > limit) std.debug.print("    {s:<22} dirty {d} B, burn {d} B, limit {d} B{s}\n", .{ st.name, d, st.burn, limit, if (d > limit) "  OUTGROWN" else "" });
                if (d > limit) over += 1;
            }
            return over;
        }
    };
}

fn primitiveDepth(call: *const fn () void) usize {
    measure(call);
    return dirtyDepth() - cal_offset;
}

fn DhDepth(comptime D: type) type {
    return struct {
        var kp: D.KeyPair = undefined;
        var out: [D.public_length]u8 = undefined;
        noinline fn gen() void {
            kp = D.KeyPair.generateDeterministic(@splat(0x42)) catch unreachable;
        }
        noinline fn mul() void {
            out = D.scalarmult(kp.secret_key, kp.public_key) catch unreachable;
        }
    };
}

fn AeadDepth(comptime A: type) type {
    return struct {
        var key: [32]u8 = @splat(7);
        var c: [plaintext.len]u8 = undefined;
        var t: [16]u8 = undefined;
        var m: [plaintext.len]u8 = undefined;
        noinline fn enc() void {
            A.encrypt(&c, &t, plaintext, "", @splat(0), key);
        }
        noinline fn dec() void {
            A.decrypt(&m, &c, t, "", @splat(0), key) catch unreachable;
        }
    };
}

fn HmacDepth(comptime H: type) type {
    return struct {
        const M = std.crypto.auth.hmac.Hmac(H);
        var key: [H.digest_length]u8 = @splat(7);
        var out: [H.digest_length]u8 = undefined;
        noinline fn mac() void {
            M.create(&out, "probe message", &key);
        }
    };
}

var over_claims: usize = 0;
fn expectWithin(comptime name: []const u8, used: usize, claimed: usize) void {
    if (verbose or used > claimed) std.debug.print("  {s:<44} {d} B (claimed {d} B){s}\n", .{ name, used, claimed, if (used > claimed) "  OVER" else "" });
    if (used > claimed) over_claims += 1;
}

test "STACKPROBE noise: std primitives dirty no more stack than state.stack_bytes claims" {
    try skipUnlessOptimized();
    calibrate();
    over_claims = 0;
    const X = DhDepth(X25519);
    expectWithin("X25519 generateDeterministic", primitiveDepth(X.gen), state.stack_bytes.dh(X25519));
    expectWithin("X25519 scalarmult", primitiveDepth(X.mul), state.stack_bytes.dh(X25519));
    const P = DhDepth(P384Dh(0));
    // Not a std type: only printed, to size the adapter's declaration below.
    if (verbose) std.debug.print("  P-384 adapter: generate {d} B, scalarmult {d} B\n", .{ primitiveDepth(P.gen), primitiveDepth(P.mul) });
    inline for (.{ .{ "std ChaChaPoly", StdChaCha }, .{ "AES-256-GCM", Aes256Gcm } }) |a| {
        const D = AeadDepth(a[1]);
        expectWithin(a[0] ++ " encrypt", primitiveDepth(D.enc), state.stack_bytes.cipher(a[1]));
        expectWithin(a[0] ++ " decrypt", primitiveDepth(D.dec), state.stack_bytes.cipher(a[1]));
    }
    inline for (.{ .{ "SHA256", sha2.Sha256 }, .{ "SHA512", sha2.Sha512 }, .{ "BLAKE2s", blake2.Blake2s256 }, .{ "BLAKE2b", blake2.Blake2b512 } }) |h| {
        expectWithin("HMAC-" ++ h[0], primitiveDepth(HmacDepth(h[1]).mac), state.stack_bytes.hash(h[1]));
    }
    try std.testing.expectEqual(@as(usize, 0), over_claims);
}

test "STACKPROBE noise: every burned entry point stays within its burn, on every std suite and a P-384 DH" {
    try skipUnlessOptimized();
    calibrate();
    chachapoly_depth = primitiveDepth(AeadDepth(noise.ChaCha20Poly1305).dec);
    if (verbose) std.debug.print("\n=== STACKPROBE noise burn sizes ({t}), burn offset {d} B ===\n", .{ builtin.mode, cal_offset });
    var over: usize = 0;
    inline for (.{ chachapolyType(), StdChaCha, Aes256Gcm }) |A| {
        inline for (.{ sha2.Sha256, sha2.Sha512, blake2.Blake2s256, blake2.Blake2b512 }) |H| {
            over += try Coverage(state.Suite(X25519, A, H)).check();
        }
    }
    over += try Coverage(state.Suite(P384Dh(16 * 1024), Aes256Gcm, sha2.Sha512)).check();
    over += try Coverage(state.Suite(P384Undeclared, AesUndeclared, sha2.Sha512)).check();
    try std.testing.expectEqual(@as(usize, 0), over);
}

fn chachapolyType() type {
    return noise.ChaCha20Poly1305;
}
