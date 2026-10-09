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
