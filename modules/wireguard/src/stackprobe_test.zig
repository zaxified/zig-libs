// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `wireguard` (wave 9, 2026-10-09; SPEC §
//! "Secret residue on the dead stack"). Engine as `noise`'s and `bolt8`'s
//! probes: a painted region below the probe, one call run under a `PAD`-deep
//! shim, the region scanned for 32-byte needles. ReleaseFast/ReleaseSmall only.
//!
//! A full Noise_IKpsk2 handshake (both roles), the transport-key split, the
//! session constructors, one `seal` and one `open`, plus the bare KDF calls,
//! one probed call per step on GLOBAL state. Needles: the static and ephemeral
//! private keys (raw and as X25519 clamps them), the PSK, the DH outputs, every
//! HKDF `temp_key`, the chaining and AEAD keys after each KDF step, the psk2
//! `tau`/`k`, and the two transport keys; all recomputed here from the fixed
//! inputs with std's HMAC-BLAKE2s. The ephemerals are pre-seeded (the module's
//! deterministic-test hook); `Keypair.generate` and the generated-ephemeral
//! `createInitiation` get their needle post hoc, from the result.
//!
//! ⛔ A zero is only readable next to the two controls: NEG (a call that never
//! sees a secret finds 0) and POS (a call that parks the control needle in a
//! local finds it).

const std = @import("std");
const builtin = @import("builtin");
const wg = @import("root.zig");

const noise = wg.noise;
const hs = wg.handshake;
const tr = wg.transport;
const X25519 = std.crypto.dh.X25519;
const Hmac = noise.HmacBlake2s;

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

// ── API adapter: the ONLY block that changes with the wireguard API ─────────

fn apiFromPriv(priv: *const hs.PrivateKey, out: *hs.Keypair) void {
    hs.Keypair.fromPrivateKey(priv, out) catch unreachable;
}
fn apiGenerate(io: std.Io, out: *hs.Keypair) void {
    hs.Keypair.generate(io, out);
}
fn apiCreateInitiation(h: *hs.Handshake, io: std.Io, out: *hs.MessageInitiation) void {
    out.* = h.createInitiation(io, ts) catch unreachable;
}
fn apiConsumeInitiation(h: *hs.Handshake, msg: *const hs.MessageInitiation) void {
    h.consumeInitiation(msg.*) catch unreachable;
}
fn apiCreateResponse(h: *hs.Handshake, io: std.Io, out: *hs.MessageResponse) void {
    out.* = h.createResponse(io) catch unreachable;
}
fn apiConsumeResponse(h: *hs.Handshake, msg: *const hs.MessageResponse) void {
    h.consumeResponse(msg.*) catch unreachable;
}
fn apiDerive(h: *hs.Handshake, is_initiator: bool, out: *tr.TransportKeys) void {
    h.deriveTransportKeys(is_initiator, out);
}
fn apiSendInit(out: *tr.SendSession, key: *const [32]u8) void {
    out.init(key, 0x1234, 1000);
}
fn apiRecvInit(out: *tr.RecvSession, key: *const [32]u8) void {
    out.init(key, 0x1234, 1000);
}
fn apiSessionInit(out: *tr.Session, keys: *const tr.TransportKeys) void {
    out.init(keys, 7, 8, 1000);
}
fn apiTransportSession(h: *hs.Handshake, is_initiator: bool, out: *tr.Session) void {
    h.transportSession(is_initiator, 1000, out);
}
fn apiKdf1(ck: *noise.ChainKey, input: []const u8) void {
    noise.kdf1(ck, input);
}
fn apiKdf2(ck: *noise.ChainKey, input: []const u8, out: *noise.SymmetricKey) void {
    noise.kdf2(ck, input, out);
}
fn apiKdf3(ck: *noise.ChainKey, input: []const u8, o1: *noise.SymmetricKey, o2: *noise.SymmetricKey) void {
    noise.kdf3(ck, input, o1, o2);
}
fn apiMixKey(ck: *noise.ChainKey, input: []const u8, out: *noise.SymmetricKey) void {
    noise.mixKey(ck, input, out);
}

// ── global state and the probed calls ───────────────────────────────────────

const ts: [12]u8 = .{ 0x40, 0, 0, 0, 0x65, 0x4a, 0x3b, 0x2c, 1, 2, 3, 4 };
var k_si: hs.Keypair = undefined;
var k_sr: hs.Keypair = undefined;
var k_ei: hs.Keypair = undefined;
var k_er: hs.Keypair = undefined;
var psk: hs.PresharedKey = undefined;
var priv_in: hs.PrivateKey = undefined;
var h_i: hs.Handshake = undefined;
var h_r: hs.Handshake = undefined;
var h_g: hs.Handshake = undefined; // generated-ephemeral run
var m1: hs.MessageInitiation = undefined;
var m2: hs.MessageResponse = undefined;
var m1_g: hs.MessageInitiation = undefined;
var kp_out: hs.Keypair = undefined;
var kp_gen: hs.Keypair = undefined;
var keys_i: tr.TransportKeys = undefined;
var keys_r: tr.TransportKeys = undefined;
var sess_a: tr.Session = undefined;
var sess_i: tr.Session = undefined;
var sess_r: tr.Session = undefined;
var send_s: tr.SendSession = undefined;
var recv_s: tr.RecvSession = undefined;
var send_key: [32]u8 = undefined;
var wire: [tr.header_len + 48 + tr.tag_len]u8 = undefined;
var wire_len: usize = 0;
var plain_in: [32]u8 = undefined;
var plain_out: [48]u8 = undefined;
var ck_x: noise.ChainKey = undefined;
var ikm_x: [32]u8 = undefined;
var out_a: noise.SymmetricKey = undefined;
var out_b: noise.SymmetricKey = undefined;
var io_g: std.Io = undefined;

fn reset() void {
    h_i = .{ .static_keypair = k_si, .remote_static_public = k_sr.public, .preshared_key = psk, .local_ephemeral = k_ei, .local_index = 0x1111 };
    h_r = .{ .static_keypair = k_sr, .remote_static_public = k_si.public, .preshared_key = psk, .local_ephemeral = k_er, .local_index = 0x2222 };
    h_g = .{ .static_keypair = k_si, .remote_static_public = k_sr.public, .preshared_key = psk, .local_index = 0x3333 };
    ck_x = hash("direct ck");
    keys_i = undefined;
    keys_r = undefined;
}

fn hash(comptime label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("wireguard-probe/" ++ label, &out, .{});
    return out;
}

noinline fn stepFromPriv() void {
    apiFromPriv(&priv_in, &kp_out);
}
noinline fn stepGenerate() void {
    apiGenerate(io_g, &kp_gen);
}
noinline fn stepCreateInitiation() void {
    apiCreateInitiation(&h_i, io_g, &m1);
}
noinline fn stepCreateInitiationGen() void {
    apiCreateInitiation(&h_g, io_g, &m1_g);
}
noinline fn stepConsumeInitiation() void {
    apiConsumeInitiation(&h_r, &m1);
}
noinline fn stepCreateResponse() void {
    apiCreateResponse(&h_r, io_g, &m2);
}
noinline fn stepConsumeResponse() void {
    apiConsumeResponse(&h_i, &m2);
}
noinline fn stepDeriveI() void {
    apiDerive(&h_i, true, &keys_i);
}
noinline fn stepDeriveR() void {
    apiDerive(&h_r, false, &keys_r);
}
noinline fn stepSendInit() void {
    apiSendInit(&send_s, &send_key);
}
noinline fn stepRecvInit() void {
    apiRecvInit(&recv_s, &send_key);
}
noinline fn stepSessionInit() void {
    apiSessionInit(&sess_a, &keys_i);
}
noinline fn stepSeal() void {
    const r = send_s.seal(&wire, &plain_in, 1000) catch unreachable;
    wire_len = r.len;
}
noinline fn stepOpen() void {
    _ = recv_s.open(&plain_out, wire[0..wire_len], 1000) catch unreachable;
}
noinline fn stepKdf1() void {
    apiKdf1(&ck_x, &ikm_x);
}
noinline fn stepKdf2() void {
    apiKdf2(&ck_x, &ikm_x, &out_a);
}
noinline fn stepKdf3() void {
    apiKdf3(&ck_x, &ikm_x, &out_a, &out_b);
}
noinline fn stepMixKey() void {
    apiMixKey(&ck_x, &ikm_x, &out_a);
}

const Step = struct { name: []const u8, call: *const fn () void };
// Order matters: later steps consume the state earlier ones leave.
const steps = [_]Step{
    .{ .name = "Keypair.fromPrivateKey", .call = stepFromPriv },
    .{ .name = "Keypair.generate", .call = stepGenerate },
    .{ .name = "createInitiation (generated e)", .call = stepCreateInitiationGen },
    .{ .name = "createInitiation (I)", .call = stepCreateInitiation },
    .{ .name = "consumeInitiation (R)", .call = stepConsumeInitiation },
    .{ .name = "createResponse (R)", .call = stepCreateResponse },
    .{ .name = "consumeResponse (I)", .call = stepConsumeResponse },
    .{ .name = "deriveTransportKeys (I)", .call = stepDeriveI },
    .{ .name = "deriveTransportKeys (R)", .call = stepDeriveR },
    .{ .name = "SendSession.init", .call = stepSendInit },
    .{ .name = "RecvSession.init", .call = stepRecvInit },
    .{ .name = "Session.init", .call = stepSessionInit },
    .{ .name = "SendSession.seal", .call = stepSeal },
    .{ .name = "RecvSession.open", .call = stepOpen },
    .{ .name = "noise.kdf1", .call = stepKdf1 },
    .{ .name = "noise.kdf2", .call = stepKdf2 },
    .{ .name = "noise.kdf3", .call = stepKdf3 },
    .{ .name = "noise.mixKey", .call = stepMixKey },
};

// ── the needles, recomputed from the fixed inputs ────────────────────────────

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

fn buildNeedles(n: *Needles) !void {
    n.addKey("static key I", k_si.private);
    n.addKey("static key R", k_sr.private);
    n.addKey("ephemeral key I", k_ei.private);
    n.addKey("ephemeral key R", k_er.private);
    n.add("psk", psk);
    n.addKey("fromPrivateKey input", priv_in);
    const es = try X25519.scalarmult(k_ei.private, k_sr.public);
    const ss = try X25519.scalarmult(k_si.private, k_sr.public);
    const ee = try X25519.scalarmult(k_er.private, k_ei.public);
    const se = try X25519.scalarmult(k_er.private, k_si.public);
    n.add("es", es);
    n.add("ss", ss);
    n.add("ee", ee);
    n.add("se", se);

    // Walk the chaining key from Ck0 through the whole handshake.
    var ck0: [32]u8 = undefined;
    noise.Blake2s.hash(noise.CONSTRUCTION, &ck0, .{});
    const k_e = hkdf3(ck0, &k_ei.public);
    const m_es = hkdf3(k_e.o1, &es);
    const m_ss = hkdf3(m_es.o1, &ss);
    n.add("temp_key (es)", m_es.temp);
    n.add("ck after es", m_es.o1);
    n.add("k (es)", m_es.o2);
    n.add("temp_key (ss)", m_ss.temp);
    n.add("ck after ss", m_ss.o1);
    n.add("k (ss)", m_ss.o2);
    const r_e = hkdf3(m_ss.o1, &k_er.public);
    const m_ee = hkdf3(r_e.o1, &ee);
    const m_se = hkdf3(m_ee.o1, &se);
    const m_psk = hkdf3(m_se.o1, &psk);
    const m_sp = hkdf3(m_psk.o1, "");
    n.add("temp_key (ee)", m_ee.temp);
    n.add("ck after ee", m_ee.o1);
    n.add("temp_key (se)", m_se.temp);
    n.add("ck after se", m_se.o1);
    n.add("temp_key (psk)", m_psk.temp);
    n.add("ck after psk", m_psk.o1);
    n.add("psk tau", m_psk.o2);
    n.add("psk k", m_psk.o3);
    n.add("temp_key (split)", m_sp.temp);
    n.add("transport key T1", m_sp.o1);
    n.add("transport key T2", m_sp.o2);

    // The bare KDF calls on ck_x / ikm_x, chained in step order.
    n.add("direct ikm", ikm_x);
    const d0 = hash("direct ck");
    const d1 = hkdf3(d0, &ikm_x); // kdf1
    n.add("direct temp (kdf1)", d1.temp);
    n.add("direct ck (kdf1)", d1.o1);
    const d2 = hkdf3(d1.o1, &ikm_x); // kdf2
    n.add("direct temp (kdf2)", d2.temp);
    n.add("direct ck (kdf2)", d2.o1);
    n.add("direct out (kdf2)", d2.o2);
    const d3 = hkdf3(d2.o1, &ikm_x); // kdf3
    n.add("direct temp (kdf3)", d3.temp);
    n.add("direct ck (kdf3)", d3.o1);
    n.add("direct out1 (kdf3)", d3.o2);
    n.add("direct out2 (kdf3)", d3.o3);
    const d4 = hkdf3(d3.o1, &ikm_x); // mixKey
    n.add("direct temp (mixKey)", d4.temp);
    n.add("direct ck (mixKey)", d4.o1);
    n.add("direct out (mixKey)", d4.o2);

    n.add("send_key (session)", send_key);
    n.add("control", control);
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

test "STACKPROBE wireguard (wave 9): no key, DH or KDF residue on the dead stack after any handshake, session or KDF call" {
    try skipUnlessOptimized();

    io_g = std.testing.io;
    priv_in = hash("static I");
    try hs.Keypair.fromPrivateKey(&priv_in, &k_si);
    priv_in = hash("static R");
    try hs.Keypair.fromPrivateKey(&priv_in, &k_sr);
    priv_in = hash("eph I");
    try hs.Keypair.fromPrivateKey(&priv_in, &k_ei);
    priv_in = hash("eph R");
    try hs.Keypair.fromPrivateKey(&priv_in, &k_er);
    psk = hash("psk");
    priv_in = hash("fromPrivateKey input");
    ikm_x = hash("direct ikm");
    send_key = hash("session send key");
    plain_in = hash("plaintext");
    control = hash("control");

    var needles: Needles = .{};
    try buildNeedles(&needles);
    const base_len = needles.len;
    const ctl = base_len - 1;

    var neg: [max_needles]usize = @splat(0);
    measure(callInnocent);
    countAll(needles.slice(), neg[0..base_len]);

    var pos: [max_needles]usize = @splat(0);
    measure(callLeaky);
    countAll(needles.slice(), pos[0..base_len]);

    var hits: [steps.len][max_needles]usize = @splat(@splat(0));
    var depth: [steps.len]usize = @splat(0);
    var shallow: [steps.len]usize = @splat(0);
    var deep: [steps.len]usize = @splat(0);
    // Post-hoc needles: what the generating calls drew.
    var post_gen: [4]Needle = undefined;
    var post_hits: [2][4]usize = @splat(@splat(0));
    for (0..3) |_| {
        reset();
        for (steps, &hits, &depth, &shallow, &deep, 0..) |st, *h, *d, *s, *dp, si| {
            resetDepths();
            measure(st.call);
            d.* = @max(d.*, dirtyDepth());
            countAll(needles.slice(), h[0..base_len]);
            if (si == 1 or si == 2) {
                // The keypair the call just generated: its private key, raw and clamped.
                const priv = if (si == 1) kp_gen.private else h_g.local_ephemeral.?.private;
                post_gen[0] = .{ .name = "generated private key", .bytes = priv };
                var c = priv;
                c[0] &= 248;
                c[31] = (c[31] & 127) | 64;
                post_gen[1] = .{ .name = "generated private key (clamped)", .bytes = c };
                const idx = si - 1;
                // The snapshot is still in `snap`.
                post_hits[idx][0] += countIn(&post_gen[0].bytes);
                post_hits[idx][1] += countIn(&post_gen[1].bytes);
            }
            if (hit_min_depth != 0 and (s.* == 0 or hit_min_depth < s.*)) s.* = hit_min_depth;
            dp.* = @max(dp.*, hit_max_depth);
        }
    }

    var bad = pos[ctl] < 1;
    for (neg[0..base_len]) |x| bad = bad or x != 0;
    var total: usize = 0;
    for (&hits) |*h| for (h[0..base_len]) |x| {
        total += x;
    };
    for (post_hits) |ph| for (ph[0..2]) |x| {
        total += x;
    };
    bad = bad or total != 0;
    if (verbose or bad) {
        std.debug.print("\n=== STACKPROBE wireguard ({t}, window {d} KiB) NEG={any} POS(control)={d} needles={d}(+2 post hoc) total residue={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg[0..base_len], pos[ctl], base_len, total });
        for (steps, &hits, depth, shallow, deep, 0..) |st, *h, d, s, dp, si| {
            std.debug.print("  {s:<34} dirty={d} B, hits {d}..{d} B\n", .{ st.name, d, s, dp });
            for (needles.slice(), h[0..base_len]) |nn, x| {
                if (x != 0) std.debug.print("    RESIDUE {s:<34} {d} (3 runs)\n", .{ nn.name, x });
            }
            if (si == 1 or si == 2) {
                for (post_hits[si - 1], 0..) |x, j| {
                    if (j < 2 and x != 0) std.debug.print("    RESIDUE generated private key {s} {d} (3 runs)\n", .{ if (j == 0) "raw" else "clamped", x });
                }
            }
        }
    }
    if (bad) return error.TestUnexpectedResult;
}

// ══ wave 9b: CookieChecker / PeerCookie, key text and the control plane ═════
//
// Second test of this file, same engine. Needles are variable-length here (the
// cookie is 16 bytes, a base64 key 44). Calls with a secret drawn INTERNALLY
// (`CookieChecker.init`/`refresh`, the cookie reply nonce) run under a
// RECORDING `std.Io` (a copy of `Threaded`'s vtable whose `randomSecure` is
// deterministic, as megolm's and signal's probes do); what they drew is read
// back from the result (`extra` needles of a step). Heap blocks of the
// control plane are checked too: the call runs on a bump allocator that never
// reuses or resizes, so every superseded block stays visible, and after the
// last `deinit` of a sequence the whole arena is scanned for the keys.
//
// NOT probed, by reasoning: `PeerCookie.init`/`recordSent` (only public values:
// a key derived from the peer's static PUBLIC key, a mac1 that is on the wire),
// and the XChaCha20 key, subkey and nonce of the cookie reply: the key is
// `HASH(LABEL_COOKIE || our_static_public)` and the nonce travels in the reply,
// so neither is secret. `Wireguard.setDevice`/`getDevice` need a netlink socket.

const Needle2 = struct { name: []const u8, bytes: []const u8 };

fn countBytes(needle: []const u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= WINDOW) : (i += 1) {
        if (snap[i] == needle[0] and std.mem.eql(u8, snap[i..][0..needle.len], needle)) {
            hits += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
        }
    }
    return hits;
}

fn countHeap(needle: []const u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= heap_buf.len) : (i += 1) {
        if (heap_buf[i] == needle[0] and std.mem.eql(u8, heap_buf[i..][0..needle.len], needle)) hits += 1;
    }
    return hits;
}

// recording Io

var cp_threaded: std.Io.Threaded = undefined;
var rec_vtable: std.Io.VTable = undefined;
var rec_counter: usize = 0;
var rec_io: std.Io = undefined;

fn recSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    var o: usize = 0;
    var blk: usize = 0;
    var h: [64]u8 = undefined;
    while (o < buf.len) : (blk += 1) {
        var s = std.crypto.hash.sha2.Sha512.init(.{});
        s.update("wireguard-cookie-probe-draw");
        s.update(std.mem.asBytes(&rec_counter));
        s.update(std.mem.asBytes(&blk));
        s.final(&h);
        const k = @min(64, buf.len - o);
        @memcpy(buf[o..][0..k], h[0..k]);
        o += k;
    }
    rec_counter += 1;
}

// bump heap that never reuses

var heap_buf: [64 * 1024]u8 align(16) = undefined;
var heap_top: usize = 0;

fn bumpAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
    const a = alignment.toByteUnits();
    const start = std.mem.alignForward(usize, heap_top, a);
    if (start + len > heap_buf.len) return null;
    heap_top = start + len;
    return heap_buf[start..].ptr;
}
fn bumpResize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
    return false;
}
fn bumpRemap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
    return null;
}
fn bumpFree(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {}
const bump_vtable: std.mem.Allocator.VTable = .{ .alloc = bumpAlloc, .resize = bumpResize, .remap = bumpRemap, .free = bumpFree };
var bump_dummy: u8 = 0;
fn bump() std.mem.Allocator {
    return .{ .ptr = &bump_dummy, .vtable = &bump_vtable };
}

// fixed inputs and state

const addr_bytes = [_]u8{ 0xc0, 0x00, 0x02, 0x4d, 0xca, 0x6c };
var sec_a: [32]u8 = undefined;
var sec_c: [32]u8 = undefined;
var cookie_a: noise.Mac = undefined;
var rpub: [32]u8 = undefined;
var ck_a: hs.CookieChecker = undefined;
var ck_b: hs.CookieChecker = undefined;
var ck_c: hs.CookieChecker = undefined;
var msg_valid: [148]u8 = undefined; // mac1 + a mac2 under cookie_a
var msg_plain: [148]u8 = undefined; // mac1 + all-zero mac2
var reply_g: hs.CookieReply = undefined;
var pc_a: hs.PeerCookie = undefined; // recordSent done, reply not consumed
var pc_b: hs.PeerCookie = undefined; // reply consumed
var cookie_out: noise.Mac = undefined;
var cookie_cur: ?noise.Mac = undefined;
var mac_out: noise.Mac = undefined;
var bool_out: bool = undefined;
var adm_out: hs.Admission = undefined;
var reply_out: hs.CookieReply = undefined;
var h_ck: hs.Handshake = undefined;
var m_ck: hs.MessageInitiation = undefined;

const cfg_priv_seed = "cfg private key";
var cfg_priv: wg.Key = undefined;
var cfg_psk: wg.Key = undefined;
var cfg_pub: wg.Key = undefined;
var cfg_b64: [wg.key_b64_len]u8 = undefined;
var key_out: wg.Key = undefined;
var reqs_g: wg.SetRequests = undefined;
var dump_buf: [1024]u8 = undefined; // canned GET payload
var dump_len: usize = 0;
var parser_g: wg.DeviceParser = undefined;
var dev_g: wg.Device = undefined;

fn buildMsg(out: *[148]u8, idx: u32, mac2_cookie: ?noise.Mac) void {
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], 1, .little);
    std.mem.writeInt(u32, out[4..8], idx, .little);
    const k1 = noise.mac1Key(rpub);
    out[116..132].* = noise.keyedMac(&k1, out[0..116]);
    if (mac2_cookie) |c| out[132..148].* = noise.keyedMac(&c, out[0..132]);
}

var cfg_g: wg.Config = undefined;
var cfg_ips: [1]wg.AllowedIp = undefined;
var cfg_peers: [1]wg.PeerConfig = undefined;
fn cfgForProbe() wg.Config {
    cfg_ips[0] = wg.AllowedIp.v4(.{ 10, 0, 0, 0 }, 24);
    cfg_peers[0] = .{ .public_key = cfg_pub, .preshared_key = cfg_psk, .allowed_ips = &cfg_ips };
    return .{ .ifname = "wg0", .private_key = cfg_priv, .listen_port = 51820, .peers = &cfg_peers };
}

fn cpReset() void {
    heap_top = 0;
    @memset(&heap_buf, 0);
    rec_counter = 0;
    apiMakeCheckers();
    cfg_g = cfgForProbe();
    ck_b = undefined;
    buildMsg(&msg_valid, 0x5151, cookie_a);
    buildMsg(&msg_plain, 0x5152, null);
    const f = hs.macFields(&msg_plain) catch unreachable;
    reply_g = ck_a.createReplyWithNonce(std.testing.io, 1000, f, &addr_bytes, @splat(0x42));
    pc_a = hs.PeerCookie.init(rpub);
    pc_a.recordSent(&msg_plain) catch unreachable;
    pc_b = pc_a;
    pc_b.consumeReply(reply_g, 1000) catch unreachable;
    h_ck = .{ .static_keypair = k_si, .remote_static_public = k_sr.public, .preshared_key = psk, .local_ephemeral = k_ei, .local_index = 0x1111, .cookie = cookie_a };
    // The canned GET dump: our own SET request's payload (same attribute grammar).
    var r = wg.buildSetRequests(std.testing.allocator, 0x1c, 1, cfgForProbe(), wg.default_max_msg_len) catch unreachable;
    defer r.deinit(std.testing.allocator);
    const mlen = std.mem.readInt(u32, r.buf[0..4], builtin.cpu.arch.endian());
    dump_len = mlen - 16; // past the 16-byte nlmsghdr
    @memcpy(dump_buf[0..dump_len], r.buf[16..mlen]);
    parser_g = wg.DeviceParser.init(bump());
}

// adapters: the ONLY block that changes with the cookie/control-plane API
fn apiMakeCheckers() void {
    hs.CookieChecker.initWithSecret(rpub, &sec_a, 1000, &ck_a);
    hs.CookieChecker.initWithSecret(rpub, &sec_c, 1000, &ck_c);
}
fn apiInitWithSecret() void {
    hs.CookieChecker.initWithSecret(rpub, &sec_a, 1000, &ck_b);
}
fn apiInit() void {
    hs.CookieChecker.init(rpub, rec_io, 1000, &ck_b);
}
fn apiRefresh() void {
    ck_c.refresh(rec_io, 2000);
}
fn apiCookieFor() void {
    ck_a.cookieFor(rec_io, 1000, &addr_bytes, &cookie_out);
}
fn apiCurrent() void {
    cookie_cur = pc_b.current(1001);
}
fn apiKeyFromB64() void {
    wg.keyFromBase64Into(&cfg_b64, &key_out) catch unreachable;
}

noinline fn cpInitWithSecret() void {
    apiInitWithSecret();
}
noinline fn cpInit() void {
    apiInit();
}
noinline fn cpRefresh() void {
    apiRefresh();
}
noinline fn cpCookieFor() void {
    apiCookieFor();
}
noinline fn cpCheckMac2() void {
    const f = hs.macFields(&msg_valid) catch unreachable;
    bool_out = ck_a.checkMac2(rec_io, 1000, f, &addr_bytes);
}
noinline fn cpCreateReply() void {
    const f = hs.macFields(&msg_plain) catch unreachable;
    reply_out = ck_a.createReply(rec_io, 1000, f, &addr_bytes);
}
noinline fn cpCreateReplyNonce() void {
    const f = hs.macFields(&msg_plain) catch unreachable;
    reply_out = ck_a.createReplyWithNonce(rec_io, 1000, f, &addr_bytes, @splat(0x43));
}
noinline fn cpAdmitReply() void {
    adm_out = ck_a.admit(rec_io, 1000, &msg_plain, &addr_bytes, true);
}
noinline fn cpAdmitAccept() void {
    adm_out = ck_a.admit(rec_io, 1000, &msg_valid, &addr_bytes, true);
}
noinline fn cpConsumeReply() void {
    pc_a.consumeReply(reply_g, 1000) catch unreachable;
}
noinline fn cpCurrent() void {
    apiCurrent();
}
noinline fn cpCreateInitiationCookie() void {
    m_ck = h_ck.createInitiation(rec_io, ts) catch unreachable;
}
noinline fn cpComputeMac2() void {
    mac_out = h_ck.computeMac2(&addr_bytes, cookie_a);
}
noinline fn cpBuildSet() void {
    reqs_g = wg.buildSetRequests(bump(), 0x1c, 1, cfg_g, wg.default_max_msg_len) catch unreachable;
}
noinline fn cpBuildSetFrom() void {
    reqs_g = wg.buildSetRequestsFrom(bump(), 0x1c, 1, &cfg_g, wg.default_max_msg_len) catch unreachable;
}
noinline fn cpDeinitSet() void {
    reqs_g.deinit(bump());
}
noinline fn cpFeed() void {
    parser_g.feed(dump_buf[0..dump_len]) catch unreachable;
}
noinline fn cpFinish() void {
    parser_g.finishInto(&dev_g) catch unreachable;
}
noinline fn cpDevDeinit() void {
    dev_g.deinit(bump());
    parser_g.deinit();
}
noinline fn cpKeyFromB64() void {
    apiKeyFromB64();
}

const Extra = struct { n: usize = 0, items: [4]Needle2 = undefined };
fn extraBSecret(e: *Extra) void {
    e.items[0] = .{ .name = "drawn Rm (init)", .bytes = &ck_b.secret };
    e.n = 1;
}
fn extraCSecret(e: *Extra) void {
    e.items[0] = .{ .name = "drawn Rm (refresh)", .bytes = &ck_c.secret };
    e.n = 1;
}
var cookie_b_dyn: noise.Mac = undefined;
fn extraBCookie(e: *Extra) void {
    cookie_b_dyn = noise.keyedMac(&ck_b.secret, &addr_bytes);
    e.items[0] = .{ .name = "cookie under drawn Rm", .bytes = &cookie_b_dyn };
    e.items[1] = .{ .name = "drawn Rm (init)", .bytes = &ck_b.secret };
    e.n = 2;
}

const Step2 = struct { name: []const u8, call: *const fn () void, extra: ?*const fn (*Extra) void = null, heap_check: bool = false, known: bool = false };
const steps2 = [_]Step2{
    .{ .name = "CookieChecker.initWithSecret", .call = cpInitWithSecret },
    .{ .name = "CookieChecker.init", .call = cpInit, .extra = extraBSecret },
    .{ .name = "CookieChecker.refresh", .call = cpRefresh, .extra = extraCSecret },
    .{ .name = "CookieChecker.cookieFor", .call = cpCookieFor },
    .{ .name = "CookieChecker.checkMac2", .call = cpCheckMac2 },
    .{ .name = "CookieChecker.createReply", .call = cpCreateReply },
    .{ .name = "CookieChecker.createReplyWithNonce", .call = cpCreateReplyNonce },
    .{ .name = "CookieChecker.admit (cookie_reply)", .call = cpAdmitReply },
    .{ .name = "CookieChecker.admit (accept)", .call = cpAdmitAccept },
    .{ .name = "PeerCookie.consumeReply", .call = cpConsumeReply },
    .{ .name = "PeerCookie.current", .call = cpCurrent },
    .{ .name = "createInitiation (with cookie)", .call = cpCreateInitiationCookie },
    .{ .name = "Handshake.computeMac2", .call = cpComputeMac2 },
    .{ .name = "keyFromBase64Into", .call = cpKeyFromB64 },
    .{ .name = "buildSetRequests (by-value cfg: arg copy)", .call = cpBuildSet, .known = true },
    .{ .name = "SetRequests.deinit (1)", .call = cpDeinitSet },
    .{ .name = "buildSetRequestsFrom", .call = cpBuildSetFrom },
    .{ .name = "SetRequests.deinit", .call = cpDeinitSet, .heap_check = true },
    .{ .name = "DeviceParser.feed", .call = cpFeed },
    .{ .name = "DeviceParser.finish", .call = cpFinish },
    .{ .name = "Device.deinit + DeviceParser.deinit", .call = cpDevDeinit, .heap_check = true },
};

const verbose2 = false;

test "STACKPROBE wireguard (wave 9b): no cookie, cookie-secret, key-text or interface-key residue on the dead stack or the freed heap" {
    try skipUnlessOptimized();

    cp_threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer cp_threaded.deinit();
    const base = cp_threaded.io();
    rec_vtable = base.vtable.*;
    rec_vtable.randomSecure = recSecure;
    rec_io = .{ .userdata = base.userdata, .vtable = &rec_vtable };

    var p: hs.PrivateKey = hash("static I");
    try hs.Keypair.fromPrivateKey(&p, &k_si);
    p = hash("static R");
    try hs.Keypair.fromPrivateKey(&p, &k_sr);
    p = hash("eph I");
    try hs.Keypair.fromPrivateKey(&p, &k_ei);
    psk = hash("psk");
    rpub = k_sr.public;
    sec_a = hash("cookie secret A");
    sec_c = hash("cookie secret C");
    cookie_a = noise.keyedMac(&sec_a, &addr_bytes);
    cfg_priv = hash(cfg_priv_seed);
    cfg_psk = hash("cfg preshared key");
    cfg_pub = hash("cfg peer public");
    cfg_b64 = wg.keyToBase64(cfg_priv);
    control = hash("control");

    const fixed = [_]Needle2{
        .{ .name = "cookie A", .bytes = &cookie_a },
        .{ .name = "Rm A", .bytes = &sec_a },
        .{ .name = "Rm C (old)", .bytes = &sec_c },
        .{ .name = "cfg private key", .bytes = &cfg_priv },
        .{ .name = "cfg preshared key", .bytes = &cfg_psk },
        .{ .name = "cfg private key base64", .bytes = &cfg_b64 },
        .{ .name = "control", .bytes = &control },
    };
    const ctl = fixed.len - 1;

    var neg: [fixed.len]usize = @splat(0);
    measure(callInnocent);
    for (fixed, &neg) |nd, *h| h.* += countBytes(nd.bytes);
    var pos: [fixed.len]usize = @splat(0);
    measure(callLeaky);
    for (fixed, &pos) |nd, *h| h.* += countBytes(nd.bytes);

    var total: usize = 0;
    var bad = pos[ctl] < 1;
    for (neg) |x| bad = bad or x != 0;

    var lines: [steps2.len][fixed.len + 4]usize = @splat(@splat(0));
    var depth: [steps2.len]usize = @splat(0);
    var heap_hits: [steps2.len][3]usize = @splat(@splat(0));
    var hmin: [steps2.len]usize = @splat(0);
    var hmax: [steps2.len]usize = @splat(0);
    for (0..3) |_| {
        cpReset();
        for (steps2, 0..) |st, si| {
            resetDepths();
            measure(st.call);
            depth[si] = @max(depth[si], dirtyDepth());
            for (fixed[0 .. fixed.len - 1], 0..) |nd, ni| lines[si][ni] += countBytes(nd.bytes);
            if (st.extra) |ex| {
                var e: Extra = .{};
                ex(&e);
                for (e.items[0..e.n], 0..) |nd, ni| lines[si][fixed.len + ni] += countBytes(nd.bytes);
            }
            hmin[si] = hit_min_depth;
            hmax[si] = @max(hmax[si], hit_max_depth);
            if (st.heap_check) {
                heap_hits[si][0] += countHeap(&cfg_priv);
                heap_hits[si][1] += countHeap(&cfg_psk);
                heap_hits[si][2] += countHeap(&cfg_b64);
            }
        }
    }
    for (&lines, steps2) |*l, st| for (l) |x| {
        if (!st.known) total += x;
    };
    for (heap_hits) |hh| for (hh) |x| {
        total += x;
    };
    bad = bad or total != 0;
    if (verbose2 or bad) {
        std.debug.print("\n=== STACKPROBE wireguard 9b ({t}, window {d} KiB) NEG={any} POS(control)={d} total residue={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg, pos[ctl], total });
        for (steps2, 0..) |st, si| {
            std.debug.print("  {s:<38} dirty={d} B, hits at {d}..{d} B\n", .{ st.name, depth[si], hmin[si], hmax[si] });
            for (fixed[0 .. fixed.len - 1], 0..) |nd, ni| {
                if (lines[si][ni] != 0) std.debug.print("    RESIDUE {s:<30} {d} (3 runs)\n", .{ nd.name, lines[si][ni] });
            }
            for (0..4) |ni| {
                if (lines[si][fixed.len + ni] != 0) std.debug.print("    RESIDUE extra#{d} {d} (3 runs)\n", .{ ni, lines[si][fixed.len + ni] });
            }
            if (st.heap_check) {
                std.debug.print("    HEAP after free: private key {d}, psk {d}, base64 {d} (3 runs)\n", .{ heap_hits[si][0], heap_hits[si][1], heap_hits[si][2] });
            }
        }
    }
    if (bad) return error.TestUnexpectedResult;
}
