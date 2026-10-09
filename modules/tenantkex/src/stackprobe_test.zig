// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `tenantkex` (wave 9, 2026-10-09; SPEC § "Secret
//! residue on the dead stack"). Engine as `noise`'s and `bolt8`'s probes: a
//! painted region below the probe, one call run under a `PAD`-deep shim, the
//! region scanned for 32-byte needles. ReleaseFast/ReleaseSmall only.
//!
//! A full IK handshake through the public `Initiator`/`Responder` API, one
//! probed call per step, on GLOBAL state (what an `Initiator` legitimately
//! holds is never in the scanned window). Needles: both static and both
//! ephemeral private keys (raw and as X25519 clamps them), the four DH outputs
//! `es`/`ss`/`ee`/`se`, every HKDF `temp_key`, the chaining and cipher key
//! after each `MixKey`, and the two session keys; all recomputed here from the
//! observed states with std's HMAC.
//!
//! ⛔ A zero is only readable next to the two controls: NEG (a call that never
//! sees a secret finds 0) and POS (a call that parks the control needle in a
//! local finds it).

const std = @import("std");
const builtin = @import("builtin");
const tk = @import("root.zig");

const X25519 = std.crypto.dh.X25519;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

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

// ── API adapter: the ONLY block that changes with the tenantkex API ──────────

fn apiInitI() void {
    ini.init(&s_i, s_r.public_key, ctx);
}
fn apiInitR() void {
    rsp.init(&s_r, s_i.public_key, ctx);
}
fn apiWrite1() void {
    wire1_len = ini.writeMessage1(prng_i.random(), "", &wire1) catch unreachable;
}
fn apiRead1() void {
    _ = rsp.readMessage1(wire1[0..wire1_len], &pl) catch unreachable;
}
fn apiWrite2() void {
    wire2_len = rsp.writeMessage2(prng_r.random(), "", &wire2, &keys_r) catch unreachable;
}
fn apiRead2() void {
    _ = ini.readMessage2(wire2[0..wire2_len], &pl, &keys_i) catch unreachable;
}

// ── global state and the probed calls ───────────────────────────────────────

const ctx: tk.FabricContext = .{ .isid = 0x123456, .initiator_pe = 11, .responder_pe = 22 };
var s_i: tk.KeyPair = undefined;
var s_r: tk.KeyPair = undefined;
var ini: tk.Initiator = undefined;
var rsp: tk.Responder = undefined;
var prng_i: std.Random.DefaultPrng = undefined;
var prng_r: std.Random.DefaultPrng = undefined;
var wire1: [tk.message1Len(0)]u8 = undefined;
var wire2: [tk.message2Len(0)]u8 = undefined;
var wire1_len: usize = 0;
var wire2_len: usize = 0;
var pl: [16]u8 = undefined;
var keys_i: tk.SessionKeys = undefined;
var keys_r: tk.SessionKeys = undefined;

fn reset() void {
    prng_i = .init(0x7e17_0001);
    prng_r = .init(0x7e17_0002);
    ini = undefined;
    rsp = undefined;
    keys_i = undefined;
    keys_r = undefined;
}

fn hash(comptime label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("tenantkex-probe/" ++ label, &out, .{});
    return out;
}

noinline fn stepInitI() void {
    apiInitI();
}
noinline fn stepInitR() void {
    apiInitR();
}
noinline fn stepWrite1() void {
    apiWrite1();
}
noinline fn stepRead1() void {
    apiRead1();
}
noinline fn stepWrite2() void {
    apiWrite2();
}
noinline fn stepRead2() void {
    apiRead2();
}

const steps = [_]struct { name: []const u8, call: *const fn () void }{
    .{ .name = "Initiator.init", .call = stepInitI },
    .{ .name = "Responder.init", .call = stepInitR },
    .{ .name = "Initiator.writeMessage1", .call = stepWrite1 },
    .{ .name = "Responder.readMessage1", .call = stepRead1 },
    .{ .name = "Responder.writeMessage2 (+keys)", .call = stepWrite2 },
    .{ .name = "Initiator.readMessage2 (+keys)", .call = stepRead2 },
};

// ── the needles, recomputed from observed states ─────────────────────────────

const Hk = struct { temp: [32]u8, o1: [32]u8, o2: [32]u8 };

fn hkdf2(ck: [32]u8, ikm: []const u8) Hk {
    var r: Hk = undefined;
    Hmac.create(&r.temp, ikm, &ck);
    Hmac.create(&r.o1, &[_]u8{1}, &r.temp);
    var m: [33]u8 = undefined;
    m[0..32].* = r.o1;
    m[32] = 2;
    Hmac.create(&r.o2, &m, &r.temp);
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
    const e_i = try tk.KeyPair.generateDeterministic(seedOf(prng_i));
    const e_r = try tk.KeyPair.generateDeterministic(seedOf(prng_r));
    n.addKey("ephemeral key I", e_i.secret_key);
    n.addKey("ephemeral key R", e_r.secret_key);
    const es = try X25519.scalarmult(e_i.secret_key, s_r.public_key);
    const ss = try X25519.scalarmult(s_i.secret_key, s_r.public_key);
    const ee = try X25519.scalarmult(e_r.secret_key, e_i.public_key);
    const se = try X25519.scalarmult(s_i.secret_key, e_r.public_key);
    n.add("es", es);
    n.add("ss", ss);
    n.add("ee", ee);
    n.add("se", se);

    stepInitI();
    const ck0 = ini.hs.symmetric_state.ck;
    const m_es = hkdf2(ck0, &es);
    const m_ss = hkdf2(m_es.o1, &ss);
    const m_ee = hkdf2(m_ss.o1, &ee);
    const m_se = hkdf2(m_ee.o1, &se);
    const m_sp = hkdf2(m_se.o1, "");
    n.add("temp_key (es)", m_es.temp);
    n.add("ck after es", m_es.o1);
    n.add("k after es", m_es.o2);
    n.add("temp_key (ss)", m_ss.temp);
    n.add("ck after ss", m_ss.o1);
    n.add("k after ss", m_ss.o2);
    n.add("temp_key (ee)", m_ee.temp);
    n.add("ck after ee", m_ee.o1);
    n.add("k after ee", m_ee.o2);
    n.add("temp_key (se)", m_se.temp);
    n.add("ck after se", m_se.o1);
    n.add("k after se", m_se.o2);
    n.add("temp_key (split)", m_sp.temp);
    n.add("session key i2r", m_sp.o1);
    n.add("session key r2i", m_sp.o2);
    stepInitR();
    stepWrite1();
    stepRead1();
    stepWrite2();
    stepRead2();
    try std.testing.expectEqualSlices(u8, &keys_i.send_key, &m_sp.o1);
    try std.testing.expectEqualSlices(u8, &keys_i.recv_key, &m_sp.o2);
    try std.testing.expectEqualSlices(u8, &keys_r.send_key, &m_sp.o2);
    n.add("control", control);
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

test "STACKPROBE tenantkex (wave 9): no key, DH or HKDF residue on the dead stack after any handshake call" {
    try skipUnlessOptimized();

    s_i = try tk.KeyPair.generateDeterministic(hash("static I"));
    s_r = try tk.KeyPair.generateDeterministic(hash("static R"));
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
        std.debug.print("\n=== STACKPROBE tenantkex ({t}, window {d} KiB) NEG={any} POS(control)={d} needles={d} total residue={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg[0..nd.len], pos[ctl], nd.len, total });
        for (steps, &hits, depth, shallow, deep) |st, *h, d, s, dp| {
            std.debug.print("  {s:<36} dirty={d} B, hits {d}..{d} B\n", .{ st.name, d, s, dp });
            for (nd, h[0..nd.len]) |nn, x| {
                if (x != 0) std.debug.print("    RESIDUE {s:<34} {d} (3 runs)\n", .{ nn.name, x });
            }
        }
    }
    if (bad) return error.TestUnexpectedResult;
}
