// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module:
//! `deriveAkeKeyPair`, the registration pair, `generateKE1/KE2/KE3` and
//! `serverFinish`. Kept in the module per `CONVENTIONS.md` §9.
//!
//! Engine as `hpke`'s probe (2026-10-08 form). ReleaseFast/ReleaseSmall only —
//! Debug and ReleaseSafe fill `undefined` with 0xaa. The module has no RNG
//! (every random value is a parameter), so no recording entropy is needed.
//!
//! Needles are every 16-byte window of every image a secret is held in: the
//! password, blind, OPRF output, randomized password, masking / auth / export
//! keys, the client's long-term and ephemeral keys and their seeds, the
//! server key, the per-client OPRF key, the three DH outputs, `ikm`, the key
//! schedule's `prk` / handshake secret / MAC keys, the session key.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const opaque_ = @import("root.zig");
const compat = @import("test_shim.zig");
const voprf = @import("voprf");
const ct25519 = @import("ct25519");
const compat_voprf = struct {
    fn scalarFromWideBytes(wide: [64]u8) [32]u8 {
        var out: [32]u8 = undefined;
        voprf.scalarFromWideBytes(&wide, &out);
        return out;
    }
};

fn finalizeBy(input: []const u8, b: [32]u8, ev: voprf.Element) [64]u8 {
    var out: [64]u8 = undefined;
    voprf.finalize(input, &b, ev, &out) catch unreachable;
    return out;
}

fn deriveBy(seed: [32]u8) [32]u8 {
    var kp: voprf.KeyPair = undefined;
    voprf.deriveKeyPair(.oprf, &seed, "OPAQUE-DeriveKeyPair", &kp) catch unreachable;
    return kp.sk;
}

const HkdfSha512 = std.crypto.kdf.hkdf.HkdfSha512;

// ── engine (as hpke/p256 probes, 2026-10-08 form) ──
const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

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
        std.debug.print("\n=== STACKPROBE opaque: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

/// Audit-local deterministic byte strings: hashes of a label, so no 16-byte
/// window of them is a run of zeros or of paint that a dead stack holds anyway.
fn seedBytes(comptime N: usize, label: []const u8, i: u8) [N]u8 {
    var out: [N]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(label);
    h.update(&[_]u8{i});
    var d: [64]u8 = undefined;
    h.final(&d);
    var o: usize = 0;
    var ctr: u8 = 0;
    while (o < N) : (ctr += 1) {
        var hh = std.crypto.hash.sha2.Sha512.init(.{});
        hh.update(&d);
        hh.update(&[_]u8{ctr});
        var blk: [64]u8 = undefined;
        hh.final(&blk);
        const k = @min(64, N - o);
        @memcpy(out[o..][0..k], blk[0..k]);
        o += k;
    }
    return out;
}

// ── fixtures ────────────────────────────────────────────────────────────────

const password = "correct horse battery staple, probe";
const cred_id = "probe-credential-identifier";
const ctx = "opaque probe context";
const n_cases = 2;

var password_s: [password.len]u8 = undefined;
var blind: [32]u8 = undefined;
var oprf_seed: [64]u8 = undefined;
var server_seed: [32]u8 = undefined;
var server_kp: opaque_.AkeKeyPair = undefined;
var envelope_nonce: [32]u8 = undefined;
var client_nonce: [32]u8 = undefined;
var client_ks_seed: [32]u8 = undefined;
var masking_nonce: [32]u8 = undefined;
var server_nonce: [32]u8 = undefined;
var server_ks_seed: [32]u8 = undefined;

var reg_request: opaque_.RegistrationRequest = undefined;
var reg_response: opaque_.RegistrationResponse = undefined;
var reg: opaque_.FinalizeRegistrationResult = undefined;
var ke1r: opaque_.GenerateKE1Result = undefined;
var ke2r: opaque_.GenerateKE2Result = undefined;
var ke3r: opaque_.GenerateKE3Result = undefined;
var session_key_sink: [64]u8 = undefined;

var kp_sink: opaque_.AkeKeyPair = undefined;
var rq_sink: opaque_.RegistrationRequest = undefined;
var rs_sink: opaque_.RegistrationResponse = undefined;
var reg_sink: opaque_.FinalizeRegistrationResult = undefined;
var ke1_sink: opaque_.GenerateKE1Result = undefined;
var ke2_sink: opaque_.GenerateKE2Result = undefined;
var ke3_sink: opaque_.GenerateKE3Result = undefined;

// ADAPTER: the only block that depends on the call shapes of the module API.
noinline fn callDerive() void {
    opaque_.deriveAkeKeyPair(&server_seed, &kp_sink) catch unreachable;
}
noinline fn callRegRequest() void {
    rq_sink = opaque_.createRegistrationRequest(&password_s, &blind) catch unreachable;
}
noinline fn callRegResponse() void {
    rs_sink = opaque_.createRegistrationResponse(reg_request, server_kp.public_key, cred_id, &oprf_seed) catch unreachable;
}
noinline fn callRegFinalize() void {
    opaque_.finalizeRegistrationRequest(&password_s, &blind, reg_response, .{}, envelope_nonce, opaque_.Ksf.identity, &reg_sink) catch unreachable;
}
noinline fn callKE1() void {
    opaque_.generateKE1(&password_s, &blind, client_nonce, &client_ks_seed, &ke1_sink) catch unreachable;
}
noinline fn callKE2() void {
    opaque_.generateKE2(&server_kp.private_key, server_kp.public_key, reg.record, cred_id, &oprf_seed, ke1r.ke1, .{}, ctx, masking_nonce, server_nonce, &server_ks_seed, &ke2_sink) catch unreachable;
}
noinline fn callKE3() void {
    opaque_.generateKE3(&ke1r.state, .{}, ctx, ke2r.ke2, opaque_.Ksf.identity, &ke3_sink) catch unreachable;
}
noinline fn callServerFinish() void {
    opaque_.serverFinish(&ke2r.state, ke3r.ke3, &session_key_sink) catch unreachable;
}
// END ADAPTER

fn setUp(ci: u8) !void {
    @memcpy(&password_s, password);
    password_s[0] ^= ci;
    blind = compat_voprf.scalarFromWideBytes(seedBytes(64, "opaque-blind", ci));
    oprf_seed = seedBytes(64, "opaque-oprf-seed", ci);
    server_seed = seedBytes(32, "opaque-server-seed", ci);
    server_kp = try compat.deriveAkeKeyPair(server_seed);
    envelope_nonce = seedBytes(32, "opaque-env-nonce", ci);
    client_nonce = seedBytes(32, "opaque-client-nonce", ci);
    client_ks_seed = seedBytes(32, "opaque-client-ks", ci);
    masking_nonce = seedBytes(32, "opaque-mask-nonce", ci);
    server_nonce = seedBytes(32, "opaque-server-nonce", ci);
    server_ks_seed = seedBytes(32, "opaque-server-ks", ci);
    reg_request = try compat.createRegistrationRequest(&password_s, blind);
    reg_response = try compat.createRegistrationResponse(reg_request, server_kp.public_key, cred_id, oprf_seed);
    reg = try compat.finalizeRegistrationRequest(&password_s, blind, reg_response, .{}, envelope_nonce, opaque_.Ksf.identity);
    ke1r = try compat.generateKE1(&password_s, blind, client_nonce, client_ks_seed);
    ke2r = try compat.generateKE2(server_kp.private_key, server_kp.public_key, reg.record, cred_id, oprf_seed, ke1r.ke1, .{}, ctx, masking_nonce, server_nonce, server_ks_seed);
    ke3r = try compat.generateKE3(ke1r.state, .{}, ctx, ke2r.ke2, opaque_.Ksf.identity);
    leak_src = server_kp.private_key;
}

// ── needle helpers (an independent recomputation of the intermediates) ─────

fn expand(comptime N: usize, prk: *const [64]u8, parts: []const []const u8) [N]u8 {
    var info: [256]u8 = undefined;
    var len: usize = 0;
    for (parts) |p| {
        @memcpy(info[len..][0..p.len], p);
        len += p.len;
    }
    var out: [N]u8 = undefined;
    HkdfSha512.expand(&out, info[0..len], prk.*);
    return out;
}

fn mul(pk: [32]u8, sk: [32]u8) [32]u8 {
    const p = voprf.Element.fromBytes(pk) catch unreachable;
    return ct25519.mulRistretto(p.p, sk).toBytes();
}

fn deriveSecret(secret: *const [64]u8, comptime label: []const u8, transcript: []const u8) [64]u8 {
    const full = "OPAQUE-" ++ label;
    return expand(64, secret, &.{ &[2]u8{ 0, 64 }, &[1]u8{full.len}, full, &[1]u8{@intCast(transcript.len)}, transcript });
}

fn addAke(n: *Needles, seed: *const [32]u8, kp: opaque_.AkeKeyPair, tag: []const u8) void {
    _ = tag;
    n.addBytes("ake seed", seed);
    n.addBytes("ake sk", &kp.private_key);
}

const Sched = struct { prk: [64]u8, hs: [64]u8, km2: [64]u8, km3: [64]u8, session: [64]u8 };

fn schedule(ikm: *const [96]u8, preamble_hash: *const [64]u8) Sched {
    var s: Sched = undefined;
    s.prk = HkdfSha512.extract("", ikm);
    s.hs = deriveSecret(&s.prk, "HandshakeSecret", preamble_hash);
    s.session = deriveSecret(&s.prk, "SessionKey", preamble_hash);
    s.km2 = deriveSecret(&s.hs, "ServerMAC", "");
    s.km3 = deriveSecret(&s.hs, "ClientMAC", "");
    return s;
}

fn addSched(n: *Needles, s: *const Sched, ikm: *const [96]u8) void {
    n.addBytes("ikm", ikm);
    n.addBytes("prk", &s.prk);
    n.addBytes("handshake secret", &s.hs);
    n.addBytes("km2", &s.km2);
    n.addBytes("km3", &s.km3);
    n.addBytes("session key", &s.session);
}

fn preambleHash(ke1: opaque_.KE1, cr: opaque_.CredentialResponse, srv_nonce: [32]u8, srv_ks: [32]u8, client_id: []const u8, server_id: []const u8) [64]u8 {
    var t = std.crypto.hash.sha2.Sha512.init(.{});
    t.update("OPAQUEv1-");
    t.update(&[2]u8{ 0, ctx.len });
    t.update(ctx);
    t.update(&[2]u8{ 0, @intCast(client_id.len) });
    t.update(client_id);
    t.update(&ke1.toBytes());
    t.update(&[2]u8{ 0, @intCast(server_id.len) });
    t.update(server_id);
    t.update(&cr.toBytes());
    t.update(&srv_nonce);
    t.update(&srv_ks);
    var out: [64]u8 = undefined;
    t.final(&out);
    return out;
}

/// The client-side secrets recomputed from the password and the response.
const Client = struct {
    oprf_output: [64]u8,
    rp: [64]u8,
    masking_key: [64]u8,
    auth_key: [64]u8,
    export_key: [64]u8,
    seed: [32]u8,
    kp: opaque_.AkeKeyPair,
    eph: opaque_.AkeKeyPair,
    inv_blind: [32]u8,
};

fn clientSecrets() Client {
    var c: Client = undefined;
    const ev = voprf.Element.fromBytes(reg_response.evaluated_message) catch unreachable;
    c.oprf_output = finalizeBy(&password_s, blind, ev);
    c.rp = HkdfSha512.extract("", &(c.oprf_output ++ c.oprf_output));
    c.masking_key = expand(64, &c.rp, &.{"MaskingKey"});
    c.auth_key = expand(64, &c.rp, &.{ &envelope_nonce, "AuthKey" });
    c.export_key = expand(64, &c.rp, &.{ &envelope_nonce, "ExportKey" });
    c.seed = expand(32, &c.rp, &.{ &envelope_nonce, "PrivateKey" });
    c.kp = compat.deriveAkeKeyPair(c.seed) catch unreachable;
    c.eph = compat.deriveAkeKeyPair(client_ks_seed) catch unreachable;
    c.inv_blind = std.crypto.ecc.Ristretto255.scalar.Scalar.fromBytes(blind).invert().toBytes();
    return c;
}

fn addClient(n: *Needles, c: *const Client) void {
    n.addBytes("password", &password_s);
    n.addBytes("blind", &blind);
    n.addBytes("blind^-1", &c.inv_blind);
    n.addBytes("oprf output", &c.oprf_output);
    n.addBytes("randomized pw", &c.rp);
    n.addBytes("masking key", &c.masking_key);
    n.addBytes("auth key", &c.auth_key);
    n.addBytes("export key", &c.export_key);
    n.addBytes("client seed", &c.seed);
    n.addBytes("client lt sk", &c.kp.private_key);
}

test "STACKPROBE: no key, password or session residue on the dead stack (opaque)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        const c = clientSecrets();
        var n: Needles = .{};

        // deriveAkeKeyPair: seed, wide string, key.
        n = .{};
        n.addBytes("seed", &server_seed);
        n.addBytes("sk", &server_kp.private_key);
        const dst = comptime "DeriveKeyPair" ++ voprf.contextString(.oprf);
        const info = "OPAQUE-DeriveDiffieHellmanKeyPair";
        n.addBytes("wide", &voprf.expandMessageXmd(64, &.{ &server_seed, &[2]u8{ 0, info.len }, info, &[1]u8{0} }, dst));
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("deriveAkeKeyPair", callDerive, &n);

        // createRegistrationRequest: password, blind.
        n = .{};
        n.addBytes("password", &password_s);
        n.addBytes("blind", &blind);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("createRegistrationRequest", callRegRequest, &n);

        // createRegistrationResponse: oprf_seed, per-client OPRF seed + key.
        const oseed = expand(32, &oprf_seed, &.{ cred_id, "OprfKey" });
        const okey = (deriveBy(oseed));
        n = .{};
        n.addBytes("oprf_seed", &oprf_seed);
        n.addBytes("oprf key seed", &oseed);
        n.addBytes("oprf key", &okey);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("createRegistrationResponse", callRegResponse, &n);

        // finalizeRegistrationRequest: everything client side.
        n = .{};
        addClient(&n, &c);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("finalizeRegistrationRequest", callRegFinalize, &n);

        // generateKE1: password, blind, ephemeral seed + key.
        n = .{};
        n.addBytes("password", &password_s);
        n.addBytes("blind", &blind);
        n.addBytes("eph seed", &client_ks_seed);
        n.addBytes("eph sk", &c.eph.private_key);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("generateKE1", callKE1, &n);

        // generateKE2: server key, per-client OPRF key, ephemeral, DH, schedule.
        const ske = compat.deriveAkeKeyPair(server_ks_seed) catch unreachable;
        const cr = ke2r.ke2.credential_response;
        const dh1 = mul(ke1r.ke1.auth_request.client_public_keyshare, ske.private_key);
        const dh2 = mul(ke1r.ke1.auth_request.client_public_keyshare, server_kp.private_key);
        const dh3 = mul(reg.record.client_public_key, ske.private_key);
        const ikm = dh1 ++ dh2 ++ dh3;
        const ph = preambleHash(ke1r.ke1, cr, server_nonce, ske.public_key, &reg.record.client_public_key, &server_kp.public_key);
        const sch = schedule(&ikm, &ph);
        n = .{};
        n.addBytes("server sk", &server_kp.private_key);
        n.addBytes("server seed", &server_seed);
        n.addBytes("oprf_seed", &oprf_seed);
        n.addBytes("oprf key seed", &oseed);
        n.addBytes("oprf key", &okey);
        n.addBytes("masking key", &reg.record.masking_key);
        n.addBytes("eph seed", &server_ks_seed);
        n.addBytes("eph sk", &ske.private_key);
        n.addBytes("dh1", &dh1);
        n.addBytes("dh2", &dh2);
        n.addBytes("dh3", &dh3);
        addSched(&n, &sch, &ikm);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("generateKE2", callKE2, &n);

        // generateKE3: client side, plus the schedule (same as the server's).
        const cdh1 = mul(ke2r.ke2.auth_response.server_public_keyshare, c.eph.private_key);
        const cdh2 = mul(server_kp.public_key, c.eph.private_key);
        const cdh3 = mul(ke2r.ke2.auth_response.server_public_keyshare, c.kp.private_key);
        const cikm = cdh1 ++ cdh2 ++ cdh3;
        const csch = schedule(&cikm, &ph);
        n = .{};
        addClient(&n, &c);
        n.addBytes("eph seed", &client_ks_seed);
        n.addBytes("eph sk", &c.eph.private_key);
        n.addBytes("dh1", &cdh1);
        n.addBytes("dh2", &cdh2);
        n.addBytes("dh3", &cdh3);
        addSched(&n, &csch, &cikm);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("generateKE3", callKE3, &n);

        // serverFinish: the session key.
        n = .{};
        n.addBytes("session key", &ke2r.state.session_key);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("serverFinish", callServerFinish, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
