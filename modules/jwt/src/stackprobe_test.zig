// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for token signing (`encodeJson` with every
//! `SigningKey` algorithm) and HS* verification (`verify`). Kept in the module
//! per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the call
//! `PAD` bytes deeper, snapshot the window and look for secrets. ReleaseFast /
//! ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with 0xaa, so the
//! scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window (with at least 8 distinct bytes) of every
//! image a secret is held in. ES256 / ES384: the private key `d`, the seed, the
//! nonce `k` solved from the signature the call produced (`k = s⁻¹·(e + r·d)`,
//! so whatever nonce the signer really used), `k⁻¹`, `r·d`, `e + r·d`.
//! Ed25519: seed, clamped scalar, prefix, the nonce `r = SHA-512(prefix ‖ M)
//! mod L`. ML-DSA: seed, `K`, the packed `s1`/`s2`/`t0`, the expanded NTT-domain
//! copies, and `ρ'`. HMAC: the secret, `key ⊕ ipad`, `key ⊕ opad` and the hash
//! states after absorbing them.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const p256 = @import("p256");
const root = @import("root.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Shake256 = std.crypto.hash.sha3.Shake256;
const hmac_sha2 = std.crypto.auth.hmac.sha2;
const P384Scalar = std.crypto.ecc.P384.scalar.Scalar;
const Ed25519Scalar = std.crypto.ecc.Edwards25519.scalar;
const P256Scalar = p256.Scalar;

const WINDOW = 1024 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 65536;

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
            if (distinctBytes(image[i..][0..W]) < 8) continue; // padding, zero runs: not a secret
            if (self.len == max_windows) @panic("needle set overflow");
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

    fn addScalar(self: *Needles, name: []const u8, s: anytype) void {
        const be = s.toBytes(.big);
        self.addImage(name, &be);
        const le = s.toBytes(.little);
        self.addImage(name, &le);
        self.addImage(name, std.mem.asBytes(&s));
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
        std.debug.print("\n=== STACKPROBE jwt: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

/// Distinct byte values in a window: below 8 it is padding or a zero run.
fn distinctBytes(w: []const u8) usize {
    var seen: [256]bool = @splat(false);
    var c: usize = 0;
    for (w) |b| {
        if (!seen[b]) c += 1;
        seen[b] = true;
    }
    return c;
}

var needles_store: Needles = .{};

fn fresh() *Needles {
    needles_store.len = 0;
    needles_store.n_names = 0;
    needles_store.addImage("leak", &leak_src); // the positive control's secret
    return &needles_store;
}

// ── needles ─────────────────────────────────────────────────────────────────

/// `b` and its byte reversal (the same number, the other endianness).
fn addBoth(n: *Needles, name: []const u8, b: []const u8) void {
    n.addImage(name, b);
    var r: [128]u8 = undefined;
    @memcpy(r[0..b.len], b);
    std.mem.reverse(u8, r[0..b.len]);
    n.addImage(name, r[0..b.len]);
}

fn caseSeed(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'j', 'w', 't', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out;
}

/// ES256: `d`, the seed, the nonce solved from the signature `sig` (raw r‖s)
/// over `signed`, its inverse, `r·d` and `e + r·d`.
fn es256Needles(n: *Needles, seed: [32]u8, sk: [32]u8, signed: []const u8, sig: [64]u8) !void {
    var h: [32]u8 = undefined;
    Sha256.hash(signed, &h, .{});
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = h;
    const e = P256Scalar.fromBytes48(wide, .big);
    const d = try P256Scalar.fromBytes(sk, .big);
    const r = try P256Scalar.fromBytes(sig[0..32].*, .big);
    const s = try P256Scalar.fromBytes(sig[32..64].*, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    addBoth(n, "seed", &seed);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

/// ES384: the same over P-384 with SHA-384 (`e` is the 48-byte hash).
fn es384Needles(n: *Needles, seed: [48]u8, sk: [48]u8, signed: []const u8, sig: [96]u8) !void {
    var h: [48]u8 = undefined;
    Sha384.hash(signed, &h, .{});
    var wide: [64]u8 = @splat(0);
    wide[16..64].* = h;
    const e = P384Scalar.fromBytes64(wide, .big);
    const d = try P384Scalar.fromBytes(sk, .big);
    const r = try P384Scalar.fromBytes(sig[0..48].*, .big);
    const s = try P384Scalar.fromBytes(sig[48..96].*, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    addBoth(n, "seed", &seed);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

/// Ed25519: seed, `az = SHA-512(seed)`, the clamped scalar (also reduced mod
/// L), the prefix and the nonce `r = SHA-512(prefix ‖ M) mod L`.
fn ed25519Needles(n: *Needles, seed: [32]u8, signed: []const u8) void {
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    var a = az[0..32].*;
    Ed25519Scalar.clamp(&a);
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(signed);
    var nonce64: [64]u8 = undefined;
    h.final(&nonce64);
    addBoth(n, "seed", &seed);
    addBoth(n, "az", &az);
    addBoth(n, "a", &a);
    addBoth(n, "a mod L", &Ed25519Scalar.reduce(a));
    addBoth(n, "prefix", az[32..64]);
    addBoth(n, "nonce", &Ed25519Scalar.reduce64(nonce64));
}

/// ML-DSA: the seed, `K`, the packed `s1 ‖ s2 ‖ t0`, the NTT-domain copies of
/// the secret vectors (their in-memory `s1`/`s2`/`t0` form is all small
/// coefficients, windows the distinct-byte filter drops) and `ρ' = H(K ‖ rnd ‖ μ)`.
/// `rho` and `tr` are public. `kp` is a pointer to the key pair.
fn mldsaNeedles(n: *Needles, kp: anytype, seed: [32]u8, signed: []const u8) void {
    const sk = kp.secret_key.toBytes();
    n.addImage("seed", &seed);
    n.addImage("K", sk[32..64]);
    n.addImage("s1s2t0", sk[128..]);
    n.addImage("s1_hat", std.mem.asBytes(&kp.secret_key.s1_hat));
    n.addImage("s2_hat", std.mem.asBytes(&kp.secret_key.s2_hat));
    n.addImage("t0_hat", std.mem.asBytes(&kp.secret_key.t0_hat));
    var mu: [64]u8 = undefined;
    var hm = Shake256.init(.{});
    hm.update(&kp.secret_key.tr);
    hm.update(&[_]u8{ 0, 0 }); // pure ML-DSA, empty context
    hm.update(signed);
    hm.squeeze(&mu);
    var rho_prime: [64]u8 = undefined;
    var hr = Shake256.init(.{});
    hr.update(&kp.secret_key.key);
    hr.update(&([_]u8{0} ** 32)); // deterministic: rnd = 0
    hr.update(&mu);
    hr.squeeze(&rho_prime);
    n.addImage("rho'", &rho_prime);
}

/// HMAC: the secret, `key ⊕ ipad`, `key ⊕ opad` (the key zero-padded to the
/// block) and the hash states after absorbing them.
fn hmacNeedles(comptime Hash: type, n: *Needles, secret: []const u8) void {
    const B = Hash.block_length;
    var key: [B]u8 = @splat(0);
    @memcpy(key[0..secret.len], secret);
    var ip: [B]u8 = undefined;
    var op: [B]u8 = undefined;
    for (key, 0..) |b, i| {
        ip[i] = b ^ 0x36;
        op[i] = b ^ 0x5c;
    }
    n.addImage("secret", secret);
    n.addImage("ipad", &ip);
    n.addImage("opad", &op);
    var hi = Hash.init(.{});
    hi.update(&ip);
    stateImages(n, "istate", hi.s);
    var ho = Hash.init(.{});
    ho.update(&op);
    stateImages(n, "ostate", ho.s);
}

fn stateImages(n: *Needles, name: []const u8, s: anytype) void {
    const Word = @TypeOf(s[0]);
    n.addImage(name, std.mem.asBytes(&s));
    var be: [8 * @sizeOf(Word)]u8 = undefined;
    for (s, 0..) |w, i| std.mem.writeInt(Word, be[i * @sizeOf(Word) ..][0..@sizeOf(Word)], w, .big);
    n.addImage(name, &be);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

const n_cases = 2;
const claims_json = "{\"sub\":\"x\",\"iss\":\"https://issuer.test\"}";

var cur_es256: root.EcdsaP256Sha256.KeyPair = undefined;
var cur_es384: root.EcdsaP384Sha384.KeyPair = undefined;
var cur_ed: root.Ed25519.KeyPair = undefined;
var cur_ml44: root.MlDsa44.KeyPair = undefined;
var cur_ml65: root.MlDsa65.KeyPair = undefined;
var cur_ml87: root.MlDsa87.KeyPair = undefined;
/// HS256 / HS384 / HS512 secrets share one buffer; `hs_len` is the length each uses.
var cur_secret: [128]u8 = undefined;
var hs_len: [3]usize = undefined;

var heap_buf: [128 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;
var tok_sink: []u8 = &.{};

fn gpa() std.mem.Allocator {
    return heap_fba.allocator();
}

fn sinkToken(r: root.EncodeError![]u8) void {
    tok_sink = r catch unreachable;
    std.mem.doNotOptimizeAway(tok_sink.ptr);
}

noinline fn callHs256() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .hs256 = cur_secret[0..hs_len[0]] }, .{}));
}
noinline fn callHs384() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .hs384 = cur_secret[0..hs_len[1]] }, .{}));
}
noinline fn callHs512() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .hs512 = cur_secret[0..hs_len[2]] }, .{}));
}
noinline fn callEs256() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .es256 = &cur_es256 }, .{}));
}
noinline fn callEs384() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .es384 = &cur_es384 }, .{}));
}
noinline fn callEd25519() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .ed25519 = &cur_ed }, .{}));
}
noinline fn callMl44() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .ml_dsa_44 = &cur_ml44 }, .{}));
}
noinline fn callMl65() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .ml_dsa_65 = &cur_ml65 }, .{}));
}
noinline fn callMl87() void {
    heap_fba.reset();
    sinkToken(root.encodeJson(gpa(), claims_json, .{ .ml_dsa_87 = &cur_ml87 }, .{}));
}

/// Tokens the verify probes check, parsed once per case (they borrow `hs_tok`).
var hs_tok: [3][512]u8 = undefined;
var hs_parsed: [3]root.ParsedToken = undefined;

noinline fn callVerifyHs256() void {
    root.verify(&hs_parsed[0], .{ .hmac = cur_secret[0..hs_len[0]] }) catch unreachable;
}
noinline fn callVerifyHs384() void {
    root.verify(&hs_parsed[1], .{ .hmac = cur_secret[0..hs_len[1]] }) catch unreachable;
}
noinline fn callVerifyHs512() void {
    root.verify(&hs_parsed[2], .{ .hmac = cur_secret[0..hs_len[2]] }) catch unreachable;
}

const Split = struct { input: []const u8, sig: []const u8 };

/// `header.payload` and the decoded signature of a compact token.
fn splitToken(tok: []const u8, sig_buf: []u8) !Split {
    const dot = std.mem.lastIndexOfScalar(u8, tok, '.').?;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const len = try dec.calcSizeForSlice(tok[dot + 1 ..]);
    try dec.decode(sig_buf[0..len], tok[dot + 1 ..]);
    return .{ .input = tok[0..dot], .sig = sig_buf[0..len] };
}

test "STACKPROBE: no key, nonce or MAC-state residue on the dead stack after jwt signing and HS* verification" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    heap_fba = .init(&heap_buf);
    var sig_buf: [8192]u8 = undefined;
    for (0..n_cases) |ci| {
        const seed = caseSeed(@intCast(ci));
        var seed48: [48]u8 = undefined;
        Sha384.hash(&seed, &seed48, .{});
        try root.EcdsaP256Sha256.KeyPair.generateDeterministicInto(&cur_es256, &seed);
        cur_es384 = try root.EcdsaP384Sha384.KeyPair.generateDeterministic(seed48);
        cur_ed = try root.Ed25519.KeyPair.generateDeterministic(seed);
        cur_ml44 = try root.MlDsa44.KeyPair.generateDeterministic(seed);
        cur_ml65 = try root.MlDsa65.KeyPair.generateDeterministic(seed);
        cur_ml87 = try root.MlDsa87.KeyPair.generateDeterministic(seed);
        Sha256.hash(&[_]u8{ 'l', 'e', 'a', 'k', @intCast(ci) }, &leak_src, .{});
        // Case 0: secrets as long as the hash block (no zero padding); case 1: the shortest allowed.
        hs_len = if (ci == 0) .{ 64, 128, 128 } else .{ 32, 48, 64 };
        Sha512.hash(&seed, cur_secret[0..64], .{});
        Sha512.hash(cur_secret[0..64], cur_secret[64..128], .{});

        // HS* signing, and the tokens HS* verification will check.
        {
            callHs256();
            @memcpy(hs_tok[0][0..tok_sink.len], tok_sink);
            hs_parsed[0] = try root.parse(std.heap.page_allocator, hs_tok[0][0..tok_sink.len]);
            const n = fresh();
            hmacNeedles(Sha256, n, cur_secret[0..hs_len[0]]);
            n.sort();
            bad += try runProbe("encodeJson HS256", callHs256, n);
            bad += try runProbe("verify HS256", callVerifyHs256, n);
        }
        {
            callHs384();
            @memcpy(hs_tok[1][0..tok_sink.len], tok_sink);
            hs_parsed[1] = try root.parse(std.heap.page_allocator, hs_tok[1][0..tok_sink.len]);
            const n = fresh();
            hmacNeedles(Sha384, n, cur_secret[0..hs_len[1]]);
            n.sort();
            bad += try runProbe("encodeJson HS384", callHs384, n);
            bad += try runProbe("verify HS384", callVerifyHs384, n);
        }
        {
            callHs512();
            @memcpy(hs_tok[2][0..tok_sink.len], tok_sink);
            hs_parsed[2] = try root.parse(std.heap.page_allocator, hs_tok[2][0..tok_sink.len]);
            const n = fresh();
            hmacNeedles(Sha512, n, cur_secret[0..hs_len[2]]);
            n.sort();
            bad += try runProbe("encodeJson HS512", callHs512, n);
            bad += try runProbe("verify HS512", callVerifyHs512, n);
        }
        for (&hs_parsed) |*p| p.deinit();

        {
            callEs256();
            const sp = try splitToken(tok_sink, &sig_buf);
            const n = fresh();
            try es256Needles(n, seed, cur_es256.secret_key.toBytes(), sp.input, sp.sig[0..64].*);
            n.sort();
            bad += try runProbe("encodeJson ES256", callEs256, n);
        }
        {
            callEs384();
            const sp = try splitToken(tok_sink, &sig_buf);
            const n = fresh();
            try es384Needles(n, seed48, cur_es384.secret_key.toBytes(), sp.input, sp.sig[0..96].*);
            n.sort();
            bad += try runProbe("encodeJson ES384", callEs384, n);
        }
        {
            callEd25519();
            const sp = try splitToken(tok_sink, &sig_buf);
            const n = fresh();
            ed25519Needles(n, seed, sp.input);
            n.sort();
            bad += try runProbe("encodeJson Ed25519", callEd25519, n);
        }
        {
            callMl44();
            const sp = try splitToken(tok_sink, &sig_buf);
            const n = fresh();
            mldsaNeedles(n, &cur_ml44, seed, sp.input);
            n.sort();
            bad += try runProbe("encodeJson ML-DSA-44", callMl44, n);
        }
        {
            callMl65();
            const sp = try splitToken(tok_sink, &sig_buf);
            const n = fresh();
            mldsaNeedles(n, &cur_ml65, seed, sp.input);
            n.sort();
            bad += try runProbe("encodeJson ML-DSA-65", callMl65, n);
        }
        {
            callMl87();
            const sp = try splitToken(tok_sink, &sig_buf);
            const n = fresh();
            mldsaNeedles(n, &cur_ml87, seed, sp.input);
            n.sort();
            bad += try runProbe("encodeJson ML-DSA-87", callMl87, n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
