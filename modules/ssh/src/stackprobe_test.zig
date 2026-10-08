// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the host/user-key paths: `HostKey.sign` (all
//! three key types, both rsa-sha2 hashes) and `HostKey.fromOpenSSH` (all three
//! container types). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in:
//! - ed25519: the seed, the clamped and unclamped scalar, the nonce prefix,
//!   and for a signature the nonce (`SHA-512(prefix ‖ H)`, raw and reduced);
//! - ecdsa-p256: `d`, and for a signature the nonce `k` solved from the
//!   signature the call produced (`k = s⁻¹·(e + r·d)`), `k⁻¹`, `r·d`, `e + r·d`;
//! - rsa: p, q, d, dP, dQ, qInv (big-endian and as ff limbs, the p/q
//!   Montgomery constants), and for a signature its CRT halves `s mod p`,
//!   `s mod q`;
//! - `fromOpenSSH`: also the container's base64 body and its decoded bytes
//!   (an unencrypted container IS the private key).
//! Windows with fewer than 8 distinct bytes are skipped (limb padding).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("rsa");
const server = @import("server.zig");
const messages = @import("messages.zig");
const vectors = @import("hostkey_vectors.zig");

const HostKey = server.HostKey;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Scalar = std.crypto.ecc.P256.scalar.Scalar;
const Ed = std.crypto.ecc.Edwards25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

const WINDOW = 1024 * 1024; // rsa `fromOpenSSH` dirties > 256 KiB
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 16384;

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

    /// `image` big-endian and byte-reversed.
    fn addBoth(self: *Needles, name: []const u8, image: []const u8) void {
        self.addImage(name, image);
        var r: [1024]u8 = undefined;
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

    fn addScalar(self: *Needles, name: []const u8, s: Scalar) void {
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
        std.debug.print("\n=== STACKPROBE ssh: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

fn ed25519KeyNeedles(n: *Needles, kp: *const Ed25519.KeyPair) void {
    const seed = kp.secret_key.seed();
    n.addBoth("seed", &seed);
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    n.addBoth("a (unclamped)", az[0..32]);
    var a = az[0..32].*;
    Ed.scalar.clamp(&a);
    n.addBoth("a", &a);
    n.addBoth("prefix", az[32..64]);
}

/// std signs without noise: nonce = reduce64(SHA-512(prefix ‖ msg)).
fn ed25519SignNeedles(n: *Needles, kp: *const Ed25519.KeyPair, msg: []const u8) void {
    ed25519KeyNeedles(n, kp);
    var az: [64]u8 = undefined;
    Sha512.hash(&kp.secret_key.seed(), &az, .{});
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(msg);
    var nonce64: [64]u8 = undefined;
    h.final(&nonce64);
    n.addBoth("nonce64", &nonce64);
    n.addBoth("r", &Ed.scalar.reduce64(nonce64));
}

fn ecdsaKeyNeedles(n: *Needles, kp: *const EcdsaP256.KeyPair) !void {
    n.addScalar("d", try Scalar.fromBytes(kp.secret_key.toBytes(), .big));
}

/// `sig` is the raw 64-byte r‖s; `msg` is exactly what was signed.
fn ecdsaSignNeedles(n: *Needles, kp: *const EcdsaP256.KeyPair, msg: []const u8, sig: [64]u8) !void {
    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = h;
    const e = Scalar.fromBytes48(wide, .big);
    const d = try Scalar.fromBytes(kp.secret_key.toBytes(), .big);
    const r = try Scalar.fromBytes(sig[0..32].*, .big);
    const s = try Scalar.fromBytes(sig[32..64].*, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

fn rsaKeyNeedles(n: *Needles, sk: *const rsa.SecretKey) !void {
    var b: [256]u8 = undefined;
    try sk.p.toBytes(b[0..128], .big);
    n.addBoth("p", b[0..128]);
    try sk.q.toBytes(b[0..128], .big);
    n.addBoth("q", b[0..128]);
    try sk.d.toBytes(b[0..256], .big);
    n.addBoth("d", b[0..256]);
    try sk.dp.toBytes(b[0..128], .big);
    n.addBoth("dP", b[0..128]);
    try sk.dq.toBytes(b[0..128], .big);
    n.addBoth("dQ", b[0..128]);
    try sk.qinv.toBytes(b[0..128], .big);
    n.addBoth("qInv", b[0..128]);
    n.addImage("p (ff)", std.mem.asBytes(&sk.p));
    n.addImage("q (ff)", std.mem.asBytes(&sk.q));
    n.addImage("d (ff)", std.mem.asBytes(&sk.d));
    n.addImage("dP (ff)", std.mem.asBytes(&sk.dp));
    n.addImage("dQ (ff)", std.mem.asBytes(&sk.dq));
    n.addImage("qInv (ff)", std.mem.asBytes(&sk.qinv));
    n.addImage("p/q (montint)", std.mem.asBytes(&sk.p_mont));
    n.addImage("p/q (montint)", std.mem.asBytes(&sk.q_mont));
}

/// `s mod p`, `s mod q` for a 2048-bit big-endian signature `s`.
fn rsaSignNeedles(n: *Needles, sk: *const rsa.SecretKey, s: *const [256]u8) !void {
    try rsaKeyNeedles(n, sk);
    var pb: [128]u8 = undefined;
    var qb: [128]u8 = undefined;
    try sk.p.toBytes(&pb, .big);
    try sk.q.toBytes(&qb, .big);
    const si = std.mem.readInt(u2048, s, .big);
    var b: [128]u8 = undefined;
    std.mem.writeInt(u1024, &b, @intCast(si % std.mem.readInt(u1024, &pb, .big)), .big);
    n.addBoth("s mod p", &b);
    std.mem.writeInt(u1024, &b, @intCast(si % std.mem.readInt(u1024, &qb, .big)), .big);
    n.addBoth("s mod q", &b);
}

/// The container's base64 body (whitespace stripped) and its decoded bytes.
fn containerNeedles(n: *Needles, text: []const u8) !void {
    const begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const end = "-----END OPENSSH PRIVATE KEY-----";
    const bi = std.mem.indexOf(u8, text, begin).? + begin.len;
    const ei = std.mem.indexOfPos(u8, text, bi, end).?;
    var b64: [4096]u8 = undefined;
    var m: usize = 0;
    for (text[bi..ei]) |c| {
        if (c == '\r' or c == '\n' or c == ' ' or c == '\t') continue;
        b64[m] = c;
        m += 1;
    }
    n.addImage("container b64", b64[0..m]);
    var bin: [4096]u8 = undefined;
    const dl = try std.base64.standard.Decoder.calcSizeForSlice(b64[0..m]);
    try std.base64.standard.Decoder.decode(bin[0..dl], b64[0..m]);
    // Only the private section is secret; the header and public blob are not,
    // and the public blob would match the public key wherever it is copied.
    // The private section is the tail after the public blob; take the last
    // half, which holds the private key encoding in every fixture.
    n.addImage("container", bin[dl / 2 .. dl]);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

/// The caller's own storage for the key — a server holds its host keys in a
/// slice like this one.
var cur_hk: HostKey = undefined;
var cur_text: []const u8 = "";
var hk_sink: HostKey = undefined;

var heap_buf: [64 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;
var out_sink: []u8 = &.{};

const exchange_hash: [32]u8 = @splat(0x5a);

noinline fn callSign() void {
    heap_fba.reset();
    const hk: *const HostKey = &cur_hk;
    out_sink = hk.sign(heap_fba.allocator(), &exchange_hash) catch unreachable;
    std.mem.doNotOptimizeAway(out_sink.ptr);
}

noinline fn callFromOpenSSH() void {
    HostKey.fromOpenSSH(&hk_sink, cur_text, null) catch unreachable;
    std.mem.doNotOptimizeAway(&hk_sink);
}

/// A high-entropy seed (a repeated byte would be skipped as low-entropy).
fn caseSeed(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 's', 's', 'h', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out;
}

/// The raw signature bytes out of a `string(alg) ‖ string(raw)` blob.
fn rawSig(blob: []const u8) ![]const u8 {
    var cur = messages.Cursor{ .b = blob };
    _ = try cur.string();
    return cur.string();
}

/// ecdsa raw = mpint(r) ‖ mpint(s) → fixed-width r‖s.
fn ecdsaRs(raw: []const u8) ![64]u8 {
    var cur = messages.Cursor{ .b = raw };
    var out: [64]u8 = @splat(0);
    for (0..2) |i| {
        const m = std.mem.trimStart(u8, try cur.string(), &.{0});
        @memcpy(out[i * 32 + 32 - m.len ..][0..m.len], m);
    }
    return out;
}

test "STACKPROBE: no key, nonce or CRT residue on the dead stack after host-key signing and loading" {
    try skipUnlessOptimized();
    heap_fba = .init(&heap_buf);
    var bad: usize = 0;

    // ── ed25519: the fixture + one generated key ──
    for (0..2) |ci| {
        if (ci == 0) {
            try HostKey.fromOpenSSH(&cur_hk, vectors.ed25519_key, null);
        } else {
            cur_hk = .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(caseSeed(1)) };
        }
        const kp = &cur_hk.ed25519;
        leak_src = kp.secret_key.seed();
        {
            var n: Needles = .{};
            ed25519SignNeedles(&n, kp, &exchange_hash);
            n.sort();
            bad += try runProbe("HostKey.sign ed25519", callSign, &n);
        }
        if (ci == 0) {
            var n: Needles = .{};
            ed25519KeyNeedles(&n, kp);
            try containerNeedles(&n, vectors.ed25519_key);
            n.sort();
            cur_text = vectors.ed25519_key;
            bad += try runProbe("HostKey.fromOpenSSH ed25519", callFromOpenSSH, &n);
        }
    }

    // ── ecdsa-p256: the fixture + one generated key ──
    for (0..2) |ci| {
        if (ci == 0) {
            try HostKey.fromOpenSSH(&cur_hk, vectors.ecdsa_p256_key, null);
        } else {
            cur_hk = .{ .ecdsa_p256 = try EcdsaP256.KeyPair.generateDeterministic(caseSeed(2)) };
        }
        const kp = &cur_hk.ecdsa_p256;
        leak_src = kp.secret_key.toBytes();
        {
            callSign();
            var n: Needles = .{};
            try ecdsaSignNeedles(&n, kp, &exchange_hash, try ecdsaRs(try rawSig(out_sink)));
            n.sort();
            bad += try runProbe("HostKey.sign ecdsa-p256", callSign, &n);
        }
        if (ci == 0) {
            var n: Needles = .{};
            try ecdsaKeyNeedles(&n, kp);
            try containerNeedles(&n, vectors.ecdsa_p256_key);
            n.sort();
            cur_text = vectors.ecdsa_p256_key;
            bad += try runProbe("HostKey.fromOpenSSH ecdsa-p256", callFromOpenSSH, &n);
        }
    }

    // ── rsa: the fixture, both signature hashes ──
    try HostKey.fromOpenSSH(&cur_hk, vectors.rsa_key, null);
    defer cur_hk.rsa.secret_key.deinit();
    const sk = &cur_hk.rsa.secret_key;
    {
        var pb: [128]u8 = undefined;
        try sk.p.toBytes(&pb, .big);
        leak_src = pb[0..LEAK].*;
    }
    for ([_]HostKey.RsaHash{ .sha2_256, .sha2_512 }) |hash| {
        cur_hk.rsa.hash = hash;
        callSign();
        const raw = try rawSig(out_sink);
        var n: Needles = .{};
        try rsaSignNeedles(&n, sk, raw[0..256]);
        n.sort();
        bad += try runProbe(if (hash == .sha2_256) "HostKey.sign rsa-sha2-256" else "HostKey.sign rsa-sha2-512", callSign, &n);
    }
    {
        var n: Needles = .{};
        try rsaKeyNeedles(&n, sk);
        try containerNeedles(&n, vectors.rsa_key);
        n.sort();
        cur_text = vectors.rsa_key;
        bad += try runProbe("HostKey.fromOpenSSH rsa", callFromOpenSSH, &n);
        hk_sink.rsa.secret_key.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
