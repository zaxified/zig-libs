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
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Scalar384 = std.crypto.ecc.P384.scalar.Scalar;
const Sha384 = std.crypto.hash.sha2.Sha384;
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

var heap_buf: [1024 * 1024]u8 = undefined;
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

/// The passphrase-protected path (2026-10-09): bcrypt_pbkdf, the AES key
/// schedule and the decrypted private section all pass through the stack.
noinline fn callFromOpenSSHEncrypted() void {
    HostKey.fromOpenSSH(&hk_sink, cur_text, vectors.enc_passphrase) catch unreachable;
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
/// P-384: `d`, and the nonce `k` solved from the signature as for P-256
/// (`e` = SHA-384 of the message, reduced the way std's ECDSA reduces it).
fn ecdsa384Needles(n: *Needles, kp: *const EcdsaP384.KeyPair, msg: ?[]const u8, sig: ?[96]u8) !void {
    const d = try Scalar384.fromBytes(kp.secret_key.toBytes(), .big);
    n.addBoth("d", &d.toBytes(.big));
    n.addImage("d", std.mem.asBytes(&d));
    const m = msg orelse return;
    var h: [48]u8 = undefined;
    Sha384.hash(m, &h, .{});
    var wide: [64]u8 = @splat(0);
    wide[16..64].* = h;
    const e = Scalar384.fromBytes64(wide, .big);
    const r = try Scalar384.fromBytes(sig.?[0..48].*, .big);
    const sv = try Scalar384.fromBytes(sig.?[48..96].*, .big);
    const k = sv.invert().mul(e.add(r.mul(d)));
    n.addBoth("k", &k.toBytes(.big));
    n.addImage("k", std.mem.asBytes(&k));
    n.addBoth("k^-1", &k.invert().toBytes(.big));
}

fn ecdsaRs384(raw: []const u8) ![96]u8 {
    var cur = messages.Cursor{ .b = raw };
    var out: [96]u8 = @splat(0);
    for (0..2) |i| {
        const m = std.mem.trimStart(u8, try cur.string(), &.{0});
        @memcpy(out[i * 48 + 48 - m.len ..][0..m.len], m);
    }
    return out;
}

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

    // ── passphrase-protected containers: ed25519 (ctr, cbc), ecdsa-p256 ──
    // Needles: the loaded key and the passphrase. The decrypted section holds
    // exactly the key images, so a section left on the stack is caught too.
    for ([_][]const u8{ vectors.ed25519_enc_ctr_key, vectors.ed25519_enc_cbc_key, vectors.ecdsa_p256_enc_ctr_key }) |text| {
        try HostKey.fromOpenSSH(&cur_hk, text, vectors.enc_passphrase);
        var n: Needles = .{};
        switch (cur_hk) {
            .ed25519 => |*kp| {
                ed25519KeyNeedles(&n, kp);
                leak_src = kp.secret_key.seed();
            },
            .ecdsa_p256 => |*kp| {
                try ecdsaKeyNeedles(&n, kp);
                leak_src = kp.secret_key.toBytes();
            },
            else => unreachable,
        }
        n.addBoth("passphrase", vectors.enc_passphrase);
        n.sort();
        cur_text = text;
        bad += try runProbe("HostKey.fromOpenSSH encrypted", callFromOpenSSHEncrypted, &n);
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

    // ── ecdsa-p384: the fixture (sign + load) ──
    {
        try HostKey.fromOpenSSH(&cur_hk, vectors.ecdsa_p384_key, null);
        const kp = &cur_hk.ecdsa_p384;
        leak_src = kp.secret_key.toBytes()[0..32].*;
        {
            callSign();
            var n: Needles = .{};
            try ecdsa384Needles(&n, kp, &exchange_hash, try ecdsaRs384(try rawSig(out_sink)));
            n.sort();
            bad += try runProbe("HostKey.sign ecdsa-p384", callSign, &n);
        }
        {
            var n: Needles = .{};
            try ecdsa384Needles(&n, kp, null, null);
            try containerNeedles(&n, vectors.ecdsa_p384_key);
            n.sort();
            cur_text = vectors.ecdsa_p384_key;
            bad += try runProbe("HostKey.fromOpenSSH ecdsa-p384", callFromOpenSSH, &n);
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

// ════════════════════════════════════════════════════════════════════════════
// Key exchange (added 2026-10-09). One KEX per method and role, each against
// a peer thread over a socketpair, plus a full handshake per role (KEX + key
// derivation + cipher install). The measured side draws its entropy from a
// recording `Io`, so the needles are exactly its ephemeral secrets: the
// X25519 seed, the ML-KEM seed and secret key, the DH exponent, the
// component and combined shared secrets `K`, and — for the full handshake —
// the installed cipher states (the traffic keys). The peer records too, so
// `K` can be recomputed. Both sides restart from fixed seeds on every call:
// all seven runs of `runProbe` are the same exchange.
// ════════════════════════════════════════════════════════════════════════════

const transport = @import("transport.zig");
const X25519 = std.crypto.dh.X25519;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const KexResult = transport.KexResult;

/// Entropy that is a fixed stream and remembers every draw of 32 bytes or more
/// (the KEX secrets; packet padding and the KEXINIT cookie are shorter and
/// public anyway). Each draw is SHAKE256(seed ‖ counter) squeezed straight
/// into the caller's buffer: the generator's state lives only in this frame,
/// deep inside the measured call. (A `std.Random.ChaCha` reset per call left
/// its by-value init temporary — keystream included, i.e. the very draws —
/// in the instrument's own frame above the burn: 2026-10-09, read as residue
/// until the stack dump showed whose frame it was.)
const Recorder = struct {
    seed: u8,
    counter: u64 = 0,
    draws: [4][1024]u8 = undefined,
    lens: [4]usize = undefined,
    n: usize = 0,

    fn reset(self: *Recorder) void {
        self.counter = 0;
        self.n = 0;
    }

    fn draw(self: *const Recorder, i: usize) []const u8 {
        return self.draws[i][0..self.lens[i]];
    }

    fn randomSecure(ud: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
        const self: *Recorder = @ptrCast(@alignCast(ud.?));
        var x = std.crypto.hash.sha3.Shake256.init(.{});
        x.update(&[_]u8{ 'k', 'e', 'x', self.seed });
        x.update(std.mem.asBytes(&self.counter));
        x.squeeze(buf);
        self.counter += 1;
        if (buf.len >= 32 and self.n < self.draws.len) {
            @memcpy(self.draws[self.n][0..buf.len], buf);
            self.lens[self.n] = buf.len;
            self.n += 1;
        }
    }
    fn random(ud: ?*anyopaque, buf: []u8) void {
        randomSecure(ud, buf) catch unreachable;
    }
};

var threaded: std.Io.Threaded = undefined;
var rec_vtable: std.Io.VTable = undefined;
var rec_me: Recorder = .{ .seed = 1 };
var rec_peer: Recorder = .{ .seed = 2 };

fn recEntropy(r: *Recorder) transport.Entropy {
    return .{ .io = .{ .userdata = r, .vtable = &rec_vtable } };
}

const Kex = enum { curve25519, mlkem, dh14, dh16, ecdh256, ecdh384 };
const Role = enum { client, server };

const kx_v_c = "SSH-2.0-zig_probe_client";
const kx_v_s = "SSH-2.0-zig_probe_server";
const kx_i_c = "I_C probe client kexinit payload";
const kx_i_s = "I_S probe server kexinit payload";

const accept_any: transport.HostKeyPolicy = .{ .verifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: transport.HostKeyInfo) transport.HostKeyVerdict {
        return .accept;
    }
}.f }, .host = "127.0.0.1" };

fn kexName(k: Kex) []const u8 {
    return switch (k) {
        .curve25519 => "curve25519-sha256",
        .mlkem => "mlkem768x25519-sha256",
        .dh14 => "diffie-hellman-group14-sha256",
        .dh16 => "diffie-hellman-group16-sha512",
        .ecdh256 => "ecdh-sha2-nistp256",
        .ecdh384 => "ecdh-sha2-nistp384",
    };
}

// ── API adapter: the only place that names the shapes under test ────────────
// (BEFORE the 2026-10-09 fix the methods returned `KexResult` by value:
// `out.* = try transport.curve25519Kex(r, w, …)`.)

fn apiKex(k: Kex, role: Role, r: *std.Io.Reader, w: *std.Io.Writer, ent: transport.Entropy, gpa: std.mem.Allocator, out: *KexResult) !void {
    var none: transport.CipherState = .plaintext;
    const cp: transport.CipherPair = .single(&none);
    switch (role) {
        .client => switch (k) {
            .curve25519 => try transport.curve25519Kex(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, accept_any, "ssh-ed25519"),
            .mlkem => try transport.mlkem768x25519Kex(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, accept_any, "ssh-ed25519"),
            .dh14, .dh16 => try transport.dhGroupKex(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, accept_any, kexName(k), "ssh-ed25519"),
            .ecdh256, .ecdh384 => try transport.ecdhNistKex(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, accept_any, kexName(k), "ssh-ed25519"),
        },
        .server => switch (k) {
            .curve25519 => try server.curve25519KexServer(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, &kex_hk, gpa),
            .mlkem => try server.mlkem768x25519KexServer(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, &kex_hk, gpa),
            .dh14, .dh16 => try server.dhGroupKexServer(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, &kex_hk, gpa, kexName(k)),
            .ecdh256, .ecdh384 => try server.ecdhNistKexServer(out, r, w, cp, ent, kx_i_c, kx_i_s, kx_v_c, kx_v_s, &kex_hk, gpa, kexName(k)),
        },
    }
}

fn apiHandshake(role: Role, t: *transport.Transport, gpa: std.mem.Allocator) !void {
    switch (role) {
        .client => {
            try t.clientHandshake(gpa, accept_any);
            try t.requestService("ssh-userauth", &svc_buf);
        },
        .server => try server.serverHandshake(t, gpa, .{ .host_keys = (&kex_hk)[0..1] }),
    }
}

// ── one exchange over a socketpair ──────────────────────────────────────────

var kex_hk: HostKey = undefined;
var svc_buf: [64 * 1024]u8 = undefined;
var cur_kex: Kex = .curve25519;
var cur_role: Role = .client;
var kex_sink: KexResult = .{};
var hs_t: transport.Transport = undefined;
var peer_t: transport.Transport = undefined;
var peer_err: ?anyerror = null;
var me_rbuf: [64 * 1024]u8 = undefined;
var me_wbuf: [64 * 1024]u8 = undefined;
var peer_rbuf: [64 * 1024]u8 = undefined;
var peer_wbuf: [64 * 1024]u8 = undefined;
var me_r: std.Io.File.Reader = undefined;
var me_w: std.Io.File.Writer = undefined;
var peer_r: std.Io.File.Reader = undefined;
var peer_w: std.Io.File.Writer = undefined;
var peer_heap: [256 * 1024]u8 = undefined;

fn other(r: Role) Role {
    return if (r == .client) .server else .client;
}

fn peerMain(fd: i32, full: bool) void {
    const io = threaded.io();
    const f: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    peer_r = f.readerStreaming(io, &peer_rbuf);
    peer_w = f.writerStreaming(io, &peer_wbuf);
    var fba: std.heap.FixedBufferAllocator = .init(&peer_heap);
    rec_peer.reset();
    const role = other(cur_role);
    if (full) {
        peer_t = .init(&peer_r.interface, &peer_w.interface);
        peer_t.entropy = recEntropy(&rec_peer);
        apiHandshake(role, &peer_t, fba.allocator()) catch |e| {
            peer_err = e;
        };
    } else {
        var res: KexResult = .{};
        apiKex(cur_kex, role, &peer_r.interface, &peer_w.interface, recEntropy(&rec_peer), fba.allocator(), &res) catch |e| {
            peer_err = e;
        };
    }
}

/// Socketpair + peer thread around `body`, which runs on this thread.
inline fn withPeer(full: bool, body: anytype) void {
    var fds: [2]i32 = undefined;
    if (std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC, 0, &fds) != 0) unreachable;
    const th = std.Thread.spawn(.{}, peerMain, .{ fds[1], full }) catch unreachable;
    const io = threaded.io();
    const f: std.Io.File = .{ .handle = fds[0], .flags = .{ .nonblocking = false } };
    me_r = f.readerStreaming(io, &me_rbuf);
    me_w = f.writerStreaming(io, &me_wbuf);
    heap_fba.reset();
    rec_me.reset();
    body();
    // Let the peer finish writing (a server sends EXT_INFO after NEWKEYS,
    // when the client may already have returned): half-close only, so a peer
    // still reading sees EOF instead of hanging; a failed call cuts both ways.
    _ = std.os.linux.shutdown(fds[0], if (call_err != null) std.os.linux.SHUT.RDWR else std.os.linux.SHUT.WR);
    th.join();
    _ = std.os.linux.close(fds[0]);
    _ = std.os.linux.close(fds[1]);
}

var call_err: ?anyerror = null;

noinline fn callKex() void {
    withPeer(false, struct {
        fn b() void {
            apiKex(cur_kex, cur_role, &me_r.interface, &me_w.interface, recEntropy(&rec_me), heap_fba.allocator(), &kex_sink) catch |e| {
                call_err = e;
            };
        }
    }.b);
}

noinline fn callHandshake() void {
    withPeer(true, struct {
        fn b() void {
            hs_t = .init(&me_r.interface, &me_w.interface);
            hs_t.entropy = recEntropy(&rec_me);
            apiHandshake(cur_role, &hs_t, heap_fba.allocator()) catch |e| {
                call_err = e;
            };
        }
    }.b);
}

// ── needles, recomputed from both sides' recorded draws ─────────────────────

fn clientOf(role: Role, me: *const Recorder, peer: *const Recorder) *const Recorder {
    return if (role == .client) me else peer;
}

fn x25519Needles(n: *Needles, mine: [32]u8, theirs: [32]u8) !void {
    n.addBoth("x25519 sk", &mine);
    const k = try X25519.scalarmult(mine, try X25519.recoverPublicKey(theirs));
    n.addBoth("x25519 K", &k);
}

/// Needles of one exchange of `k` with `role` measured; `me`/`peer` hold the
/// draws of that exchange.
fn kexNeedles(n: *Needles, k: Kex, role: Role, me: *const Recorder, peer: *const Recorder) !void {
    const c = clientOf(role, me, peer);
    const s = clientOf(other(role), me, peer);
    switch (k) {
        .curve25519 => {
            const cs = c.draw(0)[0..32].*;
            const ss = s.draw(0)[0..32].*;
            if (role == .client) try x25519Needles(n, cs, ss) else try x25519Needles(n, ss, cs);
            leak_src = me.draw(0)[0..32].*;
        },
        .mlkem => {
            // client: x_seed, kem_seed(64); server: kem encaps seed, x_seed.
            const cx = c.draw(0)[0..32].*;
            const kem_seed = c.draw(1)[0..MLKem768.seed_length].*;
            const enc_seed = s.draw(0)[0..MLKem768.encaps_seed_length].*;
            const sx = s.draw(1)[0..32].*;
            const kp = try MLKem768.KeyPair.generateDeterministic(kem_seed);
            const enc = kp.public_key.encapsDeterministic(&enc_seed);
            const xk = try X25519.scalarmult(cx, try X25519.recoverPublicKey(sx));
            if (role == .client) {
                n.addBoth("x25519 sk", &cx);
                n.addImage("mlkem seed", &kem_seed);
                n.addImage("mlkem sk", &kp.secret_key.toBytes());
            } else {
                n.addBoth("x25519 sk", &sx);
                n.addImage("mlkem m", &enc_seed);
            }
            n.addBoth("x25519 K", &xk);
            n.addImage("mlkem K", &enc.shared_secret);
            var res: KexResult = .{};
            const kk = transport.mlkemSharedK(&res, enc.shared_secret, xk);
            n.addImage("K", &kk);
            leak_src = me.draw(0)[0..32].*;
        },
        .dh14, .dh16 => {
            const group = transport.DhGroup.forName(kexName(k)).?;
            var xs: [2][1024]u8 = undefined;
            for ([_]*const Recorder{ me, peer }, 0..) |r, i| {
                const b = xs[i][0..group.prime.len];
                @memcpy(b, r.draw(0)[0..group.prime.len]);
                b[0] &= 0x7f;
                b[b.len - 1] |= 1;
            }
            const mine = xs[0][0..group.prime.len];
            const theirs = xs[1][0..group.prime.len];
            n.addBoth("dh exponent", mine);
            var pub_buf: [1024]u8 = undefined;
            const peer_pub = try transport.dhPowModPrime(group.prime, &[_]u8{2}, theirs, &pub_buf);
            var k_buf: [1024]u8 = undefined;
            const kk = try transport.dhPowModPrime(group.prime, peer_pub, mine, &k_buf);
            n.addBoth("dh K", kk);
            leak_src = mine[0..32].*;
        },
        inline .ecdh256, .ecdh384 => |kk| {
            // One draw per side: the first candidate scalar (a rejection has
            // probability < 2^-32), from which `fromScalar` builds the pair.
            const c_ = comptime transport.EcdhNist.forName(kexName(kk)).?;
            const Kp = transport.EcdhNistKeyPair(c_);
            const L = comptime c_.len();
            const mine = Kp.fromScalar(me.draw(0)[0..L].*) orelse return error.ProbeScalarRejected;
            const theirs = Kp.fromScalar(peer.draw(0)[0..L].*) orelse return error.ProbeScalarRejected;
            n.addBoth("ecdh scalar", &mine.secret);
            const shared = try transport.ecdhNistShared(c_, &mine.secret, &theirs.public);
            n.addBoth("ecdh K", &shared);
            leak_src = mine.secret[0..32].*;
        },
    }
}

fn controlNeedle(n: *Needles) void {
    // A value the call never sees: must stay at zero hits (the scan's
    // false-positive floor inside every set).
    var c: [32]u8 = undefined;
    Sha256.hash("ssh-kex-probe-control", &c, .{});
    n.addBoth("control", &c);
}

fn kexLabel(comptime k: Kex, comptime role: Role) []const u8 {
    return "kex " ++ @tagName(k) ++ " " ++ @tagName(role);
}

fn hsLabel(comptime role: Role) []const u8 {
    return "handshake " ++ @tagName(role);
}

fn setupKexProbe() !void {
    threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    rec_vtable = threaded.io().vtable.*;
    rec_vtable.randomSecure = Recorder.randomSecure;
    rec_vtable.random = Recorder.random;
    heap_fba = .init(&heap_buf);
    try HostKey.fromOpenSSH(&kex_hk, vectors.ed25519_key, null);
}

test "STACKPROBE: no ephemeral secret, shared secret or traffic key on the dead stack after a key exchange" {
    try skipUnlessOptimized();
    try setupKexProbe();
    defer threaded.deinit();
    var bad: usize = 0;

    inline for (.{ Kex.curve25519, Kex.mlkem, Kex.dh14, Kex.dh16, Kex.ecdh256, Kex.ecdh384 }) |k| {
        inline for (.{ Role.client, Role.server }) |role| {
            cur_kex = k;
            cur_role = role;
            call_err = null;
            peer_err = null;
            callKex(); // priming run: the draws the needles come from
            if (call_err) |e| return e;
            if (peer_err) |e| return e;
            var n: Needles = .{};
            try kexNeedles(&n, k, role, &rec_me, &rec_peer);
            controlNeedle(&n);
            n.sort();
            bad += try runProbe(kexLabel(k, role), callKex, &n);
            if (call_err) |e| return e;
        }
    }

    // Full handshake (the first method on both lists: mlkem768x25519): the
    // same KEX secrets plus the traffic keys the transport installed.
    inline for (.{ Role.client, Role.server }) |role| {
        cur_role = role;
        call_err = null;
        peer_err = null;
        callHandshake();
        if (call_err != null or peer_err != null) std.debug.print("handshake {t}: me={?} peer={?}\n", .{ role, call_err, peer_err });
        if (call_err) |e| return e;
        if (peer_err) |e| return e;
        var n: Needles = .{};
        try kexNeedles(&n, .mlkem, role, &rec_me, &rec_peer);
        n.addImage("read cipher", std.mem.asBytes(&hs_t.read_cipher));
        n.addImage("write cipher", std.mem.asBytes(&hs_t.write_cipher));
        controlNeedle(&n);
        n.sort();
        bad += try runProbe(hsLabel(role), callHandshake, &n);
        if (call_err) |e| return e;
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
