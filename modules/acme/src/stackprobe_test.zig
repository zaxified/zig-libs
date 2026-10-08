// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the account/certificate key paths: JWS
//! signing (`jws.sign`), CSR and TLS-ALPN-01 certificate signing
//! (`x509.csrDer`, `x509.tlsAlpnCertDer`), key minting
//! (`jws.generateKeyPair`) and the RFC 5915 key codec
//! (`x509.ecPrivateKeyToPem` / `ecPrivateKeyFromPem`). Kept in the module per
//! `CONVENTIONS.md` §9.
//!
//! Method as `p256`'s probe: paint a stack window below the probe, run the call
//! `PAD` bytes deeper, snapshot the window and look for secrets. ReleaseFast /
//! ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with 0xaa, so the
//! scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in: the
//! private key `d`, the seed it came from, and for the signing calls the nonce
//! `k` (solved from the signature the call produced, `k = s⁻¹·(e + r·d)`, so
//! whatever nonce the signer really used), `k⁻¹`, `r·d` and `e + r·d` (`e` =
//! SHA-256 of exactly what is signed).
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks `d` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const p256 = @import("p256");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");

const Scalar = p256.Scalar;
const Es256 = jws.Es256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const WINDOW = 256 * 1024;
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 2048;

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

    fn addScalar(self: *Needles, name: []const u8, s: Scalar) void {
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
        std.debug.print("\n=== STACKPROBE acme: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

// ── needles ─────────────────────────────────────────────────────────────────

/// Needles for a signature `sig` (raw r‖s) over `signed` made with key `sk`
/// from `seed`: `d`, the seed, the nonce solved from the signature, its
/// inverse, `r·d` and `e + r·d`.
fn signNeedles(n: *Needles, seed: [32]u8, sk: [32]u8, signed: []const u8, sig: [64]u8) !void {
    var h: [32]u8 = undefined;
    Sha256.hash(signed, &h, .{});
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = h;
    const e = Scalar.fromBytes48(wide, .big);
    const d = try Scalar.fromBytes(sk, .big);
    const r = try Scalar.fromBytes(sig[0..32].*, .big);
    const s = try Scalar.fromBytes(sig[32..64].*, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    n.addBytes32("seed", seed);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

fn keyNeedles(n: *Needles, seed: [32]u8, sk: [32]u8) !void {
    n.addScalar("d", try Scalar.fromBytes(sk, .big));
    n.addBytes32("seed", seed);
}

const n_cases = 2;

fn caseSeed(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'a', 'c', 'm', 'e', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out;
}

/// One DER element at `off`: its content and the offset past it.
const Elem = struct { content: []const u8, start: usize, end: usize };

fn elemAt(der: []const u8, off: usize) !Elem {
    var i = off + 1;
    var len: usize = der[i];
    i += 1;
    if (len & 0x80 != 0) {
        const nb = len & 0x7f;
        len = 0;
        for (der[i..][0..nb]) |b| len = len << 8 | b;
        i += nb;
    }
    return .{ .content = der[i..][0..len], .start = off, .end = i + len };
}

/// For a DER `SEQUENCE { signed, algorithm, BIT STRING signature }` (CSR and
/// certificate): needles from its own signature over its first element.
fn derSignedNeedles(n: *Needles, seed: [32]u8, sk: [32]u8, der: []const u8) !void {
    const outer = try elemAt(der, 0);
    const first = try elemAt(outer.content, 0);
    const alg = try elemAt(outer.content, first.end);
    const bits = try elemAt(outer.content, alg.end);
    const sig = try Es256.Signature.fromDer(bits.content[1..]);
    try signNeedles(n, seed, sk, outer.content[first.start..first.end], sig.toBytes());
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var cur_seed: [32]u8 = undefined;
var cur_pair: Es256.KeyPair = undefined;
var cur_pem: []u8 = &.{};

var heap_buf: [64 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;

/// An `Io` whose secure random is the case's seed, so `generateKeyPair`'s
/// output is known to the probe. Everything else is `std.Io.failing`'s.
var fake_vtable: std.Io.VTable = undefined;

fn fakeRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    @memcpy(buffer, cur_seed[0..buffer.len]);
}

fn fakeSwapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .unblocked;
}

fn fakeIo() std.Io {
    fake_vtable = std.Io.failing.vtable.*;
    fake_vtable.randomSecure = fakeRandomSecure;
    fake_vtable.swapCancelProtection = fakeSwapCancelProtection;
    return .{ .userdata = null, .vtable = &fake_vtable };
}

// Results land in static memory: the caller's own storage is not the probe's concern.
var pair_sink: Es256.KeyPair = undefined;
var out_sink: []u8 = &.{};

const test_header: jws.Header = .{ .nonce = "n-0123", .url = "https://ca.example/new-order" };
const test_domains: []const []const u8 = &.{ "example.com", "www.example.com" };
const acme_id: [32]u8 = @splat(0x5a);
const serial: [16]u8 = .{0x01} ++ @as([15]u8, @splat(0x33));

fn gpa() std.mem.Allocator {
    return heap_fba.allocator();
}

noinline fn callJwsSign() void {
    heap_fba.reset();
    out_sink = jws.sign(gpa(), &cur_pair, "{\"termsOfServiceAgreed\":true}", test_header) catch unreachable;
    std.mem.doNotOptimizeAway(out_sink.ptr);
}

noinline fn callCsrDer() void {
    heap_fba.reset();
    out_sink = x509.csrDer(gpa(), &cur_pair, test_domains) catch unreachable;
    std.mem.doNotOptimizeAway(out_sink.ptr);
}

noinline fn callTlsAlpnCertDer() void {
    heap_fba.reset();
    out_sink = x509.tlsAlpnCertDer(gpa(), &cur_pair, "example.com", acme_id, &serial, x509.tls_alpn_not_before, x509.tls_alpn_not_after) catch unreachable;
    std.mem.doNotOptimizeAway(out_sink.ptr);
}

noinline fn callGenerateKeyPair() void {
    jws.generateKeyPair(&pair_sink, fakeIo());
    std.mem.doNotOptimizeAway(&pair_sink);
}

noinline fn callPrivateKeyToPem() void {
    heap_fba.reset();
    out_sink = x509.ecPrivateKeyToPem(gpa(), &cur_pair) catch unreachable;
    std.mem.doNotOptimizeAway(out_sink.ptr);
}

noinline fn callPrivateKeyFromPem() void {
    heap_fba.reset();
    x509.ecPrivateKeyFromPem(&pair_sink, gpa(), cur_pem) catch unreachable;
    std.mem.doNotOptimizeAway(&pair_sink);
}

test "STACKPROBE: no key or nonce residue on the dead stack after acme signing and key handling" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    heap_fba = .init(&heap_buf);
    for (0..n_cases) |ci| {
        cur_seed = caseSeed(@intCast(ci));
        try Es256.KeyPair.generateDeterministicInto(&cur_pair, &cur_seed);
        const sk = cur_pair.secret_key.toBytes();
        leak_src = sk;

        // jws.sign — the signed bytes are `protected_b64 "." payload_b64`.
        {
            callJwsSign();
            const js = out_sink;
            const p0 = std.mem.indexOf(u8, js, "\"protected\":\"").? + 13;
            const p1 = std.mem.indexOfPos(u8, js, p0, "\"").?;
            const q0 = std.mem.indexOfPos(u8, js, p1, "\"payload\":\"").? + 11;
            const q1 = std.mem.indexOfPos(u8, js, q0, "\"").?;
            const s0 = std.mem.indexOfPos(u8, js, q1, "\"signature\":\"").? + 13;
            const s1 = std.mem.indexOfPos(u8, js, s0, "\"").?;
            var input: [1024]u8 = undefined;
            const signed = try std.fmt.bufPrint(&input, "{s}.{s}", .{ js[p0..p1], js[q0..q1] });
            var sig: [64]u8 = undefined;
            try std.base64.url_safe_no_pad.Decoder.decode(&sig, js[s0..s1]);
            var n: Needles = .{};
            try signNeedles(&n, cur_seed, sk, signed, sig);
            n.sort();
            bad += try runProbe("jws.sign", callJwsSign, &n);
        }
        {
            callCsrDer();
            var n: Needles = .{};
            try derSignedNeedles(&n, cur_seed, sk, out_sink);
            n.sort();
            bad += try runProbe("x509.csrDer", callCsrDer, &n);
        }
        {
            callTlsAlpnCertDer();
            var n: Needles = .{};
            try derSignedNeedles(&n, cur_seed, sk, out_sink);
            n.sort();
            bad += try runProbe("x509.tlsAlpnCertDer", callTlsAlpnCertDer, &n);
        }
        {
            var n: Needles = .{};
            try keyNeedles(&n, cur_seed, sk);
            n.sort();
            bad += try runProbe("jws.generateKeyPair", callGenerateKeyPair, &n);
            bad += try runProbe("x509.ecPrivateKeyToPem", callPrivateKeyToPem, &n);

            heap_fba.reset();
            cur_pem = try x509.ecPrivateKeyToPem(std.heap.page_allocator, &cur_pair);
            defer std.heap.page_allocator.free(cur_pem);
            bad += try runProbe("x509.ecPrivateKeyFromPem", callPrivateKeyFromPem, &n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
