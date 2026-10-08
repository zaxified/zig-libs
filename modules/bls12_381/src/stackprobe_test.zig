// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every entry point that holds a BLS secret:
//! `bls_sig.keyGen`, the `SecretKey` codec, `skToPk`/`sign`/`popProve` in both
//! variants (min-pk, min-sig) and the message-augmentation scheme, EIP-2333
//! derivation (`deriveMasterSk`, `deriveChildSk`, `derivePath`) and the
//! threshold scheme (`splitSecretKey`, `partialSign`, the share codec). Kept
//! in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in: the
//! secret scalar (big-endian and as montint limbs), the IKM/seed it came
//! from, keyGen's/HKDF_mod_r's PRK and OKM, EIP-2333's two Lamport secret keys
//! (255 × 32 bytes each), their 255-hash public key and its compression (the
//! child's IKM), Shamir coefficients and shares. Windows with fewer than 8
//! distinct bytes are skipped.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bls_sig = @import("bls_sig.zig");
const eip2333 = @import("eip2333.zig");
const threshold = @import("threshold.zig");
const Fr = @import("scalar.zig").Fr;

const SecretKey = bls_sig.SecretKey;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const WINDOW = 512 * 1024;
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
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    /// `image` big-endian and byte-reversed.
    fn addBoth(self: *Needles, name: []const u8, image: []const u8) void {
        self.addImage(name, image);
        var r: [16384]u8 = undefined;
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

    /// An `Fr`: its big-endian encoding (both byte orders) and its in-memory
    /// (Montgomery limb) image.
    fn addFr(self: *Needles, name: []const u8, s: Fr) void {
        self.addBoth(name, &s.toBytes());
        self.addImage(name, std.mem.asBytes(&s));
    }

    fn reset(self: *Needles) void {
        self.len = 0;
        self.n_names = 0;
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
        std.debug.print("\n=== STACKPROBE bls12_381: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

var nd: Needles = .{};

/// keyGen's first round (draft -05, salt not pre-hashed): PRK and OKM.
fn keyGenNeedles(n: *Needles, ikm: []const u8) void {
    hkdfNeedles(n, "BLS-SIG-KEYGEN-SALT-", ikm, &[_]u8{ 0, 48 });
}

/// EIP-2333 HKDF_mod_r's first round (salt = SHA-256 of the salt string).
fn hkdfModRNeedles(n: *Needles, ikm: []const u8) void {
    var salt: [32]u8 = undefined;
    Sha256.hash("BLS-SIG-KEYGEN-SALT-", &salt, .{});
    hkdfNeedles(n, &salt, ikm, &[_]u8{ 0, 48 });
}

fn hkdfNeedles(n: *Needles, salt: []const u8, ikm: []const u8, info: []const u8) void {
    var st = Hkdf.extractInit(salt);
    st.update(ikm);
    st.update(&[_]u8{0});
    var prk: [Hkdf.prk_length]u8 = undefined;
    st.final(&prk);
    n.addBoth("prk", &prk);
    var okm: [48]u8 = undefined;
    Hkdf.expand(&okm, info, prk);
    n.addBoth("okm", &okm);
}

/// EIP-2333 parent → child intermediates: both Lamport secret keys, the
/// 255-hash Lamport public key and its compression (the child's IKM).
fn lamportNeedles(n: *Needles, parent: Fr, index: u32) void {
    var salt: [4]u8 = undefined;
    std.mem.writeInt(u32, &salt, index, .big);
    const ikm = parent.toBytes();
    var not_ikm: [32]u8 = undefined;
    for (&not_ikm, ikm) |*o, b| o.* = ~b;
    n.addBoth("not_ikm", &not_ikm);
    var l0: [255 * 32]u8 = undefined;
    var l1: [255 * 32]u8 = undefined;
    Hkdf.expand(&l0, "", Hkdf.extract(&salt, &ikm));
    Hkdf.expand(&l1, "", Hkdf.extract(&salt, &not_ikm));
    n.addImage("lamport_sk", &l0);
    n.addImage("lamport_sk", &l1);
    var pk: [2 * 255 * 32]u8 = undefined;
    for (0..255) |i| {
        Sha256.hash(l0[i * 32 ..][0..32], pk[i * 32 ..][0..32], .{});
        Sha256.hash(l1[i * 32 ..][0..32], pk[(255 + i) * 32 ..][0..32], .{});
    }
    n.addImage("lamport_pk", &pk);
    var lpk: [32]u8 = undefined;
    Sha256.hash(&pk, &lpk, .{});
    n.addBoth("lamport_pk_c", &lpk);
}

// ── API adapter: the only place that names the shapes under test ────────────
// (BEFORE the 2026-10-09 fix these took and returned the secrets by value.)

const MinPkPop = bls_sig.MinPkPop;
const MinSigBasic = bls_sig.MinSigBasic;
const MinPkAug = bls_sig.MinPkAug;

fn apiKeyGen(out: *SecretKey, ikm: []const u8) void {
    bls_sig.keyGen(out, ikm, "") catch unreachable;
}
fn apiSkToBytes(sk: *const SecretKey, out: *[32]u8) void {
    sk.toBytes(out);
}
fn apiSkFromBytes(out: *SecretKey, b: *const [32]u8) void {
    SecretKey.fromBytes(out, b) catch unreachable;
}
fn apiSkToPk(comptime S: type, sk: *const SecretKey) S.PublicKey {
    return S.skToPk(sk);
}
fn apiSign(comptime S: type, sk: *const SecretKey, m: []const u8) S.Signature {
    return S.sign(sk, m);
}
fn apiPopProve(sk: *const SecretKey) MinPkPop.Signature {
    return MinPkPop.popProve(sk);
}
fn apiMaster(out: *SecretKey, seed: []const u8) void {
    eip2333.deriveMasterSk(out, seed) catch unreachable;
}
fn apiChild(out: *SecretKey, parent: *const SecretKey, index: u32) void {
    eip2333.deriveChildSk(out, parent, index);
}
fn apiPath(out: *SecretKey, seed: []const u8, p: []const u32) void {
    eip2333.derivePath(out, seed, p) catch unreachable;
}
fn apiSplit(gpa: std.mem.Allocator, sk: *const SecretKey, coeffs: []const Fr) threshold.SplitResult {
    return threshold.splitSecretKey(gpa, sk, 3, 5, coeffs) catch unreachable;
}
fn apiPartialSign(share: *const threshold.SecretKeyShare, m: []const u8) threshold.PartialSignature {
    return threshold.partialSign(share, m);
}
fn apiShareToBytes(share: *const threshold.SecretKeyShare, out: *[threshold.SecretKeyShare.encoded_bytes]u8) void {
    share.toBytes(out);
}
fn apiShareFromBytes(out: *threshold.SecretKeyShare, b: *const [threshold.SecretKeyShare.encoded_bytes]u8) void {
    threshold.SecretKeyShare.fromBytes(out, b) catch unreachable;
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

var cur_ikm: [32]u8 = undefined;
var cur_sk: SecretKey = undefined;
var cur_bytes: [32]u8 = undefined;
var cur_coeffs: [2]Fr = undefined;
var cur_share: threshold.SecretKeyShare = undefined;
var cur_share_bytes: [threshold.SecretKeyShare.encoded_bytes]u8 = undefined;
var sk_sink: SecretKey = undefined;
var bytes_sink: [64]u8 = undefined;
var share_sink: threshold.SecretKeyShare = undefined;

var heap_buf: [64 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;

const probe_msg = "probe message";
const probe_path = [_]u32{ 12381, 3600, 0 };

noinline fn callKeyGen() void {
    apiKeyGen(&sk_sink, &cur_ikm);
    std.mem.doNotOptimizeAway(&sk_sink);
}
noinline fn callSkToBytes() void {
    apiSkToBytes(&cur_sk, bytes_sink[0..32]);
    std.mem.doNotOptimizeAway(&bytes_sink);
}
noinline fn callSkFromBytes() void {
    apiSkFromBytes(&sk_sink, &cur_bytes);
    std.mem.doNotOptimizeAway(&sk_sink);
}
fn CallSkToPk(comptime S: type) type {
    return struct {
        noinline fn call() void {
            const pk = apiSkToPk(S, &cur_sk);
            std.mem.doNotOptimizeAway(&pk);
        }
    };
}
fn CallSign(comptime S: type) type {
    return struct {
        noinline fn call() void {
            const sig = apiSign(S, &cur_sk, probe_msg);
            std.mem.doNotOptimizeAway(&sig);
        }
    };
}
noinline fn callPopProve() void {
    const sig = apiPopProve(&cur_sk);
    std.mem.doNotOptimizeAway(&sig);
}
noinline fn callMaster() void {
    apiMaster(&sk_sink, &cur_ikm);
    std.mem.doNotOptimizeAway(&sk_sink);
}
noinline fn callChild() void {
    apiChild(&sk_sink, &cur_sk, probe_path[0]);
    std.mem.doNotOptimizeAway(&sk_sink);
}
noinline fn callPath() void {
    apiPath(&sk_sink, &cur_ikm, &probe_path);
    std.mem.doNotOptimizeAway(&sk_sink);
}
noinline fn callSplit() void {
    heap_fba.reset();
    const r = apiSplit(heap_fba.allocator(), &cur_sk, &cur_coeffs);
    std.mem.doNotOptimizeAway(&r);
}
noinline fn callPartialSign() void {
    const p = apiPartialSign(&cur_share, probe_msg);
    std.mem.doNotOptimizeAway(&p);
}
noinline fn callShareToBytes() void {
    apiShareToBytes(&cur_share, bytes_sink[0..threshold.SecretKeyShare.encoded_bytes]);
    std.mem.doNotOptimizeAway(&bytes_sink);
}
noinline fn callShareFromBytes() void {
    apiShareFromBytes(&share_sink, &cur_share_bytes);
    std.mem.doNotOptimizeAway(&share_sink);
}

fn caseIkm(i: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'b', 'l', 's', '-', 'i', 'k', 'm', i }, &out, .{});
    return out;
}

test "STACKPROBE: no secret-key residue on the dead stack after BLS key generation, signing, EIP-2333 and threshold" {
    try skipUnlessOptimized();
    heap_fba = .init(&heap_buf);
    var bad: usize = 0;
    for (0..2) |ci| {
        cur_ikm = caseIkm(@intCast(ci));
        apiKeyGen(&cur_sk, &cur_ikm);
        apiSkToBytes(&cur_sk, &cur_bytes);

        // keyGen: the IKM, PRK, OKM and the key.
        nd.reset();
        nd.addBoth("ikm", &cur_ikm);
        keyGenNeedles(&nd, &cur_ikm);
        nd.addFr("sk", cur_sk.scalar);
        nd.sort();
        leak_src = cur_sk.scalar.toBytes();
        bad += try runProbe("bls_sig.keyGen", callKeyGen, &nd);

        // Everything that only holds the key.
        nd.reset();
        nd.addFr("sk", cur_sk.scalar);
        nd.sort();
        bad += try runProbe("SecretKey.toBytes", callSkToBytes, &nd);
        bad += try runProbe("SecretKey.fromBytes", callSkFromBytes, &nd);
        bad += try runProbe("MinPkPop.skToPk (G1)", CallSkToPk(MinPkPop).call, &nd);
        bad += try runProbe("MinSigBasic.skToPk (G2)", CallSkToPk(MinSigBasic).call, &nd);
        bad += try runProbe("MinPkPop.sign (G2)", CallSign(MinPkPop).call, &nd);
        bad += try runProbe("MinSigBasic.sign (G1)", CallSign(MinSigBasic).call, &nd);
        bad += try runProbe("MinPkAug.sign", CallSign(MinPkAug).call, &nd);
        bad += try runProbe("MinPkPop.popProve", callPopProve, &nd);

        // EIP-2333.
        var master: SecretKey = undefined;
        apiMaster(&master, &cur_ikm);
        nd.reset();
        nd.addBoth("seed", &cur_ikm);
        hkdfModRNeedles(&nd, &cur_ikm);
        nd.addFr("master", master.scalar);
        nd.sort();
        leak_src = master.scalar.toBytes();
        bad += try runProbe("eip2333.deriveMasterSk", callMaster, &nd);

        var child: SecretKey = undefined;
        apiChild(&child, &cur_sk, probe_path[0]);
        nd.reset();
        nd.addFr("parent", cur_sk.scalar);
        lamportNeedles(&nd, cur_sk.scalar, probe_path[0]);
        nd.addFr("child", child.scalar);
        nd.sort();
        leak_src = cur_sk.scalar.toBytes();
        bad += try runProbe("eip2333.deriveChildSk", callChild, &nd);

        // derivePath: every key on the path and the last step's Lamport keys.
        nd.reset();
        nd.addBoth("seed", &cur_ikm);
        var k = master;
        nd.addFr("path key", k.scalar);
        for (probe_path, 0..) |idx, depth| {
            if (depth + 1 == probe_path.len) lamportNeedles(&nd, k.scalar, idx);
            var next: SecretKey = undefined;
            apiChild(&next, &k, idx);
            k = next;
            nd.addFr("path key", k.scalar);
        }
        nd.sort();
        leak_src = master.scalar.toBytes();
        bad += try runProbe("eip2333.derivePath", callPath, &nd);

        // Threshold: coefficients, the key, the shares.
        cur_coeffs = .{ Fr.reduceWide(&caseIkm(0x40 + @as(u8, @intCast(ci)))), Fr.reduceWide(&caseIkm(0x50 + @as(u8, @intCast(ci)))) };
        heap_fba.reset();
        const split = apiSplit(heap_fba.allocator(), &cur_sk, &cur_coeffs);
        cur_share = split.shares[0];
        nd.reset();
        nd.addFr("sk", cur_sk.scalar);
        nd.addFr("coefficient", cur_coeffs[0]);
        nd.addFr("coefficient", cur_coeffs[1]);
        for (split.shares) |s| nd.addFr("share", s.scalar);
        nd.sort();
        leak_src = cur_sk.scalar.toBytes();
        bad += try runProbe("threshold.splitSecretKey", callSplit, &nd);

        apiShareToBytes(&cur_share, &cur_share_bytes);
        nd.reset();
        nd.addFr("share", cur_share.scalar);
        nd.sort();
        leak_src = cur_share.scalar.toBytes();
        bad += try runProbe("threshold.partialSign", callPartialSign, &nd);
        bad += try runProbe("SecretKeyShare.toBytes", callShareToBytes, &nd);
        bad += try runProbe("SecretKeyShare.fromBytes", callShareFromBytes, &nd);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
