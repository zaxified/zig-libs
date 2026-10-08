// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the ECDH-ES secret paths of jwe: ephemeral key
//! generation, the ECDH shared secret `Z` (`deriveZ`), the Concat KDF and the
//! two public ECDH-ES entry points (`encryptCompact` / `decryptCompact`).
//! Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `p256`'s probe: paint a stack window, run the call `PAD` bytes
//! deeper than the probe, snapshot, and look for secrets. ReleaseFast/
//! ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with 0xaa, so the
//! scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in
//! (big-endian, little-endian, the in-memory form of the scalar / field
//! element), so a half copy or a limb pair counts too.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks the secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const p256 = @import("p256");
const jwe = @import("root.zig");
const ecdhes = jwe.ecdhes;

const P256 = p256.P256;
const Scalar = p256.Scalar;
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
        std.debug.print("\n=== STACKPROBE jwe: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

/// Audit-local seeds: hashes of a label, so no 16-byte window of what they
/// produce is a run of zeros or of paint that a dead stack holds anyway.
fn caseSeed(i: u8, tag: u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&[_]u8{ 'j', 'w', 'e', '-', tag, i }, &out, .{});
    return out;
}
const n_cases = 2;

fn addScalarImages(n: *Needles, name: []const u8, d: [32]u8) !void {
    n.addBytes32(name, d);
    const s = try Scalar.fromBytes(d, .big);
    n.addImage(name, std.mem.asBytes(&s));
}

/// The scalar plus the shared point `d·peer` in every form the code holds it in.
fn ecdhNeedles(n: *Needles, d: [32]u8, peer: P256) !void {
    try addScalarImages(n, "d", d);
    const shared = (try peer.mul(d, .big)).affineCoordinates();
    n.addBytes32("Z", shared.x.toBytes(.big));
    n.addBytes32("shared y", shared.y.toBytes(.big));
    n.addImage("Z fe", std.mem.asBytes(&shared.x));
    n.addImage("shared y fe", std.mem.asBytes(&shared.y));
}

fn kdfNeedles(n: *Needles, z: [32]u8, alg_id: []const u8, len: usize) void {
    n.addBytes32("Z", z);
    var full: [32]u8 = undefined;
    ecdhes.concatKdfSha256(&z, alg_id, "apu", "apv", full[0..len]);
    n.addImage("derived", full[0..len]);
}

// ── the probed calls (all `noinline`, secrets read from static memory) ──────

/// The csprng lives in static memory: a stack-local one would hold the drawn
/// scalar in its keystream buffer, and that is the caller's storage, not the
/// module's.
var rng_state: std.Random.DefaultCsprng = undefined;
var rng_seed: [32]u8 = undefined;
/// Re-seeding runs `ChaCha`'s block function, whose stack temporary holds the
/// first keystream block — i.e. the scalar the module is about to draw. That
/// is the CALLER's entropy setup, not the module's: zero it before the
/// measured call, or the scan finds the scalar in `encryptCompact`'s
/// still-uninitialised frame (2026-10-08: 16 B at 575 B on the encrypt side
/// only, never on decrypt, which draws nothing).
noinline fn reseed() void {
    rng_state = std.Random.DefaultCsprng.init(rng_seed);
}
fn freshEntropy() jwe.Entropy {
    reseed();
    @import("burn.zig").stack(16 * 1024);
    return .{ .fixed_for_test = rng_state.random() };
}

var cur_kp: ecdhes.EphemeralKeyPair = undefined; // the "recipient"
var cur_peer: ecdhes.PublicKey = undefined;
var cur_z: [32]u8 = undefined;
var cur_token: []u8 = &.{};
var kp_sink: ecdhes.EphemeralKeyPair = undefined;
var z_sink: [ecdhes.max_z_len]u8 = undefined;
var derived_sink: [32]u8 = undefined;
var tok_sink: ?[]u8 = null;
var pt_sink: ?[]u8 = null;

noinline fn callGenerate() void {
    ecdhes.generateEphemeral(&kp_sink, .p256, freshEntropy());
}
noinline fn callDeriveZ() void {
    _ = ecdhes.deriveZ(&cur_kp.private, cur_peer, &z_sink) catch unreachable;
}
noinline fn callKdfKw() void {
    ecdhes.concatKdfSha256(&cur_z, "ECDH-ES+A128KW", "apu", "apv", derived_sink[0..16]);
}
noinline fn callKdfDirect() void {
    ecdhes.concatKdfSha256(&cur_z, "A256GCM", "apu", "apv", derived_sink[0..32]);
}
noinline fn callEncrypt(comptime a: jwe.Alg, comptime e: jwe.Enc) void {
    tok_sink = jwe.encryptCompact(std.heap.page_allocator, a, e, .{ .ec_public = cur_peer }, "attack at dawn", "", freshEntropy(), .{ .apu = "apu", .apv = "apv" }) catch unreachable; // global-alloc-ok: stack probe; a heap the scan never reads, kept out of the measured frames
}
noinline fn callDecrypt() void {
    pt_sink = jwe.decryptCompact(std.heap.page_allocator, .{ .ec_private = &cur_kp.private }, cur_token, .{}) catch unreachable; // global-alloc-ok: stack probe; a heap the scan never reads, kept out of the measured frames
}
noinline fn callEncKw() void {
    callEncrypt(.@"ECDH-ES+A128KW", .A128GCM);
}
noinline fn callEncDirect() void {
    callEncrypt(.@"ECDH-ES", .A256GCM);
}

fn setup(ci: usize) !void {
    rng_seed = caseSeed(@intCast(ci), 'r');
    ecdhes.generateEphemeral(&cur_kp, .p256, freshEntropy());
    var peer_seed = caseSeed(@intCast(ci), 'p');
    var prng = std.Random.DefaultCsprng.init(peer_seed);
    peer_seed = undefined;
    var peer_kp: ecdhes.EphemeralKeyPair = undefined;
    ecdhes.generateEphemeral(&peer_kp, .p256, .{ .fixed_for_test = prng.random() });
    cur_peer = peer_kp.public;
    leak_src = cur_kp.private.p256;
    const shared = (try peer_kp.public.p256.mul(cur_kp.private.p256, .big)).affineCoordinates();
    cur_z = shared.x.toBytes(.big);
}

test "STACKPROBE: no scalar or Z residue after ephemeral generation, deriveZ and the KDF" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setup(ci);
        var n: Needles = .{};
        try addScalarImages(&n, "d", cur_kp.private.p256);
        n.sort();
        bad += try runProbe("generateEphemeral(p256)", callGenerate, &n);

        n = .{};
        try ecdhNeedles(&n, cur_kp.private.p256, cur_peer.p256);
        n.sort();
        bad += try runProbe("deriveZ(p256)", callDeriveZ, &n);

        n = .{};
        kdfNeedles(&n, cur_z, "ECDH-ES+A128KW", 16);
        n.sort();
        leak_src = cur_z;
        bad += try runProbe("concatKdfSha256 (KEK)", callKdfKw, &n);

        n = .{};
        kdfNeedles(&n, cur_z, "A256GCM", 32);
        n.sort();
        leak_src = cur_z;
        bad += try runProbe("concatKdfSha256 (CEK)", callKdfDirect, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no key residue after ECDH-ES encryptCompact / decryptCompact" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setup(ci);
        // The encrypt side draws its ephemeral key first, from the case seed.
        rng_state = std.Random.DefaultCsprng.init(rng_seed);
        var eph: ecdhes.EphemeralKeyPair = undefined;
        ecdhes.generateEphemeral(&eph, .p256, .{ .fixed_for_test = rng_state.random() });
        const eshared = (try cur_peer.p256.mul(eph.private.p256, .big)).affineCoordinates();
        const ez = eshared.x.toBytes(.big);

        var n: Needles = .{};
        try ecdhNeedles(&n, eph.private.p256, cur_peer.p256);
        kdfNeedles(&n, ez, "ECDH-ES+A128KW", 16);
        n.sort();
        bad += try runProbe("encryptCompact ECDH-ES+A128KW", callEncKw, &n);

        n = .{};
        try ecdhNeedles(&n, eph.private.p256, cur_peer.p256);
        kdfNeedles(&n, ez, "A256GCM", 32);
        n.sort();
        bad += try runProbe("encryptCompact ECDH-ES direct", callEncDirect, &n);

        // Decrypt side: the recipient's static key is `cur_kp`; tokens are
        // made to it. Re-key the "peer" as the recipient's public key.
        const recipient_pub = ecdhes.PublicKey{ .p256 = (try P256.basePoint.mul(cur_kp.private.p256, .big)) };
        const saved_peer = cur_peer;
        cur_peer = recipient_pub;
        defer cur_peer = saved_peer;
        for ([_]struct { a: jwe.Alg, e: jwe.Enc, id: []const u8, len: usize, label: []const u8 }{
            .{ .a = .@"ECDH-ES+A128KW", .e = .A128GCM, .id = "ECDH-ES+A128KW", .len = 16, .label = "decryptCompact ECDH-ES+A128KW" },
            .{ .a = .@"ECDH-ES", .e = .A256GCM, .id = "A256GCM", .len = 32, .label = "decryptCompact ECDH-ES direct" },
        }) |c| {
            rng_seed = caseSeed(@intCast(ci), 't');
            const tok = try jwe.encryptCompact(std.heap.page_allocator, c.a, c.e, .{ .ec_public = recipient_pub }, "attack at dawn", "", freshEntropy(), .{ .apu = "apu", .apv = "apv" });
            cur_token = tok;
            // Recover the token's Z from its epk with the recipient's key.
            var parts = std.mem.splitScalar(u8, tok, '.');
            var hdr_buf: [512]u8 = undefined;
            const hb64 = parts.next().?;
            const hn = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(hb64);
            try std.base64.url_safe_no_pad.Decoder.decode(hdr_buf[0..hn], hb64);
            const parsed = try std.json.parseFromSlice(struct { epk: struct { x: []const u8, y: []const u8 } }, std.heap.page_allocator, hdr_buf[0..hn], .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            var ex: [32]u8 = undefined;
            var ey: [32]u8 = undefined;
            try std.base64.url_safe_no_pad.Decoder.decode(&ex, parsed.value.epk.x);
            try std.base64.url_safe_no_pad.Decoder.decode(&ey, parsed.value.epk.y);
            const epk = try P256.fromSerializedAffineCoordinates(ex, ey, .big);
            const dz = (try epk.mul(cur_kp.private.p256, .big)).affineCoordinates().x.toBytes(.big);

            n = .{};
            try ecdhNeedles(&n, cur_kp.private.p256, epk);
            kdfNeedles(&n, dz, c.id, c.len);
            n.sort();
            bad += try runProbe(c.label, callDecrypt, &n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
