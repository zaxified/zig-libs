// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module: key
//! generation (`x3dh.generateKeyPair`, `generateSignedPreKey`,
//! `pqxdh.generateKemPreKey`), XEdDSA signing, X3DH and PQXDH initiate /
//! respond, and the Double Ratchet (`initAlice`, `initBob`, `encrypt`,
//! `decrypt` with a DH ratchet step). Kept in the module per
//! `CONVENTIONS.md` §9.
//!
//! Engine as `hpke`'s probe (2026-10-08 form). ReleaseFast/ReleaseSmall only —
//! Debug and ReleaseSafe fill `undefined` with 0xaa. Randomness comes from a
//! RECORDING `std.Io`: a copy of `Threaded`'s vtable whose `randomSecure` hands
//! out `SHA-512(label ‖ draw index)` and logs every draw, so the secrets a call
//! mints internally (ephemeral keys, the KEM encapsulation seed, a new ratchet
//! key) are needles. Each adapter rewinds the draw counter, so a call is
//! repeatable and a pre-run in `setUp` yields the same draws.
//!
//! ⚠ The long-lived `ratchet.State` is a by-design holder of the root / chain
//! keys; the target is copies left in DEAD frames by the calls.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const signal = @import("root.zig");
const compat = @import("test_shim.zig");
const x3dh = signal.x3dh;
const pqxdh = signal.pqxdh;
const ratchet = signal.ratchet;
const xeddsa = signal.xeddsa;
const X25519 = std.crypto.dh.X25519;
const Kem = pqxdh.Kem;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Ed = std.crypto.ecc.Edwards25519;
const sc = Ed.scalar;

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
        std.debug.print("\n=== STACKPROBE signal: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

// ── recording Io ────────────────────────────────────────────────────────────

var threaded: std.Io.Threaded = undefined;
var rec_vtable: std.Io.VTable = undefined;
var rec_label: u8 = 0;
var rec_counter: usize = 0;
var rec_log: [16][64]u8 = undefined;
var rec_len: [16]usize = @splat(0);

fn recSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    var o: usize = 0;
    var blk: usize = 0;
    var h: [64]u8 = undefined;
    while (o < buf.len) : (blk += 1) {
        var s = Sha512.init(.{});
        s.update("signal-probe-draw");
        s.update(&[_]u8{rec_label});
        s.update(std.mem.asBytes(&rec_counter));
        s.update(std.mem.asBytes(&blk));
        s.final(&h);
        const k = @min(64, buf.len - o);
        @memcpy(buf[o..][0..k], h[0..k]);
        o += k;
    }
    if (rec_counter < rec_log.len) {
        @memcpy(rec_log[rec_counter][0..@min(64, buf.len)], buf[0..@min(64, buf.len)]);
        rec_len[rec_counter] = buf.len;
    }
    rec_counter += 1;
}

var rec_io: std.Io = undefined;
fn setUpIo() void {
    threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    const base = threaded.io();
    rec_vtable = base.vtable.*;
    rec_vtable.randomSecure = recSecure;
    rec_io = .{ .userdata = base.userdata, .vtable = &rec_vtable };
}

fn rewind() void {
    rec_counter = 0;
}

// ── fixtures ────────────────────────────────────────────────────────────────

const n_cases = 2;
const msg = "signal dead-stack probe message, 40 bytes..";
const initial_pt = "initial plaintext";

var fba_buf: [8192]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;
fn alloc() std.mem.Allocator {
    fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    return fba.allocator();
}

var keep_buf: [32768]u8 = undefined;
var keep_fba: std.heap.FixedBufferAllocator = undefined;
/// Allocator for fixtures that must outlive a call (reset per case).
fn keep() std.mem.Allocator {
    return keep_fba.allocator();
}

fn kpFrom(label: []const u8, i: u8) X25519.KeyPair {
    return X25519.KeyPair.generateDeterministic(seedBytes(32, label, i)) catch unreachable;
}

var alice_ik: x3dh.IdentityKey = undefined;
var bob_ik: x3dh.IdentityKey = undefined;
var bob_spk: x3dh.SignedPreKey = undefined;
var bob_opk: x3dh.OneTimePreKey = undefined;
var bob_kem: pqxdh.KemPreKey = undefined;
var z: xeddsa.RandomData = undefined;
var bundle: x3dh.PreKeyBundle = undefined;
var pq_bundle: pqxdh.PreKeyBundle = undefined;
var x_init: x3dh.InitiateOutput = undefined;
var pq_init: pqxdh.InitiateOutput = undefined;
var alice_state: ratchet.State = undefined;
var bob_state: ratchet.State = undefined;
var alice_pristine: ratchet.State = undefined;
var bob_pristine: ratchet.State = undefined;
var first_msg: ratchet.Message = undefined;
var sk_sink: [32]u8 = undefined;

var kp_sink: X25519.KeyPair = undefined;
var spk_sink: x3dh.SignedPreKey = undefined;
var kem_sink: pqxdh.KemPreKey = undefined;
var sig_sink: xeddsa.Signature = undefined;
var xi_sink: x3dh.InitiateOutput = undefined;
var xr_sink: x3dh.RespondOutput = undefined;
var pi_sink: pqxdh.InitiateOutput = undefined;
var pr_sink: pqxdh.RespondOutput = undefined;
var state_sink: ratchet.State = undefined;
var msg_sink: ratchet.Message = undefined;
var pt_sink: []u8 = undefined;

// ADAPTER: the only block that depends on the call shapes of the module API.
noinline fn callGenKey() void {
    rewind();
    x3dh.generateKeyPair(rec_io, &kp_sink);
}
noinline fn callGenSpk() void {
    rewind();
    x3dh.generateSignedPreKey(&bob_ik, 1, z, rec_io, &spk_sink);
}
noinline fn callGenKem() void {
    rewind();
    pqxdh.generateKemPreKey(&bob_ik, 1, true, z, rec_io, &kem_sink);
}
noinline fn callSign() void {
    sig_sink = xeddsa.sign(&bob_ik.secret_key, msg, z);
}
noinline fn callSignLibsignal() void {
    sig_sink = xeddsa.libsignal.sign(&bob_ik.secret_key, msg, z);
}
noinline fn callXInitiate() void {
    rewind();
    x3dh.initiate(alloc(), &alice_ik, bundle, initial_pt, rec_io, &xi_sink) catch unreachable;
}
noinline fn callXRespond() void {
    x3dh.respond(alloc(), &bob_ik, &bob_spk, &bob_opk, x_init.message, &xr_sink) catch unreachable;
}
noinline fn callPInitiate() void {
    rewind();
    pqxdh.initiate(alloc(), &alice_ik, pq_bundle, initial_pt, rec_io, &pi_sink) catch unreachable;
}
noinline fn callPRespond() void {
    pqxdh.respond(alloc(), &bob_ik, &bob_spk, &bob_opk, &bob_kem, pq_init.message, &pr_sink) catch unreachable;
}
noinline fn callInitAlice() void {
    rewind();
    ratchet.State.initAlice(&x_init.agreement.shared_secret, x_init.agreement.associated_data, bob_spk.key_pair.public_key, rec_io, &state_sink) catch unreachable;
}
noinline fn callInitBob() void {
    ratchet.State.initBob(&x_init.agreement.shared_secret, x_init.agreement.associated_data, &bob_spk.key_pair, &state_sink);
}
noinline fn callEncrypt() void {
    alice_state = alice_pristine;
    msg_sink = alice_state.encrypt(alloc(), msg) catch unreachable;
}
noinline fn callDecrypt() void {
    rewind();
    bob_state = bob_pristine;
    pt_sink = bob_state.decrypt(alloc(), first_msg.header, first_msg.ciphertext, rec_io) catch unreachable;
}
// END ADAPTER

fn setUp(ci: u8) !void {
    keep_fba = std.heap.FixedBufferAllocator.init(&keep_buf);
    setUpIo();
    rec_label = ci;
    alice_ik = kpFrom("signal-alice-ik", ci);
    bob_ik = kpFrom("signal-bob-ik", ci);
    bob_opk = .{ .key_pair = kpFrom("signal-bob-opk", ci), .id = 7 };
    z = seedBytes(64, "signal-z", ci);
    bob_spk = .{ .key_pair = kpFrom("signal-bob-spk", ci), .signature = compat.xeddsa.sign(bob_ik.secret_key, &kpFrom("signal-bob-spk", ci).public_key, z), .id = 1 };
    const kem_kp = Kem.KeyPair.generateDeterministic(seedBytes(Kem.seed_length, "signal-kem", ci)) catch unreachable;
    bob_kem = .{ .key_pair = kem_kp, .signature = compat.xeddsa.sign(bob_ik.secret_key, &kem_kp.public_key.toBytes(), z), .id = 3, .last_resort = true };
    bundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
        .one_time_prekey = bob_opk.key_pair.public_key,
        .one_time_prekey_id = bob_opk.id,
    };
    pq_bundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
        .one_time_prekey = bob_opk.key_pair.public_key,
        .one_time_prekey_id = bob_opk.id,
        .kem_prekey = kem_kp.public_key.toBytes(),
        .kem_prekey_id = bob_kem.id,
        .kem_prekey_signature = bob_kem.signature,
    };
    rewind();
    x_init = try compat.x3dh.initiate(keep(), alice_ik, bundle, initial_pt, rec_io);
    rewind();
    pq_init = try compat.pqxdh.initiate(keep(), alice_ik, pq_bundle, initial_pt, rec_io);
    rewind();
    alice_pristine = try compat.State.initAlice(x_init.agreement.shared_secret, x_init.agreement.associated_data, bob_spk.key_pair.public_key, rec_io);
    bob_pristine = compat.State.initBob(x_init.agreement.shared_secret, x_init.agreement.associated_data, bob_spk.key_pair);
    var a2 = alice_pristine;
    first_msg = try a2.encrypt(keep(), msg);
    leak_src = bob_ik.secret_key;
}

// ── needle helpers (an independent recomputation of the intermediates) ─────

fn dhOut(sk: [32]u8, pk: [32]u8) [32]u8 {
    return X25519.scalarmult(sk, pk) catch unreachable;
}

const Xdh = struct { dh1: [32]u8, dh2: [32]u8, dh3: [32]u8, dh4: [32]u8, km: [32 * 5]u8, prk: [32]u8, sk: [32]u8 };

fn x3dhSecrets(dh1: [32]u8, dh2: [32]u8, dh3: [32]u8, dh4: [32]u8) Xdh {
    var r: Xdh = undefined;
    r.dh1 = dh1;
    r.dh2 = dh2;
    r.dh3 = dh3;
    r.dh4 = dh4;
    r.km = x3dh.f_constant ++ dh1 ++ dh2 ++ dh3 ++ dh4;
    r.prk = HkdfSha256.extract(&([_]u8{0} ** 32), &r.km);
    HkdfSha256.expand(&r.sk, x3dh.x3dh_info, r.prk);
    return r;
}

fn addX(n: *Needles, x: *const Xdh) void {
    n.addBytes("dh1", &x.dh1);
    n.addBytes("dh2", &x.dh2);
    n.addBytes("dh3", &x.dh3);
    n.addBytes("dh4", &x.dh4);
    n.addBytes("km", &x.km);
    n.addBytes("prk", &x.prk);
    n.addBytes("SK", &x.sk);
    var okm: [44]u8 = undefined;
    HkdfSha256.expand(&okm, "zig-libs/signal/initial-message/v1", x.sk);
    n.addBytes("aead key", okm[0..32]);
}

fn addPqSecrets(n: *Needles, dh1: [32]u8, dh2: [32]u8, dh3: [32]u8, dh4: [32]u8, ss: [32]u8) [32]u8 {
    const km = pqxdh.f_constant ++ dh1 ++ dh2 ++ dh3 ++ dh4 ++ ss;
    n.addBytes("dh1", &dh1);
    n.addBytes("dh2", &dh2);
    n.addBytes("dh3", &dh3);
    n.addBytes("dh4", &dh4);
    n.addBytes("kem ss", &ss);
    n.addBytes("km", &km);
    const prk = HkdfSha256.extract(&([_]u8{0} ** 32), &km);
    n.addBytes("prk", &prk);
    var sk: [32]u8 = undefined;
    HkdfSha256.expand(&sk, pqxdh.pqxdh_info, prk);
    n.addBytes("SK", &sk);
    var okm: [44]u8 = undefined;
    HkdfSha256.expand(&okm, "zig-libs/signal/initial-message/v1", sk);
    n.addBytes("aead key", okm[0..32]);
    return sk;
}

fn addDk(n: *Needles, kp: Kem.KeyPair) void {
    const dk = kp.secret_key.toBytes();
    n.addImage("kem dk 0", dk[0..160]);
    n.addImage("kem dk 1", dk[1200..1360]);
    n.addImage("kem dk 2", dk[2400..2560]);
}

/// XEdDSA's secret scalar (sign-0 form) and the nonce `r`.
fn xeddsaSecrets(n: *Needles, priv: [32]u8, with_sign_bit: bool) void {
    var k = priv;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    var a = sc.reduce(k);
    const pub_a = Ed.basePoint.mul(a) catch unreachable;
    if (!with_sign_bit and (pub_a.toBytes()[31] >> 7) == 1) a = sc.neg(a);
    n.addBytes("xeddsa a", &a);
    var s = Sha512.init(.{});
    s.update(&([_]u8{0xFE} ++ [_]u8{0xFF} ** 31));
    s.update(&a);
    s.update(msg);
    s.update(&z);
    var r64: [64]u8 = undefined;
    s.final(&r64);
    n.addBytes("xeddsa r64", &r64);
    n.addBytes("xeddsa r", &sc.reduce64(r64));
}

fn kdfRk(rk: [32]u8, dh_out: [32]u8) struct { rk: [32]u8, ck: [32]u8 } {
    const prk = HkdfSha256.extract(&rk, &dh_out);
    var okm: [64]u8 = undefined;
    HkdfSha256.expand(&okm, ratchet.kdf_rk_info, prk);
    return .{ .rk = okm[0..32].*, .ck = okm[32..].* };
}

fn addChain(n: *Needles, ck: [32]u8, tag: []const u8) void {
    _ = tag;
    var mk: [32]u8 = undefined;
    var next: [32]u8 = undefined;
    HmacSha256.create(&mk, &[_]u8{0x01}, &ck);
    HmacSha256.create(&next, &[_]u8{0x02}, &ck);
    n.addBytes("ck", &ck);
    n.addBytes("mk", &mk);
    n.addBytes("ck'", &next);
    var okm: [44]u8 = undefined;
    HkdfSha256.expand(&okm, ratchet.aead_info, mk);
    n.addBytes("aead key", okm[0..32]);
}

test "STACKPROBE: no key, DH or ratchet residue on the dead stack (signal)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};

        // x3dh.generateKeyPair: the drawn seed (= the secret key).
        rewind();
        const k0 = compat.x3dh.generateKeyPair(rec_io);
        n.addBytes("seed/sk", &k0.secret_key);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("generateKeyPair", callGenKey, &n);

        // generateSignedPreKey: identity key, new key, signing nonce.
        rewind();
        const spk0 = compat.x3dh.generateSignedPreKey(bob_ik, 1, z, rec_io);
        n = .{};
        n.addBytes("identity sk", &bob_ik.secret_key);
        n.addBytes("spk sk", &spk0.key_pair.secret_key);
        xeddsaSecrets(&n, bob_ik.secret_key, false);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("generateSignedPreKey", callGenSpk, &n);

        // generateKemPreKey: identity key, the 64-byte KEM seed, dk fragments.
        rewind();
        const kem0 = compat.pqxdh.generateKemPreKey(bob_ik, 1, true, z, rec_io);
        n = .{};
        n.addBytes("identity sk", &bob_ik.secret_key);
        n.addBytes("kem seed", rec_log[0][0..64]);
        addDk(&n, kem0.key_pair);
        xeddsaSecrets(&n, bob_ik.secret_key, false);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("generateKemPreKey", callGenKem, &n);

        // xeddsa.sign / libsignal.sign.
        n = .{};
        n.addBytes("identity sk", &bob_ik.secret_key);
        xeddsaSecrets(&n, bob_ik.secret_key, false);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("xeddsa.sign", callSign, &n);
        n = .{};
        n.addBytes("identity sk", &bob_ik.secret_key);
        xeddsaSecrets(&n, bob_ik.secret_key, true);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("xeddsa.libsignal.sign", callSignLibsignal, &n);

        // x3dh.initiate: Alice's key, EK (draw 0), four DHs, KDF chain.
        const ek = X25519.KeyPair.generateDeterministic(rec_log[0][0..32].*) catch unreachable;
        const xs = x3dhSecrets(
            dhOut(alice_ik.secret_key, bob_spk.key_pair.public_key),
            dhOut(ek.secret_key, bob_ik.public_key),
            dhOut(ek.secret_key, bob_spk.key_pair.public_key),
            dhOut(ek.secret_key, bob_opk.key_pair.public_key),
        );
        n = .{};
        n.addBytes("alice ik sk", &alice_ik.secret_key);
        n.addBytes("ek sk", &ek.secret_key);
        addX(&n, &xs);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("x3dh.initiate", callXInitiate, &n);

        // x3dh.respond: Bob's three keys, the same DHs.
        n = .{};
        n.addBytes("bob ik sk", &bob_ik.secret_key);
        n.addBytes("spk sk", &bob_spk.key_pair.secret_key);
        n.addBytes("opk sk", &bob_opk.key_pair.secret_key);
        addX(&n, &xs);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("x3dh.respond", callXRespond, &n);

        // pqxdh.initiate / respond.
        // The pre-run draws: 0 = EK, 1 = encaps seed.
        rewind();
        const pq0 = try compat.pqxdh.initiate(keep(), alice_ik, pq_bundle, initial_pt, rec_io);
        const ek2 = X25519.KeyPair.generateDeterministic(rec_log[0][0..32].*) catch unreachable;
        const dk1 = dhOut(alice_ik.secret_key, bob_spk.key_pair.public_key);
        const dk2 = dhOut(ek2.secret_key, bob_ik.public_key);
        const dk3 = dhOut(ek2.secret_key, bob_spk.key_pair.public_key);
        const dk4 = dhOut(ek2.secret_key, bob_opk.key_pair.public_key);
        const kem_ss = bob_kem.key_pair.secret_key.decaps(&pq0.message.kem_ciphertext) catch unreachable;
        n = .{};
        n.addBytes("alice ik sk", &alice_ik.secret_key);
        n.addBytes("ek sk", &ek2.secret_key);
        n.addBytes("encaps seed", rec_log[1][0..32]);
        _ = addPqSecrets(&n, dk1, dk2, dk3, dk4, kem_ss);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("pqxdh.initiate", callPInitiate, &n);

        n = .{};
        n.addBytes("bob ik sk", &bob_ik.secret_key);
        n.addBytes("spk sk", &bob_spk.key_pair.secret_key);
        n.addBytes("opk sk", &bob_opk.key_pair.secret_key);
        addDk(&n, bob_kem.key_pair);
        const pq_ss = bob_kem.key_pair.secret_key.decaps(&pq_init.message.kem_ciphertext) catch unreachable;
        const ek3 = pq_init.message.ephemeral_key;
        _ = addPqSecrets(
            &n,
            dhOut(bob_spk.key_pair.secret_key, alice_ik.public_key),
            dhOut(bob_ik.secret_key, ek3),
            dhOut(bob_spk.key_pair.secret_key, ek3),
            dhOut(bob_opk.key_pair.secret_key, ek3),
            pq_ss,
        );
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("pqxdh.respond", callPRespond, &n);

        // ratchet.initAlice: sk, ratchet key (draw 0), DH, KDF_RK output.
        rewind();
        const ra = try compat.State.initAlice(x_init.agreement.shared_secret, x_init.agreement.associated_data, bob_spk.key_pair.public_key, rec_io);
        n = .{};
        n.addBytes("SK", &x_init.agreement.shared_secret);
        n.addBytes("dhs sk", &ra.dhs.secret_key);
        n.addBytes("dh_out", &dhOut(ra.dhs.secret_key, bob_spk.key_pair.public_key));
        n.addBytes("rk", &ra.rk);
        n.addBytes("cks", &ra.cks.?);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("State.initAlice", callInitAlice, &n);

        // ratchet.initBob: sk and the ratchet key.
        n = .{};
        n.addBytes("SK", &x_init.agreement.shared_secret);
        n.addBytes("spk sk", &bob_spk.key_pair.secret_key);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("State.initBob", callInitBob, &n);

        // encrypt: chain key, message key, next chain key, AEAD key.
        n = .{};
        n.addBytes("rk", &alice_pristine.rk);
        n.addBytes("dhs sk", &alice_pristine.dhs.secret_key);
        addChain(&n, alice_pristine.cks.?, "send");
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("State.encrypt", callEncrypt, &n);

        // decrypt with a DH ratchet step (Bob's first receive).
        const hdr = first_msg.header;
        const dh_recv = dhOut(bob_pristine.dhs.secret_key, hdr.dh);
        const recv = kdfRk(bob_pristine.rk, dh_recv);
        rewind();
        var b2 = bob_pristine;
        const pt0 = try b2.decrypt(alloc(), hdr, first_msg.ciphertext, rec_io);
        _ = pt0;
        const new_seed: [32]u8 = rec_log[0][0..32].*;
        const new_dhs = X25519.KeyPair.generateDeterministic(new_seed) catch unreachable;
        const dh_send = dhOut(new_dhs.secret_key, hdr.dh);
        const send = kdfRk(recv.rk, dh_send);
        n = .{};
        n.addBytes("rk (old)", &bob_pristine.rk);
        n.addBytes("dhs sk (old)", &bob_pristine.dhs.secret_key);
        n.addBytes("dh_recv", &dh_recv);
        n.addBytes("new dhs sk", &new_dhs.secret_key);
        n.addBytes("dh_send", &dh_send);
        n.addBytes("rk (new)", &send.rk);
        n.addBytes("cks (new)", &send.ck);
        addChain(&n, recv.ck, "recv");
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("State.decrypt (DH ratchet)", callDecrypt, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
