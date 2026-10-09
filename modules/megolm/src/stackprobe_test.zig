// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for every secret path of the module:
//! `OutboundSession.init` / `encrypt` / `sessionKey`, `InboundGroupSession`
//! import / `decrypt` / `exportAt` / `forgetBefore`, the pickles (plain and
//! sealed, both directions). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Engine as `hpke`'s probe (2026-10-08 form). ReleaseFast/ReleaseSmall only —
//! Debug and ReleaseSafe fill `undefined` with 0xaa. Randomness comes from a
//! RECORDING `std.Io` (a copy of `Threaded`'s vtable whose `randomSecure`
//! hands out `SHA-512(label ‖ draw index)` and logs every draw), so R0 and the
//! signing seed minted inside `OutboundSession.init` are needles.
//!
//! ⚠ The sessions hold the ratchet and the signing key in long-lived structs
//! by design; the target is copies left in DEAD frames by the calls.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a key in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const megolm = @import("root.zig");
const Sha512 = std.crypto.hash.sha2.Sha512;
const Aes256 = std.crypto.core.aes.Aes256;
const Ed25519 = std.crypto.sign.Ed25519;
const compat = @import("test_shim.zig");
const OutboundSession = megolm.OutboundSession;
const InboundGroupSession = megolm.InboundGroupSession;

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
        std.debug.print("\n=== STACKPROBE megolm: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
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

const n_cases = 2;
const text = "megolm dead-stack probe plaintext, longer than a block";

var fba_buf: [8192]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;
fn alloc() std.mem.Allocator {
    fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    return fba.allocator();
}

var out_s: OutboundSession = undefined;
var out_pristine: OutboundSession = undefined;
var in_s: InboundGroupSession = undefined;
var in_pristine: InboundGroupSession = undefined;
var skey: megolm.SessionKey = undefined;
var xkey: megolm.ExportedSessionKey = undefined;
var wire: megolm.Message = undefined;
var wire_buf: [1024]u8 = undefined;
var pickle_key: megolm.PickleKey = undefined;
var plain_out: [megolm.pickle.outbound_len]u8 = undefined;
var plain_in: [megolm.pickle.inbound_len]u8 = undefined;
var sealed_out: [megolm.pickle.sealed_outbound_len]u8 = undefined;
var sealed_in: [megolm.pickle.sealed_inbound_len]u8 = undefined;
const target_index: u32 = 5;

var o_sink: OutboundSession = undefined;
var i_sink: InboundGroupSession = undefined;
var skey_sink: megolm.SessionKey = undefined;
var xkey_sink: megolm.ExportedSessionKey = undefined;
var msg_sink: megolm.Message = undefined;
var dec_sink: megolm.session.DecryptedMessage = undefined;
var bool_sink: bool = undefined;
var rt_sink: megolm.Ratchet = undefined;

// ADAPTER: the only block that depends on the call shapes of the module API.
noinline fn callInit() void {
    rewind();
    OutboundSession.init(rec_io, &o_sink);
}
noinline fn callEncrypt() void {
    out_s = out_pristine;
    msg_sink = out_s.encrypt(alloc(), text) catch unreachable;
}
noinline fn callSessionKey() void {
    out_s.sessionKey(&skey_sink) catch unreachable;
}
noinline fn callFromSessionKey() void {
    InboundGroupSession.fromSessionKey(&skey, &i_sink) catch unreachable;
}
noinline fn callFromExported() void {
    InboundGroupSession.fromExportedKey(&xkey, &i_sink) catch unreachable;
}
noinline fn callDecrypt() void {
    in_s = in_pristine;
    dec_sink = in_s.decrypt(alloc(), &wire) catch unreachable;
}
noinline fn callExportAt() void {
    in_s = in_pristine;
    bool_sink = in_s.exportAt(target_index, &xkey_sink);
}
noinline fn callForgetBefore() void {
    in_s = in_pristine;
    bool_sink = in_s.forgetBefore(target_index);
}
noinline fn callAdvanceTo() void {
    rt_sink = in_pristine.initial_ratchet;
    rt_sink.advanceTo(target_index) catch unreachable;
}
noinline fn callPickleOut() void {
    out_s.pickle(&plain_out);
}
noinline fn callPickleIn() void {
    in_s.pickle(&plain_in);
}
noinline fn callSealOut() void {
    rewind();
    out_s.pickleSealed(rec_io, &pickle_key, &sealed_out);
}
noinline fn callFromPickleOut() void {
    OutboundSession.fromPickle(&plain_out, &o_sink) catch unreachable;
}
noinline fn callFromPickleIn() void {
    InboundGroupSession.fromPickle(&plain_in, &i_sink) catch unreachable;
}
noinline fn callFromSealedOut() void {
    OutboundSession.fromSealedPickle(&sealed_out, &pickle_key, &o_sink) catch unreachable;
}
noinline fn callFromSealedIn() void {
    InboundGroupSession.fromSealedPickle(&sealed_in, &pickle_key, &i_sink) catch unreachable;
}
// END ADAPTER

fn setUp(ci: u8) !void {
    setUpIo();
    rec_label = ci;
    rewind();
    out_pristine = compat.outboundInit(rec_io);
    out_s = out_pristine;
    skey = try compat.sessionKey(&out_s);
    in_pristine = try compat.fromSessionKey(skey);
    in_s = in_pristine;
    xkey = compat.exportAt(&in_s, 3).?;
    // The wire message under test is at `target_index`: encrypt up to it.
    var enc = out_pristine;
    var i: u32 = 0;
    while (i < target_index) : (i += 1) {
        var m = try enc.encrypt(fbaKeep(), text);
        _ = &m;
    }
    wire = try enc.encrypt(fbaKeep(), text);
    pickle_key = seedBytes(32, "megolm-pickle-key", ci);
    out_pristine.pickle(&plain_out);
    in_pristine.pickle(&plain_in);
    rewind();
    out_pristine.pickleSealed(rec_io, &pickle_key, &sealed_out);
    in_pristine.pickleSealed(rec_io, &pickle_key, &sealed_in);
    out_s = out_pristine;
    leak_src = out_pristine.signing_key.secret_key.bytes[0..32].*;
}

var keep_buf: [65536]u8 = undefined;
var keep_fba: std.heap.FixedBufferAllocator = std.heap.FixedBufferAllocator.init(&keep_buf);
fn fbaKeep() std.mem.Allocator {
    return keep_fba.allocator();
}

// ── needle helpers ──────────────────────────────────────────────────────────

fn addRatchet(n: *Needles, name: []const u8, r: *const megolm.Ratchet) void {
    n.addBytes(name, &r.data);
    for (0..4) |p| n.addBytes(name, r.data[p * 32 ..][0..32]);
}

fn addKeys(n: *Needles, r: *const megolm.Ratchet) void {
    const k = megolm.cipher.deriveKeys(&r.data);
    n.addBytes("aes key", &k.aes_key);
    n.addBytes("hmac key", &k.hmac_key);
    n.addBytes("iv", &k.iv);
    const ctx = Aes256.initEnc(k.aes_key);
    n.addImage("aes round keys", std.mem.asBytes(&ctx));
    const dec = Aes256.initDec(k.aes_key);
    n.addImage("aes dec round keys", std.mem.asBytes(&dec));
}

fn addSigning(n: *Needles, s: *const OutboundSession) void {
    n.addBytes("signing key", &s.signing_key.secret_key.bytes);
    n.addBytes("signing seed", s.signing_key.secret_key.bytes[0..32]);
}

fn ratchetAt(from: *const megolm.Ratchet, idx: u32) megolm.Ratchet {
    var r = from.*;
    r.advanceTo(idx) catch unreachable;
    return r;
}

test "STACKPROBE: no ratchet, key or signing-key residue on the dead stack (megolm)" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..n_cases) |ci| {
        try setUp(@intCast(ci));
        var n: Needles = .{};
        const r0 = &out_pristine.ratchet;

        // OutboundSession.init: R0 (draw 0) and the signing seed (draw 1).
        n = .{};
        n.addBytes("R0", &r0.data);
        addSigning(&n, &out_pristine);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("OutboundSession.init", callInit, &n);

        // encrypt: ratchet, derived keys, signing key.
        n = .{};
        addRatchet(&n, "R", r0);
        addKeys(&n, r0);
        addSigning(&n, &out_pristine);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("OutboundSession.encrypt", callEncrypt, &n);

        // sessionKey: ratchet + signing key.
        n = .{};
        addRatchet(&n, "R", r0);
        addSigning(&n, &out_pristine);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("OutboundSession.sessionKey", callSessionKey, &n);

        // import: the ratchet.
        n = .{};
        addRatchet(&n, "R", r0);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("InboundGroupSession.fromSessionKey", callFromSessionKey, &n);
        n = .{};
        const rx = ratchetAt(r0, 3);
        addRatchet(&n, "R", &rx);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("InboundGroupSession.fromExportedKey", callFromExported, &n);

        // decrypt at the target index: initial ratchet, advanced ratchet, keys.
        const rt = ratchetAt(r0, target_index);
        n = .{};
        addRatchet(&n, "R0", r0);
        addRatchet(&n, "Rt", &rt);
        addKeys(&n, &rt);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("InboundGroupSession.decrypt", callDecrypt, &n);

        // exportAt / forgetBefore / advanceTo.
        n = .{};
        addRatchet(&n, "R0", r0);
        addRatchet(&n, "Rt", &rt);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("InboundGroupSession.exportAt", callExportAt, &n);
        bad += try runProbe("InboundGroupSession.forgetBefore", callForgetBefore, &n);
        bad += try runProbe("Ratchet.advanceTo", callAdvanceTo, &n);

        // pickles.
        n = .{};
        addRatchet(&n, "R", r0);
        addSigning(&n, &out_pristine);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("OutboundSession.pickle", callPickleOut, &n);
        bad += try runProbe("OutboundSession.fromPickle", callFromPickleOut, &n);
        n = .{};
        addRatchet(&n, "R0", r0);
        addRatchet(&n, "Rt", &rt);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("InboundGroupSession.pickle", callPickleIn, &n);
        bad += try runProbe("InboundGroupSession.fromPickle", callFromPickleIn, &n);
        n = .{};
        addRatchet(&n, "R", r0);
        addSigning(&n, &out_pristine);
        n.addBytes("pickle key", &pickle_key);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("OutboundSession.pickleSealed", callSealOut, &n);
        bad += try runProbe("OutboundSession.fromSealedPickle", callFromSealedOut, &n);
        n = .{};
        addRatchet(&n, "R0", r0);
        addRatchet(&n, "Rt", &rt);
        n.addBytes("pickle key", &pickle_key);
        n.addBytes("control", &leak_src);
        n.sort();
        bad += try runProbe("InboundGroupSession.fromSealedPickle", callFromSealedIn, &n);
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
