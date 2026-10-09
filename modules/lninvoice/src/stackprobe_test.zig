// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `lninvoice`'s signing entry points (review
//! 2026-10-09; SPEC § "Secret residue on the dead stack"). The signatures are
//! `k256`'s (`ecdsa_recover.sign`, RFC 6979) and `bip340`'s (`sign`), each
//! burned and probed in its own module; this probe checks what THIS module's
//! frames around them leave: BOLT#11 `encode` with `.private_key`, BOLT#12
//! `signMerkle`, `encodeSignedInvoiceRequest`, `encodeSignedInvoice`.
//!
//! Method as `noise`'s and `bip340`'s probes: a painted region below the probe,
//! one call under a `PAD`-deep shim, the region scanned for 32-byte needles.
//! ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with
//! 0xaa. The heap goes through a global `FixedBufferAllocator` (its buffer is
//! not in the scanned window).
//!
//! Needles: the private key (big-endian, little-endian, the scalar field's
//! in-memory image); for BOLT#11 the ECDSA nonce `k` and `k^-1` recovered
//! from the published signature (`k = s^-1 (h + r d)`, both signs, since a
//! high `s` is negated), for BOLT#12 the BIP340 nonce material `t`, `rand`,
//! `k'` and `n-k'` and the effective scalar `n-d`. Needles are computed AFTER
//! the measured calls, from their output, so the probe's own copies are never
//! in the snapshot.
//!
//! ⛔ A zero is only readable next to the two controls: NEG (a call that never
//! sees a secret finds 0) and POS (a call that parks the control needle in a
//! local finds it).

const std = @import("std");
const builtin = @import("builtin");
const bolt11 = @import("bolt11.zig");
const bolt12 = @import("bolt12.zig");
const bech32raw = @import("bech32_raw.zig");
const bitpack = @import("bitpack.zig");
const bip340 = @import("bip340");
const lnwire = @import("lnwire");
const G = @import("k256").Secp256k1;
const Scalar = G.scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Set `true` to print every call's residue and dirty depth.
const verbose = false;

const WINDOW = 256 * 1024;
const PAD = 2048;

const Needle = struct { name: []const u8, bytes: [32]u8 };
const max_needles = 24;

const Needles = struct {
    items: [max_needles]Needle = undefined,
    len: usize = 0,

    fn add(self: *Needles, name: []const u8, bytes: [32]u8) void {
        self.items[self.len] = .{ .name = name, .bytes = bytes };
        self.len += 1;
    }

    /// A scalar big-endian, little-endian and as the field holds it.
    fn addScalar(self: *Needles, comptime name: []const u8, s: Scalar) void {
        const be = s.toBytes(.big);
        self.add(name ++ ", big-endian", be);
        self.add(name ++ ", little-endian", s.toBytes(.little));
        self.add(name ++ ", Scalar in-memory", std.mem.asBytes(&s).*);
    }

    fn slice(self: *const Needles) []const Needle {
        return self.items[0..self.len];
    }
};

// ── the measured region (engine as noise's probe) ────────────────────────────

var region_lo: usize = 0;
var snaps: [4][WINDOW]u8 = undefined;
var ctl_snaps: [2][WINDOW]u8 = undefined;
var snap: *[WINDOW]u8 = &snaps[0];

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
    for (snap, 0..) |*d, i| d.* = p[i];
}

/// The callee-saved registers still hold the test's own values; the call's
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

fn dirtyDepth(s: *const [WINDOW]u8) usize {
    var i: usize = 0;
    while (i < WINDOW and s[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

fn countIn(s: *const [WINDOW]u8, needle: *const [32]u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        if (s[i] == needle[0] and std.mem.eql(u8, s[i..][0..32], needle)) hits += 1;
    }
    return hits;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    Sha256.hash("public", &out, .{});
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

// ── global state and the probed calls ───────────────────────────────────────

var heap_buf: [256 * 1024]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;
var io: std.Io = undefined;

var ecdsa_key: [32]u8 = undefined;
var bip_sk: bip340.SecretKey = undefined;
var aux: [32]u8 = undefined;
var payer_id: [33]u8 = undefined;
var node_id: [33]u8 = undefined;

var out11: []u8 = &.{};
var out_req: []u8 = &.{};
var out_inv: []u8 = &.{};
var sig_merkle: [64]u8 = undefined;

const payment_hash = [_]u8{0x01} ** 32;
const payment_secret = [_]u8{0x11} ** 32;
const fields11 = [_]bolt11.TaggedFieldOut{
    .{ .payment_hash = payment_hash },
    .{ .payment_secret = payment_secret },
    .{ .description = "lninvoice dead-stack probe" },
    .{ .expiry_seconds = 900 },
};
const params11 = bolt11.EncodeParams{
    .network = .testnet,
    .amount_msat = 1_234_000,
    .timestamp = 1_700_000_000,
    .fields = &fields11,
};

// BOLT#12 TLV types (bolt12.zig's own constants are private).
const T_METADATA = 0;
const T_CURRENCY = 6;
const T_AMOUNT = 8;
const T_PAYER_ID = 88;
const T_NODE_ID = 176;
const metadata = [_]u8{0xab} ** 8;
var req_records: [4]lnwire.RawRecord = undefined;
var inv_records: [3]lnwire.RawRecord = undefined;
var req_stream: std.ArrayList(u8) = .empty;
var inv_stream: std.ArrayList(u8) = .empty;

noinline fn callEncode11() void {
    fba = .init(&heap_buf);
    out11 = bolt11.encode(fba.allocator(), params11, .{ .private_key = &ecdsa_key }) catch unreachable;
}
noinline fn callSignMerkle() void {
    fba = .init(&heap_buf);
    sig_merkle = bolt12.signMerkle(fba.allocator(), req_stream.items, bolt12.invoice_request_sig_tag, &bip_sk, aux, io) catch unreachable;
}
noinline fn callEncodeRequest() void {
    fba = .init(&heap_buf);
    out_req = bolt12.encodeSignedInvoiceRequest(fba.allocator(), &req_records, &bip_sk, aux, io) catch unreachable;
}
noinline fn callEncodeInvoice() void {
    fba = .init(&heap_buf);
    out_inv = bolt12.encodeSignedInvoice(fba.allocator(), &inv_records, &bip_sk, aux, io) catch unreachable;
}

const Kind = enum { bolt11, req, inv };
const steps = [_]struct { name: []const u8, call: *const fn () void, kind: Kind }{
    .{ .name = "bolt11.encode (.private_key)", .call = callEncode11, .kind = .bolt11 },
    .{ .name = "bolt12.signMerkle", .call = callSignMerkle, .kind = .req },
    .{ .name = "encodeSignedInvoiceRequest", .call = callEncodeRequest, .kind = .req },
    .{ .name = "encodeSignedInvoice", .call = callEncodeInvoice, .kind = .inv },
};

// ── the needles, recomputed from the calls' output ──────────────────────────

/// BOLT#11: `h = SHA256(hrp || data-without-signature)`, then
/// `k = s^-1 (h + r d)` from the published `r`, `s`.
fn needles11(n: *Needles, invoice: []const u8) !void {
    const a = std.testing.allocator;
    var dec = try bech32raw.decode(a, invoice);
    defer dec.deinit(a);
    const sig_start = dec.data.len - 104;
    const data_bytes = try bitpack.quintetsToBytesPadded(a, dec.data[0..sig_start]);
    defer a.free(data_bytes);
    const sig = try bitpack.quintetsToBytesPadded(a, dec.data[sig_start..]);
    defer a.free(sig);
    var h: Sha256 = .init(.{});
    h.update(dec.hrp);
    h.update(data_bytes);
    var hash: [32]u8 = undefined;
    h.final(&hash);

    var wide: [48]u8 = @splat(0);
    wide[16..48].* = hash;
    const e = Scalar.fromBytes48(wide, .big);
    const d = try Scalar.fromBytes(ecdsa_key, .big);
    const r = try Scalar.fromBytes(sig[0..32].*, .big);
    const s = try Scalar.fromBytes(sig[32..64].*, .big);
    const k = s.invert().mul(e.add(r.mul(d)));
    // A wrong needle would make the zero meaningless: `k·G` must give `r`.
    const kr = (try G.basePoint.mulPublic(k.toBytes(.big), .big)).affineCoordinates().x.toBytes(.big);
    try std.testing.expectEqualSlices(u8, sig[0..32], &kr);
    n.addScalar("ECDSA d", d);
    n.addScalar("ECDSA k", k);
    n.addScalar("ECDSA n-k", k.neg());
    n.addScalar("ECDSA k^-1", k.invert());
}

/// BOLT#12: BIP340 steps 1-5 over `taggedHash(tag, merkleRoot(stream))`.
fn needles12(n: *Needles, stream: []const u8, comptime tag: []const u8, sig_r: *const [32]u8) !void {
    const root = try bolt12.merkleRoot(std.testing.allocator, stream);
    const digest = bip340.taggedHash(tag, &root);
    var kp: bip340.KeyPair = undefined;
    try bip340.KeyPair.fromSecretKey(&kp, &bip_sk);
    defer kp.deinit();
    const d = try Scalar.fromBytes(kp.secret, .big);
    const aux_hash = bip340.taggedHash(bip340.hash.aux_tag, &aux);
    var t: [32]u8 = undefined;
    for (&t, kp.secret, aux_hash) |*ti, di, ai| ti.* = di ^ ai;
    var nh = bip340.hash.taggedHasher(bip340.hash.nonce_tag);
    nh.update(&t);
    nh.update(&kp.public.x);
    nh.update(&digest);
    const rand = nh.finalResult();
    var wide: [48]u8 = @splat(0);
    wide[16..48].* = rand;
    const k = Scalar.fromBytes48(wide, .big);
    // A wrong needle would make the zero meaningless: `k'·G` must give `R.x`.
    const kr = (try G.basePoint.mulPublic(k.toBytes(.big), .big)).affineCoordinates().x.toBytes(.big);
    try std.testing.expectEqualSlices(u8, sig_r, &kr);
    n.addScalar("BIP340 d (effective)", d);
    n.add("BIP340 n-d, big-endian", d.neg().toBytes(.big));
    n.add("BIP340 t = d xor H(aux)", t);
    n.add("BIP340 rand", rand);
    n.addScalar("BIP340 k'", k);
    n.addScalar("BIP340 n-k'", k.neg());
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

test "STACKPROBE lninvoice: no key or nonce residue on the dead stack after the signing entry points" {
    try skipUnlessOptimized();
    var th = std.Io.Threaded.init(std.testing.allocator, .{});
    defer th.deinit();
    io = th.io();

    Sha256.hash("lninvoice-probe/ecdsa key", &ecdsa_key, .{});
    Sha256.hash("lninvoice-probe/aux", &aux, .{});
    Sha256.hash("lninvoice-probe/control", &control, .{});
    var bip_bytes: [32]u8 = undefined;
    Sha256.hash("lninvoice-probe/bip340 key", &bip_bytes, .{});
    bip_sk = try bip340.SecretKey.fromBytes(bip_bytes);
    {
        var kp: bip340.KeyPair = undefined;
        try bip340.KeyPair.fromSecretKey(&kp, &bip_sk);
        defer kp.deinit();
        payer_id[0] = 0x02; // BIP-340 public keys are even-y
        payer_id[1..33].* = kp.public.x;
        node_id = payer_id;
    }
    req_records = .{
        .{ .type = T_METADATA, .value = &metadata },
        .{ .type = T_CURRENCY, .value = "EUR" },
        .{ .type = T_AMOUNT, .value = &.{0x64} },
        .{ .type = T_PAYER_ID, .value = &payer_id },
    };
    inv_records = .{
        .{ .type = T_CURRENCY, .value = "EUR" },
        .{ .type = T_AMOUNT, .value = &.{0x64} },
        .{ .type = T_NODE_ID, .value = &node_id },
    };
    const a = std.testing.allocator;
    defer req_stream.deinit(a);
    defer inv_stream.deinit(a);
    try lnwire.tlv.appendStream(&req_stream, a, &req_records);
    try lnwire.tlv.appendStream(&inv_stream, a, &inv_records);

    // Controls first, then each call once into its own snapshot; the needles
    // are computed only after every snapshot is taken.
    snap = &ctl_snaps[0];
    measure(callInnocent);
    snap = &ctl_snaps[1];
    measure(callLeaky);
    for (steps, 0..) |st, i| {
        snap = &snaps[i];
        measure(st.call);
    }
    // Copy the BOLT#11 output out of the fixed buffer before anything reuses it.
    const inv11 = try a.dupe(u8, out11);
    defer a.free(inv11);

    var n11: Needles = .{};
    try needles11(&n11, inv11);
    var n_req: Needles = .{};
    try needles12(&n_req, req_stream.items, bolt12.invoice_request_sig_tag, sig_merkle[0..32]);
    var n_inv: Needles = .{};
    // BIP340 with a given `aux` is deterministic: the same signature the
    // measured call embedded, for the needle self-check.
    const inv_sig = try bolt12.signMerkle(a, inv_stream.items, bolt12.invoice_sig_tag, &bip_sk, aux, io);
    try needles12(&n_inv, inv_stream.items, bolt12.invoice_sig_tag, inv_sig[0..32]);

    const neg = countIn(&ctl_snaps[0], &control) + countIn(&ctl_snaps[0], &n11.items[0].bytes) + countIn(&ctl_snaps[0], &n_req.items[0].bytes);
    const pos = countIn(&ctl_snaps[1], &control);
    var bad = neg != 0 or pos < 1;
    if (verbose or bad) std.debug.print("\n=== STACKPROBE lninvoice ({t}, window {d} KiB) NEG={d} POS(control)={d} ===\n", .{ builtin.mode, WINDOW / 1024, neg, pos });
    for (steps, 0..) |st, i| {
        const nd = switch (st.kind) {
            .bolt11 => n11.slice(),
            .req => n_req.slice(),
            .inv => n_inv.slice(),
        };
        var total: usize = 0;
        for (nd) |*x| total += countIn(&snaps[i], &x.bytes);
        if (verbose or total != 0) {
            std.debug.print("  {s:<32} dirty={d} B, residue {d}\n", .{ st.name, dirtyDepth(&snaps[i]), total });
            for (nd) |*x| {
                const c = countIn(&snaps[i], &x.bytes);
                if (c != 0) std.debug.print("    RESIDUE {s:<34} {d}\n", .{ x.name, c });
            }
        }
        bad = bad or total != 0;
    }
    if (bad) return error.TestUnexpectedResult;
}
