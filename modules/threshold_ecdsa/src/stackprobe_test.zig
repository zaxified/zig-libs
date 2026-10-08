// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the signing path (`presign.Party` rounds,
//! `finish`, `signShare`), kept in the module per `CONVENTIONS.md` §9.
//!
//! Method (as `bip340`'s and `k256`'s `stackprobe_test.zig`): paint a large
//! stack window, make the call at that depth, then claim an equally large
//! UNINITIALISED buffer at the same depth and look for secrets in it.
//! ReleaseFast/ReleaseSmall only — Debug and ReleaseSafe fill `undefined` with
//! 0xaa, so the scan cannot see a dead frame there.
//!
//! The needles differ from bip340's fixed list: a party draws dozens of
//! secrets per round (nonces, Paillier randomness, proof masks), too many to
//! re-derive by hand. So every byte the party's `std.Random` hands out is
//! recorded, and every 16-byte window of that stream is a needle, beside the
//! long-lived secrets read from the party after the call (key share, Paillier
//! secret key, the round's `Secrets`) in their big-endian, little-endian and
//! in-memory images. A 16-byte window of random data on the dead stack is a
//! verbatim copy of a secret; windows with fewer than 10 distinct bytes
//! (zero padding of wide integers) are not needles.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const paillier = @import("paillier");
const root = @import("root.zig");
const presign = @import("presign.zig");
const signing = @import("signing.zig");
const Scalar = root.Scalar;

const WINDOW = 2 * 1024 * 1024;

/// true: print every call's copies and dirty depth (to size a burn). A
/// passing test must print nothing: the lane counts stderr as a FAIL.
const verbose = false;
/// Set around the positive control, whose one copy is expected.
var quiet = false;

// ── recording RNG ────────────────────────────────────────────────────────

const Draw = struct { at: usize, len: usize, ret: usize };

const Recorder = struct {
    csprng: std.Random.DefaultCsprng,
    log: std.ArrayList(u8) = .empty,
    draws: std.ArrayList(Draw) = .empty,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.csprng.fill(buf);
        self.draws.append(std.heap.page_allocator, .{ .at = self.log.items.len, .len = buf.len, .ret = @returnAddress() }) catch @panic("probe OOM"); // global-alloc-ok: the probe's recorder and needle index must not allocate from the allocator of the call it measures (testing.allocator), and live outside any test block
        self.log.appendSlice(std.heap.page_allocator, buf) catch @panic("probe OOM"); // global-alloc-ok: the probe's recorder and needle index must not allocate from the allocator of the call it measures (testing.allocator), and live outside any test block
    }

    fn random(self: *Recorder) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

var recorder: Recorder = undefined;

// ── stack window ─────────────────────────────────────────────────────────

var snap: [WINDOW]u8 = undefined;

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

/// Copies the uninitialised window at the depth the previous call used into
/// `snap`, with volatile reads so the buffer cannot be folded away.
noinline fn snapshot() void {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    for (0..WINDOW) |i| snap[i] = p[i];
    std.mem.doNotOptimizeAway(&buf);
}

fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

// ── needles ──────────────────────────────────────────────────────────────

const Loc = struct { src: u16, off: u32 };

const Needles = struct {
    arena: std.heap.ArenaAllocator,
    names: std.ArrayList([]const u8) = .empty,
    map: std.AutoHashMapUnmanaged(u128, Loc) = .empty,

    fn init() Needles {
        return .{ .arena = .init(std.heap.page_allocator) }; // global-alloc-ok: the probe's recorder and needle index must not allocate from the allocator of the call it measures (testing.allocator), and live outside any test block
    }

    fn deinit(self: *Needles) void {
        self.arena.deinit();
    }

    fn add(self: *Needles, name: []const u8, bytes: []const u8) void {
        const a = self.arena.allocator();
        const src: u16 = @intCast(self.names.items.len);
        self.names.append(a, name) catch @panic("probe OOM");
        if (bytes.len < 16) return;
        for (0..bytes.len - 15) |off| {
            const w = bytes[off..][0..16];
            if (!highEntropy(w)) continue;
            const gop = self.map.getOrPut(a, std.mem.readInt(u128, w, .little)) catch @panic("probe OOM");
            if (!gop.found_existing) gop.value_ptr.* = .{ .src = src, .off = @intCast(off) };
        }
    }

    fn addScalar(self: *Needles, name: []const u8, s: Scalar) void {
        const be = s.toBytes(.big);
        var le: [32]u8 = undefined;
        for (be, 0..) |b, i| le[31 - i] = b;
        const a = self.arena.allocator();
        self.add(std.fmt.allocPrint(a, "{s} BE", .{name}) catch @panic("probe OOM"), &be);
        self.add(std.fmt.allocPrint(a, "{s} LE", .{name}) catch @panic("probe OOM"), a.dupe(u8, &le) catch @panic("probe OOM"));
        self.add(std.fmt.allocPrint(a, "{s} mem", .{name}) catch @panic("probe OOM"), a.dupe(u8, std.mem.asBytes(&s)) catch @panic("probe OOM"));
    }

    fn addRaw(self: *Needles, name: []const u8, bytes: []const u8) void {
        self.add(name, self.arena.allocator().dupe(u8, bytes) catch @panic("probe OOM"));
    }

    fn addKeyShare(self: *Needles, share: *const root.KeyShare) void {
        self.addScalar("x_i (key share)", share.secret_share);
        self.addRaw("message seed", &share.message_seed);
        // Ed25519's expanded key: the clamped scalar and the nonce prefix.
        // (The second half of a 64-byte `SecretKey` is the PUBLIC key.)
        var az: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(&share.message_seed, &az, .{});
        self.addRaw("message key az (unclamped)", &az);
        az[0] &= 248;
        az[31] &= 127;
        az[31] |= 64;
        self.addRaw("message key a (clamped)", az[0..32]);
        const sk = &share.paillier_secret;
        self.addRaw("paillier lambda", std.mem.asBytes(&sk.lambda));
        self.addRaw("paillier mu", std.mem.asBytes(&sk.mu));
        if (sk.crt) |*crt| self.addRaw("paillier crt (p,q-derived)", std.mem.asBytes(crt));
    }

    fn addParty(self: *Needles, p: *const presign.Party) void {
        self.addKeyShare(&p.share);
        const s = &p.secrets;
        self.addScalar("k_i", s.k);
        self.addScalar("gamma_i", s.gamma);
        self.addScalar("w_i", s.w);
        self.addScalar("ell_i", s.ell);
        self.addScalar("delta_i", s.delta);
        self.addScalar("sigma_i", s.sigma);
        self.addRaw("gamma blind", &s.gamma_blind);
        self.addRaw("r_k (Paillier randomness of c_k)", std.mem.asBytes(&s.r_k));
    }

    /// Drops every needle window that also occurs in `public` — bytes the
    /// call publishes. Fiat-Shamir responses like Πfac's `z1 = e·p + α`
    /// carry the top bytes of a mask wider than `e·p` verbatim, by design.
    fn dropPublic(self: *Needles, public: []const u8) void {
        if (public.len < 16) return;
        for (0..public.len - 15) |off| _ = self.map.remove(std.mem.readInt(u128, public[off..][0..16], .little));
    }

    fn addRng(self: *Needles) void {
        self.add("RNG stream", recorder.log.items);
    }
};

fn highEntropy(w: *const [16]u8) bool {
    var seen: [256]bool = @splat(false);
    var distinct: usize = 0;
    for (w) |b| {
        if (!seen[b]) distinct += 1;
        seen[b] = true;
    }
    return distinct >= 10;
}

const Report = struct {
    /// Stack offsets where a needle window starts, counted once per run of
    /// consecutive matches (one copy of a 32-byte secret = 17 windows).
    copies: usize = 0,
    depth: usize = 0,
};

fn analyse(label: []const u8, needles: *const Needles) Report {
    var rep: Report = .{ .depth = dirtyDepth() };
    var prev: ?Loc = null;
    var i: usize = 0;
    while (i + 16 <= WINDOW) : (i += 1) {
        const key = std.mem.readInt(u128, snap[i..][0..16], .little);
        const hit = needles.map.get(key);
        defer prev = hit;
        const h = hit orelse continue;
        if (prev) |p| if (p.src == h.src and p.off + 1 == h.off) continue;
        rep.copies += 1;
        const name = needles.names.items[h.src];
        if (quiet) continue;
        std.debug.print("  RESIDUE [{s}] depth {d}: {s} @{d}", .{ label, WINDOW - i, name, h.off });
        if (std.mem.startsWith(u8, name, "RNG stream")) {
            const at = h.off + rng_base;
            for (recorder.draws.items, 0..) |d, n| {
                if (at >= d.at and at < d.at + d.len) {
                    std.debug.print(" (draw #{d}, {d} B at +{d}, ret anchor{s}0x{x})", .{ n, d.len, at - d.at, if (d.ret >= @intFromPtr(&anchor)) "+" else "-", if (d.ret >= @intFromPtr(&anchor)) d.ret - @intFromPtr(&anchor) else @intFromPtr(&anchor) - d.ret });
                    break;
                }
            }
        }
        std.debug.print("\n", .{});
    }
    if (verbose or (rep.copies != 0 and !quiet)) std.debug.print("  [{s}] copies={d} dirty={d} B\n", .{ label, rep.copies, rep.depth });
    return rep;
}

/// Where in `recorder.log` the current "RNG stream" needle source starts.
var rng_base: usize = 0;

/// Symbol the `ret` offsets above are relative to (for `addr2line`).
noinline fn anchor() void {
    std.mem.doNotOptimizeAway(@as(u8, 0));
}

// ── controls ─────────────────────────────────────────────────────────────

noinline fn callInnocent(h: [32]u8) void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&h, &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

noinline fn callLeaky(secret: *const [32]u8) void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = secret.*;
    std.mem.doNotOptimizeAway(&local);
}

// ── the signing session ──────────────────────────────────────────────────

const t = 2;
var parties: [t]presign.Party = undefined;
var outs: [t]?presign.Outbox = @splat(null);
var inboxes: [t]std.ArrayList([]const u8) = @splat(.empty);
var presigs: [t]presign.Presignature = undefined;
var share_bytes: [t][]u8 = undefined;
const probe_msg = "threshold_ecdsa dead-stack probe";

var probe_shares: []root.KeyShare = undefined;
var probe_indices: [t]u32 = undefined;

noinline fn callInit(i: usize) void {
    presign.Party.init(std.testing.allocator, &probe_shares[i], &probe_indices, @splat(0x33), &parties[i]) catch @panic("init");
}

noinline fn callAdvance(i: usize) void {
    outs[i] = parties[i].advance(inboxes[i].items, recorder.random()) catch @panic("advance");
}

noinline fn callFinish(i: usize) void {
    parties[i].finish(inboxes[i].items, &presigs[i]) catch @panic("finish");
}

var presig_bytes: []u8 = undefined;
var pool: presign.PresignaturePool = undefined;
var pool_id: [32]u8 = undefined;

noinline fn callPresigToBytes() void {
    presig_bytes = presigs[0].toBytesAlloc(std.testing.allocator) catch @panic("toBytesAlloc");
    presigs[0].deinit();
}
noinline fn callPresigFromBytes() void {
    presign.Presignature.fromBytesAlloc(std.testing.allocator, presig_bytes, &presigs[0]) catch @panic("fromBytesAlloc");
}
noinline fn callPoolPut() void {
    pool_id = pool.put(std.testing.allocator, &presigs[1]) catch @panic("pool.put"); // deinits it
}
noinline fn callPoolTake() void {
    if (!(pool.take(std.testing.allocator, pool_id, &presigs[1]) catch @panic("pool.take"))) @panic("pool.take: missing");
}

noinline fn callSignShare(i: usize) void {
    share_bytes[i] = presigs[i].signShare(.{ .bytes = probe_msg }) catch @panic("signShare");
}

test "STACKPROBE: no secret on the dead stack after presign rounds, finish and signShare" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x737461636b70726f); // "stackpro"
    const kg = try signing.testKeygen(allocator, prng.random(), 2, 3);
    defer kg.deinit(allocator);

    recorder = .{ .csprng = .init(@splat(0x5a)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }

    probe_shares = kg.key_shares;
    probe_indices = .{ kg.key_shares[0].index, kg.key_shares[1].index };
    const sid: presign.SessionId = @splat(0x33);
    defer for (&inboxes) |*b| b.deinit(allocator);

    var total: usize = 0;
    var label_buf: [64]u8 = undefined;
    for (0..t) |i| {
        var n = Needles.init();
        defer n.deinit();
        n.addKeyShare(&kg.key_shares[i]);
        paint();
        callInit(i);
        snapshot();
        total += analyse(try std.fmt.bufPrint(&label_buf, "init party {d}", .{i}), &n).copies;
    }
    defer for (&parties) |*p| p.deinit();

    // Controls.
    {
        var n = Needles.init();
        defer n.deinit();
        n.addParty(&parties[0]);
        paint();
        callInnocent(sid);
        snapshot();
        try std.testing.expectEqual(@as(usize, 0), analyse("NEG control", &n).copies);
        const x = parties[0].share.secret_share.toBytes(.big);
        paint();
        callLeaky(&x);
        snapshot();
        quiet = true;
        defer quiet = false;
        try std.testing.expect(analyse("POS control", &n).copies >= 1);
    }

    for (1..7) |round| {
        for (0..t) |i| {
            paint();
            callAdvance(i);
            snapshot();
            var n = Needles.init();
            defer n.deinit();
            n.addParty(&parties[i]);
            n.addRng();
            total += analyse(try std.fmt.bufPrint(&label_buf, "round {d} party {d}", .{ round, i }), &n).copies;
        }
        for (&inboxes) |*b| b.clearRetainingCapacity();
        for (0..t) |from| {
            for (outs[from].?.messages) |m| {
                for (0..t) |to| {
                    if (to == from) continue;
                    if (m.to == null or m.to.? == parties[to].share.index) try inboxes[to].append(allocator, m.bytes);
                }
            }
        }
        // The inboxes point into these outboxes: kept until the end.
        if (round == 6) break;
        held_rounds[round - 1] = outs;
    }
    for (0..t) |i| {
        var n = Needles.init();
        defer n.deinit();
        n.addParty(&parties[i]);
        n.addRng();
        paint();
        callFinish(i);
        snapshot();
        n.addScalar("presig k_i", presigs[i].k);
        n.addScalar("presig sigma_i", presigs[i].sigma);
        total += analyse(try std.fmt.bufPrint(&label_buf, "finish party {d}", .{i}), &n).copies;
    }
    // The codec (party 0) and the pool (party 1): encoding consumes the
    // presignature, so its secrets are taken as needles before the call and
    // decoding/taking restores it for `signShare` below.
    var mem = presign.MemoryPresignatureStore.init(allocator);
    defer mem.deinit();
    pool = .{ .store = mem.store() };
    for (0..t) |i| {
        var n = Needles.init();
        defer n.deinit();
        n.addScalar("presig k_i", presigs[i].k);
        n.addScalar("presig sigma_i", presigs[i].sigma);
        n.addRaw("presig message seed", &presigs[i].message_seed);
        n.addRng();
        const steps = if (i == 0)
            [2]struct { []const u8, *const fn () void }{ .{ "Presignature.toBytesAlloc", callPresigToBytes }, .{ "Presignature.fromBytesAlloc", callPresigFromBytes } }
        else
            [2]struct { []const u8, *const fn () void }{ .{ "PresignaturePool.put", callPoolPut }, .{ "PresignaturePool.take", callPoolTake } };
        for (steps) |step| {
            paint();
            step[1]();
            snapshot();
            total += analyse(step[0], &n).copies;
        }
    }
    allocator.free(presig_bytes);

    for (0..t) |i| {
        var n = Needles.init();
        defer n.deinit();
        n.addKeyShare(&parties[i].share);
        n.addScalar("presig k_i", presigs[i].k);
        n.addScalar("presig sigma_i", presigs[i].sigma);
        n.addRng();
        paint();
        callSignShare(i);
        snapshot();
        total += analyse(try std.fmt.bufPrint(&label_buf, "signShare party {d}", .{i}), &n).copies;
    }
    for (held_rounds) |r| for (r) |o| if (o) |b| b.deinit(allocator);
    for (outs) |o| if (o) |b| b.deinit(allocator);
    for (&presigs, share_bytes) |*p, b| {
        p.public.allocator.free(b);
        p.deinit();
    }
    if (verbose or total != 0) std.debug.print("TOTAL residue copies: {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}

var held_rounds: [5][t]?presign.Outbox = @splat(@splat(null));

// ── the building blocks and the key material ─────────────────────────────

const mta = root.mta;
const zkproofs = root.zkproofs;
const ecproofs = root.ecproofs;
const aux_proofs = root.aux_proofs;
const fac_proof = root.fac_proof;
const vectors = @import("tsslib_vectors.zig");

var arena_state: std.heap.ArenaAllocator = undefined;
fn arena() std.mem.Allocator {
    return arena_state.allocator();
}

/// Inputs and outputs of the probed calls, in static memory the scan never
/// reads, so what the scan finds is what the call itself left behind.
const Io = struct {
    share_a: *const root.KeyShare = undefined,
    share_b: *const root.KeyShare = undefined,
    pk_a: paillier.PublicKey = undefined,
    aux_b: root.AuxParams = undefined,
    a: Scalar = undefined,
    b: Scalar = undefined,
    coeffs: [2]Scalar = undefined,
    alice: mta.AliceInitChecked = undefined,
    bob: mta.BobResponseChecked = undefined,
    alice_plain: mta.AliceInit = undefined,
    bob_plain: mta.BobResponse = undefined,
    alpha: Scalar = undefined,
    opened: mta.DecryptionWithRandomness = undefined,
    mta_proof: zkproofs.MtaProof = undefined,
    split: root.SplitResult = undefined,
    reconstructed: Scalar = undefined,
    key_shares: []root.KeyShare = undefined,
    ks_bytes: []u8 = undefined,
    ks_back: root.KeyShare = undefined,
    p: [128]u8 = undefined,
    q: [128]u8 = undefined,
    tp: [128]u8 = undefined,
    tq: [128]u8 = undefined,
    blum: root.PaillierBlumKey = undefined,
    aux_gen: root.AuxParamsWithTrapdoor = undefined,
    aux_plain: root.AuxParams = undefined,
    lambda_in: root.AuxFe = undefined,
    lambda: root.AuxFe = undefined,
    seed: [32]u8 = undefined,
    local: root.aux_info.LocalAux = undefined,
    seed_move: [32]u8 = undefined,
    g_point: root.Element = undefined,
    x_point: root.Element = undefined,
    b_point: root.Element = undefined,
    r_point: root.Element = undefined,
    s_point: root.Element = undefined,
    t_point: root.Element = undefined,
    dealer_paillier: [2]paillier.KeyPair = undefined,
    dealer_aux: [2]root.AuxParams = undefined,
    dealer_seeds: [2][32]u8 = undefined,
    fac: fac_proof.FacProof = undefined,
    sink: usize = 0,
};
var io: Io = .{};

fn ctx() []const u8 {
    return "stackprobe ctx";
}

noinline fn callMtaAliceInit() void {
    io.alice_plain = mta.mtaAliceInit(&io.a, io.pk_a, recorder.random()) catch @panic("mtaAliceInit");
}
noinline fn callMtaAliceInitChecked() void {
    mta.mtaAliceInitChecked(&io.a, io.pk_a, recorder.random(), &io.alice) catch @panic("mtaAliceInitChecked");
}
noinline fn callMtaBobResponse() void {
    mta.mtaBobResponse(&io.b, io.alice.c_a, io.pk_a, recorder.random(), &io.bob_plain) catch @panic("mtaBobResponse");
}
noinline fn callMtaBobResponseChecked() void {
    mta.mtaBobResponseChecked(&io.b, io.alice.c_a, io.pk_a, recorder.random(), &io.bob) catch @panic("mtaBobResponseChecked");
}
noinline fn callMtaAliceFinalize() void {
    mta.mtaAliceFinalize(io.bob.c_b, &io.share_a.paillier_secret, &io.alpha) catch @panic("mtaAliceFinalize");
}
noinline fn callMtaAliceFinalizeVerified() void {
    mta.mtaAliceFinalizeVerified(io.bob.c_b, &io.share_a.paillier_secret, &io.alpha) catch @panic("mtaAliceFinalizeVerified");
}
noinline fn callMtaAliceFinalizeChecked() void {
    mta.mtaAliceFinalizeChecked(io.alice.c_a, io.bob.c_b, io.mta_proof, &io.share_a.paillier_secret, io.pk_a, io.aux_b, ctx(), &io.alpha) catch @panic("mtaAliceFinalizeChecked");
}
noinline fn callDecryptWithRandomness() void {
    mta.decryptWithRandomness(&io.share_a.paillier_secret, io.pk_a, io.alice.c_a, &io.opened) catch @panic("decryptWithRandomness");
}
noinline fn callProveAliceRange() void {
    const proof = zkproofs.proveAliceRange(arena(), &io.a, &io.alice.r_a, io.pk_a, io.aux_b, ctx(), recorder.random()) catch @panic("proveAliceRange");
    io.sink +%= proof.s1.len;
}
noinline fn callProvePdl() void {
    const proof = zkproofs.provePdl(arena(), &io.a, &io.alice.r_a, io.pk_a, io.aux_b, io.g_point, io.x_point, ctx(), recorder.random()) catch @panic("provePdl");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callProveBobMta() void {
    io.mta_proof = zkproofs.proveBobMta(arena(), &io.b, &io.bob.beta_prime, &io.bob.r_b, io.alice.c_a, io.bob.c_b, io.pk_a, io.aux_b, ctx(), recorder.random()) catch @panic("proveBobMta");
}
noinline fn callProveBobMtaWc() void {
    const proof = zkproofs.proveBobMtaWc(arena(), &io.b, &io.bob.beta_prime, &io.bob.r_b, io.alice.c_a, io.bob.c_b, io.pk_a, io.aux_b, io.b_point, ctx(), recorder.random()) catch @panic("proveBobMtaWc");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callProveSchnorr() void {
    const proof = ecproofs.proveSchnorr(&io.a, io.x_point, ctx(), recorder.random());
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callPedersenCommit() void {
    io.t_point = ecproofs.pedersenCommit(&io.a, &io.b) catch @panic("pedersenCommit");
}
noinline fn callProvePedersen() void {
    const proof = ecproofs.provePedersen(&io.a, &io.b, io.t_point, ctx(), recorder.random());
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callProveSt() void {
    const proof = ecproofs.proveSt(&io.a, &io.b, io.r_point, io.s_point, io.t_point, ctx(), recorder.random()) catch @panic("proveSt");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callProveDleq() void {
    const proof = ecproofs.proveDleq(&io.a, io.r_point, io.s_point, io.x_point, ctx(), recorder.random()) catch @panic("proveDleq");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callSplit() void {
    io.split = root.splitSecretKey(arena(), &io.a, 3, 5, &io.coeffs) catch @panic("splitSecretKey");
}
noinline fn callReconstruct() void {
    root.reconstructSecret(io.split.shares[0..3], &io.reconstructed) catch @panic("reconstructSecret");
}
noinline fn callKeyShareToBytes() void {
    io.ks_bytes = io.share_a.toBytesAlloc(arena()) catch @panic("KeyShare.toBytesAlloc");
}
noinline fn callKeyShareFromBytes() void {
    root.KeyShare.fromBytesAlloc(arena(), io.ks_bytes, &io.ks_back) catch @panic("KeyShare.fromBytesAlloc");
}
noinline fn callPaillierBlumFromPrimes() void {
    root.paillierBlumFromPrimes(&io.p, &io.q, &io.blum) catch @panic("paillierBlumFromPrimes");
}
noinline fn callGeneratePaillierBlum() void {
    root.generatePaillierBlum(recorder.random(), paillier.modulus_bits, &io.blum) catch @panic("generatePaillierBlum");
}
noinline fn callAuxFromSafePrimes() void {
    root.auxParamsWithTrapdoorFromSafePrimes(arena(), &io.tp, &io.tq, recorder.random(), &io.aux_gen) catch @panic("auxParamsWithTrapdoorFromSafePrimes");
}
noinline fn callAuxLogInverse() void {
    root.auxLogInverse(io.aux_gen.params.n_tilde, &io.tp, &io.tq, &io.lambda_in, &io.lambda) catch @panic("auxLogInverse");
}
noinline fn callGenerateAuxParams() void {
    io.aux_plain = root.generateAuxParams(recorder.random(), root.min_aux_generate_bits);
}
noinline fn callGenerateAuxWithTrapdoor() void {
    root.generateAuxParamsWithTrapdoor(arena(), recorder.random(), root.min_aux_generate_bits, &io.aux_gen) catch @panic("generateAuxParamsWithTrapdoor");
}
noinline fn callMessagePublicKey() void {
    const pk = root.messagePublicKey(io.seed) catch @panic("messagePublicKey");
    io.sink +%= pk[0];
}
noinline fn callAnnounce() void {
    const ann = io.local.announce(arena(), ctx(), recorder.random()) catch @panic("announce");
    io.sink +%= @intFromPtr(&ann);
}
noinline fn callProveFactors() void {
    io.fac = io.local.proveFactors(io.aux_b, ctx(), recorder.random()) catch @panic("proveFactors");
}
noinline fn callPimodPaillier() void {
    const proof = aux_proofs.Pimod.provePaillier(arena(), io.blum.modulus(), io.blum.p(), io.blum.q(), ctx(), recorder.random()) catch @panic("provePaillier");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callProveWellFormed() void {
    const proof = aux_proofs.proveWellFormedBound(arena(), io.aux_gen.params, &io.aux_gen.trapdoor, ctx(), recorder.random()) catch @panic("proveWellFormedBound");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callProveWellFormedUnbound() void {
    const proof = aux_proofs.proveWellFormed(arena(), io.aux_gen.params, &io.aux_gen.trapdoor, recorder.random()) catch @panic("proveWellFormed");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callPiprmProve() void {
    const proof = aux_proofs.Piprm.prove(arena(), io.aux_gen.params, &io.aux_gen.trapdoor, recorder.random()) catch @panic("Piprm.prove");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callPiprmProveBound() void {
    const proof = aux_proofs.Piprm.proveBound(arena(), io.aux_gen.params, &io.aux_gen.trapdoor, ctx(), recorder.random()) catch @panic("Piprm.proveBound");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callPimodProve() void {
    const proof = aux_proofs.Pimod.prove(arena(), io.aux_gen.params, &io.aux_gen.trapdoor, recorder.random()) catch @panic("Pimod.prove");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callPimodProveBound() void {
    const proof = aux_proofs.Pimod.proveBound(arena(), io.aux_gen.params, &io.aux_gen.trapdoor, ctx(), recorder.random()) catch @panic("Pimod.proveBound");
    io.sink +%= @intFromPtr(&proof);
}
noinline fn callKeygenTrustedDealer() void {
    io.key_shares = root.keygenTrustedDealer(arena(), 2, 2, &io.a, io.coeffs[0..1], &io.dealer_paillier, &io.dealer_aux, &io.dealer_seeds) catch @panic("keygenTrustedDealer");
}
noinline fn callLocalAuxFromParts() void {
    root.aux_info.LocalAux.fromParts(&io.blum, io.aux_gen.params, &io.aux_gen.trapdoor, &io.seed_move, &io.local);
}

fn addPaillierSecret(n: *Needles, name: []const u8, sk: *const paillier.SecretKey) void {
    _ = name;
    n.addRaw("paillier lambda", std.mem.asBytes(&sk.lambda));
    n.addRaw("paillier mu", std.mem.asBytes(&sk.mu));
    if (sk.crt) |*crt| n.addRaw("paillier crt (p,q-derived)", std.mem.asBytes(crt));
}

fn addAuxTrapdoor(n: *Needles, t_: *const root.AuxTrapdoor) void {
    n.addRaw("aux p~", t_.p);
    n.addRaw("aux q~", t_.q);
    n.addRaw("aux lambda", std.mem.asBytes(&t_.lambda));
}

/// Paint, call, scan; `needles` is filled by `fill` AFTER the call, so it
/// can read the call's outputs. Returns the copies found.
fn probeCall(label: []const u8, comptime call: fn () void, comptime fill: fn (*Needles) void) usize {
    return probeCallPublic(label, call, fill, null);
}

/// `probeCall` for a call whose output is published: `public` returns its
/// encoding, whose windows are not needles (see `Needles.dropPublic`).
fn probeCallPublic(label: []const u8, comptime call: fn () void, comptime fill: fn (*Needles) void, comptime public: ?fn () []const u8) usize {
    const start = recorder.log.items.len;
    paint();
    call();
    snapshot();
    var n = Needles.init();
    defer n.deinit();
    fill(&n);
    n.add("RNG stream (this call)", recorder.log.items[start..]);
    if (public) |f| n.dropPublic(f());
    rng_base = start;
    defer rng_base = 0;
    return analyse(label, &n).copies;
}

test "STACKPROBE: no secret on the dead stack after the MtA, proof, keygen and codec entry points" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    arena_state = .init(std.heap.page_allocator);
    defer arena_state.deinit();

    var prng = std.Random.DefaultPrng.init(0x737461636b707232); // "stackpr2"
    const kg = try signing.testKeygen(allocator, prng.random(), 2, 3);
    defer kg.deinit(allocator);

    recorder = .{ .csprng = .init(@splat(0x6b)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }

    io = .{};
    io.share_a = &kg.key_shares[0];
    io.share_b = &kg.key_shares[1];
    io.pk_a = kg.key_shares[0].public_keys.get(kg.key_shares[0].index).?.paillier_pk;
    io.aux_b = kg.key_shares[0].public_keys.get(kg.key_shares[1].index).?.aux;
    io.a = Scalar.fromBytes48(@splat(0x3c), .big);
    io.b = Scalar.fromBytes48(@splat(0x95), .big);
    io.coeffs = .{ Scalar.fromBytes48(@splat(0x17), .big), Scalar.fromBytes48(@splat(0xd2), .big) };
    io.seed = @splat(0x4e);
    const pv = vectors.tsslib_keygen.parties[0];
    _ = try std.fmt.hexToBytes(&io.p, pv.paillier_p);
    _ = try std.fmt.hexToBytes(&io.q, pv.paillier_q);
    _ = try std.fmt.hexToBytes(&io.tp, pv.aux_p_safe);
    _ = try std.fmt.hexToBytes(&io.tq, pv.aux_q_safe);
    io.sink = 0;
    // Public points the proofs take, computed here, outside the measured calls.
    const G = root.Secp256k1.basePoint;
    io.g_point = try root.Element.fromPoint(G);
    io.x_point = try root.Element.fromPoint(try G.mulPublic(io.a.toBytes(.big), .big));
    io.b_point = try root.Element.fromPoint(try G.mulPublic(io.b.toBytes(.big), .big));
    const r_pt = try G.mulPublic(@splat(0x21), .big);
    io.r_point = try root.Element.fromPoint(r_pt);
    io.s_point = try root.Element.fromPoint(try r_pt.mulPublic(io.a.toBytes(.big), .big));
    for (&io.dealer_paillier, 0..) |*kp, i| {
        var pp: [128]u8 = undefined;
        var pq: [128]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pp, vectors.tsslib_keygen.parties[i].paillier_p);
        _ = try std.fmt.hexToBytes(&pq, vectors.tsslib_keygen.parties[i].paillier_q);
        try paillier.fromPrimes(&pp, &pq, kp);
        io.dealer_aux[i] = kg.key_shares[i].public_keys.get(kg.key_shares[i].index).?.aux;
        io.dealer_seeds[i] = @splat(@intCast(0x60 + i));
    }

    const F = struct {
        fn ab(n: *Needles) void {
            n.addScalar("a", io.a);
            n.addScalar("b", io.b);
        }
        fn mta_(n: *Needles) void {
            ab(n);
            addPaillierSecret(n, "alice", &io.share_a.paillier_secret);
            n.addRaw("r_a", std.mem.asBytes(&io.alice.r_a));
            n.addRaw("r_b", std.mem.asBytes(&io.bob.r_b));
            n.addRaw("beta'", &io.bob.beta_prime);
            n.addScalar("beta", io.bob.beta);
            n.addScalar("beta (plain)", io.bob_plain.beta);
            n.addScalar("alpha", io.alpha);
        }
        fn opened(n: *Needles) void {
            mta_(n);
            n.addRaw("opened m", std.mem.asBytes(&io.opened.m));
            n.addRaw("opened rho", std.mem.asBytes(&io.opened.rho));
        }
        fn split(n: *Needles) void {
            n.addScalar("secret", io.a);
            n.addScalar("coeff 1", io.coeffs[0]);
            n.addScalar("coeff 2", io.coeffs[1]);
            for (io.split.shares) |s| n.addScalar("share", s.scalar);
        }
        fn keyShare(n: *Needles) void {
            n.addScalar("x_i", io.share_a.secret_share);
            n.addRaw("message seed", &io.share_a.message_seed);
            addPaillierSecret(n, "share", &io.share_a.paillier_secret);
        }
        fn blum(n: *Needles) void {
            n.addRaw("paillier p", &io.p);
            n.addRaw("paillier q", &io.q);
            addPaillierSecret(n, "blum", &io.blum.key.secret);
        }
        fn blumGen(n: *Needles) void {
            n.addRaw("generated p", io.blum.p());
            n.addRaw("generated q", io.blum.q());
            addPaillierSecret(n, "generated", &io.blum.key.secret);
        }
        fn auxGen(n: *Needles) void {
            n.addRaw("aux p~ (input)", &io.tp);
            n.addRaw("aux q~ (input)", &io.tq);
            addAuxTrapdoor(n, &io.aux_gen.trapdoor);
            n.addRaw("aux lambda (log inverse)", std.mem.asBytes(&io.lambda));
        }
        fn auxGenOnly(n: *Needles) void {
            addAuxTrapdoor(n, &io.aux_gen.trapdoor);
        }
        fn seed(n: *Needles) void {
            n.addRaw("seed", &io.seed);
            var az: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(&io.seed, &az, .{});
            n.addRaw("az", &az);
        }
        fn dealer(n: *Needles) void {
            n.addScalar("secret", io.a);
            n.addScalar("coeff 1", io.coeffs[0]);
            for (&io.dealer_paillier) |*kp| addPaillierSecret(n, "dealt", &kp.secret);
            for (&io.dealer_seeds) |*sd| n.addRaw("dealt seed", sd);
            for (io.key_shares) |*ks| n.addScalar("dealt x_i", ks.secret_share);
        }
        fn local(n: *Needles) void {
            n.addRaw("paillier p", io.local.paillier.p());
            n.addRaw("paillier q", io.local.paillier.q());
            addPaillierSecret(n, "local", &io.local.paillier.key.secret);
            addAuxTrapdoor(n, &io.local.trapdoor);
            n.addRaw("message seed", &io.local.message_seed);
        }
        fn facBytes() []const u8 {
            return io.fac.toBytesAlloc(arena()) catch @panic("FacProof.toBytesAlloc");
        }
        fn none(n: *Needles) void {
            _ = n;
        }
    };

    var total: usize = 0;
    total += probeCall("mtaAliceInit", callMtaAliceInit, F.ab);
    total += probeCall("mtaAliceInitChecked", callMtaAliceInitChecked, F.mta_);
    total += probeCall("mtaBobResponse", callMtaBobResponse, F.mta_);
    total += probeCall("mtaBobResponseChecked", callMtaBobResponseChecked, F.mta_);
    total += probeCall("mtaAliceFinalize", callMtaAliceFinalize, F.mta_);
    total += probeCall("mtaAliceFinalizeVerified", callMtaAliceFinalizeVerified, F.mta_);
    total += probeCall("decryptWithRandomness", callDecryptWithRandomness, F.opened);
    total += probeCall("proveAliceRange", callProveAliceRange, F.mta_);
    total += probeCall("provePdl", callProvePdl, F.mta_);
    total += probeCall("proveBobMta", callProveBobMta, F.mta_);
    total += probeCall("mtaAliceFinalizeChecked", callMtaAliceFinalizeChecked, F.mta_);
    total += probeCall("proveBobMtaWc", callProveBobMtaWc, F.mta_);
    total += probeCall("proveSchnorr", callProveSchnorr, F.ab);
    total += probeCall("pedersenCommit", callPedersenCommit, F.ab);
    total += probeCall("provePedersen", callProvePedersen, F.ab);
    total += probeCall("proveSt", callProveSt, F.ab);
    total += probeCall("proveDleq", callProveDleq, F.ab);
    total += probeCall("splitSecretKey", callSplit, F.split);
    total += probeCall("keygenTrustedDealer", callKeygenTrustedDealer, F.dealer);
    total += probeCall("reconstructSecret", callReconstruct, F.split);
    total += probeCall("KeyShare.toBytesAlloc", callKeyShareToBytes, F.keyShare);
    total += probeCall("KeyShare.fromBytesAlloc", callKeyShareFromBytes, F.keyShare);
    total += probeCall("paillierBlumFromPrimes", callPaillierBlumFromPrimes, F.blum);
    total += probeCall("Pimod.provePaillier", callPimodPaillier, F.blum);
    total += probeCall("auxParamsWithTrapdoorFromSafePrimes", callAuxFromSafePrimes, F.auxGen);
    io.lambda_in = io.aux_gen.trapdoor.lambda;
    total += probeCall("auxLogInverse", callAuxLogInverse, F.auxGen);
    total += probeCall("proveWellFormedBound", callProveWellFormed, F.auxGen);
    total += probeCall("proveWellFormed", callProveWellFormedUnbound, F.auxGen);
    total += probeCall("Piprm.prove", callPiprmProve, F.auxGen);
    total += probeCall("Piprm.proveBound", callPiprmProveBound, F.auxGen);
    total += probeCall("Pimod.prove", callPimodProve, F.auxGen);
    total += probeCall("Pimod.proveBound", callPimodProveBound, F.auxGen);
    total += probeCall("messagePublicKey", callMessagePublicKey, F.seed);
    total += probeCall("generateAuxParams (512)", callGenerateAuxParams, F.none);
    total += probeCall("generateAuxParamsWithTrapdoor (512)", callGenerateAuxWithTrapdoor, F.auxGenOnly);

    // Before LocalAux takes `io.blum` over: a real 2048-bit Blum prime search.
    {
        const tss = io.blum;
        total += probeCall("generatePaillierBlum (2048)", callGeneratePaillierBlum, F.blumGen);
        io.blum.wipe();
        io.blum = tss;
    }
    // LocalAux from the tss-lib material (no minutes-long prime search).
    io.seed_move = io.seed;
    total += probeCall("LocalAux.fromParts", callLocalAuxFromParts, F.local);
    total += probeCall("LocalAux.announce", callAnnounce, F.local);
    total += probeCallPublic("LocalAux.proveFactors", callProveFactors, F.local, F.facBytes);

    if (verbose or total != 0) std.debug.print("TOTAL residue copies (building blocks): {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}

// ── the §4.3 opening (abort path) and the in-process driver ──────────────

var abort_outs: [t]?presign.Outbox = @splat(null);
var abort_inboxes: [t]std.ArrayList([]const u8) = @splat(.empty);
var verdicts: [t]presign.Abort = undefined;

noinline fn callOpenAbort(i: usize) void {
    abort_outs[i] = parties[i].openAbort(recorder.random()) catch @panic("openAbort");
}
noinline fn callEchoOpenings(i: usize) void {
    abort_outs[i] = parties[i].echoOpenings(abort_inboxes[i].items) catch @panic("echoOpenings");
}
noinline fn callIdentify(i: usize) void {
    verdicts[i] = parties[i].identify(abort_inboxes[i].items) catch @panic("identify");
}

var sws_shares: [t]root.KeyShare = undefined;
var sws_sig: signing.Signature = undefined;
noinline fn callSignWithShares() void {
    sws_sig = signing.signWithShares(std.testing.allocator, &sws_shares, probe_msg, recorder.random()) catch @panic("signWithShares");
}

/// Routes every party's outbox of the step just run into the others'
/// inboxes (broadcasts only — the opening rounds have no p2p messages).
fn routeBroadcasts(allocator: std.mem.Allocator, boxes: *[t]?presign.Outbox, held: *std.ArrayList(presign.Outbox)) !void {
    for (&abort_inboxes) |*b| b.clearRetainingCapacity();
    for (boxes, 0..) |*box, from| {
        const o = box.* orelse continue;
        for (o.messages) |m| for (0..t) |to| if (to != from) try abort_inboxes[to].append(allocator, m.bytes);
        try held.append(allocator, o);
        box.* = null;
    }
}

test "STACKPROBE: no secret on the dead stack after the abort opening rounds and signWithShares" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0x737461636b707233); // "stackpr3"
    const kg = try signing.testKeygen(allocator, prng.random(), 2, 3);
    defer kg.deinit(allocator);
    recorder = .{ .csprng = .init(@splat(0x71)) };
    defer {
        recorder.log.deinit(std.heap.page_allocator);
        recorder.draws.deinit(std.heap.page_allocator);
    }

    probe_shares = kg.key_shares;
    probe_indices = .{ kg.key_shares[0].index, kg.key_shares[1].index };
    inboxes = @splat(.empty);
    outs = @splat(null);
    for (0..t) |i| callInit(i);
    defer for (&parties) |*p| p.deinit();
    defer for (&inboxes) |*b| b.deinit(allocator);
    defer for (&abort_inboxes) |*b| b.deinit(allocator);
    var held: std.ArrayList(presign.Outbox) = .empty;
    defer {
        for (held.items) |o| o.deinit(allocator);
        held.deinit(allocator);
    }

    // Phases 1-6 unprobed, with party 1's σ shifted before round 3: every
    // signer's `finish` sees Σ S_j ≠ X and asks for the type-7 opening.
    var opening = false;
    for (1..7) |round| {
        if (round == 3) parties[1].secrets.sigma = parties[1].secrets.sigma.add(Scalar.one);
        for (0..t) |i| {
            outs[i] = parties[i].advance(inboxes[i].items, recorder.random()) catch |e| switch (e) {
                error.ProtocolAbort => null,
                else => return e,
            };
            if (outs[i] == null) {
                try std.testing.expectEqual(.opening, parties[i].state);
                opening = true;
            }
        }
        if (opening) break;
        for (&inboxes) |*b| b.clearRetainingCapacity();
        for (0..t) |from| {
            for (outs[from].?.messages) |m| for (0..t) |to| {
                if (to == from) continue;
                if (m.to == null or m.to.? == parties[to].share.index) try inboxes[to].append(allocator, m.bytes);
            };
        }
        for (&outs) |*o| {
            try held.append(allocator, o.*.?);
            o.* = null;
        }
    }
    if (!opening) for (0..t) |i| {
        var scratch: presign.Presignature = undefined;
        try std.testing.expectError(error.ProtocolAbort, parties[i].finish(inboxes[i].items, &scratch));
    };
    for (&outs) |*o| if (o.*) |b| {
        try held.append(allocator, b);
        o.* = null;
    };

    var total: usize = 0;
    const steps = [_]struct { []const u8, *const fn (usize) void }{
        .{ "openAbort", callOpenAbort },
        .{ "echoOpenings", callEchoOpenings },
        .{ "identify", callIdentify },
    };
    var label_buf: [64]u8 = undefined;
    for (steps) |step| {
        for (0..t) |i| {
            var n = Needles.init();
            defer n.deinit();
            n.addParty(&parties[i]); // before: identify wipes the secrets
            n.addRng();
            paint();
            step[1](i);
            snapshot();
            total += analyse(try std.fmt.bufPrint(&label_buf, "{s} party {d}", .{ step[0], i }), &n).copies;
        }
        try routeBroadcasts(allocator, &abort_outs, &held);
    }
    for (verdicts) |v| try std.testing.expectEqual(@as(?u32, parties[1].share.index), v.culprit);

    // The driver: every party's CSPRNG is seeded from `random`, so the RNG
    // needles cover the seeds only; the parties' own secrets are found by
    // their images (key shares, Paillier keys) and by the session's nonces
    // not being reproducible here — the per-call probes above cover those.
    sws_shares = .{ kg.key_shares[0], kg.key_shares[1] };
    {
        var n = Needles.init();
        defer n.deinit();
        for (&sws_shares) |*sh| n.addKeyShare(sh);
        const start = recorder.log.items.len;
        paint();
        callSignWithShares();
        snapshot();
        // The first 32 bytes drawn are the session id, which is public.
        n.add("RNG stream (seeds)", recorder.log.items[start + @sizeOf(presign.SessionId) ..]);
        rng_base = start + @sizeOf(presign.SessionId);
        defer rng_base = 0;
        total += analyse("signWithShares", &n).copies;
    }

    if (verbose or total != 0) std.debug.print("TOTAL residue copies (opening, driver): {d}\n", .{total});
    try std.testing.expectEqual(@as(usize, 0), total);
}
