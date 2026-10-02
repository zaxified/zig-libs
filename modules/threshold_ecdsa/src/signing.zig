// SPDX-License-Identifier: MIT
//! signing — the in-process driver over `presign.zig`'s per-signer state
//! machine, plus the pieces every signer shares (`lagrangeCoefficient`, the
//! std ECDSA types the output verifies under).
//!
//! `signWithShares(allocator, shares, message, random)` runs one `presign.Party`
//! per share, routes every message between them through its wire encoding,
//! signs, combines, and returns a standard secp256k1 ECDSA signature that
//! verifies under `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` against the
//! group public key. It is the same protocol a deployment runs with one
//! `Party` per process — GG20 (R. Gennaro, S. Goldfeder, IACR ePrint
//! 2020/540) §3.2, Phases 1–7, with every check of the paper — only the
//! transport is a loop. It exists for tests, for simulations, and for the
//! single-operator case where one host legitimately holds every share.
//!
//! Until 2026-10-02 this file was its own, separate implementation of the
//! protocol: one function computing every party's values side by side,
//! without GG20's Phase 5/6 checks (`Σ R̄_j = G`, `Σ S_j = X`) and without
//! culprit naming. One process holding every share made that safe for
//! itself, but nothing of it carried over to separate signers. It now drives
//! the state machine, so there is one implementation, tested both ways.
//!
//! Zig std GAP: none — `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`,
//! `std.crypto.ecc.Secp256k1` and `std.Thread` are all this file needs.

const std = @import("std");
const builtin = @import("builtin");
const paillier = @import("paillier");
const root = @import("root.zig");
const presign = @import("presign.zig");

pub const Scalar = root.Scalar;
pub const Secp256k1 = root.Secp256k1;
pub const Element = root.Element;
const Ns = root.Ns;

/// The standard-library ECDSA scheme every signature here verifies under.
pub const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
/// Re-exported for callers that only import `signing` directly.
pub const Signature = ecdsa.Signature;

/// Converts a PUBLIC participant index to its `Scalar` (u32 << q, always
/// canonical) — same convention as `root.zig`'s private helper.
fn scalarFromIndex(index: u32) Scalar {
    var buf = [_]u8{0} ** Ns;
    std.mem.writeInt(u32, buf[Ns - 4 .. Ns], index, .big);
    return Scalar.fromBytes(buf, .big) catch unreachable;
}

/// Lagrange coefficient `λ_i = Π_{j∈indices, j≠i} x_j / (x_j − x_i)` at 0,
/// over PUBLIC participant indices: `Σ_{i∈S} λ_i·x_i = x`, so each signer's
/// `w_i = λ_i·x_i` is an additive share of the key without the key ever
/// being assembled. `indices` must not contain duplicates.
pub fn lagrangeCoefficient(indices: []const u32, index: u32) Scalar {
    const xi = scalarFromIndex(index);
    var numerator = Scalar.one;
    var denominator = Scalar.one;
    for (indices) |j| {
        if (j == index) continue;
        const xj = scalarFromIndex(j);
        numerator = numerator.mul(xj);
        denominator = denominator.mul(xj.sub(xi));
    }
    return numerator.mul(denominator.invert());
}

pub const SignError = std.mem.Allocator.Error || error{
    /// Fewer than two shares, duplicate indices, shares of different keys,
    /// or a share whose public material does not cover the signing set.
    InvalidParameters,
    /// A check of the protocol failed (`presign.Fault`). With every share in
    /// one process this means corrupt key material.
    SigningAborted,
};

pub const SignOptions = struct {
    /// `null` (the default): every party's round runs on the caller's
    /// thread. `n`: each round's per-party work runs on `min(n, t)` threads,
    /// the caller's included; a thread that cannot be spawned has its
    /// parties run on the caller's thread. Each party draws from its own
    /// ChaCha CSPRNG seeded from `random` up front, so the signature does not
    /// depend on `n`. Worker threads allocate from per-party arenas over
    /// `std.heap.page_allocator` (`allocator` need not be thread-safe and is
    /// touched only from the caller's thread).
    threads: ?usize = null,
};

/// Runs GG20 presigning and signing over `shares` (the signing set — at
/// least `t` shares of one key) in-process and returns a std ECDSA
/// signature over `message` (SHA-256, as `EcdsaSecp256k1Sha256` does),
/// normalised to low-S and verified under the group key before it is
/// returned. `random` must be a CSPRNG for real use.
pub fn signWithShares(
    allocator: std.mem.Allocator,
    shares: []const root.KeyShare,
    message: []const u8,
    random: std.Random,
) SignError!Signature {
    return signWithSharesOptions(allocator, shares, message, random, .{});
}

const max_threads = 64;

const PartySlot = struct {
    party: presign.Party = undefined,
    live: bool = false,
    arena: ?std.heap.ArenaAllocator = null,
    csprng: std.Random.DefaultCsprng = undefined,
    inbox: std.ArrayList([]const u8) = .empty,
    result: presign.Error!presign.Outbox = error.InvalidState,
};

/// `signWithShares` with explicit options — see `SignOptions`.
pub fn signWithSharesOptions(
    allocator: std.mem.Allocator,
    shares: []const root.KeyShare,
    message: []const u8,
    random: std.Random,
    options: SignOptions,
) SignError!Signature {
    const t = shares.len;
    if (t < 2) return error.InvalidParameters;
    const group_pk = shares[0].group_public_key.toBytes();
    for (shares[1..]) |s| {
        if (!std.mem.eql(u8, &s.group_public_key.toBytes(), &group_pk)) return error.InvalidParameters;
    }
    const indices = try allocator.alloc(u32, t);
    defer allocator.free(indices);
    for (shares, indices) |s, *idx| idx.* = s.index;

    var sid: presign.SessionId = undefined;
    random.bytes(&sid);

    const slots = try allocator.alloc(PartySlot, t);
    @memset(slots, .{});
    // Outboxes of the round whose messages sit in the inboxes right now.
    var pending: ?[]presign.Outbox = null;
    defer {
        if (pending) |boxes| freeOutboxes(allocator, slots, boxes);
        for (slots) |*s| {
            if (s.live) s.party.deinit();
            s.inbox.deinit(allocator);
            std.crypto.secureZero(u8, std.mem.asBytes(&s.csprng));
            if (s.arena) |*a| a.deinit();
        }
        allocator.free(slots);
    }
    const threaded = options.threads != null and !builtin.single_threaded;
    for (slots) |*slot| {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        random.bytes(&seed);
        slot.csprng = .init(seed);
        if (threaded) slot.arena = .init(std.heap.page_allocator);
    }
    for (slots, shares) |*slot, share| {
        const party_alloc = if (slot.arena) |*a| a.allocator() else allocator;
        slot.party = presign.Party.init(party_alloc, share, indices, sid) catch |e| return mapError(e);
        slot.live = true;
    }

    // Phases 1-6: one `advance` per party, outputs routed into the
    // recipients' inboxes for the next call.
    for (0..6) |_| {
        runRound(slots, options.threads orelse 1, threaded);
        if (pending) |boxes| freeOutboxes(allocator, slots, boxes);
        pending = null;
        for (slots) |*s| s.inbox.clearRetainingCapacity();

        var failed: ?presign.Error = null;
        for (slots) |s| {
            _ = s.result catch |e| {
                failed = e;
            };
        }
        // Allocated before anything can fail, so a failed allocation still
        // frees every party's outbox (review F9).
        const boxes_or = allocator.alloc(presign.Outbox, t);
        if (failed == null) _ = boxes_or catch |e| {
            failed = e;
        };
        if (failed) |e| {
            for (slots) |*s| if (s.result) |b| b.deinit(s.party.allocator) else |_| {};
            if (boxes_or) |b| allocator.free(b) else |_| {}
            return mapError(e);
        }
        const boxes = boxes_or catch unreachable;
        for (slots, boxes) |s, *b| b.* = s.result catch unreachable;
        pending = boxes;

        for (boxes, shares) |box, sender| {
            for (box.messages) |m| {
                for (slots, shares) |*dst, recipient| {
                    if (recipient.index == sender.index) continue;
                    if (m.to == null or m.to.? == recipient.index) try dst.inbox.append(allocator, m.bytes);
                }
            }
        }
    }

    // End of presigning, then Phase 7.
    const presigs = try allocator.alloc(presign.Presignature, t);
    var made: usize = 0;
    defer {
        for (presigs[0..made]) |*p| p.deinit();
        allocator.free(presigs);
    }
    for (slots) |*s| {
        presigs[made] = s.party.finish(s.inbox.items) catch |e| return mapError(e);
        made += 1;
    }
    const sig_shares = try allocator.alloc([]u8, t);
    var signed: usize = 0;
    defer {
        for (sig_shares[0..signed], presigs[0..signed]) |b, p| p.public.allocator.free(b);
        allocator.free(sig_shares);
    }
    for (presigs) |*p| {
        sig_shares[signed] = p.signShare(.{ .bytes = message }) catch |e| return mapError(e);
        signed += 1;
    }
    var abort: ?presign.Abort = null;
    return presigs[0].public.combine(.{ .bytes = message }, sig_shares, &abort) catch |e| mapError(e);
}

fn mapError(err: presign.Error) SignError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidParameters => error.InvalidParameters,
        error.ProtocolAbort, error.InvalidState, error.PresignatureUsed => error.SigningAborted,
    };
}

fn freeOutboxes(allocator: std.mem.Allocator, slots: []PartySlot, boxes: []presign.Outbox) void {
    for (boxes, slots) |b, *s| b.deinit(s.party.allocator);
    allocator.free(boxes);
}

fn advanceOne(slot: *PartySlot) void {
    slot.result = slot.party.advance(slot.inbox.items, slot.csprng.random());
}

fn worker(slots: []PartySlot, part: usize, stride: usize) void {
    var k = part;
    while (k < slots.len) : (k += stride) advanceOne(&slots[k]);
}

/// One round for every party: on the caller's thread, or on up to
/// `requested` threads (the caller's included) when `threaded`.
fn runRound(slots: []PartySlot, requested: usize, threaded: bool) void {
    const threads = @max(1, @min(requested, @min(slots.len, max_threads)));
    if (!threaded or threads == 1) return worker(slots, 0, 1);
    var handles: [max_threads]?std.Thread = @splat(null);
    for (1..threads) |p| handles[p] = std.Thread.spawn(.{}, worker, .{ slots, p, threads }) catch null;
    worker(slots, 0, threads);
    for (1..threads) |p| {
        if (handles[p]) |h| h.join() else worker(slots, p, threads);
    }
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

/// Fast test-only ring-Pedersen aux params: a genuine (if not safe-prime,
/// hence not production-strength) two-prime-product modulus from an ordinary
/// `paillier.generate` keygen, with `h2 = h1²` (a known `lambda = 2`). The
/// prove/verify EQUATIONS hold for any such modulus; only the SECURITY
/// margin depends on it being a safe-prime product — irrelevant for a
/// correctness test. 2048 bits: the audit-F2 floor wants `Ñ > q⁷`.
fn sampleFeBelow(m: root.AuxModulus, random: std.Random) root.AuxFe {
    const n_bits = m.bits();
    const n_len = (n_bits + 7) / 8;
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const r = root.AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (!r.isZero()) return r;
    }
}

pub fn testAuxParams(random: std.Random) !root.AuxParams {
    const nt_kp = try paillier.generate(random, 2048);
    var nt_buf: [paillier.modulus_bytes]u8 = undefined;
    const nt_len = nt_kp.public.nByteLen();
    try nt_kp.public.nToBytes(nt_buf[0..nt_len]);
    var strip: usize = 0;
    while (strip < nt_len and nt_buf[strip] == 0) : (strip += 1) {}
    const n_tilde = try root.AuxModulus.fromBytes(nt_buf[strip..nt_len], .big);
    const x = sampleFeBelow(n_tilde, random);
    const h1 = n_tilde.sq(x);
    const h2 = n_tilde.sq(h1);
    return .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };
}

pub const TestKeygen = struct {
    key_shares: []root.KeyShare,

    pub fn deinit(self: TestKeygen, allocator: std.mem.Allocator) void {
        allocator.free(self.key_shares[0].public_keys.entries);
        allocator.free(self.key_shares);
    }
};

/// Real 2048-bit Paillier keys + `testAuxParams` tuples, through the REAL
/// `root.keygenTrustedDealer`. Shared with `presign.zig`'s tests.
pub fn testKeygen(allocator: std.mem.Allocator, random: std.Random, t: u32, n: u32) !TestKeygen {
    const paillier_keys = try allocator.alloc(paillier.KeyPair, n);
    defer allocator.free(paillier_keys);
    const aux_params = try allocator.alloc(root.AuxParams, n);
    defer allocator.free(aux_params);
    for (0..n) |i| {
        paillier_keys[i] = try paillier.generate(random, 2048);
        aux_params[i] = try testAuxParams(random);
    }
    const secret = randomScalar(random);
    const coefficients = try allocator.alloc(Scalar, t - 1);
    defer allocator.free(coefficients);
    for (coefficients) |*c| c.* = randomScalar(random);
    const key_shares = try root.keygenTrustedDealer(allocator, t, n, secret, coefficients, paillier_keys, aux_params);
    return .{ .key_shares = key_shares };
}

fn expectVerifies(shares: []const root.KeyShare, message: []const u8, sig: Signature) !void {
    const pk = try ecdsa.PublicKey.fromSec1(&shares[0].group_public_key.toBytes());
    try sig.verify(message, pk);
}

fn isLowS(sig: Signature) bool {
    const s = Scalar.fromBytes(sig.s, .big) catch return false;
    return std.mem.order(u8, &sig.s, &s.neg().toBytes(.big)) != .gt;
}

test "signWithShares: decisive test — keygen(2,3) -> sign over 2 shares -> verifies under std EcdsaSecp256k1Sha256" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig, so
    // the DEFAULT lane builds it at ReleaseSafe and runs this; it skips only
    // under `-Dstrict-debug`.
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x736967_6e696e67); // "signing"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const subset = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1] };
    const message = "GG20 threshold-ECDSA decisive test";
    const sig = try signWithShares(allocator, &subset, message, random);
    try expectVerifies(kg.key_shares, message, sig);
    try testing.expect(isLowS(sig));
}

test "signWithShares: every t-subset of n, and a signing set larger than t, verify under X" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7375627365747300); // "subsets"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const message = "same group key, different signing subsets";
    const pairs = [_][2]usize{ .{ 0, 1 }, .{ 0, 2 }, .{ 2, 1 } };
    for (pairs) |pair| {
        const subset = [_]root.KeyShare{ kg.key_shares[pair[0]], kg.key_shares[pair[1]] };
        try expectVerifies(kg.key_shares, message, try signWithShares(allocator, &subset, message, random));
    }
    try expectVerifies(kg.key_shares, message, try signWithShares(allocator, kg.key_shares, message, random));
}

test "signWithShares: a flipped bit and a different message do not verify" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x74616d706572); // "tamper"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);

    var sig = try signWithShares(allocator, kg.key_shares, "message A", random);
    const pk = try ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());
    try sig.verify("message A", pk);
    try testing.expectError(error.SignatureVerificationFailed, sig.verify("message B", pk));
    sig.s[31] ^= 0x01;
    try testing.expectError(error.SignatureVerificationFailed, sig.verify("message A", pk));
}

test "signWithShares: rejects one share, mixed keys, a duplicate index, a set below t" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x76616c6964617465); // "validate"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 3, 3);
    defer kg.deinit(allocator);

    try testing.expectError(error.InvalidParameters, signWithShares(allocator, kg.key_shares[0..1], "m", random));
    const dup = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[0], kg.key_shares[1] };
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, &dup, "m", random));
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, kg.key_shares[0..2], "m", random));

    const kg2 = try testKeygen(allocator, random, 2, 2);
    defer kg2.deinit(allocator);
    const mixed = [_]root.KeyShare{ kg.key_shares[0], kg2.key_shares[1] };
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, &mixed, "m", random));
}

test "signWithShares: fails closed, not panic/UB, when a KeyShare's own index is missing from public_keys (audit F2 HIGH, 2026-09-10 fix)" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x66325f68696768); // "f2_high"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    var stripped_entries: std.ArrayList(root.PartyPublicKeys) = .empty;
    defer stripped_entries.deinit(allocator);
    for (kg.key_shares[0].public_keys.entries) |e| {
        if (e.index != kg.key_shares[0].index) try stripped_entries.append(allocator, e);
    }
    var victim = kg.key_shares[0];
    victim.public_keys = .{ .entries = stripped_entries.items };
    const subset = [_]root.KeyShare{ victim, kg.key_shares[1] };
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, &subset, "m", random));
}

test "signWithShares: a verifying share that does not match the key is refused before any round" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x62616478); // "badx"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);

    // Party 2's published X_2 replaced by G: Σ λ_j·X_j is no longer X.
    const entries = try allocator.dupe(root.PartyPublicKeys, kg.key_shares[0].public_keys.entries);
    defer allocator.free(entries);
    entries[1].verifying_share = try Element.fromPoint(Secp256k1.basePoint);
    var a = kg.key_shares[0];
    a.public_keys = .{ .entries = entries };
    var b = kg.key_shares[1];
    b.public_keys = .{ .entries = entries };
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, &[_]root.KeyShare{ a, b }, "m", random));
}

test "audit F6: the threaded driver gives the same signature as the sequential one" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var kprng = std.Random.DefaultPrng.init(0xF6_6b6579); // "key"
    const kg = try testKeygen(allocator, kprng.random(), 3, 3);
    defer kg.deinit(allocator);

    const message = "audit F6";
    var sigs: [3]Signature = undefined;
    for (&sigs, [_]?usize{ null, 1, 4 }) |*sig, threads| {
        var prng = std.Random.DefaultPrng.init(0xF6_7369676e); // "sign"
        sig.* = try signWithSharesOptions(allocator, kg.key_shares, message, prng.random(), .{ .threads = threads });
        try expectVerifies(kg.key_shares, message, sig.*);
    }
    for (sigs[1..]) |s| {
        try testing.expectEqualSlices(u8, &sigs[0].r, &s.r);
        try testing.expectEqualSlices(u8, &sigs[0].s, &s.s);
    }
}

test "lagrangeCoefficient: Σ λ_i · x_i over a subset reconstructs the group secret (self-consistency)" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6c6167_72616e6765); // "lagrange"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const indices = [_]u32{ kg.key_shares[0].index, kg.key_shares[2].index };
    var acc = Scalar.zero;
    for (indices) |idx| {
        const share = for (kg.key_shares) |s| {
            if (s.index == idx) break s;
        } else unreachable;
        acc = acc.add(lagrangeCoefficient(&indices, idx).mul(share.secret_share));
    }
    const expected_x = try Secp256k1.basePoint.mul(acc.toBytes(.big), .big);
    const actual_x = try kg.key_shares[0].group_public_key.point();
    try testing.expect(expected_x.equivalent(actual_x));
}
