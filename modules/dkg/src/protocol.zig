// SPDX-License-Identifier: MIT

//! protocol — the synchronous GJKR round driver and the self-contained
//! `BrokenDkg` positive control.
//!
//! **Why a focused synchronous round-driver, not `netsim`.** `netsim`
//! (used by `raft`/`df-elect`) models *network* faults — crashes,
//! partitions, reordering, clock skew — over a byte-payload async channel.
//! GJKR's hard property is different in kind: it is *cryptographic content*
//! soundness under a **synchronous broadcast** assumption (the protocol
//! literally requires a synchronous broadcast channel and reveals Feldman
//! commitments only after QUAL is fixed). The adversary we must defeat
//! sends a well-formed message with a *mathematically inconsistent* share,
//! not a late or dropped one. A lockstep in-process driver models the
//! protocol's own synchrony assumption exactly, lets us inject precisely
//! that content-fault, and lets the checker read the QUAL set and every
//! party's output directly — all of which `netsim`'s timing-fuzz model
//! would only obscure. `netsim` remains the right host for a future
//! *asynchronous* DKG variant; it is deliberately not used here.
//!
//! `Dkg.run` is the honest driver; it calls the five gated `core`
//! functions, so its correctness tests SKIP until the core lands.
//! `BrokenDkg.run` is a complete but deliberately-wrong DKG that skips the
//! share-vs-commitment verification (Core 1) and its QUAL logic (Core 3)
//! entirely — it touches NO gated code, so it runs today and gives the
//! harness teeth before the core exists.

const std = @import("std");
const commit = @import("commit.zig");
const core = @import("core.zig");
const types = @import("types.zig");
const checks = @import("checks.zig");
const gate = @import("gate.zig");

const tecdsa = @import("threshold_ecdsa");
pub const Secp256k1 = tecdsa.Secp256k1;
pub const Scalar = tecdsa.Scalar;
pub const Element = tecdsa.Element;
pub const Config = types.Config;
pub const Complaint = types.Complaint;
pub const DkgShareOutput = types.DkgShareOutput;

pub const DriverError = error{
    InvalidConfig,
    ProtocolError,
} || core.Error || std.mem.Allocator.Error;

/// A single scripted Byzantine deviation for the harness: dealer
/// `bad_dealer` (1-based) sends receiver `bad_receiver` (1-based) a share
/// that does NOT match its broadcast Pedersen commitment. If
/// `defend_honestly` is true, the dealer — when complained about — reveals
/// the *correct* opening (so it survives QUAL and the receiver adopts the
/// good share); if false, its defense also fails and it is disqualified.
/// `null` dealer means "no corruption" (the all-honest run).
pub const Corruption = struct {
    bad_dealer: ?u32 = null,
    bad_receiver: ?u32 = null,
    defend_honestly: bool = true,
};

// ── Round 1 dealing (mechanical, ungated) ────────────────────────────────

/// Everything produced by Round 1, allocated in the caller's arena.
/// Dealer index `d` in `0..n` is party id `d+1`; receiver `r` in `0..n`
/// is party id `r+1`. `wire_s[d][r]` is the share id `d+1` actually SENT
/// to id `r+1` (corrupted if scripted); `open_s[d][r]` is the honest
/// opening the dealer reveals on complaint.
const Dealing = struct {
    cfg: Config,
    h: Element,
    C: [][]Element, // Pedersen commitment vectors, [n][t]
    A: [][]Element, // Feldman commitment vectors, [n][t]
    wire_s: [][]Scalar,
    wire_sp: [][]Scalar,
    open_s: [][]Scalar,
    open_sp: [][]Scalar,
};

fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

fn deal(arena: std.mem.Allocator, cfg: Config, corr: Corruption, random: std.Random) DriverError!Dealing {
    const n: usize = cfg.n;
    const t: usize = cfg.t;
    const h = commit.pedersenH();

    const C = try arena.alloc([]Element, n);
    const A = try arena.alloc([]Element, n);
    const wire_s = try arena.alloc([]Scalar, n);
    const wire_sp = try arena.alloc([]Scalar, n);
    const open_s = try arena.alloc([]Scalar, n);
    const open_sp = try arena.alloc([]Scalar, n);

    for (0..n) |d| {
        const a = try arena.alloc(Scalar, t);
        const b = try arena.alloc(Scalar, t);
        for (a) |*c| c.* = randomScalar(random);
        for (b) |*c| c.* = randomScalar(random);

        C[d] = try commit.pedersenCommitVector(arena, a, b, h);
        A[d] = try commit.feldmanCommitVector(arena, a);

        wire_s[d] = try arena.alloc(Scalar, n);
        wire_sp[d] = try arena.alloc(Scalar, n);
        open_s[d] = try arena.alloc(Scalar, n);
        open_sp[d] = try arena.alloc(Scalar, n);
        for (0..n) |r| {
            const rid: u32 = @intCast(r + 1);
            const s = commit.evalPoly(a, commit.scalarFromIndex(rid));
            const sp = commit.evalPoly(b, commit.scalarFromIndex(rid));
            open_s[d][r] = s;
            open_sp[d][r] = sp;

            const is_bad = corr.bad_dealer != null and
                corr.bad_dealer.? == d + 1 and
                corr.bad_receiver != null and corr.bad_receiver.? == rid;
            if (is_bad) {
                // Tamper the share so g^s·h^{s'} != Π C_k^{r^k}.
                wire_s[d][r] = s.add(Scalar.one);
                wire_sp[d][r] = sp;
                if (!corr.defend_honestly) {
                    // Dealer also reveals a non-matching opening on challenge.
                    open_s[d][r] = s.add(Scalar.one);
                }
            } else {
                wire_s[d][r] = s;
                wire_sp[d][r] = sp;
            }
        }
    }

    return .{
        .cfg = cfg,
        .h = h,
        .C = C,
        .A = A,
        .wire_s = wire_s,
        .wire_sp = wire_sp,
        .open_s = open_s,
        .open_sp = open_sp,
    };
}

// ── the honest driver (calls the gated core) ─────────────────────────────

pub const Dkg = struct {
    /// Run the full GJKR secret-key DKG to completion and return each
    /// party's `DkgShareOutput` (allocated with `allocator`, caller frees
    /// the slice). Calls the five gated `core` functions — so this panics
    /// until `gate.fable_core_implemented` is flipped; its correctness
    /// tests are gated to SKIP until then.
    pub fn run(
        allocator: std.mem.Allocator,
        cfg: Config,
        corr: Corruption,
        random: std.Random,
    ) DriverError![]DkgShareOutput {
        if (!cfg.valid()) return error.InvalidConfig;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const n: usize = cfg.n;

        const dealing = try deal(arena, cfg, corr, random);

        // Round 2: every receiver verifies every dealer's share against
        // that dealer's Pedersen commitment; a failure is a complaint.
        var complaints: std.ArrayList(Complaint) = .empty;
        var defense_valid: std.ArrayList(bool) = .empty;
        for (0..n) |r| {
            const rid: u32 = @intCast(r + 1);
            for (0..n) |d| {
                const ok = core.verifyPedersenShare(
                    dealing.C[d],
                    rid,
                    dealing.wire_s[d][r],
                    dealing.wire_sp[d][r],
                    dealing.h,
                );
                if (!ok) {
                    try complaints.append(arena, .{ .complainant = rid, .accused = @intCast(d + 1) });
                    // Dealer's defense: reveal an opening; valid iff it
                    // matches the dealer's own committed C.
                    const defended = core.verifyPedersenShare(
                        dealing.C[d],
                        rid,
                        dealing.open_s[d][r],
                        dealing.open_sp[d][r],
                        dealing.h,
                    );
                    try defense_valid.append(arena, defended);
                }
            }
        }

        // Round 2 close: fix QUAL from complaints + defenses ONLY.
        const qualified = try arena.alloc(bool, n);
        try core.computeQual(qualified, cfg, complaints.items, defense_valid.items);

        // Extraction: QUAL dealers' Feldman commitments are now revealed;
        // every receiver checks its accepted share against them. A
        // defended complaint means the receiver adopts the revealed
        // opening in place of the bad wire share.
        for (0..n) |r| {
            const rid: u32 = @intCast(r + 1);
            for (0..n) |d| {
                if (!qualified[d]) continue;
                const s = acceptedShare(&dealing, d, r, complaints.items, defense_valid.items, rid);
                const ok = core.verifyFeldmanShare(dealing.A[d], rid, s);
                if (!ok) return error.ProtocolError;
            }
        }

        // Public key Q = Σ_{i∈QUAL} A_i0, then each party's x_j.
        const a0 = try arena.alloc(Element, n);
        for (0..n) |d| a0[d] = dealing.A[d][0];
        const Q = try core.deriveGroupPublicKey(qualified, a0);

        const out = try allocator.alloc(DkgShareOutput, n);
        errdefer allocator.free(out);
        const received = try arena.alloc(?Scalar, n);
        for (0..n) |r| {
            const rid: u32 = @intCast(r + 1);
            for (0..n) |d| {
                received[d] = if (qualified[d])
                    acceptedShare(&dealing, d, r, complaints.items, defense_valid.items, rid)
                else
                    null;
            }
            const x_j = try core.combineKeyShare(qualified, received);
            const xg = Secp256k1.basePoint.mul(x_j.toBytes(.big), .big) catch return error.ProtocolError;
            out[r] = .{
                .index = rid,
                .secret_share = x_j,
                .group_public_key = Q,
                .verifying_share = Element.fromPoint(xg) catch return error.ProtocolError,
            };
        }
        return out;
    }
};

/// The share receiver `rid` (index `r`) treats as dealer `d`'s share: the
/// honest opening if that pair was complained-about and defended, else the
/// wire share.
fn acceptedShare(
    dealing: *const Dealing,
    d: usize,
    r: usize,
    complaints: []const Complaint,
    defense_valid: []const bool,
    rid: u32,
) Scalar {
    for (complaints, defense_valid) |c, ok| {
        if (c.complainant == rid and c.accused == d + 1 and ok) return dealing.open_s[d][r];
    }
    return dealing.wire_s[d][r];
}

// ── the positive control (no gated code; runs today) ─────────────────────

/// A deliberately-broken DKG: it performs the same Round-1 dealing but
/// **skips share-vs-commitment verification entirely** — no complaints, no
/// QUAL filtering — and naively sums every received wire share. When a
/// `Corruption` feeds a bad share to some receiver, that receiver's `x_j`
/// is silently wrong, so the group key it emits is unusable. The harness's
/// `checks.reconstructsToQ` (and, ultimately, the end-to-end signature)
/// MUST catch this — that is the whole point of the positive control, and
/// it proves the teeth work with the real core still stubbed.
pub const BrokenDkg = struct {
    pub fn run(
        allocator: std.mem.Allocator,
        cfg: Config,
        corr: Corruption,
        random: std.Random,
    ) DriverError![]DkgShareOutput {
        if (!cfg.valid()) return error.InvalidConfig;
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const n: usize = cfg.n;

        const dealing = try deal(arena, cfg, corr, random);

        // Q = Σ_d A_d0 over ALL dealers (no QUAL filtering — the bug is
        // upstream: it accepted every share unverified).
        var q_point = try dealing.A[0][0].point();
        for (1..n) |d| q_point = q_point.add(try dealing.A[d][0].point());
        const Q = Element.fromPoint(q_point) catch return error.ProtocolError;

        const out = try allocator.alloc(DkgShareOutput, n);
        errdefer allocator.free(out);
        for (0..n) |r| {
            const rid: u32 = @intCast(r + 1);
            var x_j = Scalar.zero;
            for (0..n) |d| x_j = x_j.add(dealing.wire_s[d][r]); // naive: wire, unverified
            const xg = Secp256k1.basePoint.mul(x_j.toBytes(.big), .big) catch return error.ProtocolError;
            out[r] = .{
                .index = rid,
                .secret_share = x_j,
                .group_public_key = Q,
                .verifying_share = Element.fromPoint(xg) catch return error.ProtocolError,
            };
        }
        return out;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "positive control: BrokenDkg with NO corruption reconstructs to Q (teeth quiet when correct)" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xD16_0001);
    const cfg: Config = .{ .t = 2, .n = 3 };

    const outs = try BrokenDkg.run(allocator, cfg, .{}, prng.random());
    defer allocator.free(outs);

    try testing.expect(checks.allSameQ(outs));
    try testing.expect(checks.verifyingShareConsistent(outs[0]));
    // Any t=2 shares reconstruct to Q — an unverified-but-honest run is
    // still a valid sharing.
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..2]));
    try testing.expect(try checks.reconstructsToQ(allocator, &.{ outs[0], outs[2] }));
}

test "positive control: BrokenDkg that accepts a Byzantine bad share yields an unusable key — harness CATCHES it" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xD16_0002);
    const cfg: Config = .{ .t = 2, .n = 3 };

    // Dealer 1 sends receiver 2 a share inconsistent with its commitment;
    // BrokenDkg skips the check and accepts it.
    const corr: Corruption = .{ .bad_dealer = 1, .bad_receiver = 2 };
    const outs = try BrokenDkg.run(allocator, cfg, corr, prng.random());
    defer allocator.free(outs);

    // Party 2's share is corrupted, so any reconstruction subset that
    // includes it fails to reproduce Q — the teeth fire.
    try testing.expect(!(try checks.reconstructsToQ(allocator, outs[1..3]))); // {2,3}
    try testing.expect(!(try checks.reconstructsToQ(allocator, &.{ outs[0], outs[1] }))); // {1,2}
    // Party 2's verifying_share is still x_2·G by construction (consistent
    // with its own wrong x_2), so the ONLY thing that catches the fault is
    // the cross-party reconstruction — exactly the teeth we rely on.
    try testing.expect(checks.verifyingShareConsistent(outs[1]));
    // A subset that AVOIDS the corrupted party still reconstructs to Q
    // (only party 2 was poisoned), confirming the discrimination is real,
    // not a blanket failure.
    try testing.expect(try checks.reconstructsToQ(allocator, &.{ outs[0], outs[2] })); // {1,3}
}

test "honest Dkg round trip (all correctness invariants) — GATED on core" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xD16_1001);
    const cfg: Config = .{ .t = 2, .n = 3 };

    const outs = try Dkg.run(allocator, cfg, .{}, prng.random());
    defer allocator.free(outs);

    try testing.expect(checks.allSameQ(outs));
    for (outs) |o| try testing.expect(checks.verifyingShareConsistent(o));
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..2]));
    try testing.expect(try checks.reconstructsToQ(allocator, &.{ outs[0], outs[2] }));
}

test "honest Dkg detects + disqualifies a Byzantine dealer that cannot defend — GATED on core" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xD16_1002);
    const cfg: Config = .{ .t = 2, .n = 4 };

    // Dealer 3 sends a bad share to receiver 1 AND fails its defense.
    const corr: Corruption = .{ .bad_dealer = 3, .bad_receiver = 1, .defend_honestly = false };
    const outs = try Dkg.run(allocator, cfg, corr, prng.random());
    defer allocator.free(outs);

    // Even with dealer 3 disqualified, the surviving QUAL set yields a
    // consistent, reconstructible key.
    try testing.expect(checks.allSameQ(outs));
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..2]));
}

test "honest Dkg tolerates a defended complaint (transient bad share) — GATED on core" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xD16_1003);
    const cfg: Config = .{ .t = 2, .n = 3 };

    // Dealer 1 sends a bad share to receiver 2 but defends honestly on
    // complaint → stays in QUAL, receiver adopts the revealed good share.
    const corr: Corruption = .{ .bad_dealer = 1, .bad_receiver = 2, .defend_honestly = true };
    const outs = try Dkg.run(allocator, cfg, corr, prng.random());
    defer allocator.free(outs);

    try testing.expect(checks.allSameQ(outs));
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..2]));
}
