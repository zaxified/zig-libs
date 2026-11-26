// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `generateNonces`, `round1Commit` and
//! `round2Sign` (audit 2026-10-08), kept in the module per `CONVENTIONS.md`
//! §9. Method (2026-10-08): the direct-region engine of `p256`'s
//! `stackprobe_test.zig` (painted region below the probe, call under a
//! `PAD`-deep shim, snapshot scanned for 32-byte needles) — the earlier "scan a
//! local buffer" form was blind to the top few hundred bytes of the
//! measured call. ReleaseFast/ReleaseSmall only (Debug and ReleaseSafe fill
//! `undefined`); the push lane runs it in ReleaseFast.
//!
//! The needles: the signing share `sk_i` and `n-sk_i`, the hiding and the
//! binding nonce and their negations, in big-endian, little-endian and
//! `Scalar` images. A nonce next to the published signature share yields
//! `lambda_i·sk_i`, i.e. the share.
//!
//! ⛔ A zero is only readable next to the NEGATIVE control (public data only,
//! must find 0) and the POSITIVE control (parks `sk_i` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const frost = @import("root.zig");
const Scalar = frost.Scalar;

const WINDOW = 256 * 1024;
const needle_count = 18;
const Needles = [needle_count][32]u8;
const needle_names = [needle_count][]const u8{
    "sk_i, big-endian",      "sk_i, little-endian",      "sk_i, Scalar in-memory",
    "n-sk_i, big-endian",    "n-sk_i, little-endian",    "n-sk_i, Scalar in-memory",
    "hiding, big-endian",    "hiding, little-endian",    "hiding, Scalar in-memory",
    "n-hiding, big-endian",  "n-hiding, little-endian",  "n-hiding, Scalar in-memory",
    "binding, big-endian",   "binding, little-endian",   "binding, Scalar in-memory",
    "n-binding, big-endian", "n-binding, little-endian", "n-binding, Scalar in-memory",
};

const msg = "frost round2Sign dead-stack probe message";

// ── the measured region (2026-10-08) ────────────────────────────────────────
//
// Direct-region engine, as `p256`'s probe: the region lies `PAD` bytes below
// the probe's own stack position and the measured call runs as `shim(call)`
// under a `PAD`-deep frame. The earlier "scan a local buffer" form
// was blind to the top few hundred bytes (the scanner's own header and
// locals), i.e. to the callers' and wrappers' frames. Calls are no-argument
// `noinline fn`s: inputs come from module-level `var`s and results go into
// module-level `var`s, so the harness's own locals never hold the secret.
const PAD = 2048;

var region_lo: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe, at the depth
/// `paint`/`shim`/`snapshot` start at.
noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe; `pad` is touched after the
/// call too, so it cannot be a tail call.
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

/// Zero the callee-saved registers before a measured call: they still hold the
/// test's own values (needles it just computed) and the call's prologue spills
/// them into its frame, where the scan would credit them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// Paint the region, run `call` under `shim`, snapshot the region into `snap`.
/// `inline`: the region top is computed in the caller's own frame, and as a
/// frame of its own it would run the call deeper than that top.
inline fn measure(call: *const fn () void) void {
    region_lo = stackHere() - PAD - WINDOW;
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    if (call != &callInnocent and call != &callLeaky) residueCheck("a call `measure` ran");
}

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Bytes below the region's top of the shallowest / deepest needle hit seen by
/// `countIn` since the last `resetDepths`.
var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn resetDepths() void {
    hit_min_depth = 0;
    hit_max_depth = 0;
}

/// Occurrences of the 32-byte `needle` in the last snapshot.
fn countIn(needle: *const [32]u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + 32 <= WINDOW) : (i += 1) {
        if (snap[i] == needle[0] and std.mem.eql(u8, snap[i..][0..32], needle)) {
            hits += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
        }
    }
    return hits;
}

var leak_src: [32]u8 = undefined;
var hash_sink: [32]u8 = undefined;

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    std.crypto.hash.sha2.Sha256.hash(&p_hr, &hash_sink, .{});
    std.mem.doNotOptimizeAway(&hash_sink);
}

/// Positive control: parks a secret in a stack local and returns.
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

/// Sum of occurrences of every needle in the last snapshot; `hits` gets the
/// per-needle counts added.
fn countAll(needles: *const Needles, hits: *[needle_count]usize) usize {
    var sum: usize = 0;
    for (needles, hits) |*nd, *h| {
        const c = countIn(nd);
        h.* += c;
        sum += c;
    }
    return sum;
}

fn le(be: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, std.mem.readInt(u256, &be, .big), .little);
    return out;
}

fn memImage(s: Scalar) [32]u8 {
    return std.mem.asBytes(&s).*;
}

fn three(s: Scalar) [3][32]u8 {
    return .{ s.toBytes(.big), le(s.toBytes(.big)), memImage(s) };
}

/// Everything the calls read lives in static memory, which the stack scan
/// never reads: the probe measures what the calls leave, not the harness's
/// own copies.
var p_share: frost.SigningShare = undefined;
var p_id: frost.Identifier = undefined;
var p_gpk: frost.GroupPublicKey = undefined;
var p_nonces: frost.SigningNonces = undefined;
var p_list: [2]frost.SigningCommitments = undefined;
var p_hr: [32]u8 = undefined;
var p_br: [32]u8 = undefined;

var share_sink: frost.SignatureShare = undefined;
var pair_sink: frost.NonceCommitmentPair = undefined;
var nonces_sink: frost.SigningNonces = undefined;

noinline fn callSign() void {
    share_sink = frost.round2Sign(std.testing.allocator, p_id, &p_share, p_gpk, &p_nonces, msg, &p_list) catch unreachable;
    std.mem.doNotOptimizeAway(&share_sink);
}

noinline fn callCommit() void {
    pair_sink = frost.round1Commit(&p_nonces) catch unreachable;
    std.mem.doNotOptimizeAway(&pair_sink);
}

noinline fn callGenerate() void {
    frost.generateNonces(&nonces_sink, &p_share, p_hr, p_br);
    std.mem.doNotOptimizeAway(&nonces_sink);
    nonces_sink.deinit();
}

fn expectNoResidue(label: []const u8, call: *const fn () void) !void {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const coeffs = [_]Scalar{Scalar.fromBytes48(@as([48]u8, @splat(0x31)), .big)};
    const dealt = try frost.trustedDealerKeygen(gpa, Scalar.fromBytes48(@as([48]u8, @splat(0x29)), .big), &coeffs, 3, 2);
    defer gpa.free(dealt.shares);
    defer gpa.free(dealt.vss_commitment);
    p_gpk = dealt.group_public_key;

    var nonces: [2]frost.SigningNonces = undefined;
    for (dealt.shares[0..2], &nonces, &p_list, 0..) |sh, *n, *entry, i| {
        frost.generateNonces(n, &sh.signing_share, @splat(@intCast(0x40 + i)), @splat(@intCast(0x50 + i)));
        const pair = try frost.round1Commit(n);
        entry.* = .{ .identifier = sh.identifier, .hiding = pair.hiding, .binding = pair.binding };
    }
    frost.sortCommitmentsByIdentifier(&p_list);
    p_id = dealt.shares[0].identifier;
    p_share = dealt.shares[0].signing_share;
    p_nonces = nonces[0];
    p_hr = @splat(0x40);
    p_br = @splat(0x50);

    const sk = p_share.scalar();
    const parts = [_][3][32]u8{ three(sk), three(sk.neg()), three(p_nonces.hiding), three(p_nonces.hiding.neg()), three(p_nonces.binding), three(p_nonces.binding.neg()) };
    var needles: Needles = undefined;
    for (parts, 0..) |p, i| needles[3 * i ..][0..3].* = p;

    leak_src = needles[0];

    var scratch: [needle_count]usize = @splat(0);
    measure(callInnocent);
    const neg = countAll(&needles, &scratch);
    measure(callLeaky);
    const pos = countIn(&needles[0]);

    var total: [needle_count]usize = @splat(0);
    var sum: usize = 0;
    resetDepths();
    for (0..5) |_| {
        measure(call);
        sum += countAll(&needles, &total);
    }
    measure(call);
    const depth = dirtyDepth();

    // Printed only when an assertion below fails: the lane treats stderr
    // from a passing test as a FAIL (scripts/lib/test-lib.sh).
    errdefer {
        std.debug.print("\n=== STACKPROBE frost {s} ({t}, window {d} KiB) ===\n", .{ label, builtin.mode, WINDOW / 1024 });
        std.debug.print("  NEG={d} POS(sk_i)={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ neg, pos, depth, hit_min_depth, hit_max_depth });
        for (needle_names, total) |name, h| {
            if (h != 0) std.debug.print("    RESIDUE {s:<28} {d} (5 calls)\n", .{ name, h });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);
    try std.testing.expectEqual(@as(usize, 0), sum);
}

test "STACKPROBE (audit 2026-10-08): no share or nonce residue on the dead stack after round2Sign()" {
    try expectNoResidue("round2Sign", callSign);
}

test "STACKPROBE (audit 2026-10-08): no nonce residue on the dead stack after round1Commit()" {
    try expectNoResidue("round1Commit", callCommit);
}

test "STACKPROBE (audit 2026-10-08): no share or nonce residue on the dead stack after generateNonces()" {
    try expectNoResidue("generateNonces", callGenerate);
}

// ── dkg parts (delta mutation run 2026-11-25) ───────────────────────────────
//
// `dkg.part1` / `part2` / `part3` each run their body one `noinline` frame down
// and burn after it (`dkg.zig`); until this run nothing measured them, so a
// deleted `burnStack()` there was invisible. Needles: the coefficients and the
// nonce (part1), the coefficients and every share the polynomial yields
// (part2), the received shares and the summed signing share (part3), in
// big-endian, little-endian and `Scalar` images.

const dkg = frost.dkg;
const dkg_gpa = std.testing.allocator;

var d_id1: frost.Identifier = undefined;
var d_coeffs: [2]Scalar = undefined;
var d_nonce: Scalar = undefined;
var d_sec1: dkg.Round1SecretPackage = undefined;
var d_pkg1: dkg.Round1Package = undefined;
var d_r1: [2]dkg.Round1Received = undefined;
var d_r2: [2]dkg.Round2Received = undefined;
var d_sec1_in: dkg.Round1SecretPackage = undefined;
var d_sec2_in: dkg.Round2SecretPackage = undefined;
var d_sec2_out: dkg.Round2SecretPackage = undefined;
var d_key_out: dkg.KeyPackage = undefined;

noinline fn callPart1() void {
    d_pkg1 = dkg.part1(dkg_gpa, &d_sec1, d_id1, 3, 2, &d_coeffs, &d_nonce) catch unreachable;
    std.mem.doNotOptimizeAway(&d_pkg1);
    d_pkg1.deinit(dkg_gpa);
    d_sec1.deinit(dkg_gpa);
}

noinline fn callPart2() void {
    const sent = dkg.part2(dkg_gpa, &d_sec2_out, &d_sec1_in, &d_r1, null) catch unreachable;
    std.mem.doNotOptimizeAway(&sent);
    dkg.freeRound2Packages(dkg_gpa, sent);
    d_sec2_out.deinit(dkg_gpa);
}

noinline fn callPart3() void {
    var pub_pkg = dkg.part3(dkg_gpa, &d_key_out, &d_sec2_in, &d_r1, &d_r2, null) catch unreachable;
    std.mem.doNotOptimizeAway(&pub_pkg);
    pub_pkg.deinit(dkg_gpa);
    d_key_out.deinit();
}

fn dScalar(tag: u8, i: u8) Scalar {
    return Scalar.fromBytes48(@as([48]u8, @splat(tag +% i)), .big);
}

/// 3 participants, 2-of-3; participant 1 is the one measured. `which` is 1, 2
/// or 3 (the part). The other participants' round-1 packages and the shares
/// they send to participant 1 are real, produced here.
fn expectNoResidueDkg(label: []const u8, call: *const fn () void, which: u8) !void {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    const gpa = dkg_gpa;
    var secs1: [3]dkg.Round1SecretPackage = undefined;
    var pkgs: [3]dkg.Round1Package = undefined;
    var coefs: [3][2]Scalar = undefined;
    for (0..3) |i| {
        coefs[i] = .{ dScalar(0x21, @intCast(i)), dScalar(0x35, @intCast(i)) };
        const nonce = dScalar(0x49, @intCast(i));
        pkgs[i] = try dkg.part1(gpa, &secs1[i], try frost.Identifier.fromU16(@intCast(i + 1)), 3, 2, &coefs[i], &nonce);
    }
    defer for (0..3) |i| {
        pkgs[i].deinit(gpa);
        secs1[i].deinit(gpa);
    };
    // Round 1 as participant 1 receives it (senders 2 and 3).
    d_r1 = .{
        .{ .sender = try frost.Identifier.fromU16(2), .package = pkgs[1] },
        .{ .sender = try frost.Identifier.fromU16(3), .package = pkgs[2] },
    };
    // Participant 1's part2 (needed by part3 and for the share needles).
    var sec2_1: dkg.Round2SecretPackage = undefined;
    const sent1 = try dkg.part2(gpa, &sec2_1, &secs1[0], &d_r1, null);
    defer {
        dkg.freeRound2Packages(gpa, sent1);
        sec2_1.deinit(gpa);
    }
    // The shares participants 2 and 3 send to participant 1.
    var recv: [2]dkg.Round2Received = undefined;
    for ([_]usize{ 1, 2 }, 0..) |who, k| {
        var other_r1: [2]dkg.Round1Received = undefined;
        var n: usize = 0;
        for (0..3) |i| {
            if (i == who) continue;
            other_r1[n] = .{ .sender = try frost.Identifier.fromU16(@intCast(i + 1)), .package = pkgs[i] };
            n += 1;
        }
        var sec2: dkg.Round2SecretPackage = undefined;
        const sent = try dkg.part2(gpa, &sec2, &secs1[who], &other_r1, null);
        defer {
            dkg.freeRound2Packages(gpa, sent);
            sec2.deinit(gpa);
        }
        for (sent) |sp| {
            if (std.mem.eql(u8, &sp.recipient.bytes, &(try frost.Identifier.fromU16(1)).bytes))
                recv[k] = .{ .sender = try frost.Identifier.fromU16(@intCast(who + 1)), .signing_share = sp.signing_share };
        }
    }
    d_r2 = recv;
    // Static inputs of the measured calls.
    d_id1 = try frost.Identifier.fromU16(1);
    d_coeffs = coefs[0];
    d_nonce = dScalar(0x49, 0);
    d_sec1_in = secs1[0];
    d_sec2_in = sec2_1;
    // The signing share participant 1 ends with.
    var key: dkg.KeyPackage = undefined;
    var pub_pkg = try dkg.part3(gpa, &key, &sec2_1, &d_r1, &d_r2, null);
    defer pub_pkg.deinit(gpa);
    defer key.deinit();

    // part1's intermediate `a_0 * c` (c public): with the published
    // `mu = k + a_0 * c` it gives `k`, and with `k` the coefficient.
    var preimage: [frost.Ns + 2 * frost.Ne]u8 = undefined;
    preimage[0..frost.Ns].* = d_id1.toBytes();
    preimage[frost.Ns..][0..frost.Ne].* = pkgs[0].commitment[0].toBytes();
    preimage[frost.Ns + frost.Ne ..][0..frost.Ne].* = pkgs[0].proof_of_knowledge.r.toBytes();
    const a0c = d_coeffs[0].mul(frost.hdkg(&preimage));
    var secrets: [6]Scalar = undefined;
    var ns: usize = 0;
    switch (which) {
        1 => for ([_]Scalar{ d_coeffs[0], d_coeffs[1], d_nonce, a0c }) |sc| {
            secrets[ns] = sc;
            ns += 1;
        },
        2 => for ([_]Scalar{ d_coeffs[0], d_coeffs[1], sec2_1.secret_share.scalar(), sent1[0].signing_share.scalar(), sent1[1].signing_share.scalar() }) |sc| {
            secrets[ns] = sc;
            ns += 1;
        },
        else => for ([_]Scalar{ recv[0].signing_share.scalar(), recv[1].signing_share.scalar(), sec2_1.secret_share.scalar(), key.signing_share.scalar() }) |sc| {
            secrets[ns] = sc;
            ns += 1;
        },
    }
    var needles: Needles = undefined;
    for (0..needle_count / 3) |i| needles[3 * i ..][0..3].* = three(secrets[@min(i, ns - 1)]);

    leak_src = needles[0];
    var scratch: [needle_count]usize = @splat(0);
    measure(callInnocent);
    const neg = countAll(&needles, &scratch);
    measure(callLeaky);
    const pos = countIn(&needles[0]);

    var total: [needle_count]usize = @splat(0);
    var sum: usize = 0;
    resetDepths();
    for (0..5) |_| {
        measure(call);
        sum += countAll(&needles, &total);
    }
    measure(call);
    const depth = dirtyDepth();

    errdefer {
        std.debug.print("\n=== STACKPROBE frost dkg {s} ({t}, window {d} KiB) ===\n", .{ label, builtin.mode, WINDOW / 1024 });
        std.debug.print("  NEG={d} POS={d} dirty below the call={d} B, hits {d}..{d} B\n", .{ neg, pos, depth, hit_min_depth, hit_max_depth });
        for (total, 0..) |h, i| {
            if (h != 0) std.debug.print("    RESIDUE needle {d} (secret {d}): {d} (5 calls)\n", .{ i, i / 3, h });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1);
    try std.testing.expectEqual(@as(usize, 0), sum);
}

test "STACKPROBE (mutation 2026-11-25): no coefficient or nonce residue on the dead stack after dkg.part1()" {
    try expectNoResidueDkg("part1", callPart1, 1);
}

test "STACKPROBE (mutation 2026-11-25): no coefficient or share residue on the dead stack after dkg.part2()" {
    try expectNoResidueDkg("part2", callPart2, 2);
}

test "STACKPROBE (mutation 2026-11-25): no share residue on the dead stack after dkg.part3()" {
    try expectNoResidueDkg("part3", callPart3, 3);
}

// ── residue rule (`testkit.stackprobe.residueOf`, 2026-11-23) ───────────────
//
// The needles above are a model of the secrets. The shared engine's residue
// rule needs none: in a snapshot with a burn (the longest zero run, at least
// 512 B), a byte deeper than the burn's top that is neither zero nor paint is
// a frame the burn did not reach, whatever it held. It runs over this probe's
// own snapshot after every measured call (`measure`, the two controls excepted), so no call is re-run
// (protocol rounds cannot be). Origin: falcon, 2026-11-23 — a keygen burn cut
// to 4 KiB passed the needle probe and failed this rule. A snapshot without
// such a run (a call that does not burn) is not judged. Failures print here
// and are asserted by the last test in this file.
var residue_failures: usize = 0;
fn residueCheck(label: []const u8) void {
    const r = @import("testkit").stackprobe.residueOf(&snap, 0xC7, 512);
    if (r.residue_bytes == 0) return;
    residue_failures += 1;
    std.debug.print("\n=== STACKPROBE residue rule ({t}): {s}: {d} B below the burn (burn {d} B from {d} B, deepest {d} B) ===\n", .{ builtin.mode, label, r.residue_bytes, r.burn_len, r.burn_top, r.residue_deepest });
}

test "STACKPROBE residue rule: no measured call left a frame below its burn" {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
    try std.testing.expectEqual(@as(usize, 0), residue_failures);
}
