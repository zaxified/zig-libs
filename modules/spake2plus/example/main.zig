// SPDX-License-Identifier: MIT

//! What a Matter/Thread-style commissioner (Prover) and device (Verifier)
//! do with `spake2plus`: registration once, then TWO independent
//! commissioning sessions with fresh ephemeral scalars, both roles driven
//! through every round, plus the failure shapes a real deployment hits —
//! a wrong password (a device re-commissioned with the wrong passphrase)
//! and a tampered confirmation MAC on each side.
//!
//! **Real message order, genuinely blind on both sides — no workaround.**
//! `proverStart` -> `verifierStart` -> `verifierConfirm` (the Verifier
//! transmits `confirmV` FIRST, per RFC 9383 Appendix A.5 — it has no
//! `confirmP` yet) -> `proverFinish` (validates `confirmV`, only then
//! computes+transmits `confirmP`, and returns `K_shared`) ->
//! `verifierFinish` (validates `confirmP`, returns the matching
//! `K_shared`). Every step below uses only the module's top-level public
//! API, in exactly this order — no reconstruction of internal primitives
//! is needed.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! `std.heap.DebugAllocator` IS needed here, unlike this task's other five
//! modules: `computeTranscript` (called by `verifierConfirm`,
//! `proverFinish`, and `verifierFinish`) allocates the transcript buffer
//! `TT` and hands ownership to the caller — `VerifierConfirmResult.tt`/
//! `ProverFinishResult.tt`/`VerifierFinishResult.tt` are ALLOCATOR-OWNED
//! per their own doc comments, and the failure paths below are exactly
//! the "allocates and returns early" shape the module's own
//! `errdefer allocator.free(tt)` is supposed to close; this file
//! exercises that under a real leak detector rather than trusting the
//! doc comment.
//!
//! `modules/spake2plus/src/kat_test.zig` already drives RFC 9383 Appendix
//! C's official P-256/SHA-256 test vector byte-exact (every published
//! intermediate: `L`, `shareP`/`shareV`, `Z`/`V`, `TT`, the full key
//! schedule, both confirmation MACs, `K_shared`) through this module —
//! this file does NOT restate that table. Every scalar/label below is
//! FRESH.
//!
//! External oracle: NONE was run. SPAKE2+ (RFC 9383) has no widely
//! deployed, license-clear pure-Python or OpenSSL implementation of the
//! P256-SHA256-HKDF-SHA256-HMAC-SHA256 ciphersuite specifically that could
//! be verified MIT/BSD and run without native compilation in this
//! sandbox (BoringSSL ships a C SPAKE2+ implementation this module's own
//! `bssl_w0w1_vectors.zig` already cross-references at the module level —
//! not re-run here). RFC 9383 Appendix C's official vector remains the
//! real external judge for byte-exact correctness, already exercised by
//! `kat_test.zig`; this file instead exercises the protocol-sequencing,
//! ownership, and state-carrying properties a vector test cannot.

const std = @import("std");
const spake = @import("spake2plus");

/// Expand a label into `n` pseudo-random bytes via SHA-256 counter-mode
/// expansion. `spake2plus` has no internal RNG (by design — every
/// scalar/nonce is caller-supplied); a real deployment draws these from a
/// CSPRNG instead of a label hash.
fn expand(comptime n: usize, label: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var filled: usize = 0;
    var counter: u8 = 0;
    while (filled < out.len) {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(label);
        h.update(&[_]u8{counter});
        var digest: [32]u8 = undefined;
        h.final(&digest);
        const take = @min(digest.len, out.len - filled);
        @memcpy(out[filled .. filled + take], digest[0..take]);
        filled += take;
        counter += 1;
    }
    return out;
}

/// `computeW0W1` is a canonical 80-byte-PBKDF-output -> two-independent-
/// scalars reducer; reused here (through the public API, `expand` always
/// produces exactly 80 bytes so the length check can never fail) both for
/// its documented purpose (deriving `w0`/`w1` from password material) AND
/// as a convenient source of a FRESH pair of independent canonical P-256
/// scalars wherever this file just needs "two random-looking scalars"
/// (the ephemeral `x`/`y`) — one call, two scalars, no separate scalar-
/// reduction helper needed.
fn w0w1FromLabel(label: []const u8) spake.W0W1 {
    const pbkdf_output = expand(80, label);
    return spake.computeW0W1(&pbkdf_output) catch unreachable; // length is always 80
}

const SessionResult = struct { k_shared_prover: [32]u8, k_shared_verifier: [32]u8 };

/// One full commissioning session, both roles, using ONLY the module's
/// public entry points, in the real RFC 9383 Appendix A.5 message order:
/// shareP/shareV exchange, then the Verifier's confirmV (`verifierConfirm`
/// — the Verifier has not seen any Prover confirmation yet), then the
/// Prover's real confirmP (`proverFinish`, which validates confirmV
/// first), then the Verifier's real confirmation check (`verifierFinish`).
fn runSession(
    gpa: std.mem.Allocator,
    w0: [32]u8,
    w1: [32]u8,
    l: [65]u8,
    context: []const u8,
    id_prover: []const u8,
    id_verifier: []const u8,
    x: [32]u8,
    y: [32]u8,
) !SessionResult {
    // Round 1: shares. Neither side needs anything from the other yet.
    const share_p = try spake.proverStart(x, w0); // Prover -> Verifier
    const share_v = try spake.verifierStart(y, w0); // Verifier -> Prover

    // Round 2a: the Verifier goes first — it transmits confirmV with NO
    // Prover confirmation in existence yet (RFC 9383 Appendix A.5).
    const verifier_confirm = try spake.verifierConfirm(gpa, context, id_prover, id_verifier, w0, l, y, share_p, share_v);
    defer gpa.free(verifier_confirm.tt);

    // Round 2b: the Prover validates confirmV (received above) and only
    // then computes+transmits its own confirmP, receiving K_shared.
    const prover_result = try spake.proverFinish(
        gpa,
        context,
        id_prover,
        id_verifier,
        w0,
        w1,
        x,
        share_p,
        share_v,
        verifier_confirm.confirm_v, // Verifier -> Prover
    );
    defer gpa.free(prover_result.tt);

    // Round 2c: the Verifier validates confirmP (received above) and only
    // then obtains the matching K_shared.
    const verifier_result = try spake.verifierFinish(
        gpa,
        context,
        id_prover,
        id_verifier,
        w0,
        l,
        y,
        share_p,
        share_v,
        prover_result.confirm_p, // Prover -> Verifier
    );
    defer gpa.free(verifier_result.tt);

    std.debug.assert(std.mem.eql(u8, &prover_result.k_shared, &verifier_result.k_shared));

    return .{ .k_shared_prover = prover_result.k_shared, .k_shared_verifier = verifier_result.k_shared };
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── registration (once) ────────────────────────────────────────────
    const registration = w0w1FromLabel("spake2plus example: registration pbkdf output");
    const w0 = registration.w0;
    const w1 = registration.w1;
    const l = try spake.computeL(w1); // the Verifier's stored registration record — NEVER w1 itself

    const context = "zig-libs spake2plus example v1 (Matter/Thread-style commissioning)";
    const id_prover = "commissioner-app";
    const id_verifier = "device-serial-000123";

    std.debug.print("registration complete; verifier stores w0 + L, never w1\n", .{});

    // ── commissioning session 1 ────────────────────────────────────────
    const scalars1 = w0w1FromLabel("spake2plus example: session 1 ephemeral scalars");
    const result1 = try runSession(gpa, w0, w1, l, context, id_prover, id_verifier, scalars1.w0, scalars1.w1);
    std.debug.print("session 1: prover and verifier agree on K_shared\n", .{});

    // ── commissioning session 2: fresh ephemeral randomness throughout ──
    const scalars2 = w0w1FromLabel("spake2plus example: session 2 ephemeral scalars");
    const result2 = try runSession(gpa, w0, w1, l, context, id_prover, id_verifier, scalars2.w0, scalars2.w1);
    // Two independent sessions must not share a K_shared.
    std.debug.assert(!std.mem.eql(u8, &result1.k_shared_prover, &result2.k_shared_prover));
    std.debug.print("session 2: independent K_shared from session 1\n", .{});

    // ── failure path 1: wrong password (named error) ──────────────────
    // The Prover derives w0 from a DIFFERENT registration secret than the
    // one actually on file — the real shape of a mistyped/rotated
    // passphrase. The Verifier has no way to detect this from shareP
    // alone; it only surfaces once the confirmation MACs are compared.
    // `computeTranscript` DOES allocate `TT` before this check runs
    // (`proverFinish`'s own `errdefer allocator.free(tt)`) — this is the
    // "failure path that allocates and returns early" the file doc
    // comment calls out; the DebugAllocator wrapping this whole `main`
    // is what proves that `errdefer` actually fires.
    const wrong_password = w0w1FromLabel("spake2plus example: WRONG password pbkdf output");
    const scalars3 = w0w1FromLabel("spake2plus example: session 3 (wrong password) ephemeral scalars");
    const share_p3 = try spake.proverStart(scalars3.w0, wrong_password.w0); // prover's WRONG w0
    const share_v3 = try spake.verifierStart(scalars3.w1, w0); // verifier's CORRECT w0
    const verifier_confirm3 = try spake.verifierConfirm(gpa, context, id_prover, id_verifier, w0, l, scalars3.w1, share_p3, share_v3);
    defer gpa.free(verifier_confirm3.tt);
    if (spake.proverFinish(
        gpa,
        context,
        id_prover,
        id_verifier,
        wrong_password.w0,
        wrong_password.w1,
        scalars3.w0,
        share_p3,
        share_v3,
        verifier_confirm3.confirm_v,
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ConfirmationMismatch => std.debug.print("wrong password (mismatched w0): ConfirmationMismatch at prover (expected)\n", .{}),
        else => return err,
    }

    // ── failure path 2: tampered confirmP (named error, verifier-side) ─
    const scalars4 = w0w1FromLabel("spake2plus example: session 4 (tampered confirmP) ephemeral scalars");
    const share_p4 = try spake.proverStart(scalars4.w0, w0);
    const share_v4 = try spake.verifierStart(scalars4.w1, w0);
    const verifier_confirm4 = try spake.verifierConfirm(gpa, context, id_prover, id_verifier, w0, l, scalars4.w1, share_p4, share_v4);
    defer gpa.free(verifier_confirm4.tt);
    var prover_result4 = try spake.proverFinish(
        gpa,
        context,
        id_prover,
        id_verifier,
        w0,
        w1,
        scalars4.w0,
        share_p4,
        share_v4,
        verifier_confirm4.confirm_v,
    );
    defer gpa.free(prover_result4.tt);
    prover_result4.confirm_p[0] ^= 0x01; // tamper the MAC in transit
    if (spake.verifierFinish(
        gpa,
        context,
        id_prover,
        id_verifier,
        w0,
        l,
        scalars4.w1,
        share_p4,
        share_v4,
        prover_result4.confirm_p,
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ConfirmationMismatch => std.debug.print("tampered confirmP: ConfirmationMismatch at verifier (expected)\n", .{}),
        else => return err,
    }

    // ── failure path 3: malformed peer share (named error, wire-level) ─
    // The real untrusted-wire shape: `share_v` bytes that do not even
    // decode as a valid P-256 point. Rejected structurally, BEFORE any
    // allocation (`computeTranscript` is never reached) — a different
    // named error from the confirmation-MAC failures above.
    const share_p5 = try spake.proverStart(scalars4.w0, w0);
    const share_v_bad = [_]u8{0xff} ** 65;
    if (spake.proverFinish(
        gpa,
        context,
        id_prover,
        id_verifier,
        w0,
        w1,
        scalars4.w0,
        share_p5,
        share_v_bad,
        [_]u8{0} ** 32,
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidShareV => std.debug.print("malformed share_v bytes: InvalidShareV (expected)\n", .{}),
        else => return err,
    }
}
