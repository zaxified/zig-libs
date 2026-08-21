// SPDX-License-Identifier: MIT

//! What a threshold-custody service does with `frost`: shard one signing key
//! across three operators so that any TWO of them can authorise a payment,
//! and no single machine ever holds the key. The service runs all three FROST
//! roles in turn — dealer, the two participants, and the coordinator that
//! aggregates — because that is the shape of the protocol a caller has to
//! drive; the module supplies the round functions, not the session.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("frost")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! Every secret here (group secret, sharing coefficient, the four nonce
//! seeds) is a fixed literal so the run is reproducible. A deployment draws
//! each of them from a CSPRNG — `frost` never reads one itself, which is what
//! makes the whole protocol replayable against RFC 9591's own vectors.

const std = @import("std");
const frost = @import("frost");

/// The dealer's group secret `s`. Any 32-byte value below the group order.
const group_secret_bytes: [32]u8 = .{
    0x0d, 0x00, 0x4c, 0x0e, 0x99, 0x0b, 0x00, 0x51, 0x0d, 0x51, 0x53, 0x00, 0x99, 0x00, 0x51, 0x0e,
    0x0b, 0x4c, 0x00, 0x53, 0x51, 0x0d, 0x0e, 0x99, 0x00, 0x0b, 0x4c, 0x51, 0x53, 0x0d, 0x00, 0x51,
};

/// The one non-constant coefficient `a_1` of the degree-1 sharing polynomial.
/// `MIN_PARTICIPANTS = 2` means exactly one of these.
const coefficient_bytes: [32]u8 = .{
    0x03, 0x71, 0x22, 0x5f, 0x03, 0x71, 0x22, 0x5f, 0x03, 0x71, 0x22, 0x5f, 0x03, 0x71, 0x22, 0x5f,
    0x03, 0x71, 0x22, 0x5f, 0x03, 0x71, 0x22, 0x5f, 0x03, 0x71, 0x22, 0x5f, 0x03, 0x71, 0x22, 0x5e,
};

/// Four independent nonce seeds — one hiding + one binding per signer. RFC
/// 9591 §5.1: these MUST be fresh and independent per signing session;
/// reusing a pair across two messages leaks the share.
const nonce_seeds: [4][32]u8 = .{
    @splat(0x11),
    @splat(0x22),
    @splat(0x33),
    @splat(0x44),
};

/// The payment authorisation the quorum is signing.
const payload = "transfer 250 to acct-8841";

/// Which of the dealer's three shares turn up to sign. RFC 9591 lets any
/// MIN_PARTICIPANTS-sized subset sign; picking 1 and 3 (skipping 2) is the
/// interesting case, because the Lagrange coefficients are then not 1.
const quorum = [_]usize{ 0, 2 };

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── dealer ───────────────────────────────────────────────────────────
    // One-off setup: split `s` into 3 shares with threshold 2. `Scalar` has
    // to be public for a caller to build the dealer's inputs at all, and it
    // is — `fromBytes` is the DeserializeScalar range check, so a value the
    // operator typed in wrong is rejected here rather than producing a
    // silently-reduced twin.
    const group_secret = frost.Scalar.fromBytes(group_secret_bytes, .big) catch |err| switch (err) {
        error.NonCanonical => {
            std.debug.print("group secret is not a canonical scalar\n", .{});
            return;
        },
    };
    const coefficient = try frost.Scalar.fromBytes(coefficient_bytes, .big);

    const dealt = try frost.trustedDealerKeygen(gpa, group_secret, &.{coefficient}, 3, 2);
    defer gpa.free(dealt.shares);
    defer gpa.free(dealt.vss_commitment);
    defer for (dealt.shares) |*s| s.deinit(); // wipe every share we handled

    const group_public_key = dealt.group_public_key;
    const gpk_bytes = group_public_key.toBytes();
    std.debug.print("dealt {d} shares, threshold 2, group key {s}...\n", .{
        dealt.shares.len,
        std.fmt.bytesToHex(gpk_bytes[0..8].*, .lower),
    });

    // The coordinator needs one `VerifyingShare` per participant to run the
    // identifiable-abort check below. Nothing in the module derives one, so
    // the dealer computes them here while it still legitimately holds the
    // secret shares, and publishes them alongside the group key.
    var verifying_shares: [3]frost.VerifyingShare = undefined;
    for (dealt.shares, &verifying_shares) |share, *out| {
        const point = try frost.Secp256k1.combMulBase(share.signing_share.toBytes(), .big);
        out.* = try frost.Element.fromPoint(point);
    }

    // ── round 1: each signer commits to a fresh nonce pair ────────────────
    // The nonces stay on the signer's machine; only the two commitments go to
    // the coordinator.
    var nonces: [quorum.len]frost.SigningNonces = undefined;
    defer for (&nonces) |*n| n.deinit();
    var pairs: [quorum.len]frost.NonceCommitmentPair = undefined;
    var commitments: [quorum.len]frost.SigningCommitments = undefined;

    for (quorum, 0..) |share_idx, k| {
        const share = dealt.shares[share_idx];
        nonces[k] = frost.generateNonces(share.signing_share, nonce_seeds[2 * k], nonce_seeds[2 * k + 1]);
        pairs[k] = frost.round1Commit(nonces[k]) catch |err| switch (err) {
            // A zero nonce is negligible but not impossible; a signer that
            // hits it retries with fresh randomness rather than shipping a
            // commitment it cannot open.
            error.InvalidNonce => {
                std.debug.print("signer {d}: degenerate nonce, redraw\n", .{share_idx + 1});
                return;
            },
        };
        commitments[k] = .{
            .identifier = share.identifier,
            .hiding = pairs[k].hiding,
            .binding = pairs[k].binding,
        };
    }

    // RFC 9591 §4.3 states ascending-by-identifier as a PRECONDITION on every
    // function taking a commitment list; none of them sorts for you. Getting
    // this wrong yields a different binding factor per signer and a signature
    // that simply does not verify, so a coordinator sorts once, here.
    frost.sortCommitmentsByIdentifier(&commitments);

    // ── round 2: each signer produces its signature share ────────────────
    var sig_shares: [quorum.len]frost.SignatureShare = undefined;
    for (quorum, 0..) |share_idx, k| {
        const share = dealt.shares[share_idx];
        sig_shares[k] = frost.round2Sign(
            gpa,
            share.identifier,
            share.signing_share,
            group_public_key,
            nonces[k],
            payload,
            &commitments,
        ) catch |err| switch (err) {
            error.OutOfMemory => return err,
            // The signer was handed a commitment list it does not appear in,
            // or one whose elements do not parse — a coordinator bug or a
            // tampered broadcast, and a signer must refuse rather than sign
            // something it cannot bind itself to.
            error.InvalidCommitmentList => {
                std.debug.print("signer {d}: refusing, not bound to this session\n", .{share_idx + 1});
                return;
            },
        };
    }

    // ── coordinator: identifiable abort, then aggregate ──────────────────
    // RFC 9591 §5.4: check each share BEFORE aggregating, so a failure names
    // the operator that produced it instead of yielding one useless
    // signature.
    for (quorum, 0..) |share_idx, k| {
        const ok = try frost.verifySignatureShare(
            gpa,
            dealt.shares[share_idx].identifier,
            verifying_shares[share_idx],
            pairs[k],
            sig_shares[k],
            &commitments,
            group_public_key,
            payload,
        );
        if (!ok) {
            std.debug.print("share from signer {d} is bad — abort, blame that signer\n", .{share_idx + 1});
            return;
        }
    }

    const signature = try frost.aggregate(gpa, &commitments, payload, group_public_key, &sig_shares);
    const wire = signature.toBytes();
    std.debug.print("aggregate signature: {d} bytes (33-byte R || 32-byte z, NOT BIP340)\n", .{wire.len});

    // ── verifier: an ordinary relying party ──────────────────────────────
    // Everything past this point knows only the group public key. It cannot
    // tell a 2-of-3 signature from a single-signer one, which is the point.
    const parsed = frost.Signature.fromBytes(wire) catch |err| switch (err) {
        error.InvalidSignature => {
            std.debug.print("signature blob does not parse\n", .{});
            return;
        },
    };
    if (!frost.verify(payload, parsed, group_public_key)) return error.QuorumSignatureRejected;
    std.debug.print("verified under the group key\n", .{});

    // ── the rejection a caller must handle ───────────────────────────────
    // A relying party's real job is refusing. Flip one byte of the payload
    // and the same signature must fail: `verify` returns false rather than
    // erroring, so a caller that writes `try` here has written nothing.
    if (frost.verify("transfer 250 to acct-8842", parsed, group_public_key)) {
        return error.TamperedPayloadAccepted;
    }
    std.debug.print("altered payload rejected\n", .{});

    // Malformed input is the other refusal, and it IS an error: a blob whose
    // R component is not a curve point never reaches the verify equation.
    var junk = wire;
    junk[0] = 0x04; // not a valid SEC1-compressed parity byte
    if (frost.Signature.fromBytes(junk)) |_| {
        return error.MalformedSignatureAccepted;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("malformed signature blob rejected\n", .{}),
    }
}
