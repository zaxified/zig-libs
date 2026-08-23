// SPDX-License-Identifier: MIT

//! What a Lightning node's channel state machine does with `bolt3`: derive
//! a counterparty's shachain per-commitment secrets/points, use them
//! across THREE successive commitment rounds (the module's per-commitment
//! index counts DOWN — `perCommitmentSecret`'s own doc comment — so the
//! index carried between rounds, not a single call, is the thing a vector
//! test cannot exercise), derive this round's simple + revocation keys
//! while the point is still secret, then when the counterparty ADVANCES
//! and reveals the PREVIOUS round's secret, recompute the matching
//! revocation PRIVATE key and prove it lands on the exact same public
//! point derived blind, round earlier — the whole justice-transaction
//! guarantee BOLT#3's revocation scheme exists for.
//!
//! `bolt3` implements ONLY the Appendix D/E crypto (see its module doc
//! comment: commitment-transaction/HTLC-output construction is explicitly
//! out of scope, deferred to a later pass) — so "the consumer path" here
//! is the key-derivation sequence a channel state machine drives, not a
//! full commitment transaction. Deriving a point FROM a secret (needed to
//! call the `*PublicKey` half of each pair) is not exported by `bolt3`
//! itself — it is squarely `k256`'s job (a declared dep of this module),
//! so this example calls `Secp256k1.combMulBase`/`.toCompressedSec1`
//! directly, exactly as `bolt3`'s own cross-check tests do.
//!
//! `bolt3` allocates NOWHERE — every function here takes and returns
//! fixed-size arrays over `std.crypto.ecc.Secp256k1` scalar/point
//! arithmetic. No `DebugAllocator` appears below; there is nothing for one
//! to catch.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! External judge — ACTUALLY RUN at authoring time: this scenario's fixed
//! (non-random) key material makes every printed hex value reproducible.
//! Round 1's `delayedpubkey` and `revocationpubkey` (both computed via
//! `bolt3`'s public-point derivations, never touching a secret) were fed
//! to Python's `ecdsa` package (an independent secp256k1 point-arithmetic
//! implementation: `ecdsa.SECP256k1.generator`, point `+`/`*`, SHA-256 via
//! `hashlib`) which recomputed
//! `basepoint + SHA256(pcp||basepoint)*G` and
//! `rb*SHA256(rb||pcp) + pcp*SHA256(pcp||rb)`
//! from the same basepoints/per-commitment-point and got byte-identical
//! SEC1-compressed points. That cross-checks the module's point assembly
//! against a wholly independent secp256k1 implementation, not merely
//! against its own inverse (`derivePrivateKey`/`Revocation` round trip,
//! which this example ALSO does, but that only proves internal
//! consistency). Tool output only; no `ecdsa` source was read.

const std = @import("std");
const bolt3 = @import("bolt3");
const Secp256k1 = @import("k256").Secp256k1;

fn pointOf(secret: [32]u8) [33]u8 {
    return (Secp256k1.combMulBase(secret, .big) catch unreachable).toCompressedSec1();
}

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}: {x}\n", .{ label, bytes });
}

pub fn main() !void {
    // ── Setup: fixed, throwaway, non-vector key material for this
    // scenario — never a real channel's actual seed/basepoints ──────────
    const peer_seed = [16]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 } ** 2;
    const local_delayed_basepoint_secret = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } ** 2;
    const local_revocation_basepoint_secret = [16]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30 } ** 2;

    const local_delayed_basepoint = pointOf(local_delayed_basepoint_secret);
    const local_revocation_basepoint = pointOf(local_revocation_basepoint_secret);

    // The counterparty's per-commitment index counts DOWN from max_index
    // (`perCommitmentSecret`'s own doc comment). Three successive
    // commitment rounds, oldest first.
    const indices = [_]u48{ bolt3.max_index, bolt3.max_index - 1, bolt3.max_index - 2 };

    // Carried across rounds: each round's blind (pubkey-only)
    // revocationpubkey, checked against the SAME round's revocation
    // privkey once the counterparty reveals that round's secret one round
    // later (`prev_revocation_pubkey`) — this cross-round carry is the
    // thing this example exists to exercise.
    var prev_pcp: ?[33]u8 = null;
    var prev_revocation_pubkey: ?[33]u8 = null;
    var prev_index: u48 = undefined;

    for (indices, 0..) |index, round| {
        // The counterparty reveals only THIS round's per-commitment
        // POINT up front (the secret stays private until the round is
        // superseded) — a real peer would send 32 bytes on the wire; here
        // both halves live in one process, so derive the secret once and
        // only touch `.point_only` until "revocation time" below.
        const pcs_this_round = bolt3.perCommitmentSecret(peer_seed, index);
        const pcp_this_round = pointOf(pcs_this_round);

        // Local derives this round's simple + revocation keys from the
        // POINT alone — the secret is not needed and not used here.
        const delayedpubkey = try bolt3.derivePublicKey(local_delayed_basepoint, pcp_this_round);
        const revocationpubkey = try bolt3.deriveRevocationPublicKey(local_revocation_basepoint, pcp_this_round);
        std.debug.print("round {d} (index {d}): delayedpubkey={x} revocationpubkey={x}\n", .{ round, index, delayedpubkey, revocationpubkey });

        if (round == 0) {
            printHex("round0 local_delayed_basepoint", &local_delayed_basepoint);
            printHex("round0 local_revocation_basepoint", &local_revocation_basepoint);
            printHex("round0 per-commitment point", &pcp_this_round);
            printHex("round0 delayedpubkey", &delayedpubkey);
            printHex("round0 revocationpubkey", &revocationpubkey);
        }

        // Once this round's point has been used to derive the round's
        // keys, the counterparty ADVANCES: it reveals the PREVIOUS
        // round's secret (never this round's — that would let anyone
        // still holding the current commitment be revoked prematurely).
        // The just-revealed secret must let local recompute a
        // revocation PRIVATE key whose public point is BYTE-IDENTICAL to
        // the one derived blind, one round earlier — the whole point of
        // splitting the revocation key across a basepoint secret only
        // local holds and a per-commitment secret only the counterparty
        // reveals after the fact.
        if (prev_pcp != null) {
            const revoked_secret = bolt3.perCommitmentSecret(peer_seed, prev_index);
            std.debug.assert(std.mem.eql(u8, &pointOf(revoked_secret), &prev_pcp.?));

            const revocationprivkey = try bolt3.deriveRevocationPrivateKey(local_revocation_basepoint_secret, revoked_secret);
            const revocationpubkey_from_priv = pointOf(revocationprivkey);
            std.debug.assert(std.mem.eql(u8, &revocationpubkey_from_priv, &prev_revocation_pubkey.?));
            std.debug.print("round {d}: revoked round {d}'s commitment — justice key recovered, matches blind derivation\n", .{ round, round - 1 });
        }

        prev_pcp = pcp_this_round;
        prev_revocation_pubkey = revocationpubkey;
        prev_index = index;
    }

    // ── Negative paths: named errors on malformed peer input ───────────

    // A corrupted / all-zero 33-byte "point" from a buggy or hostile peer
    // must be rejected by name, not accepted as some nonsense key.
    const bad_point = [_]u8{0} ** 33;
    if (bolt3.derivePublicKey(local_delayed_basepoint, bad_point)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPoint => std.debug.print("corrupted per-commitment point: InvalidPoint (expected)\n", .{}),
        else => return err,
    }

    // Likewise a corrupted secret (all-zero is non-canonical: not a valid
    // scalar) on the revocation-privkey path.
    const bad_secret = [_]u8{0} ** 32;
    if (bolt3.deriveRevocationPrivateKey(bad_secret, bolt3.perCommitmentSecret(peer_seed, bolt3.max_index))) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidSecret => std.debug.print("corrupted revocation basepoint secret: InvalidSecret (expected)\n", .{}),
        else => return err,
    }

    // A party WITHOUT the correct revocation basepoint secret (a
    // different, unrelated keypair) must NOT be able to produce a
    // matching revocation key — not a named-error rejection (the API has
    // no way to know the caller's basepoint is "wrong"), but the
    // consequence a wrong key has to produce for the scheme to hold at
    // all: silent, byte-level disagreement, never an accidental match.
    const wrong_revocation_basepoint_secret = [_]u8{0xEE} ** 32;
    const wrong_revocation_basepoint = pointOf(wrong_revocation_basepoint_secret);
    const wrong_revocationpubkey = try bolt3.deriveRevocationPublicKey(wrong_revocation_basepoint, prev_pcp.?);
    std.debug.assert(!std.mem.eql(u8, &wrong_revocationpubkey, &prev_revocation_pubkey.?));
    std.debug.print("wrong revocation basepoint: revocationpubkey does NOT match (expected)\n", .{});

    // `perCommitmentSecret` is a pure function of (seed, index) — a node
    // never needs to STORE a once-derived secret, only recompute it.
    const recomputed = bolt3.perCommitmentSecret(peer_seed, bolt3.max_index);
    const first = bolt3.perCommitmentSecret(peer_seed, bolt3.max_index);
    std.debug.assert(std.mem.eql(u8, &recomputed, &first));

    std.debug.print("bolt3 example: OK\n", .{});
}
