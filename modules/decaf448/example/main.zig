// SPDX-License-Identifier: MIT

//! `decaf448` is a group primitive, not a protocol with its own
//! rounds/roles — the README names its consumers as "threshold signing,
//! VRFs, anonymous credentials". This example drives two of those shapes
//! through the PUBLISHED API only:
//!
//! 1. A two-party Diffie-Hellman key agreement (Alice/Bob, both roles),
//!    run for TWO independent sessions with fresh scalars each time —
//!    exactly the repeat-use shape that would expose leftover state if
//!    `Element`/`scalar` carried any (they don't: every op is a pure
//!    function over fixed-size arrays).
//! 2. A Pedersen commitment (prover/verifier), using `oneWayMap` to derive
//!    a second basis independent of the generator — the textbook use of
//!    decaf448's hash-to-group primitive — with both a correct opening and
//!    a wrong one the verifier must reject.
//!
//! Every scalar is derived from `ed448.scalar.reduceWide` (a published dep
//! of this module — see `build.zig`'s `deps` list) over a SHA-256-expanded
//! label, then narrowed with `decaf448.scalar.fromEd448` — the width
//! bridge `scalar.zig`'s own doc comment describes. This mirrors how a
//! real caller turns "I need a scalar" into a canonical decaf448 scalar
//! without decaf448 itself exposing a scalar-generation function.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: `decaf448` allocates nowhere — `Element`,
//! `scalar.CompressedScalar`, `oneWayMap`, `encode`/`decode` are all plain
//! value types over fixed-size arrays (see `element.zig`'s module doc
//! comment on internal representation), so there is nothing for a leak
//! detector to watch.
//!
//! `modules/decaf448/src/kat_test.zig` already drives the full RFC 9496
//! Appendix B decaf448 vector set (encode of `[0]G..[15]G`, decode
//! round-trip, 21 invalid-encoding rejections, 7 one-way-map vectors)
//! through this module — this file does NOT restate that table. Every
//! scalar/label below is FRESH.
//!
//! External oracle: NONE was run for the fresh scenario below, and that is
//! reported honestly rather than glossed over. RFC 9496 decaf448 has far
//! thinner library support than its ristretto255 sibling: libsodium (and
//! so PyNaCl, which is installed) implements `crypto_core_ristretto255`
//! but ships no decaf448 group at all, OpenSSL has no decaf448 support,
//! and no maintained pip package for it was found. In its place, the
//! fresh DH scenario is cross-checked the one way still available WITHOUT
//! an independent implementation: the module's own algebraic identities,
//! computed twice from independent inputs and required to agree —
//! DH shared-secret symmetry (`[a](b*G) == [b](a*G)` from two
//! independently-derived scalars) and scalar-multiplication distributivity
//! over addition (`[a+b]G == [a]G + [b]G`). This is weaker than a
//! third-party oracle (it cannot catch a bug both sides of an identity
//! share) but is what is actually available here.

const std = @import("std");
const decaf448 = @import("decaf448");
const ed448 = @import("ed448");

const Element = decaf448.Element;
const Scalar = decaf448.scalar.CompressedScalar;

/// Expand a label into `n` bytes via SHA-256 counter-mode expansion — a
/// plain, obvious way to turn "I need N pseudo-random bytes" into them;
/// decaf448 itself defines no such function. A real caller would draw this
/// from a CSPRNG (for a scalar) or a proper hash-to-field expander (for
/// `oneWayMap`'s input) instead of a label hash.
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

/// Label -> canonical decaf448 scalar, via the width-bridge chain the
/// module doc comment above describes.
fn scalarFromLabel(label: []const u8) Scalar {
    return decaf448.scalar.fromEd448(ed448.scalar.reduceWide(expand(114, label)));
}

pub fn main() !void {
    const G = Element.generator;

    // ── two independent DH sessions, both roles each time ────────────────
    var session: u8 = 1;
    var prev_shared: ?Element.EncodedBytes = null;
    while (session <= 2) : (session += 1) {
        var label_buf: [64]u8 = undefined;

        const alice_label = std.fmt.bufPrint(&label_buf, "decaf448 example alice sk session {d}", .{session}) catch unreachable;
        const alice_sk = scalarFromLabel(alice_label);
        var bob_label_buf: [64]u8 = undefined;
        const bob_label = std.fmt.bufPrint(&bob_label_buf, "decaf448 example bob sk session {d}", .{session}) catch unreachable;
        const bob_sk = scalarFromLabel(bob_label);

        const alice_pub = Element.scalarMul(G, alice_sk);
        const bob_pub = Element.scalarMul(G, bob_sk);

        // Over the "wire": encode, then decode on the peer's side — the
        // real shape a network exchange takes, not a direct in-memory pass.
        const alice_pub_wire = alice_pub.encode();
        const bob_pub_wire = bob_pub.encode();
        const alice_pub_recv = try Element.decode(bob_pub_wire); // Bob's key, as Alice receives it
        const bob_pub_recv = try Element.decode(alice_pub_wire); // Alice's key, as Bob receives it

        const alice_shared = Element.scalarMul(alice_pub_recv, alice_sk);
        const bob_shared = Element.scalarMul(bob_pub_recv, bob_sk);
        std.debug.assert(alice_shared.equals(bob_shared));

        const shared_wire = alice_shared.encode();
        std.debug.print("session {d}: DH shared secret agrees: {x}\n", .{ session, shared_wire });

        // A fresh session must not silently reproduce the previous one's
        // shared secret — the state-carried-between-sessions check the
        // task calls for, even though this module keeps none itself.
        if (prev_shared) |prev| std.debug.assert(!std.mem.eql(u8, &prev, &shared_wire));
        prev_shared = shared_wire;

        // Algebraic cross-check (see file doc comment: no external oracle
        // for decaf448 was available) — distributivity of scalar
        // multiplication over addition, computed independently of the DH
        // exchange above: [a+b]G == [a]G + [b]G.
        const sum_sk = decaf448.scalar.add(alice_sk, bob_sk);
        const lhs = Element.scalarMul(G, sum_sk);
        const rhs = Element.add(alice_pub, bob_pub);
        std.debug.assert(lhs.equals(rhs));
    }
    std.debug.print("distributivity identity [a+b]G == [a]G + [b]G held both sessions\n", .{});

    // ── Pedersen commitment: prover commits, verifier opens ──────────────
    // H independent of G, derived via oneWayMap (RFC 9496 §5.3.4) — the
    // textbook way to get a second basis nobody knows the discrete log of
    // relative to G.
    const h_input = expand(112, "decaf448 example pedersen basis H");
    const H = decaf448.element.oneWayMap(h_input);
    std.debug.assert(!H.equals(Element.identity));
    std.debug.assert(!H.equals(G));

    const m = scalarFromLabel("decaf448 example pedersen message m=42");
    const r = scalarFromLabel("decaf448 example pedersen blinding r, run 1");
    const commitment = Element.add(Element.scalarMul(G, m), Element.scalarMul(H, r));

    // Prover -> verifier: only the commitment travels first (binding, not
    // yet hiding-broken); the opening (m, r) travels later.
    const commitment_wire = commitment.encode();
    const commitment_recv = try Element.decode(commitment_wire);

    // Verifier, given the real opening, recomputes and checks equality —
    // never trusts the prover's own claim of what the commitment encodes.
    const reopened = Element.add(Element.scalarMul(G, m), Element.scalarMul(H, r));
    std.debug.assert(commitment_recv.equals(reopened));
    std.debug.print("Pedersen commitment: correct opening accepted\n", .{});

    // A dishonest prover claiming a DIFFERENT message for the SAME
    // commitment must be rejected — the binding property.
    const wrong_m = scalarFromLabel("decaf448 example pedersen message m=43 (wrong)");
    const wrong_reopened = Element.add(Element.scalarMul(G, wrong_m), Element.scalarMul(H, r));
    std.debug.assert(!commitment_recv.equals(wrong_reopened));
    std.debug.print("Pedersen commitment: wrong opening rejected\n", .{});

    // ── negative paths at the wire boundary: named errors only ───────────

    // (1) `s >= p`: RFC 9496 explicitly rejects non-canonical field
    // encodings (unlike RFC 7748's field decode). All-0xff bytes encode a
    // value far above p (p == 2^448 - 2^224 - 1).
    if (Element.decode([_]u8{0xff} ** 56)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.NonCanonical => std.debug.print("all-0xff encoding: NonCanonical (expected)\n", .{}),
        error.InvalidEncoding => return error.WrongNamedError,
    }

    // (2) `IS_NEGATIVE(s)`: s = 1 is canonical (trivially < p) but odd, so
    // step 2 of decode rejects it before any curve math runs at all.
    var negative_bytes = [_]u8{0} ** 56;
    negative_bytes[0] = 1;
    if (Element.decode(negative_bytes)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidEncoding => std.debug.print("s == 1 (odd, IS_NEGATIVE): InvalidEncoding (expected)\n", .{}),
        error.NonCanonical => return error.WrongNamedError,
    }
}
