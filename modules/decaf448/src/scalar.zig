// SPDX-License-Identifier: MIT

//! scalar — decaf448's scalar field wire codec (RFC 9496 §5.4): "the
//! scalars for the decaf448 group are integers modulo the order `l` of the
//! decaf448 group. Note that this is the SAME scalar field as edwards448,
//! allowing existing implementations to be reused" — `l` here is bit-for-bit
//! `ed448.scalar`'s `L` (RFC 8032 §5.2's edwards448 subgroup order; RFC 9496
//! restates the identical value in its own §5 prose). This file owns only
//! the WIDTH difference between the two RFCs' wire conventions:
//!
//!   - RFC 8032 (`ed448.scalar.CompressedScalar`) encodes a scalar as
//!     **57** little-endian bytes — the same 456-bit/57-byte container RFC
//!     8032 uses uniformly for both scalars AND point coordinates (`b =
//!     456` bits per that RFC's own parameter table), even though `L <
//!     2^446` never needs the top byte.
//!   - RFC 9496 §5.4 encodes the SAME-valued scalar as **56** little-endian
//!     bytes ("Scalars are encoded as 56-byte strings in little-endian
//!     order") — 448 bits is already enough room for a 446-bit value, no
//!     57th byte needed.
//!
//! Since `l`'s top 10 bits are zero (`ed448.scalar.l_bytes[56] == 0x00` by
//! construction — see that module's own "L is a 446-bit value inside the
//! 57-byte / 456-bit container" test), the two encodings carry IDENTICAL
//! bytes 0..55; byte 56 of the 57-byte form is always `0x00` for any
//! canonical (`< l`) scalar. Converting between them is therefore a pure
//! zero-pad / drop-the-always-zero-top-byte operation — mechanical, no
//! field-math core needed (unlike `element.zig`'s four stubs).
//!
//! `add`/`mul`/`rejectNonCanonical` below simply convert-then-delegate to
//! `ed448.scalar`'s already-real, already-KAT-validated mod-`L` arithmetic
//! — this file adds no numeric logic of its own, only the width bridge.

const std = @import("std");
const ed448 = @import("ed448");

/// 56-byte little-endian wire encoding of a decaf448 scalar (RFC 9496
/// §5.4) — narrower than `ed448.scalar.CompressedScalar`'s 57 bytes; see
/// the module doc comment for why the extra byte is never needed here.
pub const encoded_bytes = 56;
pub const CompressedScalar = [encoded_bytes]u8;

pub const zero: CompressedScalar = [_]u8{0} ** encoded_bytes;

pub const ScalarError = ed448.scalar.ScalarError;

/// Widen a decaf448 56-byte scalar to `ed448.scalar`'s 57-byte container
/// by appending one zero byte — REAL, pure byte copy (see module doc
/// comment: canonical `l`-scalars never populate that 57th byte).
pub fn toEd448(s: CompressedScalar) ed448.scalar.CompressedScalar {
    var out: ed448.scalar.CompressedScalar = undefined;
    out[0..encoded_bytes].* = s;
    out[encoded_bytes] = 0;
    return out;
}

/// Narrow an `ed448.scalar` 57-byte scalar to decaf448's 56-byte
/// container by dropping the top byte — REAL, pure byte copy, PROVIDED
/// the input is canonical (`< L`, so byte 56 is guaranteed `0x00` — see
/// module doc comment). Callers passing a non-canonical or deliberately
/// unreduced 57-byte value (e.g. `ed448`'s own clamped, unreduced signing
/// scalars — never a decaf448 concern, this module only ever receives
/// canonical `< L` scalars from its own `rejectNonCanonical`/arithmetic
/// below) would silently lose that top byte; nothing in THIS module ever
/// constructs such a value.
pub fn fromEd448(s: ed448.scalar.CompressedScalar) CompressedScalar {
    return s[0..encoded_bytes].*;
}

/// Check that a 56-byte scalar encoding is canonical (`< l`) — REAL,
/// delegates entirely to `ed448.scalar.rejectNonCanonical` via `toEd448`'s
/// zero-pad (that function's own byte-compare-against-`L` logic is
/// unaffected by an always-zero top byte on both sides).
pub fn rejectNonCanonical(s: CompressedScalar) ScalarError!void {
    return ed448.scalar.rejectNonCanonical(toEd448(s));
}

/// `a + b (mod l)` — REAL, delegates to `ed448.scalar.add` via `toEd448`/
/// `fromEd448`.
pub fn add(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return fromEd448(ed448.scalar.add(toEd448(a), toEd448(b)));
}

/// `a * b (mod l)` — REAL, delegates to `ed448.scalar.mul`.
pub fn mul(a: CompressedScalar, b: CompressedScalar) CompressedScalar {
    return fromEd448(ed448.scalar.mul(toEd448(a), toEd448(b)));
}

// ── tests ────────────────────────────────────────────────────────────────

test "toEd448/fromEd448 round-trip on zero and one" {
    var one = zero;
    one[0] = 1;
    try std.testing.expectEqualSlices(u8, &one, &fromEd448(toEd448(one)));
    try std.testing.expectEqualSlices(u8, &zero, &fromEd448(toEd448(zero)));
}

test "toEd448 always zero-pads byte 56" {
    var s = zero;
    s[55] = 0xff; // arbitrary high byte, still < l (l's byte 55 is 0x3f-ish)
    const wide = toEd448(s);
    try std.testing.expectEqual(@as(u8, 0), wide[56]);
}

test "l (== ed448's L), read back through the 56-byte width, matches ed448.scalar.l_bytes[0..56]" {
    // ed448.scalar.l_bytes[56] is documented as always 0x00 (446-bit value
    // in a 456-bit container) -- confirms the width-bridge premise this
    // whole file rests on.
    try std.testing.expectEqual(@as(u8, 0x00), ed448.scalar.l_bytes[56]);
    const l56 = fromEd448(ed448.scalar.l_bytes);
    try std.testing.expectEqualSlices(u8, ed448.scalar.l_bytes[0..56], &l56);
}

test "rejectNonCanonical rejects l itself (via the width bridge) and accepts l-1" {
    const l56 = fromEd448(ed448.scalar.l_bytes);
    try std.testing.expectError(error.NonCanonical, rejectNonCanonical(l56));
    var l_minus_1 = l56;
    l_minus_1[0] -= 1; // l's low byte is 0xf3 (matches ed448.scalar.l_bytes), no borrow
    try rejectNonCanonical(l_minus_1);
}

test "add/mul: identities, delegated correctly to ed448.scalar" {
    var one = zero;
    one[0] = 1;
    var two = zero;
    two[0] = 2;
    try std.testing.expectEqualSlices(u8, &two, &add(one, one));
    try std.testing.expectEqualSlices(u8, &one, &mul(one, one));
    try std.testing.expectEqualSlices(u8, &zero, &mul(one, zero));
}
