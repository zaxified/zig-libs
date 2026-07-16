// SPDX-License-Identifier: MIT

//! Byte-exact KAT assertions against RFC 9496 Appendix B (`kat_vectors.zig`)
//! through `element.zig`'s public API. Every test in this file that would
//! reach `Element.encode`/`Element.decode`/`oneWayMap` is gated behind
//! `gate.core_implemented` and reports **SKIP** (`error.SkipZigTest`), not
//! PASS, until a Fable pass fills in the four stubs in `element.zig` (see
//! `gate.zig`'s own doc comment for the full split of what's real vs.
//! gated).

const std = @import("std");
const testing = std.testing;

const ed448 = @import("ed448");
const element = @import("element.zig");
const gate = @import("gate.zig");
const vectors = @import("kat_vectors.zig");

const Element = element.Element;
const Fe = ed448.field.Fe;

/// Build `[k]G` for a small `k` by `k` repeated additions of the
/// generator — the SAME recipe RFC 9496 Appendix B.1 itself describes
/// ("each successive entry is obtained by adding the generator to the
/// previous entry"). REAL/ungated (pure `Element.add`, see `element.zig`),
/// used below both to construct the values `encode` is checked against
/// AND (in `element.zig`'s own ungated test suite) independent of
/// `encode`/`decode` entirely.
fn nthMultiple(k: usize) Element {
    var acc = Element.identity;
    var i: usize = 0;
    while (i < k) : (i += 1) acc = Element.add(acc, Element.generator);
    return acc;
}

test "B.1: encode([k]G) is byte-exact for k = 0..15" {
    if (!gate.core_implemented) return error.SkipZigTest;
    for (vectors.generator_multiples, 0..) |expected, k| {
        const p = nthMultiple(k);
        try testing.expectEqualSlices(u8, &expected, &element.Element.encode(p));
    }
}

test "B.1: decode(encode([k]G)) round-trips to an equal element, for k = 0..15" {
    if (!gate.core_implemented) return error.SkipZigTest;
    for (vectors.generator_multiples, 0..) |expected, k| {
        const p = nthMultiple(k);
        const decoded = try Element.decode(expected);
        try testing.expect(decoded.equals(p));
        // "Decoding and then re-encoding a valid group element will yield
        // an identical byte string" (RFC 9496 §5.3.2).
        try testing.expectEqualSlices(u8, &expected, &Element.encode(decoded));
    }
}

test "B.2: 21 invalid encodings are all rejected by decode" {
    if (!gate.core_implemented) return error.SkipZigTest;
    for (vectors.invalid_non_canonical) |bytes| {
        try testing.expectError(error.NonCanonical, Element.decode(bytes));
    }
    for (vectors.invalid_negative) |bytes| {
        try testing.expectError(error.InvalidEncoding, Element.decode(bytes));
    }
    for (vectors.invalid_nonsquare) |bytes| {
        try testing.expectError(error.InvalidEncoding, Element.decode(bytes));
    }
}

test "B.3: oneWayMap is byte-exact on the 7 uniform-byte-string vectors" {
    if (!gate.core_implemented) return error.SkipZigTest;
    for (vectors.derivation_vectors) |vec| {
        const p = element.oneWayMap(vec.input);
        try testing.expectEqualSlices(u8, &vec.output, &Element.encode(p));
    }
}

test "sqrtRatioM1: was_square branch (u/v a nonzero square) returns +sqrt(u/v)" {
    if (!gate.core_implemented) return error.SkipZigTest;
    // u = v = 1: 1/1 = 1 is trivially square, root should be +1 (already
    // non-negative) or its negation normalized to non-negative by CT_ABS
    // -- either way squaring the returned root must reproduce u/v = 1.
    const one = Fe.one;
    const r = element.sqrtRatioM1(one, one);
    try testing.expect(r.was_square);
    try testing.expect(r.root.square().eql(one));
    try testing.expect(!r.root.isOdd()); // CT_ABS: nonnegative
}

test "sqrtRatioM1: v == 0, u != 0 -> (false, zero)" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const one = Fe.one;
    const r = element.sqrtRatioM1(one, Fe.zero);
    try testing.expect(!r.was_square);
    try testing.expect(r.root.isZero());
}

test "sqrtRatioM1: u == 0 -> (true, zero), regardless of v" {
    if (!gate.core_implemented) return error.SkipZigTest;
    const one = Fe.one;
    const r = element.sqrtRatioM1(Fe.zero, one);
    try testing.expect(r.was_square);
    try testing.expect(r.root.isZero());
}
