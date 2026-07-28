// SPDX-License-Identifier: MIT
//! External-vector verification for `cose.zig`'s `COSE_Sign1` layer — see
//! `cose_kat_vectors.zig` for provenance of every hex string used here. This
//! closes the "no external COSE vector" census gap: `kat_test.zig` already
//! anchors `cbor` itself (RFC 8949 Appendix A); this file anchors the COSE
//! wire format specifically (RFC 9052 §4.2), which is otherwise only
//! self-tested (round-trip through this module's own encoder/decoder).

const std = @import("std");
const testing = std.testing;
const cbor = @import("root.zig");
const cose = cbor.cose;
const kat = @import("cose_kat_vectors.zig");

fn hexDecode(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    return try std.fmt.hexToBytes(out, hex);
}

test "RFC 9052 C.2.1: tag-18-wrapped COSE_Sign1 with a protected header parses byte-exact" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const bytes = try hexDecode(a, kat.rfc9052_c2_1.tagged_hex);
    const decoded = try cbor.decode(a, bytes, .{});
    try testing.expect(decoded == .tag);
    try testing.expectEqual(@as(u64, 18), decoded.tag.number);

    const s = try cose.parseSign1(decoded);
    const expected_protected = try hexDecode(a, kat.rfc9052_c2_1.protected_hex);
    try testing.expectEqualSlices(u8, expected_protected, s.protected);
    try testing.expectEqual(@as(usize, 1), s.unprotected.len); // {4: '11'} (kid)
    try testing.expectEqualStrings(kat.rfc9052_c2_1.payload, s.payload.?);
    const expected_sig = try hexDecode(a, kat.rfc9052_c2_1.signature_hex);
    try testing.expectEqualSlices(u8, expected_sig, s.signature);
}

test "RFC 9052 C.2.1: bare-array form (same vector, tag-18 wrapper stripped) parses identically" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const tagged_bytes = try hexDecode(a, kat.rfc9052_c2_1.tagged_hex);
    // The tag-18 wrapper is exactly one leading byte (0xD2, tag number < 24
    // fits in the tag byte's own additional-info field) — stripping it
    // leaves the bare 4-element array this module also accepts.
    const bare_bytes = tagged_bytes[1..];
    const bare_decoded = try cbor.decode(a, bare_bytes, .{});
    try testing.expect(bare_decoded == .array);

    const tagged_decoded = try cbor.decode(a, tagged_bytes, .{});
    const s_tagged = try cose.parseSign1(tagged_decoded);
    const s_bare = try cose.parseSign1(bare_decoded);
    try testing.expectEqualSlices(u8, s_tagged.protected, s_bare.protected);
    try testing.expectEqualSlices(u8, s_tagged.signature, s_bare.signature);
    try testing.expectEqualStrings(s_tagged.payload.?, s_bare.payload.?);
}

test "RFC 9052 C.2.1: sigStructure() matches the published Sig_structure bytes (empty external_aad)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const bytes = try hexDecode(a, kat.rfc9052_c2_1.tagged_hex);
    const decoded = try cbor.decode(a, bytes, .{});
    const s = try cose.parseSign1(decoded);

    const sig_struct = try cose.sigStructure(a, s.protected, &.{}, s.payload.?);
    const expected = try hexDecode(a, kat.rfc9052_c2_1.sig_structure_hex);
    try testing.expectEqualSlices(u8, expected, sig_struct);
}

test "cose-wg sign-pass-02: sigStructure() matches published Sig_structure with non-empty external_aad" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const bytes = try hexDecode(a, kat.sign_pass_02.tagged_hex);
    const decoded = try cbor.decode(a, bytes, .{});
    const s = try cose.parseSign1(decoded);

    const external_aad = try hexDecode(a, kat.sign_pass_02.external_aad_hex);
    const sig_struct = try cose.sigStructure(a, s.protected, external_aad, s.payload.?);
    const expected = try hexDecode(a, kat.sign_pass_02.sig_structure_hex);
    try testing.expectEqualSlices(u8, expected, sig_struct);
}

test "cose-wg sign-fail-01 (wrong CBOR tag 998): parseSign1 still succeeds — tag number is documented out of scope" {
    // This is a real published COSE-WG "failure" vector, but the failure it
    // demonstrates is "a strict verifier expecting tag 18 must reject this" —
    // a semantic/tag-conformance check, not a structural CBOR problem.
    // cose.zig's own doc comment on parseSign1 says the tag number is never
    // itself verified; this confirms that against real external test data
    // rather than asserting rejection (which would be the wrong contract).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const bytes = try hexDecode(a, kat.rfc9052_c2_1_wrong_tag.tagged_hex);
    const decoded = try cbor.decode(a, bytes, .{});
    try testing.expect(decoded == .tag);
    try testing.expectEqual(kat.rfc9052_c2_1_wrong_tag.tag_number, decoded.tag.number);

    const s = try cose.parseSign1(decoded);
    try testing.expectEqualStrings(kat.rfc9052_c2_1.payload, s.payload.?);
}

test "negative: RFC 9052 C.2.1 vector truncated to a 3-element array -> NotSign1" {
    // No external COSE test suite publishes a pure-CBOR-shape failure case
    // (cose-wg/Examples' fail-* vectors are all semantic/signature failures,
    // which parseSign1 correctly still parses structurally — see the
    // wrong-tag test above). This derives a structural negative by
    // truncating the real RFC 9052 C.2.1 vector's array header (0x84 -> 0x83)
    // and dropping its signature element, to check RFC 9052 §4.2's
    // fixed-4-tuple requirement against real vector bytes rather than an
    // arbitrary invented array.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const truncated_hex = "8343A10126A10442313154546869732069732074686520636F6E74656E742E";
    const bytes = try hexDecode(a, truncated_hex);
    const decoded = try cbor.decode(a, bytes, .{});
    try testing.expectError(error.NotSign1, cose.parseSign1(decoded));
}
