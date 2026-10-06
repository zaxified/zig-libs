// SPDX-License-Identifier: MIT

//! hash — hashing arbitrary messages to decaf448 elements and scalars.
//!
//!   - `expandMessageXof` — RFC 9380 §5.3.2 `expand_message_xof`,
//!     instantiated with SHAKE256 (the expander RFC 9380 Appendix C and
//!     RFC 9497 §4.2 name for decaf448).
//!   - `hashToElement` — `hash_to_decaf448` (RFC 9380 Appendix C, RFC 9496
//!     §5.3.4's note): `expand_message_xof(msg, DST, 112)` fed to the
//!     existing element derivation `element.oneWayMap`.
//!   - `hashToScalar` — RFC 9497 §4.2's decaf448-SHAKE256 `HashToScalar`:
//!     `expand_message_xof(msg, DST, 64)` read as a little-endian integer
//!     and reduced modulo `l`.
//!
//! Everything here is a public-input computation (a message and a domain
//! separation tag); the only data-dependent work on the expanded bytes is
//! `oneWayMap`/`scalar.reduce`, both constant-time.
//!
//! **Domain separation tags.** RFC 9380 §3.1: a DST MUST have nonzero
//! length; §5.3.3 caps it at 255 bytes. An empty DST is refused
//! (`error.DstEmpty`). A longer one is refused (`error.DstTooLong`) rather
//! than run through §5.3.3's `H2C-OVERSIZE-DST-` reduction, which needs the
//! suite's security level `k` and no suite in RFC 9380 or RFC 9497 uses —
//! a caller with such a DST reduces it themselves and passes the result.

const std = @import("std");
const element = @import("element.zig");
const scalar = @import("scalar.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;
const Element = element.Element;

pub const max_dst_length = 255;
/// RFC 9380 §5.3.2: `len_in_bytes` is carried in two bytes.
pub const max_output_length = 65535;

pub const HashError = error{
    /// The DST is empty (RFC 9380 §3.1: tags MUST have nonzero length).
    DstEmpty,
    /// The DST is longer than 255 bytes (RFC 9380 §5.3.2 step 1).
    DstTooLong,
    /// More than 65535 output bytes requested (RFC 9380 §5.3.2 step 1).
    OutputTooLong,
};

fn checkDst(dst: []const u8) HashError!void {
    if (dst.len == 0) return error.DstEmpty;
    if (dst.len > max_dst_length) return error.DstTooLong;
}

/// RFC 9380 §5.3.2 `expand_message_xof` with `H = SHAKE256`, writing
/// `out.len` bytes:
///
/// ```text
/// DST_prime     = DST || I2OSP(len(DST), 1)
/// msg_prime     = msg || I2OSP(len_in_bytes, 2) || DST_prime
/// uniform_bytes = H(msg_prime, len_in_bytes)
/// ```
///
/// `msg` may be any length, including empty. `out` may be empty (the
/// RFC sets no lower bound for the XOF variant).
pub fn expandMessageXof(out: []u8, msg: []const u8, dst: []const u8) HashError!void {
    try checkDst(dst);
    if (out.len > max_output_length) return error.OutputTooLong;
    var h = Shake256.init(.{});
    h.update(msg);
    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @intCast(out.len), .big);
    h.update(&len_be);
    h.update(dst);
    h.update(&[1]u8{@intCast(dst.len)});
    h.squeeze(out);
}

/// `hash_to_decaf448(msg)` (RFC 9380 Appendix C): 112 uniform bytes from
/// `expandMessageXof`, mapped by RFC 9496 §5.3.4's element derivation
/// (`element.oneWayMap`). This is RFC 9497's decaf448-SHAKE256
/// `HashToGroup` when `dst` is `"HashToGroup-" || contextString`.
pub fn hashToElement(msg: []const u8, dst: []const u8) HashError!Element {
    var uniform: [112]u8 = undefined;
    try expandMessageXof(&uniform, msg, dst);
    return element.oneWayMap(uniform);
}

/// RFC 9497 §4.2 decaf448-SHAKE256 `HashToScalar`: 64 bytes from
/// `expandMessageXof`, read little-endian and reduced modulo `l`
/// (`scalar.reduce`). RFC 9497 passes `"HashToScalar-" || contextString`
/// as `dst` by default and `"DeriveKeyPair" || contextString` inside
/// `DeriveKeyPair`. The 512-bit input is 66 bits wider than `l`, so the
/// output is within `2^-66` of uniform.
pub fn hashToScalar(msg: []const u8, dst: []const u8) HashError!scalar.CompressedScalar {
    var uniform: [64]u8 = undefined;
    try expandMessageXof(&uniform, msg, dst);
    return scalar.reduce(64, uniform);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "DST bounds: empty and 256-byte DSTs are refused, 1- and 255-byte accepted" {
    var out: [32]u8 = undefined;
    try testing.expectError(error.DstEmpty, expandMessageXof(&out, "abc", ""));
    const long = [_]u8{'D'} ** 256;
    try testing.expectError(error.DstTooLong, expandMessageXof(&out, "abc", &long));
    try testing.expectError(error.DstTooLong, hashToElement("abc", &long));
    try testing.expectError(error.DstEmpty, hashToScalar("abc", ""));
    try expandMessageXof(&out, "abc", long[0..255]);
    try expandMessageXof(&out, "abc", "D");
}

test "output length bound: 65535 accepted, 65536 refused" {
    const buf = try testing.allocator.alloc(u8, max_output_length + 1);
    defer testing.allocator.free(buf);
    try testing.expectError(error.OutputTooLong, expandMessageXof(buf, "", "DST"));
    try expandMessageXof(buf[0..max_output_length], "", "DST");
}

test "expandMessageXof: the length is bound into the output (not a prefix of a longer squeeze)" {
    var a: [32]u8 = undefined;
    var b: [64]u8 = undefined;
    try expandMessageXof(&a, "msg", "DST");
    try expandMessageXof(&b, "msg", "DST");
    try testing.expect(!std.mem.eql(u8, &a, b[0..32]));
}

test "hashToElement: distinct DSTs give distinct elements; output is never the identity on these inputs" {
    const p = try hashToElement("msg", "DST-A");
    const q = try hashToElement("msg", "DST-B");
    try testing.expect(!p.equals(q));
    try testing.expect(!p.equals(Element.identity));
}

test "hashToScalar: canonical output" {
    const s = try hashToScalar("msg", "DST");
    try scalar.rejectNonCanonical(s);
}

// ── fuzz harness (arbitrary message and DST) ────────────────────────────

test "fuzz: hashToElement/hashToScalar never crash; errors only on DST bounds" {
    try testing.fuzz({}, fuzzHash, .{});
}

fn fuzzHash(_: void, smith: *std.testing.Smith) !void {
    var buf = [_]u8{0} ** 512; // a short input fills only a prefix
    smith.bytes(&buf);
    // The first two bytes split the rest into DST and message: 0..256 bytes
    // of DST, so the empty, accepted and too-long cases all occur.
    const dst_len = @min(@as(usize, buf[0]) + buf[1] / 128, buf.len - 2);
    const dst = buf[2 .. 2 + dst_len];
    const msg = buf[2 + dst_len ..];
    const want_err = dst.len == 0 or dst.len > max_dst_length;
    if (hashToElement(msg, dst)) |p| {
        try testing.expect(!want_err);
        _ = p.encode();
    } else |err| {
        try testing.expect(want_err);
        try testing.expect(err == error.DstEmpty or err == error.DstTooLong);
    }
    if (hashToScalar(msg, dst)) |s| {
        try testing.expect(!want_err);
        try scalar.rejectNonCanonical(s);
    } else |_| try testing.expect(want_err);
}
