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
//! (`error.DstEmpty`). A longer one is reduced as §5.3.3 requires for
//! `expand_message_xof`: `DST = SHAKE256("H2C-OVERSIZE-DST-" || DST,
//! ceil(2k/8))` with decaf448's security level `k = 224` (RFC 9496 §5,
//! RFC 9497 §4.2), i.e. 56 bytes (`reduceOversizeDst`). `hashToElement` and
//! `hashToScalar` expand through `ed448.h2c.expandMessageXof`, the sibling's
//! SHAKE256 expander; `expandMessageXof` here is the runtime-length form.

const std = @import("std");
const ed448 = @import("ed448");
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
    /// Not returned (a DST over 255 bytes is reduced,
    /// RFC 9380 §5.3.3); kept so an exhaustive switch still compiles.
    DstTooLong,
    /// More than 65535 output bytes requested (RFC 9380 §5.3.2 step 1).
    OutputTooLong,
};

/// decaf448's security level in bits (RFC 9496 §5: ~224-bit).
pub const security_bits = 224;
/// `ceil(2k/8)`: the length of a reduced oversize DST.
pub const oversize_dst_length = (2 * security_bits + 7) / 8;

/// RFC 9380 §5.3.3 for `expand_message_xof`:
/// `SHAKE256("H2C-OVERSIZE-DST-" || dst, ceil(2k/8))`, `k = 224`.
/// `expandMessageXof` applies it to any DST over 255 bytes on its own.
pub fn reduceOversizeDst(dst: []const u8) [oversize_dst_length]u8 {
    var h = Shake256.init(.{});
    h.update("H2C-OVERSIZE-DST-");
    h.update(dst);
    var out: [oversize_dst_length]u8 = undefined;
    h.squeeze(&out);
    return out;
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
/// RFC sets no lower bound for the XOF variant). This is the runtime-length
/// form; the fixed lengths this module hashes to go through `ed448`'s
/// comptime-length `h2c.expandMessageXof` (the same SHAKE256 expander,
/// `k = 224`, oversize DST reduced the same way).
pub fn expandMessageXof(out: []u8, msg: []const u8, dst: []const u8) HashError!void {
    if (dst.len == 0) return error.DstEmpty;
    if (dst.len > max_dst_length) {
        const reduced = reduceOversizeDst(dst);
        return expandMessageXof(out, msg, &reduced);
    }
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
    if (dst.len == 0) return error.DstEmpty;
    return element.oneWayMap(ed448.h2c.expandMessageXof(112, &.{msg}, dst));
}

/// RFC 9497 §4.2 decaf448-SHAKE256 `HashToScalar`: 64 bytes from
/// `expandMessageXof`, read little-endian and reduced modulo `l`
/// (`scalar.reduce`). RFC 9497 passes `"HashToScalar-" || contextString`
/// as `dst` by default and `"DeriveKeyPair" || contextString` inside
/// `DeriveKeyPair`. The 512-bit input is 66 bits wider than `l`, so the
/// output is within `2^-66` of uniform.
pub fn hashToScalar(msg: []const u8, dst: []const u8) HashError!scalar.CompressedScalar {
    if (dst.len == 0) return error.DstEmpty;
    return scalar.reduce(64, ed448.h2c.expandMessageXof(64, &.{msg}, dst));
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "DST bounds: empty refused; 1..255 bytes used as is; 256+ reduced (RFC 9380 §5.3.3)" {
    var out: [32]u8 = undefined;
    try testing.expectError(error.DstEmpty, expandMessageXof(&out, "abc", ""));
    try testing.expectError(error.DstEmpty, hashToScalar("abc", ""));
    try expandMessageXof(&out, "abc", "D");
    const long = @as([300]u8, @splat('D'));
    try expandMessageXof(&out, "abc", long[0..255]);
    // 256 bytes: the reduced DST, by hand, gives the same bytes.
    var want: [32]u8 = undefined;
    var h = Shake256.init(.{});
    h.update("H2C-OVERSIZE-DST-");
    h.update(long[0..256]);
    var reduced: [56]u8 = undefined;
    h.squeeze(&reduced);
    try expandMessageXof(&want, "abc", &reduced);
    try expandMessageXof(&out, "abc", long[0..256]);
    try testing.expectEqualSlices(u8, &want, &out);
    try testing.expectEqualSlices(u8, &reduced, &reduceOversizeDst(long[0..256]));
    // A different oversize DST is a different domain.
    try expandMessageXof(&want, "abc", long[0..300]);
    try testing.expect(!std.mem.eql(u8, &want, &out));
    _ = try hashToElement("abc", &long);
    _ = try hashToScalar("abc", &long);
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

test "fuzz: hashToElement/hashToScalar never crash; errors only on an empty DST" {
    try testing.fuzz({}, fuzzHash, .{});
}

fn fuzzHash(_: void, smith: *std.testing.Smith) !void {
    var buf = @as([512]u8, @splat(0)); // a short input fills only a prefix
    smith.bytes(&buf);
    // The first two bytes split the rest into DST and message: 0..256 bytes
    // of DST, so the empty, accepted and too-long cases all occur.
    const dst_len = @min(@as(usize, buf[0]) + buf[1] / 128, buf.len - 2);
    const dst = buf[2 .. 2 + dst_len];
    const msg = buf[2 + dst_len ..];
    const want_err = dst.len == 0;
    if (hashToElement(msg, dst)) |p| {
        try testing.expect(!want_err);
        _ = p.encode();
    } else |err| {
        try testing.expect(want_err);
        try testing.expect(err == error.DstEmpty);
    }
    if (hashToScalar(msg, dst)) |s| {
        try testing.expect(!want_err);
        try scalar.rejectNonCanonical(s);
    } else |_| try testing.expect(want_err);
}
