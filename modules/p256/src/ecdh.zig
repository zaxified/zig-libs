// SPDX-License-Identifier: MIT

//! ecdh — the ECDH primitive over P-256 (SP 800-56A §5.7.1.2 / SEC 1 §3.3.1):
//! the x-coordinate of `secret · peer`.
//!
//! Same shape as `p384.ecdh`/`ecdhInto` with 32-byte sizes. The peer is
//! validated (canonical coordinates, on the curve, not the identity), then
//! `P256.mulInto` runs the constant-time windowed multiply, so neither the
//! secret nor the shared point lands in a caller's frame; the body runs one
//! frame down and the stack it dirtied is zeroed after it (`burn.zig`,
//! `stackprobe_test.zig`).

const std = @import("std");
const group = @import("group.zig");
const scalarmod = @import("scalar.zig");
const burn = @import("burn.zig");

const P256 = group.P256;
const IdentityElementError = std.crypto.errors.IdentityElementError;
const EncodingError = std.crypto.errors.EncodingError;
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

/// What `ecdh` can fail with.
pub const EcdhError = IdentityElementError || NonCanonicalError || EncodingError || NotSquareError;

/// ECDH: the x-coordinate of `secret · peer`, 32 bytes big-endian. `secret`
/// must be in [1, n − 1] (`error.NonCanonical` above, `error.IdentityElement`
/// for 0); `peer_sec1` is a compressed or uncompressed SEC1 point, validated
/// (canonical, on the curve, not the identity). std's shape (secret by value,
/// result returned); `ecdhInto` is the dead-stack-clean form.
pub fn ecdh(secret: [32]u8, peer_sec1: []const u8) EcdhError![32]u8 {
    var out: [32]u8 = undefined;
    try ecdhInto(&out, &secret, peer_sec1);
    return out;
}

/// `ecdh` with the secret by pointer and the shared secret into `out`
/// (zeroed on error). Burned (`burn.mul_burn`); constant time in `secret`
/// (the range verdict on it is revealed by the error).
pub fn ecdhInto(out: *[32]u8, secret: *const [32]u8, peer_sec1: []const u8) EcdhError!void {
    const r = ecdhUnburned(out, secret, peer_sec1);
    burn.stack(burn.mul_burn);
    return r;
}

noinline fn ecdhUnburned(out: *[32]u8, secret: *const [32]u8, peer_sec1: []const u8) EcdhError!void {
    errdefer std.crypto.secureZero(u8, out);
    const peer = try P256.fromSec1(peer_sec1);
    try peer.rejectIdentity();
    // Range verdicts on the secret: revealed by the error either way. The
    // test itself is branch-free arithmetic (one subtract for the borrow).
    const v = std.mem.readInt(u256, secret, .big);
    const below_n: u1 = @subWithOverflow(v, scalarmod.field_order)[1];
    if (below_n == 0) return error.NonCanonical;
    if (v == 0) return error.IdentityElement;
    var q: P256 = undefined;
    try peer.mulInto(&q, secret, .big);
    out.* = q.affineCoordinates().x.toBytes(.big);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const StdP256 = std.crypto.ecc.P256;

fn fillRandom(prng: *std.Random.DefaultPrng, buf: []u8) void {
    prng.random().bytes(buf);
}

test "ecdh: x of secret·peer agrees with std's P256 (compressed and uncompressed peers)" {
    var prng = std.Random.DefaultPrng.init(0x0ECD_4256);
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        var d: [32]u8 = undefined;
        var e: [32]u8 = undefined;
        fillRandom(&prng, &d);
        fillRandom(&prng, &e);
        d[0] &= 0x7f; // keep both inside [1, n − 1]
        e[0] &= 0x7f;
        d[31] |= 1;
        e[31] |= 1;
        const peer_std = try StdP256.basePoint.mul(e, .big);
        const want = (try peer_std.mul(d, .big)).affineCoordinates().x.toBytes(.big);

        const unc = peer_std.toUncompressedSec1();
        const comp = peer_std.toCompressedSec1();
        try testing.expectEqualSlices(u8, &want, &(try ecdh(d, &unc)));
        try testing.expectEqualSlices(u8, &want, &(try ecdh(d, &comp)));

        var out: [32]u8 = undefined;
        try ecdhInto(&out, &d, &unc);
        try testing.expectEqualSlices(u8, &want, &out);
    }
}

test "ecdh: both sides derive the same secret" {
    const a: [32]u8 = @splat(0x35);
    const b: [32]u8 = @splat(0x6c);
    const pa = (try P256.basePoint.mul(a, .big)).toUncompressedSec1();
    const pb = (try P256.basePoint.mul(b, .big)).toCompressedSec1();
    try testing.expectEqualSlices(u8, &(try ecdh(a, &pb)), &(try ecdh(b, &pa)));
}

test "ecdh: secret range 1 and n − 1 are accepted; 0, n, n + 1 and 2^256 − 1 are refused" {
    const g = P256.basePoint.toUncompressedSec1();
    var buf: [32]u8 = undefined;

    // 1·G = G; (n − 1)·G = −G: the same x.
    std.mem.writeInt(u256, &buf, 1, .big);
    const gx = try ecdh(buf, &g);
    try testing.expectEqualSlices(u8, g[1..33], &gx);
    std.mem.writeInt(u256, &buf, scalarmod.field_order - 1, .big);
    try testing.expectEqualSlices(u8, &gx, &(try ecdh(buf, &g)));

    std.mem.writeInt(u256, &buf, 0, .big);
    try testing.expectError(error.IdentityElement, ecdh(buf, &g));
    inline for (.{ scalarmod.field_order, scalarmod.field_order + 1, std.math.maxInt(u256) }) |v| {
        std.mem.writeInt(u256, &buf, v, .big);
        try testing.expectError(error.NonCanonical, ecdh(buf, &g));
    }
}

test "ecdh: a refused call zeroes out" {
    const g = P256.basePoint.toUncompressedSec1();
    var out: [32]u8 = @splat(0xaa);
    const zero: [32]u8 = @splat(0);
    try testing.expectError(error.IdentityElement, ecdhInto(&out, &zero, &g));
    try testing.expectEqualSlices(u8, &zero, &out);

    out = @splat(0xaa);
    const one = @as([31]u8, @splat(0)) ++ [_]u8{1};
    try testing.expectError(error.InvalidEncoding, ecdhInto(&out, &one, g[0..64]));
    try testing.expectEqualSlices(u8, &zero, &out);
}

test "ecdh: invalid peers are refused" {
    const d: [32]u8 = @splat(0x11);
    const g = P256.basePoint.toUncompressedSec1();

    // The identity, empty and truncated encodings, unknown tags.
    try testing.expectError(error.IdentityElement, ecdh(d, &.{0}));
    try testing.expectError(error.InvalidEncoding, ecdh(d, &.{}));
    try testing.expectError(error.InvalidEncoding, ecdh(d, g[0..64]));
    try testing.expectError(error.InvalidEncoding, ecdh(d, g[0..32]));
    var bad_tag = g;
    bad_tag[0] = 5;
    try testing.expectError(error.InvalidEncoding, ecdh(d, &bad_tag));

    // (0, 0) is off the curve (std's and this module's affine identity is
    // (0, 1), and that one decodes to the identity, which ecdh refuses).
    var zeros: [65]u8 = @splat(0);
    zeros[0] = 4;
    try testing.expectError(error.InvalidEncoding, ecdh(d, &zeros));
    zeros[64] = 1;
    try testing.expectError(error.IdentityElement, ecdh(d, &zeros));

    // Off the curve: y + 1.
    var off = g;
    off[64] +%= 1;
    try testing.expectError(error.InvalidEncoding, ecdh(d, &off));

    // Coordinate ≥ p.
    var big = g;
    @memset(big[1..33], 0xff);
    try testing.expectError(error.NonCanonical, ecdh(d, &big));

    // A compressed x with no point above it: x³ − 3x + b is a non-residue.
    var x: u256 = 1;
    var found = false;
    while (!found) : (x += 1) {
        var enc: [33]u8 = undefined;
        enc[0] = 2;
        std.mem.writeInt(u256, enc[1..33], x, .big);
        if (ecdh(d, &enc)) |_| {} else |err| {
            if (err == error.NotSquare) found = true;
        }
    }
}

test "ecdh: differential vs std on random and mutated SEC1 peers (same verdict, same bytes)" {
    var prng = std.Random.DefaultPrng.init(0x5EC1_0256);
    const d: [32]u8 = @splat(0x2d);
    var accepted: usize = 0;
    var refused: usize = 0;
    var i: usize = 0;
    while (i < 600) : (i += 1) {
        var enc: [65]u8 = undefined;
        var len: usize = undefined;
        switch (i % 3) {
            0 => { // compressed with a random x: about half lie on the curve
                len = 33;
                enc[0] = 2 + @as(u8, @intCast(prng.random().uintLessThan(u8, 2)));
                fillRandom(&prng, enc[1..33]);
                enc[1] &= 0x7f; // keep x < p almost always, so NotSquare is what is tested
            },
            1 => { // a valid uncompressed point with one byte flipped
                var e: [32]u8 = undefined;
                fillRandom(&prng, &e);
                e[0] &= 0x7f;
                e[31] |= 1;
                enc = (try StdP256.basePoint.mul(e, .big)).toUncompressedSec1();
                len = 65;
                const at = prng.random().uintLessThan(usize, 65);
                enc[at] ^= @as(u8, 1) << @intCast(prng.random().uintLessThan(u8, 8));
            },
            else => { // fully random uncompressed
                len = 65;
                enc[0] = 4;
                fillRandom(&prng, enc[1..65]);
            },
        }
        const peer = enc[0..len];
        const want: ?[32]u8 = blk: {
            const p = StdP256.fromSec1(peer) catch break :blk null;
            p.rejectIdentity() catch break :blk null;
            const q = p.mul(d, .big) catch break :blk null;
            break :blk q.affineCoordinates().x.toBytes(.big);
        };
        if (ecdh(d, peer)) |got| {
            try testing.expect(want != null);
            try testing.expectEqualSlices(u8, &want.?, &got);
            accepted += 1;
        } else |_| {
            try testing.expect(want == null);
            refused += 1;
        }
    }
    // Both verdicts occur, so neither a stuck-accept nor a stuck-refuse passes.
    try testing.expect(accepted > 100);
    try testing.expect(refused > 100);
}
