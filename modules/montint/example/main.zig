// SPDX-License-Identifier: MIT

//! What a bignum-crypto consumer (RSA, Paillier, VDF — see the module's own
//! doc comment) does with `montint`: build a fixed-width modulus from a
//! wire-format big-endian byte string, load two operands the same way, and
//! run modular multiplication and modular exponentiation on them.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const montint = @import("montint");

/// A 256-bit modulus, big-endian, odd (as any real RSA/Paillier modulus is):
/// 2^256 - 189 (a prime, chosen only for round arithmetic, not for any
/// cryptographic property this example relies on).
const modulus_be = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x43,
};

pub fn main() !void {
    const M = montint.Modint(256);

    // Build the modulus from wire bytes. `Error` must be nameable so a
    // caller loading an untrusted modulus (a peer's certificate, a config
    // file) can distinguish "even" from "too small" from "doesn't fit".
    const m = M.fromBytesBE(&modulus_be) catch |err| switch (err) {
        error.EvenModulus => {
            std.debug.print("rejected: modulus is even\n", .{});
            return;
        },
        error.ModulusTooSmall, error.Overflow, error.NonCanonical => return err,
    };
    std.debug.print("modulus bit-length: {d}\n", .{m.bits()});

    // Two operands loaded the same way real wire values arrive: big-endian
    // bytes, reduced against the modulus.
    var a_be = [_]u8{0} ** 32;
    a_be[31] = 7; // a = 7
    var b_be = [_]u8{0} ** 32;
    b_be[31] = 3; // b = 3

    const a = try m.elementFromBytesBE(&a_be);
    const b = try m.elementFromBytesBE(&b_be);

    // Normal-domain modular multiplication: (a * b) mod m.
    const product = m.mul(&a, &b);
    var product_be = [_]u8{0} ** 32;
    m.toBytesBE(&product, &product_be);
    std.debug.print("7 * 3 mod m, last byte: 0x{x:0>2}\n", .{product_be[31]});

    // Modular exponentiation: a^b mod m, the modexp primitive RSA/Paillier
    // build their public operations on.
    const result = m.powMont(&a, &b);
    var result_be = [_]u8{0} ** 32;
    m.toBytesBE(&result, &result_be);
    std.debug.print("7^3 mod m, last byte: 0x{x:0>2}\n", .{result_be[31]}); // 343 = 0x157

    // A value at or above the modulus must be rejected by name, not merely
    // truncated: this is the boundary an outside caller relies on to reject
    // a malformed operand off the wire.
    if (m.elementFromBytesBE(&modulus_be)) |_| {
        unreachable; // modulus_be equals m itself, which is non-canonical
    } else |err| switch (err) {
        error.NonCanonical => std.debug.print("operand == modulus correctly rejected\n", .{}),
        error.EvenModulus, error.ModulusTooSmall, error.Overflow => return err,
    }
}
