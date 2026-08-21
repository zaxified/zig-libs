// SPDX-License-Identifier: MIT

//! What an EVM-precompile consumer does with `bn254`: drive the three
//! Ethereum precompiles (`ecAdd`/`ecMul`/`ecPairing`, EIP-196/197) exactly
//! as an interpreter would — decode calldata-shaped byte buffers, get back
//! the byte-exact precompile output — and reject a malformed point by a
//! named error instead of a panic.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not re-exported, or an error cannot be named
//! from outside, this file stops compiling.

const std = @import("std");
const bn254 = @import("bn254");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ecAdd(G, G) via the EVM calldata shape: two 64-byte G1 points back to
    // back. Compare against [2]G computed independently through ecMul.
    const g_bytes = bn254.G1.toBytes(bn254.G1.Affine.generator);
    var add_calldata: [128]u8 = undefined;
    @memcpy(add_calldata[0..64], &g_bytes);
    @memcpy(add_calldata[64..128], &g_bytes);
    const sum = try bn254.ecAdd(&add_calldata);

    var mul_calldata: [96]u8 = undefined;
    @memcpy(mul_calldata[0..64], &g_bytes);
    @memset(mul_calldata[64..96], 0);
    mul_calldata[95] = 2; // 32-byte big-endian scalar = 2
    const doubled = try bn254.ecMul(&mul_calldata);
    if (!std.mem.eql(u8, &sum, &doubled)) @panic("ecAdd(G,G) must equal ecMul(G,2)");
    std.debug.print("ecAdd(G,G) == ecMul(G,2): {s}\n", .{std.fmt.bytesToHex(sum, .lower)});

    // ecPairing: e(G1, G2) * e(-G1, G2) == 1 -- bilinearity means negating
    // one operand inverts that factor, so the product collapses to the
    // identity. Calldata is k pairs of (64-byte G1 || 128-byte G2).
    const g2_bytes = bn254.G2.toBytes(bn254.G2.Affine.generator);
    const neg_g1 = bn254.G1.Jacobian.negate(bn254.G1.Jacobian.fromAffine(bn254.G1.Affine.generator)).toAffine();
    const neg_g1_bytes = bn254.G1.toBytes(neg_g1);

    var pairing_calldata: [2 * (64 + 128)]u8 = undefined;
    @memcpy(pairing_calldata[0..64], &g_bytes);
    @memcpy(pairing_calldata[64..192], &g2_bytes);
    @memcpy(pairing_calldata[192..256], &neg_g1_bytes);
    @memcpy(pairing_calldata[256..384], &g2_bytes);

    const ok = try bn254.ecPairingCheck(gpa, &pairing_calldata);
    if (!ok) @panic("e(G,G2) * e(-G,G2) must equal 1");
    std.debug.print("pairing check e(G,G2)*e(-G,G2) == 1: {}\n", .{ok});

    // ecPairing's ABI-encoded raw output form (what an interpreter's
    // return-data actually is), same inputs.
    const raw = try bn254.ecPairing(gpa, &pairing_calldata);
    std.debug.print("ecPairing raw output: {s}\n", .{std.fmt.bytesToHex(raw, .lower)});

    // A malformed G1 point (on-field but off-curve coordinates) is rejected
    // by name -- ecPairingCheck's error set is `precompiles.EcPairingError`
    // (PrecompileError plus Allocator.Error), which is reachable ONLY
    // through the `precompiles` submodule the root module re-exports; there
    // is no top-level `bn254.EcPairingError` alias the way there is a
    // top-level `bn254.PrecompileError` (which in turn is not actually the
    // error set `ecPairingCheck`/`ecPairing` return -- `PrecompileError` is
    // a strict subset missing `error.OutOfMemory`). A caller who wants to
    // name this function's exact return type in their own signature has to
    // know to reach one level deeper than the convenience alias suggests.
    var bad_calldata: [128]u8 = undefined;
    @memset(&bad_calldata, 0);
    bad_calldata[31] = 1; // x = 1
    bad_calldata[63] = 1; // y = 1 -- 1^2 != 1^3 + 3, off-curve
    _ = bn254.ecAdd(&bad_calldata) catch |err| switch (err) {
        error.NotOnCurve => std.debug.print("correctly rejected an off-curve G1 point\n", .{}),
        else => return err,
    };
}
