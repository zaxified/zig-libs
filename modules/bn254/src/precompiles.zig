// SPDX-License-Identifier: MIT
//! **Part 5** of the `bn254` multi-part arc (`README.md`): Ethereum's
//! EVM precompiles built directly on top of Parts 1-4 — `ecAdd`
//! (EIP-196, address `0x06`), `ecMul` (EIP-196, address `0x07`), and
//! `ecPairing` (EIP-197, address `0x08`). PURE COMPOSITION: no new
//! field/curve/pairing arithmetic is implemented here — every function
//! below decodes calldata with `g1.zig`/`g2.zig`'s existing EIP-196/197
//! codecs, calls existing `G1`/`G2` group ops or `pairing.pairingCheck`,
//! and re-encodes the result. The engineering content of this file is
//! byte-exact conformance to the EVM's precompile calling convention —
//! calldata padding/truncation and error-vs-success semantics — not
//! cryptography.
//!
//! **Tier: Sonnet, not Fable.** No cryptographic design judgment call is
//! made in this file. The one security-relevant decision — that
//! `ecPairing` MUST reject a `G2` operand that is on-curve but outside
//! the order-`r` subgroup — is not a judgment call either: it is
//! EIP-197's own specified precondition (an unchecked small-subgroup
//! point makes the pairing forgeable), and the check itself
//! (`g2.Jacobian.subgroupCheck`) already exists and was already tested
//! in Part 3 — this file only has to remember to CALL it, not derive
//! why. See `SPEC.md`'s "Part 5" section for the full accounting.
//!
//! ## Calldata padding (EIP-196 §"Note about the change in the way
//! points and outputs are represented", and go-ethereum's own
//! `core/vm/contracts.go` `getData` helper, the de facto interoperable
//! reference every mainnet client matches):
//!
//! `ecAdd`/`ecMul` calldata SHORTER than the field width they need is
//! RIGHT-PADDED with zero bytes; calldata LONGER is TRUNCATED (only the
//! first `128`/`96` bytes are consumed, any trailing bytes are ignored
//! — go-ethereum's `getData(input, start, size)` slices `input[start :
//! min(start+size, len(input))]` then right-pads the result to `size`,
//! for EACH field independently). `padTo` below reproduces that
//! combined effect with a single zero-fill-then-copy over the WHOLE
//! fixed-width buffer — proven equivalent to per-field `getData` for
//! every length regime (empty / shorter-than-one-field /
//! between-fields / exactly-enough / longer-than-needed) in this file's
//! own comment and cross-checked against the KAT vectors below (the
//! `empty`/`short_*`/`long_trailing_bytes` entries exercise exactly the
//! short and long regimes).
//!
//! `ecPairing`'s calldata has NO padding rule: length must be an EXACT
//! multiple of `192` (`64`-byte `G1` `||` `128`-byte `G2`, one pair) or
//! the call FAILS outright (`error.BadLength`) — EIP-197's own stated
//! precondition, distinct from `ecAdd`/`ecMul`'s padding-tolerant
//! convention.
//!
//! ## Failure semantics
//!
//! Every error below (`PrecompileError`, `g1.G1Error || g2.G2Error`
//! plus `BadLength`/`NotInSubgroup`) corresponds to what a real EVM does
//! on a malformed/invalid precompile call: REVERT, consuming all
//! forwarded gas. This module has no EVM/gas model of its own — mapping
//! `error.*` to "revert, burn the gas" is the CALLER's (a future EVM
//! interpreter's) job; this file's contract is only "return an error
//! for every input an EVM must revert on, and a byte-exact success
//! value for every input it must not."
//!
//! ## `ecMul`'s scalar is NOT a validated `Fr`
//!
//! EIP-196's scalar operand is a raw 256-bit big-endian integer used
//! AS-IS, not rejected if `>= r` (contrast `Fr.fromBytes`, which DOES
//! reject non-canonical input — that function is for values that must
//! be canonical scalar-field elements, e.g. a Groth16 witness; the
//! precompile scalar is not one of those). `ecMul` therefore calls
//! `g1.Jacobian.scalarMulBytes` directly on the raw 32-byte operand
//! (the same arbitrary-width-big-endian-scalar engine `g1.zig`/`g2.zig`
//! already use for their own `[r]P == O` subgroup-check KATs) rather
//! than parsing an `Fr` — computing `[scalar]P` for the LITERAL integer
//! value of the 256-bit operand. Because `P` has order `r` (`G1`'s
//! cofactor is 1), this is automatically equal to `[scalar mod r]P` —
//! no separate reduction step is needed or performed.

const std = @import("std");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const pairing = @import("pairing.zig");

/// The union of every failure this file's three precompile entry
/// points can produce. `g1.G1Error`/`g2.G2Error` (`InvalidEncoding`
/// [dead here — see `padTo`'s doc comment, every call site pads/
/// truncates to an exact width first, so length is never wrong by the
/// time `fromBytes` runs; kept in the union only because it rides along
/// with the other two fields, not because a caller of THIS file's
/// functions can trigger it], `InvalidFieldElement` [a coordinate `>=
/// p`], `NotOnCurve`) cover `ecAdd`/`ecMul`/`ecPairing`'s point-decode
/// failures; `BadLength` is `ecPairing`'s length-not-a-multiple-of-192
/// precondition; `NotInSubgroup` is `ecPairing`'s MANDATORY `G2`
/// subgroup check (see module doc comment).
pub const PrecompileError = g1.G1Error || g2.G2Error || error{
    BadLength,
};

/// `ecPairingCheck`/`ecPairing` additionally need a caller-supplied
/// allocator (to hold the decoded `k`-pair batch for
/// `pairing.pairingCheck`, `k` a runtime value derived from calldata
/// length) — same "allocator for a variable-length batch, plain values
/// elsewhere" convention `kzg.zig`'s multi-item functions already use
/// in this repo (e.g. `verifyBlobKzgProofBatch`).
pub const EcPairingError = PrecompileError || std.mem.Allocator.Error;

/// Zero-fills a `n`-byte buffer, then copies `min(input.len, n)` bytes
/// of `input` into its start — the combined effect of EIP-196's
/// right-pad-short / truncate-long calldata rule applied ONCE to a
/// whole multi-field buffer, proven equivalent to go-ethereum's
/// per-field `getData(input, start, size)` (independent right-pad per
/// field) for every input-length regime — see this file's module doc
/// comment for the four-case argument. `n` is always one of this file's
/// three fixed precompile input widths (`128`/`96` for `ecAdd`/
/// `ecMul`; `ecPairing` uses no padding at all — see `ecPairingCheck`).
fn padTo(comptime n: usize, input: []const u8) [n]u8 {
    var buf: [n]u8 = @as([n]u8, @splat(0));
    const copy_len = @min(input.len, n);
    @memcpy(buf[0..copy_len], input[0..copy_len]);
    return buf;
}

/// EIP-196 `ecAdd` (address `0x06`): calldata is two 64-byte `G1`
/// points, `p || q`, padded/truncated to exactly 128 bytes per this
/// file's module doc comment; output is the 64-byte encoding of `p +
/// q`. `(0,0)` decodes to the point at infinity (`g1.zig`'s
/// `fromBytes`), so empty calldata (`p = q = O`) returns 64 zero bytes
/// — see the `empty` KAT below. Fails
/// (`error.InvalidFieldElement`/`error.NotOnCurve`) exactly when either
/// decoded point is malformed, matching the real precompile's revert
/// condition.
pub fn ecAdd(input: []const u8) PrecompileError![64]u8 {
    const buf = padTo(2 * g1.encoded_bytes, input);
    const p = try g1.fromBytes(buf[0..g1.encoded_bytes]);
    const q = try g1.fromBytes(buf[g1.encoded_bytes .. 2 * g1.encoded_bytes]);
    const sum = g1.Jacobian.fromAffine(p).add(g1.Jacobian.fromAffine(q)).toAffine();
    return g1.toBytes(sum);
}

/// The raw scalar operand's width — EIP-196: a 32-byte big-endian
/// integer, used as-is (not a validated `Fr` — see module doc comment).
const scalar_encoded_bytes = 32;

/// EIP-196 `ecMul` (address `0x07`): calldata is a 64-byte `G1` point
/// `p` followed by a 32-byte raw scalar `s`, padded/truncated to
/// exactly 96 bytes; output is the 64-byte encoding of `[s]p`. `s` is
/// consumed via `scalarMulBytes` on the literal 32-byte value, not a
/// canonical `Fr` (module doc comment) — an `s >= r` still produces the
/// mathematically correct `[s mod r]p` because `p`'s order is `r`.
/// Fails exactly when `p` is malformed (same error set as `ecAdd`); a
/// malformed/out-of-range `s` is IMPOSSIBLE (every 32-byte string is a
/// valid `scalarMulBytes` input).
pub fn ecMul(input: []const u8) PrecompileError![64]u8 {
    const buf = padTo(g1.encoded_bytes + scalar_encoded_bytes, input);
    const p = try g1.fromBytes(buf[0..g1.encoded_bytes]);
    const s = buf[g1.encoded_bytes .. g1.encoded_bytes + scalar_encoded_bytes];
    const result = g1.Jacobian.fromAffine(p).scalarMulBytes(s).toAffine();
    return g1.toBytes(result);
}

/// One `ecPairing` pair's wire width: `G1` (64B) `||` `G2` (128B).
const pair_encoded_bytes = g1.encoded_bytes + g2.encoded_bytes;

/// EIP-197 `ecPairing` (address `0x08`), boolean form: calldata is `k`
/// back-to-back `(G1, G2)` pairs with NO padding tolerance — `input.len`
/// must be an EXACT multiple of 192, else `error.BadLength` (unlike
/// `ecAdd`/`ecMul`; see module doc comment). `k = 0` (empty calldata)
/// returns `true` (the empty product is the multiplicative identity —
/// see the `empty_data` KAT below). Every decoded `G1` must be on-curve
/// (EIP-196 cofactor-1 `G1`: on-curve implies subgroup-member
/// automatically, `g1.zig`'s module doc comment, so `g1.fromBytes`'s
/// existing on-curve check is already sufficient — no separate call
/// needed) and every decoded `G2` must be on-curve AND additionally
/// pass `g2.Jacobian.subgroupCheck` — MANDATORY, done inside
/// `g2.fromBytes` (since 2026-10-03; before, this function called it
/// explicitly), because `G2`'s nontrivial cofactor means
/// on-curve does NOT imply subgroup-member (`g2.zig`'s module doc
/// comment): an attacker-supplied on-curve-but-outside-subgroup `G2`
/// operand would otherwise make the pairing check forgeable. A batch
/// with any invalid `G1`/`G2` fails with `error.InvalidFieldElement`/
/// `error.NotOnCurve`/`error.NotInSubgroup` before `pairing.pairingCheck`
/// is ever called on it.
///
/// Needs `allocator` to build the `k`-length `pairing.PairingPair`
/// slice `pairing.pairingCheck` takes (`k` is a runtime value derived
/// from `input.len` — see `EcPairingError`'s doc comment); the
/// allocation is freed before returning.
pub fn ecPairingCheck(allocator: std.mem.Allocator, input: []const u8) EcPairingError!bool {
    if (input.len % pair_encoded_bytes != 0) return error.BadLength;
    const k = input.len / pair_encoded_bytes;
    if (k == 0) return true; // empty product == 1 (EIP-197; see empty_data KAT)

    const pairs = try allocator.alloc(pairing.PairingPair, k);
    defer allocator.free(pairs);

    for (0..k) |i| {
        const off = i * pair_encoded_bytes;
        const p = try g1.fromBytes(input[off .. off + g1.encoded_bytes]);
        // MANDATORY, security-critical (module doc comment): g2.fromBytes
        // checks on-curve and subgroup membership (error.NotInSubgroup).
        const q = try g2.fromBytes(input[off + g1.encoded_bytes .. off + pair_encoded_bytes]);
        pairs[i] = .{ .p = p, .q = q };
    }
    return pairing.pairingCheck(pairs);
}

/// `ecPairingCheck`'s boolean result, ABI-encoded the way the real
/// EVM precompile returns it: 32 bytes, all-zero for `false`, `1` in
/// the low-order byte for `true` (`0x00..01`).
pub fn encodeBool(result: bool) [32]u8 {
    var out = @as([32]u8, @splat(0));
    if (result) out[31] = 1;
    return out;
}

/// EIP-197 `ecPairing`, raw 32-byte ABI-output form — `encodeBool`
/// composed with `ecPairingCheck`. The entry point an EVM interpreter
/// actually wants (the precompile's literal return-data bytes).
pub fn ecPairing(allocator: std.mem.Allocator, input: []const u8) EcPairingError![32]u8 {
    return encodeBool(try ecPairingCheck(allocator, input));
}

// ── tests ────────────────────────────────────────────────────────────────

fn hexDecodeAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

test "padTo: shorter input is zero-right-padded" {
    const buf = padTo(8, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 0, 0, 0, 0, 0 }, &buf);
}

test "padTo: empty input yields all-zero" {
    const buf = padTo(8, &[_]u8{});
    try std.testing.expectEqualSlices(u8, &@as([8]u8, @splat(0)), &buf);
}

test "padTo: exact-length input passes through unchanged" {
    const in = [_]u8{ 9, 8, 7, 6 };
    const buf = padTo(4, &in);
    try std.testing.expectEqualSlices(u8, &in, &buf);
}

test "padTo: longer input is truncated to the first n bytes" {
    const buf = padTo(3, &[_]u8{ 1, 2, 3, 4, 5 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, &buf);
}

test "ecAdd: empty input is O + O = O (64 zero bytes)" {
    const out = try ecAdd(&[_]u8{});
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}

test "ecAdd: identity + generator == generator" {
    const out = try ecAdd(&g1.toBytes(g1.Affine.generator));
    try std.testing.expectEqualSlices(u8, &g1.toBytes(g1.Affine.generator), &out);
}

test "ecAdd: rejects a coordinate >= p" {
    var bytes = @as([128]u8, @splat(0));
    const fp_mod = @import("fp.zig");
    bytes[0..32].* = fp_mod.p_bytes; // p.x == p, non-canonical
    try std.testing.expectError(error.InvalidFieldElement, ecAdd(&bytes));
}

test "ecAdd: rejects an off-curve point" {
    var bytes = @as([128]u8, @splat(0));
    bytes[31] = 1;
    bytes[63] = 3; // (1, 3): off-curve, see g1.zig's own equivalent test
    try std.testing.expectError(error.NotOnCurve, ecAdd(&bytes));
}

test "ecMul: [0]P = O regardless of P" {
    var input: [96]u8 = undefined;
    input[0..64].* = g1.toBytes(g1.Affine.generator);
    @memset(input[64..96], 0);
    const out = try ecMul(&input);
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}

test "ecMul: [1]P = P" {
    var input: [96]u8 = undefined;
    input[0..64].* = g1.toBytes(g1.Affine.generator);
    @memset(input[64..96], 0);
    input[95] = 1;
    const out = try ecMul(&input);
    try std.testing.expectEqualSlices(u8, &g1.toBytes(g1.Affine.generator), &out);
}

test "ecMul: short input (missing scalar) is zero-padded (scalar treated as 0)" {
    // Only the 64-byte point, no scalar bytes at all.
    const out = try ecMul(&g1.toBytes(g1.Affine.generator));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}

test "ecPairingCheck: empty input is true (empty product)" {
    const result = try ecPairingCheck(std.testing.allocator, &[_]u8{});
    try std.testing.expect(result);
}

test "ecPairingCheck: length not a multiple of 192 fails" {
    var bad = @as([100]u8, @splat(0));
    try std.testing.expectError(error.BadLength, ecPairingCheck(std.testing.allocator, &bad));
    var bad2 = @as([191]u8, @splat(0));
    try std.testing.expectError(error.BadLength, ecPairingCheck(std.testing.allocator, &bad2));
}

test "ecPairing: encodeBool matches the 32-byte ABI shape" {
    const t = encodeBool(true);
    var expected_true = @as([32]u8, @splat(0));
    expected_true[31] = 1;
    try std.testing.expectEqualSlices(u8, &expected_true, &t);

    const f = encodeBool(false);
    try std.testing.expect(std.mem.allEqual(u8, &f, 0));
}

test "ecPairingCheck: on-twist-but-not-in-subgroup G2 operand is rejected (subgroup check fires in the precompile path)" {
    // The exact non-subgroup G2 point g2.zig's own test constructs
    // (x = u, c0 = 0, c1 = 1): on-curve but NOT in the order-r
    // subgroup — see g2.zig's "G2 subgroupCheck: an on-twist point
    // OUTSIDE the subgroup fails" test for the independent Python
    // verification of this exact point.
    var c1_bytes = @as([32]u8, @splat(0));
    c1_bytes[31] = 1;
    var y_c0_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c0_bytes, "0cf32d3c49a2cb8a092f24ec3201e68dc299b6216e6321ee60573e3a7f596ea8");
    var y_c1_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y_c1_bytes, "07bca656753ef8cbee60335acbffe3def91636952d4ab9eb0b839c7f3566c0e2");
    const bad_q = g2.Affine{
        .x = .{ .c0 = g2.Fp.zero, .c1 = try g2.Fp.fromBytes(c1_bytes) },
        .y = .{ .c0 = try g2.Fp.fromBytes(y_c0_bytes), .c1 = try g2.Fp.fromBytes(y_c1_bytes) },
    };
    // Sanity, independent of ecPairingCheck: on-curve, but not subgroup.
    try std.testing.expect(g2.Jacobian.fromAffine(bad_q).isOnCurve());
    try std.testing.expect(!g2.Jacobian.fromAffine(bad_q).subgroupCheck());

    var input: [192]u8 = undefined;
    input[0..64].* = g1.toBytes(g1.Affine.generator);
    input[64..192].* = g2.toBytes(bad_q);

    try std.testing.expectError(error.NotInSubgroup, ecPairingCheck(std.testing.allocator, &input));
}

test "ecPairingCheck: an off-curve G1 in a batch fails before pairingCheck ever runs" {
    var input: [192]u8 = undefined;
    @memset(&input, 0);
    input[31] = 1;
    input[63] = 3; // (1,3): off-curve G1 (see g1.zig's own equivalent test)
    input[64..192].* = g2.toBytes(g2.Affine.generator);
    try std.testing.expectError(error.NotOnCurve, ecPairingCheck(std.testing.allocator, &input));
}

// ── precompile KAT vectors ──────────────────────────────────────────────
//
// `precompile_vectors.zig`, generated by `tools/gen_precompile_vectors.py`
// over this repository's own inputs (fixed-seed scalars times the
// generators). Expected ecAdd/ecMul outputs come from the generator's own
// affine BN254 arithmetic, a second implementation sharing no code with the
// Zig tower; ecPairing truth values hold by construction (balanced pairs
// multiply to 1 by bilinearity, an unbalanced set to a non-trivial power of
// `e(G1, G2)`). `two_pairs_*`/`ten_pairs_*`/`empty`/`infinity_*` exercise the
// TRUE path and `one_pair_generators`/`*_unbalanced` the FALSE path;
// `empty`/`short_*`/`long_trailing_bytes` in ecAdd and ecMul exercise the
// short-input zero-padding and long-input truncation rules.
//
// Until 2026-10-26 these were go-ethereum's `bn256*.json` tables
// (LGPL-3.0); they were replaced because copyleft-licensed data may not live
// in this repository.

const precompile_vectors = @import("precompile_vectors.zig");
const add_vectors = precompile_vectors.add_vectors;
const mul_vectors = precompile_vectors.mul_vectors;
const pairing_vectors = precompile_vectors.pairing_vectors;

test "ecAdd: every KAT vector, byte-exact" {
    const allocator = std.testing.allocator;
    for (add_vectors) |v| {
        const input = try hexDecodeAlloc(allocator, v.input);
        defer allocator.free(input);
        const expected = try hexDecodeAlloc(allocator, v.expected);
        defer allocator.free(expected);
        const out = ecAdd(input) catch |err| {
            std.debug.print("ecAdd vector {s} failed: {}\n", .{ v.name, err });
            return err;
        };
        std.testing.expectEqualSlices(u8, expected, &out) catch |err| {
            std.debug.print("ecAdd vector {s} mismatched\n", .{v.name});
            return err;
        };
    }
}

test "ecMul: every KAT vector, byte-exact" {
    const allocator = std.testing.allocator;
    for (mul_vectors) |v| {
        const input = try hexDecodeAlloc(allocator, v.input);
        defer allocator.free(input);
        const expected = try hexDecodeAlloc(allocator, v.expected);
        defer allocator.free(expected);
        const out = ecMul(input) catch |err| {
            std.debug.print("ecMul vector {s} failed: {}\n", .{ v.name, err });
            return err;
        };
        std.testing.expectEqualSlices(u8, expected, &out) catch |err| {
            std.debug.print("ecMul vector {s} mismatched\n", .{v.name});
            return err;
        };
    }
}

test "ecPairing: every KAT vector (true AND false paths)" {
    const allocator = std.testing.allocator;
    var saw_true = false;
    var saw_false = false;
    for (pairing_vectors) |v| {
        const input = try hexDecodeAlloc(allocator, v.input);
        defer allocator.free(input);
        const result = ecPairingCheck(allocator, input) catch |err| {
            std.debug.print("ecPairing vector {s} failed: {}\n", .{ v.name, err });
            return err;
        };
        if (result != v.expected_true) {
            std.debug.print("ecPairing vector {s} mismatched: got {} want {}\n", .{ v.name, result, v.expected_true });
            return error.TestExpectedEqual;
        }
        if (v.expected_true) saw_true = true else saw_false = true;
    }
    // Both branches of ecPairing's boolean result are genuinely exercised
    // (`one_pair_generators`/`*_unbalanced` are FALSE, the balanced sets
    // TRUE) — not just the trivially-true empty case.
    try std.testing.expect(saw_true);
    try std.testing.expect(saw_false);
}

test "ecPairing: raw 32-byte ABI encoding matches the expected boolean directly" {
    const allocator = std.testing.allocator;
    for (pairing_vectors) |v| {
        const input = try hexDecodeAlloc(allocator, v.input);
        defer allocator.free(input);
        const out = try ecPairing(allocator, input);
        const expected = encodeBool(v.expected_true);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

// ── fuzz harnesses (untrusted calldata decoders) ────────────────────────
//
// ⚠ All three harnesses used to open with
//
//     smith.bytes(&buf);
//     const len: usize = smith.valueRangeAtMost(u32, 0, @intCast(buf.len));
//
// which reads the input and then throws it away: `bytes` consumes
// `@min(buf.len, in.len)` octets and the ranged draw then finds fewer than the
// eight it reads as a little-endian u64, so `len` was the range MINIMUM — 0 —
// on every input. With no corpus either, each target ran exactly one input
// for ever: `ecAdd("")`, `ecMul("")`, `ecPairing("")`.
//
// ⛔ And all three of those SUCCEED. EIP-196 right-pads short calldata, so
// `ecAdd("")` decodes `p = q = O` and returns 64 zero octets, and EIP-197's
// empty product is `true` — so a guard asserting "something was accepted"
// would have passed here while the harness walked no curve arithmetic at all.
// That is why each guard below pins a SECOND number the empty input cannot
// produce: a result that is not the point at infinity, or a `false`.
//
// ⛔ The `ecPairing` buffer was also too small for this module's own fixtures.
// The 10-pair vectors are 1920 octets and the buffer held 416, and a
// seed longer than the buffer reads back EMPTY (`Smith.slice` falls back to
// the range minimum) — so the largest calldata the module owns could never
// have passed through the harness meant to fuzz it, silently.

const testkit = @import("testkit");

/// `hex` with one hex DIGIT changed. A real vector one nibble off is still
/// well-formed calldata of the right length, so it reaches the field and
/// curve checks rather than dying on a length rule the way random bytes do.
/// The replacement is always a valid hex digit, so `seedHex` cannot be handed
/// a malformed literal.
fn nibbled(comptime hex: []const u8, comptime at: usize) []const u8 {
    return &struct {
        const s = blk: {
            var out = hex[0..hex.len].*;
            out[at] = if (out[at] == 'f') '0' else 'f';
            break :blk out;
        };
    }.s;
}

// ── ecAdd ────────────────────────────────────────────────────────────────

/// Every `ecAdd` KAT vector (they already cover empty, short-padded,
/// exact and over-long calldata) plus the shapes that must be REFUSED —
/// which no KAT vector carries, since the table is a success table.
const ecadd_seeds = blk: {
    @setEvalBranchQuota(1 << 20);
    var out: [add_vectors.len + 3][]const u8 = undefined;
    for (add_vectors, 0..) |v, i| out[i] = testkit.fuzz.seedHex(v.input);
    // `a_plus_b` with one nibble of p.x changed: a well-formed field element
    // that is not on the curve -> error.NotOnCurve.
    out[add_vectors.len + 0] = testkit.fuzz.seedHex(nibbled(add_vectors[0].input, 20));
    // A coordinate at 2^256-1, far above the field modulus p
    // -> error.InvalidFieldElement.
    out[add_vectors.len + 1] = testkit.fuzz.seedHex(strRepeat("ff", 128));
    // 65 octets: past the first point, mid-way through the second, so the
    // right-pad rule has to finish the frame.
    out[add_vectors.len + 2] = testkit.fuzz.seedHex(strRepeat("11", 65));
    break :blk out;
};

test "fuzz: ecAdd never crashes on arbitrary calldata" {
    try std.testing.fuzz({}, fuzzEcAdd, .{ .corpus = &ecadd_seeds });
}

fn fuzzEcAdd(_: void, smith: *std.testing.Smith) !void {
    // 256 against a 192-octet longest KAT vector.
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice`, never `bytes` followed by a ranged length.
    const len: usize = smith.slice(&buf);
    _ = ecAdd(buf[0..len]) catch return;
}

test "corpus: the ecAdd seeds reach the decoder, and the counts are pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var points: usize = 0; // results that are NOT the point at infinity
    for (ecadd_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const out = ecAdd(buf[0..len]) catch continue;
        accepted += 1;
        if (!std.mem.allEqual(u8, &out, 0)) points += 1;
    }
    // `empty`'s input is the empty string — the one input this target used
    // to run, now one seed among many rather than the whole corpus.
    try std.testing.expectEqual(ecadd_seeds.len - 1, nonempty);
    try std.testing.expectEqual(@as(usize, 10), accepted);
    try std.testing.expectEqual(@as(usize, 7), points);
}

// ── ecMul ────────────────────────────────────────────────────────────────

const ecmul_seeds = blk: {
    @setEvalBranchQuota(1 << 20);
    // The KAT vectors already carry the point-without-scalar
    // (`short_64_no_scalar`, s = 0 by the right-pad rule, so accepted but NOT
    // counted towards `points`) and empty calldata (`empty`: p = O, s = 0,
    // the one input this target used to run).
    var out: [mul_vectors.len + 2][]const u8 = undefined;
    for (mul_vectors, 0..) |v, i| out[i] = testkit.fuzz.seedHex(v.input);
    // `p_times_s` with one nibble of p.x changed -> error.NotOnCurve.
    out[mul_vectors.len + 0] = testkit.fuzz.seedHex(nibbled(mul_vectors[0].input, 20));
    // A coordinate above the field modulus -> error.InvalidFieldElement.
    out[mul_vectors.len + 1] = testkit.fuzz.seedHex(strRepeat("ff", 96));
    break :blk out;
};

test "fuzz: ecMul never crashes on arbitrary calldata" {
    try std.testing.fuzz({}, fuzzEcMul, .{ .corpus = &ecmul_seeds });
}

fn fuzzEcMul(_: void, smith: *std.testing.Smith) !void {
    // 256 against a 128-octet longest KAT vector.
    var buf: [256]u8 = undefined;
    const len: usize = smith.slice(&buf);
    _ = ecMul(buf[0..len]) catch return;
}

test "corpus: the ecMul seeds reach the decoder, and the counts are pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var points: usize = 0;
    for (ecmul_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const out = ecMul(buf[0..len]) catch continue;
        accepted += 1;
        if (!std.mem.allEqual(u8, &out, 0)) points += 1;
    }
    try std.testing.expectEqual(ecmul_seeds.len - 1, nonempty);
    try std.testing.expectEqual(@as(usize, 13), accepted);
    try std.testing.expectEqual(@as(usize, 8), points);
}

// ── ecPairing ────────────────────────────────────────────────────────────

const ecpairing_seeds = blk: {
    @setEvalBranchQuota(1 << 22);
    var out: [pairing_vectors.len + 3][]const u8 = undefined;
    for (pairing_vectors, 0..) |v, i| out[i] = testkit.fuzz.seedHex(v.input);
    // `two_pairs_balanced` with one nibble of a G2 coordinate changed: the pair is
    // still 192 octets, so it gets past the length rule and into the on-curve
    // and — the security-critical one — the G2 subgroup check.
    out[pairing_vectors.len + 0] = testkit.fuzz.seedHex(nibbled(pairing_vectors[0].input, 300));
    // 191 octets: not a multiple of 192 -> error.BadLength.
    out[pairing_vectors.len + 1] = testkit.fuzz.seedHex(pairing_vectors[0].input[0 .. 191 * 2]);
    // One pair of coordinates all above the field modulus.
    out[pairing_vectors.len + 2] = testkit.fuzz.seedHex(strRepeat("ff", 192));
    break :blk out;
};

test "fuzz: ecPairing never crashes on arbitrary calldata" {
    try std.testing.fuzz({}, fuzzEcPairing, .{ .corpus = &ecpairing_seeds });
}

/// The `ecPairing` buffer. ⛔ It used to be `2 * pair_encoded_bytes + 32` =
/// 416 octets, and the 10-pair KAT vectors — this module's largest — are
/// 1920. A seed over the buffer reads back EMPTY, so those could never have
/// reached the harness. 10 pairs plus 32 keeps
/// the off-multiple lengths reachable as well.
const ecpairing_buf_bytes = 10 * pair_encoded_bytes + 32;

fn fuzzEcPairing(_: void, smith: *std.testing.Smith) !void {
    var buf: [ecpairing_buf_bytes]u8 = undefined;
    const len: usize = smith.slice(&buf);
    _ = ecPairing(std.testing.allocator, buf[0..len]) catch return;
}

test "corpus: the ecPairing seeds reach the decoder, and the counts are pinned" {
    // ⛔ `accepted` alone is worthless here: EIP-197's empty product is `true`,
    // so `ecPairingCheck("")` succeeds without decoding a single point — which
    // is exactly what this target did on every run before the corpus. `falses`
    // is the number only a batch of REAL points can produce.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var falses: usize = 0;
    for (ecpairing_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [ecpairing_buf_bytes]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const ok = ecPairingCheck(std.testing.allocator, buf[0..len]) catch continue;
        accepted += 1;
        if (!ok) falses += 1;
    }
    // `empty`'s input is the empty string.
    try std.testing.expectEqual(ecpairing_seeds.len - 1, nonempty);
    try std.testing.expectEqual(@as(usize, 9), accepted);
    try std.testing.expectEqual(@as(usize, 3), falses);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
