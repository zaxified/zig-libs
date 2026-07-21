// SPDX-License-Identifier: MIT
//! Shared SIGHASH-type bit layout used by both the legacy (pre-segwit) and
//! BIP143 (segwit v0) sighash algorithms: a raw 32-bit value whose low 5
//! bits select the base type (only 1/2/3 are named; every other low-5-bit
//! value falls back to ALL-like behavior, per Bitcoin Core's
//! `(nHashType & 0x1f)` classification in `SignatureHash()`) and whose
//! `0x80` bit is the independent ANYONECANPAY flag. BIP341 (taproot) uses a
//! stricter, single-byte encoding of its own -- see `sighash_bip341.zig`.

/// Sign all inputs and all outputs (the default/only-safe-to-omit type).
pub const ALL: u32 = 0x01;
/// Sign all inputs, no outputs (anyone may redirect funds post-signing).
pub const NONE: u32 = 0x02;
/// Sign all inputs and only the output at the same index as this input.
pub const SINGLE: u32 = 0x03;
/// OR'd into the base type: sign only this one input (others may be added
/// or removed after signing).
pub const ANYONECANPAY: u32 = 0x80;

/// The low-5-bit base-type selector (`SINGLE`/`NONE` are the only two that
/// change behavior; anything else, including `ALL` and unrecognized values,
/// takes the same "ALL-like" code path).
pub fn baseType(hash_type: u32) u32 {
    return hash_type & 0x1f;
}

pub fn isAnyoneCanPay(hash_type: u32) bool {
    return (hash_type & ANYONECANPAY) != 0;
}

const testing = @import("std").testing;

test "baseType masks to the low 5 bits" {
    try testing.expectEqual(@as(u32, 0x01), baseType(ALL));
    try testing.expectEqual(@as(u32, 0x02), baseType(NONE | ANYONECANPAY));
    try testing.expectEqual(@as(u32, 0x1f), baseType(0xffffffff));
}

test "isAnyoneCanPay checks bit 0x80 only" {
    try testing.expect(isAnyoneCanPay(ALL | ANYONECANPAY));
    try testing.expect(!isAnyoneCanPay(ALL));
    // Every bit set except 0x80.
    try testing.expect(!isAnyoneCanPay(0xffffff7f));
}
