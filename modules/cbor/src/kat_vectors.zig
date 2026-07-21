// SPDX-License-Identifier: MIT
//! RFC 8949 Appendix A ("Examples of Encoded CBOR Data Items") as
//! machine-checkable vectors. Hex + expected `Value` cross-checked against
//! the community `cbor/test-vectors` repository's `appendix_a.json`
//! (https://github.com/cbor/test-vectors), itself a direct transcription of
//! the RFC table — not hand-typed from memory.
//!
//! Each vector's `roundtrip` field mirrors the RFC table: `true` for
//! definite-length/shortest-form encodings (this module's `encode()`
//! reproduces them byte-exact), `false` for indefinite-length or otherwise
//! non-preferred encodings (this module always encodes definite-length —
//! `kat_test.zig` checks these decode to the *same value* as their
//! definite-form sibling instead of a byte round-trip).
//!
//! **One discrepancy found and deliberately NOT carried over:** the
//! community `cbor/test-vectors` JSON adds an extra `simple(24)` / hex
//! `f818` vector that is not actually in RFC 8949's own Appendix A table
//! (fetched and diffed against the RFC's own text directly) — and per RFC
//! 8949 §3.3, "An encoder MUST NOT issue two-byte sequences that start with
//! 0xf8 ... and continue with a byte less than 0x20 (32 decimal)", i.e.
//! `f818` (argument 24 < 32) is not well-formed CBOR at all. This module's
//! decoder correctly rejects it (`kat_test.zig`'s "hostile: non-canonical
//! 1-byte simple-value form" case); it is not included here.

const std = @import("std");
const cbor = @import("root.zig");
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;

pub const Vector = struct {
    hex: []const u8,
    value: Value,
    roundtrip: bool = true,
};

// ── shared sub-values (addressed by `.tag.value`) ──────────────────────────

const tag0_inner: Value = .{ .text = "2013-03-21T20:04:00Z" };
const tag1a_inner: Value = .{ .uint = 1363896240 };
const tag1b_inner: Value = .{ .f64 = 1363896240.5 };
const tag23_inner: Value = .{ .bytes = &[_]u8{ 0x01, 0x02, 0x03, 0x04 } };
const tag24_inner: Value = .{ .bytes = &[_]u8{ 0x64, 0x49, 0x45, 0x54, 0x46 } };
const tag32_inner: Value = .{ .text = "http://www.example.com" };
const bignum_bytes = [_]u8{ 0x01, 0, 0, 0, 0, 0, 0, 0, 0 }; // 2^64, 9-byte bignum payload
const tag2_inner: Value = .{ .bytes = &bignum_bytes };
const tag3_inner: Value = .{ .bytes = &bignum_bytes };

// ── shared composite values (reused by indefinite-length siblings) ─────────

const arr123 = [_]Value{ .{ .uint = 1 }, .{ .uint = 2 }, .{ .uint = 3 } };
const arr23 = [_]Value{ .{ .uint = 2 }, .{ .uint = 3 } };
const arr45 = [_]Value{ .{ .uint = 4 }, .{ .uint = 5 } };
const nested_arr = [_]Value{ .{ .uint = 1 }, .{ .array = &arr23 }, .{ .array = &arr45 } };

const arr_1_25 = blk: {
    var items: [25]Value = undefined;
    for (&items, 1..) |*it, i| it.* = .{ .uint = @intCast(i) };
    break :blk items;
};

const map_ab = [_]MapEntry{
    .{ .key = .{ .text = "a" }, .value = .{ .uint = 1 } },
    .{ .key = .{ .text = "b" }, .value = .{ .array = &arr23 } },
};

const arr_a_bc = [_]Value{
    .{ .text = "a" },
    .{ .map = &[_]MapEntry{.{ .key = .{ .text = "b" }, .value = .{ .text = "c" } }} },
};

const map_fun_amt = [_]MapEntry{
    .{ .key = .{ .text = "Fun" }, .value = .{ .bool = true } },
    .{ .key = .{ .text = "Amt" }, .value = .{ .negint = 1 } }, // -1 - 1 = -2
};

pub const vectors = [_]Vector{
    // ── integers ─────────────────────────────────────────────────────────
    .{ .hex = "00", .value = .{ .uint = 0 } },
    .{ .hex = "01", .value = .{ .uint = 1 } },
    .{ .hex = "0a", .value = .{ .uint = 10 } },
    .{ .hex = "17", .value = .{ .uint = 23 } }, // largest 1-byte-head uint
    .{ .hex = "1818", .value = .{ .uint = 24 } }, // smallest 1-byte-arg uint
    .{ .hex = "1819", .value = .{ .uint = 25 } },
    .{ .hex = "1864", .value = .{ .uint = 100 } },
    .{ .hex = "1903e8", .value = .{ .uint = 1000 } }, // 2-byte arg
    .{ .hex = "1a000f4240", .value = .{ .uint = 1000000 } }, // 4-byte arg
    .{ .hex = "1b000000e8d4a51000", .value = .{ .uint = 1000000000000 } }, // 8-byte arg
    .{ .hex = "1bffffffffffffffff", .value = .{ .uint = 18446744073709551615 } }, // u64 max
    .{ .hex = "c249010000000000000000", .value = .{ .tag = .{ .number = 2, .value = &tag2_inner } } }, // 2^64 bignum
    .{ .hex = "3bffffffffffffffff", .value = .{ .negint = 18446744073709551615 } }, // -18446744073709551616
    .{ .hex = "c349010000000000000000", .value = .{ .tag = .{ .number = 3, .value = &tag3_inner } } }, // -(2^64+1) bignum
    .{ .hex = "20", .value = .{ .negint = 0 } }, // -1
    .{ .hex = "29", .value = .{ .negint = 9 } }, // -10
    .{ .hex = "3863", .value = .{ .negint = 99 } }, // -100
    .{ .hex = "3903e7", .value = .{ .negint = 999 } }, // -1000

    // ── floats ───────────────────────────────────────────────────────────
    .{ .hex = "f90000", .value = .{ .f16 = 0.0 } },
    .{ .hex = "f98000", .value = .{ .f16 = @bitCast(@as(u16, 0x8000)) } }, // -0.0
    .{ .hex = "f93c00", .value = .{ .f16 = 1.0 } },
    .{ .hex = "fb3ff199999999999a", .value = .{ .f64 = 1.1 } },
    .{ .hex = "f93e00", .value = .{ .f16 = 1.5 } },
    .{ .hex = "f97bff", .value = .{ .f16 = 65504.0 } }, // f16 max normal
    .{ .hex = "fa47c35000", .value = .{ .f32 = 100000.0 } },
    .{ .hex = "fa7f7fffff", .value = .{ .f32 = 3.4028234663852886e+38 } }, // f32 max normal
    .{ .hex = "fb7e37e43c8800759c", .value = .{ .f64 = 1.0e+300 } },
    .{ .hex = "f90001", .value = .{ .f16 = @bitCast(@as(u16, 0x0001)) } }, // smallest subnormal f16
    .{ .hex = "f90400", .value = .{ .f16 = @bitCast(@as(u16, 0x0400)) } }, // 0.00006103515625
    .{ .hex = "f9c400", .value = .{ .f16 = -4.0 } },
    .{ .hex = "fbc010666666666666", .value = .{ .f64 = -4.1 } },
    .{ .hex = "f97c00", .value = .{ .f16 = @bitCast(@as(u16, 0x7c00)) } }, // +Infinity
    .{ .hex = "f97e00", .value = .{ .f16 = @bitCast(@as(u16, 0x7e00)) } }, // NaN
    .{ .hex = "f9fc00", .value = .{ .f16 = @bitCast(@as(u16, 0xfc00)) } }, // -Infinity
    .{ .hex = "fa7f800000", .value = .{ .f32 = @bitCast(@as(u32, 0x7f800000)) } }, // +Infinity (single)
    .{ .hex = "fa7fc00000", .value = .{ .f32 = @bitCast(@as(u32, 0x7fc00000)) } }, // NaN (single)
    .{ .hex = "faff800000", .value = .{ .f32 = @bitCast(@as(u32, 0xff800000)) } }, // -Infinity (single)
    .{ .hex = "fb7ff0000000000000", .value = .{ .f64 = @bitCast(@as(u64, 0x7ff0000000000000)) } }, // +Infinity (double)
    .{ .hex = "fb7ff8000000000000", .value = .{ .f64 = @bitCast(@as(u64, 0x7ff8000000000000)) } }, // NaN (double)
    .{ .hex = "fbfff0000000000000", .value = .{ .f64 = @bitCast(@as(u64, 0xfff0000000000000)) } }, // -Infinity (double)

    // ── bool / null / undefined / simple ────────────────────────────────
    .{ .hex = "f4", .value = .{ .bool = false } },
    .{ .hex = "f5", .value = .{ .bool = true } },
    .{ .hex = "f6", .value = .null_value },
    .{ .hex = "f7", .value = .undefined_value },
    .{ .hex = "f0", .value = .{ .simple = 16 } },
    .{ .hex = "f8ff", .value = .{ .simple = 255 } },

    // ── tags ─────────────────────────────────────────────────────────────
    .{ .hex = "c074323031332d30332d32315432303a30343a30305a", .value = .{ .tag = .{ .number = 0, .value = &tag0_inner } } },
    .{ .hex = "c11a514b67b0", .value = .{ .tag = .{ .number = 1, .value = &tag1a_inner } } },
    .{ .hex = "c1fb41d452d9ec200000", .value = .{ .tag = .{ .number = 1, .value = &tag1b_inner } } },
    .{ .hex = "d74401020304", .value = .{ .tag = .{ .number = 23, .value = &tag23_inner } } },
    .{ .hex = "d818456449455446", .value = .{ .tag = .{ .number = 24, .value = &tag24_inner } } },
    .{ .hex = "d82076687474703a2f2f7777772e6578616d706c652e636f6d", .value = .{ .tag = .{ .number = 32, .value = &tag32_inner } } },

    // ── byte / text strings ─────────────────────────────────────────────
    .{ .hex = "40", .value = .{ .bytes = &.{} } },
    .{ .hex = "4401020304", .value = .{ .bytes = &[_]u8{ 1, 2, 3, 4 } } },
    .{ .hex = "60", .value = .{ .text = "" } },
    .{ .hex = "6161", .value = .{ .text = "a" } },
    .{ .hex = "6449455446", .value = .{ .text = "IETF" } },
    .{ .hex = "62225c", .value = .{ .text = "\"\\" } },
    .{ .hex = "62c3bc", .value = .{ .text = "\u{fc}" } },
    .{ .hex = "63e6b0b4", .value = .{ .text = "\u{6c34}" } },
    .{ .hex = "64f0908591", .value = .{ .text = "\u{10151}" } },

    // ── arrays ───────────────────────────────────────────────────────────
    .{ .hex = "80", .value = .{ .array = &.{} } },
    .{ .hex = "83010203", .value = .{ .array = &arr123 } },
    .{ .hex = "8301820203820405", .value = .{ .array = &nested_arr } },
    .{ .hex = "98190102030405060708090a0b0c0d0e0f101112131415161718181819", .value = .{ .array = &arr_1_25 } },

    // ── maps ─────────────────────────────────────────────────────────────
    .{ .hex = "a0", .value = .{ .map = &.{} } },
    .{
        .hex = "a201020304",
        .value = .{ .map = &[_]MapEntry{
            .{ .key = .{ .uint = 1 }, .value = .{ .uint = 2 } },
            .{ .key = .{ .uint = 3 }, .value = .{ .uint = 4 } },
        } },
    },
    .{ .hex = "a26161016162820203", .value = .{ .map = &map_ab } },
    .{ .hex = "826161a161626163", .value = .{ .array = &arr_a_bc } },
    .{
        .hex = "a56161614161626142616361436164614461656145",
        .value = .{ .map = &[_]MapEntry{
            .{ .key = .{ .text = "a" }, .value = .{ .text = "A" } },
            .{ .key = .{ .text = "b" }, .value = .{ .text = "B" } },
            .{ .key = .{ .text = "c" }, .value = .{ .text = "C" } },
            .{ .key = .{ .text = "d" }, .value = .{ .text = "D" } },
            .{ .key = .{ .text = "e" }, .value = .{ .text = "E" } },
        } },
    },

    // ── indefinite-length forms (decode-only: this encoder always emits
    //    definite-length, so these don't reproduce their own bytes, but must
    //    decode to the identical logical value as their definite sibling
    //    above / a directly-stated value) ─────────────────────────────────
    .{ .hex = "5f42010243030405ff", .value = .{ .bytes = &[_]u8{ 1, 2, 3, 4, 5 } }, .roundtrip = false },
    .{ .hex = "7f657374726561646d696e67ff", .value = .{ .text = "streaming" }, .roundtrip = false },
    .{ .hex = "9fff", .value = .{ .array = &.{} }, .roundtrip = false },
    .{ .hex = "9f018202039f0405ffff", .value = .{ .array = &nested_arr }, .roundtrip = false },
    .{ .hex = "9f01820203820405ff", .value = .{ .array = &nested_arr }, .roundtrip = false },
    .{ .hex = "83018202039f0405ff", .value = .{ .array = &nested_arr }, .roundtrip = false },
    .{ .hex = "83019f0203ff820405", .value = .{ .array = &nested_arr }, .roundtrip = false },
    .{ .hex = "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff", .value = .{ .array = &arr_1_25 }, .roundtrip = false },
    .{ .hex = "bf61610161629f0203ffff", .value = .{ .map = &map_ab }, .roundtrip = false },
    .{ .hex = "826161bf61626163ff", .value = .{ .array = &arr_a_bc }, .roundtrip = false },
    .{ .hex = "bf6346756ef563416d7421ff", .value = .{ .map = &map_fun_amt }, .roundtrip = false },
};
