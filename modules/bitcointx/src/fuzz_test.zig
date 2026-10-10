// SPDX-License-Identifier: MIT

//! Shared plumbing for bitcointx's deterministic fuzz driver (added
//! 2026-10-10).
//!
//! The two harness bodies (`fuzzDeserializePartial` in `tx.zig`,
//! `fuzzSighash` in `root.zig`) stay beside their corpora, generic over their
//! source of choices, `fn(comptime S, *S, gpa)`; `testing.fuzz` hands them a
//! `std.testing.Smith` (corpus seeds replay as before). This file holds what
//! they share with the driver -- reach counters and the transaction draw --
//! and a third oracle: a transaction the decoder accepted re-serializes to
//! something that decodes again and re-serializes to the same octets, and the
//! module's own reference transactions come back byte-identical.
//!
//! Driver: `BITCOINTX_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_ONLY` selects a harness). Harness names: `bitcointx-deserialize`,
//! `bitcointx-sighash`, `bitcointx-roundtrip`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const tx = @import("tx.zig");

/// One transaction input into `buf`; returns its length. Under `Smith`
/// (`--fuzz`, `_INPUT` replay) it is exactly `src.slice`. Under the driver's
/// `Rng` half the draws are a reference transaction (legacy or BIP144 segwit)
/// with 0-3 octets damaged and maybe truncated, or fresh octets: random bytes
/// almost never survive the CompactSize counts.
pub fn drawTx(comptime S: type, src: *S, buf: []u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (!src.value(bool)) return src.slice(buf);
    const frame: []const u8 = if (src.value(bool)) &tx.fuzz_kat_legacy else &tx.fuzz_kat_segwit;
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── oracle ───────────────────────────────────────────────────────────────

const Mark = Marker(enum { genuine_exact, damaged_accepted, damaged_refused, segwit, idempotent });

/// A reference transaction round-trips byte-identically; whatever else the
/// decoder accepts (full-buffer) must re-serialize to octets that decode again
/// and re-serialize to the same octets.
fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [tx.fuzz_tx_buf_len]u8 = undefined;
    const genuine = src.valueRangeAtMost(u8, 0, 3) == 0;
    const segwit_kat = src.value(bool);
    const len: usize = if (genuine) blk: {
        const k: []const u8 = if (segwit_kat) &tx.fuzz_kat_segwit else &tx.fuzz_kat_legacy;
        @memcpy(buf[0..k.len], k);
        break :blk k.len;
    } else drawTx(S, src, &buf);

    var t = tx.deserialize(gpa, buf[0..len]) catch {
        if (genuine) return error.GenuineTransactionRefused;
        Mark.mark(.damaged_refused);
        return;
    };
    defer t.deinit(gpa);
    if (t.has_witness) Mark.mark(.segwit);
    const s1 = try tx.serialize(gpa, t);
    defer gpa.free(s1);
    if (genuine) {
        if (!std.mem.eql(u8, s1, buf[0..len])) return error.GenuineNotByteIdentical;
        Mark.mark(.genuine_exact);
        return;
    }
    Mark.mark(.damaged_accepted);
    var t2 = tx.deserialize(gpa, s1) catch return error.ReserializedRefused;
    defer t2.deinit(gpa);
    const s2 = try tx.serialize(gpa, t2);
    defer gpa.free(s2);
    if (!std.mem.eql(u8, s1, s2)) return error.ReserializationNotIdempotent;
    Mark.mark(.idempotent);
}

test "fuzz driver: BITCOINTX_FUZZ (roundtrip)" {
    try fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "BITCOINTX_FUZZ", .name = "bitcointx-roundtrip" });
}

test "fuzz harness: roundtrip, 600 seeds, reaches every outcome" {
    try Mark.reach(fuzzRoundtrip, "bitcointx-roundtrip", 600);
}

fn roundtripSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzRoundtrip(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: roundtrip, exploration" {
    try testing.fuzz({}, roundtripSmith, .{});
}
