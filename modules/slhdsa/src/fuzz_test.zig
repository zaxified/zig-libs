// SPDX-License-Identifier: MIT

//! Shared plumbing for slhdsa's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `SLHDSA_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `slhdsa-sha2-128f-verify`,
//! `slhdsa-shake-128f-verify`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
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

// ── verify, per parameter set ───────────────────────────────────────────────

const engine = @import("engine.zig");
const params = @import("params.zig");

/// A signature this module issued VERIFIES; every damaged signature (0-3
/// octets of the real one damaged, maybe truncated or extended, or wild
/// bytes) does NOT; the genuine signature under another message or another
/// context does NOT.
fn Verify(comptime P: params.Params) type {
    return struct {
        const Scheme = engine.SlhDsa(P);
        const Mark = Marker(enum { genuine_accepted, damaged_refused, wrong_length, wrong_message_refused, wrong_context_refused, long_context_refused });
        const message = "fuzz msg";

        var cached: ?struct { pk: Scheme.PublicKey, sig: [Scheme.signature_length]u8 } = null;

        fn fixture() @TypeOf(cached.?) {
            if (cached) |c| return c;
            var kp: Scheme.KeyPair = undefined;
            const a: [Scheme.n]u8 = @splat(1);
            const b: [Scheme.n]u8 = @splat(2);
            const c: [Scheme.n]u8 = @splat(3);
            Scheme.keyGenFromSeed(&kp, &a, &b, &c);
            var sig: [Scheme.signature_length]u8 = undefined;
            Scheme.sign(&sig, message, &kp.sk, "", null) catch unreachable;
            cached = .{ .pk = kp.pk, .sig = sig };
            return cached.?;
        }

        pub fn run(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
            const f = fixture();
            // The buffer is a little over one signature: both the length guard
            // and the structural parse are reached.
            var buf: [Scheme.signature_length + 32]u8 = undefined;
            var n: usize = undefined;
            if (S == fuzz_driver.Rng) {
                switch (src.index(5)) {
                    0, 1, 2 => n = damage(src, &buf, &f.sig),
                    3 => {
                        // Extend by a few octets.
                        @memcpy(buf[0..f.sig.len], &f.sig);
                        n = f.sig.len + src.index(33);
                        src.bytes(buf[f.sig.len..n]);
                    },
                    else => {
                        const cap: usize = if (src.value(bool)) 64 else buf.len;
                        n = src.index(cap + 1);
                        src.bytes(buf[0..n]);
                    },
                }
            } else n = src.slice(&buf);
            if (n != f.sig.len) Mark.mark(.wrong_length);
            const pristine = std.mem.eql(u8, buf[0..n], &f.sig);
            const ok = Scheme.verify(buf[0..n], message, f.pk, "");
            if (ok) {
                if (!pristine) return error.DamagedSignatureVerified;
                Mark.mark(.genuine_accepted);
            } else {
                if (pristine) return error.GenuineSignatureRefused;
                Mark.mark(.damaged_refused);
            }
            if (!pristine) return;
            // The genuine signature under another message / another context.
            var m2: [message.len + 1]u8 = undefined;
            @memcpy(m2[0..message.len], message);
            m2[message.len] = src.value(u8);
            if (Scheme.verify(&f.sig, &m2, f.pk, "")) return error.OtherMessageVerified;
            Mark.mark(.wrong_message_refused);
            var ctx: [256]u8 = undefined;
            src.bytes(&ctx);
            const cl = src.index(256);
            if (Scheme.verify(&f.sig, message, f.pk, ctx[0..cl]) and cl != 0) return error.OtherContextVerified;
            if (cl != 0) Mark.mark(.wrong_context_refused);
            if (Scheme.verify(&f.sig, message, f.pk, &ctx ++ "x".*)) return error.LongContextVerified;
            Mark.mark(.long_context_refused);
        }
    };
}

const Sha2 = Verify(params.sha2_128f);
const Shake = Verify(params.shake_128f);

fn smithRun(comptime f: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try f(std.testing.Smith, smith, testing.allocator);
        }
    }.run;
}

test "fuzz: slhdsa verify never panics (Smith replay)" {
    try testing.fuzz({}, smithRun(Sha2.run), .{});
    try testing.fuzz({}, smithRun(Shake.run), .{});
}

test "fuzz driver: SLHDSA_FUZZ (SHA2-128f verify)" {
    // `.scale`: a run is up to five full verifications of a 17 KiB signature.
    try fuzz_driver.run(Sha2.run, .{ .prefix = "SLHDSA_FUZZ", .name = "slhdsa-sha2-128f-verify", .scale = 10 });
}

test "fuzz driver: SLHDSA_FUZZ (SHAKE-128f verify)" {
    try fuzz_driver.run(Shake.run, .{ .prefix = "SLHDSA_FUZZ", .name = "slhdsa-shake-128f-verify", .scale = 10 });
}

test "fuzz harness: slhdsa verify, 60 seeds each, reaches every outcome" {
    try Sha2.Mark.reach(Sha2.run, "slhdsa-sha2-128f-verify", 60);
    try Shake.Mark.reach(Shake.run, "slhdsa-shake-128f-verify", 60);
}
