// SPDX-License-Identifier: MIT

//! Shared plumbing for falcon's deterministic fuzz driver (added 2026-10-09).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `FALCON_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `falcon-{512,1024}-{verify,open,pubkey,seckey}`.

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

// ── the harnesses (Falcon-512 and Falcon-1024, same bodies) ─────────────────

const falcon = @import("root.zig");
const v = @import("kat_vectors.zig");

/// The vector-0 fixtures of a variant, decoded once for the process.
fn Fixture(comptime big: bool) type {
    return struct {
        var cached: ?struct { msg: []u8, pk: []u8, sk: []u8, sm: []u8 } = null;

        fn get() @TypeOf(cached.?) {
            if (cached) |c| return c;
            const vec = if (big) v.falcon1024[0] else v.falcon512[0];
            const a = std.heap.page_allocator; // global-alloc-ok: process-lifetime fuzz/test fixture cached across driver runs, outlives testing.allocator's per-test teardown
            const hex = struct {
                fn f(h: []const u8) []u8 {
                    const out = a.alloc(u8, h.len / 2) catch unreachable;
                    _ = std.fmt.hexToBytes(out, h) catch unreachable;
                    return out;
                }
            }.f;
            cached = .{ .msg = hex(vec.msg), .pk = hex(vec.pk), .sk = hex(vec.sk), .sm = hex(vec.sm) };
            return cached.?;
        }
    };
}

/// One input into `buf`; returns its length. The driver's `Rng`: half the
/// draws are the real encoding with 0-3 octets damaged and maybe truncated,
/// then a share of wild bytes behind the real first octet (the header check
/// is the first thing any of these decoders does), then plain `slice`. Under
/// `Smith` it is exactly `src.slice`.
fn draw(comptime S: type, src: *S, buf: []u8, real: []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    switch (src.index(4)) {
        0, 1 => return damage(src, buf, real),
        2 => {
            const n = src.index(buf.len + 1);
            src.bytes(buf[0..n]);
            if (n != 0) buf[0] = real[0];
            return n;
        },
        else => return src.slice(buf),
    }
}

fn Harness(comptime big: bool) type {
    return struct {
        const PK = if (big) falcon.PublicKey1024 else falcon.PublicKey;
        const SK = if (big) falcon.SecretKey1024 else falcon.SecretKey;
        const sig_cap = if (big) falcon.max_sig_field_length_1024 else falcon.max_sig_field_length;
        const sig_header = if (big) falcon.sig_header_1024 else falcon.sig_header;
        const Fx = Fixture(big);
        fn open(pk: *const PK, sm: []const u8) ![]const u8 {
            return if (big) falcon.openNistSignedMessage1024(pk, sm) else falcon.openNistSignedMessage(pk, sm);
        }

        const VerifyMark = Marker(enum { genuine_accepted, damaged_refused, wild_refused, msg_flip_refused, nonce_flip_refused });
        const OpenMark = Marker(enum { genuine_accepted, damaged_refused });
        const PubMark = Marker(enum { accepted, refused });
        const SecMark = Marker(enum { accepted, refused, genuine_matches_pk, derived_ok, derived_refused });

        /// `verify` over a damaged signature field: the genuine one is accepted,
        /// every other octet string refused; one flipped message octet or nonce
        /// octet under the genuine field is refused too.
        pub fn verify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
            const f = Fx.get();
            const pk = PK.fromBytes(f.pk[0..PK.encoded_length]) catch return error.GenuineKeyRefused;
            const sig_len = (@as(usize, f.sm[0]) << 8) | f.sm[1];
            const nonce: *const [falcon.nonce_length]u8 = f.sm[2..][0..falcon.nonce_length];
            const msg = f.sm[2 + falcon.nonce_length .. f.sm.len - sig_len];
            const real = f.sm[f.sm.len - sig_len ..];

            var buf: [sig_cap]u8 = undefined;
            const n = draw(S, src, &buf, real);
            const pristine = std.mem.eql(u8, buf[0..n], real);
            if (pk.verify(msg, nonce, buf[0..n])) |_| {
                if (!pristine) return error.DamagedSignatureVerified;
                VerifyMark.mark(.genuine_accepted);
            } else |_| {
                if (pristine) return error.GenuineSignatureRefused;
                VerifyMark.mark(.damaged_refused);
                if (n == 0 or buf[0] == sig_header) VerifyMark.mark(.wild_refused);
            }
            if (!pristine) return;
            // One flipped octet of the message, one of the nonce.
            if (msg.len != 0) {
                var m2: [64]u8 = undefined;
                const ml = @min(msg.len, m2.len);
                @memcpy(m2[0..ml], msg[0..ml]);
                m2[src.index(ml)] ^= src.valueRangeAtMost(u8, 1, 255);
                if (pk.verify(m2[0..ml], nonce, real)) |_| {
                    // Only a wrong answer when the copy differs from the signed message.
                    if (ml == msg.len) return error.FlippedMessageVerified;
                } else |_| VerifyMark.mark(.msg_flip_refused);
            }
            var n2 = nonce.*;
            n2[src.index(n2.len)] ^= src.valueRangeAtMost(u8, 1, 255);
            if (pk.verify(msg, &n2, real)) |_| return error.FlippedNonceVerified else |_| VerifyMark.mark(.nonce_flip_refused);
        }

        /// `openNistSignedMessage` over a damaged signed-message envelope.
        pub fn openSm(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
            const f = Fx.get();
            const pk = PK.fromBytes(f.pk[0..PK.encoded_length]) catch return error.GenuineKeyRefused;
            var buf: [4096]u8 = undefined;
            const n = draw(S, src, &buf, f.sm);
            const pristine = std.mem.eql(u8, buf[0..n], f.sm);
            if (open(&pk, buf[0..n])) |got| {
                if (!pristine) return error.DamagedEnvelopeOpened;
                if (!std.mem.eql(u8, got, f.msg)) return error.GenuineEnvelopeChanged;
                OpenMark.mark(.genuine_accepted);
            } else |_| {
                if (pristine) return error.GenuineEnvelopeRefused;
                OpenMark.mark(.damaged_refused);
            }
        }

        /// `PublicKey.fromBytes`: what decodes re-encodes to the same octets.
        pub fn pubkey(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
            const f = Fx.get();
            var buf: [PK.encoded_length]u8 = undefined;
            var raw: [PK.encoded_length]u8 = undefined;
            const n = draw(S, src, &raw, f.pk);
            @memset(&buf, 0);
            @memcpy(buf[0..n], raw[0..n]);
            const pk = PK.fromBytes(&buf) catch {
                PubMark.mark(.refused);
                return;
            };
            PubMark.mark(.accepted);
            if (!std.mem.eql(u8, &pk.toBytes(), &buf)) return error.NonCanonicalPublicKeyAccepted;
        }

        /// `SecretKey.fromBytes` and, when it decodes, `publicKey()`: never a
        /// panic; the pristine key reproduces the public key.
        pub fn seckey(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
            const f = Fx.get();
            var buf: [SK.encoded_length]u8 = undefined;
            var raw: [SK.encoded_length]u8 = undefined;
            const n = draw(S, src, &raw, f.sk);
            @memset(&buf, 0);
            @memcpy(buf[0..n], raw[0..n]);
            const pristine = std.mem.eql(u8, &buf, f.sk);
            var sk: SK = undefined;
            SK.fromBytes(&sk, &buf) catch {
                if (pristine) return error.GenuineSecretKeyRefused;
                SecMark.mark(.refused);
                return;
            };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
            SecMark.mark(.accepted);
            if (sk.publicKey()) |pk| {
                SecMark.mark(.derived_ok);
                if (pristine) {
                    if (!std.mem.eql(u8, &pk.toBytes(), f.pk)) return error.GenuinePublicKeyMismatch;
                    SecMark.mark(.genuine_matches_pk);
                }
            } else |_| {
                if (pristine) return error.GenuineSecretKeyNoPublicKey;
                SecMark.mark(.derived_refused);
            }
        }
    };
}

const H512 = Harness(false);
const H1024 = Harness(true);

fn smithOf(comptime f: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try f(std.testing.Smith, smith, testing.allocator);
        }
    }.run;
}

test "fuzz: falcon decoders and verify never panic (Smith replay)" {
    try testing.fuzz({}, smithOf(H512.verify), .{});
    try testing.fuzz({}, smithOf(H512.openSm), .{});
    try testing.fuzz({}, smithOf(H512.pubkey), .{});
    try testing.fuzz({}, smithOf(H512.seckey), .{});
    try testing.fuzz({}, smithOf(H1024.verify), .{});
    try testing.fuzz({}, smithOf(H1024.openSm), .{});
    try testing.fuzz({}, smithOf(H1024.pubkey), .{});
    try testing.fuzz({}, smithOf(H1024.seckey), .{});
}

test "fuzz driver: FALCON_FUZZ (512 verify)" {
    try fuzz_driver.run(H512.verify, .{ .prefix = "FALCON_FUZZ", .name = "falcon-512-verify" });
}
test "fuzz driver: FALCON_FUZZ (512 open)" {
    try fuzz_driver.run(H512.openSm, .{ .prefix = "FALCON_FUZZ", .name = "falcon-512-open" });
}
test "fuzz driver: FALCON_FUZZ (512 pubkey)" {
    try fuzz_driver.run(H512.pubkey, .{ .prefix = "FALCON_FUZZ", .name = "falcon-512-pubkey" });
}
test "fuzz driver: FALCON_FUZZ (512 seckey)" {
    try fuzz_driver.run(H512.seckey, .{ .prefix = "FALCON_FUZZ", .name = "falcon-512-seckey" });
}
test "fuzz driver: FALCON_FUZZ (1024 verify)" {
    try fuzz_driver.run(H1024.verify, .{ .prefix = "FALCON_FUZZ", .name = "falcon-1024-verify" });
}
test "fuzz driver: FALCON_FUZZ (1024 open)" {
    try fuzz_driver.run(H1024.openSm, .{ .prefix = "FALCON_FUZZ", .name = "falcon-1024-open" });
}
test "fuzz driver: FALCON_FUZZ (1024 pubkey)" {
    try fuzz_driver.run(H1024.pubkey, .{ .prefix = "FALCON_FUZZ", .name = "falcon-1024-pubkey" });
}
test "fuzz driver: FALCON_FUZZ (1024 seckey)" {
    try fuzz_driver.run(H1024.seckey, .{ .prefix = "FALCON_FUZZ", .name = "falcon-1024-seckey" });
}

test "fuzz harness: falcon, 300 seeds each, reaches every outcome" {
    try H512.VerifyMark.reach(H512.verify, "falcon-512-verify", 300);
    try H512.OpenMark.reach(H512.openSm, "falcon-512-open", 300);
    try H512.PubMark.reach(H512.pubkey, "falcon-512-pubkey", 300);
    try H512.SecMark.reach(H512.seckey, "falcon-512-seckey", 300);
    try H1024.VerifyMark.reach(H1024.verify, "falcon-1024-verify", 300);
    try H1024.OpenMark.reach(H1024.openSm, "falcon-1024-open", 300);
    try H1024.PubMark.reach(H1024.pubkey, "falcon-1024-pubkey", 300);
    try H1024.SecMark.reach(H1024.seckey, "falcon-1024-seckey", 300);
}
