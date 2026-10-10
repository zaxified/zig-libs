// SPDX-License-Identifier: MIT

//! fuzz_test — the byte-accepting entry points (`codec.zig`'s readers) on
//! damaged input.
//!
//!     TFHE_FUZZ=<runs>[,<first seed>]  (testkit's driver: _MS, _SEEDFILE, …)
//!
//! Each input starts from a VALID encoding of one of the six kinds (made once,
//! from fixed seeds) and is then: kept intact, given a random payload under a
//! valid header, damaged at a few bytes (half of them aimed at the 24-byte
//! header, where every field is checked), truncated, or replaced with random
//! bytes. The oracle: no reader panics or leaks; whatever a reader accepts
//! re-encodes to exactly the bytes it read (the format has one encoding per
//! value); an intact encoding and any payload under a valid header are
//! accepted, except a client key whose words are not all bits. The reach line
//! counts how each input ended.

const std = @import("std");
const testing = std.testing;
const tfhe = @import("tfhe.zig");
const codec = @import("codec.zig");
const fuzz_driver = @import("testkit").fuzz.driver;

const F = tfhe.Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 6,
    .lwe_noise = .{ .uniform = 1 << 8 },
    .glwe_noise = .{ .uniform = 1 << 6 },
});
const C = F.Codec;
const kinds = [_]codec.Kind{ .lwe, .lwe_big, .client_key, .bootstrap_key, .key_switch_key, .server_key };
const max_len = C.encodedLen(.server_key) + 16;

/// One valid encoding per kind, made on first use and kept for the process
/// (the driver runs thousands of inputs per process; rebuilding the keys per
/// input would be the whole cost).
var bases: ?[kinds.len][]u8 = null;
var scratch: [max_len]u8 = undefined;

fn makeBases() ![kinds.len][]u8 {
    const pa = std.heap.page_allocator; // global-alloc-ok: process-lifetime fixtures of a test-only harness
    var prng = std.Random.DefaultPrng.init(0xF022);
    const rnd = prng.random();
    const lwe = F.lweKeyGenForTest(16, rnd);
    const glwe = F.glweKeyGenForTest(rnd);
    var bsk = try F.bootstrapKeyGenForTest(pa, &lwe, &glwe, rnd);
    defer bsk.deinit(pa);
    const ksk = try F.keySwitchKeyGenForTest(pa, &glwe, &lwe, rnd);
    var sk = try F.ServerKey.fromKeys(pa, &bsk, ksk);
    defer sk.deinit(pa);
    const ck: F.ClientKey = .{ .lwe = lwe, .glwe = glwe };
    const ct = ck.encrypt(true, std.testing.io);
    var big: F.LweBig = undefined;
    for (&big.a) |*x| x.* = rnd.int(u32);
    big.b = rnd.int(u32);

    var out: [kinds.len][]u8 = undefined;
    for (kinds, 0..) |kind, i| {
        var aw: std.Io.Writer.Allocating = .init(pa);
        switch (kind) {
            .lwe => try C.writeLwe(&aw.writer, &ct),
            .lwe_big => try C.writeLweBig(&aw.writer, &big),
            .client_key => try C.writeClientKey(&aw.writer, &ck),
            .bootstrap_key => try C.writeBootstrapKey(&aw.writer, &bsk),
            .key_switch_key => try C.writeKeySwitchKey(&aw.writer, &sk.ksk),
            .server_key => try C.writeServerKey(&aw.writer, &sk),
        }
        out[i] = try aw.toOwnedSlice();
        std.debug.assert(out[i].len == C.encodedLen(kind));
    }
    return out;
}

/// Decode `in` as `kind`; on success re-encode and require the same bytes.
fn decodeRoundTrip(kind: codec.Kind, in: []const u8, gpa: std.mem.Allocator) !bool {
    var r: std.Io.Reader = .fixed(in);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const ok = switch (kind) {
        .lwe => if (C.readLwe(&r)) |v| blk: {
            try C.writeLwe(&aw.writer, &v);
            break :blk true;
        } else |e| classify(e),
        .lwe_big => if (C.readLweBig(&r)) |v| blk: {
            try C.writeLweBig(&aw.writer, &v);
            break :blk true;
        } else |e| classify(e),
        .client_key => if (C.readClientKey(&r)) |v| blk: {
            var ck = v;
            defer ck.deinit();
            try C.writeClientKey(&aw.writer, &ck);
            break :blk true;
        } else |e| classify(e),
        .bootstrap_key => if (C.readBootstrapKey(gpa, &r)) |v| blk: {
            var bsk = v;
            defer bsk.deinit(gpa);
            try C.writeBootstrapKey(&aw.writer, &bsk);
            break :blk true;
        } else |e| classify(e),
        .key_switch_key => if (C.readKeySwitchKey(gpa, &r)) |v| blk: {
            var ksk = v;
            defer ksk.deinit(gpa);
            try C.writeKeySwitchKey(&aw.writer, &ksk);
            break :blk true;
        } else |e| classify(e),
        .server_key => if (C.readServerKey(gpa, &r)) |v| blk: {
            var sk = v;
            defer sk.deinit(gpa);
            try C.writeServerKey(&aw.writer, &sk);
            break :blk true;
        } else |e| classify(e),
    };
    if (ok) {
        fuzz_driver.hit("accepted");
        if (!std.mem.eql(u8, aw.written(), in[0..C.encodedLen(kind)])) return error.NotCanonical;
    }
    return ok;
}

fn classify(e: anyerror) bool {
    switch (e) {
        error.BadMagic => fuzz_driver.hit("bad_magic"),
        error.UnsupportedVersion => fuzz_driver.hit("bad_version"),
        error.WrongKind => fuzz_driver.hit("wrong_kind"),
        error.ParameterMismatch => fuzz_driver.hit("parameter_mismatch"),
        error.InvalidKey => fuzz_driver.hit("invalid_key"),
        error.EndOfStream => fuzz_driver.hit("truncated"),
        else => fuzz_driver.hit("other_error"),
    }
    return false;
}

var reached: struct { accepted: [kinds.len]usize = @splat(0), refused: [kinds.len]usize = @splat(0) } = .{};

fn codecHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    if (bases == null) bases = try makeBases();
    const ki = src.index(kinds.len);
    const kind = kinds[ki];
    const base = bases.?[ki];
    var len = base.len;
    @memcpy(scratch[0..len], base);
    const mode = src.valueRangeAtMost(u8, 0, 4);
    switch (mode) {
        0 => {}, // intact
        1 => src.bytes(scratch[codec.header_len..len]), // valid header, any payload
        2 => { // a few damaged bytes, half aimed at the header
            const flips = src.valueRangeAtMost(u8, 1, 8);
            for (0..flips) |_| {
                const at = if (src.value(bool)) src.index(codec.header_len) else src.index(len);
                scratch[at] ^= src.valueRangeAtMost(u8, 1, 255);
            }
        },
        3 => len = src.index(len), // truncated
        else => { // random bytes of a random length
            len = src.index(@min(len + 9, max_len));
            src.bytes(scratch[0..len]);
        },
    }
    const ok = try decodeRoundTrip(kind, scratch[0..len], gpa);
    if (ok) reached.accepted[ki] += 1 else reached.refused[ki] += 1;
    if (mode == 0 and !ok) return error.IntactRefused;
    if (mode == 1 and !ok and kind != .client_key) return error.ValidHeaderRefused;
}

test "fuzz driver: codec readers on damaged encodings (TFHE_FUZZ)" {
    try fuzz_driver.run(codecHarness, .{ .prefix = "TFHE_FUZZ", .name = "codec" });
}

test "fuzz driver reach: every kind is both accepted and refused within 400 seeds" {
    reached = .{};
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try codecHarness(fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (kinds, 0..) |kind, i| {
        if (reached.accepted[i] == 0 or reached.refused[i] == 0) {
            std.debug.print("reach: kind {t} accepted={d} refused={d}\n", .{ kind, reached.accepted[i], reached.refused[i] });
            return error.HarnessDoesNotReach;
        }
    }
}

test "fuzz: codec readers on damaged encodings (coverage-guided exploration)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) !void {
            try codecHarness(std.testing.Smith, smith, testing.allocator);
        }
    }.one, .{});
}
