// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for vdf (added 2026-10-10, the jwt pattern).
//!
//! Driver: `VDF_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `vdf-verify`, `vdf-proof-codec`, `vdf-eval`.
//!
//!   - `vdf-verify`: a genuine (x, y, T, proof) triple (made once with this
//!     module's own `eval` / `prove`) is ACCEPTED; every damaged copy is
//!     REFUSED, never a panic: octets flipped in x, y or the proof, edge
//!     values (0, 1, N-1, N, N+1, 2^2048-1) put in their place, a wrong
//!     length, a different T.
//!   - `vdf-proof-codec`: `Proof.fromBytes` accepts exactly
//!     `group.modulus_bytes` octets and round-trips.
//!   - `vdf-eval`: `eval` equals the naive repeated squaring (canonicalised) on
//!     arbitrary elements and delays, and its output proves and verifies.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const vdf = @import("root.zig");
const group = vdf.group;
pub const fuzz_driver = testkit.fuzz.driver;

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

const Triple = struct {
    x: [group.modulus_bytes]u8,
    y: [group.modulus_bytes]u8,
    proof: vdf.Proof,
    t: u64,
};

const delays = [_]u64{ 1, 2, 5, 40, 300 };
var triples: [delays.len * 2]Triple = undefined;
var triples_built = false;

fn buildTriples() !void {
    if (triples_built) return;
    const m = group.rsa2048ChallengeModulus();
    for (delays, 0..) |t, i| {
        for (0..2) |k| {
            var x_bytes: [group.modulus_bytes]u8 = @splat(0);
            x_bytes[group.modulus_bytes - 1] = @intCast(3 + 2 * i + k);
            x_bytes[group.modulus_bytes - 40] = @intCast(1 + k * 77);
            const x = try group.elementFromBytes(m, &x_bytes);
            const y = vdf.eval(m, x, t);
            var y_bytes: [group.modulus_bytes]u8 = undefined;
            try group.toBytes(y, &y_bytes);
            const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);
            triples[i * 2 + k] = .{ .x = x_bytes, .y = y_bytes, .proof = proof, .t = t };
        }
    }
    triples_built = true;
}

const VerifyMark = Marker(enum { genuine_accepted, flipped_refused, edge_refused, length_refused, delay_refused, swapped_refused });

fn editBytes(comptime S: type, src: *S, buf: []u8) void {
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => { // a few flipped octets (at least one changes)
            for (0..src.valueRangeAtMost(u8, 1, 3)) |_| buf[src.index(buf.len)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        1 => { // the top octet(s), where the range check lives
            buf[src.index(4)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        2 => buf[buf.len - 1] ^= @as(u8, 1) << @as(u3, @intCast(src.index(8))),
        else => { // one octet far down
            buf[buf.len / 2 + src.index(buf.len / 2)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
    }
}

pub fn fuzzVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    try buildTriples();
    const m = group.rsa2048ChallengeModulus();
    const tr = triples[src.index(triples.len)];
    var x = tr.x;
    var y = tr.y;
    var pi = tr.proof;
    var t = tr.t;
    const which = src.valueRangeAtMost(u8, 0, 7);
    var x_slice: []const u8 = &x;
    var y_slice: []const u8 = &y;
    switch (which) {
        0 => {}, // intact
        1 => editBytes(S, src, &x),
        2 => editBytes(S, src, &y),
        3 => editBytes(S, src, &pi.pi),
        4 => { // an edge value in x, y or pi
            const target: *[group.modulus_bytes]u8 = switch (src.valueRangeAtMost(u8, 0, 2)) {
                0 => &x,
                1 => &y,
                else => &pi.pi,
            };
            var n_bytes: [group.modulus_bytes]u8 = undefined;
            try m.toBytes(&n_bytes, .big);
            switch (src.valueRangeAtMost(u8, 0, 5)) {
                0 => @memset(target, 0),
                1 => {
                    @memset(target, 0);
                    target[group.modulus_bytes - 1] = 1;
                },
                2 => { // N - 1
                    target.* = n_bytes;
                    target[group.modulus_bytes - 1] ^= 1;
                },
                3 => target.* = n_bytes,
                4 => { // N + 2 (N is odd), wraps only past 2^2048
                    target.* = n_bytes;
                    target[group.modulus_bytes - 1] +%= 2;
                },
                else => @memset(target, 0xff),
            }
            VerifyMark.mark(.edge_refused);
        },
        5 => { // wrong lengths for x / y
            const cut = src.index(group.modulus_bytes);
            if (src.value(bool)) x_slice = x[0..cut] else y_slice = y[0..cut];
            VerifyMark.mark(.length_refused);
        },
        6 => { // another delay
            t = tr.t +% (1 + src.index(5));
            VerifyMark.mark(.delay_refused);
        },
        else => { // a proof (or y) of another statement
            const other = triples[src.index(triples.len)];
            if (std.mem.eql(u8, &other.y, &tr.y) and std.mem.eql(u8, &other.proof.pi, &tr.proof.pi)) {
                // same triple: nothing swapped, treat as intact
            } else {
                if (src.value(bool)) pi = other.proof else y = other.y;
                VerifyMark.mark(.swapped_refused);
            }
        },
    }
    const changed = !(std.mem.eql(u8, &x, &tr.x) and std.mem.eql(u8, &y, &tr.y) and std.mem.eql(u8, &pi.pi, &tr.proof.pi) and t == tr.t and x_slice.len == x.len and y_slice.len == y.len);
    const ok = vdf.verify(m, x_slice, y_slice, pi, t) catch false;
    if (!changed) {
        if (!ok) return error.GenuineProofRefused;
        VerifyMark.mark(.genuine_accepted);
    } else {
        if (ok) return error.DamagedProofAccepted;
        if (which >= 1 and which <= 3) VerifyMark.mark(.flipped_refused);
    }
}

const CodecMark = Marker(enum { accepted, refused });

pub fn fuzzProofCodec(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [group.modulus_bytes + 8]u8 = undefined;
    const n: usize = if (S == fuzz_driver.Rng and src.valueRangeAtMost(u8, 0, 3) != 0)
        group.modulus_bytes - 1 + @as(usize, src.valueRangeAtMost(u8, 0, 2))
    else
        src.slice(&buf);
    if (S == fuzz_driver.Rng) src.bytes(buf[0..n]);
    const p = vdf.Proof.fromBytes(buf[0..n]) catch |e| {
        if (n == group.modulus_bytes) return error.RightLengthRefused;
        if (e != error.WrongLength) return error.UnexpectedError;
        CodecMark.mark(.refused);
        return;
    };
    if (n != group.modulus_bytes) return error.WrongLengthAccepted;
    var out: [group.modulus_bytes]u8 = undefined;
    try p.toBytes(&out);
    if (!std.mem.eql(u8, &out, buf[0..n])) return error.CodecRoundTrip;
    CodecMark.mark(.accepted);
}

const EvalMark = Marker(enum { evaluated, refused_element, proved });

pub fn fuzzEval(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const m = group.rsa2048ChallengeModulus();
    var x_bytes: [group.modulus_bytes]u8 = @splat(0);
    // mostly short elements (always < N), sometimes full-width random ones
    const used: usize = if (src.valueRangeAtMost(u8, 0, 3) == 0) x_bytes.len else 1 + src.index(40);
    src.bytes(x_bytes[x_bytes.len - used ..]);
    const x = group.elementFromBytes(m, &x_bytes) catch {
        EvalMark.mark(.refused_element);
        return;
    };
    const t: u64 = src.valueRangeAtMost(u8, 0, 40);
    const y = vdf.eval(m, x, t);
    var naive = x;
    for (0..t) |_| naive = group.square(m, naive);
    if (!group.canonicalize(m, naive).eql(y)) return error.EvalDiffersFromNaive;
    EvalMark.mark(.evaluated);
    var y_bytes: [group.modulus_bytes]u8 = undefined;
    try group.toBytes(y, &y_bytes);
    // x in {1, N-1} is the identity class: refused by design
    const proof = vdf.prove(m, &x_bytes, &y_bytes, t) catch return;
    if (!(vdf.verify(m, &x_bytes, &y_bytes, proof, t) catch false)) {
        if (group.isIdentityClass(m, x)) return;
        return error.OwnProofRefused;
    }
    EvalMark.mark(.proved);
}

test "fuzz driver: VDF_FUZZ (verify)" {
    try fuzz_driver.run(fuzzVerify, .{ .prefix = "VDF_FUZZ", .name = "vdf-verify", .scale = 20 });
}
test "fuzz driver: VDF_FUZZ (proof codec)" {
    try fuzz_driver.run(fuzzProofCodec, .{ .prefix = "VDF_FUZZ", .name = "vdf-proof-codec" });
}
test "fuzz driver: VDF_FUZZ (eval)" {
    try fuzz_driver.run(fuzzEval, .{ .prefix = "VDF_FUZZ", .name = "vdf-eval", .scale = 50 });
}

test "fuzz harness: verify, 400 seeds, reaches every outcome" {
    try VerifyMark.reach(fuzzVerify, "vdf-verify", 400);
}
test "fuzz harness: proof codec, 200 seeds, reaches every outcome" {
    try CodecMark.reach(fuzzProofCodec, "vdf-proof-codec", 200);
}
test "fuzz harness: eval, 300 seeds, reaches every outcome" {
    try EvalMark.reach(fuzzEval, "vdf-eval", 300);
}

fn smithVerify(_: void, smith: *std.testing.Smith) !void {
    try fuzzVerify(std.testing.Smith, smith, testing.allocator);
}
test "fuzz: a genuine proof is accepted and a damaged one refused" {
    try testing.fuzz({}, smithVerify, .{});
}
