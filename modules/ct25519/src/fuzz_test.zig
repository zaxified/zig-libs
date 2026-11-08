// SPDX-License-Identifier: MIT

//! The deterministic fuzz harness (testkit's driver) over ct25519's
//! byte-accepting entry points, judged by std as an independent oracle:
//!
//!   * `verifyEd25519Strict(sig, msg, pk)` must give the SAME accept/reject and
//!     the SAME error as `std.crypto.sign.Ed25519.Signature.verifyStrict` for
//!     every input. Shapes: valid signatures from std, then one-bit flips in
//!     sig / key / message, S + L (non-canonical S), small-order and
//!     non-canonical R / A, mixed-order points (A + torsion, R + torsion), both
//!     degenerate, wholly random signature bytes and random key bytes;
//!   * `X25519.scalarmult(sk, pk)` and `recoverPublicKey(sk)` against std's
//!     X25519 for random and low-order u-coordinates (same result, same error).
//!
//! Driver: `CT25519_FUZZ=<runs>[,<first seed>]` (`_ONLY`, `_MS`, `_SEEDFILE`,
//! `_INPUT` per testkit's `fuzz_driver.zig`), harness `ct25519-ed25519-x25519`.
//! Without the variable the driver test skips; the in-suite reach test runs
//! 300 seeds every time.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const root = @import("root.zig");

const Ed = std.crypto.sign.Ed25519;
const Edwards25519 = root.Edwards25519;
const StdX = std.crypto.dh.X25519;

const Label = enum {
    valid,
    flip_sig,
    flip_key,
    flip_msg,
    s_plus_l,
    small_order_r,
    small_order_a,
    both_degenerate,
    torsion_a,
    torsion_r,
    random_sig,
    random_key,
    accepted,
    err_noncanonical,
    err_encoding,
    err_identity,
    err_weak,
    err_signature,
    x25519_ok,
    x25519_low_order,
    x25519_recover,
};
var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

// Low-order and non-canonical encodings (also valid u-coordinates for X25519).
const hex32 = testkit.hex.literal;
const low_order = [_][32]u8{
    hex32("0100000000000000000000000000000000000000000000000000000000000000"), // identity
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // (0,-1)
    hex32("0000000000000000000000000000000000000000000000000000000000000000"), // order 4
    hex32("0000000000000000000000000000000000000000000000000000000000000080"),
    hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), // order 8
    hex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p
    hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p + 1
    hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    hex32("0100000000000000000000000000000000000000000000000000000000000080"), // identity, sign set
};

fn flipBit(src: anytype, buf: []u8) void {
    buf[src.index(buf.len)] ^= @as(u8, 1) << @intCast(src.index(8));
}

fn pickLow(src: anytype) [32]u8 {
    return low_order[src.index(low_order.len)];
}

fn pickTorsion(src: anytype) ?Edwards25519 {
    return Edwards25519.fromBytes(low_order[4 + src.index(4)]) catch null;
}

fn markError(e: anyerror) void {
    switch (e) {
        error.NonCanonical => mark(.err_noncanonical),
        error.InvalidEncoding => mark(.err_encoding),
        error.IdentityElement => mark(.err_identity),
        error.WeakPublicKey => mark(.err_weak),
        error.SignatureVerificationFailed => mark(.err_signature),
        else => {},
    }
}

fn sameVerdict(sig: [64]u8, msg: []const u8, pk: [32]u8) !void {
    // Built directly: `PublicKey.fromBytes` would add a canonicity check that
    // `verifyStrict` itself does not make (A's y may exceed p).
    const want: anyerror!void = Ed.Signature.fromBytes(sig).verifyStrict(msg, .{ .bytes = pk });
    const got: anyerror!void = root.verifyEd25519Strict(sig, msg, pk);
    if (want) |_| {
        got catch |e| {
            std.debug.print("std accepts, ours: {t}\n", .{e});
            return error.TestUnexpectedResult;
        };
        mark(.accepted);
    } else |we| {
        if (got) |_| {
            std.debug.print("std rejects ({t}), ours accepts\n", .{we});
            return error.TestUnexpectedResult;
        } else |ge| {
            if (ge != we) {
                std.debug.print("std: {t}, ours: {t}\n", .{ we, ge });
                return error.TestUnexpectedResult;
            }
        }
        markError(we);
    }
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var seed: [32]u8 = undefined;
    src.bytes(&seed);
    var msg_buf: [96]u8 = undefined;
    const msg_len = src.slice(&msg_buf);
    const m = msg_buf[0..msg_len];

    const kp = try Ed.KeyPair.generateDeterministic(seed);
    var sig = (try kp.sign(m, null)).toBytes();
    var pk = kp.public_key.bytes;
    var mm: []const u8 = m;
    var msg2: [96]u8 = undefined;

    switch (src.index(13)) {
        0, 1 => mark(.valid),
        2 => {
            flipBit(src, &sig);
            mark(.flip_sig);
        },
        3 => {
            flipBit(src, &pk);
            mark(.flip_key);
        },
        4 => {
            @memcpy(msg2[0..m.len], m);
            if (m.len > 0) flipBit(src, msg2[0..m.len]) else msg2[0] = 1;
            mm = msg2[0..@max(m.len, 1)];
            mark(.flip_msg);
        },
        5 => { // S + L: non-canonical, same scalar mod L
            const s: u256 = std.mem.readInt(u256, sig[32..64], .little);
            std.mem.writeInt(u256, sig[32..64], s +% Edwards25519.scalar.field_order, .little);
            mark(.s_plus_l);
        },
        6 => {
            sig[0..32].* = pickLow(src);
            mark(.small_order_r);
        },
        7 => {
            pk = pickLow(src);
            mark(.small_order_a);
        },
        8 => { // both degenerate, S sometimes small
            sig[0..32].* = pickLow(src);
            pk = pickLow(src);
            if (src.index(2) == 0) @memset(sig[33..], 0);
            mark(.both_degenerate);
        },
        9 => { // A + torsion: mixed order
            if (pickTorsion(src)) |t| {
                if (Edwards25519.fromBytes(pk)) |a| {
                    pk = a.add(t).toBytes();
                } else |_| {}
            }
            mark(.torsion_a);
        },
        10 => { // R + torsion
            if (pickTorsion(src)) |t| {
                if (Edwards25519.fromBytes(sig[0..32].*)) |r| {
                    sig[0..32].* = r.add(t).toBytes();
                } else |_| {}
            }
            mark(.torsion_r);
        },
        11 => {
            src.bytes(&sig);
            mark(.random_sig);
        },
        else => { // random key bytes (most are not curve points)
            src.bytes(&pk);
            mark(.random_key);
        },
    }
    try sameVerdict(sig, mm, pk);

    // X25519: random secret against a random or low-order u-coordinate, and the
    // public key recovery.
    var sk: [32]u8 = undefined;
    src.bytes(&sk);
    var u: [32]u8 = undefined;
    if (src.index(3) == 0) {
        u = pickLow(src);
        mark(.x25519_low_order);
    } else {
        src.bytes(&u);
    }
    const want_x: anyerror![32]u8 = StdX.scalarmult(sk, u);
    const got_x: anyerror![32]u8 = root.X25519.scalarmult(sk, u);
    if (want_x) |w| {
        const g = try got_x;
        try testing.expectEqualSlices(u8, &w, &g);
        mark(.x25519_ok);
    } else |we| {
        if (got_x) |_| return error.TestUnexpectedResult else |ge| try testing.expect(ge == we);
    }
    const want_p: anyerror![32]u8 = StdX.recoverPublicKey(sk);
    const got_p: anyerror![32]u8 = root.X25519.recoverPublicKey(sk);
    if (want_p) |w| {
        try testing.expectEqualSlices(u8, &w, &(try got_p));
    } else |we| {
        if (got_p) |_| return error.TestUnexpectedResult else |ge| try testing.expect(ge == we);
    }
    mark(.x25519_recover);
}

test "fuzz driver: CT25519_FUZZ (ed25519 verifyStrict + x25519)" {
    try fuzz_driver.run(harness, .{ .prefix = "CT25519_FUZZ", .name = "ct25519-ed25519-x25519" });
}

test "fuzz harness: 300 seeds reach every check" {
    counts = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("ct25519-ed25519-x25519 seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (counts, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: ct25519-ed25519-x25519 label {t} never hit\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "fuzz: coverage-guided (std.testing.fuzz) over the same harness" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return harness(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}
