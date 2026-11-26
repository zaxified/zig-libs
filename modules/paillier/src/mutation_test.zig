// SPDX-License-Identifier: MIT

//! Killing tests from the 2026-11-25 delta mutation run (packed encoding).

const std = @import("std");
const testing = std.testing;
const paillier = @import("root.zig");

test "mutation 2026-11-25: pack/unpack at every component width, full capacity, all-ones and random components" {
    var prng = std.Random.DefaultPrng.init(0x6d75);
    const rnd = prng.random();
    var kp: paillier.KeyPair = undefined;
    try paillier.generate(rnd, 512, &kp);
    defer kp.secret.deinit();
    const pk = kp.public;
    var vals: [520]u64 = undefined;
    var back: [520]u64 = undefined;
    for (1..65) |c_usize| {
        const c: u8 = @intCast(c_usize);
        const cap = paillier.packCapacity(pk, c);
        // The capacity is exactly the number of components below n: a full
        // pack of all-ones components is a canonical plaintext (no overflow
        // past n) and one component more is refused.
        try testing.expect(cap >= 1 and cap <= vals.len);
        const mask: u64 = if (c == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(c)) - 1;
        for (0..3) |round| {
            for (vals[0..cap]) |*v| v.* = if (round == 0) mask else rnd.int(u64) & mask;
            const m = try paillier.pack(pk, vals[0..cap], c);
            try paillier.unpack(pk, &m, c, back[0..cap]);
            try testing.expectEqualSlices(u64, vals[0..cap], back[0..cap]);
        }
        try testing.expectError(error.TooManyComponents, paillier.pack(pk, vals[0 .. cap + 1], c));
        const m0 = try paillier.pack(pk, vals[0..1], c);
        try testing.expectError(error.TooManyComponents, paillier.unpack(pk, &m0, c, back[0 .. cap + 1]));
    }
    // unpack refuses a width of 0 or > 64 itself, whatever the output length.
    const m1 = try paillier.pack(pk, &.{5}, 8);
    try testing.expectError(error.InvalidComponentBits, paillier.unpack(pk, &m1, 0, back[0..0]));
    try testing.expectError(error.InvalidComponentBits, paillier.unpack(pk, &m1, 0, back[0..1]));
    try testing.expectError(error.InvalidComponentBits, paillier.unpack(pk, &m1, 65, back[0..1]));
}
