// SPDX-License-Identifier: MIT
//! Differential oracle: this module's TOTP against karlseguin/otp.zig (MIT, fetched by `oracle.sh`, never
//! vendored). Random secrets (1 to 100 bytes, so both sides' HMAC key hashing is exercised), times, periods,
//! digit counts 1 to 9 and the algorithms that library has (SHA-1, SHA-256): the code strings must be identical.
//! `karlseguin_oracle <cases> [seed]`; exits 1 on the first difference.

const std = @import("std");
const otp = @import("otp");
const theirs = @import("theirs");

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    const cases = try std.fmt.parseInt(u64, it.next() orelse "20000", 10);
    const seed = try std.fmt.parseInt(u64, it.next() orelse "1", 10);
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();

    var checked: u64 = 0;
    for (0..cases) |_| {
        var secret_buf: [100]u8 = undefined;
        const secret = secret_buf[0..rng.intRangeAtMost(usize, 1, 100)];
        rng.bytes(secret);
        const time = rng.int(u64) >> 31; // up to 2^33 seconds
        const period = rng.intRangeAtMost(u32, 1, 86400);
        const digits = rng.intRangeAtMost(u5, 1, 9);
        const use_256 = rng.boolean();

        var ours_buf: [16]u8 = undefined;
        const ours = if (use_256)
            try otp.totpFmt(.sha256, secret, time, period, 0, digits, &ours_buf)
        else
            try otp.totpFmt(.sha1, secret, time, period, 0, digits, &ours_buf);

        var their_buf: [16]u8 = undefined;
        const their = try theirs.generateAt(&their_buf, secret, @intCast(time), .{
            .interval = period,
            .digits = digits,
            .algorithm = if (use_256) .sha256 else .sha1,
        });
        if (!std.mem.eql(u8, ours, their)) {
            std.debug.print("MISMATCH alg={s} secret={x} time={d} period={d} digits={d}: ours {s} theirs {s}\n", .{ if (use_256) "sha256" else "sha1", secret, time, period, digits, ours, their });
            std.process.exit(1);
        }
        checked += 1;
    }
    std.debug.print("karlseguin/otp.zig: {d} cases identical (seed {d})\n", .{ checked, seed });
}
