// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: the module's fuzz target walks the splits its input picks.
// This walks the header space EXHAUSTIVELY -- every value of byte 0 (LI|VN|Mode)
// against every value of byte 1 (stratum), all 65 536 -- and then sweeps every
// length 0..80 with random bytes. It is the "never panics on hostile input"
// claim, measured rather than asserted.
//
// ⚠ THE ACCEPT COUNT IS A MOVING TARGET, AND THAT IS THE POINT. The audit
// measured 420 accepted = 4 LI x 7 VN x 15 stratum. Since then F7 added
// `UnsynchronizedLeap`, so LI=3 is refused and the LI factor drops from 4 to 3.
// A changed count here is evidence the fix shipped; an UNCHANGED 420 would mean
// F7 had regressed. Read the number, do not assume it.
//
// ⚠ Two things had to change for this to run against the live module at all,
// and both were invisible until it was built:
//   1. `switch (e)` was exhaustive over the OLD error set. F3 and F7 added
//      `ReceiveTimestampUnset` and `UnsynchronizedLeap`; without them the probe
//      does not compile.
//   2. The probe set a non-zero `transmit` but left `receive` zero. With F3's
//      new check every packet would now fail on `ReceiveTimestampUnset` and the
//      sweep would report 0 accepted -- a number that looks like a finding and
//      is actually the instrument being stale.
//
// WHAT IT NEEDS: the live module. Build in ReleaseSafe so bounds and overflow
// checks are live -- a "no panic" claim from a build with checks off is worth
// nothing.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseSafe --dep sntp \
//       -Mmain=sweep.zig -Msntp=../src/root.zig \
//       --cache-dir <scratch>/zc-sweep -femit-bin=<scratch>/sweep

const std = @import("std");
const sntp = @import("sntp");

pub fn main() !void {
    var accepted: usize = 0;
    var rejected: usize = 0;
    var n_len: usize = 0;
    var n_ver: usize = 0;
    var n_mode: usize = 0;
    var n_kod: usize = 0;
    var n_stratum: usize = 0;
    var n_leap: usize = 0;
    var n_xmit: usize = 0;
    var n_recv: usize = 0;

    // 1. Exhaustive over byte 0 (LI|VN|Mode) x byte 1 (stratum) = 65 536 packets.
    //    Both transmit AND receive are non-zero so the later guards stay
    //    reachable (see the header note).
    var buf: [48]u8 = @splat(0);
    std.mem.writeInt(u32, buf[32..36], 1, .big); // receive  (T2)
    std.mem.writeInt(u32, buf[40..44], 1, .big); // transmit (T3)
    for (0..256) |b0| {
        for (0..256) |b1| {
            buf[0] = @intCast(b0);
            buf[1] = @intCast(b1);
            var kod: sntp.KissOfDeath = undefined;
            if (sntp.decodeResponse(&buf, &kod)) |r| {
                accepted += 1;
                sntp.verifyOriginate(r, .{ .seconds = 1, .fraction = 2 }) catch {};
            } else |e| {
                rejected += 1;
                switch (e) {
                    error.InvalidLength => n_len += 1,
                    error.InvalidVersion => n_ver += 1,
                    error.NotServerMode => n_mode += 1,
                    error.KissOfDeath => n_kod += 1,
                    error.UnsynchronizedStratum => n_stratum += 1,
                    error.UnsynchronizedLeap => n_leap += 1,
                    error.TransmitTimestampUnset => n_xmit += 1,
                    error.ReceiveTimestampUnset => n_recv += 1,
                }
            }
        }
    }
    std.debug.print("exhaustive header sweep (byte0 x byte1, 65536 packets): accepted={d} rejected={d}\n", .{ accepted, rejected });
    std.debug.print("  InvalidLength={d} InvalidVersion={d} NotServerMode={d} KissOfDeath={d}\n", .{ n_len, n_ver, n_mode, n_kod });
    std.debug.print("  UnsynchronizedStratum={d} UnsynchronizedLeap={d} TransmitUnset={d} ReceiveUnset={d}\n", .{ n_stratum, n_leap, n_xmit, n_recv });
    std.debug.print("  expected accepted = (#LI accepted) x (#VN accepted) x (#stratum accepted)\n", .{});

    // 2. Random sweep over every length 0..80, 40 000 packets each length.
    var seed_ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &seed_ts);
    const seed: u64 = @bitCast(@as(i64, seed_ts.nsec) ^ @as(i64, seed_ts.sec) << 20);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var rbuf: [80]u8 = undefined;
    var total: usize = 0;
    var acc48: usize = 0;
    var t1_ok: usize = 0;
    for (0..81) |len| {
        for (0..40_000) |_| {
            rnd.bytes(rbuf[0..len]);
            var kod: sntp.KissOfDeath = undefined;
            total += 1;
            if (sntp.decodeResponse(rbuf[0..len], &kod)) |r| {
                acc48 += 1;
                // Feed the offset/delay math with the accepted (attacker-chosen)
                // values -- the arithmetic is part of what must not panic.
                const s: sntp.Sample = .{
                    .originate = r.originate,
                    .receive = r.receive,
                    .transmit = r.transmit,
                    .destination = sntp.nowTimestamp() catch .zero,
                };
                std.mem.doNotOptimizeAway(s.offsetNanos());
                std.mem.doNotOptimizeAway(s.roundtripDelayNanos());
                if (sntp.verifyOriginate(r, r.originate)) t1_ok += 1 else |_| {}
            } else |_| {}
        }
    }
    std.debug.print("random sweep seed=0x{x}: {d} packets over lengths 0..80, accepted={d} (expect all at len=48), no panic\n", .{ seed, total, acc48 });
    // ⚠ `verifyOriginate(r, r.originate)` compares a field with itself and so
    // CANNOT fail. It is kept only to prove the call is reached on every
    // accepted packet -- never read it as evidence the correlation works; the
    // dedicated `verifyOriginate` tests in src/ are what pin that.
    std.debug.print("  offset/delay computed on every accepted packet; self-compare reached {d}/{d}\n", .{ t1_ok, acc48 });
}
