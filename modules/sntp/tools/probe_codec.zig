// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: five questions about the codec that the suite answers only
// in part, kept together because each is a different way of asking "what does
// this module do with values an attacker picks?"
//
//   A. origin-timestamp correlation (half-width compares, zeroed, foreign)
//   B. bounds on the offset handed back to a caller
//   C. arithmetic extremes -- does anything overflow?
//   D. era-0 rollover in 2036
//   E. entropy of the wire nonce `query` sends
//
// ⚠ SECTIONS A, B AND D ARE LARGELY SPENT, and that is recorded here rather
// than deleted: A is now pinned by the `verifyOriginate` tests, and B's two
// headline gaps are closed -- `zero_t2` by F3's `ReceiveTimestampUnset` and
// `li3` by F7's `UnsynchronizedLeap`. Those cases are KEPT so the probe shows
// the guards firing; a case that now reports an error where the audit reported
// ACCEPTED is the fix being visible. What remains genuinely unpinned is the
// root delay/dispersion bound (still absent, honestly acknowledged in SPEC) and
// C's overflow headroom, which no test asserts.
//
// ⚠ SECTION E WAS RE-POINTED, NOT COPIED. The audit measured the entropy of
// `nowTimestamp()`, because back then the clock reading WAS the wire nonce --
// 21-24 bits against a doc comment claiming 64. F4 split them: the nonce is now
// `t1.seconds` plus 32 fresh bits from `std.Io.randomSecure`, and the offset
// math uses the real `t1`. Measuring the clock today would answer a question
// the module no longer asks. The record explicitly leaves the replacement
// unmeasured ("skutečná entropie std.Io.randomSecure na tomto stroji … ne
// znovu empiricky ověřeno"), so E now measures the CSPRNG draw, and keeps the
// clock measurement beside it labelled as the OLD nonce for contrast.
//
// WHAT IT NEEDS: the live module. Build in ReleaseSafe so overflow checks are
// live -- section C's whole point is that nothing traps.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseSafe --dep sntp \
//       -Mmain=probe_codec.zig -Msntp=../src/root.zig \
//       --cache-dir <scratch>/zc-probe -femit-bin=<scratch>/probe_codec

const std = @import("std");
const sntp = @import("sntp");

fn hdr(comptime s: []const u8) void {
    std.debug.print("\n=== {s} ===\n", .{s});
}

fn mkReply(stratum: u8, origin: sntp.Timestamp, recv: sntp.Timestamp, xmit: sntp.Timestamp) [48]u8 {
    const p: sntp.Packet = .{
        .version = 4,
        .mode = .server,
        .stratum = stratum,
        .originate = origin,
        .receive = recv,
        .transmit = xmit,
    };
    return p.encode();
}

pub fn main() !void {
    const t1: sntp.Timestamp = .{ .seconds = 3_994_581_532, .fraction = 0xEF6B2800 };
    // ⚠ Non-zero receive everywhere it is not the subject: since F3 an all-zero
    // T2 is `ReceiveTimestampUnset`, so a probe that left it zero would have
    // every case fail on that one guard and measure nothing else.
    const good_recv: sntp.Timestamp = .{ .seconds = t1.seconds, .fraction = 1 };

    // ── A. origin-timestamp correlation ─────────────────────────────────────
    hdr("A. origin timestamp: zeroed / foreign / half-width / correct");
    {
        const cases = [_]struct { name: []const u8, o: sntp.Timestamp }{
            .{ .name = "zeroed origin       ", .o = .zero },
            .{ .name = "foreign origin      ", .o = .{ .seconds = 1, .fraction = 2 } },
            .{ .name = "hi32 right, lo wrong", .o = .{ .seconds = t1.seconds, .fraction = t1.fraction ^ 1 } },
            .{ .name = "lo32 right, hi wrong", .o = .{ .seconds = t1.seconds ^ 1, .fraction = t1.fraction } },
            .{ .name = "correct origin      ", .o = t1 },
        };
        for (cases) |c| {
            const bytes = mkReply(2, c.o, good_recv, .{ .seconds = t1.seconds + 1 });
            const r = sntp.decodeResponse(&bytes, null) catch |e| {
                std.debug.print("  {s}: decodeResponse -> {t}\n", .{ c.name, e });
                continue;
            };
            if (sntp.verifyOriginate(r, t1)) {
                std.debug.print("  {s}: ACCEPTED\n", .{c.name});
            } else |e| {
                std.debug.print("  {s}: verifyOriginate -> {t}\n", .{ c.name, e });
            }
        }
    }

    // ── B. bounds on the reported offset ────────────────────────────────────
    hdr("B. offset handed to a caller (audit F3/F7 cases now expected to FAIL)");
    {
        // A reply passing every check the module makes, whose server time is
        // ~50 years off. Still unbounded: no test and no guard caps the offset.
        const far: sntp.Timestamp = .{ .seconds = 4_294_967_295, .fraction = 0xFFFF_FFFF };
        const bytes = mkReply(1, t1, far, far);
        const r = try sntp.decodeResponse(&bytes, null);
        try sntp.verifyOriginate(r, t1);
        const s: sntp.Sample = .{ .originate = r.originate, .receive = r.receive, .transmit = r.transmit, .destination = t1 };
        std.debug.print("  far-future server: offset = {d} ns = {d:.1} days  (STILL UNBOUNDED)\n", .{ s.offsetNanos(), @as(f64, @floatFromInt(s.offsetNanos())) / 86_400e9 });

        // receive (T2) all-zero: the audit's -63-year case. F3 must refuse it.
        const zero_t2 = mkReply(1, t1, .zero, .{ .seconds = t1.seconds });
        if (sntp.decodeResponse(&zero_t2, null)) |_| {
            std.debug.print("  T2 == 0: ACCEPTED  ⛔ F3 HAS REGRESSED\n", .{});
        } else |e| std.debug.print("  T2 == 0 -> {t}  (F3 holding)\n", .{e});

        // LI == 3 (alarm / clock not synchronized). F7 must refuse it.
        const li3: sntp.Packet = .{ .leap = .unsynchronized, .version = 4, .mode = .server, .stratum = 1, .originate = t1, .receive = good_recv, .transmit = .{ .seconds = 1 } };
        const li3b = li3.encode();
        if (sntp.decodeResponse(&li3b, null)) |rr| {
            std.debug.print("  LI=3: ACCEPTED, leap={t}  ⛔ F7 HAS REGRESSED\n", .{rr.leap});
        } else |e| std.debug.print("  LI=3 -> {t}  (F7 holding)\n", .{e});

        // root_dispersion = 0xFFFFFFFF (65536 s): a legitimate wire value that
        // nothing bounds. SPEC acknowledges the gap; this keeps it visible.
        const disp: sntp.Packet = .{ .version = 4, .mode = .server, .stratum = 1, .root_delay = 0xFFFF_FFFF, .root_dispersion = 0xFFFF_FFFF, .originate = t1, .receive = good_recv, .transmit = .{ .seconds = 1 } };
        const dispb = disp.encode();
        if (sntp.decodeResponse(&dispb, null)) |rr| {
            std.debug.print("  root_delay/disp = 0xFFFFFFFF: ACCEPTED, disp = {d:.1} s  (no bound, per SPEC)\n", .{rr.rootDispersionSeconds()});
        } else |e| std.debug.print("  root disp max -> {t}\n", .{e});
    }

    // ── C. arithmetic extremes ──────────────────────────────────────────────
    hdr("C. offset/delay at extreme timestamps (attacker chooses T1..T4)");
    {
        const zero: sntp.Timestamp = .zero;
        const max: sntp.Timestamp = .{ .seconds = 0xFFFF_FFFF, .fraction = 0xFFFF_FFFF };
        const combos = [_]struct { a: sntp.Timestamp, b: sntp.Timestamp, c: sntp.Timestamp, d: sntp.Timestamp, n: []const u8 }{
            .{ .a = zero, .b = zero, .c = zero, .d = zero, .n = "all zero      " },
            .{ .a = max, .b = max, .c = max, .d = max, .n = "all max       " },
            .{ .a = zero, .b = max, .c = max, .d = zero, .n = "min/max       " },
            .{ .a = max, .b = zero, .c = zero, .d = max, .n = "max/min       " },
            .{ .a = max, .b = zero, .c = max, .d = zero, .n = "negative delay" },
        };
        for (combos) |k| {
            const off = sntp.computeOffsetNanos(k.a, k.b, k.c, k.d);
            const del = sntp.computeDelayNanos(k.a, k.b, k.c, k.d);
            std.debug.print("  {s}: offset={d} delay={d}\n", .{ k.n, off, del });
        }
        std.debug.print("  nanosSinceNtpEpoch(max) = {d} (u64 max = {d})\n", .{ max.nanosSinceNtpEpoch(), std.math.maxInt(u64) });
        std.debug.print("  toUnixNanos(max)        = {d}\n", .{max.toUnixNanos()});
        std.debug.print("  toUnixNanos(zero)       = {d}\n", .{zero.toUnixNanos()});
    }

    // ── D. era rollover ─────────────────────────────────────────────────────
    hdr("D. era 0 rollover (2036-02-07T06:28:16Z = NTP seconds 2^32)");
    {
        const last: sntp.Timestamp = .{ .seconds = 0xFFFF_FFFF, .fraction = 0 };
        std.debug.print("  last era-0 second   -> unix ns {d}\n", .{last.toUnixNanos()});
        const wrapped: sntp.Timestamp = .{ .seconds = 0, .fraction = 0 };
        std.debug.print("  wrapped (era 1 s=0) -> unix ns {d} (1900-01-01)\n", .{wrapped.toUnixNanos()});
        const past = sntp.Timestamp.fromNanosSinceNtpEpoch(@as(u64, 0x1_0000_0000) * std.time.ns_per_s);
        std.debug.print("  fromNanosSinceNtpEpoch(2^32 s) -> seconds={d} (silent wrap)\n", .{past.seconds});
        std.debug.print("  the suite's 2036 tripwire asserts nowTimestamp().seconds < 4294944000 = unix {d}\n", .{@as(i64, 4_294_944_000) - 2_208_988_800});
    }

    // ── E. entropy of the wire nonce `query` actually sends (audit F4) ──────
    hdr("E. nonce entropy: the CSPRNG draw F4 introduced, and the clock it replaced");
    {
        const N = 200_000;
        var da: std.heap.DebugAllocator(.{}) = .init;
        defer _ = da.deinit();
        const gpa = da.allocator();
        var threaded: std.Io.Threaded = .init(gpa, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // E1: what `query` puts on the wire today -- 32 bits from randomSecure.
        var uniq_nonce = std.AutoHashMap(u32, void).init(gpa);
        defer uniq_nonce.deinit();
        var lowbits: [8]usize = @splat(0);
        var draw: [4]u8 = undefined;
        for (0..N) |_| {
            try std.Io.randomSecure(io, &draw);
            const v = std.mem.readInt(u32, &draw, .big);
            try uniq_nonce.put(v, {});
            lowbits[@as(u3, @truncate(v))] += 1;
        }
        std.debug.print("  E1 randomSecure 32-bit draws: N={d} distinct={d}\n", .{ N, uniq_nonce.count() });
        std.debug.print("     bottom-3-bit histogram: {any}  (expect ~{d} each)\n", .{ lowbits, N / 8 });
        std.debug.print("     collisions: {d}  (birthday expectation over 2^32 ~ {d})\n", .{ N - uniq_nonce.count(), (N * (N - 1)) / 2 / 4294967296 });

        // E2: the OLD nonce, for contrast only -- this is what F4 removed.
        var uniq_clock = std.AutoHashMap(u64, void).init(gpa);
        defer uniq_clock.deinit();
        var prev: u64 = 0;
        var mono: usize = 0;
        var min_step: u64 = std.math.maxInt(u64);
        var sum_step: u128 = 0;
        for (0..N) |i| {
            const ts = sntp.nowTimestamp() catch break;
            const v = (@as(u64, ts.seconds) << 32) | ts.fraction;
            try uniq_clock.put(v, {});
            if (i > 0 and v > prev) {
                mono += 1;
                const d = v - prev;
                if (d < min_step) min_step = d;
                sum_step += d;
            }
            prev = v;
        }
        std.debug.print("  E2 clock reading (the PRE-F4 nonce, contrast only): distinct={d}\n", .{uniq_clock.count()});
        if (mono > 0) {
            std.debug.print("     strictly increasing pairs {d}/{d}, min step={d}, mean step={d:.1} ns\n", .{
                mono,                                                          N - 1, min_step,
                @as(f64, @floatFromInt(sum_step / mono)) * 1e9 / 4294967296.0,
            });
            // ⚠ The candidate space is the window divided by the OBSERVED
            // granularity, not the window expressed in raw 2^-32 s units. Those
            // differ by orders of magnitude (~2^29 vs ~2^22), and printing the
            // raw unit count would be a number that does not mean what the
            // sentence beside it claims.
            const step_ns = @as(f64, @floatFromInt(min_step)) * 1e9 / 4294967296.0;
            const candidates = 0.1e9 / step_ns;
            std.debug.print("     -> an off-path attacker bracketing a 100 ms window searches ~{d:.0} clock values (~2^{d:.1}),\n", .{ candidates, @log2(candidates) });
            std.debug.print("        against 2^32 for the CSPRNG nonce above -- which is why F4 stopped using the clock.\n", .{});
        }
    }
}
