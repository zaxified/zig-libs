// SPDX-License-Identifier: MIT

//! bench — MB/s throughput micro-benchmarks. Off by default; opt in with
//! `CHACHAPOLY_BENCH`:
//!
//!   CHACHAPOLY_BENCH=1 scripts/capped zig build test-chachapoly -Doptimize=ReleaseFast -Dcpu=native
//!
//! Reports, at a fixed 8 KiB working-set (small enough to stay in L1 — the
//! point is the arithmetic, not the memory system):
//!
//!   * ChaCha20 keystream — ours (block-parallel `@Vector`) vs std
//!   * Poly1305 MAC       — ours (lane-parallel `@Vector`) vs std (scalar 64-bit)
//!   * ChaCha20-Poly1305  — full AEAD, ours vs std
//!
//! **Buffer size is deliberately small.** A previous oversized benchmark in
//! this repo allocated multi-megabyte in-memory working sets and OOM-killed the
//! host's editor; throughput is measured by iterating a small buffer many
//! times, never by making one giant buffer. Everything runs under
//! `scripts/capped`.
//!
//! Numbers are noisy on a mobile CPU (turbo / thermal). Treat them as ratios.

const std = @import("std");
const root = @import("root.zig");
const poly = @import("poly1305.zig");

const StdChaCha = std.crypto.stream.chacha.ChaCha20IETF;
const StdAead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const StdPoly = std.crypto.onetimeauth.Poly1305;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// MB/s for `iters` passes over a `len`-byte buffer taking `dt_ns`.
/// MB = 1e6 bytes (the unit every public ChaCha/Poly benchmark quotes).
fn mbps(len: usize, iters: usize, dt_ns: u64) f64 {
    const bytes: f64 = @floatFromInt(len * iters);
    const secs: f64 = @as(f64, @floatFromInt(dt_ns)) / 1e9;
    return bytes / secs / 1e6;
}

test "bench (opt-in via CHACHAPOLY_BENCH)" {
    if (std.testing.environ.getPosix("CHACHAPOLY_BENCH") == null) return error.SkipZigTest;

    // 8 KiB working set — see the OOM note in the module doc comment.
    const len = 8 * 1024;
    const iters: usize = 20_000; // 8 KiB * 20k = 164 MB moved per measurement

    var buf: [len]u8 = undefined;
    var out: [len]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC1A0_5EED);
    prng.random().bytes(&buf);

    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0x24} ** 12;
    const otk = [_]u8{0x17} ** 32;

    std.debug.print(
        \\
        \\=== chachapoly bench (8 KiB buffer, {d} iters) ===
        \\    poly1305 lanes = {d} ({s}), avx2={}, avx512f={}
        \\
    , .{
        iters,
        poly.lanes,
        if (poly.simd_active) "SIMD" else "scalar fallback",
        @import("builtin").cpu.has(.x86, .avx2),
        @import("builtin").cpu.has(.x86, .avx512f),
    });

    // ── ChaCha20 keystream ──
    {
        var t0 = nowNs();
        for (0..iters) |_| root.ChaCha20.stream(&out, 1, key, nonce);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours = mbps(len, iters, dt);

        t0 = nowNs();
        for (0..iters) |_| StdChaCha.stream(&out, 1, key, nonce);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs = mbps(len, iters, dt);
        std.debug.print("chacha20 keystream : ours {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n", .{ ours, theirs, ours / theirs });
    }

    // ── ChaCha20 xor (what the AEAD actually calls). Since the XOR was fused
    //    into the block emit this should track `stream` above within noise; a
    //    result far below it means the staging buffer is back. ──
    {
        var t0 = nowNs();
        for (0..iters) |_| root.ChaCha20.xor(&out, &buf, 1, key, nonce);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours = mbps(len, iters, dt);

        t0 = nowNs();
        for (0..iters) |_| StdChaCha.xor(&out, &buf, 1, key, nonce);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs = mbps(len, iters, dt);
        std.debug.print("chacha20 xor       : ours {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n", .{ ours, theirs, ours / theirs });
    }

    // ── Poly1305 MAC only ──
    {
        var tag: [16]u8 = undefined;
        var t0 = nowNs();
        for (0..iters) |_| poly.Poly1305.create(&tag, &buf, &otk);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&tag);
        const ours = mbps(len, iters, dt);

        t0 = nowNs();
        for (0..iters) |_| StdPoly.create(&tag, &buf, &otk);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&tag);
        const theirs = mbps(len, iters, dt);
        std.debug.print("poly1305 mac       : ours {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n", .{ ours, theirs, ours / theirs });
    }

    // ── full AEAD (encrypt: keystream + MAC over the ciphertext) ──
    {
        var tag: [16]u8 = undefined;
        var t0 = nowNs();
        for (0..iters) |_| root.ChaCha20Poly1305.encrypt(&out, &tag, &buf, "", nonce, key);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours = mbps(len, iters, dt);

        t0 = nowNs();
        for (0..iters) |_| StdAead.encrypt(&out, &tag, &buf, "", nonce, key);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs = mbps(len, iters, dt);
        std.debug.print("aead encrypt       : ours {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n", .{ ours, theirs, ours / theirs });
    }

    // ── the S1b / WireGuard case: one MTU-sized packet, not a bulk stream.
    //    Short messages are where a lane-parallel MAC can LOSE: it must build
    //    the r^1..r^L power table before the first wide group. This line is the
    //    regression guard for that. ──
    {
        const pkt = 1420; // WireGuard payload at a 1500-byte MTU
        var tag: [16]u8 = undefined;
        const pkt_iters = iters * 4;

        var t0 = nowNs();
        for (0..pkt_iters) |_| root.ChaCha20Poly1305.encrypt(out[0..pkt], &tag, buf[0..pkt], "", nonce, key);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours = mbps(pkt, pkt_iters, dt);

        t0 = nowNs();
        for (0..pkt_iters) |_| StdAead.encrypt(out[0..pkt], &tag, buf[0..pkt], "", nonce, key);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs = mbps(pkt, pkt_iters, dt);
        std.debug.print("aead 1420B packet  : ours {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n", .{ ours, theirs, ours / theirs });
    }

    // ── MAC size sweep. The lane-parallel engine has a floor: it must build
    //    the r^1..r^L power table before the first wide group, so below a
    //    threshold it is a LOSS and the hybrid deliberately stays on std's
    //    scalar core. This sweep is both the tuning input for that threshold
    //    and the regression guard that short inputs never go backwards. ──
    {
        std.debug.print("poly1305 by size (ours / std / ratio):\n", .{});
        inline for (.{ 32, 64, 128, 256, 512, 1024, 1420, 4096, 8192 }) |n| {
            var tag: [16]u8 = undefined;
            const n_iters = @max(iters, iters * 8192 / n);

            var t0 = nowNs();
            for (0..n_iters) |_| poly.Poly1305.create(&tag, buf[0..n], &otk);
            var dt = nowNs() - t0;
            std.mem.doNotOptimizeAway(&tag);
            const ours = mbps(n, n_iters, dt);

            t0 = nowNs();
            for (0..n_iters) |_| StdPoly.create(&tag, buf[0..n], &otk);
            dt = nowNs() - t0;
            std.mem.doNotOptimizeAway(&tag);
            const theirs = mbps(n, n_iters, dt);
            std.debug.print("  {d:>5} B : {d:>8.0} / {d:>8.0} MB/s  ({d:.2}x)\n", .{ n, ours, theirs, ours / theirs });
        }
        std.debug.print("\n", .{});
    }

    // ── SHORT-PACKET SWEEPS ─────────────────────────────────────────────────
    //
    // Everything below exists to answer one question the sweeps above cannot:
    // *where* a short AEAD call spends its time, and at what length the wide
    // machinery starts paying for itself. Three properties make these
    // different from the bulk lines above:
    //
    //   * They report **ns per call**, not MB/s. A short call is dominated by
    //     a FIXED cost; MB/s hides a fixed cost behind a division by the
    //     length, and a 30 ns difference at 64 bytes is invisible as MB/s but
    //     is 10% of the call.
    //   * They take the **minimum** of `reps` runs, not one run. Microbench
    //     noise on a mobile CPU is one-sided — preemption, migration, thermal
    //     throttle only ever make a run slower — so the fastest observed run
    //     is the best estimate of the true cost. Single-shot runs of these
    //     sizes were non-monotonic in length (a 96-byte call "faster" than a
    //     64-byte one), which is noise, and a threshold tuned on noise is a
    //     guess wearing a number's clothes.
    //   * They step in 16-byte increments through the crossover region rather
    //     than doubling, because the threshold has to be read off them.
    //
    // ── ChaCha20 `xor` by size — the AEAD's cipher half, in isolation. Note
    //    that EVERY AEAD call, whatever its length, also pays one `xor` of 32
    //    bytes to derive the Poly1305 key; the 32-byte row below is that cost.
    {
        std.debug.print("chacha20 xor by size (ns/call, min of {d}; ours / std / ratio):\n", .{reps});
        inline for (short_sizes) |n| {
            const n_iters = shortIters(iters, n);

            var ours: u64 = std.math.maxInt(u64);
            for (0..reps) |_| {
                const t0 = nowNs();
                for (0..n_iters) |_| root.ChaCha20.xor(out[0..n], buf[0..n], 1, key, nonce);
                ours = @min(ours, nowNs() - t0);
                std.mem.doNotOptimizeAway(&out);
            }

            var theirs: u64 = std.math.maxInt(u64);
            for (0..reps) |_| {
                const t0 = nowNs();
                for (0..n_iters) |_| StdChaCha.xor(out[0..n], buf[0..n], 1, key, nonce);
                theirs = @min(theirs, nowNs() - t0);
                std.mem.doNotOptimizeAway(&out);
            }
            printRow(n, n_iters, ours, theirs);
        }
        std.debug.print("\n", .{});
    }

    // ── FULL AEAD by size — the number a consumer actually feels, and the one
    //    this file was missing: it swept the MAC by size, but the AEAD only at
    //    8 KiB and 1420 B. A WireGuard tunnel carries keepalives (0-byte
    //    payload) and tunnelled TCP ACKs (40-60 B), so the left end of this
    //    sweep is real traffic, not a microbenchmark curiosity.
    //
    //    `seal` and `open` are swept separately: `open` runs the MAC *before*
    //    the keystream XOR, so a fix that only covered one direction would
    //    show up as a split between the two tables.
    {
        std.debug.print("aead seal by size (ns/call, min of {d}; ours / std / ratio):\n", .{reps});
        inline for (short_sizes) |n| {
            const n_iters = shortIters(iters, n);
            var tag: [16]u8 = undefined;

            var ours: u64 = std.math.maxInt(u64);
            for (0..reps) |_| {
                const t0 = nowNs();
                for (0..n_iters) |_| root.ChaCha20Poly1305.encrypt(out[0..n], &tag, buf[0..n], "", nonce, key);
                ours = @min(ours, nowNs() - t0);
                std.mem.doNotOptimizeAway(&out);
            }

            var theirs: u64 = std.math.maxInt(u64);
            for (0..reps) |_| {
                const t0 = nowNs();
                for (0..n_iters) |_| StdAead.encrypt(out[0..n], &tag, buf[0..n], "", nonce, key);
                theirs = @min(theirs, nowNs() - t0);
                std.mem.doNotOptimizeAway(&out);
            }
            printRow(n, n_iters, ours, theirs);
        }
        std.debug.print("\n", .{});
    }

    {
        std.debug.print("aead open by size (ns/call, min of {d}; ours / std / ratio):\n", .{reps});
        var ct: [len]u8 = undefined;
        inline for (short_sizes) |n| {
            const n_iters = shortIters(iters, n);
            var tag: [16]u8 = undefined;
            root.ChaCha20Poly1305.encrypt(ct[0..n], &tag, buf[0..n], "", nonce, key);

            var ours: u64 = std.math.maxInt(u64);
            for (0..reps) |_| {
                const t0 = nowNs();
                for (0..n_iters) |_| root.ChaCha20Poly1305.decrypt(out[0..n], ct[0..n], tag, "", nonce, key) catch unreachable;
                ours = @min(ours, nowNs() - t0);
                std.mem.doNotOptimizeAway(&out);
            }

            var theirs: u64 = std.math.maxInt(u64);
            for (0..reps) |_| {
                const t0 = nowNs();
                for (0..n_iters) |_| StdAead.decrypt(out[0..n], ct[0..n], tag, "", nonce, key) catch unreachable;
                theirs = @min(theirs, nowNs() - t0);
                std.mem.doNotOptimizeAway(&out);
            }
            printRow(n, n_iters, ours, theirs);
        }
        std.debug.print("\n", .{});
    }
}

/// Sizes for the short-packet sweeps: 16-byte steps through the crossover
/// region (a WireGuard keepalive is 0 bytes and a tunnelled TCP ACK is 40-60),
/// then doubling out to a full MTU and beyond so the same table also shows
/// that no large size was traded away for the short ones.
const short_sizes = .{ 0, 16, 32, 48, 64, 65, 80, 96, 112, 120, 128, 129, 136, 144, 160, 176, 192, 224, 256, 320, 384, 448, 512, 1024, 1420, 8192 };

/// Runs taken per measurement; the minimum is kept. See the block comment.
const reps = 5;

/// Iterations for a `n`-byte measurement — a fixed byte budget so a 16-byte
/// row does not run for a minute, floored so the fixed-cost rows still get
/// enough calls to time. Deliberately modest: benchmarks in this repo stay
/// small (an oversized one once OOM-killed the host's editor).
fn shortIters(iters: usize, comptime n: usize) usize {
    return @max(iters, iters * 2048 / @max(n, 16));
}

fn printRow(comptime n: usize, n_iters: usize, ours_ns: u64, theirs_ns: u64) void {
    const o = @as(f64, @floatFromInt(ours_ns)) / @as(f64, @floatFromInt(n_iters));
    const t = @as(f64, @floatFromInt(theirs_ns)) / @as(f64, @floatFromInt(n_iters));
    // Ratio is reported speed-wise (>1 = ours faster), i.e. theirs/ours in
    // time, so it reads the same direction as the MB/s tables above.
    std.debug.print("  {d:>5} B : {d:>8.1} / {d:>8.1} ns  ({d:.2}x)\n", .{ n, o, t, t / o });
}
