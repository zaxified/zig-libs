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

    // ── ChaCha20 xor (what the AEAD actually calls; `stream` above writes the
    //    keystream straight to `out`, `xor` stages it through a stack buffer) ──
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
}
