// SPDX-License-Identifier: MIT

//! bench — WireGuard data-plane AEAD throughput. Off by default; opt in with
//! `WIREGUARD_BENCH`:
//!
//!   WIREGUARD_BENCH=1 scripts/capped zig build test-wireguard -Doptimize=ReleaseFast -Dcpu=native
//!
//! **What this measures, and what it does NOT.** The one operation on
//! WireGuard's packet path is `AEAD(T_send, counterNonce(counter), packet, ε)`
//! — one seal per outbound transport-data packet, one open per inbound one.
//! That is what is timed here, at a realistic 1420-byte payload (a 1500-byte
//! Ethernet MTU minus the 20-byte IPv4 + 8-byte UDP + 16-byte WireGuard
//! transport headers and the 16-byte Poly1305 tag), for `noise.Aead` (the
//! `chachapoly` sibling) against `noise.StdAead`.
//!
//! It does NOT measure a tunnel. This module implements the handshake and the
//! wire codecs, not a packet forwarding loop — there is no socket, no queue,
//! no routing table in the timed region. A real tunnel adds a syscall per
//! packet (or a batched `sendmmsg`), a routing/allowed-ips lookup and a
//! replay-window update on top of every number below, so the END-TO-END
//! speed-up of a deployment is strictly smaller than the ratio printed here,
//! and by a lot once the kernel boundary is in the path. Read this as "the
//! crypto is no longer the bottleneck", not as "the tunnel got 2.4x faster".
//!
//! The handshake line is included to make the other half of the honesty
//! explicit: a handshake is two 32-byte and 12-byte AEAD calls, dominated by
//! four X25519 scalar multiplications. The AEAD swap is invisible there.
//!
//! Buffer sizes are deliberately tiny (one MTU) and throughput comes from
//! iterating, never from allocating a large working set — a previous
//! oversized benchmark in this repo OOM-killed the host's editor. Everything
//! runs under `scripts/capped`.
//!
//! Numbers are noisy on a mobile CPU (turbo / thermal). Treat them as ratios.

const std = @import("std");
const noise = @import("noise.zig");
const transport = @import("transport.zig");

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

/// The transport-data nonce: 4 zero bytes then the 64-bit counter,
/// little-endian (whitepaper 5.4.6). THE definition, shared with the data
/// plane and the handshake — a bench with its own copy could not have caught a
/// layout regression.
const counterNonce = transport.counterNonce;

/// 1500-byte MTU - 20 (IPv4) - 8 (UDP) - 16 (WG transport header) - 16
/// (Poly1305 tag) = 1440; 1420 is the conventional WireGuard tunnel MTU and
/// the size `chachapoly`'s own bench quotes, so the two are comparable.
const bench_mtu = 1420;

// Buffers for the full-path (`transport.zig`) bench. At file scope so the
// 64-slot ring lives in .bss rather than on the test thread's stack — still
// ~93 KB total, i.e. one MTU per slot. Benchmarks in this repo stay small on
// purpose: an oversized one once OOM-killed the host's editor.
var sealed_scratch: [transport.sealedLen(bench_mtu)]u8 = undefined;
var out_padded: [transport.paddedLen(bench_mtu)]u8 = undefined;
var open_ring: [64][transport.sealedLen(bench_mtu)]u8 = undefined;

test "bench (opt-in via WIREGUARD_BENCH)" {
    if (std.testing.environ.getPosix("WIREGUARD_BENCH") == null) return error.SkipZigTest;

    const mtu = bench_mtu;
    const iters: usize = 80_000; // 1420 B * 80k = 114 MB moved per measurement

    var packet: [mtu]u8 = undefined;
    var out: [mtu]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5A17_C0DE);
    prng.random().bytes(&packet);

    const key: [32]u8 = @splat(0x42);
    var tag: [16]u8 = undefined;

    std.debug.print(
        \\
        \\=== wireguard transport-data bench ({d}-byte payload, {d} iters) ===
        \\    NOTE: AEAD only — no socket, no routing, no replay window.
        \\
    , .{ mtu, iters });

    // ── seal: the outbound transport-data path ──
    {
        var t0 = nowNs();
        for (0..iters) |i| noise.Aead.encrypt(&out, &tag, &packet, "", counterNonce(i), key);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours = mbps(mtu, iters, dt);

        t0 = nowNs();
        for (0..iters) |i| noise.StdAead.encrypt(&out, &tag, &packet, "", counterNonce(i), key);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs = mbps(mtu, iters, dt);
        std.debug.print(
            "transport seal : chachapoly {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n",
            .{ ours, theirs, ours / theirs },
        );
    }

    // ── open: the inbound path. Tag verification runs BEFORE the keystream
    //    XOR, so an open is a MAC pass plus a cipher pass just like a seal —
    //    if this line diverges much from the seal line, one of the two has a
    //    copy the other does not. ──
    {
        var ct: [mtu]u8 = undefined;
        const npub = counterNonce(0);
        noise.Aead.encrypt(&ct, &tag, &packet, "", npub, key);

        var t0 = nowNs();
        for (0..iters) |_| noise.Aead.decrypt(&out, &ct, tag, "", npub, key) catch unreachable;
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours = mbps(mtu, iters, dt);

        t0 = nowNs();
        for (0..iters) |_| noise.StdAead.decrypt(&out, &ct, tag, "", npub, key) catch unreachable;
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs = mbps(mtu, iters, dt);
        std.debug.print(
            "transport open : chachapoly {d:>8.0} MB/s   std {d:>8.0} MB/s   ({d:.2}x)\n",
            .{ ours, theirs, ours / theirs },
        );
    }

    // ── packets/second, the number a data-plane budget is actually written
    //    in. Reported as ns/packet too, because that is what has to fit
    //    alongside a syscall (~1-2 us) to mean anything. ──
    {
        var t0 = nowNs();
        for (0..iters) |i| noise.Aead.encrypt(&out, &tag, &packet, "", counterNonce(i), key);
        var dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const ours_ns = @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(iters));

        t0 = nowNs();
        for (0..iters) |i| noise.StdAead.encrypt(&out, &tag, &packet, "", counterNonce(i), key);
        dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(&out);
        const theirs_ns = @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(iters));
        std.debug.print(
            "per packet     : chachapoly {d:>8.0} ns ({d:.2} Mpps)   std {d:>8.0} ns ({d:.2} Mpps)\n",
            .{ ours_ns, 1000.0 / ours_ns, theirs_ns, 1000.0 / theirs_ns },
        );
    }

    // ── the REAL data-plane path: `transport.SendSession.seal` /
    //    `RecvSession.open`, i.e. the AEAD plus everything the module wraps
    //    around it — the 16-byte header write, the copy-and-pad into the
    //    output buffer, the counter limit checks and (on receive) the
    //    anti-replay window. This is the number a tunnel budget is written
    //    in; the AEAD-only lines above are its lower bound. Still no socket
    //    and no routing table. ──
    {
        var s = transport.SendSession.init(key, 0xDEADBEEF);
        var t0 = nowNs();
        for (0..iters) |_| {
            const r = s.seal(&sealed_scratch, &packet) catch unreachable;
            std.mem.doNotOptimizeAway(r.len);
        }
        var dt = nowNs() - t0;
        const seal_ns = @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(iters));

        // Open needs distinct counters (a replay is rejected by design), so
        // pre-seal a small ring and reset the receiver once per lap. The
        // reset is a `.{}` assignment amortised over `ring_len` opens.
        var ring_sender = transport.SendSession.init(key, 0xDEADBEEF);
        for (&open_ring) |*slot| _ = ring_sender.seal(slot, &packet) catch unreachable;
        const msg_len = transport.sealedLen(mtu);

        var r = transport.RecvSession.init(key, 0xDEADBEEF);
        t0 = nowNs();
        var done: usize = 0;
        while (done < iters) : (done += open_ring.len) {
            r.window.reset();
            for (&open_ring) |*slot| {
                const o = r.open(&out_padded, slot[0..msg_len]) catch unreachable;
                std.mem.doNotOptimizeAway(o.len);
            }
        }
        dt = nowNs() - t0;
        const open_ns = @as(f64, @floatFromInt(dt)) / @as(f64, @floatFromInt(done));
        std.debug.print(
            \\full path      : seal {d:>8.0} ns ({d:.2} Mpps, {d:.0} MB/s)   open {d:>8.0} ns ({d:.2} Mpps, {d:.0} MB/s)
            \\    (header + pad-to-16 + AEAD + counter limits [+ replay window on open])
            \\
        , .{
            seal_ns,      1000.0 / seal_ns, @as(f64, mtu) / seal_ns * 1000.0,
            open_ns,      1000.0 / open_ns, @as(f64, mtu) / open_ns * 1000.0,
        });
    }

    // ── size sweep: the AEAD's advantage is length-dependent (the wide
    //    ChaCha group and the lane-parallel Poly1305 both have a warm-up),
    //    and a tunnel carries plenty of 64-byte ACKs, not only full MTUs.
    //
    //    MEASURED (i7-7920HQ, AVX2, ReleaseFast, -Dcpu=native): the crossover
    //    is around 256 bytes. Below it the swap is a small LOSS —
    //    ~0.85-0.92x at 64 and 128 bytes — because a wide ChaCha group and
    //    the Poly1305 r^L power table both cost a fixed setup that a short
    //    packet cannot amortise. `chachapoly`'s own bench sweeps the MAC by
    //    size but not the full AEAD, so this line is where that shows up.
    //    It matters for WireGuard specifically: keepalives are a 0-byte
    //    payload and tunnelled TCP ACKs are ~40-60 bytes, so a flow that is
    //    mostly ACKs sees no gain at all. It is not a regression worth
    //    reverting (the loss is a few percent of a cheap operation, the win
    //    is >2x on the bytes that dominate a tunnel's byte count), but it
    //    must not be reported as "2.4x everywhere". ──
    {
        std.debug.print("by payload size (chachapoly / std / ratio):\n", .{});
        inline for (.{ 64, 128, 256, 512, 1024, 1420 }) |n| {
            const n_iters = @max(iters, iters * 1420 / n);
            var t0 = nowNs();
            for (0..n_iters) |i| noise.Aead.encrypt(out[0..n], &tag, packet[0..n], "", counterNonce(i), key);
            var dt = nowNs() - t0;
            std.mem.doNotOptimizeAway(&out);
            const ours = mbps(n, n_iters, dt);

            t0 = nowNs();
            for (0..n_iters) |i| noise.StdAead.encrypt(out[0..n], &tag, packet[0..n], "", counterNonce(i), key);
            dt = nowNs() - t0;
            std.mem.doNotOptimizeAway(&out);
            const theirs = mbps(n, n_iters, dt);
            std.debug.print("  {d:>5} B : {d:>8.0} / {d:>8.0} MB/s  ({d:.2}x)\n", .{ n, ours, theirs, ours / theirs });
        }
        std.debug.print("\n", .{});
    }
}
