// SPDX-License-Identifier: MIT

//! bench — ns/op micro-benchmarks for the portable path (and the amd64 core
//! once it lands). Off by default; opt in with the `MONTINT_BENCH` env var:
//!
//!   MONTINT_BENCH=1 zig build test-montint -Doptimize=ReleaseFast
//!
//! It prints modmul + modexp ns/op at 2048/4096-bit. The C baseline the
//! director wants is `openssl speed rsa2048 rsa4096` on the same host (a
//! 2048-bit private modexp ≈ RSA-2048 sign ≈ 0.67 ms on this box per the `rsa`
//! audit; a single 2048-bit modmul ≈ low hundreds of ns). The owner-verify and
//! Fable phases produce the actual zig-vs-OpenSSL table.

const std = @import("std");
const builtin = @import("builtin");
const montint = @import("montint.zig");
const kv = @import("kat_vectors.zig");

fn nowNs() u64 {
    if (builtin.os.tag != .linux) return 0; // opt-in dev bench; linux clock only
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn benchSize(comptime bits: comptime_int, comptime Size: type) void {
    const M = montint.Modint(bits);
    const m = M.fromElem(Size.m) catch return;
    const a: M.Elem = Size.a;
    const b: M.Elem = Size.b;
    const e: M.Elem = Size.e;

    // modmul (normal-domain a·b mod m)
    {
        const iters: usize = if (bits >= 4096) 20_000 else 100_000;
        var sink: u64 = 0;
        const t0 = nowNs();
        var i: usize = 0;
        var acc = a;
        while (i < iters) : (i += 1) {
            acc = m.mul(&acc, &b);
            sink ^= acc[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint modmul  {d:>5}-bit: {d:>8} ns/op ({d} iters){s}\n", .{
            bits, dt / iters, iters, if (montint.asm_active) "  [asm]" else "  [portable]",
        });
    }
    // modexp (full-width exponent, constant-time windowed)
    {
        const iters: usize = if (bits >= 4096) 20 else 100;
        var sink: u64 = 0;
        const t0 = nowNs();
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            const r = m.powMont(&a, &e);
            sink ^= r[0];
        }
        const dt = nowNs() - t0;
        std.mem.doNotOptimizeAway(sink);
        std.debug.print("montint modexp  {d:>5}-bit: {d:>8} ns/op ({d} iters){s}\n", .{
            bits, dt / iters, iters, if (montint.asm_active) "  [asm]" else "  [portable]",
        });
    }
}

test "bench (opt-in via MONTINT_BENCH)" {
    // `std.testing.environ` is the test-runner's environment block.
    if (std.testing.environ.getPosix("MONTINT_BENCH") == null) return error.SkipZigTest;
    std.debug.print("\n=== montint bench (asm_active={}) ===\n", .{montint.asm_active});
    benchSize(2048, kv.Size2048);
    benchSize(4096, kv.Size4096);
    std.debug.print("C baseline: run `openssl speed rsa2048 rsa4096` on this host.\n", .{});
}
