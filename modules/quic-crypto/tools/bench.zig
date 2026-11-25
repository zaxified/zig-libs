// SPDX-License-Identifier: MIT

//! Packet-protection benchmark for `quic-crypto`: `Protection(A).seal`/`open`
//! (the stateless call: the AEAD key schedule runs on every packet) against
//! `Protection(A).Keyed` (the key schedule kept per key epoch). It compares the
//! module with itself; the RFC 9001 vectors in `src/` are the correctness
//! check, and the gate below checks the two shapes agree before anything is
//! timed.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-quic-crypto` runs it
//! (always ReleaseFast); `zig build check-interop` compiles it. It needs
//! nothing outside this repository. Arguments filter workloads by substring.
//!
//! Workloads: seal_<aead>_<n> / open_<aead>_<n> for AES-128-GCM and
//! ChaCha20-Poly1305 (the latter has no per-key state: its ratio is ~1 by
//! construction), n = 64, 1200, 1400 payload bytes. Method as `dtls`'s bench:
//! `benchkit.timeIt`, the two sides alternate for `BENCH_ROUNDS` rounds, ratio
//! = keyed / stateless by user-mode cycles, spread = (worst - best) / best.

const std = @import("std");
const bench = @import("benchkit");
const qc = @import("quic-crypto");
const aesgcm = @import("aesgcm");
const chachapoly = @import("chachapoly");

const bench_name = "bench-quic-crypto";
const sizes = [_]usize{ 64, 1200, 1400 };

var in_buf: [1500]u8 = undefined;
var out_buf: [1600]u8 = undefined;
var ct_buf: [1600]u8 = undefined;
const hdr = [_]u8{ 0x41, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x12, 0x34 };
const iv: [12]u8 = .{ 0x5b, 0x6e, 0x11, 0x02, 0x7a, 0x33, 0x9c, 0x40, 0x0d, 0xe1, 0x22, 0x47 };

fn Row(comptime A: type) type {
    return struct {
        const P = qc.Protection(A);
        var key: [A.key_length]u8 = undefined;
        var keyed: P.Keyed = undefined;
        var pn: u64 = 0;
        var len: usize = 0;
        var ct_len: usize = 0;

        fn setup(n: usize) void {
            for (&key, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
            P.Keyed.initInto(&keyed, &key, iv);
            len = n;
            pn = 0;
        }

        fn sealStateless() u64 {
            pn +%= 1;
            return P.seal(&key, iv, pn, &hdr, in_buf[0..len], &out_buf) catch unreachable;
        }

        fn sealKeyed() u64 {
            pn +%= 1;
            return keyed.seal(pn, &hdr, in_buf[0..len], &out_buf) catch unreachable;
        }

        fn prepareOpen() void {
            ct_len = P.seal(&key, iv, 42, &hdr, in_buf[0..len], &ct_buf) catch unreachable;
        }

        fn openStateless() u64 {
            return P.open(&key, iv, 42, &hdr, ct_buf[0..ct_len], &out_buf) catch unreachable;
        }

        fn openKeyed() u64 {
            return keyed.open(42, &hdr, ct_buf[0..ct_len], &out_buf) catch unreachable;
        }

        fn gate() !void {
            pn = 98;
            const a = sealStateless();
            var first: [1600]u8 = undefined;
            @memcpy(first[0..a], out_buf[0..a]);
            pn = 98;
            const b = sealKeyed();
            if (a != b or !std.mem.eql(u8, first[0..a], out_buf[0..b])) return error.KeyedDiffers;
            prepareOpen();
            if (openStateless() != openKeyed()) return error.KeyedDiffers;
        }
    };
}

fn ab(io: std.Io, cyc: bench.Cycles, rounds: usize, w: *std.Io.Writer, name: []const u8, comptime a: anytype, comptime b: anytype) !void {
    var sa: bench.Side = .{};
    var sb: bench.Side = .{};
    for (0..rounds) |_| {
        sa.add(bench.timeIt(io, cyc, a, .{}, false));
        sb.add(bench.timeIt(io, cyc, b, .{}, false));
    }
    if (sa.count != sb.count) return error.CountMismatch;
    const by = sa.best_cyc > 0 and sb.best_cyc > 0;
    try w.print("{s:<24} {d:>10.1} {d:>10.1} {d:>8.3} {d:>6.1}%\n", .{ name, sa.best_ns, sb.best_ns, sb.best(by) / sa.best(by), 100 * @max(sa.spread(by), sb.spread(by)) });
    try w.flush();
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;
    for (&in_buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);

    var obuf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &obuf);
    const w = &fw.interface;

    inline for (.{ aesgcm.Aes128Gcm, chachapoly.ChaCha20Poly1305 }) |A| {
        Row(A).setup(64);
        try Row(A).gate();
    }
    std.debug.print("{s}: gate OK (Keyed = stateless, seal and open)\n", .{bench_name});

    const cyc: bench.Cycles = .open();
    defer cyc.close();
    try w.print("{s:<24} {s:>10} {s:>10} {s:>8} {s:>7}\n", .{ "workload", "stateless", "keyed ns", "keyed/", "spread" });
    inline for (.{ .{ aesgcm.Aes128Gcm, "aes128gcm" }, .{ chachapoly.ChaCha20Poly1305, "chacha20" } }) |pair| {
        const R = Row(pair[0]);
        inline for (sizes) |n| {
            const seal_name = std.fmt.comptimePrint("seal_{s}_{d}", .{ pair[1], n });
            if (bench.selected(seal_name, filters)) {
                R.setup(n);
                try ab(io, cyc, rounds, w, seal_name, R.sealStateless, R.sealKeyed);
            }
            const open_name = std.fmt.comptimePrint("open_{s}_{d}", .{ pair[1], n });
            if (bench.selected(open_name, filters)) {
                R.setup(n);
                R.prepareOpen();
                try ab(io, cyc, rounds, w, open_name, R.openStateless, R.openKeyed);
            }
        }
    }
    try w.print("rounds: {d}; ratio = keyed / stateless ({s}); a claim needs the spread below the effect\n", .{ rounds, if (cyc.fd != null) "user-mode cycles" else "wall time" });
    try w.flush();
    return 0;
}
