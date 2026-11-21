// SPDX-License-Identifier: MIT

//! Record-protection benchmark for `dtls`: the per-record AEAD call the engine
//! makes today against a cached AEAD context, and the whole `send` + `recv`
//! path of a connected pair. It answers the SPEC Backlog question "would a
//! per-epoch cached AEAD context pay?" with numbers; it compares the module
//! with itself, not with a foreign stack (`zig build interop-dtls` is the
//! third-party check).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-dtls` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. It needs nothing
//! outside this repository. Arguments filter workloads by substring.
//!
//! Workloads, per AEAD and record payload size (64, 256, 1024, 1400 bytes):
//!   seal_<aead>_<n>   `aead.Protection(A).protect` (the engine's call: the
//!                     key schedule of the AEAD runs on every record, under the
//!                     module's stack burn) against `A.Context.init` once +
//!                     `Context.encrypt` per record (the cached shape). Only
//!                     for the AES-GCM suites: std's ChaCha20-Poly1305 has no
//!                     per-key state to cache.
//!   open_<aead>_<n>   the same for `unprotect` / `Context.decrypt`.
//!   conn_<suite>_<n>  info: one `Connection.send` + `Connection.recv` of an
//!                     n-byte message on a connected PSK pair (header, sequence
//!                     number encryption, replay window, both AEAD calls).
//!
//! Before anything is timed, the cached context must produce the same
//! ciphertext and tag as the per-record call (the gate). Method: `benchkit
//! .timeIt` (batch doubled past 100 ms, best of five); per workload the two
//! sides alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its
//! best; the ratio is cached / per-record by user-mode cycles (wall time when
//! the counter is unavailable), the spread (worst round − best round) / best
//! round, the larger of the two sides'. A ratio claim needs the spread below
//! the effect.

const std = @import("std");
const bench = @import("benchkit");
const dtls = @import("dtls");
const aesgcm = @import("aesgcm");

const bench_name = "bench-dtls";
const sizes = [_]usize{ 64, 256, 1024, 1400 };

const Aes128Gcm = aesgcm.Aes128Gcm;
const Aes256Gcm = aesgcm.Aes256Gcm;

var in_buf: [1500]u8 = undefined;
var out_buf: [1600]u8 = undefined;
var ct_buf: [1600]u8 = undefined;
const aad = [_]u8{ 0x2e, 0x00, 0x01, 0x05, 0x6c }; // a unified header with a length
const iv: [12]u8 = .{ 0x5b, 0x6e, 0x11, 0x02, 0x7a, 0x33, 0x9c, 0x40, 0x0d, 0xe1, 0x22, 0x47 };

fn Seal(comptime A: type) type {
    return struct {
        const P = dtls.aead.Protection(A);
        var key: [A.key_length]u8 = undefined;
        var ctx: A.Context = undefined;
        var seq: u64 = 0;
        var len: usize = 0;
        var ct_len: usize = 0;

        fn setup(n: usize) void {
            for (&key, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
            ctx = A.Context.init(key);
            len = n;
            seq = 0;
        }

        fn perRecord() u64 {
            seq +%= 1;
            return P.protect(&key, iv, 3, seq, in_buf[0..len], &aad, &out_buf) catch unreachable;
        }

        fn cached() u64 {
            seq +%= 1;
            const npub = P.nonce(iv, 3, seq);
            var tag: [A.tag_length]u8 = undefined;
            ctx.encrypt(out_buf[0..len], &tag, in_buf[0..len], &aad, npub);
            out_buf[len..][0..A.tag_length].* = tag;
            return len + A.tag_length;
        }

        /// One fixed ciphertext for the open rows.
        fn prepareOpen() void {
            ct_len = P.protect(&key, iv, 3, 42, in_buf[0..len], &aad, &ct_buf) catch unreachable;
        }

        fn openPerRecord() u64 {
            return P.unprotect(&key, iv, 3, 42, ct_buf[0..ct_len], &aad, &out_buf) catch unreachable;
        }

        fn openCached() u64 {
            const npub = P.nonce(iv, 3, 42);
            const body = ct_len - A.tag_length;
            ctx.decrypt(out_buf[0..body], ct_buf[0..body], ct_buf[body..][0..A.tag_length].*, &aad, npub) catch unreachable;
            return body;
        }

        /// The gate: same bytes from both shapes.
        fn gate() !void {
            seq = 99;
            const a = perRecord();
            var first: [1600]u8 = undefined;
            @memcpy(first[0..a], out_buf[0..a]);
            seq = 99;
            const b = cached();
            if (a != b or !std.mem.eql(u8, first[0..a], out_buf[0..b])) return error.CachedContextDiffers;
            prepareOpen();
            if (openPerRecord() != openCached()) return error.CachedContextDiffers;
        }
    };
}

// ── the connected pair ──────────────────────────────────────────────────────

var client: dtls.Connection = undefined;
var server: dtls.Connection = undefined;
var wire: [1600]u8 = undefined;
var plain: [1600]u8 = undefined;
var conn_len: usize = 0;

fn connect(suite: dtls.CipherSuite) !void {
    const suites = [_]dtls.CipherSuite{suite};
    client = try dtls.Connection.clientInit(.{ .role = .client, .psk_identity = "bench", .psk = "a bench pre-shared key", .psk_hash = suite.hash(), .cipher_suites = &suites });
    server = try dtls.Connection.serverInit(.{ .role = .server, .psk_identity = "bench", .psk = "a bench pre-shared key", .psk_hash = suite.hash(), .cipher_suites = &suites });
    var csprng = std.Random.DefaultCsprng.init(@splat(0xbe));
    const rnd: dtls.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &b1);
    const f2 = try server.handleFlight(ch, rnd, 0, &b2);
    const fin = try client.handleFlight(f2.out, rnd, 0, &b1);
    const done = try server.handleFlight(fin.out, rnd, 0, &b2);
    if (!fin.done or !done.done) return error.HandshakeDidNotComplete;
}

fn sendRecv() u64 {
    const rec = client.send(in_buf[0..conn_len], &wire) catch unreachable;
    const got = server.recv(rec, &plain) catch unreachable;
    return got.len;
}

// ── driver ──────────────────────────────────────────────────────────────────

fn ab(io: std.Io, cyc: bench.Cycles, rounds: usize, w: *std.Io.Writer, name: []const u8, comptime a: anytype, comptime b: anytype) !void {
    var sa: bench.Side = .{};
    var sb: bench.Side = .{};
    for (0..rounds) |_| {
        sa.add(bench.timeIt(io, cyc, a, .{}, false));
        sb.add(bench.timeIt(io, cyc, b, .{}, false));
    }
    if (sa.count != sb.count) return error.CountMismatch;
    const by = sa.best_cyc > 0 and sb.best_cyc > 0;
    try w.print("{s:<20} {d:>10.1} {d:>10.1} {d:>8.3} {d:>6.1}%\n", .{ name, sa.best_ns, sb.best_ns, sb.best(by) / sa.best(by), 100 * @max(sa.spread(by), sb.spread(by)) });
    try w.flush();
}

fn single(io: std.Io, cyc: bench.Cycles, rounds: usize, w: *std.Io.Writer, name: []const u8, comptime a: anytype) !void {
    var sa: bench.Side = .{};
    for (0..rounds) |_| sa.add(bench.timeIt(io, cyc, a, .{}, false));
    const by = sa.best_cyc > 0;
    try w.print("{s:<20} {d:>10.1} {s:>10} {s:>8} {d:>6.1}%  (info)\n", .{ name, sa.best_ns, "-", "-", 100 * sa.spread(by) });
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

    inline for (.{ Aes128Gcm, Aes256Gcm }) |A| {
        Seal(A).setup(64);
        try Seal(A).gate();
    }
    std.debug.print("{s}: gate OK (cached AES-GCM context = per-record call, seal and open)\n", .{bench_name});

    const cyc: bench.Cycles = .open();
    defer cyc.close();
    try w.print("{s:<20} {s:>10} {s:>10} {s:>8} {s:>7}\n", .{ "workload", "per-rec ns", "cached ns", "cached/", "spread" });
    inline for (.{ .{ Aes128Gcm, "aes128gcm" }, .{ Aes256Gcm, "aes256gcm" } }) |pair| {
        const S = Seal(pair[0]);
        inline for (sizes) |n| {
            const seal_name = std.fmt.comptimePrint("seal_{s}_{d}", .{ pair[1], n });
            if (bench.selected(seal_name, filters)) {
                S.setup(n);
                try ab(io, cyc, rounds, w, seal_name, S.perRecord, S.cached);
            }
            const open_name = std.fmt.comptimePrint("open_{s}_{d}", .{ pair[1], n });
            if (bench.selected(open_name, filters)) {
                S.setup(n);
                S.prepareOpen();
                try ab(io, cyc, rounds, w, open_name, S.openPerRecord, S.openCached);
            }
        }
    }
    inline for (.{ .{ dtls.CipherSuite.aes_128_gcm_sha256, "aes128gcm" }, .{ dtls.CipherSuite.chacha20_poly1305_sha256, "chacha20" } }) |pair| {
        inline for (sizes) |n| {
            const name = std.fmt.comptimePrint("conn_{s}_{d}", .{ pair[1], n });
            if (bench.selected(name, filters)) {
                try connect(pair[0]);
                conn_len = n;
                try single(io, cyc, rounds, w, name, sendRecv);
            }
        }
    }
    try w.print("rounds: {d}; ratio = cached / per-record ({s}); a claim needs the spread below the effect\n", .{ rounds, if (cyc.fd != null) "user-mode cycles" else "wall time" });
    try w.flush();
    return 0;
}
