// SPDX-License-Identifier: MIT

//! Transport-message benchmark for `noise`: `CipherState.encryptWithAd` /
//! `decryptWithAd` on `Noise_*_AESGCM_*` with the AES-GCM key schedule kept in
//! the `CipherState` (`aesgcm.Aes256Gcm`, which carries a keyed `Context`)
//! against the same AEAD seen through a wrapper without `Context` (the
//! stateless call: the key schedule runs on every message, as before the
//! cache). It compares the module with itself; the spec vectors in `src/` are
//! the correctness check, and the gate below checks the two shapes agree
//! before anything is timed.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-noise` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. It needs nothing
//! outside this repository. Arguments filter workloads by substring.
//!
//! Workloads: enc_aesgcm_<n> / dec_aesgcm_<n>, n = 64, 1024, 65519 payload
//! bytes (65519 + 16 = Noise's 65535-byte message limit). Method as `dtls`'s
//! bench: `benchkit.timeIt`, the two sides alternate for `BENCH_ROUNDS`
//! rounds, ratio = keyed / stateless by user-mode cycles, spread = (worst -
//! best) / best.

const std = @import("std");
const bench = @import("benchkit");
const noise = @import("noise");
const aesgcm = @import("aesgcm");

const bench_name = "bench-noise";
const sizes = [_]usize{ 64, 1024, 65519 };

/// `aesgcm.Aes256Gcm` without its `Context`: `CipherState` takes the
/// stateless per-message call.
const StatelessAes256Gcm = struct {
    const A = aesgcm.Aes256Gcm;
    pub const noise_name = "AESGCM";
    pub const noise_stack_bytes = 2048;
    pub const key_length = A.key_length;
    pub const nonce_length = A.nonce_length;
    pub const tag_length = A.tag_length;
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        A.encrypt(c, tag, m, ad, npub, k);
    }
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) !void {
        return A.decrypt(m, c, tag, ad, npub, k);
    }
};

const Keyed = noise.Suite(std.crypto.dh.X25519, aesgcm.Aes256Gcm, std.crypto.hash.sha2.Sha256);
const Plain = noise.Suite(std.crypto.dh.X25519, StatelessAes256Gcm, std.crypto.hash.sha2.Sha256);

var in_buf: [65519]u8 = undefined;
var out_buf: [65535]u8 = undefined;
var ct_buf: [65535]u8 = undefined;
var back_buf: [65519]u8 = undefined;
const key: [32]u8 = .{ 0x5b, 0x6e, 0x11, 0x02, 0x7a, 0x33, 0x9c, 0x40, 0x0d, 0xe1, 0x22, 0x47, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

var ks: Keyed.CipherState = .{};
var ps: Plain.CipherState = .{};
var len: usize = 0;

fn setup(n: usize) void {
    ks.initializeKey(&key);
    ps.initializeKey(&key);
    len = n;
}

fn encPlain() u64 {
    ps.encryptWithAd("ad", in_buf[0..len], out_buf[0 .. len + 16]) catch unreachable;
    return len;
}
fn encKeyed() u64 {
    ks.encryptWithAd("ad", in_buf[0..len], out_buf[0 .. len + 16]) catch unreachable;
    return len;
}

fn prepareDec() void {
    var s: Plain.CipherState = .{};
    s.initializeKey(&key);
    s.setNonce(7);
    s.encryptWithAd("ad", in_buf[0..len], ct_buf[0 .. len + 16]) catch unreachable;
}
fn decPlain() u64 {
    ps.setNonce(7);
    ps.decryptWithAd("ad", ct_buf[0 .. len + 16], back_buf[0..len]) catch unreachable;
    return len;
}
fn decKeyed() u64 {
    ks.setNonce(7);
    ks.decryptWithAd("ad", ct_buf[0 .. len + 16], back_buf[0..len]) catch unreachable;
    return len;
}

fn gate() !void {
    setup(1024);
    ps.setNonce(98);
    _ = encPlain();
    var first: [1024 + 16]u8 = undefined;
    @memcpy(&first, out_buf[0 .. 1024 + 16]);
    ks.setNonce(98);
    _ = encKeyed();
    if (!std.mem.eql(u8, &first, out_buf[0 .. 1024 + 16])) return error.KeyedDiffers;
    prepareDec();
    _ = decKeyed();
    if (!std.mem.eql(u8, in_buf[0..1024], back_buf[0..1024])) return error.KeyedDiffers;
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

    try gate();
    std.debug.print("{s}: gate OK (cached key schedule = stateless, encrypt and decrypt)\n", .{bench_name});

    const cyc: bench.Cycles = .open();
    defer cyc.close();
    try w.print("{s:<24} {s:>10} {s:>10} {s:>8} {s:>7}\n", .{ "workload", "stateless", "keyed ns", "keyed/", "spread" });
    inline for (sizes) |n| {
        const enc_name = std.fmt.comptimePrint("enc_aesgcm_{d}", .{n});
        if (bench.selected(enc_name, filters)) {
            setup(n);
            try ab(io, cyc, rounds, w, enc_name, encPlain, encKeyed);
        }
        const dec_name = std.fmt.comptimePrint("dec_aesgcm_{d}", .{n});
        if (bench.selected(dec_name, filters)) {
            setup(n);
            prepareDec();
            try ab(io, cyc, rounds, w, dec_name, decPlain, decKeyed);
        }
    }
    try w.print("rounds: {d}; ratio = keyed / stateless ({s}); a claim needs the spread below the effect\n", .{ rounds, if (cyc.fd != null) "user-mode cycles" else "wall time" });
    try w.flush();
    return 0;
}
