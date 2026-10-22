// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tlsserver.Server` against OpenSSL 3's libssl TLS
//! 1.3 server (the reference named by the maturity card) and against rustls
//! over aws-lc-rs (the fastest in the field, the `alt` column), the program
//! behind the `**Performance:**` line of the card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! What is timed is the SERVER's work only. Each side first records a session
//! — its own client against its own server, in memory, the server's
//! randomness from a fixed seed — and each timed op replays the client's
//! octets into a fresh server: here `tlsclient` against `Server` with
//! `Config.random` reset per connection; on the OpenSSL side
//! (`tools/c_bench/foreign_bench.c`) an OpenSSL client against an OpenSSL
//! server with a deterministic `RAND_METHOD`. Before anything is timed each
//! side replays once and checks that its server sends exactly the recorded
//! octets (and the negotiated suite, group and resumption); the clients
//! differ, the server's work does not (same certificate and key, same suite,
//! group and signature scheme, one ticket per handshake where tickets are on,
//! stateless tickets, no session cache).
//!
//! The rustls side (`tools/rust_bench`, read its header) cannot replay:
//! aws-lc takes ECDSA nonces, RSA-PSS salts and ephemeral keys from its own
//! RNG. Each of its handshake ops is a fresh rustls client and server in
//! memory, and only the server's calls are timed.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tlsserver` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds the C side with `zig cc -O3 -march=native`), `cargo` with rustls
//! 0.23.43 and aws-lc-rs 1.18.0 in the local registry (built offline into
//! `.zig-cache/bench-tlsserver/target`), and the system OpenSSL 3
//! (`libssl.so.3` + `libcrypto.so.3`, paths below or `LIBSSL_SO` /
//! `LIBCRYPTO_SO`; no headers needed). Run from the repository root.
//!
//! Workloads (TLS_AES_256_GCM_SHA384 throughout):
//!   hs_p256        full handshake, ECDSA P-256 certificate, X25519
//!   hs_p256_mlkem  the same over X25519MLKEM768
//!   hs_rsa2048     full handshake, RSA-2048 certificate (rsa_pss_rsae_sha256)
//!   resumed        a ticket resumed (psk_dhe_ke over X25519), one ticket issued
//!   send_16k       one 16384-octet application data record sealed
//!   recv_16k       one such record opened
//! The count is 1 per handshake and the plaintext octets per bulk record.
//! The bulk rows replace their connection (a timed replay) every `pool`
//! records, as the C side does: the sequence numbers start over under the
//! same keys, so the client records sealed once open again (~1 % of a bulk
//! op). The certificates and keys are `tlsserver.test_fixtures`, written into
//! `.zig-cache/bench-tlsserver/` as DER for OpenSSL.
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over
//! 100 ms and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the spread
//! printed is (worst round − best round) / best round per side. Ratios are
//! ours/theirs by user-mode cycles when both sides count them, else by wall
//! time; `/fast` is ours over the faster of OpenSSL and rustls. Arguments
//! filter workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const tlsserver = @import("tlsserver");
const tlsresume = @import("tlsresume");
const rsa = @import("rsa");
const ZlClient = @import("tlsclient").Client;

const Server = tlsserver.Server;
const certs = tlsserver.test_fixtures;
const Work = bench.Work(Op);

const bench_name = "bench-tlsserver";
const cargo_manifest = "modules/tlsserver/tools/rust_bench/Cargo.toml";
const work_dir = ".zig-cache/bench-tlsserver";
const default_ssl = "/usr/lib/x86_64-linux-gnu/libssl.so.3";
const default_crypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";

/// Records per bulk connection (as `pool` in foreign_bench.c).
const pool = 2048;
const rec = 16384;
const seed: u8 = 0x5e;
const clock_ms: i64 = 1_900_000_000_000;
const x25519: u16 = 0x001d;
const x25519_mlkem768: u16 = 0x11ec;

const Case = enum { hs_p256, hs_p256_mlkem, hs_rsa2048, resumed, send_16k, recv_16k };
const Op = Case;

fn clock(_: ?*anyopaque) i64 {
    return clock_ms;
}

/// One case's server and its recording.
const Ctx = struct {
    gpa: std.mem.Allocator,
    op: Op = undefined,
    p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    rsa_key: rsa.SecretKey,
    chain: [1][]const u8 = undefined,
    ck: tlsserver.CertifiedKey = undefined,
    groups: [1]u16 = undefined,
    schemes: [1]u16 = undefined,
    csprng: std.Random.DefaultCsprng = undefined,
    ring: tlsresume.stek.DefaultRing = undefined,
    stek: tlsserver.StekTicketer(tlsresume.stek.DefaultRing) = undefined,
    tickets: tlsserver.Tickets = undefined,
    cfg: tlsserver.Config = undefined,
    joiner: []u8,
    /// Sized per case (`setup`): the first flight and a full record.
    out: []u8 = &.{},
    /// The client's octets of the replayed handshake, and a copy to feed
    /// (records are opened in place).
    hs_in: []u8 = &.{},
    hs_out: []u8 = &.{},
    scratch: []u8,
    /// `pool` client records (recv_16k).
    recs: []u8 = &.{},
    plain: []u8,
    bulk: ?Server = null,
    bulk_left: usize = 0,
    rec_at: usize = 0,
};

/// A fresh server fed the recorded handshake. The output is dropped, or
/// kept in `keep`.
fn replay(x: *Ctx, keep: ?*std.ArrayList(u8)) !Server {
    x.csprng = .init(@splat(seed));
    var s: Server = .init(&x.cfg, x.joiner, x.out);
    errdefer s.deinit();
    const buf = x.scratch[0..x.hs_in.len];
    @memcpy(buf, x.hs_in);
    var at: usize = 0;
    while (true) {
        const r = try s.feed(buf[at..]);
        at += r.consumed;
        const o = s.pendingOutput();
        if (keep) |k| try k.appendSlice(x.gpa, o);
        s.discardOutput(o.len);
        switch (r.event) {
            .handshake_done => break,
            .need_more => return error.ReplayShort,
            else => return error.ReplayUnexpected,
        }
    }
    if (at != buf.len) return error.ReplayLeftover;
    return s;
}

fn opHandshake(x: *Ctx) !usize {
    var s = try replay(x, null);
    s.deinit();
    return 1;
}

fn bulkRenew(x: *Ctx) !void {
    if (x.bulk) |*s| s.deinit();
    x.bulk = try replay(x, null);
    x.bulk_left = pool;
    x.rec_at = 0;
}

fn opSend(x: *Ctx) !usize {
    if (x.bulk_left == 0) try bulkRenew(x);
    x.bulk_left -= 1;
    const s = &x.bulk.?;
    const n = try s.write(x.plain);
    s.discardOutput(s.pendingOutput().len);
    return n;
}

fn opRecv(x: *Ctx) !usize {
    if (x.bulk_left == 0) try bulkRenew(x);
    x.bulk_left -= 1;
    const len = record_len;
    const buf = x.scratch[0..len];
    @memcpy(buf, x.recs[x.rec_at..][0..len]);
    x.rec_at += len;
    const r = try x.bulk.?.feed(buf);
    return switch (r.event) {
        .app_data => |d| d.len,
        else => error.NotAppData,
    };
}

const record_len = 5 + rec + 1 + 16;

fn once(x: *Ctx) usize {
    const r = switch (x.op) {
        .hs_p256, .hs_p256_mlkem, .hs_rsa2048, .resumed => opHandshake(x),
        .send_16k => opSend(x),
        .recv_16k => opRecv(x),
    };
    return r catch |err| std.debug.panic("{s}: {t} in {t}", .{ bench_name, err, x.op });
}

// ---- recording: tlsclient ↔ Server in memory ----

/// The server end of the pipes behind the client's input `Reader` (as in
/// `handshake_test.zig`), keeping every octet the server consumed until its
/// handshake was done.
const Pipe = struct {
    reader: std.Io.Reader,
    reader_buf: [ZlClient.min_buffer_len]u8 = undefined,
    client_out: std.Io.Writer.Allocating,
    server: *Server,
    gpa: std.mem.Allocator,
    /// Received and not yet consumed (a raw copy beside it: records are
    /// opened in place).
    pending: std.ArrayList(u8) = .empty,
    raw: std.ArrayList(u8) = .empty,
    hs_in: std.ArrayList(u8) = .empty,
    hs_out: std.ArrayList(u8) = .empty,
    done: bool = false,

    fn pump(p: *Pipe) !void {
        const w = p.client_out.written();
        try p.pending.appendSlice(p.gpa, w);
        try p.raw.appendSlice(p.gpa, w);
        p.client_out.shrinkRetainingCapacity(0);
        while (true) {
            const r = try p.server.feed(p.pending.items);
            if (!p.done) try p.hs_in.appendSlice(p.gpa, p.raw.items[0..r.consumed]);
            switch (r.event) {
                .handshake_done => p.done = true,
                .need_more, .app_data, .peer_closed => {},
                .early_data_accepted, .early_data => return error.UnexpectedEarlyData,
            }
            dropFront(&p.pending, r.consumed);
            dropFront(&p.raw, r.consumed);
            if (r.event == .need_more) break;
        }
    }

    fn dropFront(l: *std.ArrayList(u8), n: usize) void {
        std.mem.copyForwards(u8, l.items[0 .. l.items.len - n], l.items[n..]);
        l.shrinkRetainingCapacity(l.items.len - n);
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const p: *Pipe = @fieldParentPtr("reader", r);
        p.pump() catch return error.ReadFailed;
        const out = p.server.pendingOutput();
        if (out.len == 0) return error.EndOfStream;
        const dst = w.writableSliceGreedy(1) catch return error.WriteFailed;
        const m = @min(limit.minInt(out.len), dst.len);
        @memcpy(dst[0..m], out[0..m]);
        p.hs_out.appendSlice(p.gpa, out[0..m]) catch return error.ReadFailed;
        w.advance(m);
        p.server.discardOutput(m);
        return m;
    }

    fn deinit(p: *Pipe) void {
        p.client_out.deinit();
        p.pending.deinit(p.gpa);
        p.raw.deinit(p.gpa);
        p.hs_in.deinit(p.gpa);
        p.hs_out.deinit(p.gpa);
    }
};

/// One recorded connection; keeps its handshake octets in `x` and, when
/// `with_pool`, the client's `pool` records after it.
fn record(x: *Ctx, cache: *ZlClient.SessionCache, want_resumed: bool, with_pool: bool) !void {
    const gpa = x.gpa;
    x.csprng = .init(@splat(seed));
    var server: Server = .init(&x.cfg, x.joiner, x.out);
    defer server.deinit();
    const p = try gpa.create(Pipe);
    defer gpa.destroy(p);
    p.* = .{ .reader = undefined, .client_out = try .initCapacity(gpa, 64 * 1024), .server = &server, .gpa = gpa };
    defer p.deinit();
    p.reader = .{ .vtable = &.{ .stream = Pipe.stream }, .buffer = &p.reader_buf, .seek = 0, .end = 0 };

    var entropy: [ZlClient.Options.entropy_len]u8 = @splat(0xc1);
    var read_buf: [ZlClient.min_buffer_len]u8 = undefined;
    var write_buf: [ZlClient.min_buffer_len]u8 = undefined;
    const group: std.crypto.tls.NamedGroup = @fromBackingInt(x.groups[0]);
    var storage: [16 * 1024]u8 = undefined;
    var info: ZlClient.ConnectionInfo = .init(&storage);
    var client = try ZlClient.init(&p.reader, &p.client_out.writer, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = .fromNanoseconds(@as(i96, clock_ms) * std.time.ns_per_ms),
        .min_version = .tls_1_3,
        .groups = &.{group},
        .key_share_groups = &.{group},
        .connection_info = &info,
        .session_cache = cache,
        .request_ocsp = false,
        .request_scts = false,
    });
    try p.pump();
    if (!p.done) return error.HandshakeNotDone;
    if (x.cfg.tickets != null) {
        // The client takes the ticket on its first read.
        var b: [1]u8 = undefined;
        _ = client.reader.readSliceShort(&b) catch {};
    }
    try p.hs_out.appendSlice(gpa, server.pendingOutput());
    if (server.cipherSuite().? != .aes_256_gcm_sha384) return error.WrongSuite;
    if (server.negotiatedGroup().? != x.groups[0]) return error.WrongGroup;
    x.gpa.free(x.hs_in);
    x.gpa.free(x.hs_out);
    x.hs_in = try gpa.dupe(u8, p.hs_in.items);
    x.hs_out = try gpa.dupe(u8, p.hs_out.items);
    if (server.isResumed() != want_resumed or info.did_resume != want_resumed) return error.WrongResumption;
    if (with_pool) {
        p.client_out.shrinkRetainingCapacity(0);
        for (0..pool) |_| {
            try client.writer.writeAll(x.plain);
            try client.writer.flush();
        }
        x.recs = try gpa.dupe(u8, p.client_out.written());
        if (x.recs.len != pool * record_len) return error.PoolRecordSize;
    }
}

fn setup(x: *Ctx, c: Case) !void {
    x.op = c;
    x.groups = .{if (c == .hs_p256_mlkem) x25519_mlkem768 else x25519};
    if (c == .hs_rsa2048) {
        x.chain = .{&certs.rsa2048_cert};
        x.schemes = .{0x0804}; // rsa_pss_rsae_sha256
        x.ck = .{ .chain = &x.chain, .key = .{ .rsa = &x.rsa_key }, .signature_schemes = &x.schemes };
    } else {
        x.chain = .{&certs.p256_cert};
        x.schemes = .{0x0403}; // ecdsa_secp256r1_sha256
        x.ck = .{ .chain = &x.chain, .key = .{ .ecdsa_p256 = &x.p256 }, .signature_schemes = &x.schemes };
    }
    x.ring = .init();
    x.ring.rotate(1, &@as([32]u8, @splat(0x5e)), @divFloor(clock_ms, 1000));
    x.stek = .{ .ring = &x.ring };
    x.tickets = .{ .ticketer = x.stek.ticketer(), .clock = .{ .now_ms = clock }, .count = 1 };
    x.cfg = .{
        .certificate = .{ .fixed = &x.ck },
        .cipher_suites = &.{.aes_256_gcm_sha384},
        .groups = &x.groups,
        .random = x.csprng.random(),
        .tickets = if (c == .resumed) &x.tickets else null,
    };
    if (x.bulk) |*s| s.deinit();
    x.bulk = null;
    x.bulk_left = 0;
    x.out = try x.gpa.alloc(u8, tlsserver.server.minOutputLen(&x.cfg, &x.ck) + tlsserver.server.full_record_output_len);

    const entries = try x.gpa.alloc(ZlClient.ClientSession, 2);
    defer x.gpa.free(entries);
    var cache: ZlClient.SessionCache = .init(entries, null);
    defer cache.deinit();
    try record(x, &cache, false, c == .recv_16k);
    if (c == .resumed) try record(x, &cache, true, false);
    // The replay must give the recorded server octets back.
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(x.gpa);
    var s = try replay(x, &got);
    defer s.deinit();
    if (!std.mem.eql(u8, got.items, x.hs_out)) {
        std.debug.print("{s}: {t}: the replayed server is not the recorded one ({d} vs {d} octets)\n", .{ bench_name, c, got.items.len, x.hs_out.len });
        return error.ReplayDiffers;
    }
    if (s.isResumed() != (c == .resumed)) return error.WrongResumption;
    if (c == .recv_16k) {
        var at: usize = 0;
        for (0..pool) |_| {
            const buf = x.scratch[0..record_len];
            @memcpy(buf, x.recs[at..][0..record_len]);
            at += record_len;
            const r = try s.feed(buf);
            if (r.event != .app_data or !std.mem.eql(u8, r.event.app_data, x.plain)) return error.PoolDiffers;
        }
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    // OpenSSL's inputs: the certificates as DER, the P-256 key as a SEC1
    // ECPrivateKey (RFC 5915: version 1, the scalar, the curve's OID),
    // the RSA key as PKCS#1.
    try dir.writeFile(io, .{ .sub_path = "p256_cert.der", .data = &certs.p256_cert });
    try dir.writeFile(io, .{ .sub_path = "p256_key.der", .data = &(.{ 0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ certs.p256_scalar ++ .{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }) });
    try dir.writeFile(io, .{ .sub_path = "rsa2048_cert.der", .data = &certs.rsa2048_cert });
    try dir.writeFile(io, .{ .sub_path = "rsa2048_key.der", .data = &certs.rsa2048_pkcs1 });

    const ssl_so = init.environ_map.get("LIBSSL_SO") orelse default_ssl;
    const crypto_so = init.environ_map.get("LIBCRYPTO_SO") orelse default_crypto;
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/tlsserver/tools/c_bench/foreign_bench.c", &.{ ssl_so, crypto_so });
    // OpenSSL records and checks its replays before anything is timed.
    try bench.foreignOnce(arena, io, bench_name, exe, abs, "interop");
    // rustls: built once, offline; checks what each workload negotiates.
    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const cargo = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (cargo.term != .exited or cargo.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, cargo.stderr });
        return 1;
    }
    const rust_exe = try arena.print("{s}/release/rust_bench", .{target});
    try bench.foreignOnce(arena, io, bench_name, rust_exe, abs, "interop");

    const x = try arena.create(Ctx);
    x.* = .{
        .gpa = arena,
        .p256 = try .fromBytes(certs.p256_scalar),
        .rsa_key = undefined,
        .joiner = try arena.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message)),
        .scratch = try arena.alloc(u8, 64 * 1024),
        .plain = try arena.alloc(u8, rec),
    };
    try rsa.SecretKey.fromDer(&x.rsa_key, &certs.rsa2048_pkcs1);
    for (x.plain, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    // One case at a time: `setup` records it, then `drive` times it alone.
    var total: bench.Summary = .{};
    for (std.enums.values(Case)) |c| {
        const name = @tagName(c);
        if (!bench.selected(name, filters)) continue;
        try setup(x, c);
        const ws = [_]Work{.{ .name = name, .op = c, .ref = name, .alt = name, .alt_exe = 1 }};
        var line: std.Io.Writer.Allocating = .init(arena);
        const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ exe, rust_exe }, .abs = abs, .rounds = rounds }, x, once, &ws, &line.writer);
        // `drive` prints a header and a rounds line per call: keep the row.
        var it = std.mem.splitScalar(u8, line.written(), '\n');
        _ = it.next();
        try w.print("{s}\n", .{it.next().?});
        try w.flush();
        total.banner = s.banner;
        total.by_cycles = total.by_cycles and s.by_cycles;
        total.max_spread = @max(total.max_spread, s.max_spread);
        total.best_ref = @min(total.best_ref, s.best_ref);
        total.worst_ref = @max(total.worst_ref, s.worst_ref);
        total.alt_banner = s.alt_banner;
        if (s.worst_fast) |f| total.worst_fast = @max(total.worst_fast orelse 0, f);
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (total.by_cycles) "user-mode cycles" else "wall time", 100 * total.max_spread, if (total.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.print("reference: {s}\ncandidate: {s}\nworst ours/OpenSSL = {d:.3} (best {d:.3}); worst ours/min(OpenSSL, rustls) = {d:.3}\n", .{ std.mem.trimEnd(u8, total.banner, "\n"), std.mem.trimEnd(u8, total.alt_banner, "\n"), total.worst_ref, total.best_ref, total.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> libssl (server side, replayed sessions: full handshake P-256/RSA-2048/X25519MLKEM768, resumption, AES-256-GCM 16 KiB records) · fastest {d:.2}× worst vs the faster of OpenSSL and rustls 0.23.43 + aws-lc-rs 1.18.0 (measured <today>)\n", .{ total.best_ref, total.worst_ref, total.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
