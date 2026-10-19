// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tlsclient` against Go's `crypto/tls` client (the
//! reference named by the maturity card; Go 1.26 standard library only), the
//! program behind the `**Performance:**` line of the card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tlsclient` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (`GOTOOLCHAIN=local`, `GOPROXY=off`; stdlib only, `tools/go_bench`) and
//! loopback networking. Run from the repository root.
//!
//! The API takes a `*Reader`/`*Writer` pair and the server's flight depends on
//! the client's random key share, so a handshake cannot be replayed from a
//! recording; both clients therefore talk to a real server: ONE Go
//! `crypto/tls` server process (default config, TLS 1.3, certificate chains
//! it generates at start: `ecdsa256` = ECDSA P-256 root/intermediate/leaf,
//! `rsa2048` = RSA-2048 throughout; SAN `bench.example.test`), which both
//! sides use alike over 127.0.0.1.
//!
//! Workload `handshake_<kind>` = one complete client handshake: TCP connect,
//! ClientHello (with the library's default key shares), server flight read,
//! chain verified against the root and the name `bench.example.test`, client
//! Finished written, close. Ours: `Client.init` over a std.Io.net stream with
//! the root in a `Certificate.Bundle`; theirs: `tls.Client(...).Handshake()`
//! with the root in a `CertPool`, TLS 1.3 asserted. No application data, no
//! resumption on either side.
//!
//! What is measured: the CLIENT thread's user-mode cycles per handshake (ours
//! `perf_event_open` on the calling thread, Go's the same on its pinned
//! (`LockOSThread`) goroutine thread) -- not wall time, which would be
//! dominated by the server's work and round trips that are identical for both
//! and dilute the ratio. Kernel time (socket syscalls) is excluded on both
//! sides. Go's GC and runtime threads are therefore not counted; ours
//! allocates nothing on the heap.
//!
//! ⚠ Caveats worth knowing when reading the ratio: the two clients may not
//! offer identical key-share groups (the Zig std-derived key share set versus
//! Go's default list including a hybrid ML-KEM group), and the negotiated
//! cipher suite is the server's choice (Go server prefers AES-GCM with
//! hardware support); the count is 1 per handshake.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side.
//! Before timing anything a handshake with the right name must succeed and
//! one with a wrong name must fail on our side. Arguments filter workloads by
//! substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const tlsclient = @import("tlsclient");
const Client = tlsclient.Client;

const bench_name = "bench-tlsclient";
const work_dir = ".zig-cache/bench-tlsclient";
const go_dir = "modules/tlsclient/tools/go_bench";
const host = "bench.example.test";
const kinds = [_][]const u8{ "ecdsa256", "rsa2048" };

const Op = struct { kind: usize };

const Ctx = struct {
    io: std.Io,
    ports: [kinds.len]u16,
    bundles: [kinds.len]std.crypto.Certificate.Bundle,
    lock: std.Io.RwLock = .init,
    op: Op = undefined,
};

fn handshake(x: *Ctx, kind: usize, name: []const u8) !void {
    const io = x.io;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", x.ports[kind]);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var net_in: [Client.min_buffer_len]u8 = undefined;
    var net_out: [Client.min_buffer_len]u8 = undefined;
    var tls_in: [Client.min_buffer_len]u8 = undefined;
    var tls_out: [Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_in);
    var sw = stream.writer(io, &net_out);
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    _ = try Client.init(&sr.interface, &sw.interface, .{
        .host = .{ .explicit = name },
        .ca = .{ .bundle = .{ .gpa = std.heap.smp_allocator, .io = io, .lock = &x.lock, .bundle = &x.bundles[kind] } },
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
    });
}

fn once(x: *Ctx) usize {
    handshake(x, x.op.kind, host) catch |e| {
        std.debug.print("{s}: handshake failed: {t}\n", .{ bench_name, e });
        std.process.exit(1);
    };
    return 1;
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

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const build = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, build.stderr });
        return 1;
    }

    // The Go server, until we are done (killed on every exit path).
    var server = try std.process.spawn(io, .{
        .argv = &.{ exe, abs, "serve" },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    defer server.kill(io);
    {
        var buf: [256]u8 = undefined;
        var r = server.stdout.?.reader(io, &buf);
        const line = (try r.interface.takeDelimiter('\n')) orelse {
            std.debug.print("{s}: the Go server exited before it was ready\n", .{bench_name});
            return 1;
        };
        if (!std.mem.eql(u8, std.mem.trim(u8, line, " \r"), "READY")) return error.BadServerBanner;
    }

    const ctx = try arena.create(Ctx);
    ctx.* = .{ .io = io, .ports = undefined, .bundles = undefined };
    const now = std.Io.Clock.real.now(io);
    for (kinds, 0..) |k, i| {
        const port_txt = try dir.readFileAlloc(io, try arena.print("port_{s}.txt", .{k}), arena, .limited(16));
        ctx.ports[i] = try std.fmt.parseInt(u16, std.mem.trim(u8, port_txt, " \n"), 10);
        ctx.bundles[i] = .empty;
        try ctx.bundles[i].addCertsFromFilePath(arena, io, now, dir, try arena.print("root_{s}.pem", .{k}));
    }

    // Sanity before timing: the right name works, a wrong one is refused.
    for (kinds, 0..) |k, i| {
        handshake(ctx, i, host) catch |e| {
            std.debug.print("{s}: FAILED -- our client cannot handshake with the Go server ({s}): {t}\n", .{ bench_name, k, e });
            return 1;
        };
        if (handshake(ctx, i, "other.example.test")) |_| {
            std.debug.print("{s}: FAILED -- a wrong server name was accepted ({s})\n", .{ bench_name, k });
            return 1;
        } else |_| {}
    }

    var ws: std.ArrayList(Work) = .empty;
    for (kinds, 0..) |k, i| {
        const name = try arena.print("handshake_{s}", .{k});
        try ws.append(arena, .{ .name = name, .op = .{ .kind = i }, .ref = name });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/Go = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go <version> crypto/tls client (handshake, client CPU) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
