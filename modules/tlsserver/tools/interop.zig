// SPDX-License-Identifier: MIT

//! Interop: OpenSSL's `s_client` and Go's crypto/tls client
//! (`tools/go_client/main.go`) — two foreign TLS 1.3 clients — against
//! `tlsserver.Server` over loopback TCP, one connection per case.
//!
//!     zig build interop-tlsserver                     # run every case
//!     zig build interop-tlsserver -- --case p256-aes128
//!     zig build interop-tlsserver -- --capture        # also rewrite
//!                                                     # src/interop_vectors.zig
//!
//! Each case: the server (a seeded CSPRNG, so its output is a function of
//! what it receives) completes the handshake, receives "ping\n", answers
//! "pong\n" and sends close_notify. A case passes when the client exits 0,
//! verified our certificate against the test CA file and SNI `localhost`,
//! printed what the case expects (suite, group, signature type, ALPN) and
//! received "pong" (the Go client also requires the close_notify). With `--capture` every octet each side sent is written
//! to `src/interop_vectors.zig`; the module's hermetic test
//! (`interop_replay_test.zig`) feeds the client's octets to a server with
//! the same seed through `Connection` and requires the same octets back —
//! so "OpenSSL / Go accepted it" keeps being checked in every test lane,
//! with neither there.
//!
//! Needs `openssl` (3.x) and `go` (1.25+: `ConnectionState.CurveID`) on
//! PATH; the Go client is built into `.zig-cache/tlsserver-interop` first
//! (`GOTOOLCHAIN=local`, nothing downloaded). Run from the repository root (`zig build`
//! does) or pass `--repo-root <path>`.

const std = @import("std");
const net = std.Io.net;
const tlsserver = @import("tlsserver");
const rsa = @import("rsa");
const certs = tlsserver.test_fixtures;

const Server = tlsserver.Server;
const record = tlsserver.record;

const usage =
    \\usage: interop-tlsserver [--case NAME]... [--capture] [--list] [--repo-root PATH]
    \\
;

pub const CertKind = enum { p256, p384, ed25519, rsa2048 };

const Peer = enum { openssl, go };

const Case = struct {
    name: []const u8,
    client: Peer = .openssl,
    why: []const u8,
    cert: CertKind = .p256,
    seed: u8,
    suites: []const record.CipherSuite = &tlsserver.server.default_cipher_suites,
    groups: []const u16 = &tlsserver.server.default_groups,
    alpn: []const []const u8 = &.{},
    /// Extra client arguments (`s_client`'s, or go-client's flags).
    args: []const []const u8 = &.{},
    /// Substrings the client must print (its stdout or stderr).
    expect: []const []const u8 = &.{},
    /// `-brief` (a summary on stderr); without it the full session report
    /// goes to stdout — the only place s_client names the ALPN protocol.
    brief: bool = true,
};

const cases = [_]Case{
    .{ .name = "p256-default", .why = "OpenSSL's defaults: its first group (X25519MLKEM768) and suite", .seed = 1, .expect = &.{ "Protocol version: TLSv1.3", "Ciphersuite: TLS_AES_256_GCM_SHA384", "Verification: OK", "Negotiated TLS1.3 group: X25519MLKEM768" } },
    .{ .name = "p256-aes128", .why = "TLS_AES_128_GCM_SHA256 over X25519", .seed = 2, .args = &.{ "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-groups", "X25519" }, .expect = &.{ "Ciphersuite: TLS_AES_128_GCM_SHA256", "Peer Temp Key: X25519" } },
    .{ .name = "p256-chacha", .why = "TLS_CHACHA20_POLY1305_SHA256 over secp256r1", .seed = 3, .args = &.{ "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-groups", "P-256" }, .expect = &.{ "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256", "Peer Temp Key: ECDH, prime256v1" } },
    .{ .name = "p256-aes256-x25519", .why = "a P-256 certificate under the SHA-384 suite (the transcript hash is not the scheme's)", .seed = 4, .args = &.{ "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-groups", "X25519" }, .expect = &.{ "Ciphersuite: TLS_AES_256_GCM_SHA384", "Signature type: ecdsa_secp256r1_sha256" } },
    .{ .name = "p256-p384group", .why = "TLS_AES_256_GCM_SHA384 over secp384r1", .seed = 9, .args = &.{ "-groups", "P-384" }, .expect = &.{ "Ciphersuite: TLS_AES_256_GCM_SHA384", "Peer Temp Key: ECDH, secp384r1" } },
    .{ .name = "p384", .why = "an ECDSA P-384 certificate over secp384r1", .cert = .p384, .seed = 10, .args = &.{ "-groups", "P-384:X25519" }, .expect = &.{ "Signature type: ecdsa_secp384r1_sha384", "Peer Temp Key: ECDH, secp384r1", "Verification: OK" } },
    .{ .name = "ed25519", .why = "an Ed25519 certificate (std's client cannot check one)", .cert = .ed25519, .seed = 5, .expect = &.{ "Signature type: ed25519", "Verification: OK" } },
    .{ .name = "rsa2048-pss", .why = "an RSA certificate signed with RSA-PSS", .cert = .rsa2048, .seed = 6, .expect = &.{ "Signature type: rsa_pss_rsae_sha256", "Verification: OK" } },
    .{ .name = "alpn-h2", .why = "ALPN: the server's choice among the client's offers", .seed = 7, .alpn = &.{ "h2", "http/1.1" }, .args = &.{ "-alpn", "http/1.1,h2" }, .brief = false, .expect = &.{"ALPN protocol: h2"} },
    .{ .name = "no-sni", .why = "a client that sends no server_name", .seed = 8, .args = &.{"-noservername"}, .expect = &.{"Verification: OK"} },
    // Go: its suite order (AES-128 first on AES hardware) is not
    // configurable in TLS 1.3, so the server's list picks the suite.
    .{ .name = "go-default", .client = .go, .why = "Go's defaults: X25519MLKEM768, its first suite", .seed = 21, .expect = &.{ "version: TLS 1.3", "suite: TLS_AES_128_GCM_SHA256", "group: X25519MLKEM768", "peer_certs: 1" } },
    .{ .name = "go-aes256", .client = .go, .why = "TLS_AES_256_GCM_SHA384 (the server enables only it)", .seed = 22, .suites = &.{.aes_256_gcm_sha384}, .expect = &.{"suite: TLS_AES_256_GCM_SHA384"} },
    .{ .name = "go-chacha", .client = .go, .why = "TLS_CHACHA20_POLY1305_SHA256 over X25519", .seed = 23, .suites = &.{.chacha20_poly1305_sha256}, .args = &.{ "-groups", "X25519" }, .expect = &.{ "suite: TLS_CHACHA20_POLY1305_SHA256", "group: X25519\n" } },
    .{ .name = "go-p256group", .client = .go, .why = "secp256r1 as Go's only group", .seed = 24, .args = &.{ "-groups", "P-256" }, .expect = &.{"group: CurveP256"} },
    .{ .name = "go-p384", .client = .go, .why = "an ECDSA P-384 certificate over secp384r1", .cert = .p384, .seed = 25, .args = &.{ "-groups", "P-384" }, .expect = &.{"group: CurveP384"} },
    .{ .name = "go-ed25519", .client = .go, .why = "an Ed25519 certificate", .cert = .ed25519, .seed = 26, .expect = &.{"peer_certs: 1"} },
    .{ .name = "go-rsa2048-pss", .client = .go, .why = "an RSA certificate signed with RSA-PSS", .cert = .rsa2048, .seed = 27, .expect = &.{"peer_certs: 1"} },
    .{ .name = "go-alpn-h2", .client = .go, .why = "ALPN: the server's choice among Go's offers", .seed = 28, .alpn = &.{ "h2", "http/1.1" }, .args = &.{ "-alpn", "http/1.1,h2" }, .expect = &.{"alpn: h2"} },
    .{ .name = "go-no-sni", .client = .go, .why = "Go without server_name (verified by hand)", .seed = 29, .args = &.{"-nosni"}, .expect = &.{"peer_certs: 1"} },
    .{ .name = "go-no-hybrid", .client = .go, .why = "a server without X25519MLKEM768: Go's X25519 share, no retry", .seed = 30, .groups = &.{ tlsserver.server.default_groups[1], tlsserver.server.default_groups[2] }, .expect = &.{"group: X25519\n"} },
};

var child_env: ?*const std.process.Environ.Map = null;

const Keys = struct {
    p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    p384: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey,
    ed25519: std.crypto.sign.Ed25519.SecretKey,
    rsa2048: rsa.SecretKey,
};

fn certifiedKey(keys: *const Keys, kind: CertKind, chain: *[1][]const u8) tlsserver.CertifiedKey {
    return switch (kind) {
        .p256 => blk: {
            chain[0] = &certs.p256_cert;
            break :blk .{ .chain = chain, .key = .{ .ecdsa_p256 = &keys.p256 } };
        },
        .p384 => blk: {
            chain[0] = &certs.p384_cert;
            break :blk .{ .chain = chain, .key = .{ .ecdsa_p384 = &keys.p384 } };
        },
        .ed25519 => blk: {
            chain[0] = &certs.ed25519_cert;
            break :blk .{ .chain = chain, .key = .{ .ed25519 = &keys.ed25519 } };
        },
        .rsa2048 => blk: {
            chain[0] = &certs.rsa2048_cert;
            break :blk .{ .chain = chain, .key = .{ .rsa = &keys.rsa2048 } };
        },
    };
}

fn pem(gpa: std.mem.Allocator, der: []const u8) ![]u8 {
    const Enc = std.base64.standard.Encoder;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "-----BEGIN CERTIFICATE-----\n");
    var b64: [1024 * 2]u8 = undefined;
    const s = Enc.encode(&b64, der);
    var i: usize = 0;
    while (i < s.len) : (i += 64) {
        try out.appendSlice(gpa, s[i..@min(s.len, i + 64)]);
        try out.append(gpa, '\n');
    }
    try out.appendSlice(gpa, "-----END CERTIFICATE-----\n");
    return out.toOwnedSlice(gpa);
}

const Recorded = struct {
    client: std.ArrayList(u8) = .empty,
    server: std.ArrayList(u8) = .empty,
};

/// Serve one connection by hand, recording every octet both ways. The
/// application protocol: receive "ping\n", answer "pong\n", close_notify,
/// then read until the client closes.
fn serve(gpa: std.mem.Allocator, io: std.Io, stream: net.Stream, server: *Server, rec: *Recorded) !void {
    var rbuf: [8192]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var wbuf: [8192]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var in: [2 * record.max_record_len]u8 = undefined;
    var have: usize = 0;
    var app: std.ArrayList(u8) = .empty;
    defer app.deinit(gpa);
    var answered = false;
    while (true) {
        const r = server.feed(in[0..have]) catch |err| {
            try flushOut(server, &sw.interface, rec, gpa);
            return err;
        };
        switch (r.event) {
            .need_more => {},
            .handshake_done => {},
            .app_data => |d| {
                try app.appendSlice(gpa, d);
                if (!answered and std.mem.endsWith(u8, app.items, "ping\n")) {
                    _ = try server.write("pong\n");
                    try server.close();
                    answered = true;
                }
            },
            .peer_closed => {},
        }
        std.mem.copyForwards(u8, in[0 .. have - r.consumed], in[r.consumed..have]);
        have -= r.consumed;
        try flushOut(server, &sw.interface, rec, gpa);
        if (r.event == .peer_closed) return;
        if (r.event != .need_more) continue;
        sr.interface.fillMore() catch |err| switch (err) {
            error.EndOfStream => return if (answered) {} else error.ClientLeft,
            else => return err,
        };
        const b = sr.interface.buffered();
        @memcpy(in[have..][0..b.len], b);
        have += b.len;
        try rec.client.appendSlice(gpa, b);
        sr.interface.toss(b.len);
    }
}

fn flushOut(server: *Server, w: *std.Io.Writer, rec: *Recorded, gpa: std.mem.Allocator) !void {
    const p = server.pendingOutput();
    if (p.len == 0) return;
    try rec.server.appendSlice(gpa, p);
    try w.writeAll(p);
    try w.flush();
    server.discardOutput(p.len);
}

fn runCase(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir, keys: *const Keys, c: Case, rec: *Recorded) !void {
    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try local.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var port_buf: [32]u8 = undefined;
    const target = try std.mem.print(&port_buf, "127.0.0.1:{d}", .{listener.socket.address.getPort()});

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    const ca_file: []const u8 = switch (c.cert) {
        .p256 => "p256.pem",
        .p384 => "p384.pem",
        .ed25519 => "ed25519.pem",
        .rsa2048 => "rsa2048.pem",
    };
    var no_sni = false;
    for (c.args) |a| if (std.mem.eql(u8, a, "-noservername") or std.mem.eql(u8, a, "-nosni")) {
        no_sni = true;
    };
    switch (c.client) {
        .openssl => {
            try argv.appendSlice(gpa, &.{ "openssl", "s_client", "-connect", target, "-tls1_3", if (c.brief) "-brief" else "-ign_eof", "-ign_eof", "-verify_return_error", "-CAfile", ca_file, "-verify_hostname", "localhost" });
            if (!no_sni) try argv.appendSlice(gpa, &.{ "-servername", "localhost" });
        },
        .go => try argv.appendSlice(gpa, &.{ "./go-client", "-addr", target, "-ca", ca_file, "-servername", "localhost" }),
    }
    try argv.appendSlice(gpa, c.args);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    var waited = false;
    defer if (!waited) child.kill(io);
    {
        var b: [16]u8 = undefined;
        var w = child.stdin.?.writer(io, &b);
        try w.interface.writeAll("ping\n");
        try w.interface.flush();
    }

    const stream = try listener.accept(io);
    defer stream.close(io);

    var chain: [1][]const u8 = undefined;
    const ck = certifiedKey(keys, c.cert, &chain);
    const seed: [32]u8 = @splat(c.seed);
    var csprng = std.Random.DefaultCsprng.init(seed);
    const cfg: tlsserver.Config = .{
        .certificate = .{ .fixed = &ck },
        .cipher_suites = c.suites,
        .groups = c.groups,
        .alpn_protocols = c.alpn,
        .random = csprng.random(),
    };
    const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, tlsserver.server.minOutputLen(&ck) + 4096);
    defer gpa.free(out);
    var server: Server = .init(&cfg, joiner, out);
    defer server.deinit();

    const served = serve(gpa, io, stream, &server, rec);
    child.stdin.?.close(io);
    child.stdin = null;

    var ob: [4096]u8 = undefined;
    var or_ = child.stdout.?.reader(io, &ob);
    const stdout = try or_.interface.allocRemaining(gpa, .unlimited);
    var eb: [4096]u8 = undefined;
    var er = child.stderr.?.reader(io, &eb);
    const stderr = try er.interface.allocRemaining(gpa, .unlimited);
    const term = try child.wait(io);
    waited = true;

    served catch |err| {
        std.debug.print("  server: {t}\n  client said:\n{s}\n", .{ err, stderr });
        return err;
    };
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("  client exited {d}:\n{s}\n", .{ code, stderr });
            return error.ClientFailed;
        },
        else => {
            std.debug.print("  client ended {any}\n", .{term});
            return error.ClientFailed;
        },
    }
    if (std.mem.indexOf(u8, stdout, "pong") == null) {
        std.debug.print("  client did not receive pong; stdout: {s}\n", .{stdout});
        return error.NoPong;
    }
    for (c.expect) |e| if (std.mem.indexOf(u8, stderr, e) == null and std.mem.indexOf(u8, stdout, e) == null) {
        std.debug.print("  client lacks \"{s}\":\n{s}\n", .{ e, stderr });
        return error.ExpectationMissing;
    };
    if (no_sni and server.serverName() != null) return error.SniFromNowhere;
}

fn writeVectors(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, done: []const struct { Case, Recorded }) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll(
        \\// SPDX-License-Identifier: MIT
        \\
        \\//! Recorded OpenSSL `s_client` and Go crypto/tls client sessions against
        \\//! `Server`, written by `tools/interop.zig --capture` (OpenSSL 3.5, Go
        \\//! 1.26). Each case: the server's
        \\//! configuration and seed, every octet the client sent, every octet the
        \\//! server sent. Replayed by `interop_replay_test.zig`. Do not edit by hand.
        \\
        \\pub const CertKind = enum { p256, p384, ed25519, rsa2048 };
        \\
        \\pub const Case = struct {
        \\    name: []const u8,
        \\    cert: CertKind,
        \\    seed: u8,
        \\    suites: []const u16,
        \\    groups: []const u16,
        \\    alpn: []const []const u8,
        \\    client: []const u8,
        \\    server: []const u8,
        \\};
        \\
        \\pub const cases = [_]Case{
        \\
    );
    for (done) |d| {
        const c = d[0];
        try w.print("    .{{\n        .name = \"{s}\",\n        .cert = .{t},\n        .seed = {d},\n        .suites = &.{{", .{ c.name, c.cert, c.seed });
        // zig fmt's spacing: `&.{}`, `&.{x}`, `&.{ x, y }`.
        for (c.suites, 0..) |s, i| try w.print("{s}0x{x:0>4}", .{ listSep(i, c.suites.len), @backingInt(s) });
        try w.print("{s}}},\n        .groups = &.{{", .{listEnd(c.suites.len)});
        for (c.groups, 0..) |g, i| try w.print("{s}0x{x:0>4}", .{ listSep(i, c.groups.len), g });
        try w.print("{s}}},\n        .alpn = &.{{", .{listEnd(c.groups.len)});
        for (c.alpn, 0..) |a, i| try w.print("{s}\"{s}\"", .{ listSep(i, c.alpn.len), a });
        try w.print("{s}}},\n", .{listEnd(c.alpn.len)});
        try hexField(w, "client", d[1].client.items);
        try hexField(w, "server", d[1].server.items);
        try w.writeAll("    },\n");
    }
    try w.writeAll(
        \\};
        \\
        \\fn hx(comptime n: usize, comptime hex: []const u8) [n]u8 {
        \\    @setEvalBranchQuota(10_000_000);
        \\    var out: [n]u8 = undefined;
        \\    _ = @import("std").fmt.hexToBytes(&out, hex) catch unreachable;
        \\    return out;
        \\}
        \\
    );
    try root.writeFile(io, .{ .sub_path = "modules/tlsserver/src/interop_vectors.zig", .data = out.written() });
}

fn listSep(i: usize, len: usize) []const u8 {
    return if (i != 0) ", " else if (len == 1) "" else " ";
}

fn listEnd(len: usize) []const u8 {
    return if (len <= 1) "" else " ";
}

fn hexField(w: *std.Io.Writer, name: []const u8, data: []const u8) !void {
    try w.print("        .{s} = &hx({d}, \"\"", .{ name, data.len });
    var i: usize = 0;
    while (i < data.len) : (i += 48) {
        try w.print(" ++\n            \"{x}\"", .{data[i..@min(data.len, i + 48)]});
    }
    try w.writeAll("),\n");
}

fn isSelected(selected: []const []const u8, c: Case) bool {
    if (selected.len == 0) return true;
    for (selected) |s| if (std.mem.eql(u8, s, c.name)) return true;
    return false;
}

/// `go build` the Go client into the work directory (Go's build cache makes
/// a repeat cheap). The work directory is `<root>/.zig-cache/tlsserver-interop`.
fn buildGoClient(io: std.Io, work: std.Io.Dir) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "go", "build", "-o", "go-client", "../../modules/tlsserver/tools/go_client/main.go" },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        std.debug.print("go build of tools/go_client failed: {any}\n", .{term});
        return error.GoBuildFailed;
    }
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    var arena: std.heap.ArenaAllocator = .init(da.allocator());
    defer arena.deinit();
    const gpa = arena.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var env_map: std.process.Environ.Map = .init(gpa);
    try env_map.putPosixBlock(init.environ.block.view());
    // The Go client is built with the installed toolchain only.
    try env_map.put("GOTOOLCHAIN", "local");
    child_env = &env_map;

    var capture = false;
    var repo_root: []const u8 = ".";
    var selected: std.ArrayList([]const u8) = .empty;
    var args = init.args.iterate();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, arg, "--list")) {
            for (cases) |c| std.debug.print("{s}\t{s}\n", .{ c.name, c.why });
            return 0;
        } else if (std.mem.eql(u8, arg, "--case")) {
            try selected.append(gpa, args.next() orelse {
                std.debug.print("{s}", .{usage});
                return 2;
            });
        } else if (std.mem.eql(u8, arg, "--repo-root")) {
            repo_root = args.next() orelse return 2;
        } else {
            std.debug.print("unknown argument \"{s}\"\n{s}", .{ arg, usage });
            return 2;
        }
    }
    if (capture and selected.items.len != 0) {
        std.debug.print("--capture rewrites every case: run it without --case\n", .{});
        return 2;
    }

    var root = std.Io.Dir.cwd().openDir(io, repo_root, .{}) catch {
        std.debug.print("cannot open repository root \"{s}\"\n", .{repo_root});
        return 2;
    };
    defer root.close(io);
    try root.createDirPath(io, ".zig-cache/tlsserver-interop");
    var work = try root.openDir(io, ".zig-cache/tlsserver-interop", .{});
    defer work.close(io);
    try work.writeFile(io, .{ .sub_path = "p256.pem", .data = try pem(gpa, &certs.p256_cert) });
    try work.writeFile(io, .{ .sub_path = "p384.pem", .data = try pem(gpa, &certs.p384_cert) });
    try work.writeFile(io, .{ .sub_path = "ed25519.pem", .data = try pem(gpa, &certs.ed25519_cert) });
    try work.writeFile(io, .{ .sub_path = "rsa2048.pem", .data = try pem(gpa, &certs.rsa2048_cert) });

    var keys: Keys = undefined;
    keys.p256 = try .fromBytes(certs.p256_scalar);
    keys.p384 = try .fromBytes(certs.p384_scalar);
    keys.ed25519 = try .fromBytes(certs.ed25519_secret);
    try rsa.SecretKey.fromDer(&keys.rsa2048, &certs.rsa2048_pkcs1);

    for (cases) |c| {
        if (c.client != .go or !isSelected(selected.items, c)) continue;
        try buildGoClient(io, work);
        break;
    }

    var done: std.ArrayList(struct { Case, Recorded }) = .empty;
    var failed: usize = 0;
    for (cases) |c| {
        if (!isSelected(selected.items, c)) continue;
        std.debug.print("{s}: {s}\n", .{ c.name, c.why });
        var rec: Recorded = .{};
        runCase(gpa, io, work, &keys, c, &rec) catch |err| {
            std.debug.print("  FAIL {t}\n", .{err});
            failed += 1;
            continue;
        };
        std.debug.print("  ok (client {d} octets, server {d})\n", .{ rec.client.items.len, rec.server.items.len });
        try done.append(gpa, .{ c, rec });
    }
    if (failed != 0) {
        std.debug.print("{d} case(s) failed\n", .{failed});
        return 1;
    }
    if (capture) {
        try writeVectors(gpa, io, root, done.items);
        std.debug.print("wrote modules/tlsserver/src/interop_vectors.zig ({d} cases)\n", .{done.items.len});
    }
    return 0;
}
