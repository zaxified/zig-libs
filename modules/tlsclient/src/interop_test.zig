// SPDX-License-Identifier: MIT

//! The handshake end to end against a foreign server: `openssl s_server`
//! serves the chains in `testdata/`, and this module's client connects over
//! loopback. Skipped when `openssl` is not on PATH.
//!
//! The same forged chain is also offered to std's own client, which must
//! ACCEPT it today (ziglang/zig #35877). The day it refuses, std has fixed the
//! hole and this module can go -- that test is the tripwire, not a wish.

const std = @import("std");
const Client = @import("Client.zig");
const testing = std.testing;

const files = .{
    .{ "root.pem", @embedFile("testdata/root.pem") },
    .{ "inter.pem", @embedFile("testdata/inter.pem") },
    .{ "leaf.pem", @embedFile("testdata/leaf.pem") },
    .{ "leaf.key.pem", @embedFile("testdata/leaf.key.pem") },
    .{ "forged.pem", @embedFile("testdata/forged.pem") },
    .{ "forged.key.pem", @embedFile("testdata/forged.key.pem") },
    // What sits behind the forged leaf on the wire: the attacker's own
    // honest chain.
    .{ "forged-chain.pem", @embedFile("testdata/leaf.pem") ++ @embedFile("testdata/inter.pem") },
    // zig-libs tlsclient additions: the CA the server trusts for client
    // certificates (its key was thrown away at generation).
    .{ "client-ca.pem", @embedFile("testdata/client-ca.pem") },
};

const Server = struct {
    child: std.process.Child,
    port: u16,
    out_buf: [512]u8,

    /// `openssl s_server` for one connection, serving `cert` (+ `chain`).
    fn start(io: std.Io, dir: std.Io.Dir, cert: []const u8, key: []const u8, chain: []const u8) !Server {
        return startWith(io, dir, cert, key, chain, &.{});
    }

    /// The same with `extra` arguments (`-alpn`, `-Verify`, `-rev`, …).
    fn startWith(io: std.Io, dir: std.Io.Dir, cert: []const u8, key: []const u8, chain: []const u8, extra: []const []const u8) !Server {
        return startProto(io, dir, "-tls1_3", cert, key, chain, extra);
    }

    /// The same with the protocol flag (`-tls1_2`, `-tls1_3`, or "" for both).
    fn startProto(io: std.Io, dir: std.Io.Dir, proto: []const u8, cert: []const u8, key: []const u8, chain: []const u8, extra: []const []const u8) !Server {
        var argv_buf: [32][]const u8 = undefined;
        const base_all = [_][]const u8{
            "openssl", "s_server", "-accept",     "127.0.0.1:0", "-cert",    cert,
            "-key",    key,        "-cert_chain", chain,         "-naccept", "1",
            proto,
        };
        const base = if (proto.len == 0) base_all[0 .. base_all.len - 1] else base_all[0..];
        @memcpy(argv_buf[0..base.len], base);
        @memcpy(argv_buf[base.len..][0..extra.len], extra);
        var child = std.process.spawn(io, .{
            .argv = argv_buf[0 .. base.len + extra.len],
            .cwd = .{ .dir = dir },
            .stdin = .pipe,
            .stdout = .pipe,
            // Read only by `reported`, after the server has exited.
            .stderr = .pipe,
        }) catch return error.SkipZigTest;
        errdefer child.kill(io);
        // "ACCEPT 127.0.0.1:<port>" once it listens.
        var buf: [256]u8 = undefined;
        var r = child.stdout.?.reader(io, &buf);
        while (true) {
            const line = (r.interface.takeDelimiter('\n') catch return error.SkipZigTest) orelse return error.SkipZigTest;
            const tag = "ACCEPT 127.0.0.1:";
            if (std.mem.startsWith(u8, line, tag)) {
                const port = std.fmt.parseInt(u16, std.mem.trim(u8, line[tag.len..], " \r"), 10) catch return error.SkipZigTest;
                return .{ .child = child, .port = port, .out_buf = undefined };
            }
        }
    }

    fn stop(s: *Server, io: std.Io) void {
        s.child.kill(io);
    }

    /// The rest of the first report line starting with `prefix`, copied
    /// into `out` (s_server prints "Keying material: <hex>").
    fn reportedValue(s: *Server, io: std.Io, prefix: []const u8, out: []u8) ?[]const u8 {
        var r = s.child.stdout.?.reader(io, &s.out_buf);
        while (r.interface.takeDelimiter('\n') catch null) |line| {
            const t = std.mem.trim(u8, line, " \r");
            if (std.mem.startsWith(u8, t, prefix)) {
                const v = t[prefix.len..];
                @memcpy(out[0..v.len], v);
                return out[0..v.len];
            }
        }
        return null;
    }

    /// Whether the server's report (stdout, up to its exit after the one
    /// connection) has a line starting with `want`.
    fn reported(s: *Server, io: std.Io, want: []const u8) bool {
        for ([_]std.Io.File{ s.child.stdout.?, s.child.stderr.? }) |f| {
            var r = f.reader(io, &s.out_buf);
            while (r.interface.takeDelimiter('\n') catch null) |line| {
                if (std.mem.startsWith(u8, std.mem.trim(u8, line, " \r"), want)) return true;
            }
        }
        return false;
    }
};

const Outcome = enum { handshake_ok, not_verified, other_error };

/// One handshake with `ClientType` (this module's, or std's) naming `host`
/// and trusting `bundle`.
fn handshake(comptime ClientType: type, io: std.Io, port: u16, host: []const u8, bundle: *std.crypto.Certificate.Bundle) !Outcome {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const tv: std.posix.timeval = .{ .sec = 5, .usec = 0 };
    std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    var net_in: [ClientType.min_buffer_len]u8 = undefined;
    var net_out: [ClientType.min_buffer_len]u8 = undefined;
    var tls_in: [ClientType.min_buffer_len]u8 = undefined;
    var tls_out: [ClientType.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_in);
    var sw = stream.writer(io, &net_out);
    var entropy: [ClientType.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var lock: std.Io.RwLock = .init;
    _ = ClientType.init(&sr.interface, &sw.interface, .{
        .host = .{ .explicit = host },
        .ca = .{ .bundle = .{ .gpa = testing.allocator, .io = io, .lock = &lock, .bundle = bundle } },
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
    }) catch |err| return switch (err) {
        error.TlsCertificateNotVerified => .not_verified,
        else => .other_error,
    };
    return .handshake_ok;
}

fn rootBundle(io: std.Io, dir: std.Io.Dir) !std.crypto.Certificate.Bundle {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(testing.allocator);
    try bundle.addCertsFromFilePath(testing.allocator, io, std.Io.Clock.real.now(io), dir, "root.pem");
    return bundle;
}

fn setUp(io: std.Io) !testing.TmpDir {
    var tmp = testing.tmpDir(.{});
    errdefer tmp.cleanup();
    inline for (files) |f| try tmp.dir.writeFile(io, .{ .sub_path = f[0], .data = f[1] });
    return tmp;
}

test "interop: an honest chain from openssl verifies" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    var srv = try Server.start(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem");
    defer srv.stop(io);
    try testing.expectEqual(Outcome.handshake_ok, try handshake(Client, io, srv.port, "good.example.test", &bundle));
}

test "interop: a leaf signed by another leaf is refused (ziglang/zig #35877)" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    var srv = try Server.start(io, tmp.dir, "forged.pem", "forged.key.pem", "forged-chain.pem");
    defer srv.stop(io);
    try testing.expectEqual(Outcome.not_verified, try handshake(Client, io, srv.port, "victim.example.test", &bundle));
}

test "interop: tripwire -- std's client still accepts the forged chain" {
    // If this fails, std fixed #35877: re-check, and retire this module.
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    var srv = try Server.start(io, tmp.dir, "forged.pem", "forged.key.pem", "forged-chain.pem");
    defer srv.stop(io);
    try testing.expectEqual(Outcome.handshake_ok, try handshake(std.crypto.tls.Client, io, srv.port, "victim.example.test", &bundle));
}

// ── zig-libs tlsclient additions: ALPN and client certificates ──────────────
//
// Hermetic: loopback only, the server's chain and the client CA/certs are
// throwaway openssl-made fixtures (`testdata/README.md`), and the client keys
// are raw scalars cut from their DER files at fixed, prefix-checked offsets.

const Ext = struct {
    alpn: []const []const u8 = &.{},
    alert: ?*std.crypto.tls.Alert = null,
    client_auth: ?Client.ClientAuth = null,
    min_version: std.crypto.tls.ProtocolVersion = .tls_1_2,
    max_version: std.crypto.tls.ProtocolVersion = .tls_1_3,
    groups: []const std.crypto.tls.NamedGroup = &Client.default_groups,
    key_share_groups: []const std.crypto.tls.NamedGroup = &Client.default_key_share_groups,
    connection_info: ?*Client.ConnectionInfo = null,
    verify_connection: ?Client.VerifyConnection = null,
    client_auth_select: ?Client.ClientAuthSelect = null,
    extended_master_secret: bool = true,
    host: []const u8 = "good.example.test",
    /// Trust the server's self-signed certificate instead of the bundle.
    self_signed: bool = false,
    /// Skip the "hello" round trip (a server without `-rev`).
    no_echo: bool = false,
    /// Export this many bytes under `export_label` after the handshake.
    export_label: []const u8 = "",
    export_len: usize = 0,
};

const Session = struct {
    alpn: ?[]const u8,
    version: std.crypto.tls.ProtocolVersion = .tls_1_3,
    group: ?std.crypto.tls.NamedGroup = null,
    hrr: bool = false,
    exported: [64]u8 = undefined,
    /// What the server's `-rev` mode sent back for "hello\n".
    echo: [16]u8 = undefined,
    echo_len: usize = 0,
};

/// A handshake with the additions, then one "hello\n" round trip (s_server
/// `-rev` answers "olleh"): in TLS 1.3 the client's Finished goes before the
/// server judges our certificate, so a refusal shows on the first read.
fn session(io: std.Io, port: u16, bundle: *std.crypto.Certificate.Bundle, ext: Ext) !Session {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const tv: std.posix.timeval = .{ .sec = 5, .usec = 0 };
    std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    var net_in: [Client.min_buffer_len]u8 = undefined;
    var net_out: [Client.min_buffer_len]u8 = undefined;
    var tls_in: [Client.min_buffer_len]u8 = undefined;
    var tls_out: [Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_in);
    var sw = stream.writer(io, &net_out);
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var lock: std.Io.RwLock = .init;
    var c = try Client.init(&sr.interface, &sw.interface, .{
        .alert = ext.alert,
        .host = .{ .explicit = ext.host },
        .ca = if (ext.self_signed) .self_signed else .{ .bundle = .{ .gpa = testing.allocator, .io = io, .lock = &lock, .bundle = bundle } },
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        .alpn_protocols = ext.alpn,
        .client_auth = ext.client_auth,
        .min_version = ext.min_version,
        .max_version = ext.max_version,
        .groups = ext.groups,
        .key_share_groups = ext.key_share_groups,
        .connection_info = ext.connection_info,
        .verify_connection = ext.verify_connection,
        .client_auth_select = ext.client_auth_select,
        .extended_master_secret = ext.extended_master_secret,
    });
    var out: Session = .{ .alpn = c.alpn_protocol, .version = c.tls_version, .group = c.negotiated_group, .hrr = c.hello_retry_request };
    if (ext.export_len != 0) try c.exportKeyingMaterial(ext.export_label, null, out.exported[0..ext.export_len]);
    if (ext.no_echo) return out;
    try c.writer.writeAll("hello\n");
    try c.writer.flush();
    try sw.interface.flush();
    const line = (try c.reader.takeDelimiter('\n')) orelse return error.EndOfStream;
    out.echo_len = @min(line.len, out.echo.len);
    @memcpy(out.echo[0..out.echo_len], line[0..out.echo_len]);
    return out;
}

const p256_der = @embedFile("testdata/client-p256.key.der");
const p384_der = @embedFile("testdata/client-p384.key.der");
const ed25519_der = @embedFile("testdata/client-ed25519.key.der");

fn derFromPem(comptime pem: []const u8) []const u8 {
    // Fixtures hold one certificate each; decode its base64 body.
    const b64 = comptime blk: {
        @setEvalBranchQuota(100_000);
        const begin = std.mem.indexOf(u8, pem, "-----\n").? + 6;
        const end = std.mem.indexOf(u8, pem, "\n-----END").?;
        var clean: [end - begin]u8 = undefined;
        var n: usize = 0;
        for (pem[begin..end]) |ch| if (ch != '\n') {
            clean[n] = ch;
            n += 1;
        };
        break :blk clean[0..n].*;
    };
    const S = struct {
        const der = blk: {
            @setEvalBranchQuota(1_000_000);
            var out: [std.base64.standard.Decoder.calcSizeForSlice(&b64) catch unreachable]u8 = undefined;
            std.base64.standard.Decoder.decode(&out, &b64) catch unreachable;
            break :blk out;
        };
    };
    return &S.der;
}

fn p256Key() Client.ClientAuth.PrivateKey {
    // SEC1 ECPrivateKey: 30 77 02 01 01 04 20 <32-byte scalar> …
    std.debug.assert(std.mem.eql(u8, p256_der[0..7], "\x30\x77\x02\x01\x01\x04\x20"));
    return .{ .ecdsa_secp256r1_sha256 = p256_der[7..39].* };
}
fn p384Key() Client.ClientAuth.PrivateKey {
    // SEC1 ECPrivateKey: 30 81 a4 02 01 01 04 30 <48-byte scalar> …
    std.debug.assert(std.mem.eql(u8, p384_der[0..8], "\x30\x81\xa4\x02\x01\x01\x04\x30"));
    return .{ .ecdsa_secp384r1_sha384 = p384_der[8..56].* };
}
fn ed25519Key() Client.ClientAuth.PrivateKey {
    // PKCS#8: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32-byte seed>
    std.debug.assert(std.mem.eql(u8, ed25519_der[0..16], "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"));
    return .{ .ed25519 = ed25519_der[16..48].* };
}

test "interop: ALPN -- openssl selects its first protocol we offer; no overlap is its no_application_protocol" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    {
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-alpn", "h2,http/1.1", "-rev" });
        defer srv.stop(io);
        // OpenSSL's s_server picks by its own order (SSL_select_next_proto:
        // the first server protocol the client offered): h2.
        const s = try session(io, srv.port, &bundle, .{ .alpn = &.{ "http/1.1", "h2" } });
        try testing.expectEqualStrings("h2", s.alpn.?);
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
    }
    {
        // RFC 7301 §3.2: a server with no protocol in common MAY refuse
        // with no_application_protocol; OpenSSL 3.5's s_server does.
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-alpn", "h2", "-rev" });
        defer srv.stop(io);
        var alert: std.crypto.tls.Alert = .{ .level = .warning, .description = .close_notify };
        try testing.expectError(error.TlsAlert, session(io, srv.port, &bundle, .{ .alpn = &.{"spdy/1"}, .alert = &alert }));
        try testing.expectEqual(std.crypto.tls.Alert.Description.no_application_protocol, alert.description);
    }
    {
        // A server without ALPN ignores the offer: no protocol, no error.
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .alpn = &.{"h2"} });
        try testing.expectEqual(@as(?[]const u8, null), s.alpn);
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
    }
}

test "interop: client certificates -- P-256, P-384 and Ed25519 verified by openssl -Verify" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    const cases = .{
        .{ derFromPem(@embedFile("testdata/client-p256.pem")), p256Key(), "Peer certificate: CN=client-p256" },
        .{ derFromPem(@embedFile("testdata/client-p384.pem")), p384Key(), "Peer certificate: CN=client-p384" },
        .{ derFromPem(@embedFile("testdata/client-ed25519.pem")), ed25519Key(), "Peer certificate: CN=client-ed25519" },
    };
    inline for (cases) |c| {
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-Verify", "1", "-CAfile", "client-ca.pem", "-rev" });
        defer srv.stop(io);
        const key: Client.ClientAuth.PrivateKey = c[1];
        const s = try session(io, srv.port, &bundle, .{ .client_auth = .{ .certificate_chain = &.{c[0]}, .key = &key } });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expect(srv.reported(io, c[2]));
    }
}

test "interop: a CertificateRequest without our scheme gets an empty Certificate (RFC 8446 §4.4.2.3)" {
    // The server asks only for ECDSA+SHA384; our key is P-256. We send an
    // empty Certificate and no CertificateVerify -- the RFC's rule, which
    // leaves the decision to the server: `-verify` (optional) proceeds
    // without a client identity, `-Verify` (required) aborts, and we learn
    // it on the first read.
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    const key = p256Key();
    const auth: Client.ClientAuth = .{ .certificate_chain = &.{derFromPem(@embedFile("testdata/client-p256.pem"))}, .key = &key };
    {
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-verify", "1", "-CAfile", "client-ca.pem", "-client_sigalgs", "ECDSA+SHA384", "-rev" });
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .client_auth = auth });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expect(!srv.reported(io, "Peer certificate: CN=client-p256"));
    }
    {
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-Verify", "1", "-CAfile", "client-ca.pem", "-client_sigalgs", "ECDSA+SHA384", "-rev" });
        defer srv.stop(io);
        if (session(io, srv.port, &bundle, .{ .client_auth = auth })) |_| return error.TestExpectedRefusal else |_| {}
    }
}

test "interop: defaults are std's -- a CertificateRequest without client_auth fails as in std" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ Client, std.crypto.tls.Client }) |C| {
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-verify", "1", "-CAfile", "client-ca.pem" });
        defer srv.stop(io);
        try testing.expectEqual(Outcome.other_error, try handshake(C, io, srv.port, "good.example.test", &bundle));
    }
}

// ── S2 (2026-10-13): HelloRetryRequest, group preferences, version bounds ──

test "interop: HelloRetryRequest -- a server limited to P-256 / P-384 / P-521 gets its group on the second hello" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    const T = std.crypto.tls.NamedGroup;
    inline for (.{ .{ "P-256", T.secp256r1 }, .{ "P-384", T.secp384r1 }, .{ "P-521", T.secp521r1 } }) |c| {
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-groups", c[0], "-rev" });
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{});
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expect(s.hrr);
        try testing.expectEqual(@as(?T, c[1]), s.group);
    }
    {
        // A share for its group already in the first hello: no HRR.
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-groups", "X25519", "-rev" });
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{});
        try testing.expect(!s.hrr);
        try testing.expectEqual(@as(?T, .x25519), s.group);
    }
    {
        // No share at all (an empty key_share): the server must ask.
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .key_share_groups = &.{} });
        try testing.expect(s.hrr);
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
    }
    {
        // No group in common: the server's handshake_failure.
        var srv = try Server.startWith(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-groups", "P-521", "-rev" });
        defer srv.stop(io);
        try testing.expectError(error.TlsAlert, session(io, srv.port, &bundle, .{ .groups = &.{ .x25519, .secp256r1 }, .key_share_groups = &.{.x25519} }));
    }
}

/// The client's output after a canned HelloRetryRequest carrying `exts`
/// (with `second`, a second HRR follows the first), and the error `init`
/// ended with. `s_server -stateless` sends no cookie on a plain TCP accept
/// (checked 2026-10-13: an 88-byte HRR), so the cookie path is tested here.
fn afterHrr(out: []u8, exts: []const u8, second: bool) !struct { written: []const u8, err: anyerror } {
    var msg_buf: [512]u8 = undefined;
    var m: std.Io.Writer = .fixed(&msg_buf);
    const body_len = 2 + 32 + 1 + 32 + 2 + 1 + 2 + exts.len;
    try m.writeAll(&.{ 0x16, 0x03, 0x03 });
    try m.writeInt(u16, @intCast(4 + body_len), .big);
    try m.writeByte(2);
    try m.writeInt(u24, @intCast(body_len), .big);
    try m.writeInt(u16, 0x0303, .big);
    try m.writeAll(&std.crypto.tls.hello_retry_request_sequence);
    try m.writeByte(32);
    try m.writeAll(&([_]u8{0x5a} ** 32)); // the session id clientHelloWith's entropy gives
    try m.writeInt(u16, 0x1301, .big);
    try m.writeByte(0);
    try m.writeInt(u16, @intCast(exts.len), .big);
    try m.writeAll(exts);
    const one = m.buffered();
    var in_buf: [Client.min_buffer_len]u8 = undefined;
    @memcpy(in_buf[0..one.len], one);
    var in_len = one.len;
    if (second) {
        @memcpy(in_buf[one.len..][0..one.len], one);
        in_len += one.len;
    }
    var in: std.Io.Reader = .fixed(&in_buf); // the client asserts a full-size buffer
    in.end = in_len;
    var w: std.Io.Writer = .fixed(out);
    var tls_in: [Client.min_buffer_len]u8 = undefined;
    var tls_out: [Client.min_buffer_len]u8 = undefined;
    const entropy = [_]u8{0x5a} ** Client.Options.entropy_len;
    if (Client.init(&in, &w, .{
        .host = .{ .explicit = "good.example.test" },
        .ca = .no_verification,
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
    })) |_| return error.TestUnexpectedSuccess else |e| return .{ .written = w.buffered(), .err = e };
}

const versions_13 = "\x00\x2b\x00\x02\x03\x04";

test "HelloRetryRequest (offline): a cookie is echoed, a selected group gets the only share" {
    var a: [8192]u8 = undefined;
    {
        // Cookie only: the second hello repeats the shares and adds the cookie.
        const r = try afterHrr(&a, versions_13 ++ "\x00\x2c\x00\x07\x00\x05c00k!", false);
        try testing.expectEqual(error.TlsConnectionTruncated, r.err); // waiting for the ServerHello
        const ch1_len = 5 + @as(usize, std.mem.readInt(u16, r.written[3..5], .big));
        const ch2 = r.written[ch1_len..];
        try testing.expectEqualSlices(u8, "\x16\x03\x03", ch2[0..3]); // 0x0303 after an HRR (RFC 8446 §5.1)
        try testing.expect(std.mem.indexOf(u8, ch2, "\x00\x2c\x00\x07\x00\x05c00k!") != null);
        try testing.expect(std.mem.indexOf(u8, r.written[0..ch1_len], "c00k!") == null);
        try testing.expectEqual(ch1_len + 11, ch2.len);
    }
    {
        // Group P-256 (no share in the first hello): one P-256 share.
        const r = try afterHrr(&a, versions_13 ++ "\x00\x33\x00\x02\x00\x17", false);
        try testing.expectEqual(error.TlsConnectionTruncated, r.err);
        const ch1_len = 5 + @as(usize, std.mem.readInt(u16, r.written[3..5], .big));
        const ch2 = r.written[ch1_len..];
        const ks = std.mem.indexOf(u8, ch2, "\x00\x33\x00\x47\x00\x45\x00\x17\x00\x41\x04").?; // 65-byte SEC1
        _ = ks;
        try testing.expect(std.mem.indexOf(u8, ch2, "\x11\xec\x04\xc0") == null); // no hybrid share any more
    }
}

test "HelloRetryRequest (offline): refusals -- a group we shared, no change, not offered, a second HRR, not TLS 1.3" {
    var a: [8192]u8 = undefined;
    // X25519 already had a share.
    try testing.expectEqual(error.TlsIllegalParameter, (try afterHrr(&a, versions_13 ++ "\x00\x33\x00\x02\x00\x1d", false)).err);
    // Neither a group nor a cookie: nothing would change.
    try testing.expectEqual(error.TlsIllegalParameter, (try afterHrr(&a, versions_13, false)).err);
    // A group we never listed (ffdhe2048).
    try testing.expectEqual(error.TlsIllegalParameter, (try afterHrr(&a, versions_13 ++ "\x00\x33\x00\x02\x01\x00", false)).err);
    // A second HRR.
    try testing.expectEqual(error.TlsUnexpectedMessage, (try afterHrr(&a, versions_13 ++ "\x00\x33\x00\x02\x00\x17", true)).err);
    // An HRR naming TLS 1.2.
    try testing.expectEqual(error.TlsIllegalParameter, (try afterHrr(&a, "\x00\x33\x00\x02\x00\x17", false)).err);
}

test "interop: TLS 1.2 with an ECDSA certificate (ECDHE_ECDSA), each group" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    const T = std.crypto.tls.NamedGroup;
    inline for (.{ .{ "X25519", T.x25519 }, .{ "P-256", T.secp256r1 }, .{ "P-384", T.secp384r1 }, .{ "P-521", T.secp521r1 } }) |c| {
        var srv = try Server.startProto(io, tmp.dir, "-tls1_2", "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-groups", c[0], "-rev" });
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{});
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_2, s.version);
        try testing.expectEqual(@as(?T, c[1]), s.group);
    }
}

test "interop: version bounds -- TLS 1.3 only refuses a 1.2 server, TLS 1.2 only talks 1.2 to a dual one" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    {
        var srv = try Server.startProto(io, tmp.dir, "-tls1_2", "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
        defer srv.stop(io);
        // The server finds no common version: protocol_version alert.
        var alert: std.crypto.tls.Alert = .{ .level = .warning, .description = .close_notify };
        try testing.expectError(error.TlsAlert, session(io, srv.port, &bundle, .{ .min_version = .tls_1_3, .alert = &alert }));
        try testing.expectEqual(std.crypto.tls.Alert.Description.protocol_version, alert.description);
    }
    {
        var srv = try Server.startProto(io, tmp.dir, "", "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .max_version = .tls_1_2 });
        try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_2, s.version);
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
    }
}

// ── S2 (2026-10-13): session view, OCSP/SCT, EMS, exporter, hook, Ed25519 ──

/// A minimal valid OCSPResponse: status malformedRequest(1), no body
/// (RFC 6960 §4.2.1). s_server staples any parseable response.
const ocsp_der = "\x30\x03\x0a\x01\x01";

test "interop: ConnectionInfo -- chain, version, group; stapled OCSP in TLS 1.3 and TLS 1.2; storage too small" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "ocsp.der", .data = ocsp_der });
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ "-tls1_3", "-tls1_2" }) |proto| {
        var srv = try Server.startProto(io, tmp.dir, proto, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-status_file", "ocsp.der", "-rev" });
        defer srv.stop(io);
        var storage: [16 * 1024]u8 = undefined;
        var ci: Client.ConnectionInfo = .init(&storage);
        const s = try session(io, srv.port, &bundle, .{ .connection_info = &ci });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expectEqual(@as(usize, 2), ci.peerCertificates().len);
        try testing.expectEqualSlices(u8, derFromPem(@embedFile("testdata/leaf.pem")), ci.peerCertificates()[0]);
        try testing.expectEqualSlices(u8, derFromPem(@embedFile("testdata/inter.pem")), ci.peerCertificates()[1]);
        try testing.expectEqualSlices(u8, ocsp_der, ci.ocsp_response);
        try testing.expectEqual(s.version, ci.version);
        try testing.expectEqual(s.group, ci.negotiated_group);
        if (comptime std.mem.eql(u8, proto, "-tls1_2")) {
            try testing.expect(ci.extended_master_secret); // openssl agrees to EMS by default
            try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_2, ci.version);
        }
        // A storage too small for the chain is refused, not truncated.
        var srv2 = try Server.startProto(io, tmp.dir, proto, "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
        defer srv2.stop(io);
        var tiny: [64]u8 = undefined;
        var ci2: Client.ConnectionInfo = .init(&tiny);
        try testing.expectError(error.ConnectionInfoTooSmall, session(io, srv2.port, &bundle, .{ .connection_info = &ci2 }));
    }
}

test "interop: TLS 1.2 SCTs from ServerHello (s_server -serverinfo)" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    // serverinfo v1: extension 18 (signed_certificate_timestamp) whose body
    // is a SignedCertificateTimestampList of two SCTs, "SCT-one" and "SCT-2".
    const body = "\x00\x12\x00\x12" ++ "\x00\x10" ++ "\x00\x07SCT-one" ++ "\x00\x05SCT-2";
    var b64: [std.base64.standard.Encoder.calcSize(body.len)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&b64, body);
    var pem_buf: [256]u8 = undefined;
    const pem = try std.fmt.bufPrint(&pem_buf, "-----BEGIN SERVERINFO FOR signed_certificate_timestamp-----\n{s}\n-----END SERVERINFO FOR signed_certificate_timestamp-----\n", .{b64});
    try tmp.dir.writeFile(io, .{ .sub_path = "sct.pem", .data = pem });
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    var srv = try Server.startProto(io, tmp.dir, "-tls1_2", "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-serverinfo", "sct.pem", "-rev" });
    defer srv.stop(io);
    var storage: [16 * 1024]u8 = undefined;
    var ci: Client.ConnectionInfo = .init(&storage);
    _ = try session(io, srv.port, &bundle, .{ .connection_info = &ci });
    try testing.expectEqual(@as(usize, 2), ci.signedCertificateTimestamps().len);
    try testing.expectEqualStrings("SCT-one", ci.signedCertificateTimestamps()[0]);
    try testing.expectEqualStrings("SCT-2", ci.signedCertificateTimestamps()[1]);
}

const Hook = struct {
    calls: usize = 0,
    leaf_len: usize = 0,
    refuse: bool,
    fn verify(ctx: ?*anyopaque, info: *const Client.ConnectionInfo) anyerror!void {
        const h: *Hook = @ptrCast(@alignCast(ctx.?));
        h.calls += 1;
        h.leaf_len = info.peerCertificates()[0].len;
        if (h.refuse) return error.Pinned;
    }
};

test "interop: verify_connection -- runs once with the chain; refusing aborts with TlsConnectionRejected" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ "-tls1_3", "-tls1_2" }) |proto| {
        var storage: [16 * 1024]u8 = undefined;
        {
            var srv = try Server.startProto(io, tmp.dir, proto, "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
            defer srv.stop(io);
            var ci: Client.ConnectionInfo = .init(&storage);
            var h: Hook = .{ .refuse = false };
            const s = try session(io, srv.port, &bundle, .{ .connection_info = &ci, .verify_connection = .{ .context = &h, .verify = Hook.verify } });
            try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
            try testing.expectEqual(@as(usize, 1), h.calls);
            try testing.expectEqual(derFromPem(@embedFile("testdata/leaf.pem")).len, h.leaf_len);
        }
        {
            var srv = try Server.startProto(io, tmp.dir, proto, "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
            defer srv.stop(io);
            var ci: Client.ConnectionInfo = .init(&storage);
            var h: Hook = .{ .refuse = true };
            try testing.expectError(error.TlsConnectionRejected, session(io, srv.port, &bundle, .{ .connection_info = &ci, .verify_connection = .{ .context = &h, .verify = Hook.verify } }));
            try testing.expectEqual(@as(usize, 1), h.calls);
        }
    }
    var h: Hook = .{ .refuse = false };
    var srv = try Server.start(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem");
    defer srv.stop(io);
    try testing.expectError(error.ConnectionInfoRequired, session(io, srv.port, &bundle, .{ .verify_connection = .{ .context = &h, .verify = Hook.verify } }));
    try testing.expectEqual(@as(usize, 0), h.calls);
}

test "interop: exportKeyingMaterial equals openssl's -keymatexport (TLS 1.3; TLS 1.2 with EMS), refused without EMS" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ "-tls1_3", "-tls1_2" }) |proto| {
        var srv = try Server.startProto(io, tmp.dir, proto, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-keymatexport", "EXPERIMENTAL-zig-libs", "-keymatexportlen", "40" });
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .no_echo = true, .export_label = "EXPERIMENTAL-zig-libs", .export_len = 40 });
        var hex_buf: [128]u8 = undefined;
        const theirs = srv.reportedValue(io, "Keying material: ", &hex_buf) orelse return error.NoKeyingMaterialReported;
        var want: [40]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, theirs);
        try testing.expectEqualSlices(u8, &want, s.exported[0..40]);
    }
    {
        var srv = try Server.startProto(io, tmp.dir, "-tls1_2", "leaf.pem", "leaf.key.pem", "inter.pem", &.{"-rev"});
        defer srv.stop(io);
        try testing.expectError(error.ExporterUnavailable, session(io, srv.port, &bundle, .{ .extended_master_secret = false, .export_label = "x", .export_len = 8 }));
    }
}

test "interop: an Ed25519 server certificate (TLS 1.3 CertificateVerify, TLS 1.2 ECDHE_ECDSA)" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    const gen = std.process.run(testing.allocator, io, .{
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", "ed.key", "-out", "ed.pem", "-days", "2", "-subj", "/CN=ed.example.test", "-addext", "subjectAltName=DNS:ed.example.test" },
        .cwd = .{ .dir = tmp.dir },
    }) catch return error.SkipZigTest;
    testing.allocator.free(gen.stdout);
    testing.allocator.free(gen.stderr);
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ "-tls1_3", "-tls1_2" }) |proto| {
        var srv = try Server.startProto(io, tmp.dir, proto, "ed.pem", "ed.key", "ed.pem", &.{"-rev"});
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .host = "ed.example.test", .self_signed = true });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
    }
}

test "interop: KeyUpdate -- the server's update_requested is answered before our next record (s_server K / k)" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ "K", "k" }) |cmd| {
        var srv = try Server.start(io, tmp.dir, "leaf.pem", "leaf.key.pem", "inter.pem");
        defer srv.stop(io);
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", srv.port);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        const tv: std.posix.timeval = .{ .sec = 5, .usec = 0 };
        std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        var net_in: [Client.min_buffer_len]u8 = undefined;
        var net_out: [Client.min_buffer_len]u8 = undefined;
        var tls_in: [Client.min_buffer_len]u8 = undefined;
        var tls_out: [Client.min_buffer_len]u8 = undefined;
        var sr = stream.reader(io, &net_in);
        var sw = stream.writer(io, &net_out);
        var entropy: [Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        var lock: std.Io.RwLock = .init;
        var c = try Client.init(&sr.interface, &sw.interface, .{
            .host = .{ .explicit = "good.example.test" },
            .ca = .{ .bundle = .{ .gpa = testing.allocator, .io = io, .lock = &lock, .bundle = &bundle } },
            .read_buffer = &tls_in,
            .write_buffer = &tls_out,
            .entropy = &entropy,
            .realtime_now = std.Io.Clock.real.now(io),
        });
        // The server sends a KeyUpdate (K: update_requested, k: not), then "hello".
        var cmd_buf: [16]u8 = undefined;
        var sin = srv.child.stdin.?.writer(io, &cmd_buf);
        // Two writes: s_server acts on a command line and drops the rest of
        // that read (checked by hand, 2026-10-13).
        try sin.interface.writeAll(cmd ++ "\n");
        try sin.interface.flush();
        io.sleep(.fromMilliseconds(300), .awake) catch {};
        try sin.interface.writeAll("hello\n");
        try sin.interface.flush();
        const line = (try c.reader.takeDelimiter('\n')) orelse return error.EndOfStream;
        try testing.expectEqualStrings("hello", line);
        try testing.expectEqual(std.mem.eql(u8, cmd, "K"), c.key_update_pending);
        // Our next record: preceded by our KeyUpdate after "K"; either way the
        // server must read it.
        try c.writer.writeAll("ping-after-update\n");
        try c.writer.flush();
        try sw.interface.flush();
        try testing.expect(!c.key_update_pending);
        try c.end(); // close_notify: s_server ends the connection and exits (-naccept 1)
        try sw.interface.flush();
        try testing.expect(srv.reported(io, "ping-after-update"));
    }
}

// ── S2 (2026-10-13): client authentication -- TLS 1.2, RSA keys, selection ──

test "interop: TLS 1.2 client certificates -- P-256 and P-384 verified by openssl -Verify; Ed25519 sends none" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    const cases = .{
        .{ derFromPem(@embedFile("testdata/client-p256.pem")), p256Key(), "Peer certificate: CN=client-p256", "ECDSA+SHA256" },
        .{ derFromPem(@embedFile("testdata/client-p384.pem")), p384Key(), "Peer certificate: CN=client-p384", "ECDSA+SHA384" },
        // TLS 1.2 schemes bind the hash only: a P-256 key signing ECDSA+SHA384.
        .{ derFromPem(@embedFile("testdata/client-p256.pem")), p256Key(), "Peer certificate: CN=client-p256", "ECDSA+SHA384" },
    };
    inline for (cases) |c| {
        var srv = try Server.startProto(io, tmp.dir, "-tls1_2", "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-Verify", "1", "-CAfile", "client-ca.pem", "-client_sigalgs", c[3], "-rev" });
        defer srv.stop(io);
        const key: Client.ClientAuth.PrivateKey = c[1];
        const s = try session(io, srv.port, &bundle, .{ .client_auth = .{ .certificate_chain = &.{c[0]}, .key = &key } });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expectEqual(std.crypto.tls.ProtocolVersion.tls_1_2, s.version);
        try testing.expect(srv.reported(io, c[2]));
    }
    {
        // Ed25519 cannot sign a TLS 1.2 CertificateVerify: an empty
        // Certificate, and openssl -Verify refuses.
        var srv = try Server.startProto(io, tmp.dir, "-tls1_2", "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-Verify", "1", "-CAfile", "client-ca.pem", "-rev" });
        defer srv.stop(io);
        const key = ed25519Key();
        if (session(io, srv.port, &bundle, .{ .client_auth = .{ .certificate_chain = &.{derFromPem(@embedFile("testdata/client-ed25519.pem"))}, .key = &key } })) |_| return error.TestExpectedRefusal else |_| {}
    }
}

/// The first PEM block's DER, decoded at run time into `out`.
fn pemToDer(pem: []const u8, out: []u8) ![]const u8 {
    const begin = (std.mem.indexOf(u8, pem, "-----\n") orelse return error.BadPem) + 6;
    const end = std.mem.indexOfPos(u8, pem, begin, "\n-----END") orelse return error.BadPem;
    var clean: [8192]u8 = undefined;
    var n: usize = 0;
    for (pem[begin..end]) |ch| if (ch != '\n' and ch != '\r') {
        clean[n] = ch;
        n += 1;
    };
    const len = try std.base64.standard.Decoder.calcSizeForSlice(clean[0..n]);
    try std.base64.standard.Decoder.decode(out[0..len], clean[0..n]);
    return out[0..len];
}

test "interop: an RSA client key -- RSA-PSS in TLS 1.3, PKCS#1 v1.5 and PSS in TLS 1.2" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    const gen = std.process.run(testing.allocator, io, .{
        .argv = &.{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rsa.key", "-out", "rsa.pem", "-days", "2", "-subj", "/CN=client-rsa", "-addext", "extendedKeyUsage=clientAuth" },
        .cwd = .{ .dir = tmp.dir },
    }) catch return error.SkipZigTest;
    testing.allocator.free(gen.stdout);
    testing.allocator.free(gen.stderr);
    var key_pem: [4096]u8 = undefined;
    const key_text = try tmp.dir.readFile(io, "rsa.key", &key_pem);
    var cert_pem: [4096]u8 = undefined;
    const cert_text = try tmp.dir.readFile(io, "rsa.pem", &cert_pem);
    var der_buf: [4096]u8 = undefined;
    const cert_der = try pemToDer(cert_text, &der_buf);
    var kp: Client.rsa.KeyPair = undefined;
    try kp.secret_key.fromPem(key_text);
    const key: Client.ClientAuth.PrivateKey = .{ .rsa = &kp };
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    inline for (.{ .{ "-tls1_3", "RSA-PSS+SHA256" }, .{ "-tls1_3", "RSA-PSS+SHA512" }, .{ "-tls1_2", "RSA+SHA256" }, .{ "-tls1_2", "RSA-PSS+SHA384" } }) |c| {
        var srv = try Server.startProto(io, tmp.dir, c[0], "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-Verify", "1", "-CAfile", "rsa.pem", "-client_sigalgs", c[1], "-rev" });
        defer srv.stop(io);
        const s = try session(io, srv.port, &bundle, .{ .client_auth = .{ .certificate_chain = &.{cert_der}, .key = &key } });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expect(srv.reported(io, "Peer certificate: CN=client-rsa"));
    }
}

const Picker = struct {
    calls: usize = 0,
    schemes: usize = 0,
    cas: usize = 0,
    ca_matches: bool = false,
    auth: Client.ClientAuth,
    fn select(ctx: ?*anyopaque, info: *const Client.CertificateRequestInfo) ?Client.ClientAuth {
        const p: *Picker = @ptrCast(@alignCast(ctx.?));
        p.calls += 1;
        p.schemes = info.signature_schemes.len;
        p.cas = info.certificate_authorities.len;
        const ca_der = derFromPem(@embedFile("testdata/client-ca.pem"));
        for (info.certificate_authorities) |dn| {
            if (std.mem.indexOf(u8, ca_der, dn) != null) p.ca_matches = true;
        }
        return if (p.ca_matches) p.auth else null;
    }
};

test "interop: client_auth_select gets the request's schemes and CA names (TLS 1.3 and 1.2)" {
    const io = testing.io;
    var tmp = try setUp(io);
    defer tmp.cleanup();
    var bundle = try rootBundle(io, tmp.dir);
    defer bundle.deinit(testing.allocator);
    const key = p256Key();
    inline for (.{ "-tls1_3", "-tls1_2" }) |proto| {
        var srv = try Server.startProto(io, tmp.dir, proto, "leaf.pem", "leaf.key.pem", "inter.pem", &.{ "-Verify", "1", "-CAfile", "client-ca.pem", "-rev" });
        defer srv.stop(io);
        var picker: Picker = .{ .auth = .{ .certificate_chain = &.{derFromPem(@embedFile("testdata/client-p256.pem"))}, .key = &key } };
        const s = try session(io, srv.port, &bundle, .{ .client_auth_select = .{ .context = &picker, .select = Picker.select } });
        try testing.expectEqualStrings("olleh", s.echo[0..s.echo_len]);
        try testing.expectEqual(@as(usize, 1), picker.calls);
        try testing.expect(picker.schemes > 0);
        try testing.expectEqual(@as(usize, 1), picker.cas);
        try testing.expect(picker.ca_matches);
        try testing.expect(srv.reported(io, "Peer certificate: CN=client-p256"));
    }
}

// ── offline: the ClientHello, the ALPN answer, the CertificateRequest ──────

/// The ClientHello this module writes with Go-shaped option overrides.
const HelloOpts = struct {
    min_version: std.crypto.tls.ProtocolVersion = .tls_1_2,
    max_version: std.crypto.tls.ProtocolVersion = .tls_1_3,
    groups: []const std.crypto.tls.NamedGroup = &Client.default_groups,
    key_share_groups: []const std.crypto.tls.NamedGroup = &Client.default_key_share_groups,
};

fn clientHelloWith(out: []u8, o: HelloOpts) ![]const u8 {
    var in_buf: [Client.min_buffer_len]u8 = undefined;
    var in: std.Io.Reader = .fixed(&in_buf);
    in.end = 0;
    var w: std.Io.Writer = .fixed(out);
    var tls_in: [Client.min_buffer_len]u8 = undefined;
    var tls_out: [Client.min_buffer_len]u8 = undefined;
    const entropy = [_]u8{0x5a} ** Client.Options.entropy_len;
    if (Client.init(&in, &w, .{
        .host = .{ .explicit = "good.example.test" },
        .ca = .no_verification,
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .min_version = o.min_version,
        .max_version = o.max_version,
        .groups = o.groups,
        .key_share_groups = o.key_share_groups,
    })) |_| return error.TestUnexpectedSuccess else |e| switch (e) {
        error.VersionsInvalid, error.GroupsInvalid => |x| return x,
        else => {},
    }
    return w.buffered();
}

/// The ClientHello a client type writes with these options before it
/// blocks on the (empty) server stream -- std's shape for this module
/// (`std_groups`, a share each).
fn clientHello(comptime C: type, out: []u8, alpn: []const []const u8) ![]const u8 {
    var in_buf: [C.min_buffer_len]u8 = undefined;
    var in: std.Io.Reader = .fixed(&in_buf);
    in.end = 0;
    var w: std.Io.Writer = .fixed(out);
    var tls_in: [C.min_buffer_len]u8 = undefined;
    var tls_out: [C.min_buffer_len]u8 = undefined;
    const entropy = [_]u8{0x5a} ** C.Options.entropy_len;
    var opts: C.Options = .{
        .host = .{ .explicit = "good.example.test" },
        .ca = .no_verification,
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = 0 },
    };
    if (@hasField(C.Options, "alpn_protocols")) opts.alpn_protocols = alpn;
    if (@hasField(C.Options, "groups")) {
        opts.groups = &C.std_groups;
        opts.key_share_groups = &C.std_groups;
        opts.request_ocsp = false;
        opts.request_scts = false;
        opts.extended_master_secret = false;
        opts.renegotiation_info = false;
    }
    if (C.init(&in, &w, opts)) |_| return error.TestUnexpectedSuccess else |e| {
        // The option check comes before anything is written.
        if (std.mem.eql(u8, @errorName(e), "AlpnProtocolsInvalid")) return error.AlpnProtocolsInvalid;
    }
    return w.buffered();
}

test "std profile: with std's groups and shares the ClientHello is std's, plus the three ECDHE_ECDSA suites" {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const ours = try clientHello(Client, &a, &.{});
    const theirs = try clientHello(std.crypto.tls.Client, &b, &.{});
    try testing.expect(theirs.len > 100);
    // record(5) handshake(4) version(2) random(32) session id(33): the
    // cipher_suites vector starts at 76.
    const cs = 5 + 4 + 2 + 32 + 33;
    const n_std = std.mem.readInt(u16, theirs[cs..][0..2], .big);
    try testing.expectEqual(n_std + 6, std.mem.readInt(u16, ours[cs..][0..2], .big));
    // Ours = std's with 6 bytes of suites inserted after std's last suite
    // (which ones depends on AES hardware, as std's order does) ...
    const ins = cs + 2 + n_std;
    try testing.expectEqualSlices(u8, theirs[ins..], ours[ins + 6 ..]);
    const ecdsa = [_]u16{ 0xC02B, 0xC02C, 0xCCA9 };
    for (0..3) |i| try testing.expect(std.mem.indexOfScalar(u16, &ecdsa, std.mem.readInt(u16, ours[ins + 2 * i ..][0..2], .big)) != null);
    // ... and the three length fields in front of it grown by 6.
    try testing.expectEqual(std.mem.readInt(u16, theirs[3..5], .big) + 6, std.mem.readInt(u16, ours[3..5], .big));
    try testing.expectEqual(std.mem.readInt(u24, theirs[6..9], .big) + 6, std.mem.readInt(u24, ours[6..9], .big));
    try testing.expectEqualSlices(u8, theirs[9..cs], ours[9..cs]);
    try testing.expectEqualSlices(u8, theirs[cs + 2 .. ins], ours[cs + 2 .. ins]);
}

test "default options: Go's shape -- five groups listed, shares for X25519MLKEM768 and X25519 only" {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const go = try clientHelloWith(&a, .{});
    const std_shape = try clientHello(Client, &b, &.{});
    // Two shares instead of four: P-256 (65 + 4) and P-384 (97 + 4) bytes
    // gone, P-521 (2) added to supported_groups; then Go's requests:
    // status_request (9), signed_certificate_timestamp (4),
    // extended_master_secret (4), renegotiation_info (5).
    try testing.expectEqual(std_shape.len - (65 + 4) - (97 + 4) + 2 + 9 + 4 + 4 + 5, go.len);
    try testing.expect(std.mem.endsWith(u8, go, "\x00\x05\x00\x05\x01\x00\x00\x00\x00" ++ "\x00\x12\x00\x00" ++ "\x00\x17\x00\x00" ++ "\xff\x01\x00\x01\x00"));
    const groups = "\x00\x0a\x00\x0c\x00\x0a\x11\xec\x00\x1d\x00\x17\x00\x18\x00\x19";
    try testing.expect(std.mem.indexOf(u8, go, groups) != null);
    // key_share: X25519MLKEM768 (1184 + 32) then X25519 (32).
    const ks_at = std.mem.indexOf(u8, go, "\x00\x33").?;
    try testing.expectEqual(@as(u16, 4 + 1216 + 4 + 32), std.mem.readInt(u16, go[ks_at + 4 ..][0..2], .big));
    try testing.expectEqualSlices(u8, "\x11\xec\x04\xc0", go[ks_at + 6 ..][0..4]);
    try testing.expectEqualSlices(u8, "\x00\x1d\x00\x20", go[ks_at + 6 + 4 + 1216 ..][0..4]);
}

test "options: versions and groups are checked before anything is sent" {
    var a: [4096]u8 = undefined;
    try testing.expectError(error.VersionsInvalid, clientHelloWith(&a, .{ .min_version = .tls_1_3, .max_version = .tls_1_2 }));
    try testing.expectError(error.VersionsInvalid, clientHelloWith(&a, .{ .min_version = .tls_1_1 }));
    try testing.expectError(error.GroupsInvalid, clientHelloWith(&a, .{ .groups = &.{} }));
    try testing.expectError(error.GroupsInvalid, clientHelloWith(&a, .{ .groups = &.{.ffdhe2048} }));
    try testing.expectError(error.GroupsInvalid, clientHelloWith(&a, .{ .groups = &.{ .x25519, .x25519 } }));
    try testing.expectError(error.GroupsInvalid, clientHelloWith(&a, .{ .groups = &.{.x25519}, .key_share_groups = &.{.secp256r1} }));
    // TLS 1.3 only: supported_versions lists 1.3 alone.
    const h = try clientHelloWith(&a, .{ .min_version = .tls_1_3 });
    try testing.expect(std.mem.indexOf(u8, h, "\x00\x2b\x00\x03\x02\x03\x04") != null);
    // TLS 1.2 only: no key_share at all.
    const h2 = try clientHelloWith(&a, .{ .max_version = .tls_1_2 });
    try testing.expect(std.mem.indexOf(u8, h2, "\x00\x2b\x00\x03\x02\x03\x03") != null);
    try testing.expect(std.mem.indexOf(u8, h2, "\x00\x33\x00") == null);
}

test "ALPN offer: std's ClientHello plus the RFC 7301 extension, lengths grown by its size" {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const base = try clientHello(Client, &b, &.{});
    const with = try clientHello(Client, &a, &.{ "h2", "http/1.1" });
    // RFC 7301 §3.1: type 16, length 14, list length 12, "h2", "http/1.1".
    const ext = "\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1";
    try testing.expectEqual(base.len + ext.len, with.len);
    try testing.expectEqualSlices(u8, ext, with[base.len..]);
    // Record length, handshake length and extensions length each grew by 18.
    try testing.expectEqual(std.mem.readInt(u16, base[3..5], .big) + 18, std.mem.readInt(u16, with[3..5], .big));
    try testing.expectEqual(std.mem.readInt(u24, base[6..9], .big) + 18, std.mem.readInt(u24, with[6..9], .big));
    var diff: usize = 0;
    for (base, with[0..base.len]) |x, y| diff += @intFromBool(x != y);
    try testing.expect(diff >= 3 and diff <= 6); // only the three length fields
    var c: [4096]u8 = undefined;
    try testing.expectError(error.AlpnProtocolsInvalid, clientHello(Client, &c, &.{""}));
    try testing.expectError(error.AlpnProtocolsInvalid, clientHello(Client, &c, &.{"x" ** 256}));
}
