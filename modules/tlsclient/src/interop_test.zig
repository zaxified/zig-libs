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
        var argv_buf: [32][]const u8 = undefined;
        const base = [_][]const u8{
            "openssl", "s_server", "-accept",     "127.0.0.1:0", "-cert",   cert,
            "-key",    key,        "-cert_chain", chain,         "-tls1_3", "-naccept",
            "1",
        };
        @memcpy(argv_buf[0..base.len], &base);
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
};

const Session = struct {
    alpn: ?[]const u8,
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
        .host = .{ .explicit = "good.example.test" },
        .ca = .{ .bundle = .{ .gpa = testing.allocator, .io = io, .lock = &lock, .bundle = bundle } },
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        .alpn_protocols = ext.alpn,
        .client_auth = ext.client_auth,
    });
    var out: Session = .{ .alpn = c.alpn_protocol };
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

// ── offline: the ClientHello, the ALPN answer, the CertificateRequest ──────

/// The ClientHello a client type writes with these options before it
/// blocks on the (empty) server stream.
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
    if (C.init(&in, &w, opts)) |_| return error.TestUnexpectedSuccess else |e| {
        // The option check comes before anything is written.
        if (std.mem.eql(u8, @errorName(e), "AlpnProtocolsInvalid")) return error.AlpnProtocolsInvalid;
    }
    return w.buffered();
}

test "default options: the ClientHello is std's, byte for byte" {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const ours = try clientHello(Client, &a, &.{});
    const theirs = try clientHello(std.crypto.tls.Client, &b, &.{});
    try testing.expect(ours.len > 100);
    try testing.expectEqualSlices(u8, theirs, ours);
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
