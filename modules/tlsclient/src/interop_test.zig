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
};

const Server = struct {
    child: std.process.Child,
    port: u16,

    /// `openssl s_server` for one connection, serving `cert` (+ `chain`).
    fn start(io: std.Io, dir: std.Io.Dir, cert: []const u8, key: []const u8, chain: []const u8) !Server {
        var child = std.process.spawn(io, .{
            .argv = &.{
                "openssl", "s_server", "-accept",     "127.0.0.1:0", "-cert",   cert,
                "-key",    key,        "-cert_chain", chain,         "-tls1_3", "-naccept",
                "1",
            },
            .cwd = .{ .dir = dir },
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .ignore,
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
                return .{ .child = child, .port = port };
            }
        }
    }

    fn stop(s: *Server, io: std.Io) void {
        s.child.kill(io);
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
