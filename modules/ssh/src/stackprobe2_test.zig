// SPDX-License-Identifier: MIT

//! Dead-stack probe for `userauth.PasswordCheck.check` on `testkit.stackprobe`
//! (the older `stackprobe_test.zig` covers the key paths): residue below the
//! burn, and the presented password as a needle in any frame -- including the
//! frames of the hook, which runs under the burn. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode).

const std = @import("std");
const userauth = @import("userauth.zig");
const transport = @import("transport.zig");
const server = @import("server.zig");
const vectors = @import("hostkey_vectors.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var password: [32]u8 = undefined;
var expected: [32]u8 = undefined;

fn hook(ctx: *anyopaque, user: []const u8, pw: []const u8) bool {
    _ = ctx;
    _ = user;
    if (pw.len != expected.len) return false;
    return std.crypto.timing_safe.eql([32]u8, pw[0..32].*, expected);
}

test "STACKPROBE: no password residue after PasswordCheck.check" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ssh probe password", &password, .{});
    expected = password;
    var ctx: u8 = 0;
    const check: userauth.PasswordCheck = .{ .ctx = &ctx, .checkFn = hook };
    const secrets = [_][]const u8{&password};

    _ = try P.run("PasswordCheck.check", userauth.PasswordCheck.check, .{ check, @as([]const u8, "probe-user"), @as([]const u8, &password) }, &secrets, .{});
}

// ── transport.connectInto ───────────────────────────────────────────────────
//
// `connectInto` is a client handshake, so it needs a server on the other end.
// A pool of socketpairs, each with a peer thread already blocked in
// `serverHandshake`, is built OUTSIDE the probed call; the probed function
// (`connectOnce`, tiny frames) takes the next pair, so every call the engine
// makes (the controls do not call it) gets a fresh peer. The needles are the
// session cipher state `connectInto` leaves in the caller's slot; nothing else
// is derived.

const pairs = 6;
var threaded: std.Io.Threaded = undefined;
var host_key: server.HostKey = undefined;
var next_pair: usize = 0;
var fds: [pairs][2]i32 = undefined;
var threads: [pairs]std.Thread = undefined;
var me_rbuf: [pairs][16 * 1024]u8 = undefined;
var me_wbuf: [pairs][16 * 1024]u8 = undefined;
var me_r: [pairs]std.Io.File.Reader = undefined;
var me_w: [pairs]std.Io.File.Writer = undefined;
var peer_rbuf: [pairs][16 * 1024]u8 = undefined;
var peer_wbuf: [pairs][16 * 1024]u8 = undefined;
var peer_heap: [pairs][256 * 1024]u8 = undefined;
var conn: transport.Transport = undefined;
var conn_heap: [256 * 1024]u8 = undefined;
var conn_fba: std.heap.FixedBufferAllocator = undefined;

const accept_any: transport.HostKeyPolicy = .{ .verifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: transport.HostKeyInfo) transport.HostKeyVerdict {
        return .accept;
    }
}.f }, .host = "127.0.0.1" };

fn peerMain(i: usize) void {
    const io = threaded.io();
    const f: std.Io.File = .{ .handle = fds[i][1], .flags = .{ .nonblocking = false } };
    var r = f.readerStreaming(io, &peer_rbuf[i]);
    var w = f.writerStreaming(io, &peer_wbuf[i]);
    var fba: std.heap.FixedBufferAllocator = .init(&peer_heap[i]);
    var t = transport.Transport.init(&r.interface, &w.interface);
    server.serverHandshake(&t, fba.allocator(), .{ .host_keys = (&host_key)[0..1] }) catch {};
}

fn connectOnce(out: *transport.Transport, gpa: std.mem.Allocator) transport.TransportError!void {
    const i = next_pair;
    next_pair += 1;
    return transport.connectInto(out, &me_r[i].interface, &me_w[i].interface, gpa, accept_any);
}

test "STACKPROBE: no session key residue after transport.connectInto" {
    try sp.skipUnlessOptimized();
    threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try server.HostKey.fromOpenSSH(&host_key, vectors.ed25519_key, null);
    const io = threaded.io();
    var started: usize = 0;
    defer for (0..started) |i| {
        _ = std.os.linux.shutdown(fds[i][0], std.os.linux.SHUT.RDWR);
        threads[i].join();
        _ = std.os.linux.close(fds[i][0]);
        _ = std.os.linux.close(fds[i][1]);
    };
    for (0..pairs) |i| {
        if (std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC, 0, &fds[i]) != 0) return error.SocketpairFailed;
        const f: std.Io.File = .{ .handle = fds[i][0], .flags = .{ .nonblocking = false } };
        me_r[i] = f.readerStreaming(io, &me_rbuf[i]);
        me_w[i] = f.writerStreaming(io, &me_wbuf[i]);
        threads[i] = try std.Thread.spawn(.{}, peerMain, .{i});
        started += 1;
    }
    conn_fba = .init(&conn_heap);

    _ = try P.run("connectInto", connectOnce, .{ &conn, conn_fba.allocator() }, &[_][]const u8{
        std.mem.asBytes(&conn.read_cipher),
        std.mem.asBytes(&conn.write_cipher),
    }, .{});
}
