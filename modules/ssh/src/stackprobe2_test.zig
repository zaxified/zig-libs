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
const messages = @import("messages.zig");
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

fn decideHook(ctx: *anyopaque, req: *const userauth.AuthRequest, pw: []const u8) userauth.Decision {
    _ = ctx;
    _ = req;
    return if (hook(transport.no_context, "", pw)) userauth.Decision.accepted else .reject;
}

test "STACKPROBE: no password residue after PasswordCallback.decide" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ssh probe password 2", &password, .{});
    expected = password;
    const cb: userauth.PasswordCallback = .{ .decideFn = decideHook };
    const req: userauth.AuthRequest = .{ .user = "probe-user", .completed = .empty, .session_id = "sid" };
    const secrets = [_][]const u8{&password};
    _ = try P.run("PasswordCallback.decide", userauth.PasswordCallback.decide, .{ cb, &req, @as([]const u8, &password) }, &secrets, .{});
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

// ── server.serverHandshake, by replay ────────────────────────────────────────
//
// The server's handshake reads the client's SERVICE_REQUEST before it
// returns, so a live peer has to get that far (a mirror of the connectInto
// pool whose peers stopped after NEWKEYS deadlocked: the probed server waited
// for a request nobody sent, and the peers were only shut down after the
// probe). No live peer at all is needed: with a deterministic entropy source
// each side is a pure function of what it has read, so both transcripts are
// built OUTSIDE the probe by alternating single-threaded passes, each side
// re-run from the start on everything the other has written so far, until
// both run to the end. A short transcript ends a pass with EndOfStream, never
// with a blocking read. The probed call replays the client's transcript from a
// fixed reader into a fixed writer.
//
// Each side's transcript then goes on with a re-exchange that puts
// CHANNEL_DATA where its KEXINIT announced a (wrong) guessed KEX packet. The
// receiving side reads that packet into its KEX round's heap scratch to
// discard it, then fails the round on the transcript's end; the round must
// wipe the scratch when it frees it. The scratch otherwise only ever holds public KEX
// packets, so this is the one way a secret reaches it.

const Det = struct {
    tag: u8,
    counter: u64 = 0,
    vt: std.Io.VTable = undefined,

    fn randomSecure(ud: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
        const self: *Det = @ptrCast(@alignCast(ud.?));
        var x = std.crypto.hash.sha3.Shake256.init(.{});
        x.update(&[_]u8{ 'h', 's', self.tag });
        x.update(std.mem.asBytes(&self.counter));
        x.squeeze(buf);
        self.counter += 1;
    }

    /// The same stream from its start.
    fn start(self: *Det) transport.Entropy {
        self.counter = 0;
        self.vt = std.Io.failing.vtable.*;
        self.vt.randomSecure = randomSecure;
        return .{ .io = .{ .userdata = self, .vtable = &self.vt } };
    }
};

var det_c: Det = .{ .tag = 'c' };
var det_s: Det = .{ .tag = 's' };
var cli_tx: [64 * 1024]u8 = undefined;
var cli_len: usize = 0;
var srv_tx: [64 * 1024]u8 = undefined;
var srv_len: usize = 0;
var pass_heap: [256 * 1024]u8 = undefined;
/// What each side sends as CHANNEL_DATA inside its misbehaving re-exchange.
var c_data: [32]u8 = undefined;
var s_data: [32]u8 = undefined;

fn serverConfig() server.ServerConfig {
    return .{ .host_keys = (&host_key)[0..1] };
}

/// A KEXINIT whose `first_kex_packet_follows` guess is wrong (its first KEX
/// name is one nobody supports), then, as the "guessed" packet the receiver
/// must read and discard (RFC 4253 §7), CHANNEL_DATA carrying `data`; both
/// under the current keys. The transcript ends there.
fn misbehave(t: *transport.Transport, gpa: std.mem.Allocator, data: []const u8) !void {
    const ki = try t.buildKexInit(gpa, .rekey);
    var kr: std.Io.Reader = .fixed(ki[1..]);
    var kex = try transport.KexInit.decode(gpa, &kr);
    var names: [32][]const u8 = undefined;
    names[0] = "no-such-kex@probe.invalid";
    @memcpy(names[1 .. kex.kex_algorithms.len + 1], kex.kex_algorithms);
    kex.kex_algorithms = names[0 .. kex.kex_algorithms.len + 1];
    kex.first_kex_packet_follows = true;
    var kb: [4096]u8 = undefined;
    var kw: std.Io.Writer = .fixed(&kb);
    try kex.encode(&kw);
    try transport.writePacket(t.writer, &t.write_cipher, t.entropy, kw.buffered());
    var b: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&b);
    try w.writeByte(@backingInt(messages.MessageType.SSH_MSG_CHANNEL_DATA));
    try w.writeInt(u32, 0, .big);
    try messages.writeString(&w, data);
    try transport.writePacket(t.writer, &t.write_cipher, t.entropy, w.buffered());
}

fn clientPass() bool {
    var fba: std.heap.FixedBufferAllocator = .init(&pass_heap);
    var r: std.Io.Reader = .fixed(srv_tx[0..srv_len]);
    var w: std.Io.Writer = .fixed(&cli_tx);
    defer cli_len = w.end;
    var t = transport.Transport.init(&r, &w);
    t.entropy = det_c.start();
    var buf: [4096]u8 = undefined;
    t.clientHandshake(fba.allocator(), accept_any) catch return false;
    t.requestService("ssh-userauth", &buf) catch return false;
    misbehave(&t, fba.allocator(), &c_data) catch return false;
    return true;
}

fn serverPass() bool {
    var fba: std.heap.FixedBufferAllocator = .init(&pass_heap);
    var r: std.Io.Reader = .fixed(cli_tx[0..cli_len]);
    var w: std.Io.Writer = .fixed(&srv_tx);
    defer srv_len = w.end;
    var t = transport.Transport.init(&r, &w);
    t.entropy = det_s.start();
    server.serverHandshake(&t, fba.allocator(), serverConfig()) catch return false;
    misbehave(&t, fba.allocator(), &s_data) catch return false;
    return true;
}

fn setupReplay() !void {
    try server.HostKey.fromOpenSSH(&host_key, vectors.ed25519_key, null);
    std.crypto.hash.sha2.Sha256.hash("ssh replay client channel data", &c_data, .{});
    std.crypto.hash.sha2.Sha256.hash("ssh replay server channel data", &s_data, .{});
    cli_len = 0;
    srv_len = 0;
    for (0..16) |_| {
        const c_ok = clientPass();
        const s_ok = serverPass();
        if (c_ok and s_ok) return;
    }
    return error.TranscriptsDidNotSettle;
}

var rp_r: std.Io.Reader = undefined;
var rp_w: std.Io.Writer = undefined;
var rp_sink: [64 * 1024]u8 = undefined;
var rp_heap: [256 * 1024]u8 = undefined;
var rp_fba: std.heap.FixedBufferAllocator = undefined;
var srv_t: transport.Transport = undefined;
var cli_t: transport.Transport = undefined;

/// The server's handshake on the recorded client transcript (tiny frame: it
/// only resets the replay and calls through).
fn serverOnce(out: *transport.Transport, gpa: std.mem.Allocator) transport.TransportError!void {
    rp_r = .fixed(cli_tx[0..cli_len]);
    rp_w = .fixed(&rp_sink);
    rp_fba.reset();
    out.* = transport.Transport.init(&rp_r, &rp_w);
    out.entropy = det_s.start();
    return server.serverHandshake(out, gpa, serverConfig());
}

fn clientOnce(out: *transport.Transport, gpa: std.mem.Allocator, buf: []u8) transport.TransportError!void {
    rp_r = .fixed(srv_tx[0..srv_len]);
    rp_w = .fixed(&rp_sink);
    rp_fba.reset();
    out.* = transport.Transport.init(&rp_r, &rp_w);
    out.entropy = det_c.start();
    try out.clientHandshake(gpa, accept_any);
    try out.requestService("ssh-userauth", buf);
}

test "STACKPROBE: no session key residue after server.serverHandshake" {
    try sp.skipUnlessOptimized();
    try setupReplay();
    rp_fba = .init(&rp_heap);
    // The replay is the exchange the transcript recorded (else the probe
    // would measure an early failure).
    try serverOnce(&srv_t, rp_fba.allocator());
    _ = try P.run("serverHandshake", serverOnce, .{ &srv_t, rp_fba.allocator() }, &[_][]const u8{
        std.mem.asBytes(&srv_t.read_cipher),
        std.mem.asBytes(&srv_t.write_cipher),
    }, .{});
}

/// `serverHandshake` up to the end of its initial KEX round: the version
/// exchange and `serverKexRound`, nothing sent after it. The handshake goes on
/// to send EXT_INFO and SERVICE_ACCEPT, and those packets' record burns cover
/// the round's dead frames too; this stops before them.
fn serverRoundOnce(out: *transport.Transport, gpa: std.mem.Allocator) transport.TransportError!void {
    rp_r = .fixed(cli_tx[0..cli_len]);
    rp_w = .fixed(&rp_sink);
    rp_fba.reset();
    out.* = transport.Transport.init(&rp_r, &rp_w);
    out.entropy = det_s.start();
    const cfg = serverConfig();
    out.role = .server;
    out.gpa = gpa;
    out.server_host_keys = cfg.host_keys;
    const v_c = try transport.exchangeVersions(gpa, &rp_r, &rp_w, .{ .softwareversion = cfg.server_software });
    try out.v_c.set(v_c);
    var vs: [255]u8 = undefined;
    try out.v_s.set(std.mem.print(&vs, "SSH-2.0-{s}", .{cfg.server_software}) catch return error.VersionExchangeFailed);
    _ = try server.serverKexRound(out, gpa, .initial, null, null);
}

test "STACKPROBE: no session key residue after server.serverKexRound (the initial exchange)" {
    try sp.skipUnlessOptimized();
    try setupReplay();
    rp_fba = .init(&rp_heap);
    try serverRoundOnce(&srv_t, rp_fba.allocator());
    _ = try P.run("serverKexRound", serverRoundOnce, .{ &srv_t, rp_fba.allocator() }, &[_][]const u8{
        std.mem.asBytes(&srv_t.read_cipher),
        std.mem.asBytes(&srv_t.write_cipher),
    }, .{});
}

test "server KEX round: a peer's out-of-order CHANNEL_DATA read into the round's scratch is wiped with it" {
    // Every mode runs the exchange; only an optimized build can fail the scan
    // (a safe build's `free` paints the block).
    try setupReplay();
    rp_fba = .init(&rp_heap);
    @memset(&rp_heap, 0);
    try serverOnce(&srv_t, rp_fba.allocator());
    var buf: [4096]u8 = undefined;
    // The client's KEXINIT starts a re-exchange inside recvPacket; the round
    // discards the CHANNEL_DATA as a wrong guess, then the transcript ends
    // (were it not discarded, the KEX method would fail on it: KexFailed).
    try std.testing.expectError(error.EndOfStream, srv_t.recvPacket(&buf));
    try std.testing.expect(std.mem.find(u8, &rp_heap, &c_data) == null);
}

test "client KEX round: a peer's out-of-order CHANNEL_DATA read into the round's scratch is wiped with it" {
    // Every mode runs the exchange; only an optimized build can fail the scan
    // (a safe build's `free` paints the block).
    try setupReplay();
    rp_fba = .init(&rp_heap);
    @memset(&rp_heap, 0);
    var sbuf: [4096]u8 = undefined;
    try clientOnce(&cli_t, rp_fba.allocator(), &sbuf);
    var buf: [4096]u8 = undefined;
    try std.testing.expectError(error.EndOfStream, cli_t.recvPacket(&buf));
    try std.testing.expect(std.mem.find(u8, &rp_heap, &s_data) == null);
}
