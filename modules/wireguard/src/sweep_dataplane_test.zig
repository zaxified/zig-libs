// SPDX-License-Identifier: MIT
//! No-panic sweep tests for the data plane (handshake/noise/transport), wave GR.
//! Findings WH-1 .. WH-6, see ~/CML/20261029-panic-sweep/wireguard-dataplane-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const noise = @import("noise.zig");
const transport = @import("transport.zig");
const hs = @import("handshake.zig");

/// Run `body` in a forked child with its stderr captured into `buf`; returns
/// the captured length and whether the child died from a signal (a panic
/// aborts). A child past five seconds counts as hung.
const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

fn kp(seed: u8) hs.Keypair {
    var priv: hs.PrivateKey = @splat(seed);
    var out: hs.Keypair = undefined;
    hs.Keypair.fromPrivateKey(&priv, &out) catch unreachable;
    return out;
}

/// A responder that has consumed a valid initiation (deterministic, no entropy).
fn consumedResponder(ini: *hs.Handshake, rsp: *hs.Handshake) !void {
    const si = kp(1);
    const sr = kp(2);
    ini.* = .{ .static_keypair = si, .remote_static_public = sr.public, .local_ephemeral = kp(3), .local_index = 5 };
    rsp.* = .{ .static_keypair = sr, .remote_static_public = si.public, .local_ephemeral = kp(4), .local_index = 6 };
    const m1 = try ini.createInitiation(testing.io, @splat(0));
    try rsp.consumeInitiation(m1);
}

// ── WH-1: noise.keyedMac key length ─────────────────────────────────────────

fn keyedMacLong() void {
    const k: [65]u8 = @splat(7);
    _ = noise.keyedMac(&k, "x");
}
fn keyedMacMid() void {
    const k: [40]u8 = @splat(7);
    _ = noise.keyedMac(&k, "x");
}
fn keyedMac33() void {
    const k: [33]u8 = @splat(7);
    _ = noise.keyedMac(&k, "x");
}
fn keyedMacEmpty() void {
    _ = noise.keyedMac("", "x");
}

test "keyedMac: a key outside 1..32 bytes is a checked wireguard panic (sweep WH-1)" {
    const ok: [32]u8 = @splat(7);
    _ = noise.keyedMac(&ok, "x");
    try expectPanicMessage(keyedMacLong, "wireguard: keyedMac");
    try expectPanicMessage(keyedMacMid, "wireguard: keyedMac");
    try expectPanicMessage(keyedMacEmpty, "wireguard: keyedMac");
}

test "keyedMac: the upper bound is exactly 32 bytes (sweep audit GR-B1)" {
    try expectPanicMessage(keyedMac33, "wireguard: keyedMac");
}

// ── WH-2 (r1) / R-WH-1 / R-WH-2 / R-WH-3: state-machine misuse ──────────────

fn deriveIdle() void {
    var h: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public };
    var out: transport.TransportKeys = undefined;
    h.deriveTransportKeys(true, &out);
}

fn sessionIdle() void {
    var h: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public };
    var out: transport.Session = undefined;
    h.transportSession(true, 0, &out);
}

/// Complete handshake (deterministic ephemerals, no entropy).
fn completed(ini: *hs.Handshake, rsp: *hs.Handshake) !void {
    try consumedResponder(ini, rsp);
    const m2 = try rsp.createResponse(testing.io);
    try ini.consumeResponse(m2);
}

fn deriveTwice() void {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    completed(&ini, &rsp) catch return;
    var k: transport.TransportKeys = undefined;
    rsp.deriveTransportKeys(false, &k);
    rsp.deriveTransportKeys(false, &k);
}

fn sessionTwice() void {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    completed(&ini, &rsp) catch return;
    var s: transport.Session = undefined;
    ini.transportSession(true, 0, &s);
    ini.transportSession(true, 0, &s);
}

fn initiatorWrongRole() void {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    completed(&ini, &rsp) catch return;
    var k: transport.TransportKeys = undefined;
    ini.deriveTransportKeys(false, &k);
}

fn responderWrongRole() void {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    completed(&ini, &rsp) catch return;
    var sess: transport.Session = undefined;
    rsp.transportSession(true, 0, &sess);
}

test "Handshake: derive before complete is a checked panic (sweep WH-2)" {
    try expectPanicMessage(deriveIdle, "wireguard: deriveTransportKeys before");
    try expectPanicMessage(sessionIdle, "wireguard: deriveTransportKeys before");
}

test "Handshake: a replayed initiation at a used handshake is AlreadyStarted, not a panic (sweep WH-2)" {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    try consumedResponder(&ini, &rsp);
    var ini2: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public, .local_ephemeral = kp(3), .local_index = 5 };
    const m1 = try ini2.createInitiation(testing.io, @splat(0));
    try testing.expectError(error.AlreadyStarted, rsp.consumeInitiation(m1)); // initiation_consumed
    const m2 = try rsp.createResponse(testing.io);
    try ini.consumeResponse(m2);
    try testing.expectError(error.AlreadyStarted, rsp.consumeInitiation(m1)); // complete
}

test "Handshake: a second derive/transportSession is a checked panic; a finished handshake restarts nothing (sweep R-WH-1)" {
    try expectPanicMessage(deriveTwice, "wireguard: deriveTransportKeys before");
    try expectPanicMessage(sessionTwice, "wireguard: deriveTransportKeys before");
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    try completed(&ini, &rsp);
    var k: transport.TransportKeys = undefined;
    ini.deriveTransportKeys(true, &k);
    try testing.expectError(error.AlreadyStarted, ini.createInitiation(testing.io, @splat(0)));
    rsp.deriveTransportKeys(false, &k);
    try testing.expectError(error.AlreadyStarted, rsp.createResponse(testing.io));
}

test "Handshake: deriving with the wrong role is a checked panic (sweep R-WH-3)" {
    try expectPanicMessage(initiatorWrongRole, "wireguard: deriveTransportKeys role mismatch");
    try expectPanicMessage(responderWrongRole, "wireguard: deriveTransportKeys role mismatch");
}

// ── R-WH-4: CookieChecker.wipe must not leave a zero-key secret in force ────

test "CookieChecker.wipe: the next cookie at now_s < 120 is not MAC(0^32, addr) (sweep R-WH-4)" {
    var c: hs.CookieChecker = undefined;
    hs.CookieChecker.initWithSecret(kp(2).public, &@as([32]u8, @splat(0x55)), 1000, &c);
    c.wipe();
    const addr = "192.0.2.1:51820";
    var cookie: noise.Mac = undefined;
    c.cookieFor(testing.io, 5, addr, &cookie);
    const zero_key: [32]u8 = @splat(0);
    try testing.expect(!std.mem.eql(u8, &cookie, &noise.keyedMac(&zero_key, addr)));
    // admit under load with a zero mac2 answers with a cookie reply (gate not bypassed)
    c.wipe();
    var ini: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public, .local_ephemeral = kp(3) };
    const m1 = try ini.createInitiation(testing.io, @splat(0));
    switch (c.admit(testing.io, 5, std.mem.asBytes(&m1), addr, true)) {
        .cookie_reply => {},
        else => return error.TestUnexpectedResult,
    }
}

// ── R-WH-5: consumeResponse rejects a mis-addressed response before any DH ──

test "consumeResponse: wrong receiver_index / type is NoPendingInitiation, not a MAC/DH failure (sweep R-WH-5)" {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    try consumedResponder(&ini, &rsp);
    const m2 = try rsp.createResponse(testing.io);
    var bad = m2;
    bad.receiver_index +%= 1;
    try testing.expectError(error.NoPendingInitiation, ini.consumeResponse(bad));
    bad = m2;
    bad.type = 3;
    try testing.expectError(error.NoPendingInitiation, ini.consumeResponse(bad));
    try ini.consumeResponse(m2); // the genuine one still works
}

// ── R-WH-6: timestampNewer ──────────────────────────────────────────────────

test "timestampNewer: big-endian lexicographic, strict (sweep R-WH-6)" {
    var a: [12]u8 = @splat(0);
    var b: [12]u8 = @splat(0);
    try testing.expect(!hs.timestampNewer(a, b)); // equal
    a[11] = 1;
    try testing.expect(hs.timestampNewer(a, b)); // nanoseconds
    try testing.expect(!hs.timestampNewer(b, a));
    a = @splat(0);
    a[7] = 1; // 1 s, 0 ns
    b = @splat(0);
    b[8..12].* = .{ 0xff, 0xff, 0xff, 0xff }; // 0 s, max ns
    try testing.expect(hs.timestampNewer(a, b)); // seconds dominate nanoseconds
    try testing.expect(!hs.timestampNewer(b, a));
    a = @splat(0);
    a[0] = 1; // high second byte beats low ones
    b = @splat(0);
    b[7] = 0xff;
    try testing.expect(hs.timestampNewer(a, b));
    try testing.expect(!hs.timestampNewer(b, a));
}

// ── R-WH-8: a cookie reply is consumed once ─────────────────────────────────

test "PeerCookie.consumeReply: replaying the same reply is rejected (sweep R-WH-8)" {
    var ini: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public, .local_ephemeral = kp(3) };
    const m1 = try ini.createInitiation(testing.io, @splat(0));
    const bytes = std.mem.asBytes(&m1);
    var pc = hs.PeerCookie.init(kp(2).public);
    try pc.recordSent(bytes);
    var c: hs.CookieChecker = undefined;
    hs.CookieChecker.initWithSecret(kp(2).public, &@as([32]u8, @splat(0x55)), 1000, &c);
    const f = try hs.macFields(bytes);
    const reply = c.createReplyWithNonce(testing.io, 1000, f, "addr", @splat(1));
    try pc.consumeReply(reply, 1000);
    try testing.expect(pc.current(1000) != null);
    try testing.expectError(error.NoPendingMessage, pc.consumeReply(reply, 1100));
    try testing.expectEqual(@as(u64, 1000), pc.cookie_born_s); // not refreshed by the replay
}

// ── R-WH-9: createResponse is atomic ────────────────────────────────────────

test "createResponse: a failing DH leaves the handshake untouched and retryable (sweep R-WH-9)" {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    try consumedResponder(&ini, &rsp);
    const good = rsp.remote_static_public;
    const ck = rsp.chaining_key;
    const h = rsp.hash;
    rsp.remote_static_public = @splat(0); // low-order: the `se` DH fails after `e` and `ee` ran
    try testing.expectError(error.InvalidPublicKey, rsp.createResponse(testing.io));
    try testing.expectEqual(ck, rsp.chaining_key);
    try testing.expectEqual(h, rsp.hash);
    try testing.expect(rsp.state == .initiation_consumed);
    rsp.remote_static_public = good;
    const m2 = try rsp.createResponse(testing.io);
    try ini.consumeResponse(m2);
    try testing.expectEqual(ini.chaining_key, rsp.chaining_key);
}

// ── WH-6: public state fields desynchronised -> error, not `.?` ─────────────

test "Handshake: state set without its companion field is an error, not a panic (sweep WH-6)" {
    var h: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public };
    h.state = .initiation_sent; // local_ephemeral still null
    var bytes: [@sizeOf(hs.MessageResponse)]u8 = @splat(0);
    try testing.expectError(error.NoPendingInitiation, h.consumeResponse(std.mem.bytesToValue(hs.MessageResponse, &bytes)));
    h.state = .initiation_consumed; // remote_ephemeral still null
    try testing.expectError(error.NoInitiationConsumed, h.createResponse(testing.io));
}

// ── WH-3: paddedLen / sealedLen are total ───────────────────────────────────

test "paddedLen / sealedLen: lengths near maxInt(usize) saturate instead of overflowing (sweep WH-3)" {
    const max = std.math.maxInt(usize);
    try testing.expectEqual(max, transport.paddedLen(max));
    try testing.expectEqual(max, transport.paddedLen(max - 7));
    try testing.expectEqual(max, transport.sealedLen(max));
    try testing.expectEqual(@as(usize, 16), transport.paddedLen(1));
    try testing.expectEqual(@as(usize, 0), transport.paddedLen(0));
    try testing.expectEqual(@as(usize, 48), transport.sealedLen(1));
}

// ── WH-4: seal tolerates `packet` overlapping `out` ─────────────────────────

test "SendSession.seal: a packet overlapping out seals correctly (sweep WH-4)" {
    const key: [32]u8 = @splat(9);
    var plain: [37]u8 = undefined;
    for (&plain, 0..) |*b, i| b.* = @intCast(i + 1);
    inline for (.{ 0, 5, 16, 20 }) |off| {
        var s: transport.SendSession = undefined;
        s.init(&key, 77, 100);
        var r: transport.RecvSession = undefined;
        r.init(&key, 77, 100);
        var buf: [128]u8 = @splat(0);
        @memcpy(buf[off..][0..plain.len], &plain);
        const res = try s.seal(&buf, buf[off..][0..plain.len], 100);
        try testing.expectEqual(transport.sealedLen(plain.len), res.len);
        var out: [64]u8 = undefined;
        const o = try r.open(&out, buf[0..res.len], 100);
        try testing.expectEqualSlices(u8, &plain, out[0..plain.len]);
        try testing.expect(std.mem.allEqual(u8, out[plain.len..o.len], 0));
    }
}

// ── WH-5: ReplayWindow.commit ignores a counter off the trailing edge ───────

test "ReplayWindow: committing a stale counter does not mark a newer one seen (sweep WH-5)" {
    const W = transport.ReplayWindow(transport.default_window_bits);
    var w: W = .{};
    w.commit(20000);
    const fresh: u64 = 19990; // inside the window, unseen
    const stale: u64 = fresh - 8192; // aliases fresh's block and bit
    try testing.expect(w.accepts(fresh));
    try testing.expect(!w.accepts(stale));
    w.commit(stale); // caller error: accepts() said no
    try testing.expect(w.accepts(fresh));
    w.commit(fresh);
    try testing.expect(!w.accepts(fresh));
}

// ── audit GR-B2..B4: failed calls must not record a role / reach `.?` ───────

test "Handshake: a refused createInitiation / consumeInitiation does not record a role (sweep audit GR-B2)" {
    var ini: hs.Handshake = undefined;
    var rsp: hs.Handshake = undefined;
    try consumedResponder(&ini, &rsp);
    try testing.expect(rsp.role == .responder);
    try testing.expectError(error.AlreadyStarted, rsp.createInitiation(testing.io, @splat(0)));
    try testing.expect(rsp.role == .responder); // not flipped by the refused call
    // a consumeInitiation that fails (bad mac1) leaves the role unset
    var ini2: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public, .local_ephemeral = kp(3) };
    var m1 = try ini2.createInitiation(testing.io, @splat(0));
    m1.mac1[0] ^= 1;
    var fresh: hs.Handshake = .{ .static_keypair = kp(2), .remote_static_public = kp(1).public, .local_ephemeral = kp(4) };
    try testing.expectError(error.InvalidMac1, fresh.consumeInitiation(m1));
    try testing.expect(fresh.role == .none);
    try testing.expect(fresh.state == .idle);
}

test "consumeResponse: initiation_sent without local_ephemeral on an addressed response is an error (sweep audit GR-B3)" {
    var h: hs.Handshake = .{ .static_keypair = kp(1), .remote_static_public = kp(2).public, .local_index = 9 };
    h.state = .initiation_sent; // local_ephemeral still null
    var msg = std.mem.zeroes(hs.MessageResponse);
    msg.type = 2;
    msg.receiver_index = 9;
    try testing.expectError(error.NoPendingInitiation, h.consumeResponse(msg));
}

test "ReplayWindow: a counter one past the trailing edge does not mark a future counter seen (sweep audit GR-B4)" {
    const W = transport.ReplayWindow(transport.default_window_bits);
    var w: W = .{};
    w.commit(20031); // last = 20032, a multiple of 64
    const stale: u64 = 20032 - 8130; // last - n == capacity + 1
    try testing.expect(!w.accepts(stale));
    w.commit(stale);
    w.commit(20100); // moves past 20095 without clearing its block (n=20101 is in the next block)
    try testing.expect(w.accepts(20094)); // aliases stale's bit; was never seen
}
