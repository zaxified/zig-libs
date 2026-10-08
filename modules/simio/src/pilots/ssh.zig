// SPDX-License-Identifier: MIT

//! Pilot: the `ssh` client and server, unchanged above `std.Io.net`, over
//! simulated TCP: key exchange, publickey userauth, one `exec` session, with
//! short reads, a lossy link, partitions and a server that crashes mid-run.
//! The property: a client that retries gets the command's exact output and
//! exit status once the network behaves; one that gives up after the first
//! broken connection does not, and the check must say so.
//!
//! The readiness check before it found a defect: the module drew its
//! ephemeral keys, KEXINIT cookies and padding from getrandom(2) behind
//! `std.Io`'s back, so the same seed gave a different session every run and
//! a failing trace could not be replayed byte for byte. Fixed in `ssh` the
//! same day (`transport.Entropy`); the session-id test below holds it.

const std = @import("std");
const ssh = @import("ssh");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const port = 22;
const expected_stdout = "ran 'report' as alice stdin='from-the-client'";
const expected_exit = 7;

fn userKey() ssh.userauth.AuthKey {
    return .{ .ed25519 = Ed25519.KeyPair.generateDeterministic(@splat(0x11)) catch unreachable };
}

const State = struct {
    /// The server signs with ECDSA, whose signature length depends on the
    /// exchange hash — so a nondeterministic KEX also changes packet sizes.
    ecdsa: bool = false,
    /// The broken variant: the client gives up after its first attempt.
    single_attempt: bool = false,
    /// The defect this pilot found: entropy from getrandom(2), not the `Io`.
    os_entropy: bool = false,
    /// Exchange hash of the client's last completed handshake.
    session_id: [64]u8 = @splat(0),
    session_id_len: usize = 0,
    attempts: u32 = 0,
    done: bool = false,
    stdout_ok: bool = false,
    exit_status: ?u32 = null,
    served: u32 = 0,
};

// ── the server ─────────────────────────────────────────────────────────────

const accept_any: ssh.transport.HostKeyPolicy = .{ .verifier = .{ .verifyFn = struct {
    fn f(_: *anyopaque, _: ssh.transport.HostKeyInfo) ssh.transport.HostKeyVerdict {
        return .accept;
    }
}.f }, .host = "server" };

const Authorized = struct {
    blob: []const u8,

    fn check(ctx: *anyopaque, user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
        const self: *Authorized = @ptrCast(@alignCast(ctx));
        return std.mem.eql(u8, user, "alice") and std.mem.eql(u8, algorithm, "ssh-ed25519") and
            std.mem.eql(u8, key_blob, self.blob);
    }
};

fn runCommand(
    _: *anyopaque,
    gpa: std.mem.Allocator,
    user: []const u8,
    command: []const u8,
    stdin: []const u8,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
) ssh.connection.CommandError!u32 {
    try stdout.print(gpa, "ran '{s}' as {s} stdin='{s}'", .{ command, user, stdin });
    try stderr.appendSlice(gpa, "diagnostic");
    return expected_exit;
}

fn serverMain(io: Io, gpa: std.mem.Allocator, st: *State) !void {
    var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{});
    defer listener.deinit(io);
    var group: Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        const stream = try listener.accept(io);
        group.async(io, serveConn, .{ io, gpa, stream, st });
    }
}

fn serveConn(io: Io, gpa: std.mem.Allocator, stream: net.Stream, st: *State) void {
    defer stream.close(io);
    serveConnInner(io, gpa, stream, st) catch {};
}

fn serveConnInner(io: Io, gpa: std.mem.Allocator, stream: net.Stream, st: *State) !void {
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const host_key: ssh.server.HostKey = if (st.ecdsa)
        .{ .ecdsa_p256 = try EcdsaP256.KeyPair.generateDeterministic(@splat(0x33)) }
    else
        .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(@splat(0x33)) };
    const keys = [_]ssh.server.HostKey{host_key};
    var t = ssh.transport.Transport.init(&sr.interface, &sw.interface);
    t.entropy = if (st.os_entropy) .os else .{ .io = io };
    try ssh.server.serverHandshake(&t, gpa, .{ .host_keys = &keys });

    const blob = try userKey().publicBlob(gpa);
    defer gpa.free(blob);
    var authorized: Authorized = .{ .blob = blob };
    const auth = try ssh.userauth.serveUserauth(&t, gpa, .{
        .authorized_key = .{ .ctx = &authorized, .checkFn = Authorized.check },
        .max_attempts = 2,
    });
    try ssh.connection.serveSession(&t, gpa, .{
        .user = auth.user(),
        .exec = .{ .ctx = ssh.transport.no_context, .runFn = runCommand },
        // A small window, so the output needs a WINDOW_ADJUST round trip.
        .window_size = 4 * 1024,
        .max_packet_size = 1024,
    });
    st.served += 1;
}

// ── the client ─────────────────────────────────────────────────────────────

/// Runs the command, giving each attempt 10 s: a server that crashed sends
/// no RST to a client that is only waiting, so without a deadline the client
/// would wait forever (TCP has no keepalive here, and neither has `ssh`).
fn client(io: Io, gpa: std.mem.Allocator, server: net.IpAddress, st: *State) !void {
    try io.sleep(.fromMilliseconds(200), .awake);
    while (!st.done) {
        st.attempts += 1;
        var attempt = io.async(clientAttempt, .{ io, gpa, server, st });
        var waited: u32 = 0;
        while (!st.done and waited < 100) : (waited += 1) try io.sleep(.fromMilliseconds(100), .awake);
        attempt.cancel(io) catch {};
        if (st.single_attempt) return;
        if (!st.done) try io.sleep(.fromMilliseconds(500), .awake);
    }
}

fn clientAttempt(io: Io, gpa: std.mem.Allocator, server: net.IpAddress, st: *State) !void {
    const stream = try server.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var t = ssh.transport.Transport.init(&sr.interface, &sw.interface);
    t.entropy = if (st.os_entropy) .os else .{ .io = io };
    try t.clientHandshake(gpa, accept_any);
    const sid = t.session_id.?.slice();
    @memcpy(st.session_id[0..sid.len], sid);
    st.session_id_len = sid.len;

    var pbuf: [16 * 1024]u8 = undefined;
    try t.requestService("ssh-userauth", &pbuf);
    const key = userKey();
    try ssh.userauth.authenticatePublickey(&t, gpa, "alice", &key, .{});
    const res = try ssh.exec(&t, gpa, "report", .{ .stdin = "from-the-client" });
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    st.stdout_ok = std.mem.eql(u8, res.stdout, expected_stdout) and std.mem.eql(u8, res.stderr, "diagnostic");
    st.exit_status = res.exit_status;
    st.done = true;
}

// ── the world ──────────────────────────────────────────────────────────────

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const s = try sim.addHost(.{}); // node 0
    const c = try sim.addHost(.{}); // node 1
    try sim.link(s, c, .{ .latency_ns = 20 * ns_per_ms, .jitter_ns = 5 * ns_per_ms });
    try s.spawnBoot(serverMain, .{ s.io(), s.allocator(), st });
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = s.ip4, .port = port } };
    // A client host that crashes runs the client again when it comes back.
    try c.spawnBoot(client, .{ c.io(), c.allocator(), addr, st });
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (!st.done) return error.NeverCompleted;
    if (!st.stdout_ok) return error.WrongOutput;
    if (st.exit_status != expected_exit) return error.WrongExitStatus;
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .ecdsa = st.ecdsa, .single_attempt = st.single_attempt, .os_entropy = st.os_entropy };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 1024 * 1024 },
        .setup = setup,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 120 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot ssh: exec over simulated TCP returns the exact output and exit status" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 1), st.attempts);
    try testing.expectEqual(@as(u32, 1), st.served);
}

test "pilot ssh: the same seed gives the same session, key exchange included" {
    for ([_]bool{ false, true }) |ecdsa| {
        var st: State = .{ .ecdsa = ecdsa };
        var first: [64]u8 = undefined;
        for (0..3) |i| {
            const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
            try testing.expectEqual(@as(?search.Violation, null), r.violation);
            try testing.expect(st.session_id_len > 0);
            if (i == 0) first = st.session_id else try testing.expectEqualSlices(u8, &first, &st.session_id);
        }
    }
}

test "pilot ssh: a server crash mid-run costs the client one attempt, not the result" {
    var st: State = .{};
    // The handshake is over by ~250 ms; the crash lands inside the session.
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(300, .{ .net = .{ .crash_node = .{ .node = 0 } } }),
        at(2000, .{ .net = .{ .restart_node = .{ .node = 0 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 2), st.attempts);
}

test "pilot ssh: a client that does not retry loses the result, and the check sees it" {
    var st: State = .{ .single_attempt = true };
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(300, .{ .net = .{ .crash_node = .{ .node = 0 } } }),
        at(2000, .{ .net = .{ .restart_node = .{ .node = 0 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.NeverCompleted), r.violation.?.err);
}

test "pilot ssh: the session survives loss, duplication, partitions and crashes across seeds" {
    var st: State = .{};
    const faults: search.FaultConfig = .{
        .schedule = .{
            .max_events = 6,
            .horizon = 5000,
            .repair_permille = 1000,
            .enable_clock_jump = false,
        },
    };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 20)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}

test "pilot ssh: the generic determinism check catches entropy drawn outside the Io" {
    // The bytes differ, the schedule does not: only the data fingerprint
    // sees it.
    var bad: State = .{ .os_entropy = true };
    try testing.expectError(error.NondeterministicData, search.checkDeterminism(testing.allocator, case(&bad), .{
        .schedule = .{ .max_events = 0, .horizon = 1000 },
    }));
    var good: State = .{};
    try search.checkDeterminism(testing.allocator, case(&good), .{ .schedule = .{ .max_events = 0, .horizon = 1000 } });
}
