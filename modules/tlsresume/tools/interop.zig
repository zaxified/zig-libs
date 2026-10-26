// SPDX-License-Identifier: MIT

//! Interop: real TLS clients resuming sessions whose every resumption step is
//! this module's — OpenSSL 3.x `s_client` and Go's crypto/tls client
//! (`tools/go_peer/main.go`) against `tlsserver.Server` over loopback TCP,
//! one connection per case, the cases in order (later ones resume what
//! earlier ones saved). `tlsserver` is only the engine: the tickets it
//! issues are `select.SessionState` sealed by a `StekRing` this program
//! rotates, it resumes through `select.selectPsk`, 0-RTT single use is a
//! `replay.StrikeRegister`, the stateful cases a `cache.SessionCache`.
//!
//!     zig build interop-tlsresume                    # run every case
//!     zig build interop-tlsresume -- --case openssl-grace
//!     zig build interop-tlsresume -- --capture       # also rewrite
//!                                                    # src/interop_vectors.zig
//!
//! What a foreign client proves here, per piece of this module:
//!   ticket.NewSessionTicket   the client stored our ticket and offered it back
//!   psk.*                     the server accepted the client's binder: the
//!                             client derived the same PSK from our
//!                             ticket_nonce (`resumed`)
//!   replay.deobfuscateAge     a 0-RTT case is refused for its age once the
//!                             server's clock runs 5 minutes ahead
//!   earlydata.*               the server read the client's 0-RTT "ping"
//!   replay.StrikeRegister     the same ticket's early data a second time is
//!                             refused, the resumption itself still taken
//!   stek rotation             a ticket under a rotated-out key resumes inside
//!                             `RotationPolicy.lifetime_s` and not after it,
//!                             the key still in the ring
//!   cache.SessionCache        a stateful ticket resumes once, then not again
//!   ticket12                  Go's client against OpenSSL's and Go's TLS 1.2
//!                             servers: their NewSessionTicket decodes, and
//!                             the client's SessionTicket extension says
//!                             "supports" on a full handshake and offers
//!                             exactly that ticket on the resumption
//!
//! The server's clock is simulated (`clock_ms`, set per case), the clients'
//! is real: a ticket "hours old" to the server is milliseconds old to the
//! client. The STEK keys are constants, so with `--capture` the resuming
//! ClientHellos (and the early data record behind one) are written to
//! `src/interop_vectors.zig`, and the hermetic `interop_replay_test.zig`
//! runs `selectPsk` and `EarlyDataContext` over them with no peer present —
//! a real client's binder, ticket age and 0-RTT record keep being checked in
//! every test lane. The TLS 1.2 messages go there too.
//!
//! Needs `openssl` (3.x) and `go` on PATH; the Go peer is built into
//! `.zig-cache/tlsresume-interop` first (`GOTOOLCHAIN=local`, nothing
//! downloaded). Run from the repository root (`zig build` does) or pass
//! `--repo-root <path>`.

const std = @import("std");
const net = std.Io.net;
const tlsresume = @import("tlsresume");
const tlsserver = @import("tlsserver");
const certs = tlsserver.test_fixtures;

const Server = tlsserver.Server;
const record = tlsserver.record;
const EarlyDataReason = tlsserver.server.EarlyDataReason;

const usage =
    \\usage: interop-tlsresume [--case NAME]... [--capture] [--list] [--repo-root PATH]
    \\
;

/// Short periods so that rotation and key expiry happen within one run:
/// a key rotates out after an hour and opens nothing after three.
pub const policy: tlsresume.RotationPolicy = .{ .period_s = 3600, .lifetime_s = 3 * 3600 };
const Ring = tlsresume.StekRing(tlsresume.depthFor(policy));

/// The server's clock at the start of the run (case `at_s` is added).
pub const clock0_ms: i64 = 1_800_000_000_000;
/// The STEK with id `n` is `@splat(key_fill + n)`.
pub const key_fill: u8 = 0x50;
/// `EarlyData.max_size` of the early-data cases.
const max_early_data: u32 = 16384;

const Peer = enum {
    openssl,
    go,
    /// Go's client in TLS 1.2 against `openssl s_server`: two connections,
    /// a full handshake saving the session and its resumption.
    go12_openssl,
    /// The same against the Go peer's own TLS 1.2 server.
    go12_go,
};

const TicketerKind = enum { stek, cache };

const Case = struct {
    name: []const u8,
    why: []const u8,
    peer: Peer = .openssl,
    /// Seconds after `clock0_ms` the server's clock reads.
    at_s: i64 = 0,
    /// Before the case, `maybeRotate` with the next key id.
    rotate: bool = false,
    ticketer: TicketerKind = .stek,
    suites: []const record.CipherSuite = &tlsserver.server.default_cipher_suites,
    groups: []const u16 = &tlsserver.server.default_groups,
    /// Extra client arguments.
    args: []const []const u8 = &.{},
    /// Substrings the client must print (stdout or stderr).
    expect: []const []const u8 = &.{},
    resumed: bool = false,
    /// The server takes early data (a register shared by the whole run).
    early_data: bool = false,
    /// What the server must report about early data.
    early_reason: ?EarlyDataReason = null,
    /// Write the client's ClientHello (and its early data record) to the
    /// vectors: the replay test resumes it through `selectPsk`.
    capture: bool = false,
    /// `freshness_window_ms` for the replay: null where the simulated clock
    /// moved between issue and resumption.
    freshness_ms: ?u32 = 10_000,
};

const resumed_ossl = "Reused, TLSv1.3";
const new_ossl = "New, TLSv1.3";

const cases = [_]Case{
    // Plain resumption, both hashes.
    .{ .name = "go-new", .peer = .go, .why = "Go saves a ticket (TLS_AES_128_GCM_SHA256: SHA-256 binder chain)", .suites = &.{.aes_128_gcm_sha256}, .args = &.{ "-sess-out", "go.sess" }, .expect = &.{"saved: true"} },
    .{ .name = "go-resume", .peer = .go, .why = "Go resumes it: its binder verifies, its ticket age de-obfuscates", .suites = &.{.aes_128_gcm_sha256}, .args = &.{ "-sess-in", "go.sess" }, .resumed = true, .capture = true },
    .{ .name = "openssl-new", .why = "s_client saves a ticket (TLS_AES_256_GCM_SHA384: SHA-384 chain)", .args = &.{ "-sess_out", "ossl.sess" } },
    .{ .name = "openssl-resume", .why = "s_client resumes it", .args = &.{ "-sess_in", "ossl.sess" }, .resumed = true, .capture = true },
    .{ .name = "openssl-resume-hrr", .why = "resumption after a HelloRetryRequest (binder over message_hash + HRR)", .groups = &.{tlsserver.server.default_groups[2]}, .args = &.{ "-sess_in", "ossl.sess", "-groups", "X25519:P-256" }, .resumed = true, .expect = &.{"Peer Temp Key: ECDH, prime256v1"} },
    // 0-RTT.
    .{ .name = "openssl-early-new", .why = "a ticket allowing early data", .early_data = true, .args = &.{ "-sess_out", "early.sess" }, .expect = &.{"Max Early Data: 16384"} },
    .{ .name = "openssl-early", .why = "0-RTT taken: the early traffic key opens s_client's record", .early_data = true, .args = &.{ "-sess_in", "early.sess", "-early_data", "early.txt" }, .resumed = true, .early_reason = .accepted, .expect = &.{"Early data was accepted"}, .capture = true },
    .{ .name = "openssl-early-replay", .why = "the same ticket's early data again: the strike register refuses it, the resumption stands", .early_data = true, .args = &.{ "-sess_in", "early.sess", "-early_data", "early.txt" }, .resumed = true, .early_reason = .replayed, .expect = &.{"Early data was rejected"} },
    .{ .name = "openssl-early2-new", .why = "a second early-data ticket", .early_data = true, .args = &.{ "-sess_out", "early2.sess" } },
    .{ .name = "openssl-early-skew", .at_s = 300, .why = "the server's clock 5 minutes ahead of the client's ticket age: early data refused, resumed", .early_data = true, .args = &.{ "-sess_in", "early2.sess", "-early_data", "early.txt" }, .resumed = true, .early_reason = .ticket_age_skew, .expect = &.{"Early data was rejected"} },
    // STEK rotation (`policy`: rotate hourly, keys live 3 hours).
    .{ .name = "openssl-grace", .at_s = 2 * 3600, .rotate = true, .why = "key 2 active; the ticket under key 1 still resumes (1 h past rotation)", .args = &.{ "-sess_in", "ossl.sess" }, .resumed = true, .capture = true, .freshness_ms = null },
    .{ .name = "openssl-new-k2", .at_s = 2 * 3600, .why = "a ticket under key 2", .args = &.{ "-sess_out", "ossl2.sess" } },
    .{ .name = "openssl-expired", .at_s = 3 * 3600 + 1, .why = "key 1 past its lifetime, still in the ring: its ticket is a full handshake", .args = &.{ "-sess_in", "ossl.sess" }, .capture = true, .freshness_ms = null },
    .{ .name = "go-expired", .peer = .go, .at_s = 3 * 3600 + 1, .why = "Go's ticket under key 1 likewise", .suites = &.{.aes_128_gcm_sha256}, .args = &.{ "-sess-in", "go.sess" } },
    .{ .name = "openssl-k2-resume", .at_s = 3 * 3600 + 1, .why = "the ticket under key 2 resumes", .args = &.{ "-sess_in", "ossl2.sess" }, .resumed = true },
    // Stateful tickets.
    .{ .name = "openssl-cache-new", .at_s = 4 * 3600, .ticketer = .cache, .why = "a stateful ticket (session id into a SessionCache)", .args = &.{ "-sess_out", "cache.sess" } },
    .{ .name = "openssl-cache-resume", .at_s = 4 * 3600, .ticketer = .cache, .why = "it resumes, taken from the cache", .args = &.{ "-sess_in", "cache.sess" }, .resumed = true },
    .{ .name = "openssl-cache-again", .at_s = 4 * 3600, .ticketer = .cache, .why = "the same ticket again: single use, full handshake", .args = &.{ "-sess_in", "cache.sess" } },
    // TLS 1.2 tickets (RFC 5077) from foreign servers.
    .{ .name = "go12-openssl", .peer = .go12_openssl, .why = "OpenSSL's TLS 1.2 NewSessionTicket and Go's SessionTicket extension, full and resumed" },
    .{ .name = "go12-go", .peer = .go12_go, .why = "Go's TLS 1.2 NewSessionTicket and SessionTicket extension, full and resumed" },
};

var clock_ms: i64 = clock0_ms;

fn now(_: ?*anyopaque) i64 {
    return clock_ms;
}

/// Everything later cases build on.
const Run = struct {
    ring: Ring = .init(),
    next_id: u8 = 2,
    /// (id, installed at s) of every key put into the ring.
    rotations: std.ArrayList([2]i64) = .empty,
    strikes: tlsresume.replay.StrikeRegister,
    cache: tlsserver.server.SessionCache(0),
    cache_random: std.Random.DefaultCsprng,
    key: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    /// Captured resumptions and TLS 1.2 messages.
    flights: std.ArrayList(Flight) = .empty,
    tls12: std.ArrayList(Tls12) = .empty,
};

const Flight = struct { case: Case, suite: record.CipherSuite, now_ms: i64, rotations: usize, bytes: []const u8 };
const Tls12 = struct { name: []const u8, nst: []const u8, offered: []const u8 };

fn stekKey(id: u8) [32]u8 {
    return @splat(key_fill +% id);
}

var child_env: ?*const std.process.Environ.Map = null;

/// Serve one connection by hand, recording what the client sent: receive
/// "ping\n" (as early data or after the handshake), answer "pong\n",
/// close_notify, read until the client closes.
fn serve(gpa: std.mem.Allocator, io: std.Io, stream: net.Stream, server: *Server, client_bytes: *std.ArrayList(u8)) !void {
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
            try flushOut(server, &sw.interface);
            return err;
        };
        switch (r.event) {
            .need_more, .handshake_done, .early_data_accepted => {},
            .signature_needed => return error.UnexpectedSignatureRequest,
            .app_data, .early_data => |d| {
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
        try flushOut(server, &sw.interface);
        if (r.event == .peer_closed) return;
        if (r.event != .need_more) continue;
        sr.interface.fillMore() catch |err| switch (err) {
            error.EndOfStream => return if (answered) {} else error.ClientLeft,
            else => return err,
        };
        const b = sr.interface.buffered();
        @memcpy(in[have..][0..b.len], b);
        have += b.len;
        try client_bytes.appendSlice(gpa, b);
        sr.interface.toss(b.len);
    }
}

fn flushOut(server: *Server, w: *std.Io.Writer) !void {
    const p = server.pendingOutput();
    if (p.len == 0) return;
    try w.writeAll(p);
    try w.flush();
    server.discardOutput(p.len);
}

const ChildOutput = struct { term: std.process.Child.Term, stdout: []u8, stderr: []u8 };

fn finish(gpa: std.mem.Allocator, io: std.Io, child: *std.process.Child) !ChildOutput {
    var ob: [4096]u8 = undefined;
    var or_ = child.stdout.?.reader(io, &ob);
    const stdout = try or_.interface.allocRemaining(gpa, .unlimited);
    var eb: [4096]u8 = undefined;
    var er = child.stderr.?.reader(io, &eb);
    const stderr = try er.interface.allocRemaining(gpa, .unlimited);
    return .{ .term = try child.wait(io), .stdout = stdout, .stderr = stderr };
}

fn exitedZero(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn runCase(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir, run: *Run, c: Case) !void {
    clock_ms = clock0_ms + c.at_s * 1000;
    if (c.rotate) {
        const key = stekKey(run.next_id);
        if (!run.ring.maybeRotate(policy, &key, @divFloor(clock_ms, 1000))) return error.NoRotation;
        try run.rotations.append(gpa, .{ run.next_id, @divFloor(clock_ms, 1000) });
        run.next_id += 1;
    }
    switch (c.peer) {
        .openssl, .go => {},
        .go12_openssl, .go12_go => return runTls12(gpa, io, work, run, c),
    }

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try local.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var port_buf: [32]u8 = undefined;
    const target = try std.mem.print(&port_buf, "127.0.0.1:{d}", .{listener.socket.address.getPort()});

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    switch (c.peer) {
        .openssl => try argv.appendSlice(gpa, &.{
            "openssl", "s_client", "-connect",         target,      "-tls1_3",     "-ign_eof",  "-verify_return_error",
            "-CAfile", "p256.pem", "-verify_hostname", "localhost", "-servername", "localhost",
        }),
        .go => try argv.appendSlice(gpa, &.{ "./go-peer", "-addr", target, "-ca", "p256.pem" }),
        else => unreachable,
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
    var stdin_buf: [16]u8 = undefined;
    var stdin_w = child.stdin.?.writer(io, &stdin_buf);
    // With its early data taken the client has said it all.
    if (c.early_reason != .accepted) {
        try stdin_w.interface.writeAll("ping\n");
        try stdin_w.interface.flush();
    }

    const stream = try listener.accept(io);
    defer stream.close(io);

    var chain: [1][]const u8 = .{&certs.p256_cert};
    const ck: tlsserver.CertifiedKey = .{ .chain = &chain, .key = .{ .ecdsa_p256 = &run.key } };
    var csprng = std.Random.DefaultCsprng.init(@splat(@truncate(@as(u64, @bitCast(clock_ms)))));
    const stek: tlsserver.StekTicketer(Ring) = .{ .ring = &run.ring, .policy = policy };
    const cache: tlsserver.server.CacheTicketer(tlsserver.server.SessionCache(0)) = .{
        .cache = &run.cache,
        .clock = .{ .now_ms = now },
        .random = run.cache_random.random(),
    };
    const tickets: tlsserver.Tickets = .{
        .ticketer = switch (c.ticketer) {
            .stek => stek.ticketer(),
            .cache => cache.ticketer(),
        },
        .clock = .{ .now_ms = now },
    };
    const early: tlsserver.server.EarlyData = .{ .max_size = max_early_data, .replay = tlsserver.server.strikeRegisterGuard(&run.strikes) };
    const cfg: tlsserver.Config = .{
        .certificate = .{ .fixed = &ck },
        .cipher_suites = c.suites,
        .groups = c.groups,
        .random = csprng.random(),
        .tickets = &tickets,
        .early_data = if (c.early_data) &early else null,
    };
    const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
    defer gpa.free(joiner);
    const out = try gpa.alloc(u8, tlsserver.server.minOutputLen(&cfg, &ck) + 4096);
    defer gpa.free(out);
    var server: Server = .init(&cfg, joiner, out);
    defer server.deinit();

    var client_bytes: std.ArrayList(u8) = .empty;
    const served = serve(gpa, io, stream, &server, &client_bytes);
    child.stdin.?.close(io);
    child.stdin = null;
    const o = try finish(gpa, io, &child);
    waited = true;

    served catch |err| {
        std.debug.print("  server: {t}\n  client said:\n{s}\n", .{ err, o.stderr });
        return err;
    };
    if (!exitedZero(o.term)) {
        std.debug.print("  client ended {any}:\n{s}\n", .{ o.term, o.stderr });
        return error.ClientFailed;
    }
    if (std.mem.indexOf(u8, o.stdout, "pong") == null) {
        std.debug.print("  client did not receive pong; stdout: {s}\n", .{o.stdout});
        return error.NoPong;
    }
    const resumed_line: []const u8 = switch (c.peer) {
        .openssl => if (c.resumed) resumed_ossl else new_ossl,
        .go => if (c.resumed) "resumed: true" else "resumed: false",
        else => unreachable,
    };
    var expect: std.ArrayList([]const u8) = .empty;
    try expect.appendSlice(gpa, c.expect);
    try expect.append(gpa, resumed_line);
    for (expect.items) |e| if (std.mem.indexOf(u8, o.stderr, e) == null and std.mem.indexOf(u8, o.stdout, e) == null) {
        std.debug.print("  client lacks \"{s}\":\n{s}\n--- stdout\n{s}\n", .{ e, o.stderr, o.stdout });
        return error.ExpectationMissing;
    };
    if (server.isResumed() != c.resumed) return error.ResumptionMismatch;
    if (c.early_reason) |want| if (server.earlyDataReason() != want) {
        std.debug.print("  early data: {s}, want {s}\n", .{ server.earlyDataReason().name(), want.name() });
        return error.EarlyDataMismatch;
    };
    if (c.capture) try run.flights.append(gpa, .{
        .case = c,
        .suite = server.cipherSuite() orelse return error.NoSuite,
        .now_ms = clock_ms,
        .rotations = run.rotations.items.len,
        .bytes = try firstFlight(gpa, client_bytes.items),
    });
}

/// The client's records up to its ClientHello's end, plus the first
/// application_data record after it (early data) if there is one before
/// anything else but a change_cipher_spec.
fn firstFlight(gpa: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var off: usize = 0;
    var hs_len: usize = 0;
    var need: ?usize = null;
    while (off + 5 <= bytes.len) {
        const len = std.mem.readInt(u16, bytes[off + 3 ..][0..2], .big);
        const end = off + 5 + len;
        if (end > bytes.len) return error.TruncatedFlight;
        const ct = bytes[off];
        if (need == null) {
            if (ct != 22) return error.NoClientHello;
            const body = bytes[off + 5 .. end];
            if (hs_len == 0) need = 4 + std.mem.readInt(u24, body[1..4], .big);
            hs_len += len;
            off = end;
            continue;
        }
        if (hs_len < need.?) {
            if (ct != 22) return error.NoClientHello;
            hs_len += len;
            off = end;
            continue;
        }
        if (ct == 20) {
            off = end;
            continue;
        }
        if (ct == 23) off = end;
        break;
    }
    return gpa.dupe(u8, bytes[0..off]);
}

/// The plaintext handshake messages of one direction (records of type 22
/// before its first change_cipher_spec), concatenated.
fn plaintextHandshake(gpa: std.mem.Allocator, stream: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var off: usize = 0;
    while (off + 5 <= stream.len) {
        const len = std.mem.readInt(u16, stream[off + 3 ..][0..2], .big);
        if (off + 5 + len > stream.len) return error.TruncatedRecord;
        if (stream[off] == 20) break;
        if (stream[off] == 22) try out.appendSlice(gpa, stream[off + 5 ..][0..len]);
        off += 5 + len;
    }
    return out.toOwnedSlice(gpa);
}

/// The body of the first handshake message of `msg_type` in `hs`.
fn findMessage(hs: []const u8, msg_type: u8) ?[]const u8 {
    var off: usize = 0;
    while (off + 4 <= hs.len) {
        const len = std.mem.readInt(u24, hs[off + 1 ..][0..3], .big);
        if (off + 4 + len > hs.len) return null;
        if (hs[off] == msg_type) return hs[off + 4 ..][0..len];
        off += 4 + len;
    }
    return null;
}

/// The data of extension `ext_type` in a ClientHello body (null if absent).
fn clientHelloExtension(ch: []const u8, ext_type: u16) !?[]const u8 {
    var off: usize = 2 + 32;
    if (off >= ch.len) return error.ShortClientHello;
    off += 1 + ch[off]; // legacy_session_id
    if (off + 2 > ch.len) return error.ShortClientHello;
    off += 2 + std.mem.readInt(u16, ch[off..][0..2], .big); // cipher_suites
    if (off >= ch.len) return error.ShortClientHello;
    off += 1 + ch[off]; // compression methods
    if (off + 2 > ch.len) return error.ShortClientHello;
    const end = off + 2 + std.mem.readInt(u16, ch[off..][0..2], .big);
    if (end > ch.len) return error.ShortClientHello;
    off += 2;
    while (off + 4 <= end) {
        const t = std.mem.readInt(u16, ch[off..][0..2], .big);
        const len = std.mem.readInt(u16, ch[off + 2 ..][0..2], .big);
        if (off + 4 + len > end) return error.ShortClientHello;
        if (t == ext_type) return ch[off + 4 ..][0..len];
        off += 4 + len;
    }
    return null;
}

/// One direction of a go-peer `-record` file.
fn direction(gpa: std.mem.Allocator, log: []const u8, dir: u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var off: usize = 0;
    while (off + 5 <= log.len) {
        const len = std.mem.readInt(u32, log[off + 1 ..][0..4], .big);
        if (off + 5 + len > log.len) return error.TruncatedRecording;
        if (log[off] == dir) try out.appendSlice(gpa, log[off + 5 ..][0..len]);
        off += 5 + len;
    }
    return out.toOwnedSlice(gpa);
}

/// Start a TLS 1.2 server (s_server or the Go peer's) and return it and
/// its address once it listens.
fn startServer12(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir, peer: Peer, addr_buf: []u8) !struct { std.process.Child, []const u8 } {
    switch (peer) {
        .go12_openssl => {
            // A free port: bind one, let it go, hand it to s_server.
            const local: net.IpAddress = .{ .ip4 = .loopback(0) };
            var probe = try local.listen(io, .{ .reuse_address = true });
            const port = probe.socket.address.getPort();
            probe.deinit(io);
            var port_s: [8]u8 = undefined;
            const p = try std.mem.print(&port_s, "{d}", .{port});
            var child = try std.process.spawn(io, .{
                .argv = &.{ "openssl", "s_server", "-accept", p, "-4", "-tls1_2", "-cert", "p256.pem", "-key", "p256.key", "-www", "-naccept", "2" },
                .cwd = .{ .dir = work },
                .environ_map = child_env,
                .stdin = .pipe,
                .stdout = .pipe,
                .stderr = .ignore,
            });
            errdefer child.kill(io);
            var lb: [256]u8 = undefined;
            var lr = child.stdout.?.reader(io, &lb);
            while (true) {
                const line = lr.interface.takeDelimiterExclusive('\n') catch return error.ServerDidNotStart;
                lr.interface.toss(1);
                if (std.mem.startsWith(u8, line, "ACCEPT")) break;
            }
            return .{ child, try std.mem.print(addr_buf, "127.0.0.1:{s}", .{p}) };
        },
        .go12_go => {
            var child = try std.process.spawn(io, .{
                .argv = &.{ "./go-peer", "-serve12", "-cert", "p256.pem", "-key", "p256.key", "-n", "2" },
                .cwd = .{ .dir = work },
                .environ_map = child_env,
                .stdin = .ignore,
                .stdout = .pipe,
                .stderr = .ignore,
            });
            errdefer child.kill(io);
            var lb: [256]u8 = undefined;
            var lr = child.stdout.?.reader(io, &lb);
            const line = lr.interface.takeDelimiterExclusive('\n') catch return error.ServerDidNotStart;
            const prefix = "listening: ";
            if (!std.mem.startsWith(u8, line, prefix)) return error.ServerDidNotStart;
            return .{ child, try std.mem.print(addr_buf, "{s}", .{line[prefix.len..]}) };
        },
        else => unreachable,
    }
    _ = gpa;
}

/// Go's client against a TLS 1.2 server, twice: a full handshake (the
/// server's NewSessionTicket must decode, the client's SessionTicket
/// extension must be empty) and the resumption (the extension must carry
/// exactly that ticket, and the server must resume).
fn runTls12(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir, run: *Run, c: Case) !void {
    var addr_buf: [64]u8 = undefined;
    var started = try startServer12(gpa, io, work, c.peer, &addr_buf);
    var server = &started[0];
    defer server.kill(io);
    const addr = started[1];
    const http = c.peer == .go12_openssl; // s_server -www answers HTTP
    var ticket: []const u8 = undefined;
    var nst_body: []const u8 = undefined;
    for ([_]bool{ false, true }) |resume_| {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(gpa, &.{ "./go-peer", "-addr", addr, "-ca", "p256.pem", "-tls12", "-record", "tls12.rec" });
        try argv.appendSlice(gpa, if (resume_) &.{ "-sess-in", "tls12.sess" } else &.{ "-sess-out", "tls12.sess" });
        if (http) try argv.appendSlice(gpa, &.{ "-send", "GET / HTTP/1.0\r\n\r\n", "-expect", "HTTP/1.0 200" });
        var child = try std.process.spawn(io, .{
            .argv = argv.items,
            .cwd = .{ .dir = work },
            .environ_map = child_env,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        const o = finish(gpa, io, &child) catch |err| {
            child.kill(io);
            return err;
        };
        if (!exitedZero(o.term)) {
            std.debug.print("  go-peer ended {any}:\n{s}\n", .{ o.term, o.stderr });
            return error.ClientFailed;
        }
        const want: []const u8 = if (resume_) "resumed: true" else "resumed: false";
        if (std.mem.indexOf(u8, o.stdout, want) == null or std.mem.indexOf(u8, o.stdout, "version: TLS 1.2") == null) {
            std.debug.print("  go-peer lacks \"{s}\" / TLS 1.2:\n{s}\n", .{ want, o.stdout });
            return error.ExpectationMissing;
        }
        const log = try work.readFileAlloc(io, "tls12.rec", gpa, .limited(1 << 20));
        const ch = findMessage(try plaintextHandshake(gpa, try direction(gpa, log, 'c')), 1) orelse return error.NoClientHello;
        const ext = try clientHelloExtension(ch, tlsresume.ticket12.extension_type) orelse return error.NoSessionTicketExtension;
        const class = tlsresume.ticket12.classifyClientExtension(ext);
        const server_hs = try plaintextHandshake(gpa, try direction(gpa, log, 's'));
        if (!resume_) {
            if (class != .supports_new) return error.ExtensionNotEmpty;
            nst_body = findMessage(server_hs, 4) orelse return error.NoNewSessionTicket;
            const nst = try tlsresume.ticket12.NewSessionTicket12.decode(nst_body);
            if (nst.isWithdrawal()) return error.TicketWithdrawn;
            ticket = nst.ticket;
            std.debug.print("  NewSessionTicket: lifetime hint {d} s, ticket {d} octets\n", .{ nst.lifetime_hint_s, nst.ticket.len });
        } else {
            if (class != .offers_ticket) return error.NoTicketOffered;
            if (!std.mem.eql(u8, ext, ticket)) return error.OfferedTicketDiffers;
            // An abbreviated handshake: no Certificate from the server.
            if (findMessage(server_hs, 11) != null) return error.NotAbbreviated;
            try run.tls12.append(gpa, .{ .name = c.name, .nst = nst_body, .offered = ext });
        }
    }
}

fn isSelected(selected: []const []const u8, c: Case) bool {
    if (selected.len == 0) return true;
    for (selected) |s| if (std.mem.eql(u8, s, c.name)) return true;
    return false;
}

fn pemLabel(gpa: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    const Enc = std.base64.standard.Encoder;
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "-----BEGIN {s}-----\n", .{label});
    const b64 = try gpa.alloc(u8, Enc.calcSize(der.len));
    const s = Enc.encode(b64, der);
    var i: usize = 0;
    while (i < s.len) : (i += 64) {
        try out.appendSlice(gpa, s[i..@min(s.len, i + 64)]);
        try out.append(gpa, '\n');
    }
    try out.print(gpa, "-----END {s}-----\n", .{label});
    return out.toOwnedSlice(gpa);
}

/// RFC 5915 ECPrivateKey for the P-256 test scalar (no public key: both
/// OpenSSL and Go derive it).
fn sec1Key() [51]u8 {
    return [_]u8{ 0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ certs.p256_scalar ++
        [_]u8{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
}

fn writeBytes(w: *std.Io.Writer, indent: []const u8, bytes: []const u8) !void {
    try w.writeAll("\"\" ++\n");
    var i: usize = 0;
    while (i < bytes.len) : (i += 32) {
        try w.print("{s}    \"", .{indent});
        for (bytes[i..@min(bytes.len, i + 32)]) |b| try w.print("\\x{x:0>2}", .{b});
        try w.writeAll(if (i + 32 < bytes.len) "\" ++\n" else "\"");
    }
}

fn writeVectors(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, run: *const Run) !void {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    const w = &aw.writer;
    try w.print(
        \\// SPDX-License-Identifier: MIT
        \\
        \\//! GENERATED by `zig build interop-tlsresume -- --capture`
        \\//! (`tools/interop.zig`); do not edit. Real clients' resuming
        \\//! ClientHellos against tickets this module sealed, and foreign TLS 1.2
        \\//! NewSessionTicket messages; `interop_replay_test.zig` replays them.
        \\
        \\/// The run's rotation policy, the server's clock at its start, and the
        \\/// STEKs: key `id` is `@splat(key_fill + id)`, installed at `at_s`.
        \\pub const period_s: i64 = {d};
        \\pub const lifetime_s: i64 = {d};
        \\pub const clock0_ms: i64 = {d};
        \\pub const key_fill: u8 = 0x{x:0>2};
        \\pub const Rotation = struct {{ id: u8, at_s: i64 }};
        \\pub const rotations = [_]Rotation{{
        \\    .{{ .id = 1, .at_s = {d} }},
        \\
    , .{ policy.period_s, policy.lifetime_s, clock0_ms, key_fill, @divFloor(clock0_ms, 1000) });
    for (run.rotations.items) |r| try w.print("    .{{ .id = {d}, .at_s = {d} }},\n", .{ r[0], r[1] });
    try w.writeAll(
        \\};
        \\
        \\pub const Resumption = struct {
        \\    name: []const u8,
        \\    /// Client: "openssl" or "go".
        \\    client: []const u8,
        \\    /// The suite negotiated (0x1301 / 0x1302 / 0x1303).
        \\    suite: u16,
        \\    /// The server's clock; the keys of `rotations[0..keys]` existed.
        \\    now_ms: i64,
        \\    keys: usize,
        \\    /// `selectPsk`'s freshness window (null: the simulated clock moved).
        \\    freshness_ms: ?u32,
        \\    /// The server resumed the ticket.
        \\    resumed: bool,
        \\    /// The plaintext of the early data record after the ClientHello.
        \\    early: ?[]const u8,
        \\    /// The client's records: its ClientHello, then any early data.
        \\    flight: []const u8,
        \\};
        \\
        \\pub const resumptions = [_]Resumption{
        \\
    );
    for (run.flights.items) |f| {
        try w.print("    .{{\n        .name = \"{s}\",\n        .client = \"{t}\",\n        .suite = 0x{x:0>4},\n        .now_ms = {d},\n        .keys = {d},\n", .{ f.case.name, f.case.peer, @backingInt(f.suite), f.now_ms, f.rotations + 1 });
        if (f.case.freshness_ms) |ms| try w.print("        .freshness_ms = {d},\n", .{ms}) else try w.writeAll("        .freshness_ms = null,\n");
        try w.print("        .resumed = {},\n", .{f.case.resumed});
        try w.writeAll(if (f.case.early_reason == .accepted) "        .early = \"ping\\n\",\n" else "        .early = null,\n");
        try w.writeAll("        .flight = ");
        try writeBytes(w, "        ", f.bytes);
        try w.writeAll(",\n    },\n");
    }
    try w.writeAll(
        \\};
        \\
        \\pub const Tls12 = struct {
        \\    name: []const u8,
        \\    /// The server's NewSessionTicket body (RFC 5077 §3.3).
        \\    nst: []const u8,
        \\    /// The resuming ClientHello's SessionTicket extension data.
        \\    offered: []const u8,
        \\};
        \\
        \\pub const tls12 = [_]Tls12{
        \\
    );
    for (run.tls12.items) |t| {
        try w.print("    .{{\n        .name = \"{s}\",\n        .nst = ", .{t.name});
        try writeBytes(w, "        ", t.nst);
        try w.writeAll(",\n        .offered = ");
        try writeBytes(w, "        ", t.offered);
        try w.writeAll(",\n    },\n");
    }
    try w.writeAll("};\n");
    try root.writeFile(io, .{ .sub_path = "modules/tlsresume/src/interop_vectors.zig", .data = aw.written() });
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
    // The Go peer is built with the installed toolchain only.
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
    try root.createDirPath(io, ".zig-cache/tlsresume-interop");
    var work = try root.openDir(io, ".zig-cache/tlsresume-interop", .{});
    defer work.close(io);
    try work.writeFile(io, .{ .sub_path = "p256.pem", .data = try pemLabel(gpa, "CERTIFICATE", &certs.p256_cert) });
    try work.writeFile(io, .{ .sub_path = "p256.key", .data = try pemLabel(gpa, "EC PRIVATE KEY", &sec1Key()) });
    // s_client's `-early_data` file.
    try work.writeFile(io, .{ .sub_path = "early.txt", .data = "ping\n" });

    var go_build = try std.process.spawn(io, .{
        .argv = &.{ "go", "build", "-o", "go-peer", "../../modules/tlsresume/tools/go_peer/main.go" },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
    });
    if (!exitedZero(try go_build.wait(io))) {
        std.debug.print("go build of tools/go_peer failed\n", .{});
        return 1;
    }

    var run: Run = .{
        .strikes = .init(gpa, 64, 3600 * 1000),
        .cache = try .init(gpa, 16, 24 * 3600),
        .cache_random = .init(@splat(0xca)),
        .key = try .fromBytes(certs.p256_scalar),
    };
    run.ring.rotate(1, &stekKey(1), @divFloor(clock0_ms, 1000));

    var failed: usize = 0;
    for (cases) |c| {
        if (!isSelected(selected.items, c)) continue;
        std.debug.print("{s}: {s}\n", .{ c.name, c.why });
        runCase(gpa, io, work, &run, c) catch |err| {
            std.debug.print("  FAIL {t}\n", .{err});
            failed += 1;
            continue;
        };
        std.debug.print("  ok\n", .{});
    }
    if (failed != 0) {
        std.debug.print("{d} case(s) failed\n", .{failed});
        return 1;
    }
    if (capture) {
        try writeVectors(gpa, io, root, &run);
        std.debug.print("wrote modules/tlsresume/src/interop_vectors.zig ({d} resumptions, {d} TLS 1.2)\n", .{ run.flights.items.len, run.tls12.items.len });
    }
    return 0;
}
