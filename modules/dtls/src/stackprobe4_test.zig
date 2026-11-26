// SPDX-License-Identifier: MIT

//! Dead-stack probes (`testkit.stackprobe`, `Probe.run`) for the burn/wipe sites of the 2026-11-26 whole-module
//! mutation run that the older probes (`stackprobe_test.zig`: DTLS 1.3 PSK/cert hand-written; `stackprobe3_test.zig`:
//! DTLS 1.2 PSK) could not judge:
//!
//!   * every public entry point of both engines that carries a `burn.run` (`startHandshake`, `handleFlight`, `poll`
//!     in the handshake and in the connected state, `send`, `recv`, `installApplicationKeys`): the entry is called in a
//!     state where it does real work; a removed burn leaves the body's frames (the payload, the key schedule, the
//!     ECDHE and ticket secrets) on the dead stack, which the needles or the residue rule then find;
//!   * the flows that reach the stack-local wipes inside the handshake bodies (1.3: certificate ECDHE with tickets,
//!     resumption with 0-RTT, an expired ticket, a ticket of another hash; 1.2: PSK with tickets, abbreviated
//!     resumption, ECDHE_PSK), so that a wipe that is only a second line behind the entry's burn is shown to be
//!     redundant (the probe passes with the wipe removed) and the entry's burn to be load-bearing (the probe fails
//!     with it removed).
//!
//! ReleaseFast only (`sp.skipUnlessOptimized`). Connections, buffers and tickets live in static memory.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const conn13 = @import("Connection.zig");
const c12 = @import("Connection12.zig");
const record = @import("record.zig");
const prf12 = @import("prf12.zig");
const cert_kat = @import("certauth_kat_vectors.zig");
const tlsresume = @import("tlsresume");

const Ecdsa = std.crypto.sign.ecdsa;
const Aes128 = std.crypto.core.aes.Aes128;
const testing = std.testing;

/// Handshake entry points (burns of 128 / 224 KiB) and record-sized ones (8 KiB).
const PB = sp.Probe(.{ .window = 256 * 1024, .repeats = 1 });
const PR = sp.Probe(.{ .window = 64 * 1024, .repeats = 1 });

var cl13: conn13.Connection = undefined;
var sv13: conn13.Connection = undefined;
var cl12: c12.Connection12 = undefined;
var sv12: c12.Connection12 = undefined;
var xa: [8192]u8 = undefined; // client -> server
var yb: [8192]u8 = undefined; // server -> client
var pc: [2048]u8 = undefined; // poll output
var pb: [2048]u8 = undefined; // recv output
var ex_out: [32]u8 = undefined;
var last: usize = 0;
var okf: bool = false;
var done: bool = false;
var prng: std.Random.DefaultCsprng = undefined;

const msg1 = "client probe payload 0123456789abcdef";
const msg2 = "server probe payload fedcba9876543210";

fn seed(s: u8) void {
    prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(s)));
}

fn rnd() conn13.Entropy {
    return .{ .seeded_for_test = prng.random() };
}

/// One probed call; the wrapper must have succeeded.
fn step(comptime P: type, comptime label: []const u8, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f)), needles: []const []const u8) !void {
    okf = false;
    _ = try P.run(label, f, args, needles, .{});
    try testing.expect(okf);
}

/// One probed call whose wrapper may report an error by design (a record that is an ACK, a KeyUpdate ...).
fn stepAny(comptime P: type, comptime label: []const u8, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f)), needles: []const []const u8) !void {
    _ = try P.run(label, f, args, needles, .{});
}

// ── wrappers: DTLS 1.3 ───────────────────────────────────────────────────

fn w13Start(c: *conn13.Connection, o: []u8) void {
    okf = false;
    const r = c.startHandshake(rnd(), 0, o) catch return;
    last = r.len;
    okf = true;
}
fn w13Flight(c: *conn13.Connection, dg: []const u8, now_ms: u64, o: []u8) void {
    okf = false;
    const r = c.handleFlight(dg, rnd(), now_ms, o) catch return;
    last = r.out.len;
    done = r.done;
    okf = true;
}
fn w13Poll(c: *conn13.Connection, now_ms: u64, o: []u8) void {
    okf = false;
    const r = c.poll(now_ms, o) catch return;
    last = if (r) |b| b.len else 0;
    okf = true;
}
fn w13Send(c: *conn13.Connection, p: []const u8, o: []u8) void {
    okf = false;
    const r = c.send(p, o) catch return;
    last = r.len;
    okf = true;
}
fn w13Recv(c: *conn13.Connection, dg: []const u8, o: []u8) void {
    okf = false;
    const r = c.recv(dg, o) catch return;
    last = r.len;
    okf = true;
}
fn w13InstallKeys(c: *conn13.Connection, a: *const [32]u8, b: *const [32]u8) void {
    okf = false;
    c.installApplicationKeys(c.suite, a, b) catch return;
    okf = true;
}

// ── wrappers: DTLS 1.2 ───────────────────────────────────────────────────

fn w12Start(c: *c12.Connection12, o: []u8) void {
    okf = false;
    const r = c.startHandshake(rnd(), 0, o) catch return;
    last = r.len;
    okf = true;
}
fn w12Flight(c: *c12.Connection12, dg: []const u8, o: []u8) void {
    okf = false;
    const r = c.handleFlight(dg, rnd(), 0, o) catch return;
    last = r.out.len;
    done = r.done;
    okf = true;
}
fn w12Poll(c: *c12.Connection12, now_ms: u64, o: []u8) void {
    okf = false;
    const r = c.poll(now_ms, o) catch return;
    last = if (r) |b| b.len else 0;
    okf = true;
}
fn w12Send(c: *c12.Connection12, p: []const u8, o: []u8) void {
    okf = false;
    const r = c.send(p, o) catch return;
    last = r.len;
    okf = true;
}
fn w12Recv(c: *c12.Connection12, dg: []const u8, o: []u8) void {
    okf = false;
    const r = c.recv(dg, o) catch return;
    last = r.len;
    okf = true;
}
fn w12Export(c: *c12.Connection12, o: []u8) void {
    okf = false;
    c.exportKeyingMaterial("EXPORTER-probe", null, o) catch return;
    okf = true;
}

// ── DTLS 1.3 ─────────────────────────────────────────────────────────────

const psk13 = "a 1.3 probe pre-shared key, 32 B";
const now13: i64 = cert_kat.valid_now_sec;

const AesCtx = @TypeOf(Aes128.initEnc(@as([16]u8, @splat(0))));

fn aesImage(key: []const u8) AesCtx {
    return Aes128.initEnc(key[0..16].*);
}

/// A needle list in static memory (the AES key-schedule images it names must outlive the probed call).
const NeedleList = struct {
    items: [40][]const u8 = undefined,
    n: usize = 0,
    imgs: [12]AesCtx = undefined,
    ni: usize = 0,

    fn reset(self: *NeedleList) *NeedleList {
        self.n = 0;
        self.ni = 0;
        return self;
    }
    fn add(self: *NeedleList, s: []const u8) void {
        self.items[self.n] = s;
        self.n += 1;
    }
    fn addAll(self: *NeedleList, more: []const []const u8) void {
        for (more) |m| self.add(m);
    }
    fn addAes(self: *NeedleList, key: []const u8) void {
        self.imgs[self.ni] = aesImage(key);
        self.add(std.mem.asBytes(&self.imgs[self.ni]));
        self.ni += 1;
    }
    /// One direction's keys (either engine's `DirKeys`): record key, sequence-number key (1.3), their AES-128 round
    /// keys, and the expanded AES-GCM context the connection keeps.
    fn addDir(self: *NeedleList, d: anytype, comptime has_sn: bool) void {
        const klen: usize = if (@hasField(@TypeOf(d.*), "key_len")) d.key_len else d.bulk.keyLen();
        self.add(d.key[0..klen]);
        if (klen == 16) self.addAes(d.key[0..16]);
        if (has_sn) {
            self.add(d.sn_key[0..d.sn_len]);
            if (d.sn_len == 16) self.addAes(d.sn_key[0..16]);
        }
        switch (d.gcm) {
            .none => {},
            .g128 => |*c| self.add(std.mem.asBytes(c)),
            .g256 => |*c| self.add(std.mem.asBytes(c)),
        }
    }
};
var nl: NeedleList = .{};

fn initCert() !void {
    sk_srv = try Ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes);
    ring13 = .init();
    ring13.rotate(1, &@as([32]u8, @splat(0x42)), now13);
    tkr13 = .{ .ring = &ring13 };
}

/// One unprobed pass over the code every probe below runs, so that the first probed call of a process does not depend on
/// which test ran before it (a first call can leave bytes below its burn that later ones do not: see `stackprobe2_test.zig`
/// `warmUp`; the mutation schemata's one-time `DTLS_MUT` read is such an effect too).
fn warmUp() !void {
    seed(0x7f);
    try plainPsk13();
    const r = try cl13.send(msg1, &xa);
    _ = try sv13.recv(r, &pb);
    cl13.deinit();
    sv13.deinit();
    try initCert();
    seed(0x7c);
    cl13 = try conn13.Connection.clientInit(certClient(.aes_128_gcm_sha256, null, &.{}));
    sv13 = try conn13.Connection.serverInit(certServer(0, null));
    const c1 = try cl13.startHandshake(rnd(), 0, &xa);
    const s1 = try sv13.handleFlight(c1, rnd(), 0, &yb);
    const c2 = try cl13.handleFlight(s1.out, rnd(), 0, &xa);
    _ = try sv13.handleFlight(c2.out, rnd(), 0, &yb);
    cl13.deinit();
    sv13.deinit();
    seed(0x7e);
    try connectPlain12(cfg12(.client, .psk_with_aes_128_gcm_sha256, false), cfg12(.server, .psk_with_aes_128_gcm_sha256, false));
    const r2 = try cl12.send(msg1, &xa);
    _ = try sv12.recv(r2, &pb);
    cl12.deinit();
    sv12.deinit();
    seed(0x7d);
    try connectPlain12(cfg12(.client, .ecdhe_psk_with_chacha20_poly1305_sha256, false), cfg12(.server, .ecdhe_psk_with_chacha20_poly1305_sha256, false));
    cl12.deinit();
    sv12.deinit();
}

fn cfg13Psk(role: conn13.Role) conn13.Config {
    return .{ .role = role, .psk_identity = "device-13", .psk = psk13, .cipher_suites = &.{.aes_128_gcm_sha256} };
}

test "mutation 2026-11-26: STACKPROBE: DTLS 1.3 PSK handshake, retransmission, records and KeyUpdate burn at every entry point" {
    try sp.skipUnlessOptimized();
    try warmUp();
    seed(0x31);
    cl13 = try conn13.Connection.clientInit(cfg13Psk(.client));
    sv13 = try conn13.Connection.serverInit(cfg13Psk(.server));
    const hs_needles: []const []const u8 = &.{psk13};
    try step(PB, "13 psk client startHandshake", w13Start, .{ &cl13, &xa }, hs_needles);
    const n1 = last;
    try step(PB, "13 psk server handleFlight (ClientHello)", w13Flight, .{ &sv13, xa[0..n1], 0, &yb }, hs_needles);
    const n2 = last;
    // the retransmission timer has expired: flight 2 is sealed again under the handshake keys
    var l = nl.reset();
    l.add(psk13);
    l.add(sv13.hs_traffic_server[0..32]);
    l.add(sv13.hs_traffic_client[0..32]);
    l.add(sv13.tx_buf[0..sv13.tx_len]); // the cached flight: the handshake messages the retransmission seals again
    l.addDir(&sv13.hs_write_keys, true);
    l.addDir(&sv13.hs_read_keys, true);
    try step(PB, "13 psk server poll (handshake retransmission)", w13Poll, .{ &sv13, 5000, &pc }, l.items[0..l.n]);
    try testing.expect(last > 0);
    try step(PB, "13 psk client handleFlight (server flight)", w13Flight, .{ &cl13, yb[0..n2], 0, &xa }, hs_needles);
    const n3 = last;
    try testing.expect(done);
    try step(PB, "13 psk server handleFlight (client Finished)", w13Flight, .{ &sv13, xa[0..n3], 0, &yb }, hs_needles);
    try testing.expect(done);

    l = nl.reset();
    l.add(psk13);
    l.add(msg1);
    l.add(msg2);
    l.addDir(&cl13.write_keys, true);
    l.addDir(&sv13.write_keys, true);
    const rn = l.items[0..l.n];
    try step(PR, "13 psk client send", w13Send, .{ &cl13, msg1, &xa }, rn);
    const m1 = last;
    try step(PR, "13 psk server recv", w13Recv, .{ &sv13, xa[0..m1], &pb }, rn);
    try testing.expectEqualStrings(msg1, pb[0..last]);
    try step(PR, "13 psk server send", w13Send, .{ &sv13, msg2, &yb }, rn);
    const m2 = last;
    try step(PR, "13 psk client recv", w13Recv, .{ &cl13, yb[0..m2], &pb }, rn);
    try testing.expectEqualStrings(msg2, pb[0..last]);
    // a connected poll with nothing owed
    try step(PR, "13 psk client poll (connected, idle)", w13Poll, .{ &cl13, 6000, &pc }, rn);

    // the client's KeyUpdate: poll emits it, the server installs the new read keys, its ACK goes back
    try cl13.requestKeyUpdate(false);
    try step(PR, "13 psk client poll (KeyUpdate)", w13Poll, .{ &cl13, 7000, &pc }, rn);
    const k1 = last;
    try testing.expect(k1 > 0);
    try stepAny(PR, "13 psk server recv (KeyUpdate)", w13Recv, .{ &sv13, pc[0..k1], &pb }, rn);
    try step(PR, "13 psk server poll (ACK)", w13Poll, .{ &sv13, 7000, &pc }, rn);
    const k2 = last;
    try testing.expect(k2 > 0);
    try stepAny(PR, "13 psk client recv (ACK)", w13Recv, .{ &cl13, pc[0..k2], &pb }, rn);
    cl13.deinit();
    sv13.deinit();
}

var pend_c: [32]u8 = undefined;
var pend_s: [32]u8 = undefined;

/// An unprobed PSK handshake; the server's pending application secrets (what the client has installed) are kept.
fn plainPsk13() !void {
    cl13 = try conn13.Connection.clientInit(cfg13Psk(.client));
    sv13 = try conn13.Connection.serverInit(cfg13Psk(.server));
    var to_sv: []const u8 = try cl13.startHandshake(rnd(), 0, &xa);
    var sr = try sv13.handleFlight(to_sv, rnd(), 0, &yb);
    pend_c = sv13.pending_ap_client[0..32].*;
    pend_s = sv13.pending_ap_server[0..32].*;
    const cr = try cl13.handleFlight(sr.out, rnd(), 0, &xa);
    to_sv = cr.out;
    sr = try sv13.handleFlight(to_sv, rnd(), 0, &yb);
    try testing.expect(sr.done);
}

test "mutation 2026-11-26: STACKPROBE: DTLS 1.3 installApplicationKeys burns" {
    try sp.skipUnlessOptimized();
    try warmUp();
    seed(0x32);
    try plainPsk13(); // the server's pending application secrets are what the client installs again at the end
    // the same secrets give the same keys, which the needles name
    var l = nl.reset();
    l.add(&pend_c);
    l.add(&pend_s);
    l.addDir(&cl13.write_keys, true);
    l.addDir(&cl13.read_keys, true);
    try step(PR, "13 psk client installApplicationKeys", w13InstallKeys, .{ &cl13, &pend_c, &pend_s }, l.items[0..l.n]);
    cl13.deinit();
    sv13.deinit();
}

// The certificate flows: the server's EC key and chain are the module's KAT fixtures (public test keys).

var sk_srv: Ecdsa.EcdsaP256Sha256.SecretKey = undefined;
const Tkr = conn13.StekTicketer(tlsresume.stek.DefaultRing);
var ring13: tlsresume.stek.DefaultRing = undefined;
var tkr13: Tkr = undefined;
var ticket13: conn13.SessionTicket = undefined;

fn certServer(now_off: i64, reg: ?*tlsresume.replay.StrikeRegister) conn13.Config {
    return .{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 },
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &sk_srv } },
        .now_sec = now13 + now_off,
        .tickets = .{
            .ticketer = tkr13.ticketer(),
            .lifetime_s = 60,
            .max_early_data = if (reg != null) 1000 else 0,
            .replay = if (reg) |r| conn13.strikeRegisterGuard(r) else null,
        },
    };
}

fn certClient(suite: conn13.CipherSuite, resumption: ?*const conn13.SessionTicket, early: []const u8) conn13.Config {
    return .{
        .role = .client,
        .key_exchange = .cert_dhe,
        .cipher_suites = if (suite == .aes_128_gcm_sha256) &.{.aes_128_gcm_sha256} else &.{.aes_256_gcm_sha384},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = now13,
        .require_peer_cert = true,
        .resumption = resumption,
        .early_data = early,
    };
}

/// The four handshake steps of a certificate handshake, every one probed; returns with both sides connected.
fn handshake13(comptime name: []const u8, needles: []const []const u8) !void {
    try step(PB, name ++ " client startHandshake", w13Start, .{ &cl13, &xa }, needles);
    const n1 = last;
    try step(PB, name ++ " server handleFlight (ClientHello)", w13Flight, .{ &sv13, xa[0..n1], 0, &yb }, needles);
    const n2 = last;
    try step(PB, name ++ " client handleFlight (server flight)", w13Flight, .{ &cl13, yb[0..n2], 0, &xa }, needles);
    const n3 = last;
    try testing.expect(done);
    try step(PB, name ++ " server handleFlight (client Finished)", w13Flight, .{ &sv13, xa[0..n3], 0, &yb }, needles);
    try testing.expect(done);
}

/// The server's final flight (ACK, NewSessionTicket) delivered to the client record by record.
fn deliverFinal13(comptime name: []const u8, n: usize, needles: []const []const u8) !void {
    var rest: []const u8 = yb[0..n];
    while (rest.len > 0) {
        const dec = try record.decodeUnified(rest, 0);
        const m = dec.consumed + (dec.hdr.length orelse return error.TestBadRecord);
        try stepAny(PR, name ++ " client recv (post-handshake record)", w13Recv, .{ &cl13, rest[0..m], &pb }, needles);
        rest = rest[m..];
    }
    // the ACK of the ticket and the traffic that follows
    try step(PR, name ++ " client poll (ACK of the ticket)", w13Poll, .{ &cl13, 1000, &pc }, needles);
}

test "mutation 2026-11-26: STACKPROBE: DTLS 1.3 certificate handshake with tickets, resumption with 0-RTT, an expired ticket and a ticket of another hash" {
    try sp.skipUnlessOptimized();
    try warmUp();
    try initCert();
    var reg = tlsresume.replay.StrikeRegister.init(testing.allocator, 16, 121_000);
    defer reg.deinit();

    // 1. a full handshake that issues a ticket
    seed(0x41);
    cl13 = try conn13.Connection.clientInit(certClient(.aes_128_gcm_sha256, null, &.{}));
    sv13 = try conn13.Connection.serverInit(certServer(0, &reg)); // a ticket that allows early data
    const full_needles: []const []const u8 = &.{ msg1, msg2 };
    try handshake13("13 cert full", full_needles);
    try deliverFinal13("13 cert full", last, full_needles);
    ticket13 = (cl13.sessionTicket() orelse return error.TestNoTicket).*;
    const resume_needles: []const []const u8 = &.{ ticket13.psk[0..32], msg1, msg2, "0-RTT application data, secret" };
    cl13.deinit();
    sv13.deinit();

    // 2. resumption with 0-RTT: the client's early data rides behind the ClientHello
    seed(0x42);
    cl13 = try conn13.Connection.clientInit(certClient(.aes_128_gcm_sha256, &ticket13, "0-RTT application data, secret"));
    sv13 = try conn13.Connection.serverInit(certServer(0, &reg));
    try handshake13("13 cert resumption 0-RTT", resume_needles);
    try testing.expect(sv13.resumed() and sv13.earlyDataAccepted());
    try deliverFinal13("13 cert resumption 0-RTT", last, resume_needles);
    cl13.deinit();
    sv13.deinit();

    // 3. the same ticket after its lifetime (60 s): the server drops it and runs a full handshake
    seed(0x43);
    cl13 = try conn13.Connection.clientInit(certClient(.aes_128_gcm_sha256, &ticket13, &.{}));
    sv13 = try conn13.Connection.serverInit(certServer(61, null));
    try step(PB, "13 cert expired ticket client startHandshake", w13Start, .{ &cl13, &xa }, resume_needles);
    const e1 = last;
    try step(PB, "13 cert expired ticket server handleFlight (ClientHello)", w13Flight, .{ &sv13, xa[0..e1], 0, &yb }, resume_needles);
    try testing.expect(!sv13.resumed());
    cl13.deinit();
    sv13.deinit();

    // 4. a client that offers only a SHA-384 suite with a SHA-256 ticket: the server cannot take the PSK
    seed(0x44);
    cl13 = try conn13.Connection.clientInit(certClient(.aes_256_gcm_sha384, &ticket13, &.{}));
    sv13 = try conn13.Connection.serverInit(certServer(0, null));
    try step(PB, "13 cert other-hash ticket client startHandshake", w13Start, .{ &cl13, &xa }, resume_needles);
    const o1 = last;
    try step(PB, "13 cert other-hash ticket server handleFlight (ClientHello)", w13Flight, .{ &sv13, xa[0..o1], 0, &yb }, resume_needles);
    try testing.expect(!sv13.resumed());
    cl13.deinit();
    sv13.deinit();
    ticket13.wipe();
}

// ── DTLS 1.2 ─────────────────────────────────────────────────────────────

const psk12 = "a 1.2 pre-shared key";
const now12: i64 = 1798761600; // after the fixtures' notBefore
var ring12: tlsresume.stek.DefaultRing = undefined;
var tkr12: Tkr = undefined;
var ticket12: conn13.SessionTicket12 = undefined;

fn cfg12(role: conn13.Role, suite: conn13.CipherSuite12, tickets: bool) conn13.Config {
    var c: conn13.Config = .{
        .role = role,
        .versions = &.{.dtls12},
        .psk_identity = "device-12",
        .psk = psk12,
        .cipher_suites12 = switch (suite) {
            .psk_with_aes_128_gcm_sha256 => &.{.psk_with_aes_128_gcm_sha256},
            else => &.{.ecdhe_psk_with_chacha20_poly1305_sha256},
        },
        .now_sec = now12,
    };
    if (tickets) switch (role) {
        .server => c.tickets = .{ .ticketer = tkr12.ticketer() },
        .client => c.session_tickets12 = true,
    };
    return c;
}

/// A whole 1.2 handshake with every step probed, then both directions of the record path and the idle polls.
fn flow12(comptime name: []const u8, ccfg: conn13.Config, scfg: conn13.Config, needles: []const []const u8) !void {
    cl12 = try c12.Connection12.clientInit(ccfg);
    sv12 = try c12.Connection12.serverInit(scfg);
    try step(PB, name ++ " client startHandshake", w12Start, .{ &cl12, &xa }, needles);
    var to_sv = last;
    var rounds: usize = 0;
    while (rounds < 6 and !(cl12.isConnected() and sv12.isConnected())) : (rounds += 1) {
        try step(PB, name ++ " server handleFlight", w12Flight, .{ &sv12, xa[0..to_sv], &yb }, needles);
        const to_cl = last;
        if (cl12.isConnected() and sv12.isConnected()) break;
        try step(PB, name ++ " client handleFlight", w12Flight, .{ &cl12, yb[0..to_cl], &xa }, needles);
        to_sv = last;
    }
    try testing.expect(cl12.isConnected() and sv12.isConnected());

    var l = nl.reset();
    l.addAll(needles);
    l.add(&cl12.master);
    l.addDir(&cl12.write_keys, false);
    l.addDir(&sv12.write_keys, false);
    const rn = l.items[0..l.n];
    try step(PR, name ++ " client send", w12Send, .{ &cl12, msg1, &xa }, rn);
    const m1 = last;
    try step(PR, name ++ " server recv", w12Recv, .{ &sv12, xa[0..m1], &pb }, rn);
    try testing.expectEqualStrings(msg1, pb[0..last]);
    try step(PR, name ++ " server send", w12Send, .{ &sv12, msg2, &yb }, rn);
    const m2 = last;
    try step(PR, name ++ " client recv", w12Recv, .{ &cl12, yb[0..m2], &pb }, rn);
    try testing.expectEqualStrings(msg2, pb[0..last]);
    try step(PR, name ++ " client poll (idle)", w12Poll, .{ &cl12, 9000, &pc }, rn);
    try step(PR, name ++ " server poll (idle)", w12Poll, .{ &sv12, 9000, &pc }, rn);
}

test "mutation 2026-11-26: STACKPROBE: DTLS 1.2 PSK handshake with tickets, abbreviated resumption and ECDHE_PSK burn at every entry point" {
    try sp.skipUnlessOptimized();
    try warmUp();
    ring12 = .init();
    ring12.rotate(7, &@as([32]u8, @splat(0x24)), now12);
    tkr12 = .{ .ring = &ring12 };

    // 1. a full PSK handshake that issues a ticket (the server seals it in `sendTicket12`)
    seed(0x51);
    const needles: []const []const u8 = &.{ psk12, msg1, msg2 };
    try flow12("12 psk tickets", cfg12(.client, .psk_with_aes_128_gcm_sha256, true), cfg12(.server, .psk_with_aes_128_gcm_sha256, true), needles);
    ticket12 = (cl12.sessionTicket() orelse return error.TestNoTicket).*;
    cl12.deinit();
    sv12.deinit();

    // 2. the abbreviated handshake from that ticket (`openTicket12`, the resumed master secret, the key block)
    seed(0x52);
    var cc = cfg12(.client, .psk_with_aes_128_gcm_sha256, true);
    cc.resumption12 = &ticket12;
    const rneedles: []const []const u8 = &.{ psk12, msg1, msg2, &ticket12.master };
    try flow12("12 resumption", cc, cfg12(.server, .psk_with_aes_128_gcm_sha256, true), rneedles);
    try testing.expect(sv12.resumed());
    cl12.deinit();
    sv12.deinit();
    ticket12.wipe();

    // 3. ECDHE_PSK: the server's ECDHE secret, the shared secret and the premaster secret
    seed(0x53);
    try flow12("12 ecdhe_psk", cfg12(.client, .ecdhe_psk_with_chacha20_poly1305_sha256, false), cfg12(.server, .ecdhe_psk_with_chacha20_poly1305_sha256, false), needles);
    cl12.deinit();
    sv12.deinit();
}

fn connectPlain12(ccfg: conn13.Config, scfg: conn13.Config) !void {
    cl12 = try c12.Connection12.clientInit(ccfg);
    sv12 = try c12.Connection12.serverInit(scfg);
    var to_sv: []const u8 = try cl12.startHandshake(rnd(), 0, &xa);
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        const sr = try sv12.handleFlight(to_sv, rnd(), 0, &yb);
        if (cl12.isConnected() and sv12.isConnected()) return;
        const cr = try cl12.handleFlight(sr.out, rnd(), 0, &xa);
        if (cl12.isConnected() and sv12.isConnected()) return;
        to_sv = cr.out;
    }
    return error.TestHandshakeDidNotComplete;
}

test "mutation 2026-11-26: STACKPROBE: Connection12.exportKeyingMaterial leaves no master secret or exported value on the dead stack" {
    try sp.skipUnlessOptimized();
    try warmUp();
    seed(0x54);
    try connectPlain12(cfg12(.client, .psk_with_aes_128_gcm_sha256, false), cfg12(.server, .psk_with_aes_128_gcm_sha256, false));
    // no burn is expected (the entry point has none): only the needles are judged
    _ = try PR.run("12 exportKeyingMaterial", w12Export, .{ &cl12, &ex_out }, &.{ cl12.master[0..], &ex_out }, .{ .burn = false, .residue = false });
    try testing.expect(okf);
    cl12.deinit();
    sv12.deinit();
}

// `prf12.prf` is a public function without a burn; its own A(i) and block temporaries are wiped on return.
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
var prf_secret: [48]u8 = undefined;
var prf_out: [100]u8 = undefined;
var prf_seed1: [32]u8 = undefined;
var prf_seed2: [32]u8 = undefined;
var prf_parts: [2][]const u8 = undefined;
var prf_a_last: [32]u8 = undefined;

fn wPrf(secret: []const u8, o: []u8) void {
    okf = false;
    prf12.prf(.sha256, secret, "probe label", &prf_parts, o);
    okf = true;
}

test "mutation 2026-11-26: STACKPROBE: prf12.prf leaves neither the P_hash chain value A(i) nor an output block on the dead stack" {
    try sp.skipUnlessOptimized();
    try warmUp();
    std.crypto.hash.sha2.Sha384.hash("prf probe secret", &prf_secret, .{});
    std.crypto.hash.sha2.Sha256.hash("prf probe seed 1", &prf_seed1, .{});
    std.crypto.hash.sha2.Sha256.hash("prf probe seed 2", &prf_seed2, .{});
    prf_parts = .{ &prf_seed1, &prf_seed2 };
    // A(1) = HMAC(secret, label + seeds); 100 bytes are four blocks, so the last `a` left in the function is A(5)
    var h = HmacSha256.init(&prf_secret);
    h.update("probe label");
    h.update(&prf_seed1);
    h.update(&prf_seed2);
    h.final(&prf_a_last);
    for (0..4) |_| HmacSha256.create(&prf_a_last, &prf_a_last, &prf_secret);
    // no burn is expected (the function has none): only the needles are judged
    _ = try PR.run("prf12.prf (SHA-256, 100 bytes)", wPrf, .{ &prf_secret, &prf_out }, &.{ &prf_secret, &prf_a_last, &prf_out }, .{ .burn = false, .residue = false });
    try testing.expect(okf);
}
