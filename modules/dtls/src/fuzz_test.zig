// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for dtls (added 2026-10-10).
//!
//! Three harnesses (a damaged record that is accepted at all is a failure) over the module's in-memory client <-> server flow, each
//! generic over its source of choices; `DTLS_FUZZ=<runs>[,<first seed>]` runs
//! them (testkit's fuzz driver; `_ONLY`, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there):
//! - `dtls-handshake`: a whole handshake (PSK AES-GCM, PSK ChaCha20, PSK with
//!   the HelloRetryRequest cookie exchange, certificate-less (EC)DHE) where ONE
//!   flight on the way is damaged (0-3 octets / truncation), replaced by
//!   random bytes, dropped or duplicated. Undamaged: both sides connect and
//!   an application record crosses both ways. Whatever happens: if both
//!   sides report connected their directional keys agree and a record
//!   crosses; the state machine never panics.
//! - `dtls-record`: a connected pair, application records delivered
//!   damaged / replayed / reordered. An undamaged record is accepted once; a
//!   replay is refused; a damaged record is refused or, if accepted, carries
//!   exactly the plaintext that was sent.
//! - `dtls-wire`: the parsers (plaintext and unified record headers,
//!   handshake header + reassembler, ClientHello / ServerHello and the
//!   message decoders, ACK) on damaged genuine hellos and on random bytes.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const conn_mod = @import("Connection.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const messages = @import("messages.zig");
const flight = @import("flight.zig");
const Connection = conn_mod.Connection;
const Config = conn_mod.Config;
pub const fuzz_driver = testkit.fuzz.driver;

/// `frame` into `buf` with 0-3 octets damaged (half of them in the first 64:
/// the headers) and maybe truncated. The driver's `Rng` only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 64) else n;
        buf[src.index(span)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── configurations ──────────────────────────────────────────────────────────

const psk_identity = "device-042";
const psk = "a-shared-pre-shared-key";
const cookie_secret = "server-side cookie MAC key, never on the wire";

const Mode = enum { psk_gcm, psk_chacha, psk_hrr, dhe };

fn configs(mode: Mode) [2]Config {
    return switch (mode) {
        .psk_gcm, .psk_hrr => .{
            .{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} },
            .{
                .role = .server,
                .psk_identity = psk_identity,
                .psk = psk,
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .hello_retry = if (mode == .psk_hrr) .{ .cookie_secret = cookie_secret, .peer_binding = "203.0.113.9:51000" } else null,
            },
        },
        .psk_chacha => .{
            .{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.chacha20_poly1305_sha256} },
            .{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.chacha20_poly1305_sha256} },
        },
        .dhe => .{
            .{ .role = .client, .key_exchange = .cert_dhe_insecure_unauthenticated, .cipher_suites = &.{.aes_128_gcm_sha256} },
            .{ .role = .server, .key_exchange = .cert_dhe_insecure_unauthenticated, .cipher_suites = &.{.aes_128_gcm_sha256} },
        },
    };
}

fn entropyFrom(src: anytype, csprng: *std.Random.DefaultCsprng) conn_mod.Entropy {
    var seed: [32]u8 = undefined;
    src.bytes(&seed);
    csprng.* = std.Random.DefaultCsprng.init(seed);
    return .{ .seeded_for_test = csprng.random() };
}

/// Both directions: one record each way over the freshly installed keys, and
/// the directional keys agree.
fn expectEstablished(client: *Connection, server: *Connection) !void {
    const c = &client.write_keys;
    const s = &server.read_keys;
    if (!std.mem.eql(u8, c.key[0..c.key_len], s.key[0..s.key_len]) or !std.mem.eql(u8, &c.iv, &s.iv)) return error.KeysDisagree;
    const c2 = &client.read_keys;
    const s2 = &server.write_keys;
    if (!std.mem.eql(u8, c2.key[0..c2.key_len], s2.key[0..s2.key_len]) or !std.mem.eql(u8, &c2.iv, &s2.iv)) return error.KeysDisagree;
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const r1 = try client.send("client to server", &wire);
    if (!std.mem.eql(u8, "client to server", try server.recv(r1, &plain))) return error.RecordLost;
    const r2 = try server.send("server to client", &wire);
    if (!std.mem.eql(u8, "server to client", try client.recv(r2, &plain))) return error.RecordLost;
}

// ── dtls-handshake ──────────────────────────────────────────────────────────

const HsMark = Marker(enum {
    connected,
    refused,
    one_sided,
    stalled,
    after_damage_connected,
    hrr,
    dhe,
});

pub fn fuzzHandshake(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const mode: Mode = if (S == fuzz_driver.Rng) @enumFromInt(src.valueRangeAtMost(u8, 0, 3)) else .psk_gcm;
    const cfg = configs(mode);
    var client = try Connection.clientInit(cfg[0]);
    var server = try Connection.serverInit(cfg[1]);
    var csprng: std.Random.DefaultCsprng = undefined;
    const rnd = entropyFrom(src, &csprng);

    const Kind = enum { none, damage, random, drop, duplicate };
    var kind: Kind = .none;
    var at: usize = 0;
    var raw: [4096]u8 = undefined;
    if (S == fuzz_driver.Rng) {
        kind = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0, 1, 2 => .none,
            3, 4, 5, 6 => .damage,
            7 => .random,
            8 => .drop,
            else => .duplicate,
        };
        at = src.valueRangeAtMost(u8, 0, 5);
    } else {
        // `--fuzz`: the first flight to the server is replaced by the input.
        kind = .random;
    }

    var bufs: [2][8192]u8 = undefined;
    var step: usize = 0;
    var cur: []const u8 = client.startHandshake(rnd, 0, &bufs[0]) catch return;
    var to_server = true;
    var err_seen = false;
    // The datagram the peer was handed instead of the genuine one differs
    // from it ONLY in octets that no one authenticates: legacy_version,
    // epoch and sequence number of a PLAINTEXT record header (octets 1..10).
    var changed = false;
    var only_plain_header = true;
    while (step < 8) : (step += 1) {
        var msg: []const u8 = cur;
        var scratch: [8192]u8 = undefined;
        if (step == at and kind != .none) switch (kind) {
            .damage => {
                const n = damage(src, &scratch, cur);
                msg = scratch[0..n];
                if (n != cur.len or !std.mem.eql(u8, msg, cur)) {
                    changed = true;
                    if (n != cur.len or cur[0] != 22) only_plain_header = false;
                    for (msg[0..@min(n, cur.len)], cur[0..@min(n, cur.len)], 0..) |a, b, i| {
                        if (a != b and (i < 1 or i > 10)) only_plain_header = false;
                    }
                }
            },
            .random => {
                const n = src.slice(&raw);
                msg = raw[0..n];
                changed = true;
                only_plain_header = false;
            },
            .drop => break,
            else => {},
        };
        const peer: *Connection = if (to_server) &server else &client;
        const out = &bufs[(step + 1) % 2];
        const res = peer.handleFlight(msg, rnd, 0, out) catch {
            err_seen = true;
            break;
        };
        if (step == at and kind == .duplicate) {
            // A retransmission of the very same datagram: absorbed or refused, never fatal to the pair.
            var dup: [8192]u8 = undefined;
            _ = peer.handleFlight(msg, rnd, 0, &dup) catch {};
        }
        if (client.state == .connected and server.state == .connected) break;
        if (res.out.len == 0) break;
        cur = res.out;
        to_server = !to_server;
    }

    const both = client.state == .connected and server.state == .connected;
    if (both) {
        try expectEstablished(&client, &server);
        if (changed and !only_plain_header) {
            std.debug.print("dtls-handshake: a handshake with a damaged flight CONNECTED (mode {t})\n", .{mode});
            return error.DamagedFlightAccepted;
        }
        if (kind == .damage or kind == .random) HsMark.mark(.after_damage_connected) else HsMark.mark(.connected);
        if (mode == .psk_hrr and kind == .none) HsMark.mark(.hrr);
        if (mode == .dhe) HsMark.mark(.dhe);
    } else {
        if ((kind == .none or kind == .duplicate) and S == fuzz_driver.Rng) {
            std.debug.print("dtls-handshake: an undamaged handshake did not connect (mode {t}, kind {t}, client {t}, server {t})\n", .{ mode, kind, client.state, server.state });
            return error.GenuineHandshakeFailed;
        }
        if (err_seen) HsMark.mark(.refused) else if (client.state == .connected or server.state == .connected) HsMark.mark(.one_sided) else HsMark.mark(.stalled);
    }
}

fn fuzzHandshakeSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzHandshake(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: a handshake with one flight damaged never panics" {
    try testing.fuzz({}, fuzzHandshakeSmith, .{});
}

test "fuzz driver: DTLS_FUZZ (handshake)" {
    try fuzz_driver.run(fuzzHandshake, .{ .prefix = "DTLS_FUZZ", .name = "dtls-handshake" });
}

test "fuzz harness: handshake, 300 seeds, reaches every outcome" {
    try HsMark.reach(fuzzHandshake, "dtls-handshake", 300);
}

// ── dtls-record ─────────────────────────────────────────────────────────────

var pair_ready = false;
var pair: [2]Connection = undefined;

fn ensurePair(mode: Mode) !void {
    _ = mode;
    if (pair_ready) return;
    const cfg = configs(.psk_gcm);
    pair[0] = try Connection.clientInit(cfg[0]);
    pair[1] = try Connection.serverInit(cfg[1]);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x31} ** 32);
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const rnd: conn_mod.Entropy = .{ .seeded_for_test = csprng.random() };
    const ch = try pair[0].startHandshake(rnd, 0, &b1);
    const f2 = try pair[1].handleFlight(ch, rnd, 0, &b2);
    const fin = try pair[0].handleFlight(f2.out, rnd, 0, &b1);
    _ = try pair[1].handleFlight(fin.out, rnd, 0, &b2);
    try expectEstablished(&pair[0], &pair[1]);
    // `expectEstablished` moved both send counters on; the template is the
    // pair AFTER that exchange, which is a fine "established session".
    pair_ready = true;
}

const RecMark = Marker(enum { accepted, replay_refused, damaged_refused, reordered_accepted });

pub fn fuzzRecord(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try ensurePair(.psk_gcm);
    var tx = pair[0];
    var rx = pair[1];
    if (S == fuzz_driver.Rng and src.value(bool)) {
        tx = pair[1];
        rx = pair[0];
    }
    var wires: [4][128]u8 = undefined;
    var lens: [4]usize = undefined;
    var msgs: [4][40]u8 = undefined;
    var mlens: [4]usize = undefined;
    const count = 3;
    for (0..count) |i| {
        mlens[i] = 1 + if (S == fuzz_driver.Rng) src.index(39) else 3;
        src.bytes(msgs[i][0..mlens[i]]);
        lens[i] = (try tx.send(msgs[i][0..mlens[i]], &wires[i])).len;
    }
    var delivered = [_]bool{false} ** count;
    const deliveries = if (S == fuzz_driver.Rng) src.valueRangeAtMost(u8, 1, 6) else 1;
    var last: ?usize = null;
    for (0..deliveries) |_| {
        const idx = if (S == fuzz_driver.Rng) src.index(count) else 0;
        var d: [160]u8 = undefined;
        var dn: usize = lens[idx];
        @memcpy(d[0..dn], wires[idx][0..dn]);
        var mutated = false;
        if (S != fuzz_driver.Rng) {
            dn = src.slice(&d);
            mutated = true;
        } else if (src.valueRangeAtMost(u8, 0, 2) == 0) {
            dn = damage(src, &d, wires[idx][0..lens[idx]]);
            mutated = dn != lens[idx] or !std.mem.eql(u8, d[0..dn], wires[idx][0..dn]);
        }
        var plain: [256]u8 = undefined;
        if (rx.recv(d[0..dn], &plain)) |got| {
            if (!std.mem.eql(u8, got, msgs[idx][0..mlens[idx]])) {
                std.debug.print("dtls-record: record {d} delivered with the WRONG plaintext (mutated={})\n", .{ idx, mutated });
                return error.WrongPlaintextAccepted;
            }
            if (mutated) {
                std.debug.print("dtls-record: a damaged record {d} was ACCEPTED (right plaintext)\n", .{idx});
                return error.DamagedRecordAccepted;
            }
            if (delivered[idx]) return error.ReplayAccepted;
            RecMark.mark(.accepted);
            if (last) |l| if (idx < l) RecMark.mark(.reordered_accepted);
            delivered[idx] = true;
            last = idx;
        } else |_| {
            if (mutated) {
                RecMark.mark(.damaged_refused);
            } else if (delivered[idx]) {
                RecMark.mark(.replay_refused);
            } else {
                std.debug.print("dtls-record: a genuine, first-time record {d} was refused\n", .{idx});
                return error.GenuineRecordRefused;
            }
        }
    }
}

fn fuzzRecordSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzRecord(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: damaged, replayed and reordered application records" {
    try testing.fuzz({}, fuzzRecordSmith, .{});
}

test "fuzz driver: DTLS_FUZZ (record)" {
    try fuzz_driver.run(fuzzRecord, .{ .prefix = "DTLS_FUZZ", .name = "dtls-record" });
}

test "fuzz harness: record, 300 seeds, reaches every outcome" {
    try RecMark.reach(fuzzRecord, "dtls-record", 300);
}

// ── dtls-wire ───────────────────────────────────────────────────────────────

var seeds_ready = false;
var seed_ch: [2][2048]u8 = undefined;
var seed_ch_len: [2]usize = undefined;
var seed_sh: [2048]u8 = undefined;
var seed_sh_len: usize = 0;
var seed_ext: [64]u8 = undefined;
var seed_ext_len: usize = 0;
var seed_ack: [64]u8 = undefined;
var seed_ack_len: usize = 0;

fn ensureSeeds() !void {
    if (seeds_ready) return;
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x44} ** 32);
    const rnd: conn_mod.Entropy = .{ .seeded_for_test = csprng.random() };
    for ([_]Mode{ .psk_gcm, .dhe }, 0..) |mode, i| {
        const cfg = configs(mode);
        var client = try Connection.clientInit(cfg[0]);
        var server = try Connection.serverInit(cfg[1]);
        var b1: [4096]u8 = undefined;
        var b2: [4096]u8 = undefined;
        const ch = try client.startHandshake(rnd, 0, &b1);
        const body = try firstHandshakeBody(ch, &seed_ch[i]);
        seed_ch_len[i] = body;
        if (i == 0) {
            const f2 = try server.handleFlight(ch, rnd, 0, &b2);
            seed_sh_len = try firstHandshakeBody(f2.out, &seed_sh);
        }
    }
    const exts = try messages.encodeExtensions(&.{
        .{ .ext_type = 43, .data = "\x02\x03\x04" },
        .{ .ext_type = 44, .data = "cookie-bytes" },
        .{ .ext_type = 51, .data = "" },
    }, &seed_ext);
    seed_ext_len = exts.len;
    seed_ack_len = (try flight.encodeAck(&.{ .{ .epoch = 2, .sequence_number = 0 }, .{ .epoch = 2, .sequence_number = 5 } }, &seed_ack)).len;
    seeds_ready = true;
}

/// The first handshake message body of a plaintext datagram into `out`.
fn firstHandshakeBody(datagram: []const u8, out: []u8) !usize {
    const rec = try record.decodePlaintext(datagram);
    const frag = datagram[record.plaintext_header_len..][0..rec.length];
    const hdr = try handshake.decodeHeader(frag);
    const body = frag[handshake.header_len..][0..hdr.fragment_length];
    @memcpy(out[0..body.len], body);
    return body.len;
}

const WireMark = Marker(enum {
    plaintext_header,
    unified_header,
    handshake_header,
    reassembled,
    client_hello,
    server_hello,
    extensions,
    ack,
    refused,
});

pub fn fuzzWire(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    try ensureSeeds();
    var buf: [2200]u8 = undefined;
    var n: usize = 0;
    if (S != fuzz_driver.Rng) {
        n = src.slice(&buf);
    } else switch (src.valueRangeAtMost(u8, 0, 6)) {
        4 => n = damage(src, &buf, seed_ext[0..seed_ext_len]),
        5 => n = damage(src, &buf, seed_ack[0..seed_ack_len]),
        0, 1 => n = damage(src, &buf, seed_ch[src.index(2)][0..seed_ch_len[0]]),
        2 => n = damage(src, &buf, seed_sh[0..seed_sh_len]),
        3 => {
            // a handshake fragment: header + body, header fields drawn
            var f: [200]u8 = undefined;
            const bl = src.index(100);
            src.bytes(f[12..][0..bl]);
            const hdr: handshake.HandshakeHeader = .{
                .msg_type = src.value(u8),
                .length = @intCast(bl + if (src.value(bool)) 0 else src.index(40)),
                .message_seq = src.valueRangeAtMost(u16, 0, 3),
                .fragment_offset = if (src.value(bool)) 0 else @intCast(src.index(bl + 1)),
                .fragment_length = 0,
            };
            var h = hdr;
            h.fragment_length = @intCast(@min(bl, h.length - h.fragment_offset));
            handshake.encodeHeader(h, f[0..12]);
            n = damage(src, &buf, f[0 .. 12 + h.fragment_length]);
        },
        else => n = src.slice(&buf),
    }
    const input = buf[0..n];

    if (record.decodePlaintext(input)) |_| WireMark.mark(.plaintext_header) else |_| {}
    if (record.decodeUnified(input, 0)) |_| WireMark.mark(.unified_header) else |_| {}
    if (record.decodeUnified(input, 8)) |_| {} else |_| {}
    var ok = false;
    if (handshake.decodeHeader(input)) |hdr| {
        WireMark.mark(.handshake_header);
        ok = true;
        if (input.len >= handshake.header_len + hdr.fragment_length) {
            var mbuf: [256]u8 = undefined;
            var got: [256]bool = undefined;
            var re = handshake.Reassembler.init(&mbuf, &got);
            const frag = input[handshake.header_len..][0..hdr.fragment_length];
            if (re.feed(hdr, frag)) |done| {
                if (done != null) WireMark.mark(.reassembled);
                // The same fragment again, and with a contradicting header.
                _ = re.feed(hdr, frag) catch {};
                var h2 = hdr;
                h2.length +%= 1;
                _ = re.feed(h2, frag) catch {};
            } else |_| {}
        }
    } else |_| {}
    var exts: [24]messages.Extension = undefined;
    if (messages.decodeClientHello(input, &exts)) |ch| {
        WireMark.mark(.client_hello);
        ok = true;
        var it: messages.CipherSuiteIter = .{ .raw = ch.cipher_suites_raw };
        while (it.next()) |_| {}
    } else |_| {}
    if (messages.decodeServerHello(input, &exts)) |_| {
        WireMark.mark(.server_hello);
        ok = true;
    } else |_| {}
    if (messages.decodeExtensions(input, &exts)) |_| {
        WireMark.mark(.extensions);
        ok = true;
    } else |_| {}
    var rns: [8]flight.RecordNumber = undefined;
    if (flight.decodeAck(input, &rns)) |_| {
        WireMark.mark(.ack);
        ok = true;
    } else |_| {}
    var ce: [4]messages.CertificateEntry = undefined;
    if (messages.decodeCertificate(input, &ce)) |_| {
        ok = true;
    } else |_| {}
    if (messages.decodeCertificateVerify(input)) |_| {
        ok = true;
    } else |_| {}
    if (messages.decodeCertificateRequest(input, &exts)) |_| {
        ok = true;
    } else |_| {}
    if (messages.decodeEncryptedExtensions(input, &exts)) |_| {
        ok = true;
    } else |_| {}
    var kse: [4]messages.KeyShareEntry = undefined;
    if (messages.decodeKeyShareClientHello(input, &kse)) |_| {
        ok = true;
    } else |_| {}
    if (messages.decodeKeyShareServerHello(input)) |_| {
        ok = true;
    } else |_| {}
    if (messages.decodeCookieExtension(input)) |_| {
        ok = true;
    } else |_| {}
    var u16s: [16]u16 = undefined;
    if (messages.decodeU16ListExtension(input, &u16s)) |_| {
        ok = true;
    } else |_| {}
    if (!ok) WireMark.mark(.refused);
}

fn fuzzWireSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzWire(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: the wire parsers never panic" {
    try testing.fuzz({}, fuzzWireSmith, .{});
}

test "fuzz driver: DTLS_FUZZ (wire)" {
    try fuzz_driver.run(fuzzWire, .{ .prefix = "DTLS_FUZZ", .name = "dtls-wire" });
}

test "fuzz harness: wire, 400 seeds, reaches every outcome" {
    try WireMark.reach(fuzzWire, "dtls-wire", 400);
}
