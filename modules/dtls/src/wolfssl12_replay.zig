// SPDX-License-Identifier: MIT

//! HERMETIC replay of the recorded DTLS 1.2 exchanges with wolfSSL
//! (`wolfDTLSv1_2_*_method`) — the 1.2 counterpart of `wolfssl_replay.zig`,
//! with the same line format, the same parser and the same limits (read that
//! file's "What this CANNOT do" before trusting a green run). The recording,
//! `testdata/wolfssl12_transcript.txt`, is written by `tools/interop.zig`
//! (`zig build interop-dtls -- --capture --version 12`); it is a file of its
//! own so that re-taking one version's anchor never rewrites the other's.
//!
//! What it pins, per case: our ClientHello, every answer `Connection12`
//! gives to wolfSSL's datagrams (its HelloVerifyRequest, its fragmented
//! Certificate at a 256-byte MTU, its CertificateRequest), our fragmented
//! flights when `Config.max_datagram_len` was set, and both directions of
//! application data — ECDHE_PSK, ECDHE_ECDSA (AES-128-GCM, AES-256-GCM /
//! SHA-384, ChaCha20-Poly1305, secp256r1) and ECDHE_RSA, both roles, mutual
//! authentication both ways, and our stateless HelloVerifyRequest server.

const std = @import("std");
const testing = std.testing;

const conn13 = @import("Connection.zig");
const Connection12 = @import("Connection12.zig").Connection12;
const Config = conn13.Config;
const Entropy = conn13.Entropy;
const cert_kat = @import("certauth_kat_vectors.zig");
const certverify = @import("tls13").certverify;
const rsa = @import("rsa");
const r13 = @import("wolfssl_replay.zig");

const arg = r13.arg;
const hexArg = r13.hexArg;
const numArg = r13.numArg;
const hex4Arg = r13.hex4Arg;
const boolArg = r13.boolArg;

const transcript = @embedFile("testdata/wolfssl12_transcript.txt");

/// A floor, not a mirror (see `wolfssl_replay.zig`'s `recorded_cases_floor`).
const recorded_cases_floor = 15;

var client_ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var server_ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var rsa_sk: rsa.SecretKey = undefined;

const v12 = [_]conn13.ProtocolVersion{.dtls12};

const Kind = enum { psk, ecdsa, rsa };
const Flow = enum { client, server, server_cookie };

/// The `config` line, with storage for what a `Config` points at.
const Recorded = struct {
    kind: Kind = .psk,
    seed: [32]u8 = @splat(0),
    now_sec: i64 = 0,
    mutual: bool = false,
    max_datagram: u16 = 0,
    psk_buf: [64]u8 = @splat(0),
    psk_len: usize = 0,
    identity_buf: [64]u8 = @splat(0),
    identity_len: usize = 0,
    hint_buf: [64]u8 = @splat(0),
    hint_len: usize = 0,
    cookie_buf: [128]u8 = @splat(0),
    cookie_len: usize = 0,
    binding_buf: [128]u8 = @splat(0),
    binding_len: usize = 0,
    has_binding: bool = false,

    fn parse(line: []const u8) !Recorded {
        var r: Recorded = .{};
        r.kind = std.meta.stringToEnum(Kind, arg(line, "kind") orelse return error.MissingArgument) orelse return error.UnknownKind;
        const seed_hex = arg(line, "seed") orelse return error.MissingArgument;
        if (seed_hex.len != 64) return error.BadSeed;
        _ = std.fmt.hexToBytes(&r.seed, seed_hex) catch return error.BadHex;
        r.now_sec = try numArg(i64, line, "now_sec");
        r.mutual = try boolArg(line, "mutual");
        r.max_datagram = try numArg(u16, line, "max_datagram");
        r.identity_len = try copyHex(&r.identity_buf, arg(line, "psk_identity") orelse return error.MissingArgument);
        r.psk_len = try copyHex(&r.psk_buf, arg(line, "psk") orelse return error.MissingArgument);
        r.hint_len = try copyHex(&r.hint_buf, arg(line, "psk_hint") orelse return error.MissingArgument);
        r.cookie_len = try copyHex(&r.cookie_buf, arg(line, "cookie_secret") orelse return error.MissingArgument);
        return r;
    }

    fn copyHex(dest: []u8, text: []const u8) !usize {
        if (text.len % 2 != 0) return error.OddHexLength;
        if (text.len / 2 > dest.len) return error.ValueTooLong;
        _ = std.fmt.hexToBytes(dest[0 .. text.len / 2], text) catch return error.BadHex;
        return text.len / 2;
    }

    /// Mirrors `tools/interop.zig`'s `config12`, with the fixtures taken from
    /// `certauth_kat_vectors.zig` (the same files the live run read).
    fn config(self: *Recorded, role: conn13.Role) Config {
        var c: Config = .{ .role = role, .versions = &v12, .now_sec = self.now_sec, .max_datagram_len = self.max_datagram };
        switch (self.kind) {
            .psk => {
                c.psk_identity = self.identity_buf[0..self.identity_len];
                c.psk = self.psk_buf[0..self.psk_len];
                if (role == .server) c.psk_identity_hint = self.hint_buf[0..self.hint_len];
            },
            .ecdsa, .rsa => {
                c.key_exchange = .cert_dhe;
                const anchor: []const u8 = if (self.kind == .rsa) &cert_kat.rsa12_cert_der else &cert_kat.anchor_cert_der;
                switch (role) {
                    .client => {
                        c.peer_verify = .{ .trust_anchor = anchor };
                        if (self.mutual) {
                            client_ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes) catch unreachable;
                            c.cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = .{ .ecdsa_p256 = &client_ecdsa_sk } };
                        }
                    },
                    .server => {
                        if (self.kind == .rsa) {
                            rsa.SecretKey.fromDer(&rsa_sk, &cert_kat.rsa12_key_der) catch unreachable;
                            c.cert = .{ .chain = &.{&cert_kat.rsa12_cert_der}, .private_key = .{ .rsa = &rsa_sk } };
                        } else {
                            server_ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
                            c.cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &server_ecdsa_sk } };
                        }
                        if (self.mutual) {
                            c.request_client_cert = true;
                            c.require_peer_cert = true;
                            c.peer_verify = .{ .trust_anchor = anchor };
                        }
                    },
                }
            },
        }
        if (self.has_binding) c.hello_retry = .{
            .cookie_secret = self.cookie_buf[0..self.cookie_len],
            .peer_binding = self.binding_buf[0..self.binding_len],
        };
        return c;
    }
};

const Replay = struct {
    gpa: std.mem.Allocator,
    case: []const u8 = "<none>",
    line_no: usize = 0,
    csprng: std.Random.DefaultCsprng = undefined,
    rec: Recorded = .{},
    conn: ?Connection12 = null,
    largest_in: usize = 0,
    partial_steps: usize = 0,
    retries: usize = 0,

    cases_seen: usize = 0,
    flows_seen: std.EnumSet(Flow) = .empty,
    kinds_seen: std.EnumSet(Kind) = .empty,
    suites_seen: [8]u16 = undefined,
    suites_len: usize = 0,
    hvr_cases: usize = 0,
    mutual_cases: usize = 0,
    fragmenting_cases: usize = 0,
    reassembling_cases: usize = 0,
    out: [8192]u8 = undefined,
    plain: [2048]u8 = undefined,

    fn entropy(self: *Replay) Entropy {
        return .{ .seeded_for_test = self.csprng.random() };
    }

    fn fail(self: *Replay, comptime what: []const u8, args: anytype) error{ReplayMismatch} {
        std.debug.print("\nwolfSSL 1.2 replay, case \"{s}\", transcript line {d}: ", .{ self.case, self.line_no });
        std.debug.print(what ++ "\n", args);
        std.debug.print("  re-run the live exchange with: zig build interop-dtls -- --case {s}\n", .{self.case});
        return error.ReplayMismatch;
    }

    fn deinit(self: *Replay) void {
        if (self.conn) |*c| c.deinit();
        self.conn = null;
    }

    fn step(self: *Replay, line: []const u8) !void {
        const op = r13.opName(line);
        if (std.mem.eql(u8, op, "format")) {
            if ((try numArg(u8, line, "version")) != 1) return error.UnknownTranscriptVersion;
        } else if (std.mem.eql(u8, op, "why")) {} else if (std.mem.eql(u8, op, "case")) {
            self.deinit();
            self.case = r13.opRest(line);
            self.largest_in = 0;
            self.partial_steps = 0;
            self.retries = 0;
            self.cases_seen += 1;
        } else if (std.mem.eql(u8, op, "config")) {
            self.rec = try Recorded.parse(line);
            self.csprng = std.Random.DefaultCsprng.init(self.rec.seed);
            self.flows_seen.insert(std.meta.stringToEnum(Flow, arg(line, "flow") orelse return error.MissingArgument) orelse return error.UnknownFlow);
            self.kinds_seen.insert(self.rec.kind);
            if (self.rec.mutual) self.mutual_cases += 1;
            if (self.rec.max_datagram != 0) self.fragmenting_cases += 1;
        } else if (std.mem.eql(u8, op, "client_init")) {
            self.deinit();
            self.conn = try Connection12.clientInit(self.rec.config(.client));
        } else if (std.mem.eql(u8, op, "server_init")) {
            self.deinit();
            if (arg(line, "binding")) |b| {
                self.rec.binding_len = try Recorded.copyHex(&self.rec.binding_buf, b);
                self.rec.has_binding = true;
            }
            self.conn = try Connection12.serverInit(self.rec.config(.server));
        } else if (std.mem.eql(u8, op, "drop_conn")) {
            // The stateless HelloVerifyRequest server, replayed: the object
            // that answered ClientHello 1 is gone before ClientHello 2.
            self.deinit();
            self.retries += 1;
        } else if (std.mem.eql(u8, op, "start")) {
            const want = try hexArg(self.gpa, line, "out");
            defer self.gpa.free(want);
            const got = try self.conn.?.startHandshake(self.entropy(), 0, &self.out);
            if (!std.mem.eql(u8, want, got))
                return self.fail("our ClientHello differs from the recorded one ({d} bytes recorded, {d} produced)", .{ want.len, got.len });
        } else if (std.mem.eql(u8, op, "flight")) {
            const in = try hexArg(self.gpa, line, "in");
            defer self.gpa.free(in);
            const want = try hexArg(self.gpa, line, "out");
            defer self.gpa.free(want);
            self.largest_in = @max(self.largest_in, in.len);
            const result = self.conn.?.handleFlight(in, self.entropy(), 0, &self.out) catch |err|
                return self.fail("handleFlight REJECTED a datagram a real wolfSSL sent: {s}", .{@errorName(err)});
            if (result.need_more_data) self.partial_steps += 1;
            if (result.need_more_data != try boolArg(line, "more"))
                return self.fail("need_more_data disagrees with the recording (got {})", .{result.need_more_data});
            if (!std.mem.eql(u8, want, result.out))
                return self.fail("our answering flight differs from the recorded one ({d} bytes recorded, {d} produced)", .{ want.len, result.out.len });
        } else if (std.mem.eql(u8, op, "send")) {
            const in = try hexArg(self.gpa, line, "in");
            defer self.gpa.free(in);
            const want = try hexArg(self.gpa, line, "out");
            defer self.gpa.free(want);
            const got = try self.conn.?.send(in, &self.out);
            if (!std.mem.eql(u8, want, got)) return self.fail("our application record differs from the recorded one", .{});
        } else if (std.mem.eql(u8, op, "recv")) {
            const in = try hexArg(self.gpa, line, "in");
            defer self.gpa.free(in);
            if (arg(line, "skip")) |want_err| {
                if (self.conn.?.recv(in, &self.plain)) |_| {
                    return self.fail("a datagram recorded as {s} decrypted as application data", .{want_err});
                } else |err| {
                    if (!std.mem.eql(u8, want_err, @errorName(err)))
                        return self.fail("recv gave {s}, the recording says {s}", .{ @errorName(err), want_err });
                }
            } else {
                const want = try hexArg(self.gpa, line, "out");
                defer self.gpa.free(want);
                const got = self.conn.?.recv(in, &self.plain) catch |err|
                    return self.fail("recv could not open a record wolfSSL encrypted: {s}", .{@errorName(err)});
                if (!std.mem.eql(u8, want, got)) return self.fail("the plaintext we recovered differs from the recorded one", .{});
            }
        } else if (std.mem.eql(u8, op, "expect")) {
            const c = &self.conn.?;
            if (!c.isConnected()) return self.fail("the connection is {t}, not connected", .{c.state});
            const suite: u16 = @backingInt(c.negotiatedSuite().?);
            if (suite != try hex4Arg(line, "suite")) return self.fail("negotiated suite 0x{x:0>4} differs from the recording", .{suite});
            if (c.ecdhe_group != try hex4Arg(line, "group")) return self.fail("ECDHE group 0x{x:0>4} differs from the recording", .{c.ecdhe_group});
            if (c.ems != try boolArg(line, "ems")) return self.fail("extended master secret disagrees with the recording", .{});
            const hvr = try numArg(u8, line, "hvr");
            if (c.hvr_count != hvr) return self.fail("{d} HelloVerifyRequests answered, the recording says {d}", .{ c.hvr_count, hvr });
            if (hvr > 0) self.hvr_cases += 1;
            for (self.suites_seen[0..self.suites_len]) |s| {
                if (s == suite) break;
            } else if (self.suites_len < self.suites_seen.len) {
                self.suites_seen[self.suites_len] = suite;
                self.suites_len += 1;
            }
            if (arg(line, "min_retries") != null and self.retries < try numArg(usize, line, "min_retries"))
                return self.fail("no HelloVerifyRequest was served — the cookie case degraded into the plain one", .{});
            if (arg(line, "client_cert") != null and !c.client_cert_presented)
                return self.fail("the client presented no certificate", .{});
            if (arg(line, "max_in_datagram") != null) {
                const cap = try numArg(usize, line, "max_in_datagram");
                if (self.largest_in > cap) return self.fail("a recorded datagram is {d} bytes, over the {d}-byte peer MTU", .{ self.largest_in, cap });
                if (cert_kat.server_cert_der.len <= cap) return self.fail("the fixture certificate fits the MTU, nothing was fragmented", .{});
            }
            if (arg(line, "min_partial") != null) {
                if (self.partial_steps < try numArg(usize, line, "min_partial"))
                    return self.fail("the engine reassembled nothing", .{});
                self.reassembling_cases += 1;
            }
        } else {
            std.debug.print("\nunknown transcript op \"{s}\" on line {d}\n", .{ op, self.line_no });
            return error.UnknownTranscriptOp;
        }
    }
};

test "wolfSSL DTLS 1.2 transcript: every recorded exchange replays byte-for-byte, with no wolfSSL and no C compiler" {
    var r: Replay = .{ .gpa = testing.allocator };
    defer r.deinit();
    var it = std.mem.splitScalar(u8, transcript, '\n');
    while (it.next()) |raw| {
        r.line_no += 1;
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0 or line[0] == '#') continue;
        try r.step(line);
    }
    try testing.expect(r.cases_seen >= recorded_cases_floor);
    // Both roles plus the stateless server, all three key exchanges, four
    // suites, wolfSSL's HelloVerifyRequest, mutual authentication both ways,
    // a peer that fragments and two cases where WE fragment.
    try testing.expect(r.flows_seen.count() == 3);
    try testing.expect(r.kinds_seen.count() == 3);
    try testing.expect(r.suites_len >= 5);
    try testing.expect(r.hvr_cases >= 5);
    try testing.expect(r.mutual_cases >= 3);
    try testing.expect(r.reassembling_cases >= 1);
    try testing.expect(r.fragmenting_cases >= 2);
}

test "wolfSSL DTLS 1.2 transcript: the header names the release, the date and the command that took it" {
    const head = transcript[0..@min(transcript.len, 4096)];
    try testing.expect(std.mem.find(u8, head, "wolfSSL:") != null);
    try testing.expect(std.mem.find(u8, head, "captured:") != null);
    try testing.expect(std.mem.find(u8, head, "zig build interop-dtls -- --capture --version 12") != null);
}
