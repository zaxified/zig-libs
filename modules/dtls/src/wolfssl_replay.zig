// SPDX-License-Identifier: MIT

//! HERMETIC replay of the recorded wolfSSL exchanges — pure Zig, no child
//! process, no C compiler, no wolfSSL, no socket.
//!
//! ## What this is and where it came from
//!
//! Until 2026-09-06 the live wolfSSL interop was a test file inside this
//! module. It `@embedFile`d a 555-line C peer, wrote it to a temp directory,
//! compiled it with `cc -lwolfssl`, and drove real handshakes against it. So
//! the library shipped foreign source, `zig build test-dtls` wanted a toolchain
//! it had no business wanting, and every one of those tests skipped — loudly,
//! but skipped — wherever that toolchain was absent. In CI, where the peer
//! install runs `continue-on-error`, a failed install turned the whole anchor
//! into a silent skip.
//!
//! The anchor now arrives in two halves. `tools/interop.zig` — a standalone
//! program, outside this module — still runs the live handshakes and is the
//! only thing that can find a NEW divergence. What it records,
//! `testdata/wolfssl_transcript.txt`, is replayed here, in the lane that runs
//! everywhere.
//!
//! ## What makes a replay possible at all
//!
//! A DTLS handshake is interactive and randomised, so a recording replays only
//! if our side's randomness is pinned. **This module already had the seam**:
//! every random byte comes from a caller-supplied `Entropy` (std 0.16 removed
//! `std.crypto.random`, so there is no hidden generator), and its
//! `.seeded_for_test` arm is exactly a fixed generator. The live runs have used
//! it from a fixed seed since they were written, for a different reason — so a
//! failing interop run could be re-run byte-for-byte. Nothing was added,
//! loosened, or stubbed to make this file possible; the transcript records the
//! seed and this file reads it back.
//!
//! Given the same seed and the same inbound datagrams, our ClientHello, our
//! ECDHE private key, our ECDSA/PSS signature noise and our record layer are
//! the same bytes every time. That is what lets the peer's *recorded* answers
//! still verify: wolfSSL's Finished MAC is over a transcript that includes our
//! ClientHello, and its application record is under keys derived from our
//! ECDHE share. If any of that drifted by one byte, the recorded Finished would
//! not verify and the recorded ciphertext would not decrypt.
//!
//! ## What this CANNOT do — read this before trusting a green run
//!
//!   * It cannot discover a NEW divergence. The peer's bytes are frozen at one
//!     wolfSSL release. A change that a newer wolfSSL would reject passes here.
//!   * A failure here is not a verdict that we became non-interoperable: a
//!     change that makes us emit different-but-still-valid bytes (a reordered
//!     extension, a different signature nonce) fails the replay without any
//!     real peer having refused anything. The response to a red replay is to
//!     re-run `zig build interop-dtls` and, if that is green, re-capture.
//!   * It cannot check anything that was not bytes on the wire. The peer's exit
//!     status, its `wolfSSL_get_verify_result`, and the `PEERCERT` subject it
//!     printed were all checked when the transcript was taken, and are kept in
//!     the file as `#` notes precisely because nothing here can re-check them.
//!   * It cannot prove wolfSSL ACCEPTS what we send. It proves we still send
//!     what wolfSSL accepted. Those coincide only for as long as the recording
//!     is current.
//!
//! What it CAN do is the part that used to disappear on a machine without
//! `libwolfssl-dev`: parse a real third-party stack's ServerHello,
//! HelloRetryRequest, Certificate, CertificateVerify and Finished; reassemble a
//! fragmented flight; derive the same keys from a foreign (EC)DHE or ML-KEM
//! share; and decrypt what foreign code encrypted.

const std = @import("std");
const testing = std.testing;

const conn_mod = @import("Connection.zig");
const Connection = conn_mod.Connection;
const Config = conn_mod.Config;
const Entropy = conn_mod.Entropy;
const cert_kat = @import("certauth_kat_vectors.zig");

const transcript = @embedFile("testdata/wolfssl_transcript.txt");

/// The number of cases the recorder emits. A floor, not a mirror: `--capture`
/// writes every case or none, so the only way the file can hold fewer is that
/// the anchor got smaller — which a replay over "whatever is in the file"
/// would report as a pass. Raise it when cases are added; a drop needs a
/// sentence in CHANGELOG.md saying which anchor was given up.
const recorded_cases_floor = 14;

// ── a tiny line format, parsed here ───────────────────────────────────────
//
// One operation per line, `op key=value ...`, `#` is a comment, hex is
// lowercase, an empty value is an empty byte string. The generated file
// documents it in its own header; this is the reader.

fn opName(line: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
    return line[0..end];
}

/// The rest of the line after the op name, untrimmed of inner spaces — for the
/// two ops whose argument is prose (`case`, `why`).
fn opRest(line: []const u8) []const u8 {
    const sp = std.mem.indexOfScalar(u8, line, ' ') orelse return "";
    return std.mem.trim(u8, line[sp + 1 ..], " ");
}

/// The value of `key=` on this line, or null when the key is absent. An empty
/// value (`out=`) returns an empty slice, which is a different answer.
fn arg(line: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next(); // the op
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
        if (std.mem.eql(u8, tok[0..eq], key)) return tok[eq + 1 ..];
    }
    // A key whose value is empty produces a token that ends at '='; the loop
    // above already handles it, so reaching here means the key is not present.
    return null;
}

fn hexArg(gpa: std.mem.Allocator, line: []const u8, key: []const u8) ![]u8 {
    const text = arg(line, key) orelse return error.MissingArgument;
    if (text.len % 2 != 0) return error.OddHexLength;
    const out = try gpa.alloc(u8, text.len / 2);
    errdefer gpa.free(out);
    _ = std.fmt.hexToBytes(out, text) catch return error.BadHex;
    return out;
}

fn numArg(comptime T: type, line: []const u8, key: []const u8) !T {
    const text = arg(line, key) orelse return error.MissingArgument;
    return std.fmt.parseInt(T, text, 10);
}

fn hex4Arg(line: []const u8, key: []const u8) !u16 {
    const text = arg(line, key) orelse return error.MissingArgument;
    return std.fmt.parseInt(u16, text, 16);
}

fn boolArg(line: []const u8, key: []const u8) !bool {
    return (try numArg(u8, line, key)) != 0;
}

// ── the recorded configuration ────────────────────────────────────────────

/// Everything the `config` line carries, with storage for the byte strings it
/// names. Held by value so a `Config` can point into it for the whole case.
const Recorded = struct {
    cert_mode: bool = false,
    seed: [32]u8 = @splat(0),
    now_sec: i64 = 0,
    offer_group: u16 = 0,
    client_cert: bool = false,

    psk_buf: [64]u8 = @splat(0),
    psk_len: usize = 0,
    identity_buf: [64]u8 = @splat(0),
    identity_len: usize = 0,
    cookie_buf: [128]u8 = @splat(0),
    cookie_len: usize = 0,
    binding_buf: [128]u8 = @splat(0),
    binding_len: usize = 0,
    has_binding: bool = false,

    fn parse(line: []const u8) !Recorded {
        var r: Recorded = .{};
        const kx = arg(line, "key_exchange") orelse return error.MissingArgument;
        r.cert_mode = std.mem.eql(u8, kx, "cert_dhe");

        const seed_hex = arg(line, "seed") orelse return error.MissingArgument;
        if (seed_hex.len != 64) return error.BadSeed;
        _ = std.fmt.hexToBytes(&r.seed, seed_hex) catch return error.BadHex;

        r.now_sec = try numArg(i64, line, "now_sec");
        r.offer_group = try hex4Arg(line, "offer_group");
        r.client_cert = try boolArg(line, "client_cert");

        // The suite is recorded so a transcript taken under a different one is
        // visible in the file; only one is wired here, and a second would need
        // a `Config.cipher_suites` mapping rather than a silent pass.
        const suite = arg(line, "suite") orelse return error.MissingArgument;
        if (!std.mem.eql(u8, suite, "aes_128_gcm_sha256")) return error.UnknownCipherSuite;

        if (!r.cert_mode) {
            r.identity_len = try copyHex(&r.identity_buf, arg(line, "psk_identity") orelse return error.MissingArgument);
            r.psk_len = try copyHex(&r.psk_buf, arg(line, "psk") orelse return error.MissingArgument);
            r.cookie_len = try copyHex(&r.cookie_buf, arg(line, "cookie_secret") orelse return error.MissingArgument);
        }
        return r;
    }

    fn copyHex(dest: []u8, text: []const u8) !usize {
        if (text.len % 2 != 0) return error.OddHexLength;
        if (text.len / 2 > dest.len) return error.ValueTooLong;
        _ = std.fmt.hexToBytes(dest[0 .. text.len / 2], text) catch return error.BadHex;
        return text.len / 2;
    }

    fn setBinding(self: *Recorded, text: []const u8) !void {
        self.binding_len = try copyHex(&self.binding_buf, text);
        self.has_binding = true;
    }

    fn psk(self: *const Recorded) []const u8 {
        return self.psk_buf[0..self.psk_len];
    }
    fn identity(self: *const Recorded) []const u8 {
        return self.identity_buf[0..self.identity_len];
    }

    /// The two fixture chains stay in `certauth_kat_vectors.zig` and are
    /// referenced by role, not copied into the transcript: the peer read the
    /// SAME bytes off disk when the recording was taken, so "which certificate"
    /// has one answer in the tree, not one per consumer.
    fn config(self: *const Recorded, role: enum { client, server }) Config {
        if (!self.cert_mode) return switch (role) {
            .client => .{
                .role = .client,
                .psk_identity = self.identity(),
                .psk = self.psk(),
                .cipher_suites = &.{.aes_128_gcm_sha256},
            },
            .server => .{
                .role = .server,
                .psk_identity = self.identity(),
                .psk = self.psk(),
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .hello_retry = if (self.has_binding) .{
                    .cookie_secret = self.cookie_buf[0..self.cookie_len],
                    .peer_binding = self.binding_buf[0..self.binding_len],
                } else null,
            },
        };
        return switch (role) {
            .client => .{
                .role = .client,
                .key_exchange = .cert_dhe,
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
                .require_peer_cert = true,
                .now_sec = self.now_sec,
                .cert = if (self.client_cert) .{
                    .chain = &.{&cert_kat.client_cert_der},
                    .private_key = .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes) catch unreachable },
                } else null,
                .key_share_group = @enumFromInt(self.offer_group),
            },
            .server => .{
                .role = .server,
                .key_exchange = .cert_dhe,
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .cert = .{
                    .chain = &.{&cert_kat.server_cert_der},
                    .private_key = .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable },
                },
            },
        };
    }
};

// ── the interpreter ───────────────────────────────────────────────────────

/// Per-case bookkeeping the `expect` op reads back.
const Tally = struct {
    largest_datagram: usize = 0,
    partial_steps: usize = 0,
    retries: usize = 0,
};

const Replay = struct {
    gpa: std.mem.Allocator,
    /// Named in every failure message: a byte mismatch that does not say WHICH
    /// live case to re-run is a mismatch nobody can act on.
    case: []const u8 = "<none>",
    line_no: usize = 0,

    csprng: std.Random.DefaultCsprng = undefined,
    rec: Recorded = .{},
    conn: ?Connection = null,
    tally: Tally = .{},
    cases_seen: usize = 0,
    flows_seen: std.EnumSet(Flow) = .initEmpty(),
    kx_seen: std.EnumSet(KeyExchange) = .initEmpty(),
    retry_cases: usize = 0,
    /// Big enough for the whole of a hybrid ServerHello flight in one buffer.
    out: [4096]u8 = undefined,
    plain: [2048]u8 = undefined,

    const Flow = enum { client, server, server_cookie };
    const KeyExchange = enum { psk, cert_dhe };

    fn entropy(self: *Replay) Entropy {
        // The module's own seam, used through its own test arm — the same call
        // the live harness makes, which is why the bytes come out identical.
        return .{ .seeded_for_test = self.csprng.random() };
    }

    fn fail(self: *Replay, comptime what: []const u8, args: anytype) error{ReplayMismatch} {
        std.debug.print("\nwolfSSL replay, case \"{s}\", transcript line {d}: ", .{ self.case, self.line_no });
        std.debug.print(what ++ "\n", args);
        std.debug.print("  re-run the live exchange with: zig build interop-dtls -- --case {s}\n", .{self.case});
        return error.ReplayMismatch;
    }

    fn deinit(self: *Replay) void {
        if (self.conn) |*c| c.deinit();
        self.conn = null;
    }

    fn step(self: *Replay, line: []const u8) !void {
        const op = opName(line);

        if (std.mem.eql(u8, op, "format")) {
            if ((try numArg(u8, line, "version")) != 1) return error.UnknownTranscriptVersion;
        } else if (std.mem.eql(u8, op, "why")) {
            // Prose. It is in the file so a reader of the FIXTURE learns what
            // each case is for without opening the tool.
        } else if (std.mem.eql(u8, op, "case")) {
            self.deinit();
            self.case = opRest(line);
            self.tally = .{};
            self.cases_seen += 1;
        } else if (std.mem.eql(u8, op, "config")) {
            self.rec = try Recorded.parse(line);
            self.csprng = std.Random.DefaultCsprng.init(self.rec.seed);
            const flow = arg(line, "flow") orelse return error.MissingArgument;
            self.flows_seen.insert(std.meta.stringToEnum(Flow, flow) orelse return error.UnknownFlow);
            self.kx_seen.insert(if (self.rec.cert_mode) .cert_dhe else .psk);
        } else if (std.mem.eql(u8, op, "client_init")) {
            self.deinit();
            self.conn = try Connection.clientInit(self.rec.config(.client));
        } else if (std.mem.eql(u8, op, "server_init")) {
            self.deinit();
            if (arg(line, "binding")) |b| try self.rec.setBinding(b);
            self.conn = try Connection.serverInit(self.rec.config(.server));
        } else if (std.mem.eql(u8, op, "drop_conn")) {
            // The stateless-server proof, replayed: the object that answered
            // ClientHello1 is destroyed before ClientHello2 is read, so
            // anything the next flight needs has to come out of the cookie.
            self.deinit();
            self.tally.retries += 1;
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
            self.tally.largest_datagram = @max(self.tally.largest_datagram, in.len);
            const result = self.conn.?.handleFlight(in, self.entropy(), 0, &self.out) catch |err| {
                return self.fail("handleFlight REJECTED a datagram a real wolfSSL sent: {s}", .{@errorName(err)});
            };
            if (result.need_more_data) self.tally.partial_steps += 1;
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
            if (!std.mem.eql(u8, want, got))
                return self.fail("our application record differs from the recorded one", .{});
        } else if (std.mem.eql(u8, op, "recv")) {
            const in = try hexArg(self.gpa, line, "in");
            defer self.gpa.free(in);
            if (arg(line, "skip")) |want_err| {
                // "This datagram must come back as exactly this error" is as
                // much of a check as a plaintext is: it is how the recording
                // pins that wolfSSL's ACK and NewSessionTicket DECRYPT (they
                // are rejected by kind, after the AEAD opened them) rather
                // than being waved through.
                if (self.conn.?.recv(in, &self.plain)) |_| {
                    return self.fail("a datagram recorded as {s} decrypted as application data", .{want_err});
                } else |err| {
                    if (!std.mem.eql(u8, want_err, @errorName(err)))
                        return self.fail("recv gave {s}, the recording says {s}", .{ @errorName(err), want_err });
                }
            } else {
                const want = try hexArg(self.gpa, line, "out");
                defer self.gpa.free(want);
                const got = self.conn.?.recv(in, &self.plain) catch |err| {
                    return self.fail("recv could not open a record wolfSSL encrypted: {s}", .{@errorName(err)});
                };
                if (!std.mem.eql(u8, want, got))
                    return self.fail("the plaintext we recovered differs from the recorded one", .{});
            }
        } else if (std.mem.eql(u8, op, "expect")) {
            const want_hrr = try boolArg(line, "hrr");
            if (self.conn.?.sawHelloRetryRequest() != want_hrr)
                return self.fail("sawHelloRetryRequest() is {}, the recording says {}", .{ self.conn.?.sawHelloRetryRequest(), want_hrr });
            if (want_hrr) self.retry_cases += 1;
            const want_group = try hex4Arg(line, "group");
            if (self.conn.?.ecdhe_group != want_group)
                return self.fail("the handshake ran on group 0x{x:0>4}, the recording says 0x{x:0>4}", .{ self.conn.?.ecdhe_group, want_group });
            if (self.conn.?.state != .connected)
                return self.fail("the connection is {t}, not connected", .{self.conn.?.state});
            if (arg(line, "max_datagram") != null) {
                const cap = try numArg(usize, line, "max_datagram");
                if (self.tally.largest_datagram > cap)
                    return self.fail("a recorded datagram is {d} bytes, over the {d}-byte peer MTU", .{ self.tally.largest_datagram, cap });
                // The point of the constrained-MTU case: the certificate does
                // not fit in one datagram, so this handshake cannot have
                // completed unless message reassembly really ran.
                if (cert_kat.server_cert_der.len <= cap)
                    return self.fail("the fixture certificate ({d} B) now fits inside the {d}-byte MTU, so this case no longer fragments anything", .{ cert_kat.server_cert_der.len, cap });
            }
            if (arg(line, "min_partial") != null) {
                const min = try numArg(usize, line, "min_partial");
                if (self.tally.partial_steps < min)
                    return self.fail("the engine reassembled nothing: {d} partial flights, {d} required", .{ self.tally.partial_steps, min });
            }
            if (arg(line, "min_retries") != null) {
                const min = try numArg(usize, line, "min_retries");
                if (self.tally.retries < min)
                    return self.fail("{d} HelloRetryRequests served, {d} required — the cookie case degraded into the plain one", .{ self.tally.retries, min });
            }
        } else {
            std.debug.print("\nunknown transcript op \"{s}\" on line {d}\n", .{ op, self.line_no });
            return error.UnknownTranscriptOp;
        }
    }
};

test "wolfSSL transcript: every recorded exchange replays byte-for-byte, with no wolfSSL and no C compiler" {
    var r: Replay = .{ .gpa = testing.allocator };
    defer r.deinit();

    var it = std.mem.splitScalar(u8, transcript, '\n');
    while (it.next()) |raw| {
        r.line_no += 1;
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0 or line[0] == '#') continue;
        try r.step(line);
    }

    // A transcript that lost cases would replay green over whatever was left.
    try testing.expect(r.cases_seen >= recorded_cases_floor);
    // ...and one that kept the count but collapsed into fourteen copies of the
    // easy case would too. Both roles, both key exchanges, the stateless-cookie
    // server, and several HelloRetryRequests have to be in there.
    try testing.expect(r.flows_seen.count() == 3);
    try testing.expect(r.kx_seen.count() == 2);
    try testing.expect(r.retry_cases >= 5);
}

test "wolfSSL transcript: the header names the release, the date and the command that took it" {
    // Provenance is the difference between a fixture and a pile of bytes: a
    // recording nobody can re-take is one nobody can update when it goes
    // stale. Checked here rather than trusted, because the header is written
    // by a tool that only runs where wolfSSL is installed.
    const head = transcript[0..@min(transcript.len, 4096)];
    try testing.expect(std.mem.indexOf(u8, head, "wolfSSL:") != null);
    try testing.expect(std.mem.indexOf(u8, head, "captured:") != null);
    try testing.expect(std.mem.indexOf(u8, head, "zig build interop-dtls -- --capture") != null);
}
