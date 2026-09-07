// SPDX-License-Identifier: MIT

//! HERMETIC replay of the recorded `asyncua` exchange — pure Zig, no child
//! process, no interpreter, no `asyncua`, no socket.
//!
//! ## What this is and where it came from
//!
//! Until 2026-09-07 the live asyncua interop was a test inside this module, and
//! its Python driver was a ~190-line `\\` string literal in
//! `server_interop.zig` run with `python3 -c`. So `zig build test-opcua` wanted
//! an interpreter and a third-party package it had no business wanting, and the
//! anchor skipped — loudly, but skipped — wherever they were absent. It was the
//! seventh instance of the shape six modules were separated from on 2026-09-06,
//! missed because a string constant is not a file anybody can `git mv`.
//!
//! The anchor now arrives in two halves. `tools/interop.zig` — a standalone
//! program, outside this module — still runs the live exchange and is the only
//! thing that can find a NEW divergence. What it records,
//! `testdata/asyncua_transcript.txt`, is replayed here, in the lane that runs
//! everywhere.
//!
//! ## What makes a replay possible at all
//!
//! OPC UA is about as hostile to replay as a protocol gets: every message
//! carries timestamps, sequence numbers, request handles, SecureChannel ids,
//! SecurityToken ids and nonces, and above Basic256Sha256 all of it is signed
//! and encrypted under keys derived from a nonce pair. **Two seams this module
//! already had are what make it work, and neither was added, widened or stubbed
//! for this file:**
//!
//!   * `server.Server.init` takes the `std.Random` it draws from. One
//!     `DefaultCsprng`, seeded from the transcript's `seed`, produces the RSA
//!     key pair, the self-signed certificate, every channel nonce, every token
//!     id and every 32-byte AuthenticationToken — in that order, which is why
//!     the order of draws in `Fixture.init` is part of the fixture.
//!   * `feed`/`tick` take `now_ms` as a PARAMETER — "time is a parameter, not a
//!     dependency" is the server's stated contract — and `wall_clock_epoch`
//!     fixes where the wall clock's zero is. Every `DateTime`, token lifetime,
//!     publish deadline and session timeout follows from the recorded `t=`.
//!
//! Sequence numbers, request ids and channel ids then follow from the recorded
//! inputs. Given the same seed, the same `start_time` and the same `t=`/`in=`
//! sequence, this server emits the same bytes — which is also why the peer's
//! recorded ciphertext still decrypts and still verifies: asyncua derived its
//! keys from OUR nonce and signed over a transcript containing OUR certificate.
//! If any of that drifted by one byte, the recorded traffic would stop opening.
//!
//! ## What this CANNOT do — read this before trusting a green run
//!
//!   * It cannot discover a NEW divergence. The peer's bytes are frozen at one
//!     asyncua release. A change a newer asyncua would reject passes here.
//!   * A failure here is not a verdict that we became non-interoperable: a
//!     change that makes us emit different-but-still-valid bytes (a different
//!     nonce draw, a reordered endpoint list, one more millisecond on a
//!     revised lifetime) fails the replay without any real peer having refused
//!     anything. The response to a red replay is to re-run
//!     `zig build interop-opcua` and, if that is green, re-capture.
//!   * It cannot prove asyncua ACCEPTS what we send. It proves we still send
//!     what asyncua accepted. Those coincide only while the recording is
//!     current.
//!   * It cannot check anything that was not bytes on the wire. asyncua's own
//!     assertions — that it browsed `the.answer`, that its write read back as
//!     31337, that the method echoed, that its subscription handler fired, that
//!     30 reads survived two token renewals — and its exit status were all
//!     checked when the transcript was taken, and are kept in the file as `#`
//!     notes precisely because nothing here can re-check them. What IS re-
//!     checked is that the server produces the very bytes those assertions were
//!     made about, plus the structural facts listed at `expectations` below.
//!
//! What it CAN do is the part that used to disappear on a machine without
//! `asyncua`: answer a real third-party stack's Hello, OpenSecureChannel,
//! GetEndpoints, CreateSession, ActivateSession, Browse, Read, Write, Call,
//! CreateSubscription, Publish and SecurityToken renewals — at
//! SecurityPolicy#None, at Basic256Sha256/Sign with an RSA-OAEP-encrypted
//! UserNameIdentityToken, and at Basic256Sha256/SignAndEncrypt — byte for byte.

const std = @import("std");
const testing = std.testing;

const encoding = @import("encoding.zig");
const services = @import("services.zig");
const nodestore = @import("nodestore.zig");
const server = @import("server.zig");
const security = @import("security.zig");

const transcript = @embedFile("testdata/asyncua_transcript.txt");

// ── the fixture ────────────────────────────────────────────────────────────
//
// ⚠ MIRRORED FROM `tools/interop.zig`, NOT SHARED, and it cannot be otherwise:
// an interop program's package root is `modules/opcua/tools/`, so it can import
// `opcua` and nothing under `src/`. The two copies are held together by the
// `fixture cert_sha256=` line the transcript carries — a drift in ANY value
// below changes the certificate this seed produces, and the replay says so in
// one sentence instead of leaving a 400-byte diff in an OpenSecureChannel
// response for somebody to read.

const live_endpoint_url = "opc.tcp://localhost:4841";
const live_ns_uri = "urn:zig-libs:opcua:interop";
const application_uri = "urn:zig-libs:opcua:interop-server";

const answer_node: encoding.NodeId = .{ .string = .{ .namespace = 1, .id = "the.answer" } };
const method_node: encoding.NodeId = .{ .numeric = .{ .namespace = 1, .id = 62_541 } };

const users = [_]server.UserCredential{.{ .user_name = "user1", .password = "password" }};

const app: services.ApplicationDescription = .{
    .application_uri = application_uri,
    .product_uri = "urn:zig-libs:opcua",
    .application_name = .{ .locale = "en", .text = "zig-libs opcua interop server" },
    .application_type = .server,
    .gateway_server_uri = null,
    .discovery_profile_uri = null,
    .discovery_urls = null,
};

fn echoMethod(
    user_context: ?*anyopaque,
    allocator: std.mem.Allocator,
    inputs: []const encoding.Variant,
    outputs: *std.ArrayList(encoding.Variant),
) std.mem.Allocator.Error!encoding.StatusCode {
    _ = user_context;
    if (inputs.len != 1) return services.status.bad_arguments_missing;
    const text = switch (inputs[0]) {
        .scalar => |s| switch (s) {
            .string => |v| v orelse "",
            else => return services.status.bad_invalid_argument,
        },
        else => return services.status.bad_invalid_argument,
    };
    const echoed = try std.fmt.allocPrint(allocator, "{s} (echoed by zig-libs)", .{text});
    try outputs.append(allocator, .{ .scalar = .{ .string = echoed } });
    return services.status.good;
}

const Fixture = struct {
    gpa: std.mem.Allocator,
    csprng: std.Random.DefaultCsprng,
    store: nodestore.NodeStore,
    srv: server.Server,
    creds: security.Credentials,
    endpoint_storage: [3]services.EndpointDescription,
    start_time: encoding.DateTime,

    fn init(
        f: *Fixture,
        gpa: std.mem.Allocator,
        seed: [32]u8,
        start_time: encoding.DateTime,
        min_token_lifetime_ms: u32,
    ) !void {
        f.gpa = gpa;
        f.start_time = start_time;
        // ⚠ THE ORDER OF EVERY DRAW FROM HERE ON IS PART OF THE FIXTURE.
        f.csprng = std.Random.DefaultCsprng.init(seed);
        const random = f.csprng.random();

        f.store = nodestore.NodeStore.init(gpa);
        try f.store.addStandardNodes(.{ .start_time = start_time });
        const ns = try f.store.addNamespace(live_ns_uri);
        std.debug.assert(ns == 1);
        try f.store.refreshNamespaceArray();
        try f.store.addVariable(.{
            .node_id = answer_node,
            .parent_id = nodestore.n0(nodestore.id.objects_folder),
            .reference_type_id = nodestore.n0(nodestore.id.organizes),
            .browse_name = .{ .namespace_index = 1, .name = "the.answer" },
            .display_name = .{ .locale = "en", .text = "the answer" },
            .value = .{ .scalar = .{ .int32 = 42 } },
            .data_type = nodestore.n0(nodestore.id.int32),
            .access_level = nodestore.access_level.read_write,
            .timestamp = start_time,
        });
        try f.store.addMethod(.{
            .node_id = method_node,
            .parent_id = nodestore.n0(nodestore.id.objects_folder),
            .browse_name = .{ .namespace_index = 1, .name = "hello world" },
            .implementation = echoMethod,
        });

        f.creds = try security.Credentials.generateSelfSigned(gpa, random, .{
            .modulus_bits = 2048,
            .common_name = "zig-libs opcua interop server",
            .not_before = "200101000000Z",
            .not_after = "350101000000Z",
            .application_uri = application_uri,
        });
        f.endpoint_storage[0] = server.noneEndpointWithEncryptedUserTokens(live_endpoint_url, app, f.creds.certificate_der);
        f.endpoint_storage[1] = server.secureEndpoint(live_endpoint_url, app, .sign, f.creds.certificate_der, 10);
        f.endpoint_storage[2] = server.secureEndpoint(live_endpoint_url, app, .sign_and_encrypt, f.creds.certificate_der, 20);

        f.srv = server.Server.init(gpa, &f.store, .{
            .application_uri = application_uri,
            .application_name = .{ .locale = "en", .text = "zig-libs opcua interop server" },
            .endpoints = &f.endpoint_storage,
            .users = &users,
            .security = .{ .credentials = f.creds },
        }, random);
        f.srv.wall_clock_epoch = start_time;
        f.srv.config.security.?.min_token_lifetime_ms = min_token_lifetime_ms;
    }

    fn deinit(f: *Fixture) void {
        f.creds.deinit(f.gpa);
        f.srv.deinit();
        f.store.deinit();
    }

    fn certSha256(f: *const Fixture) [32]u8 {
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(f.creds.certificate_der, &out, .{});
        return out;
    }

    fn answerValue(store: *nodestore.NodeStore) i32 {
        const dv = store.readAttribute(answer_node, services.attribute_id.value);
        const variant = dv.value orelse return 0;
        return switch (variant) {
            .scalar => |s| switch (s) {
                .int32 => |v| v,
                else => 0,
            },
            else => 0,
        };
    }
};

// ── the floors ─────────────────────────────────────────────────────────────
//
// A replay over "whatever is in the file" passes on a file that lost half the
// exchange, so what the anchor must contain is stated here rather than inferred
// from the recording. Every number is a FLOOR, not a mirror: `--capture` writes
// the whole session or none of it, so the only way the file can hold less is
// that the anchor got smaller. Raise them when the driver grows a leg; lowering
// one needs a sentence in CHANGELOG.md saying which anchor was given up.
//
// The counts come from asyncua 2.0.1, which makes SEVEN connections, not the
// four the pre-migration test asserted: it re-runs `GetEndpoints` over a fresh
// unsecured connection before every secured session. The floors are written
// against the SHAPE (an unsecured leg, a SignAndEncrypt session, a Sign session,
// a renewal run) so a different asyncua that reaches the same shape with a
// different connection count still satisfies them.

/// Endpoint discovery, the SignAndEncrypt session, the Sign session, the
/// renewal run — the four legs the driver script walks.
const min_connections = 4;
/// The renewal leg holds one connection for ~30 s at a 20 ms poll.
const min_steps = 800;
/// At least the SignAndEncrypt session and the SignAndEncrypt renewal run.
const min_sign_and_encrypt_connections = 2;
/// The Sign leg, which is the only one that carries an RSA-OAEP-encrypted
/// UserNameIdentityToken.
const min_sign_connections = 1;
/// GetEndpoints has to be answered over an unsecured channel for any of this to
/// start.
const min_none_connections = 1;
/// One `OpenSecureChannel` opens the channel; the rest are renewals. The live
/// leg holds a 10 s token for ~30 s, so two renewals is what it proves.
const min_opn_on_renewal_connection = 3;
/// `Objects/the.answer` starts at 42; asyncua writes this and reads it back.
const written_answer: i32 = 31337;

// ── a tiny line format, parsed here ────────────────────────────────────────
//
// One operation per line, `op key=value ...`, `#` is a comment, hex is
// lowercase. The generated file documents it in its own header; this is the
// reader.

fn opName(line: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
    return line[0..end];
}

fn arg(line: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next(); // the op
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
        if (std.mem.eql(u8, tok[0..eq], key)) return tok[eq + 1 ..];
    }
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

// ── the opc.tcp framing walker ─────────────────────────────────────────────
//
// Every opc.tcp message — HEL, ACK, ERR, OPN, MSG, CLO — starts with the same
// 8-byte header (OPC 10000-6 §7.1.2): a 3-byte type code, a chunk-type byte
// (`F`inal / `C`ontinuation / `A`bort) and a little-endian u32 that counts the
// header itself. That is plaintext even at SignAndEncrypt, so a census of what
// each side sent is available to this file without any key material — and
// walking it end to end also proves the recorded stream is exactly framed,
// with no trailing slop and no truncation.

const Census = struct {
    hel: usize = 0,
    ack: usize = 0,
    err: usize = 0,
    opn: usize = 0,
    msg: usize = 0,
    clo: usize = 0,
    bytes: usize = 0,

    fn walk(bytes: []const u8) !Census {
        var c: Census = .{ .bytes = bytes.len };
        var i: usize = 0;
        while (i < bytes.len) {
            if (bytes.len - i < 8) return error.TruncatedFrameHeader;
            const size = std.mem.readInt(u32, bytes[i + 4 ..][0..4], .little);
            if (size < 8 or size > bytes.len - i) return error.BadFrameLength;
            const kind = bytes[i..][0..3];
            if (std.mem.eql(u8, kind, "HEL")) {
                c.hel += 1;
            } else if (std.mem.eql(u8, kind, "ACK")) {
                c.ack += 1;
            } else if (std.mem.eql(u8, kind, "ERR")) {
                c.err += 1;
            } else if (std.mem.eql(u8, kind, "OPN")) {
                c.opn += 1;
            } else if (std.mem.eql(u8, kind, "MSG")) {
                c.msg += 1;
            } else if (std.mem.eql(u8, kind, "CLO")) {
                c.clo += 1;
            } else {
                return error.UnknownMessageType;
            }
            i += size;
        }
        return c;
    }
};

/// One connection's recorded traffic, both directions, plus what the server
/// said it had become when the socket went away.
const Conn = struct {
    c2s: std.ArrayList(u8) = .empty,
    s2c: std.ArrayList(u8) = .empty,
    policy: security.SecurityPolicy = .none,
    mode: services.MessageSecurityMode = .none,
    c2s_census: Census = .{},
    s2c_census: Census = .{},

    fn deinit(self: *Conn, gpa: std.mem.Allocator) void {
        self.c2s.deinit(gpa);
        self.s2c.deinit(gpa);
    }
};

// ── the interpreter ────────────────────────────────────────────────────────

const Replay = struct {
    gpa: std.mem.Allocator,
    line_no: usize = 0,
    fx: ?*Fixture = null,

    conn: ?server.Connection = null,
    recv_buf: []u8,
    msg_buf: []u8,
    out: std.Io.Writer.Allocating,

    /// The connection currently open, and every one that has closed — the
    /// census below is run over the recorded bytes, not over live state, so it
    /// is available after the fact.
    open: ?Conn = null,
    closed: std.ArrayList(Conn) = .empty,

    steps: usize = 0,
    opens: usize = 0,

    fn deinit(self: *Replay) void {
        if (self.conn) |*c| c.deinit();
        self.conn = null;
        if (self.open) |*c| c.deinit(self.gpa);
        self.open = null;
        for (self.closed.items) |*c| c.deinit(self.gpa);
        self.closed.deinit(self.gpa);
        self.gpa.free(self.recv_buf);
        self.gpa.free(self.msg_buf);
        self.out.deinit();
    }

    fn fail(self: *Replay, comptime what: []const u8, args: anytype) error{ReplayMismatch} {
        std.debug.print("\nasyncua replay, transcript line {d}: ", .{self.line_no});
        std.debug.print(what ++ "\n", args);
        std.debug.print("  re-take the exchange with: zig build interop-opcua -- --capture\n", .{});
        return error.ReplayMismatch;
    }

    fn step(self: *Replay, line: []const u8) !void {
        const op = opName(line);

        if (std.mem.eql(u8, op, "format")) {
            if ((try numArg(u8, line, "version")) != 1) return error.UnknownTranscriptVersion;
        } else if (std.mem.eql(u8, op, "config")) {
            // Handled by the caller: the fixture has to exist before any op
            // runs, and it is what `fixture` then checks.
        } else if (std.mem.eql(u8, op, "fixture")) {
            const want = arg(line, "cert_sha256") orelse return error.MissingArgument;
            const digest = self.fx.?.certSha256();
            var got: [64]u8 = undefined;
            for (digest, 0..) |b, i| {
                _ = std.fmt.bufPrint(got[i * 2 ..][0..2], "{x:0>2}", .{b}) catch unreachable;
            }
            if (!std.mem.eql(u8, want, &got)) {
                return self.fail(
                    "the server certificate this seed produces is {s}, the recording was taken against {s}.\n" ++
                        "  The fixture in src/asyncua_replay.zig and the one in tools/interop.zig have drifted apart,\n" ++
                        "  or something under rsa.generate/rsa.selfSignedCert changed what a seed produces.",
                    .{ got, want },
                );
            }
        } else if (std.mem.eql(u8, op, "open")) {
            if (self.open != null) return self.fail("a connection opened while one was still open", .{});
            self.conn = try server.Connection.init(&self.fx.?.srv, self.recv_buf, self.msg_buf);
            self.open = .{};
            self.opens += 1;
        } else if (std.mem.eql(u8, op, "close")) {
            var c = self.open orelse return self.fail("close with no connection open", .{});
            const want_policy = arg(line, "policy") orelse return error.MissingArgument;
            const want_mode = arg(line, "mode") orelse return error.MissingArgument;
            const live = &self.conn.?;
            // ⭐ The recorded SecurityPolicy/SecurityMode are re-derived, not
            // read: this is what makes "the Sign leg really ran at Sign" a
            // checked fact in a test with no peer.
            if (!std.mem.eql(u8, want_policy, @tagName(live.sec_policy)) or
                !std.mem.eql(u8, want_mode, @tagName(live.sec_mode)))
            {
                return self.fail(
                    "connection {d} reached {s}/{s}, the recording says {s}/{s}",
                    .{ self.opens, @tagName(live.sec_policy), @tagName(live.sec_mode), want_policy, want_mode },
                );
            }
            c.policy = live.sec_policy;
            c.mode = live.sec_mode;
            c.c2s_census = Census.walk(c.c2s.items) catch |e| return self.fail(
                "the recorded client stream of connection {d} is not validly framed: {t}",
                .{ self.opens, e },
            );
            c.s2c_census = Census.walk(c.s2c.items) catch |e| return self.fail(
                "the server stream we reproduced for connection {d} is not validly framed: {t}",
                .{ self.opens, e },
            );
            try self.closed.append(self.gpa, c);
            self.open = null;
            self.conn.?.deinit();
            self.conn = null;
        } else if (std.mem.eql(u8, op, "step")) {
            const t = try numArg(i64, line, "t");
            const input: ?[]u8 = if (arg(line, "in") != null) try hexArg(self.gpa, line, "in") else null;
            defer if (input) |b| self.gpa.free(b);
            const recorded: ?[]u8 = if (arg(line, "out") != null) try hexArg(self.gpa, line, "out") else null;
            defer if (recorded) |b| self.gpa.free(b);
            const want: []const u8 = recorded orelse &.{};

            self.out.clearRetainingCapacity();
            self.fx.?.srv.refreshTime(t, self.fx.?.start_time) catch {};
            if (input) |b| {
                if (self.conn == null) return self.fail("bytes arrived with no connection open", .{});
                self.conn.?.feed(b, &self.out.writer, t) catch |err| {
                    return self.fail("feed REJECTED bytes a real asyncua sent: {t}", .{err});
                };
                if (self.open) |*c| try c.c2s.appendSlice(self.gpa, b);
            }
            if (self.conn) |*c| c.tick(&self.out.writer, t) catch |err| {
                return self.fail("tick failed: {t}", .{err});
            };
            const produced = self.out.written();
            if (!std.mem.eql(u8, want, produced)) {
                return self.fail(
                    "at t={d} this server answered {d} bytes, the recording has {d}{s}",
                    .{ t, produced.len, want.len, firstDifference(want, produced) },
                );
            }
            if (self.open) |*c| try c.s2c.appendSlice(self.gpa, produced);
            self.steps += 1;
        } else if (std.mem.eql(u8, op, "expect")) {
            const want_connections = try numArg(usize, line, "connections");
            const want_steps = try numArg(usize, line, "steps");
            const want_answer = try numArg(i32, line, "answer");
            if (self.opens != want_connections)
                return self.fail("{d} connections replayed, the recording has {d}", .{ self.opens, want_connections });
            if (self.steps != want_steps)
                return self.fail("{d} steps replayed, the recording has {d}", .{ self.steps, want_steps });
            const answer = Fixture.answerValue(&self.fx.?.store);
            if (answer != want_answer)
                return self.fail("`the.answer` ended at {d}, the recording says {d}", .{ answer, want_answer });
        } else {
            std.debug.print("\nunknown transcript op \"{s}\" on line {d}\n", .{ op, self.line_no });
            return error.UnknownTranscriptOp;
        }
    }
};

/// A byte-diff hint in the failure message. A length is not enough to act on —
/// "the first 24 bytes agree and then the sequence number diverges" and "the
/// whole chunk is different" call for different investigations.
var diff_buf: [96]u8 = undefined;
fn firstDifference(want: []const u8, got: []const u8) []const u8 {
    const n = @min(want.len, got.len);
    var i: usize = 0;
    while (i < n and want[i] == got[i]) i += 1;
    if (i == n and want.len == got.len) return "";
    return std.fmt.bufPrint(&diff_buf, " (first {d} bytes agree)", .{i}) catch "";
}

// ── the tests ──────────────────────────────────────────────────────────────

test "asyncua transcript: the whole recorded exchange replays byte-for-byte, with no python and no asyncua" {
    const gpa = testing.allocator;

    // The `config` line has to be read before any op runs, because the fixture
    // it describes is what every later op acts on.
    var seed: [32]u8 = undefined;
    var start_time: encoding.DateTime = 0;
    var min_token_lifetime_ms: u32 = 0;
    {
        var it = std.mem.splitScalar(u8, transcript, '\n');
        const config = while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \r\t");
            if (std.mem.startsWith(u8, line, "config ")) break line;
        } else return error.TranscriptHasNoConfig;
        const seed_hex = arg(config, "seed") orelse return error.MissingArgument;
        if (seed_hex.len != 64) return error.BadSeed;
        _ = std.fmt.hexToBytes(&seed, seed_hex) catch return error.BadHex;
        start_time = try numArg(i64, config, "start_time");
        min_token_lifetime_ms = try numArg(u32, config, "min_token_lifetime_ms");
    }

    var fx: Fixture = undefined;
    try fx.init(gpa, seed, start_time, min_token_lifetime_ms);
    defer fx.deinit();

    var r: Replay = .{
        .gpa = gpa,
        .fx = &fx,
        // The same buffer pair the live driver handed the server, so the
        // negotiated limits in the recorded ACK are the ones we compute.
        .recv_buf = try gpa.alloc(u8, 128 * 1024),
        .msg_buf = try gpa.alloc(u8, 1 << 20),
        .out = .init(gpa),
    };
    defer r.deinit();

    var it = std.mem.splitScalar(u8, transcript, '\n');
    while (it.next()) |raw| {
        r.line_no += 1;
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0 or line[0] == '#') continue;
        try r.step(line);
    }
    if (r.open != null) return error.TranscriptEndsMidConnection;

    // ── the shape, so a transcript that lost a leg cannot pass green ───────
    try testing.expect(r.opens >= min_connections);
    try testing.expect(r.steps >= min_steps);

    var none_conns: usize = 0;
    var sign_conns: usize = 0;
    var seal_conns: usize = 0;
    var max_opn: usize = 0;
    var renewal_mode: services.MessageSecurityMode = .invalid;
    var client_bytes: usize = 0;
    for (r.closed.items) |c| {
        client_bytes += c.c2s_census.bytes;
        switch (c.mode) {
            .none => none_conns += 1,
            .sign => sign_conns += 1,
            .sign_and_encrypt => seal_conns += 1,
            .invalid => {},
        }
        // Every connection begins with exactly one Hello answered by exactly
        // one Acknowledge, and NO connection is answered with an ERR — a
        // server that faulted every request would still replay byte-for-byte,
        // so "we answered, and none of it was an error frame" is checked.
        try testing.expectEqual(@as(usize, 1), c.c2s_census.hel);
        try testing.expectEqual(@as(usize, 1), c.s2c_census.ack);
        try testing.expectEqual(@as(usize, 0), c.s2c_census.err);
        try testing.expect(c.c2s_census.opn >= 1);
        try testing.expect(c.s2c_census.opn >= 1);
        if (c.c2s_census.opn > max_opn) {
            max_opn = c.c2s_census.opn;
            renewal_mode = c.mode;
        }
    }
    try testing.expect(none_conns >= min_none_connections);
    try testing.expect(sign_conns >= min_sign_connections);
    try testing.expect(seal_conns >= min_sign_and_encrypt_connections);
    // The renewal leg: one OPN opens the channel, each further one renews the
    // SecurityToken mid-stream, and it runs sealed.
    try testing.expect(max_opn >= min_opn_on_renewal_connection);
    try testing.expectEqual(services.MessageSecurityMode.sign_and_encrypt, renewal_mode);
    try testing.expect(client_bytes >= 20_000);

    // The write asyncua made, still in the address space.
    try testing.expectEqual(written_answer, Fixture.answerValue(&fx.store));
}

test "asyncua transcript: the endpoint list a real client discovered is the one we advertise" {
    // The discovery leg runs at SecurityPolicy#None, so its GetEndpointsResponse
    // is plaintext in the recording and can be decoded here — which turns
    // asyncua's own `ZIGLIBS-OK-ENDPOINTS 3 Basic256Sha256|Sign,
    // Basic256Sha256|SignAndEncrypt,None|None_` from a note into a check, and
    // its `assert e.ServerCertificate` with it.
    const gpa = testing.allocator;

    var seed: [32]u8 = undefined;
    var start_time: encoding.DateTime = 0;
    {
        var it = std.mem.splitScalar(u8, transcript, '\n');
        const config = while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \r\t");
            if (std.mem.startsWith(u8, line, "config ")) break line;
        } else return error.TranscriptHasNoConfig;
        const seed_hex = arg(config, "seed") orelse return error.MissingArgument;
        _ = std.fmt.hexToBytes(&seed, seed_hex) catch return error.BadHex;
        start_time = try numArg(i64, config, "start_time");
    }
    var fx: Fixture = undefined;
    try fx.init(gpa, seed, start_time, 2_000);
    defer fx.deinit();

    // Collect the server's bytes on the FIRST connection straight out of the
    // recording — no replay needed, because what is being read here is what the
    // transcript says we sent, and the byte-for-byte test above is what proves
    // we still send it.
    var s2c: std.ArrayList(u8) = .empty;
    defer s2c.deinit(gpa);
    {
        var it = std.mem.splitScalar(u8, transcript, '\n');
        var in_first = false;
        var seen_open = false;
        while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \r\t");
            if (line.len == 0 or line[0] == '#') continue;
            if (std.mem.startsWith(u8, line, "open ")) {
                if (seen_open) break;
                seen_open = true;
                in_first = true;
                continue;
            }
            if (std.mem.startsWith(u8, line, "close ")) break;
            if (!in_first) continue;
            if (!std.mem.startsWith(u8, line, "step ")) continue;
            if (arg(line, "out") == null) continue;
            const bytes = try hexArg(gpa, line, "out");
            defer gpa.free(bytes);
            try s2c.appendSlice(gpa, bytes);
        }
    }
    try testing.expect(s2c.items.len > 0);

    // Reassemble the MSG chunks (`C`… then `F`) and decode the one that is a
    // GetEndpointsResponse. At #None the extended header is 16 bytes —
    // SecureChannelId, TokenId, SequenceNumber, RequestId — after the 8-byte
    // message header.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var found = false;
    var i: usize = 0;
    while (i < s2c.items.len) {
        const frame = s2c.items[i..];
        if (frame.len < 8) return error.TruncatedFrameHeader;
        const size = std.mem.readInt(u32, frame[4..8], .little);
        if (size < 24 or size > frame.len) return error.BadFrameLength;
        defer i += size;
        if (!std.mem.eql(u8, frame[0..3], "MSG")) continue;
        try body.appendSlice(gpa, frame[24..size]);
        if (frame[3] != 'F') continue;
        defer body.clearRetainingCapacity();

        var br: std.Io.Reader = .fixed(body.items);
        var d = encoding.Decoder.init(&br, gpa);
        const type_id = try d.decodeNodeId();
        if (!services.nodeIdEql(type_id, services.type_id.get_endpoints_response)) continue;

        const response = try services.decodeGetEndpointsResponse(&d);
        defer services.freeGetEndpointsResponse(gpa, response);
        const endpoints = response.endpoints orelse return error.NoEndpoints;
        try testing.expectEqual(@as(usize, 3), endpoints.len);
        const expected = [_]struct { uri: []const u8, mode: services.MessageSecurityMode }{
            .{ .uri = services.security_policy_none_uri, .mode = .none },
            .{ .uri = security.SecurityPolicy.basic256sha256.uri(), .mode = .sign },
            .{ .uri = security.SecurityPolicy.basic256sha256.uri(), .mode = .sign_and_encrypt },
        };
        for (endpoints, expected[0..]) |ep, want| {
            try testing.expectEqualStrings(live_endpoint_url, ep.endpoint_url.?);
            try testing.expectEqualStrings(want.uri, ep.security_policy_uri.?);
            try testing.expectEqual(want.mode, ep.security_mode);
            try testing.expectEqualStrings(server.transport_profile_uri, ep.transport_profile_uri.?);
            // asyncua asserts every secured endpoint carries a
            // ServerCertificate; this goes further and requires it to be OUR
            // certificate, which is the one its handshake then encrypts to.
            if (ep.security_mode != .none) {
                try testing.expectEqualSlices(u8, fx.creds.certificate_der, ep.server_certificate.?);
            }
        }
        found = true;
        break;
    }
    try testing.expect(found);
}

test "asyncua transcript: the header names the peer, the date and the command that took it" {
    // Provenance is the difference between a fixture and a pile of bytes: a
    // recording nobody can re-take is one nobody can update when it goes stale.
    // Checked here rather than trusted, because the header is written by a tool
    // that only runs where asyncua is installed.
    const head = transcript[0..@min(transcript.len, 4096)];
    try testing.expect(std.mem.indexOf(u8, head, "asyncua=") != null);
    try testing.expect(std.mem.indexOf(u8, head, "python=") != null);
    try testing.expect(std.mem.indexOf(u8, head, "captured:") != null);
    try testing.expect(std.mem.indexOf(u8, head, "zig build interop-opcua -- --capture") != null);
}
