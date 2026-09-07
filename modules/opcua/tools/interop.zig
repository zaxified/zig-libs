// SPDX-License-Identifier: MIT

//! LIVE third-party-client interop for `opcua`: Python **`asyncua`** driving
//! this module's server over a real loopback socket at
//! `SecurityPolicy#Basic256Sha256` — and the recorder that turns that exchange
//! into a committed transcript the module replays with no interpreter and no
//! `asyncua` anywhere near it.
//!
//! ## Why this is a PROGRAM and not a test
//!
//! A zig-libs module is standalone Zig with no external dependency. Until
//! 2026-09-07 this exchange lived in `modules/opcua/src/server_interop.zig` as
//! a ~190-line Python driver held in an inline `\\` string literal and run with
//! `python3 -c`, so `zig build test-opcua` reached for an interpreter and a
//! third-party package the module has no business needing, and skipped —
//! loudly, but skipped — wherever they were absent. It was the seventh instance
//! of the shape six modules were separated from on 2026-09-06 (`f3dbf38d`,
//! `f42cc67a`), missed for a mechanical reason: the other six kept their driver
//! in a FILE, which could be `git mv`'d and was therefore visible, while a
//! string constant moves nowhere and shows up in no diff of moved files.
//!
//! Now: the TAKING of the anchor lives here, outside the module, where spawning
//! an interpreter is unremarkable. The VALUE of the anchor lives in
//! `src/testdata/asyncua_transcript.txt` and is replayed by
//! `src/asyncua_replay.zig`, which is pure Zig and runs everywhere.
//!
//! What only THIS can do, stated so the replay is not mistaken for a
//! replacement: discover a NEW divergence. The transcript is frozen bytes from
//! one asyncua release; it can prove we still answer those bytes the way a real
//! peer accepted, and it can never prove a real peer accepts an answer it has
//! not seen. Run it after any wire-visible change, and before a release.
//!
//! ## Usage
//!
//!     zig build interop-opcua                  # run the exchange live
//!     zig build interop-opcua -- --capture     # ...and rewrite the transcript
//!     zig build interop-opcua -- --python PATH # a virtualenv's interpreter
//!     zig build interop-opcua -- --repo-root P # read the driver from P
//!
//! It reads `modules/opcua/tools/asyncua_driver.py` **from its own path at run
//! time**, relative to the repository root (which is `zig build`'s working
//! directory). Nothing is embedded and nothing is inlined, so nothing forces
//! foreign source to live inside the module.
//!
//! To install the peer: `python3 -m pip install asyncua cryptography` (a
//! virtualenv plus `--python <venv>/bin/python3` is the tidy way).
//!
//! ⛔ NOT IN SCOPE HERE, deliberately: `src/server_interop.zig` and
//! `src/root.zig` also run open62541's stock binaries inside a `podman`
//! container. A container running a third-party SERVER is a live PEER, not a
//! foreign toolchain — whether a module's tests may reach a live peer at all is
//! a different question, answered by `live` in `build.zig`'s `module_list`, and
//! `check-module-purity` deliberately does not flag it.

const std = @import("std");
const opcua = @import("opcua");

const encoding = opcua.encoding;
const services = opcua.services;
const nodestore = opcua.nodestore;
const server = opcua.server;
const security = opcua.security;

const transcript_path = "modules/opcua/src/testdata/asyncua_transcript.txt";
const driver_path = "modules/opcua/tools/asyncua_driver.py";

// ── the fixture ────────────────────────────────────────────────────────────
//
// ⚠ MIRRORED, NOT SHARED, and it cannot be otherwise: an interop program's
// package root is `modules/opcua/tools/`, so it can import `opcua` and nothing
// under `../src/`. Every constant from here down to `Fixture.init` is repeated
// verbatim in `src/asyncua_replay.zig`, and the two are held together by the
// `fixture cert_sha256=` line the transcript carries: the replay regenerates
// this server from the recorded seed and refuses to go on if the certificate it
// gets is not the one the recording was taken against. A drift in ANY of these
// values changes that hash, so it is named at the top of the replay rather than
// showing up as "the OpenSecureChannel response differs by 400 bytes".

const live_host = "127.0.0.1";
const live_port: u16 = 4841;
const live_endpoint_url = "opc.tcp://localhost:4841";
const live_ns_uri = "urn:zig-libs:opcua:interop";
const application_uri = "urn:zig-libs:opcua:interop-server";

/// `Objects/the.answer` — the node the driver reads, writes and monitors.
const answer_node: encoding.NodeId = .{ .string = .{ .namespace = 1, .id = "the.answer" } };
/// `UA_NODEID_NUMERIC(1, 62541)` on the Objects folder — the method it calls.
const method_node: encoding.NodeId = .{ .numeric = .{ .namespace = 1, .id = 62_541 } };

/// The CSPRNG seed the whole server is derived from: its RSA key pair and
/// self-signed certificate, every SecureChannel nonce, every token id and every
/// AuthenticationToken. Fixed so a failing live run can be re-run byte for byte
/// — and so the transcript replays at all. Test material; nothing here is a
/// default for anything, and the private key never leaves the process.
const server_seed: [32]u8 = @splat(0x7e);

/// A short SecurityToken floor so the renewal leg forces renewals inside a
/// test-sized window (the product default is 60 s).
const min_token_lifetime_ms: u32 = 2_000;

/// The driver connects with `user1`/`password` on its Sign leg — a test
/// fixture, not a credential of anything real.
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

/// Echoes its String input back — the method the driver invokes. Anything else
/// is answered with a Bad status, never a crash.
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

/// The server this exchange runs against, built entirely from `server_seed` and
/// a caller-supplied `start_time`. Init is IN PLACE because `Server` holds a
/// pointer to the store and a `std.Random` that points into `csprng`.
const Fixture = struct {
    gpa: std.mem.Allocator,
    csprng: std.Random.DefaultCsprng,
    store: nodestore.NodeStore,
    srv: server.Server,
    creds: security.Credentials,
    endpoint_storage: [3]services.EndpointDescription,
    start_time: encoding.DateTime,

    fn init(f: *Fixture, gpa: std.mem.Allocator, start_time: encoding.DateTime) !void {
        f.gpa = gpa;
        f.start_time = start_time;
        // ⚠ THE ORDER OF EVERY DRAW FROM HERE ON IS PART OF THE FIXTURE. One
        // stream feeds the key pair and then the server, so inserting a draw
        // anywhere ahead of another moves every later nonce.
        f.csprng = std.Random.DefaultCsprng.init(server_seed);
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

        // 2048 bits: the conventional application-certificate size for
        // Basic256Sha256. `not_before`/`not_after` bracket a decade so neither
        // the live run nor the replay rots on a date.
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
            // No trust list: this interop server accepts any structurally
            // valid, in-date client certificate. Stated plainly — it is what
            // makes the exchange self-contained, and it is not a production
            // posture (see `server.CertificatePolicy`).
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

    /// `Objects/the.answer` as an Int32, or `0` when it is anything else — the
    /// one piece of server state the driver is supposed to have changed.
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

    /// The fingerprint the transcript carries and the replay checks first.
    fn certSha256(f: *const Fixture) [32]u8 {
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(f.creds.certificate_der, &out, .{});
        return out;
    }
};

// ── what each connection turned out to be ──────────────────────────────────

/// ⚠ NOT A LABEL THIS PROGRAM CHOOSES. The first version of this file wrote a
/// `phase=` name onto each connection from its ordinal, on the theory that the
/// driver makes four of them -- endpoint discovery, SignAndEncrypt, Sign,
/// renewal -- which is what the in-module test asserted (`connections >= 4`)
/// and what its comments said. asyncua 2.0.1 makes SEVEN: it re-runs
/// `GetEndpoints` over a fresh unsecured connection before each secured
/// session, so the secured legs are #3, #5 and #7 and every even one is
/// discovery. A hand-written label would have recorded that wrong and the
/// replay would have re-checked the wrong thing forever.
///
/// So what is recorded is what the SERVER observed: the SecurityPolicy and
/// SecurityMode the channel actually reached, read off `Connection` before it
/// is torn down. The replay recomputes both from its own replayed connection
/// and compares -- which is how "the Sign leg really ran at Sign, with an
/// encrypted UserNameIdentityToken" survives into a hermetic test at all.
fn recordClose(s: *Session, c: *const server.Connection) void {
    s.rec.op("close");
    s.rec.numArg("n", s.connections);
    s.rec.strArg("policy", @tagName(c.sec_policy));
    s.rec.strArg("mode", @tagName(c.sec_mode));
    s.rec.end();
}

/// The floor the in-module test used before the migration, kept as the LIVE
/// check: fewer than this and the driver did not walk its legs at all.
const min_connections = 4;

// ── clocks (raw syscalls; no libc, matching this repo's invariant) ─────────

fn monotonicMs() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// The current OPC UA `DateTime` (100ns ticks since 1601-01-01) from the system
/// clock — 11644473600 is the 1601→1970 epoch offset in seconds.
fn opcUaNow() encoding.DateTime {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return (@as(i64, ts.sec) + 11_644_473_600) * 10_000_000 + @divTrunc(@as(i64, ts.nsec), 100);
}

fn utcDate(buf: []u8) []const u8 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.system.clock_gettime(.REALTIME, &ts) != 0) return "unknown";
    const secs: u64 = @intCast(ts.sec);
    const day = (std.time.epoch.EpochSeconds{ .secs = secs }).getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        day.year, md.month.numeric(), md.day_index + 1,
    }) catch "unknown";
}

// ── the recorder ───────────────────────────────────────────────────────────

const Recorder = struct {
    enabled: bool,
    out: *std.Io.Writer,

    fn raw(self: *Recorder, comptime fmt: []const u8, args: anytype) void {
        if (!self.enabled) return;
        self.out.print(fmt, args) catch @panic("OOM writing transcript");
    }

    fn op(self: *Recorder, name: []const u8) void {
        self.raw("{s}", .{name});
    }

    fn hexArg(self: *Recorder, key: []const u8, bytes: []const u8) void {
        if (!self.enabled) return;
        self.raw(" {s}=", .{key});
        for (bytes) |b| self.raw("{x:0>2}", .{b});
    }

    fn strArg(self: *Recorder, key: []const u8, value: []const u8) void {
        self.raw(" {s}={s}", .{ key, value });
    }

    fn numArg(self: *Recorder, key: []const u8, value: anytype) void {
        self.raw(" {s}={d}", .{ key, value });
    }

    fn end(self: *Recorder) void {
        self.raw("\n", .{});
    }

    /// A line the replay ignores. For everything the transcript can SHOW but
    /// not CHECK — the peer's own stdout, which is not bytes on the wire.
    fn note(self: *Recorder, comptime fmt: []const u8, args: anytype) void {
        self.raw("# ", .{});
        self.raw(fmt, args);
        self.raw("\n", .{});
    }
};

// ── the peer process ───────────────────────────────────────────────────────

/// The environment handed to the child.
///
/// It has to be passed explicitly. `std.process.SpawnOptions.environ_map` says
/// a null value inherits, and under the `Init.Minimal` main signature there is
/// nothing to inherit FROM: the environment arrives as a parameter instead of
/// living in a process global. A null there spawns Python with an EMPTY
/// environment, and a Python with no `PATH`/`HOME` finds a different set of
/// site-packages than the one the operator installed `asyncua` into.
var child_env: ?*const std.process.Environ.Map = null;

/// The driver process, plus the thread that drains it. Draining has to be
/// concurrent with serving: this program is the server the child is talking to,
/// so a main loop blocked in `child.wait` would deadlock the exchange it is
/// waiting for.
const Peer = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    stdout: []u8 = &.{},
    stderr: []u8 = &.{},
    exit_code: ?u8 = null,
    failed: ?anyerror = null,
    /// Raised by `drain` once the process has actually exited — the only honest
    /// answer to "is the peer finished", and the reason this loop never has to
    /// guess from a gap between connections. The driver makes FOUR separate
    /// connections and the pauses between them belong to the machine, not to
    /// the protocol.
    done: std.atomic.Value(bool) = .init(false),

    fn drain(p: *Peer) void {
        defer p.done.store(true, .release);
        var out_buf: [4096]u8 = undefined;
        var stdout_reader = p.child.stdout.?.reader(p.io, &out_buf);
        p.stdout = stdout_reader.interface.allocRemaining(p.gpa, .unlimited) catch |e| blk: {
            p.failed = e;
            break :blk &.{};
        };
        var err_buf: [4096]u8 = undefined;
        var stderr_reader = p.child.stderr.?.reader(p.io, &err_buf);
        p.stderr = stderr_reader.interface.allocRemaining(p.gpa, .unlimited) catch |e| blk: {
            p.failed = e;
            break :blk &.{};
        };
        const term = p.child.wait(p.io) catch |e| {
            p.failed = e;
            return;
        };
        p.exit_code = switch (term) {
            .exited => |code| code,
            else => null,
        };
    }
};

/// Ask the interpreter whether it can import what the driver needs, before
/// standing a server up for it. A clear "install this" beats a socket that
/// nobody ever connects to.
fn probeInterpreter(gpa: std.mem.Allocator, io: std.Io, python: []const u8) !void {
    var child = std.process.spawn(io, .{
        .argv = &.{ python, "-c", "import asyncua, cryptography" },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
        .environ_map = child_env,
    }) catch |err| {
        std.debug.print("cannot run \"{s}\": {t}\n", .{ python, err });
        return error.NoInterpreter;
    };
    var out_buf: [1024]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    const out = stdout_reader.interface.allocRemaining(gpa, .limited(64 * 1024)) catch "";
    var err_buf: [1024]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &err_buf);
    const err_text = stderr_reader.interface.allocRemaining(gpa, .limited(64 * 1024)) catch "";
    _ = out;
    const term = child.wait(io) catch return error.NoInterpreter;
    const code = switch (term) {
        .exited => |c| c,
        else => 255,
    };
    if (code != 0) {
        std.debug.print(
            "\"{s}\" cannot import asyncua/cryptography:\n{s}\n" ++
                "install them (`python3 -m pip install asyncua cryptography`) or pass --python <venv>/bin/python3\n",
            .{ python, err_text },
        );
        return error.NoAsyncua;
    }
}

// ── the serve loop ─────────────────────────────────────────────────────────

/// How long one poll waits. Also the resolution of the recorded clock, and
/// therefore of the replay: every iteration is one `step` line.
const poll_ms = 20;
/// Whatever happens, this program exits. The driver's own renewal leg is ~30 s
/// and the whole session ~40 s; this is a backstop, not a budget.
const deadline_ms = 240_000;
/// Keep serving this long after the child has exited, so a last CLO/FIN is
/// recorded rather than truncated.
const drain_ms = 300;

const Session = struct {
    fx: *Fixture,
    rec: *Recorder,
    connections: usize = 0,
    rejected: usize = 0,
    steps: usize = 0,
};

fn serve(s: *Session, io: std.Io, listener: *std.Io.net.Server, peer: *Peer) !void {
    var out: std.Io.Writer.Allocating = .init(s.fx.gpa);
    defer out.deinit();

    var conn: ?server.Connection = null;
    var stream: ?std.Io.net.Stream = null;
    var write_buf: [64 * 1024]u8 = undefined;
    var stream_writer: ?std.Io.net.Stream.Writer = null;
    const recv_buf = try s.fx.gpa.alloc(u8, 128 * 1024);
    defer s.fx.gpa.free(recv_buf);
    const msg_buf = try s.fx.gpa.alloc(u8, 1 << 20);
    defer s.fx.gpa.free(msg_buf);
    defer if (stream) |st| st.close(io);
    defer if (conn) |*c| c.deinit();

    const started = monotonicMs();
    var finished_at: ?i64 = null;
    var read_buf: [64 * 1024]u8 = undefined;

    while (monotonicMs() - started < deadline_ms) {
        if (peer.done.load(.acquire)) {
            const now = monotonicMs();
            if (finished_at == null) finished_at = now;
            if (now - finished_at.? > drain_ms) break;
        }

        var fds: [2]std.posix.pollfd = undefined;
        var nfds: usize = 1;
        fds[0] = .{ .fd = listener.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        if (stream) |st| {
            fds[1] = .{ .fd = st.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
            nfds = 2;
        }
        _ = std.posix.poll(fds[0..nfds], poll_ms) catch break;

        // ⚠ THE CLOSED PEER IS HANDLED BEFORE A NEW ONE IS ACCEPTED, and the
        // order is the whole point: one `poll` can report BOTH that the current
        // peer hung up and that the next connection is waiting, which is the
        // ordinary shape of a client that disconnects and immediately
        // reconnects — and this driver does it three times.
        var input: []const u8 = &.{};
        if (nfds == 2 and fds[1].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR) != 0) {
            const n = std.posix.read(stream.?.socket.handle, &read_buf) catch 0;
            if (n == 0) {
                stream.?.close(io);
                stream = null;
                stream_writer = null;
                if (conn) |*c| {
                    recordClose(s, c);
                    c.deinit();
                }
                conn = null;
                continue;
            }
            input = read_buf[0..n];
        }

        if (fds[0].revents & std.posix.POLL.IN != 0) {
            if (stream == null) {
                const accepted = listener.accept(io) catch continue;
                stream = accepted;
                stream_writer = accepted.writer(io, &write_buf);
                conn = try server.Connection.init(&s.fx.srv, recv_buf, msg_buf);
                s.connections += 1;
                s.rec.op("open");
                s.rec.numArg("n", s.connections);
                s.rec.end();
            } else {
                // A second connection while one is in flight is CLOSED, not left
                // in the backlog: the kernel completes its handshake there, so
                // the peer sees an ESTABLISHED socket, sends HEL and waits for
                // an ACK nobody will write — a healthy server that reads exactly
                // like a hung one.
                if (listener.accept(io)) |extra| {
                    extra.close(io);
                    s.rejected += 1;
                } else |_| {}
            }
        }

        // ⭐ ONE ITERATION IS ONE `step`, AND ITS ORDER IS THE CONTRACT the
        // replay re-executes: refresh the server's own time-bearing nodes, feed
        // whatever arrived, then let the clock run. Both halves of the output
        // go on the wire back to back, so they are recorded as one `out=`.
        const now = monotonicMs() - started;
        out.clearRetainingCapacity();
        s.fx.srv.refreshTime(now, s.fx.start_time) catch {};
        if (input.len > 0) try conn.?.feed(input, &out.writer, now);
        if (conn) |*c| try c.tick(&out.writer, now);
        const produced = out.written();

        s.rec.op("step");
        s.rec.numArg("t", now);
        if (input.len > 0) s.rec.hexArg("in", input);
        if (produced.len > 0) s.rec.hexArg("out", produced);
        s.rec.end();
        s.steps += 1;

        if (produced.len > 0) {
            stream_writer.?.interface.writeAll(produced) catch {};
            stream_writer.?.interface.flush() catch {};
        }

        if (conn) |*c| {
            if (c.isClosed()) {
                stream.?.close(io);
                stream = null;
                stream_writer = null;
                recordClose(s, c);
                c.deinit();
                conn = null;
            }
        }
    }
}

// ── the header ─────────────────────────────────────────────────────────────

fn writeHeader(w: *std.Io.Writer, versions: []const u8, fx: *const Fixture) !void {
    var date_buf: [16]u8 = undefined;
    try w.print(
        \\# opcua ↔ Python asyncua Basic256Sha256 transcript — a RECORDING, not a
        \\# specification.
        \\#
        \\# Every byte below was taken off a real loopback TCP socket between this
        \\# module's server and Python `asyncua`. `modules/opcua/tools/interop.zig`
        \\# wrote it; `modules/opcua/src/asyncua_replay.zig` replays it with no
        \\# interpreter and no asyncua in sight, which is where the anchor's value now
        \\# lives. Re-taking it needs a Python with `asyncua` and `cryptography`:
        \\#
        \\#     peer:     {s}
        \\#     captured: {s}
        \\#     command:  zig build interop-opcua -- --capture
        \\#
        \\# WHAT PINS IT — and OPC UA has a great deal to pin. Every random byte this
        \\# server draws (its RSA key pair and self-signed certificate, every
        \\# SecureChannel nonce, every SecurityToken id, every 32-byte
        \\# AuthenticationToken) comes from ONE `std.Random.DefaultCsprng` seeded with
        \\# the `seed` below, and every timestamp it writes (`DateTime`s, token
        \\# lifetimes, publish and session deadlines) is computed from `start_time`
        \\# plus the `t=` the caller passes in — because `feed`/`tick` take time as a
        \\# PARAMETER. Nothing was weakened and nothing was stubbed to make this
        \\# replay: seeded randomness and injected time are the module's own seams,
        \\# used by `server.zig`'s own tests since before this file existed. Sequence
        \\# numbers, request handles and channel ids then follow from the recorded
        \\# inputs. Given the same seed, the same start_time and the same `t=`/`in=`
        \\# sequence, this server emits the same bytes, which is why asyncua's
        \\# recorded ciphertext still decrypts: its keys were derived from OUR nonce.
        \\#
        \\# WHAT IT CANNOT DO. Nothing here can discover a NEW divergence: the peer's
        \\# bytes are frozen at one asyncua release, so a change a newer asyncua would
        \\# refuse passes, and a change that makes us emit different-but-still-valid
        \\# bytes (a different nonce, a reordered endpoint list) fails the replay
        \\# without any real peer having refused anything. A red replay is a summons
        \\# to re-run `zig build interop-opcua`, not a verdict. It also cannot check
        \\# what was never bytes on the wire — asyncua's own assertions and its exit
        \\# status were checked when the recording was taken and are kept below as `#`
        \\# notes precisely because nothing here can re-check them.
        \\#
        \\# FORMAT. One operation per line; `#` is a comment; hex is lowercase.
        \\#
        \\#   config seed=<hex32> start_time=<i64> ...   what the fixture was built from
        \\#   fixture cert_sha256=<hex32>                the server certificate that seed produced
        \\#   open n=<k>                                 a TCP connection was accepted
        \\#   close n=<k> policy=<name> mode=<name>      ...and went away, having reached this
        \\#   step t=<ms> [in=<hex>] [out=<hex>]         refreshTime(t); feed(in,t); tick(t)
        \\#                                              must produce exactly <out>
        \\#   expect answer=<i32> connections=<k> ...    the server's own view, at the end
        \\#
        \\format version=1
        \\
        \\
    , .{ versions, utcDate(&date_buf) });

    try w.print("config seed=", .{});
    for (server_seed) |b| try w.print("{x:0>2}", .{b});
    try w.print(" start_time={d} min_token_lifetime_ms={d} poll_ms={d} endpoint_url={s}\n", .{
        fx.start_time, min_token_lifetime_ms, poll_ms, live_endpoint_url,
    });
    try w.print("fixture cert_sha256=", .{});
    for (fx.certSha256()) |b| try w.print("{x:0>2}", .{b});
    try w.print(" ns_uri={s} app_uri={s}\n\n", .{ live_ns_uri, application_uri });
}

// ── main ───────────────────────────────────────────────────────────────────

const usage =
    \\opcua live interop against Python asyncua.
    \\
    \\  zig build interop-opcua                   run the exchange live
    \\  zig build interop-opcua -- --capture      ...and rewrite the committed transcript
    \\  zig build interop-opcua -- --python PATH  interpreter to use (default: python3)
    \\  zig build interop-opcua -- --repo-root P  read the driver script from P
    \\
    \\Needs a Python with `asyncua` and `cryptography`. The hermetic half of this
    \\-- replaying what a capture recorded -- is `zig build test-opcua`, and needs
    \\neither.
    \\
;

/// Every marker the driver prints that the exchange is judged by. Identical in
/// content to what the in-module test asserted before the migration; the
/// replay's own, byte-level assertions are in `src/asyncua_replay.zig`.
const expectations = [_][]const u8{
    "ZIGLIBS-OK-ENDPOINTS 3 Basic256Sha256|Sign,Basic256Sha256|SignAndEncrypt,None|None_",
    "ZIGLIBS-OK-CONNECT SignAndEncrypt", // the asymmetric handshake + key derivation agreed
    "ZIGLIBS-OK-BROWSE", // Browse over signed+encrypted chunks
    "ZIGLIBS-OK-READ", // Read
    "ZIGLIBS-OK-WRITE 31337", // Write, read back through the same channel
    "ZIGLIBS-OK-CALL", // Call
    "ZIGLIBS-OK-SUBSCRIPTION", // CreateSubscription + Publish
    "ZIGLIBS-OK-SIGN-USERNAME", // Sign mode + RSA-OAEP-encrypted UserNameIdentityToken
    "ZIGLIBS-OK-RENEWAL 30", // 30 reads across ~30 s with a 10 s token: renewals mid-stream
    "ZIGLIBS-ALL-DONE",
};

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    // An arena over it: this program is one short run and then it exits, and
    // the alternative is threading `free` through every early-return diagnosis
    // path -- where a forgotten one turns a real interop failure into a leak
    // report printed on top of it.
    var arena: std.heap.ArenaAllocator = .init(da.allocator());
    defer arena.deinit();
    const gpa = arena.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var env_map: std.process.Environ.Map = .init(gpa);
    try env_map.putPosixBlock(init.environ.block.view());
    child_env = &env_map;

    var capture = false;
    var repo_root: []const u8 = ".";
    var python: []const u8 = "python3";

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, arg, "--python")) {
            python = args.next() orelse {
                std.debug.print("--python needs a path\n{s}", .{usage});
                return 2;
            };
        } else if (std.mem.eql(u8, arg, "--repo-root")) {
            repo_root = args.next() orelse {
                std.debug.print("--repo-root needs a path\n{s}", .{usage});
                return 2;
            };
        } else {
            std.debug.print("unknown argument \"{s}\"\n{s}", .{ arg, usage });
            return 2;
        }
    }

    var root = std.Io.Dir.cwd().openDir(io, repo_root, .{}) catch {
        std.debug.print("cannot open repository root \"{s}\"\n", .{repo_root});
        return 2;
    };
    defer root.close(io);

    // Read from its own path, never embedded: the whole point of the
    // separation is that no foreign source is compiled into anything.
    const script_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ repo_root, driver_path });
    root.access(io, driver_path, .{}) catch {
        std.debug.print(
            "cannot find {s} under \"{s}\" -- run this from the repository root\n" ++
                "(`zig build interop-opcua` does) or pass --repo-root <path>\n",
            .{ driver_path, repo_root },
        );
        return 2;
    };

    probeInterpreter(gpa, io, python) catch return 1;

    const start_time = opcUaNow();
    var fx: Fixture = undefined;
    try fx.init(gpa, start_time);
    defer fx.deinit();

    const addr = try std.Io.net.IpAddress.parse(live_host, live_port);
    var listener = addr.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("cannot bind {s}:{d}: {t} (is another server holding it?)\n", .{ live_host, live_port, err });
        return 1;
    };
    defer listener.socket.close(io);

    var transcript: std.Io.Writer.Allocating = .init(gpa);
    defer transcript.deinit();
    var rec: Recorder = .{ .enabled = capture, .out = &transcript.writer };

    var peer: Peer = .{
        .gpa = gpa,
        .io = io,
        .child = std.process.spawn(io, .{
            .argv = &.{ python, script_path, live_endpoint_url },
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
            .environ_map = child_env,
        }) catch |err| {
            std.debug.print("cannot start the driver: {t}\n", .{err});
            return 1;
        },
    };
    const drainer = std.Thread.spawn(.{}, Peer.drain, .{&peer}) catch {
        std.debug.print("cannot spawn the drain thread\n", .{});
        return 1;
    };

    var session: Session = .{ .fx = &fx, .rec = &rec };
    // The header needs the peer's version banner, which only exists once the
    // child has printed it, so the body is recorded first and the header is
    // prepended after.
    const serve_result = serve(&session, io, &listener, &peer);
    drainer.join();
    if (serve_result) |_| {} else |err| {
        std.debug.print("the serve loop failed: {t}\n", .{err});
        return 1;
    }

    if (peer.failed) |err| {
        std.debug.print("could not read the driver's output: {t}\n", .{err});
        return 1;
    }

    const logs = peer.stdout;
    var failed = false;
    for (expectations) |needle| {
        if (std.mem.indexOf(u8, logs, needle) == null) {
            std.debug.print("driver output missing \"{s}\"\n", .{needle});
            failed = true;
        }
    }
    if (peer.exit_code != 0) {
        std.debug.print("the driver exited {?d}, not 0\n", .{peer.exit_code});
        failed = true;
    }
    if (session.connections < min_connections) {
        std.debug.print("only {d} connections, expected at least {d}\n", .{ session.connections, min_connections });
        failed = true;
    }
    if (failed) {
        std.debug.print("\n--- driver stdout ---\n{s}\n--- driver stderr ---\n{s}\n", .{ logs, peer.stderr });
        return 1;
    }

    const answer = Fixture.answerValue(&fx.store);
    std.debug.print(
        "ok: {d} connections, {d} steps, {d} rejected, driver exited 0\n",
        .{ session.connections, session.steps, session.rejected },
    );

    if (!capture) return 0;

    // Everything the transcript can SHOW but not CHECK goes in as a note.
    rec.raw("\n", .{});
    var it = std.mem.splitScalar(u8, logs, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0) continue;
        rec.note("peer said (not replayable): {s}", .{trimmed});
    }
    rec.note("peer exited 0 (not replayable): every assertion inside the driver held", .{});
    rec.raw("\n", .{});

    rec.op("expect");
    rec.numArg("connections", session.connections);
    rec.numArg("steps", session.steps);
    rec.numArg("answer", answer);
    rec.end();

    // The version banner the driver printed first, for the header.
    var versions: []const u8 = "asyncua (version not reported)";
    var vit = std.mem.splitScalar(u8, logs, '\n');
    while (vit.next()) |line| {
        const marker = "ZIGLIBS-VERSIONS ";
        if (std.mem.startsWith(u8, line, marker)) {
            versions = std.mem.trim(u8, line[marker.len..], " \r\t");
            break;
        }
    }

    var full: std.Io.Writer.Allocating = .init(gpa);
    defer full.deinit();
    try writeHeader(&full.writer, versions, &fx);
    try full.writer.writeAll(transcript.written());

    root.createDirPath(io, "modules/opcua/src/testdata") catch {};
    try root.writeFile(io, .{ .sub_path = transcript_path, .data = full.written() });
    std.debug.print("wrote {s} ({d} bytes)\n", .{ transcript_path, full.written().len });
    return 0;
}
