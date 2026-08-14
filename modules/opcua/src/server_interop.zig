// SPDX-License-Identifier: MIT

//! Live interop for the server side: a **real third-party client driving this
//! module's server** over a real TCP socket, plus the same server driven by
//! this module's own client over loopback.
//!
//! The oracle is `open62541` (MPL-2.0) — the same implementation the client
//! half of this module was validated against, here used purely as a black box:
//! its stock `tutorial_client_firststeps`, `client_subscription_loop` and
//! `client` example binaries are run inside `docker.io/open62541/open62541`
//! with `--network host`, pointed at the server this file stands up on
//! 127.0.0.1:4840, and their *stdout* is the assertion. No open62541 source is
//! used at build or run time (its example sources were read once, at authoring
//! time, to know which services each binary exercises — see `NOTICE`).
//!
//! Every test here **skips loudly** (`SKIPPED: …` + `error.SkipZigTest`) when
//! podman, the image or the loopback port is unavailable — never silently, and
//! never as a failure.
//!
//! The driver below is also the worked example of how to run this server for
//! real: a poll loop that feeds bytes in, ticks the clock, and writes bytes
//! out. It owns the socket and the timer; the module owns neither.

const builtin = @import("builtin");
const std = @import("std");
const encoding = @import("encoding.zig");
const transport = @import("transport.zig");
const services = @import("services.zig");
const nodestore = @import("nodestore.zig");
const server = @import("server.zig");
const security = @import("security.zig");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

const testing = std.testing;

/// The open62541 example binaries connect to a hard-coded
/// `opc.tcp://localhost:4840`, and glibc's resolver hands them **::1** first
/// — so the interop listener binds IPv6 loopback, with IPv4 loopback as the
/// fallback for hosts without IPv6.
const live_hosts = [_][]const u8{ "::1", "127.0.0.1" };
const live_port: u16 = 4840;
const live_endpoint_url = "opc.tcp://localhost:4840";
/// A second loopback port for the Basic256Sha256 interop server, so a secured
/// run never collides with the SecurityPolicy#None one above.
const live_secure_port: u16 = 4841;
const live_secure_endpoint_url = "opc.tcp://localhost:4841";
const live_ns_uri = "urn:zig-libs:opcua:interop";

/// `Objects/the.answer` — the node the open62541 `client` example reads,
/// writes and monitors (it addresses it as `UA_NODEID_STRING(1,
/// "the.answer")`), so this server publishes exactly that NodeId in exactly
/// that namespace index.
const answer_node: encoding.NodeId = .{ .string = .{ .namespace = 1, .id = "the.answer" } };
/// `UA_NODEID_NUMERIC(1, 62541)` on the Objects folder — the method that
/// example calls.
const method_node: encoding.NodeId = .{ .numeric = .{ .namespace = 1, .id = 62_541 } };

// ── clocks (raw syscalls; no libc, matching this repo's invariant) ──────────

fn monotonicMs() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// The current OPC UA `DateTime` (100ns ticks since 1601-01-01) from the
/// system clock — 11644473600 is the 1601→1970 epoch offset in seconds.
fn opcUaNow() encoding.DateTime {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return (@as(i64, ts.sec) + 11_644_473_600) * 10_000_000 + @divTrunc(@as(i64, ts.nsec), 100);
}

fn sleepMs(ms: u64) void {
    var ts: std.os.linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    _ = std.os.linux.nanosleep(&ts, null);
}

// ── the driver: sockets + clock around the pure state machine ───────────────

/// Echoes its String input back — the method the open62541 `client` example
/// invokes. Anything else is answered with a Bad status, never a crash.
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

const Driver = struct {
    gpa: std.mem.Allocator,
    /// The caller owns the `std.Io.Threaded` behind this — it must outlive
    /// the driver (socket lifecycle goes through `std.Io.net`; the serve loop
    /// itself polls/reads the raw handles).
    io: std.Io,
    store: nodestore.NodeStore,
    srv: server.Server,
    prng: std.Random.DefaultPrng,
    listener: std.Io.net.Server,
    /// Whichever loopback address `init` managed to bind.
    bound_host: []const u8 = live_hosts[0],
    recv_buf: []u8,
    msg_buf: []u8,
    out: std.Io.Writer.Allocating,
    /// Every byte the peer sent / this server answered, in order — the source
    /// of the goldens in `server_goldens.zig` and of the rawshark capture.
    capture_c2s: std.ArrayList(u8),
    capture_s2c: std.ArrayList(u8),
    start_ms: i64,
    start_time: encoding.DateTime,
    connections: usize = 0,
    /// Bumped every serve iteration so a monitored `the.answer` actually
    /// changes for a subscribing client.
    counter: i32 = 42,
    /// Basic256Sha256 material, when this driver was built with
    /// `InitOptions.secure`. **Test material**: a 2048-bit RSA key pair and a
    /// self-signed application certificate generated in-process at test time
    /// from the module's own `rsa`; never read from disk, never a real key.
    creds: ?security.Credentials = null,
    /// Backing storage for the endpoint list a secured driver advertises
    /// (None + Basic256Sha256 Sign + Basic256Sha256 SignAndEncrypt); the
    /// certificate they embed is `creds`, so it cannot be a comptime array.
    endpoint_storage: [3]services.EndpointDescription = undefined,
    endpoint_count: usize = 0,
    port: u16 = live_port,

    const app: services.ApplicationDescription = .{
        .application_uri = "urn:zig-libs:opcua:interop-server",
        .product_uri = "urn:zig-libs:opcua",
        .application_name = .{ .locale = "en", .text = "zig-libs opcua interop server" },
        .application_type = .server,
        .gateway_server_uri = null,
        .discovery_profile_uri = null,
        .discovery_urls = null,
    };

    const endpoints = [_]services.EndpointDescription{server.noneEndpoint(live_endpoint_url, app)};

    /// open62541's `client` example connects with `UA_Client_connect_username
    /// ("user1", "password")`, so the interop server accepts exactly that pair
    /// — a test fixture, not a credential of anything real.
    const users = [_]server.UserCredential{.{ .user_name = "user1", .password = "password" }};

    const InitOptions = struct {
        /// Stand the server up with `SecurityPolicy#Basic256Sha256` at Sign
        /// and SignAndEncrypt as well as None, generating a fresh test key
        /// pair + self-signed certificate for it.
        secure: bool = false,
        port: u16 = live_port,
        endpoint_url: []const u8 = live_endpoint_url,
    };

    fn init(d: *Driver, gpa: std.mem.Allocator, io: std.Io) !void {
        return d.initWith(gpa, io, .{});
    }

    fn initWith(d: *Driver, gpa: std.mem.Allocator, io: std.Io, options: InitOptions) !void {
        var bound_host: []const u8 = live_hosts[0];
        const listener = blk: {
            var last_err: anyerror = error.AddressInUse;
            for (live_hosts) |host| {
                const addr = std.Io.net.IpAddress.parse(host, options.port) catch continue;
                if (addr.listen(io, .{ .reuse_address = true })) |l| {
                    bound_host = host;
                    break :blk l;
                } else |err| last_err = err;
            }
            return last_err;
        };
        d.* = .{
            .gpa = gpa,
            .io = io,
            .store = nodestore.NodeStore.init(gpa),
            .srv = undefined,
            .prng = std.Random.DefaultPrng.init(@bitCast(monotonicMs())),
            .listener = listener,
            .bound_host = bound_host,
            .recv_buf = try gpa.alloc(u8, 128 * 1024),
            .msg_buf = try gpa.alloc(u8, 1 << 20),
            .out = std.Io.Writer.Allocating.init(gpa),
            .capture_c2s = .empty,
            .capture_s2c = .empty,
            .start_ms = monotonicMs(),
            .start_time = opcUaNow(),
            .port = options.port,
        };

        try d.store.addStandardNodes(.{ .start_time = d.start_time });
        const ns = try d.store.addNamespace(live_ns_uri);
        std.debug.assert(ns == 1);
        try d.store.refreshNamespaceArray();
        try d.store.addVariable(.{
            .node_id = answer_node,
            .parent_id = nodestore.n0(nodestore.id.objects_folder),
            .reference_type_id = nodestore.n0(nodestore.id.organizes),
            .browse_name = .{ .namespace_index = 1, .name = "the.answer" },
            .display_name = .{ .locale = "en", .text = "the answer" },
            .value = .{ .scalar = .{ .int32 = 42 } },
            .data_type = nodestore.n0(nodestore.id.int32),
            .access_level = nodestore.access_level.read_write,
            .timestamp = d.start_time,
        });
        try d.store.addMethod(.{
            .node_id = method_node,
            .parent_id = nodestore.n0(nodestore.id.objects_folder),
            .browse_name = .{ .namespace_index = 1, .name = "hello world" },
            .implementation = echoMethod,
        });

        var security_config: ?server.SecurityConfig = null;
        if (options.secure) {
            // 2048 bits: the conventional application-certificate size for
            // Basic256Sha256, and what a real third-party client expects to
            // meet. `not_before`/`not_after` bracket a decade so the test
            // does not rot.
            const creds = try security.Credentials.generateSelfSigned(gpa, d.prng.random(), .{
                .modulus_bits = 2048,
                .common_name = "zig-libs opcua interop server",
                .not_before = "200101000000Z",
                .not_after = "350101000000Z",
                .application_uri = "urn:zig-libs:opcua:interop-server",
            });
            d.creds = creds;
            d.endpoint_storage[0] = server.noneEndpointWithEncryptedUserTokens(options.endpoint_url, app, creds.certificate_der);
            d.endpoint_storage[1] = server.secureEndpoint(options.endpoint_url, app, .sign, creds.certificate_der, 10);
            d.endpoint_storage[2] = server.secureEndpoint(options.endpoint_url, app, .sign_and_encrypt, creds.certificate_der, 20);
            d.endpoint_count = 3;
            // No trust list: this interop server accepts any structurally
            // valid, in-date client certificate. Stated plainly — it is what
            // makes the test self-contained, and it is not a production
            // posture (see `server.CertificatePolicy`).
            security_config = .{ .credentials = creds };
        }
        const endpoint_slice: []const services.EndpointDescription =
            if (options.secure) d.endpoint_storage[0..d.endpoint_count] else &endpoints;

        d.srv = server.Server.init(gpa, &d.store, .{
            .application_uri = "urn:zig-libs:opcua:interop-server",
            .application_name = .{ .locale = "en", .text = "zig-libs opcua interop server" },
            .endpoints = endpoint_slice,
            .users = &users,
            .security = security_config,
        }, d.prng.random());
        // `now_ms` is measured from `start_ms`, so the wall clock's zero point
        // is the server's start instant.
        d.srv.wall_clock_epoch = d.start_time;
    }

    fn deinit(d: *Driver) void {
        d.listener.socket.close(d.io);
        if (d.creds) |c| c.deinit(d.gpa);
        d.srv.deinit();
        d.store.deinit();
        d.gpa.free(d.recv_buf);
        d.gpa.free(d.msg_buf);
        d.out.deinit();
        d.capture_c2s.deinit(d.gpa);
        d.capture_s2c.deinit(d.gpa);
    }

    fn nowMs(d: *const Driver) i64 {
        return monotonicMs() - d.start_ms;
    }

    /// Push whatever the state machine produced onto the socket.
    fn flush(d: *Driver, writer: *std.Io.Writer) !void {
        const bytes = d.out.written();
        if (bytes.len == 0) return;
        try d.capture_s2c.appendSlice(d.gpa, bytes);
        writer.writeAll(bytes) catch {};
        writer.flush() catch {};
        d.out.clearRetainingCapacity();
    }

    const ServeOptions = struct {
        /// Give up after this long no matter what.
        deadline_ms: i64 = 30_000,
        /// Stop this long after the last connection closed (the peer is done).
        idle_stop_ms: i64 = 1_500,
        /// Advance `the.answer` on every iteration so a subscribing client
        /// sees data changes.
        vary_value: bool = true,
    };

    /// The whole runtime contract of this module, in one loop: poll, feed
    /// bytes in, tick the clock, write bytes back.
    fn serve(d: *Driver, options: ServeOptions) !void {
        var conn: ?server.Connection = null;
        var stream: ?std.Io.net.Stream = null;
        var write_buf: [64 * 1024]u8 = undefined;
        var stream_writer: ?std.Io.net.Stream.Writer = null;
        defer if (stream) |s| s.close(d.io);
        defer if (conn) |*c| c.deinit();

        const started = monotonicMs();
        var last_close_ms: ?i64 = null;
        while (monotonicMs() - started < options.deadline_ms) {
            if (last_close_ms) |closed_at| {
                if (stream == null and monotonicMs() - closed_at > options.idle_stop_ms) break;
            }

            var fds: [2]std.posix.pollfd = undefined;
            var nfds: usize = 1;
            fds[0] = .{ .fd = d.listener.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
            if (stream) |s| {
                fds[1] = .{ .fd = s.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
                nfds = 2;
            }
            _ = std.posix.poll(fds[0..nfds], 20) catch break;

            if (fds[0].revents & std.posix.POLL.IN != 0 and stream == null) {
                const accepted = d.listener.accept(d.io) catch continue;
                stream = accepted;
                stream_writer = accepted.writer(d.io, &write_buf);
                conn = try server.Connection.init(&d.srv, d.recv_buf, d.msg_buf);
                d.connections += 1;
            }

            if (nfds == 2 and fds[1].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR) != 0) {
                var buf: [16 * 1024]u8 = undefined;
                const n = std.posix.read(stream.?.socket.handle, &buf) catch 0;
                if (n == 0) {
                    stream.?.close(d.io);
                    stream = null;
                    stream_writer = null;
                    if (conn) |*c| c.deinit(); // frees the peer certificate, wipes the keys
                    conn = null;
                    last_close_ms = monotonicMs();
                    continue;
                }
                try d.capture_c2s.appendSlice(d.gpa, buf[0..n]);
                try conn.?.feed(buf[0..n], &d.out.writer, d.nowMs());
                try d.flush(&stream_writer.?.interface);
            }

            // The clock side: refresh the server's own time-bearing nodes,
            // vary the user variable, then let the subscription engine run.
            if (options.vary_value) {
                d.counter += 1;
                _ = d.store.setValue(answer_node, .{ .scalar = .{ .int32 = d.counter } }, d.srv.dateTime(d.nowMs())) catch {};
            }
            d.srv.refreshTime(d.nowMs(), d.start_time) catch {};
            if (conn) |*c| {
                try c.tick(&d.out.writer, d.nowMs());
                try d.flush(&stream_writer.?.interface);
                if (c.isClosed()) {
                    stream.?.close(d.io);
                    stream = null;
                    stream_writer = null;
                    c.deinit();
                    conn = null;
                    last_close_ms = monotonicMs();
                }
            }
        }
    }

    /// Dump the captured streams when `OPCUA_CAPTURE_DIR` is set — how the
    /// goldens were cut, and how the rawshark cross-check was fed.
    fn dumpCapture(d: *Driver, tag: []const u8) void {
        const dir_path = std.process.Environ.getPosix(std.testing.environ, "OPCUA_CAPTURE_DIR") orelse return;
        var path_buf: [256]u8 = undefined;
        if (std.fmt.bufPrint(&path_buf, "{s}/{s}-c2s.bin", .{ dir_path, tag })) |path| {
            std.Io.Dir.cwd().writeFile(d.io, .{ .sub_path = path, .data = d.capture_c2s.items }) catch {};
        } else |_| {}
        if (std.fmt.bufPrint(&path_buf, "{s}/{s}-s2c.bin", .{ dir_path, tag })) |path| {
            std.Io.Dir.cwd().writeFile(d.io, .{ .sub_path = path, .data = d.capture_s2c.items }) catch {};
        } else |_| {}
    }
};

// ── podman helpers (the open62541 image is the only external dependency) ────

const image = "docker.io/open62541/open62541:latest";

const PodmanResult = struct {
    exit_code: ?u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: PodmanResult, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
    }
};

fn runPodman(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) !PodmanResult {
    var argv = try gpa.alloc([]const u8, args.len + 1);
    defer gpa.free(argv);
    argv[0] = "podman";
    @memcpy(argv[1..], args);

    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return error.SkipZigTest;

    var out_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    const stdout = try stdout_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stdout);

    var err_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stderr);

    const term = try child.wait(io);
    return .{
        .exit_code = switch (term) {
            .exited => |code| code,
            else => null,
        },
        .stdout = stdout,
        .stderr = stderr,
    };
}

/// Spawn one of the image's client examples against this server, detached.
fn startClient(gpa: std.mem.Allocator, io: std.Io, name: []const u8, example: []const u8) !PodmanResult {
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/opt/open62541/build/bin/examples/{s}", .{example});
    // Deliberately no `--rm`: a client that exits quickly would take its
    // container (and therefore `podman logs`, this test's assertion source)
    // with it. The container is removed by `stopContainer` instead.
    return runPodman(gpa, io, &.{
        "run",    "-d", "--network",    "host",
        "--name", name, "--pull=never", image,
        path,
    });
}

/// Stop *and remove* a live-test container by name — best effort, used both
/// as leftover cleanup before starting and as teardown afterwards.
fn stopContainer(gpa: std.mem.Allocator, io: std.Io, name: []const u8) void {
    var result = runPodman(gpa, io, &.{ "rm", "-f", "-t", "1", name }) catch return;
    result.deinit(gpa);
}

const LiveClient = struct {
    driver: Driver,
    logs: []u8,

    fn deinit(lc: *LiveClient) void {
        lc.driver.gpa.free(lc.logs);
        lc.driver.deinit();
    }
};

/// Stand the server up, run `example` from the open62541 image against it, and
/// return the driver (for assertions on server state) plus the client's
/// stdout. Skips loudly when podman/the image/the port is unavailable.
fn runLiveClient(gpa: std.mem.Allocator, io: std.Io, name: []const u8, example: []const u8, options: Driver.ServeOptions) !LiveClient {
    if (builtin.os.tag != .linux) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE opcua server interop needs Linux (podman --network host).\n", .{});
        return error.SkipZigTest;
    }
    stopContainer(gpa, io, name); // leftover cleanup from a crashed run

    var driver: Driver = undefined;
    driver.init(gpa, io) catch |err| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE opcua server interop cannot bind loopback:{d} ({t}).\n", .{ live_port, err });
        return error.SkipZigTest;
    };
    errdefer driver.deinit();

    var run_result = startClient(gpa, io, name, example) catch |err| switch (err) {
        error.SkipZigTest => {
            if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE opcua server interop: `podman` is not available here.\n", .{});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer run_result.deinit(gpa);
    if (run_result.exit_code != 0) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE opcua server interop: `podman run` failed (image not pulled / podman unusable).\nstderr: {s}\n",
            .{run_result.stderr},
        );
        return error.SkipZigTest;
    }
    defer stopContainer(gpa, io, name);

    try driver.serve(options);
    driver.dumpCapture(example);

    // No connection at all means the client never reached this server — the
    // loopback port is held by something else, podman's networking is not
    // what this test assumes, or the image lacks the example. That is an
    // environment gap, not a server bug: skip loudly rather than fail.
    if (driver.connections == 0) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE opcua server interop: `{s}` never connected to loopback:{d} (port held by another process, or podman networking unavailable).\n",
            .{ example, live_port },
        );
        // `errdefer driver.deinit()` above releases the driver.
        return error.SkipZigTest;
    }

    const logs = try runPodman(gpa, io, &.{ "logs", name });
    defer gpa.free(logs.stderr);
    return .{ .driver = driver, .logs = logs.stdout };
}

test "LIVE open62541 -> our server: tutorial_client_firststeps connects, reads i=2258 and prints the time" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var live = try runLiveClient(gpa, threaded.io(), "opcua-zig-libs-server-firststeps", "tutorial_client_firststeps", .{
        .deadline_ms = 30_000,
        .vary_value = false,
    });
    defer live.deinit();

    // The example prints `date is: DD-MM-YYYY` after reading
    // Server_ServerStatus_CurrentTime over a full HEL / OPN / GetEndpoints /
    // CreateSession / ActivateSession / Read sequence.
    if (std.mem.indexOf(u8, live.logs, "date is:") == null) {
        std.debug.print("\ntutorial_client_firststeps output was:\n{s}\n", .{live.logs});
        return error.TestUnexpectedResult;
    }
    try testing.expect(live.driver.connections >= 1);
    // The very first thing it sent must be a Hello…
    try testing.expectEqualSlices(u8, "HELF", live.driver.capture_c2s.items[0..4]);
    // …and the first thing this server answered, an Acknowledge.
    try testing.expectEqualSlices(u8, "ACKF", live.driver.capture_s2c.items[0..4]);
}

test "LIVE open62541 -> our server: client_subscription_loop receives DataChangeNotifications" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var live = try runLiveClient(gpa, threaded.io(), "opcua-zig-libs-server-subs", "client_subscription_loop", .{
        .deadline_ms = 25_000,
        .idle_stop_ms = 1_000,
    });
    defer live.deinit();

    // The example subscribes to Server_ServerStatus_CurrentTime (i=2258) and
    // prints one line per data change — which only happens if this server's
    // CreateSubscription / CreateMonitoredItems / Publish path works end to
    // end, sequence numbering included.
    var changes: usize = 0;
    var it = std.mem.splitScalar(u8, live.logs, '\n');
    while (it.next()) |line| {
        if (std.mem.indexOf(u8, line, "currentTime has changed") != null) changes += 1;
    }
    if (changes == 0) {
        std.debug.print("\nclient_subscription_loop output was:\n{s}\n", .{live.logs});
        return error.TestUnexpectedResult;
    }
    try testing.expect(changes >= 2); // the initial value plus at least one change
}

test "LIVE open62541 -> our server: the `client` example browses, reads, writes, subscribes and calls" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var live = try runLiveClient(gpa, threaded.io(), "opcua-zig-libs-server-client", "client", .{
        .deadline_ms = 30_000,
        .idle_stop_ms = 2_000,
    });
    defer live.deinit();

    const logs = live.logs;
    const expectations = [_][]const u8{
        "endpoints found", // GetEndpoints, over its own connection
        "BROWSE NAME", // the Browse table header — Browse of the Objects folder
        "the.answer", // our string NodeId showed up in that table
        "Create subscription succeeded", // CreateSubscription
        "Monitoring 'the.answer'", // CreateMonitoredItems
        "the value is:", // Read of (1, "the.answer")
        "the new value is:", // Write of the same node
        "Method call was successful", // Call of (1, 62541)
    };
    for (expectations) |needle| {
        if (std.mem.indexOf(u8, logs, needle) == null) {
            std.debug.print("\n`client` output missing \"{s}\":\n{s}\n", .{ needle, logs });
            return error.TestUnexpectedResult;
        }
    }
    // It connects twice: once for GetEndpoints, once for the session — and
    // the session one authenticates with a UserNameIdentityToken.
    try testing.expect(live.driver.connections >= 2);
}

// ── our client against our server, over a real loopback socket ──────────────

const LoopbackCtx = struct {
    driver: *Driver,
    done: std.atomic.Value(bool) = .init(false),
};

fn loopbackServeThread(ctx: *LoopbackCtx) void {
    ctx.driver.serve(.{ .deadline_ms = 20_000, .idle_stop_ms = 500, .vary_value = false }) catch {};
    ctx.done.store(true, .release);
}

test "LIVE loopback: this module's own client drives this module's own server over TCP" {
    if (builtin.os.tag != .linux) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: loopback server test needs Linux sockets.\n", .{});
        return error.SkipZigTest;
    }
    const gpa = testing.allocator;
    const root = @import("root.zig");

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var driver: Driver = undefined;
    driver.init(gpa, io) catch |err| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: loopback server test cannot bind loopback:{d} ({t}).\n", .{ live_port, err });
        return error.SkipZigTest;
    };
    defer driver.deinit();

    var ctx: LoopbackCtx = .{ .driver = &driver };
    const thread = std.Thread.spawn(.{}, loopbackServeThread, .{&ctx}) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: loopback server test cannot spawn a thread.\n", .{});
        return error.SkipZigTest;
    };
    defer thread.join();

    const addr = std.Io.net.IpAddress.parse(driver.bound_host, live_port) catch unreachable;
    var stream: std.Io.net.Stream = blk: {
        var attempt: usize = 0;
        while (attempt < 40) : (attempt += 1) {
            if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
            sleepMs(50);
        }
        if (verboseSkip()) std.debug.print("\nSKIPPED: loopback server test could not connect.\n", .{});
        return error.SkipZigTest;
    };
    defer stream.close(io);

    var read_buf: [64 * 1024]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var conn = transport.Connection.init(&stream_reader.interface, &stream_writer.interface);
    const ack = try conn.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = live_endpoint_url,
    });
    try testing.expect(ack.receive_buffer_size >= 8192);

    var channel = try root.SecureChannel.open(&conn, gpa, .{});
    defer channel.close() catch {};

    var session = try root.Session.create(&channel, gpa, .{
        .client_description = .{
            .application_uri = "urn:zig-libs:opcua:loopback-client",
            .product_uri = "urn:zig-libs:opcua",
            .application_name = .{ .locale = "en", .text = "zig-libs opcua loopback client" },
            .application_type = .client,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .endpoint_url = live_endpoint_url,
    });
    defer session.deinit();
    // The server advertised an Anonymous UserTokenPolicy; the client finds it
    // in `server_endpoints` on its own.
    try testing.expect(session.findAnonymousPolicyId() != null);
    try session.activate(null);
    defer session.close(true) catch {};

    // Read: the server's own CurrentTime, and the user variable.
    const current_time = try session.readAttribute(nodestore.n0(nodestore.id.server_status_current_time), services.attribute_id.value);
    defer encoding.freeDataValue(gpa, current_time);
    try testing.expect(current_time.value.?.scalar.date_time >= driver.start_time);

    const answer = try session.readAttribute(answer_node, services.attribute_id.value);
    defer encoding.freeDataValue(gpa, answer);
    try testing.expectEqual(@as(i32, 42), answer.value.?.scalar.int32);

    // Browse from RootFolder down to the user variable.
    var current = nodestore.n0(nodestore.id.root_folder);
    for ([_][]const u8{ "Objects", "the.answer" }) |want| {
        const descriptions = [_]services.BrowseDescription{.{
            .node_id = current,
            .browse_direction = .forward,
            .reference_type_id = nodestore.n0(nodestore.id.hierarchical_references),
            .include_subtypes = true,
            .node_class_mask = 0,
            .result_mask = nodestore.result_mask.all,
        }};
        const response = try session.browse(&descriptions, .{});
        defer services.freeBrowseResponse(gpa, response);
        var found = false;
        for (response.results.?[0].references orelse &.{}) |ref| {
            if (ref.browse_name.name) |name| {
                if (std.mem.eql(u8, name, want)) {
                    // The NodeId is freed with the response; the next
                    // iteration only needs it for the duration of this loop
                    // body, so a borrowed copy would dangle — browse by the
                    // known ids instead.
                    found = true;
                }
            }
        }
        try testing.expect(found);
        current = if (std.mem.eql(u8, want, "Objects")) nodestore.n0(nodestore.id.objects_folder) else answer_node;
    }

    // Write + read back.
    const writes = [_]services.WriteValue{.{
        .node_id = answer_node,
        .attribute_id = services.attribute_id.value,
        .index_range = null,
        .value = .{ .value = .{ .scalar = .{ .int32 = 4242 } } },
    }};
    const write_response = try session.write(&writes);
    defer services.freeWriteResponse(gpa, write_response);
    try testing.expectEqual(services.status.good, write_response.results.?[0]);

    const after = try session.readAttribute(answer_node, services.attribute_id.value);
    defer encoding.freeDataValue(gpa, after);
    try testing.expectEqual(@as(i32, 4242), after.value.?.scalar.int32);

    // Call the method.
    const inputs = [_]encoding.Variant{.{ .scalar = .{ .string = "hello" } }};
    const calls = [_]services.CallMethodRequest{.{
        .object_id = nodestore.n0(nodestore.id.objects_folder),
        .method_id = method_node,
        .input_arguments = &inputs,
    }};
    const call_response = try session.call(&calls);
    defer services.freeCallResponse(gpa, call_response);
    try testing.expectEqual(services.status.good, call_response.results.?[0].status_code);
    try testing.expect(std.mem.startsWith(u8, call_response.results.?[0].output_arguments.?[0].scalar.string.?, "hello"));

    // Subscribe and receive a data change: the client's Publish loop against
    // the server's publish queue, over a real socket.
    var sub = try root.Subscription.create(&session, gpa, .{
        .requested_publishing_interval_ms = 100,
        .requested_max_keep_alive_count = 20,
        .requested_lifetime_count = 200,
    });
    defer sub.deinit();
    const specs = [_]root.Subscription.MonitoredItemSpec{.{
        .node_id = answer_node,
        .client_handle = 11,
        .sampling_interval_ms = 100,
        .queue_size = 10,
    }};
    const created = try sub.createMonitoredItems(&specs, .both);
    defer services.freeCreateMonitoredItemsResponse(gpa, created);
    try testing.expectEqual(services.status.good, created.results.?[0].status_code);

    var saw_change = false;
    var attempt: usize = 0;
    while (attempt < 10 and !saw_change) : (attempt += 1) {
        // Move the value from this side so the change is unambiguous.
        const bump = [_]services.WriteValue{.{
            .node_id = answer_node,
            .attribute_id = services.attribute_id.value,
            .index_range = null,
            .value = .{ .value = .{ .scalar = .{ .int32 = @intCast(5000 + attempt) } } },
        }};
        const bumped = try session.write(&bump);
        services.freeWriteResponse(gpa, bumped);
        sleepMs(150);

        const result = try sub.publish(.{ .timeout_hint_ms = 2_000 });
        defer root.freePublishResult(gpa, result);
        for (result.notifications) |n| {
            switch (n) {
                .data_change => |dcn| {
                    for (dcn.monitored_items orelse &.{}) |mi| {
                        if (mi.client_handle == 11 and mi.value.value != null) saw_change = true;
                    }
                },
                else => {},
            }
        }
    }
    try testing.expect(saw_change);
    try sub.delete();
}

// ── goldens ─────────────────────────────────────────────────────────────────
//
// Provenance is stated per constant. **CAPTURED** = cut verbatim out of a real
// open62541 client's byte stream during the LIVE tests above
// (`OPCUA_CAPTURE_DIR=… zig build test-opcua`, then sliced at the chunk
// boundaries). **SELF-DERIVED** = produced by this module's own encoder in the
// same run and kept as a regression anchor — never presented as third-party
// evidence. Everything here is anonymised: the only address that appears is
// loopback, there are no certificates and no device identities.
//
// Every golden is checked twice: it must decode, and re-encoding the decoded
// value must reproduce the exact bytes.

/// CAPTURED — open62541 1.0.5 (`tutorial_client_firststeps`, from the image)
/// -> this server: the `HEL` that opens every connection. Endpoint URL
/// `opc.tcp://localhost:4840`: loopback only, no real deployment address.
const golden_hello = [_]u8{
    0x48, 0x45, 0x4c, 0x46, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70, 0x63, 0x2e,
    0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
    0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30,
};

/// CAPTURED: the client's `OpenSecureChannel` request at
/// SecurityPolicy#None — an AsymmetricAlgorithmSecurityHeader with a null
/// certificate/thumbprint, the SequenceHeader, and the request body.
const golden_opn_request = [_]u8{
    0x4f, 0x50, 0x4e, 0x46, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2f, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f,
    0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x63, 0x75,
    0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x23, 0x4e,
    0x6f, 0x6e, 0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xbe, 0x01, 0x00,
    0x00, 0x00, 0x83, 0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x27, 0x09, 0x00,
};

/// CAPTURED: `GetEndpoints`, the first MSG a real client sends after the
/// channel opens (it is session-less by design).
const golden_get_endpoints_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x5d, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0xac, 0x01, 0x00, 0x00, 0x3c, 0x88, 0xbc, 0x69, 0x8a, 0x1a,
    0xdd, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
    0x00, 0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c,
    0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34,
    0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// CAPTURED: `CreateSession` — carries the client's ApplicationDescription
/// and a present-but-empty nonce (SecurityMode=None).
const golden_create_session_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0xa6, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x01, 0x00, 0xcd, 0x01, 0x00, 0x00, 0xac, 0x90, 0xbc, 0x69, 0x8a, 0x1a,
    0xdd, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00,
    0x00, 0x75, 0x72, 0x6e, 0x3a, 0x75, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
    0x67, 0x75, 0x72, 0x65, 0x64, 0x3a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x00,
    0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18, 0x00, 0x00, 0x00, 0x6f, 0x70,
    0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61,
    0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x4f, 0x32, 0x41, 0xff, 0xff, 0xff, 0x7f,
};

/// CAPTURED: `ActivateSession` with an **anonymous** identity token; the
/// 32-byte AuthenticationToken in the RequestHeader is the ephemeral session
/// token this server issued during that run (random, long dead — not a
/// credential of anything).
const golden_activate_session_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x8c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x01, 0x00, 0xd3, 0x01, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10,
    0x34, 0x1b, 0x5b, 0x5e, 0x28, 0x69, 0x39, 0x99, 0xd7, 0xe7, 0x22, 0x34,
    0xa3, 0xbc, 0xae, 0x51, 0x01, 0x9c, 0xa2, 0xec, 0x7d, 0x11, 0x2b, 0xb0,
    0x1e, 0xd9, 0x66, 0x6b, 0xfa, 0xf1, 0x9a, 0x5a, 0x97, 0xbc, 0x69, 0x8a,
    0x1a, 0xdd, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0xc0, 0x27, 0x09, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x01, 0x00, 0x41, 0x01, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x00, 0x61, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// CAPTURED: `Read` of Server_ServerStatus_CurrentTime (i=2258), the Value
/// attribute (13), TimestampsToReturn = Both.
const golden_read_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x77, 0x02, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10,
    0x34, 0x1b, 0x5b, 0x5e, 0x28, 0x69, 0x39, 0x99, 0xd7, 0xe7, 0x22, 0x34,
    0xa3, 0xbc, 0xae, 0x51, 0x01, 0x9c, 0xa2, 0xec, 0x7d, 0x11, 0x2b, 0xb0,
    0x1e, 0xd9, 0x66, 0x6b, 0xfa, 0xf1, 0x9a, 0xbe, 0x9c, 0xbc, 0x69, 0x8a,
    0x1a, 0xdd, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0xd2, 0x08, 0x0d, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

/// CAPTURED (from the `client` example): `Browse` of the Objects folder
/// (i=85) with ResultMask = All.
const golden_browse_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x85, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x0f, 0x02, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x7e,
    0xb1, 0x10, 0x2e, 0xe7, 0xef, 0x12, 0x4e, 0xf8, 0xde, 0x6e, 0x8d, 0xa8,
    0x9f, 0x11, 0x6b, 0x68, 0x51, 0x02, 0xdc, 0xf4, 0x92, 0x9b, 0x2d, 0x9a,
    0x02, 0x8d, 0x8a, 0xbc, 0xfe, 0x2b, 0xbf, 0x18, 0x47, 0xa7, 0x7a, 0x8a,
    0x1a, 0xdd, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00,
    0x00,
};

/// CAPTURED (from `client_subscription_loop`): `CreateSubscription`.
const golden_create_subscription_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x74, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x13, 0x03, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x32,
    0xd0, 0x5e, 0x99, 0xf2, 0x80, 0x52, 0xc4, 0x98, 0x77, 0xff, 0x9d, 0x5e,
    0x7f, 0x6e, 0xa9, 0xc1, 0x32, 0xcc, 0x88, 0x8e, 0x45, 0x08, 0xbd, 0xd8,
    0xad, 0x2b, 0x1b, 0x55, 0x88, 0x1e, 0x8e, 0x2a, 0xdc, 0xdd, 0x6a, 0x8a,
    0x1a, 0xdd, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x40, 0x7f, 0x40, 0x10, 0x27, 0x00, 0x00, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
};

/// CAPTURED: `CreateMonitoredItems` for i=2258 with no filter.
const golden_create_monitored_items_request = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x01, 0x00, 0xef, 0x02, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x32,
    0xd0, 0x5e, 0x99, 0xf2, 0x80, 0x52, 0xc4, 0x98, 0x77, 0xff, 0x9d, 0x5e,
    0x7f, 0x6e, 0xa9, 0xc1, 0x32, 0xcc, 0x88, 0x8e, 0x45, 0x08, 0xbd, 0xd8,
    0xad, 0x2b, 0x1b, 0x55, 0x88, 0x1e, 0x8e, 0x4c, 0xe2, 0xdd, 0x6a, 0x8a,
    0x1a, 0xdd, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xd2, 0x08, 0x0d, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x6f, 0x40, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01,
};

/// CAPTURED: a `Publish` request carrying one SubscriptionAcknowledgement —
/// the piggy-backed acknowledgement path (§5.13.5).
const golden_publish_request_with_ack = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x6a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x3a, 0x03, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x32,
    0xd0, 0x5e, 0x99, 0xf2, 0x80, 0x52, 0xc4, 0x98, 0x77, 0xff, 0x9d, 0x5e,
    0x7f, 0x6e, 0xa9, 0xc1, 0x32, 0xcc, 0x88, 0x8e, 0x45, 0x08, 0xbd, 0xd8,
    0xad, 0x2b, 0x1b, 0x55, 0x88, 0x1e, 0x8e, 0x46, 0x97, 0x26, 0x6e, 0x8a,
    0x1a, 0xdd, 0x01, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x60, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
};

/// SELF-DERIVED (this server's encoder): the `ACK` answering the captured
/// Hello at the interop configuration's limits.
const golden_ack = [_]u8{
    0x41, 0x43, 0x4b, 0x46, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x01, 0x00, 0x00,
};

/// SELF-DERIVED: this server's `OpenSecureChannel` response — the issued
/// ChannelSecurityToken and a present-but-empty ServerNonce.
const golden_opn_response = [_]u8{
    0x4f, 0x50, 0x4e, 0x46, 0x87, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x2f, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f,
    0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x63, 0x75,
    0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x23, 0x4e,
    0x6f, 0x6e, 0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x01, 0x2c,
    0x96, 0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2c,
    0x96, 0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01, 0xc0, 0x27, 0x09, 0x00, 0x00,
    0x00, 0x00, 0x00,
};

/// SELF-DERIVED: this server's `GetEndpoints` response — one None endpoint
/// with the Anonymous + UserName token policies. This is the message
/// Wireshark's `opcua` dissector was pointed at (see SPEC.md): it reads
/// EndpointUrl, ApplicationUri and three SecurityPolicyUris out of it.
const golden_get_endpoints_response = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0xe3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0xaf, 0x01, 0x2c, 0x96, 0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f,
    0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30,
    0x21, 0x00, 0x00, 0x00, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69, 0x67, 0x2d,
    0x6c, 0x69, 0x62, 0x73, 0x3a, 0x6f, 0x70, 0x63, 0x75, 0x61, 0x3a, 0x69,
    0x6e, 0x74, 0x65, 0x72, 0x6f, 0x70, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65,
    0x72, 0x12, 0x00, 0x00, 0x00, 0x75, 0x72, 0x6e, 0x3a, 0x7a, 0x69, 0x67,
    0x2d, 0x6c, 0x69, 0x62, 0x73, 0x3a, 0x6f, 0x70, 0x63, 0x75, 0x61, 0x03,
    0x02, 0x00, 0x00, 0x00, 0x65, 0x6e, 0x1d, 0x00, 0x00, 0x00, 0x7a, 0x69,
    0x67, 0x2d, 0x6c, 0x69, 0x62, 0x73, 0x20, 0x6f, 0x70, 0x63, 0x75, 0x61,
    0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6f, 0x70, 0x20, 0x73, 0x65, 0x72,
    0x76, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a,
    0x2f, 0x2f, 0x6f, 0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53,
    0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63,
    0x79, 0x23, 0x4e, 0x6f, 0x6e, 0x65, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x61, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2f,
    0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x70,
    0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
    0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x63, 0x75, 0x72,
    0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x23, 0x4e, 0x6f,
    0x6e, 0x65, 0x08, 0x00, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61,
    0x6d, 0x65, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x2f, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
    0x2f, 0x6f, 0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53, 0x65,
    0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79,
    0x23, 0x4e, 0x6f, 0x6e, 0x65, 0x41, 0x00, 0x00, 0x00, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41,
    0x2d, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x2f, 0x54, 0x72, 0x61,
    0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75, 0x61, 0x74, 0x63, 0x70,
    0x2d, 0x75, 0x61, 0x73, 0x63, 0x2d, 0x75, 0x61, 0x62, 0x69, 0x6e, 0x61,
    0x72, 0x79, 0x00,
};

/// SELF-DERIVED: the `Read` response to the captured request — a DateTime
/// DataValue with both timestamps.
const golden_read_response = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x7a, 0x02, 0x3c, 0xbd, 0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x0d, 0x2c, 0x96,
    0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x96,
    0xbc, 0x69, 0x8a, 0x1a, 0xdd, 0x01, 0xff, 0xff, 0xff, 0xff,
};

/// SELF-DERIVED: a `Publish` response carrying a DataChangeNotification
/// (ClientHandle 1, one DataValue). Wireshark decodes its DateTime to a real
/// wall-clock instant, which is the cross-check that this server's
/// DateTime/notification encoding is right.
const golden_publish_response_data_change = [_]u8{
    0x4d, 0x53, 0x47, 0x46, 0x90, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x3d, 0x03, 0xbb, 0x11, 0x78, 0x6b, 0x8a, 0x1a, 0xdd, 0x01,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xbb, 0x11, 0x78,
    0x6b, 0x8a, 0x1a, 0xdd, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2b,
    0x03, 0x01, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x0f, 0x0d, 0xbb, 0x11, 0x78, 0x6b, 0x8a, 0x1a, 0xdd, 0x01,
    0x00, 0x00, 0x00, 0x00, 0xbb, 0x11, 0x78, 0x6b, 0x8a, 0x1a, 0xdd, 0x01,
    0xbb, 0x11, 0x78, 0x6b, 0x8a, 0x1a, 0xdd, 0x01, 0xff, 0xff, 0xff, 0xff,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

// ── golden round-trip helpers ───────────────────────────────────────────────

/// Split a MSG/CLO chunk into its framing fields and its service body.
const Framed = struct {
    channel_id: u32,
    token_id: u32,
    sequence_number: u32,
    request_id: u32,
    body: []const u8,
};

fn splitSymmetric(golden: []const u8, body_buf: []u8) !Framed {
    var r: std.Io.Reader = .fixed(golden);
    var c = transport.Connection.init(&r, undefined);
    const chunk = try c.recvChunk(body_buf);
    try testing.expectEqual(transport.ChunkType.final, chunk.header.chunk_type);
    var br: std.Io.Reader = .fixed(chunk.body);
    return .{
        .channel_id = try br.takeInt(u32, .little),
        .token_id = try br.takeInt(u32, .little),
        .sequence_number = try br.takeInt(u32, .little),
        .request_id = try br.takeInt(u32, .little),
        .body = br.buffered(),
    };
}

/// Decode a captured MSG chunk's service body and re-encode it inside the same
/// framing, asserting the bytes come back identical.
fn expectMsgRoundTrip(
    gpa: std.mem.Allocator,
    golden: []const u8,
    type_id: encoding.NodeId,
    comptime T: type,
    comptime decodeFn: fn (*encoding.Decoder) encoding.DecodeError!T,
    comptime encodeFn: fn (*encoding.Encoder, T) encoding.EncodeError!void,
    comptime freeFn: fn (std.mem.Allocator, T) void,
) !void {
    var body_buf: [4096]u8 = undefined;
    const framed = try splitSymmetric(golden, &body_buf);

    var br: std.Io.Reader = .fixed(framed.body);
    var d = encoding.Decoder.init(&br, gpa);
    const decoded_type = try d.decodeNodeId();
    try testing.expect(services.nodeIdEql(decoded_type, type_id));
    const value = try decodeFn(&d);
    defer freeFn(gpa, value);

    var out: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var payload: [8192]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&payload);
    var e = encoding.Encoder.init(&pw);
    try pw.writeInt(u32, framed.channel_id, .little);
    try pw.writeInt(u32, framed.token_id, .little);
    try pw.writeInt(u32, framed.sequence_number, .little);
    try pw.writeInt(u32, framed.request_id, .little);
    try e.encodeNodeId(type_id);
    try encodeFn(&e, value);
    var wc = transport.Connection.init(undefined, &w);
    try wc.sendChunk(.{
        .message_type = .message,
        .chunk_type = .final,
        .message_size = 8 + @as(u32, @intCast(pw.buffered().len)),
    }, pw.buffered());
    try testing.expectEqualSlices(u8, golden, w.buffered());
}

/// The OPN variant: the chunk carries an AsymmetricAlgorithmSecurityHeader
/// instead of a TokenId.
fn expectOpnRoundTrip(
    gpa: std.mem.Allocator,
    golden: []const u8,
    type_id: encoding.NodeId,
    comptime T: type,
    comptime decodeFn: fn (*encoding.Decoder) encoding.DecodeError!T,
    comptime encodeFn: fn (*encoding.Encoder, T) encoding.EncodeError!void,
    comptime freeFn: fn (std.mem.Allocator, T) void,
) !void {
    var body_buf: [4096]u8 = undefined;
    var r: std.Io.Reader = .fixed(golden);
    var c = transport.Connection.init(&r, undefined);
    const chunk = try c.recvChunk(&body_buf);
    try testing.expectEqual(transport.MessageType.open_secure_channel, chunk.header.message_type);

    var br: std.Io.Reader = .fixed(chunk.body);
    const channel_id = try br.takeInt(u32, .little);
    var hd = encoding.Decoder.init(&br, gpa);
    const policy = try hd.decodeString();
    defer if (policy) |p| gpa.free(p);
    try testing.expectEqualStrings(services.security_policy_none_uri, policy.?);
    const sender_cert = try hd.decodeByteString();
    defer if (sender_cert) |v| gpa.free(v);
    const thumbprint = try hd.decodeByteString();
    defer if (thumbprint) |v| gpa.free(v);
    const sequence_number = try br.takeInt(u32, .little);
    const request_id = try br.takeInt(u32, .little);

    var d = encoding.Decoder.init(&br, gpa);
    const decoded_type = try d.decodeNodeId();
    try testing.expect(services.nodeIdEql(decoded_type, type_id));
    const value = try decodeFn(&d);
    defer freeFn(gpa, value);

    var out: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var payload: [4096]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&payload);
    var e = encoding.Encoder.init(&pw);
    try pw.writeInt(u32, channel_id, .little);
    try e.encodeString(policy);
    try e.encodeByteString(sender_cert);
    try e.encodeByteString(thumbprint);
    try pw.writeInt(u32, sequence_number, .little);
    try pw.writeInt(u32, request_id, .little);
    try e.encodeNodeId(type_id);
    try encodeFn(&e, value);
    var wc = transport.Connection.init(undefined, &w);
    try wc.sendChunk(.{
        .message_type = .open_secure_channel,
        .chunk_type = .final,
        .message_size = 8 + @as(u32, @intCast(pw.buffered().len)),
    }, pw.buffered());
    try testing.expectEqualSlices(u8, golden, w.buffered());
}

fn freeNothing(a: std.mem.Allocator, v: anytype) void {
    _ = a;
    _ = v;
}

test "golden (captured): the open62541 Hello parses to the limits it announces and re-encodes" {
    var r: std.Io.Reader = .fixed(&golden_hello);
    var c = transport.Connection.init(&r, undefined);
    var body_buf: [256]u8 = undefined;
    const chunk = try c.recvChunk(&body_buf);
    try testing.expectEqual(transport.MessageType.hello, chunk.header.message_type);

    var br: std.Io.Reader = .fixed(chunk.body);
    const protocol_version = try br.takeInt(u32, .little);
    const receive_buffer = try br.takeInt(u32, .little);
    const send_buffer = try br.takeInt(u32, .little);
    const max_message = try br.takeInt(u32, .little);
    const max_chunks = try br.takeInt(u32, .little);
    const url_len = try br.takeInt(i32, .little);
    const url = try br.take(@intCast(url_len));
    try testing.expectEqual(@as(u32, 0), protocol_version);
    try testing.expectEqual(@as(u32, 65535), receive_buffer);
    try testing.expectEqual(@as(u32, 65535), send_buffer);
    try testing.expectEqualStrings("opc.tcp://localhost:4840", url);

    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var body: [256]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&body);
    try bw.writeInt(u32, protocol_version, .little);
    try bw.writeInt(u32, receive_buffer, .little);
    try bw.writeInt(u32, send_buffer, .little);
    try bw.writeInt(u32, max_message, .little);
    try bw.writeInt(u32, max_chunks, .little);
    try bw.writeInt(i32, url_len, .little);
    try bw.writeAll(url);
    var wc = transport.Connection.init(undefined, &w);
    try wc.sendChunk(.{
        .message_type = .hello,
        .chunk_type = .final,
        .message_size = 8 + @as(u32, @intCast(bw.buffered().len)),
    }, bw.buffered());
    try testing.expectEqualSlices(u8, &golden_hello, w.buffered());
}

test "golden (self-derived): this server answers the captured Hello with the ACK bytes" {
    const gpa = testing.allocator;
    var store = nodestore.NodeStore.init(gpa);
    defer store.deinit();
    try store.addStandardNodes(.{});
    var prng = std.Random.DefaultPrng.init(1);
    var srv = server.Server.init(gpa, &store, .{ .endpoints = &Driver.endpoints }, prng.random());
    defer srv.deinit();

    var recv_buf: [128 * 1024]u8 = undefined;
    var msg_buf: [64 * 1024]u8 = undefined;
    var conn = try server.Connection.init(&srv, &recv_buf, &msg_buf);
    var out = std.Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    try conn.feed(&golden_hello, &out.writer, 0);
    try testing.expectEqualSlices(u8, &golden_ack, out.written());
    // The negotiated limits are the minimum of the two proposals.
    try testing.expectEqual(@as(u32, 65535), conn.limits.receive_buffer_size);
    try testing.expectEqual(@as(u32, 65535), conn.limits.send_buffer_size);
}

test "golden (captured): OpenSecureChannel request round-trips byte-identically" {
    try expectOpnRoundTrip(
        testing.allocator,
        &golden_opn_request,
        services.type_id.open_secure_channel_request,
        services.OpenSecureChannelRequest,
        services.decodeOpenSecureChannelRequest,
        services.encodeOpenSecureChannelRequest,
        services.freeOpenSecureChannelRequest,
    );
}

test "golden (self-derived): OpenSecureChannel response round-trips byte-identically" {
    try expectOpnRoundTrip(
        testing.allocator,
        &golden_opn_response,
        services.type_id.open_secure_channel_response,
        services.OpenSecureChannelResponse,
        services.decodeOpenSecureChannelResponse,
        services.encodeOpenSecureChannelResponse,
        services.freeOpenSecureChannelResponse,
    );
}

test "golden (captured): GetEndpoints / CreateSession / ActivateSession requests round-trip" {
    const gpa = testing.allocator;
    try expectMsgRoundTrip(gpa, &golden_get_endpoints_request, services.type_id.get_endpoints_request, services.GetEndpointsRequest, services.decodeGetEndpointsRequest, services.encodeGetEndpointsRequest, services.freeGetEndpointsRequest);
    try expectMsgRoundTrip(gpa, &golden_create_session_request, services.type_id.create_session_request, services.CreateSessionRequest, services.decodeCreateSessionRequest, services.encodeCreateSessionRequest, services.freeCreateSessionRequest);
    try expectMsgRoundTrip(gpa, &golden_activate_session_request, services.type_id.activate_session_request, services.ActivateSessionRequest, services.decodeActivateSessionRequest, services.encodeActivateSessionRequest, services.freeActivateSessionRequest);
}

test "golden (captured): Read / Browse requests round-trip, and say what they asked for" {
    const gpa = testing.allocator;
    try expectMsgRoundTrip(gpa, &golden_read_request, services.type_id.read_request, services.ReadRequest, services.decodeReadRequest, services.encodeReadRequest, services.freeReadRequest);
    try expectMsgRoundTrip(gpa, &golden_browse_request, services.type_id.browse_request, services.BrowseRequest, services.decodeBrowseRequest, services.encodeBrowseRequest, services.freeBrowseRequest);

    // …and the decoded contents are the ones the examples are documented to
    // ask for: CurrentTime's Value, and the Objects folder's references.
    var body_buf: [4096]u8 = undefined;
    {
        const framed = try splitSymmetric(&golden_read_request, &body_buf);
        var br: std.Io.Reader = .fixed(framed.body);
        var d = encoding.Decoder.init(&br, gpa);
        _ = try d.decodeNodeId();
        const request = try services.decodeReadRequest(&d);
        defer services.freeReadRequest(gpa, request);
        try testing.expectEqual(@as(usize, 1), request.nodes_to_read.?.len);
        try testing.expect(services.nodeIdEql(request.nodes_to_read.?[0].node_id, nodestore.n0(nodestore.id.server_status_current_time)));
        try testing.expectEqual(services.attribute_id.value, request.nodes_to_read.?[0].attribute_id);
    }
    {
        const framed = try splitSymmetric(&golden_browse_request, &body_buf);
        var br: std.Io.Reader = .fixed(framed.body);
        var d = encoding.Decoder.init(&br, gpa);
        _ = try d.decodeNodeId();
        const request = try services.decodeBrowseRequest(&d);
        defer services.freeBrowseRequest(gpa, request);
        try testing.expect(services.nodeIdEql(request.nodes_to_browse.?[0].node_id, nodestore.n0(nodestore.id.objects_folder)));
        try testing.expectEqual(nodestore.result_mask.all, request.nodes_to_browse.?[0].result_mask);
    }
}

test "golden (captured): subscription requests round-trip, ack included" {
    const gpa = testing.allocator;
    try expectMsgRoundTrip(gpa, &golden_create_subscription_request, services.type_id.create_subscription_request, services.CreateSubscriptionRequest, services.decodeCreateSubscriptionRequest, services.encodeCreateSubscriptionRequest, services.freeCreateSubscriptionRequest);
    try expectMsgRoundTrip(gpa, &golden_create_monitored_items_request, services.type_id.create_monitored_items_request, services.CreateMonitoredItemsRequest, services.decodeCreateMonitoredItemsRequest, services.encodeCreateMonitoredItemsRequest, services.freeCreateMonitoredItemsRequest);
    try expectMsgRoundTrip(gpa, &golden_publish_request_with_ack, services.type_id.publish_request, services.PublishRequest, services.decodePublishRequest, services.encodePublishRequest, services.freePublishRequest);

    var body_buf: [4096]u8 = undefined;
    const framed = try splitSymmetric(&golden_publish_request_with_ack, &body_buf);
    var br: std.Io.Reader = .fixed(framed.body);
    var d = encoding.Decoder.init(&br, gpa);
    _ = try d.decodeNodeId();
    const request = try services.decodePublishRequest(&d);
    defer services.freePublishRequest(gpa, request);
    const acks = request.subscription_acknowledgements.?;
    try testing.expectEqual(@as(usize, 1), acks.len);
    try testing.expectEqual(@as(u32, 1), acks[0].subscription_id);
    try testing.expect(acks[0].sequence_number > 0);
}

test "golden (self-derived): the server's GetEndpoints / Read / Publish responses round-trip" {
    const gpa = testing.allocator;
    try expectMsgRoundTrip(gpa, &golden_get_endpoints_response, services.type_id.get_endpoints_response, services.GetEndpointsResponse, services.decodeGetEndpointsResponse, services.encodeGetEndpointsResponse, services.freeGetEndpointsResponse);
    try expectMsgRoundTrip(gpa, &golden_read_response, services.type_id.read_response, services.ReadResponse, services.decodeReadResponse, services.encodeReadResponse, services.freeReadResponse);
    try expectMsgRoundTrip(gpa, &golden_publish_response_data_change, services.type_id.publish_response, services.PublishResponse, services.decodePublishResponse, services.encodePublishResponse, services.freePublishResponse);

    var body_buf: [4096]u8 = undefined;
    // The endpoint this server advertised is the one a client can use.
    {
        const framed = try splitSymmetric(&golden_get_endpoints_response, &body_buf);
        var br: std.Io.Reader = .fixed(framed.body);
        var d = encoding.Decoder.init(&br, gpa);
        _ = try d.decodeNodeId();
        const response = try services.decodeGetEndpointsResponse(&d);
        defer services.freeGetEndpointsResponse(gpa, response);
        const ep = response.endpoints.?[0];
        try testing.expectEqualStrings("opc.tcp://localhost:4840", ep.endpoint_url.?);
        try testing.expectEqual(services.MessageSecurityMode.none, ep.security_mode);
        try testing.expectEqualStrings(services.security_policy_none_uri, ep.security_policy_uri.?);
        try testing.expectEqual(@as(usize, 2), ep.user_identity_tokens.?.len);
        try testing.expectEqualStrings(server.transport_profile_uri, ep.transport_profile_uri.?);
    }
    // The Publish response carries one DataChangeNotification for client
    // handle 1 — the same values Wireshark's dissector reads out of it.
    {
        const framed = try splitSymmetric(&golden_publish_response_data_change, &body_buf);
        var br: std.Io.Reader = .fixed(framed.body);
        var d = encoding.Decoder.init(&br, gpa);
        _ = try d.decodeNodeId();
        const response = try services.decodePublishResponse(&d);
        defer services.freePublishResponse(gpa, response);
        try testing.expectEqual(@as(u32, 1), response.subscription_id);
        const data = response.notification_message.notification_data.?;
        try testing.expectEqual(@as(usize, 1), data.len);
        try testing.expect(services.nodeIdEql(data[0].type_id, services.type_id.data_change_notification));
        var nr: std.Io.Reader = .fixed(data[0].body);
        var nd = encoding.Decoder.init(&nr, gpa);
        const dcn = try services.decodeDataChangeNotification(&nd);
        defer services.freeDataChangeNotification(gpa, dcn);
        try testing.expectEqual(@as(u32, 1), dcn.monitored_items.?[0].client_handle);
        try testing.expect(dcn.monitored_items.?[0].value.value.?.scalar.date_time > 0);
        try testing.expect(dcn.monitored_items.?[0].value.source_timestamp != null);
        try testing.expect(dcn.monitored_items.?[0].value.server_timestamp != null);
    }
}

// ── LIVE Basic256Sha256: a real third-party client against our server ───────
//
// The oracle here is **Python `asyncua`** (LGPL-3.0), used purely as a black
// box: no asyncua source is read, built or linked — the test runs a stock
// interpreter with the driver script below and asserts on its *stdout*. It is
// the natural second opinion to open62541: a wholly independent stack, written
// in a different language, with its own reading of OPC 10000-6 §6.7.
//
// The script generates its own throwaway 2048-bit RSA key pair and
// self-signed certificate (via `cryptography`, in a temp dir it makes and
// owns) — **no certificate or private key ships in this repository**, and the
// server's own key pair is likewise generated in-process by `Driver.initWith`.
//
// Skips loudly when the interpreter or `asyncua` is unavailable. Set
// `OPCUA_PYTHON` to point at a specific interpreter (e.g. a virtualenv).

const asyncua_script =
    \\import asyncio, datetime, os, sys, tempfile
    \\from asyncua import Client, ua
    \\from cryptography import x509
    \\from cryptography.x509.oid import NameOID
    \\from cryptography.hazmat.primitives import hashes, serialization
    \\from cryptography.hazmat.primitives.asymmetric import rsa as crsa
    \\
    \\URL = "opc.tcp://localhost:4841"
    \\ANSWER = ua.NodeId("the.answer", 1)
    \\METHOD = ua.NodeId(62541, 1)
    \\
    \\def make_cert(d):
    \\    key = crsa.generate_private_key(public_exponent=65537, key_size=2048)
    \\    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "asyncua interop client")])
    \\    now = datetime.datetime.now(datetime.timezone.utc)
    \\    cert = (x509.CertificateBuilder()
    \\            .subject_name(name).issuer_name(name)
    \\            .public_key(key.public_key())
    \\            .serial_number(x509.random_serial_number())
    \\            .not_valid_before(now - datetime.timedelta(days=1))
    \\            .not_valid_after(now + datetime.timedelta(days=365))
    \\            .add_extension(x509.SubjectAlternativeName(
    \\                [x509.UniformResourceIdentifier("urn:zig-libs:opcua:asyncua-client")]), critical=False)
    \\            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    \\            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
    \\                                         key_encipherment=True, data_encipherment=True,
    \\                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
    \\                                         encipher_only=False, decipher_only=False), critical=True)
    \\            .sign(key, hashes.SHA256()))
    \\    cp = os.path.join(d, "client.der")
    \\    kp = os.path.join(d, "client.pem")
    \\    with open(cp, "wb") as f:
    \\        f.write(cert.public_bytes(serialization.Encoding.DER))
    \\    with open(kp, "wb") as f:
    \\        f.write(key.private_bytes(serialization.Encoding.PEM,
    \\                                  serialization.PrivateFormat.PKCS8,
    \\                                  serialization.NoEncryption()))
    \\    return cp, kp
    \\
    \\class Handler:
    \\    def __init__(self):
    \\        self.count = 0
    \\    def datachange_notification(self, node, val, data):
    \\        self.count += 1
    \\
    \\async def secure_client(cp, kp, mode, user=None, password=None, timeout_ms=None):
    \\    c = Client(url=URL)
    \\    if timeout_ms is not None:
    \\        c.secure_channel_timeout = timeout_ms
    \\    await c.set_security_string("Basic256Sha256,%s,%s,%s" % (mode, cp, kp))
    \\    if user is not None:
    \\        c.set_user(user)
    \\        c.set_password(password)
    \\    return c
    \\
    \\async def main():
    \\    d = tempfile.mkdtemp(prefix="ziglibs-opcua-")
    \\    cp, kp = make_cert(d)
    \\
    \\    eps = await Client(url=URL).connect_and_get_server_endpoints()
    \\    modes = sorted({"%s|%s" % (e.SecurityPolicyUri.rsplit("#", 1)[-1], e.SecurityMode.name) for e in eps})
    \\    print("ZIGLIBS-OK-ENDPOINTS", len(eps), ",".join(modes), flush=True)
    \\    for e in eps:
    \\        if e.SecurityMode != ua.MessageSecurityMode.None_:
    \\            assert e.ServerCertificate, "secure endpoint without a ServerCertificate"
    \\
    \\    # ---- SignAndEncrypt, anonymous: browse / read / write / call / subscribe
    \\    c = await secure_client(cp, kp, "SignAndEncrypt")
    \\    async with c:
    \\        print("ZIGLIBS-OK-CONNECT SignAndEncrypt", flush=True)
    \\        children = await c.nodes.objects.get_children()
    \\        names = [ (await ch.read_browse_name()).Name for ch in children ]
    \\        assert "the.answer" in names, names
    \\        print("ZIGLIBS-OK-BROWSE", len(children), flush=True)
    \\
    \\        node = c.get_node(ANSWER)
    \\        v = await node.read_value()
    \\        print("ZIGLIBS-OK-READ", v, flush=True)
    \\
    \\        await node.write_value(ua.DataValue(ua.Variant(31337, ua.VariantType.Int32)))
    \\        back = await node.read_value()
    \\        assert back == 31337, back
    \\        print("ZIGLIBS-OK-WRITE", back, flush=True)
    \\
    \\        out = await c.nodes.objects.call_method(METHOD, ua.Variant("ping", ua.VariantType.String))
    \\        print("ZIGLIBS-OK-CALL", out, flush=True)
    \\
    \\        h = Handler()
    \\        sub = await c.create_subscription(200, h)
    \\        await sub.subscribe_data_change(node)
    \\        await asyncio.sleep(2.0)
    \\        await sub.delete()
    \\        assert h.count >= 1, h.count
    \\        print("ZIGLIBS-OK-SUBSCRIPTION", h.count, flush=True)
    \\
    \\    # ---- Sign only, with a Basic256Sha256-encrypted UserNameIdentityToken
    \\    c = await secure_client(cp, kp, "Sign", user="user1", password="password")
    \\    async with c:
    \\        v = await c.get_node(ANSWER).read_value()
    \\        print("ZIGLIBS-OK-SIGN-USERNAME", v, flush=True)
    \\
    \\    # ---- SecurityToken renewal: a 10 s channel lifetime held for ~30 s makes
    \\    #      asyncua renew at least twice while requests keep flowing.
    \\    #
    \\    #      The margin is deliberately wide. It was a 4 s lifetime held for
    \\    #      ~10 s until 2026-08-14, which is a real property proved on an idle
    \\    #      machine and a coin flip on a busy one: inside a full 215-module
    \\    #      lane the token expired before the renewal was served and the
    \\    #      server answered BadSecureChannelTokenUnknown, while the same test
    \\    #      passed on its own in every optimize mode. A live test that fails
    \\    #      under load teaches people to re-run the gate, which costs more
    \\    #      than the seconds this widening spends.
    \\    c = await secure_client(cp, kp, "SignAndEncrypt", timeout_ms=10000)
    \\    async with c:
    \\        node = c.get_node(ANSWER)
    \\        reads = 0
    \\        for _ in range(30):
    \\            await node.read_value()
    \\            reads += 1
    \\            await asyncio.sleep(1.0)
    \\        print("ZIGLIBS-OK-RENEWAL", reads, flush=True)
    \\
    \\    print("ZIGLIBS-ALL-DONE", flush=True)
    \\
    \\asyncio.run(main())
;

/// Spawn `argv` and collect its output. `runPodman`'s generalisation — the
/// Python driver is not a container, but the plumbing is the same.
fn runProcess(gpa: std.mem.Allocator, io: std.Io, argv: []const []const u8) !PodmanResult {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return error.SkipZigTest;

    var out_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    const stdout = try stdout_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stdout);

    var err_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stderr);

    const term = try child.wait(io);
    return .{
        .exit_code = switch (term) {
            .exited => |code| code,
            else => null,
        },
        .stdout = stdout,
        .stderr = stderr,
    };
}

/// The interpreter to drive `asyncua` with: `$OPCUA_PYTHON` if set (point it
/// at a virtualenv), otherwise whatever `python3` resolves to.
fn pythonInterpreter() []const u8 {
    return std.process.Environ.getPosix(std.testing.environ, "OPCUA_PYTHON") orelse "python3";
}

test "LIVE asyncua -> our server: Basic256Sha256 SignAndEncrypt browse/read/write/call/subscribe, Sign + encrypted username, token renewal" {
    const gpa = testing.allocator;
    if (builtin.os.tag != .linux) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE asyncua interop needs Linux.\n", .{});
        return error.SkipZigTest;
    }
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const python = pythonInterpreter();
    {
        var probe = runProcess(gpa, io, &.{ python, "-c", "import asyncua, cryptography" }) catch {
            if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE asyncua interop: no usable `{s}` (set OPCUA_PYTHON).\n", .{python});
            return error.SkipZigTest;
        };
        defer probe.deinit(gpa);
        if (probe.exit_code != 0) {
            if (verboseSkip()) std.debug.print(
                "\nSKIPPED: LIVE asyncua interop: `{s}` lacks the `asyncua`/`cryptography` packages (set OPCUA_PYTHON to a venv that has them).\n",
                .{python},
            );
            return error.SkipZigTest;
        }
    }

    var driver: Driver = undefined;
    driver.initWith(gpa, io, .{
        .secure = true,
        .port = live_secure_port,
        .endpoint_url = live_secure_endpoint_url,
    }) catch |err| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE asyncua interop cannot bind loopback:{d} ({t}).\n", .{ live_secure_port, err });
        return error.SkipZigTest;
    };
    defer driver.deinit();
    // A short SecurityToken floor so the renewal leg of the script actually
    // forces renewals inside a test-sized window (the product default is 60 s).
    driver.srv.config.security.?.min_token_lifetime_ms = 2_000;

    var ctx: LoopbackCtx = .{ .driver = &driver };
    const thread = std.Thread.spawn(.{}, secureServeThread, .{&ctx}) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE asyncua interop cannot spawn a thread.\n", .{});
        return error.SkipZigTest;
    };

    var result = runProcess(gpa, io, &.{ python, "-c", asyncua_script }) catch |err| {
        ctx.done.store(true, .release);
        thread.join();
        return err;
    };
    defer result.deinit(gpa);
    thread.join();
    driver.dumpCapture("asyncua-basic256sha256");

    if (driver.connections == 0) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE asyncua interop: nothing ever connected to loopback:{d} (port held by another process?).\nstderr: {s}\n",
            .{ live_secure_port, result.stderr },
        );
        return error.SkipZigTest;
    }

    const logs = result.stdout;
    const expectations = [_][]const u8{
        "ZIGLIBS-OK-ENDPOINTS 3 Basic256Sha256|Sign,Basic256Sha256|SignAndEncrypt,None|None_",
        "ZIGLIBS-OK-CONNECT SignAndEncrypt", // the asymmetric handshake + key derivation agreed
        "ZIGLIBS-OK-BROWSE", // Browse over signed+encrypted chunks
        "ZIGLIBS-OK-READ", // Read
        "ZIGLIBS-OK-WRITE 31337", // Write, read back through the same channel
        "ZIGLIBS-OK-CALL", // Call
        "ZIGLIBS-OK-SUBSCRIPTION", // CreateSubscription + Publish
        "ZIGLIBS-OK-SIGN-USERNAME", // Sign mode + RSA-OAEP-encrypted UserNameIdentityToken
        "ZIGLIBS-OK-RENEWAL 30", // 30 reads across ~30 s with a 10 s token: at least two renewals happened mid-stream
        "ZIGLIBS-ALL-DONE",
    };
    for (expectations) |needle| {
        if (std.mem.indexOf(u8, logs, needle) == null) {
            std.debug.print("\nasyncua driver output missing \"{s}\":\nstdout:\n{s}\nstderr:\n{s}\n", .{ needle, logs, result.stderr });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(@as(?u8, 0), result.exit_code);
    // Four separate connections: endpoint discovery, SignAndEncrypt, Sign,
    // and the renewal run.
    try testing.expect(driver.connections >= 4);
}

fn secureServeThread(ctx: *LoopbackCtx) void {
    // `vary_value = false`: the write/read-back assertion in the driver script
    // would race a server that keeps bumping the same node.
    ctx.driver.serve(.{ .deadline_ms = 120_000, .idle_stop_ms = 3_000, .vary_value = false }) catch {};
    ctx.done.store(true, .release);
}

// ── LIVE Basic256Sha256: open62541's stock encrypted client ─────────────────

/// Where the openssl-generated test key pair for the open62541 client is
/// staged so the container can bind-mount it. **Test material only**: a
/// throwaway 2048-bit key generated per run and deleted afterwards; no
/// certificate or private key is stored in this repository.
const o62_pki_dir = "/tmp/opcua-zig-libs-o62-encryption";

/// Minimal openssl config giving the generated certificate the shape an OPC UA
/// application certificate needs (OPC 10000-6 §6.2.3: an `ApplicationUri` in
/// the `subjectAltName`, plus the key usages the profile requires).
const o62_openssl_config =
    \\[req]
    \\distinguished_name = dn
    \\prompt = no
    \\[dn]
    \\CN = zig-libs opcua interop peer
    \\[v3]
    \\basicConstraints = CA:FALSE
    \\keyUsage = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
    \\extendedKeyUsage = clientAuth
    \\subjectAltName = URI:urn:open62541.client.application,DNS:localhost
    \\
;

/// Generate a throwaway RSA-2048 key pair + self-signed certificate in DER
/// with `openssl` (a black box — open62541's mbedtls build wants a DER
/// PKCS#1 private key, which this module's `rsa` has no encoder for).
/// Returns `false` if openssl is unavailable or unhappy, so the caller skips.
fn makeO62ClientPki(gpa: std.mem.Allocator, io: std.Io) bool {
    std.Io.Dir.cwd().createDirPath(io, o62_pki_dir) catch return false;
    std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = o62_pki_dir ++ "/openssl.cnf",
        .data = o62_openssl_config,
    }) catch return false;

    const steps = [_][]const []const u8{
        &.{
            "openssl",     "req",
            "-x509",       "-newkey",
            "rsa:2048",    "-nodes",
            "-keyout",     o62_pki_dir ++ "/key.pem",
            "-out",        o62_pki_dir ++ "/cert.pem",
            "-days",       "3650",
            "-config",     o62_pki_dir ++ "/openssl.cnf",
            "-extensions", "v3",
        },
        &.{ "openssl", "x509", "-in", o62_pki_dir ++ "/cert.pem", "-outform", "der", "-out", o62_pki_dir ++ "/client_cert.der" },
        &.{ "openssl", "rsa", "-in", o62_pki_dir ++ "/key.pem", "-outform", "der", "-out", o62_pki_dir ++ "/client_key.der" },
    };
    for (steps) |argv| {
        var result = runProcess(gpa, io, argv) catch return false;
        defer result.deinit(gpa);
        if (result.exit_code != 0) return false;
    }
    return true;
}

fn removeO62ClientPki(io: std.Io) void {
    for ([_][]const u8{ "openssl.cnf", "key.pem", "cert.pem", "client_cert.der", "client_key.der" }) |name| {
        var buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ o62_pki_dir, name }) catch continue;
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
    }
    std.Io.Dir.cwd().deleteDir(io, o62_pki_dir) catch {};
}

test "LIVE open62541 client_encryption -> our server: picks the Basic256Sha256 SignAndEncrypt endpoint out of GetEndpoints" {
    const gpa = testing.allocator;
    if (builtin.os.tag != .linux) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE open62541 encryption interop needs Linux (podman --network host).\n", .{});
        return error.SkipZigTest;
    }
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const name = "opcua-zig-libs-server-encryption";
    stopContainer(gpa, io, name); // leftover cleanup from a crashed run

    if (!makeO62ClientPki(gpa, io)) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE open62541 encryption interop needs `openssl` to stage a throwaway client key pair.\n", .{});
        removeO62ClientPki(io);
        return error.SkipZigTest;
    }
    defer removeO62ClientPki(io);

    var driver: Driver = undefined;
    driver.initWith(gpa, io, .{
        .secure = true,
        .port = live_secure_port,
        .endpoint_url = live_secure_endpoint_url,
    }) catch |err| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE open62541 encryption interop cannot bind loopback:{d} ({t}).\n", .{ live_secure_port, err });
        return error.SkipZigTest;
    };
    defer driver.deinit();

    var run_result = runPodman(gpa, io, &.{
        "run",                                                 "-d",
        "--network",                                           "host",
        "--name",                                              name,
        "-v",                                                  o62_pki_dir ++ ":/certs:Z",
        "--pull=never",                                        image,
        "/opt/open62541/build/bin/examples/client_encryption", live_secure_endpoint_url,
        "/certs/client_cert.der",                              "/certs/client_key.der",
    }) catch |err| switch (err) {
        error.SkipZigTest => {
            if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE open62541 encryption interop: `podman` is not available here.\n", .{});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer run_result.deinit(gpa);
    if (run_result.exit_code != 0) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE open62541 encryption interop: `podman run` failed (image not pulled / podman unusable).\nstderr: {s}\n",
            .{run_result.stderr},
        );
        return error.SkipZigTest;
    }
    defer stopContainer(gpa, io, name);

    try driver.serve(.{ .deadline_ms = 40_000, .idle_stop_ms = 2_000, .vary_value = false });
    driver.dumpCapture("open62541-client_encryption");

    if (driver.connections == 0) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE open62541 encryption interop: `client_encryption` never connected to loopback:{d}.\n",
            .{live_secure_port},
        );
        return error.SkipZigTest;
    }

    const logs = try runPodman(gpa, io, &.{ "logs", name });
    defer gpa.free(logs.stdout);
    defer gpa.free(logs.stderr);
    // open62541 logs to stderr; take whichever stream carried the text.
    const text = if (logs.stderr.len > logs.stdout.len) logs.stderr else logs.stdout;

    // The client discovers our endpoints over an unsecured channel, rejects
    // the ones whose SecurityMode does not match what it wants, and selects
    // ours — its own words, which is the assertion.
    const expectations = [_][]const u8{
        "Opened SecureChannel with SecurityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
        "SecurityMode SignAndEncrypt",
    };
    for (expectations) |needle| {
        if (std.mem.indexOf(u8, text, needle) == null) {
            std.debug.print("\nclient_encryption output missing \"{s}\":\n{s}\n", .{ needle, text });
            return error.TestUnexpectedResult;
        }
    }
    // It connects twice: once at #None to read GetEndpoints, then again on
    // the endpoint it picked.
    try testing.expect(driver.connections >= 2);
}

// ── Basic256Sha256 goldens ─────────────────────────────────────────────────
//
// **SELF-DERIVED**, all of them: there is no published OPC UA test vector for
// a secured chunk, and a *captured* one would have to embed a real peer's
// certificate — which this repository does not carry. What makes them worth
// freezing anyway is that every input is fixed and every output is
// deterministic, so the constants below pin the exact bytes this module puts
// on the wire across the whole stack underneath them (`rsa.generate`,
// `rsa.selfSignedCert`, RSA-OAEP, RSA-PKCS1v1.5, P-SHA256, AES-256-CBC,
// HMAC-SHA256 and the padding arithmetic). A change anywhere in that stack
// that alters a single byte fails here rather than silently at a customer's
// server. Each one is checked in both directions: it must be *reproduced* by
// the encoder and *opened* by the decoder back to the exact input.
//
// The third-party cross-check that these bytes are also *correct* — not just
// stable — is the live interop above: open62541 and asyncua both speak this
// framing back to us.

/// The nonce pair every symmetric golden derives its keys from. Fixed
/// constants, not secrets.
const golden_client_nonce = [_]u8{0x11} ** 32;
const golden_server_nonce = [_]u8{0x22} ** 32;

/// Plaintext MSG body behind both symmetric goldens: SecureChannelId 42,
/// TokenId 7, SequenceNumber 51, RequestId 51, then 24 bytes of payload.
const golden_sym_body_hex =
    "2a0000000700000033000000330000007a69672d6c696273206f7063756120676f6c64656e212121";

/// SELF-DERIVED. One `SecurityMode=Sign` MSG chunk, server→client:
/// MessageHeader + body + HMAC-SHA256 signature, no padding, no encryption.
const golden_sym_sign_hex =
    "4d534746500000002a0000000700000033000000330000007a69672d6c696273206f7063756120676f6c" ++
    "64656e2121216abfd9d25bcdcf49131b6522dd9967a8841ac419e1abb518c91f90560519eebb";

/// SELF-DERIVED. The same body at `SecurityMode=SignAndEncrypt`: the region
/// from the SequenceHeader on is padded to whole AES blocks, signed, then
/// AES-256-CBC encrypted — 96 bytes against Sign's 80, the 16 extra being one
/// full block of padding footer.
const golden_sym_sign_and_encrypt_hex =
    "4d534746600000002a00000007000000b613b3590329a8422241fafe38c59f87c0887e22bcc9e2e10745" ++
    "a225102dbc37b960935b272a350c5b18cf295ea3534f865b1783f324276ac867c078e35a259d43a98dad" ++
    "6fd3046300d4b8d62d2086ea";

test "golden (self-derived): symmetric MSG chunks at Sign and SignAndEncrypt" {
    const gpa = testing.allocator;
    const keys = security.deriveKeys(&golden_client_nonce, &golden_server_nonce, .basic256sha256);

    var body_buf: [64]u8 = undefined;
    const body = try std.fmt.hexToBytes(&body_buf, golden_sym_body_hex);

    const cases = [_]struct { mode: services.MessageSecurityMode, hex: []const u8 }{
        .{ .mode = .sign, .hex = golden_sym_sign_hex },
        .{ .mode = .sign_and_encrypt, .hex = golden_sym_sign_and_encrypt_hex },
    };
    for (cases) |c| {
        var expected_buf: [256]u8 = undefined;
        const expected = try std.fmt.hexToBytes(&expected_buf, c.hex);

        // Re-encode: the module must still produce exactly these bytes.
        const produced = try security.symmetricSignAndEncrypt(gpa, "MSG", body, c.mode, keys, .server_to_client);
        defer gpa.free(produced);
        try testing.expectEqualSlices(u8, expected, produced);

        // Decode: the frozen bytes must open back to exactly the input body.
        const opened = try security.symmetricDecryptAndVerify(gpa, expected[0..8], expected[8..], c.mode, keys, .server_to_client);
        defer gpa.free(opened);
        try testing.expectEqualSlices(u8, body, opened);
    }

    // Sign carries only the 32-byte MAC; SignAndEncrypt adds a full padding
    // block on top — the arithmetic, stated as a number.
    try testing.expectEqual(@as(usize, 8 + 40 + 32), golden_sym_sign_hex.len / 2);
    try testing.expectEqual(@as(usize, 8 + 40 + 16 + 32), golden_sym_sign_and_encrypt_hex.len / 2);
}

/// The deterministic seeds behind the asymmetric golden. `rsa.generate` is a
/// pure function of its random stream, so a fixed CSPRNG seed pins the whole
/// key pair — and therefore the certificate, the OAEP ciphertext and the
/// PKCS#1 v1.5 signature.
const golden_key_seed = [_]u8{0xA5} ** 32;
const golden_seal_seed = [_]u8{0x5A} ** 32;

/// SELF-DERIVED. The 512-bit client application certificate `golden_key_seed`
/// produces (a small key so the golden stays readable; the live interop runs
/// 2048-bit).
const golden_client_cert_hex =
    "3082016e30820118a003020102020101300d06092a864886f70d01010b050030183116301406035504030c" ++
    "0d676f6c64656e20636c69656e74301e170d3230303130313030303030305a170d33353031303130303030" ++
    "30305a30183116301406035504030c0d676f6c64656e20636c69656e74305c300d06092a864886f70d0101" ++
    "010500034b003048024100c7254c11347503e8c9d0f6af7aff56417b39df593a7df80f5ca0c7a4e5562ec8" ++
    "dd2c99337529dac692f368669b0127fdba17b9881bc044926143adf1b928bbd90203010001a34d304b300c" ++
    "0603551d130101ff04023000300e0603551d0f0101ff040403020780302b0603551d1104243022862075726" ++
    "e3a7a69672d6c6962733a6f706375613a676f6c64656e2d636c69656e74300d06092a864886f70d01010b05" ++
    "000341008b20ad1fb69041d8127a36cf28647f192912277502bf4a6042a39a8d9e232a66f3896d2ea73144b" ++
    "e309b5566264a304afed1fbf618ca3cbadd4e02ed8a15009d";

/// SELF-DERIVED. The server certificate from the same stream (generated
/// second, hence a different key).
const golden_server_cert_hex =
    "3082016e30820118a003020102020101300d06092a864886f70d01010b050030183116301406035504030c" ++
    "0d676f6c64656e20736572766572301e170d3230303130313030303030305a170d33353031303130303030" ++
    "30305a30183116301406035504030c0d676f6c64656e20736572766572305c300d06092a864886f70d0101" ++
    "010500034b003048024100d6ba93d3c73da9e9a8a4792a525dd35d7b785b0970ae0328348db281487ee044" ++
    "c697c70006bbfe9c5cb291a7fe6e282724b9e72984082f8d69ae8dd86f7c27b50203010001a34d304b300c" ++
    "0603551d130101ff04023000300e0603551d0f0101ff040403020780302b0603551d1104243022862075726" ++
    "e3a7a69672d6c6962733a6f706375613a676f6c64656e2d736572766572300d06092a864886f70d01010b05" ++
    "00034100330003458a2830ea61082f3429050a0d13ad9ec9bffecb0239121002bca2f25e3078db2413ebf6c" ++
    "92ddc3737b339bb57cd40a690d261c540402e4ed005299d9a";

/// SELF-DERIVED. A complete `OpenSecureChannel` message under
/// Basic256Sha256: `OPNF` + size, SecureChannelId 0, the plaintext
/// `AsymmetricAlgorithmSecurityHeader` (policy URI, the client certificate
/// above, the SHA-1 thumbprint of the server certificate), then the
/// SequenceHeader + payload + padding + RSA-PKCS1v1.5/SHA-256 signature,
/// RSA-OAEP/SHA-1-encrypted to the server key in 64-byte blocks. 791 bytes:
/// 8 header + 455 clear security header + 328 ciphertext.
const golden_opn_hex =
    "4f504e46170300000000000039000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f5541" ++
    "2f5365637572697479506f6c696379234261736963323536536861323536720100003082016e3082011" ++
    "8a003020102020101300d06092a864886f70d01010b050030183116301406035504030c0d676f6c64656e" ++
    "20636c69656e74301e170d3230303130313030303030305a170d3335303130313030303030305a3018311" ++
    "6301406035504030c0d676f6c64656e20636c69656e74305c300d06092a864886f70d0101010500034b00" ++
    "3048024100c7254c11347503e8c9d0f6af7aff56417b39df593a7df80f5ca0c7a4e5562ec8dd2c9933752" ++
    "9dac692f368669b0127fdba17b9881bc044926143adf1b928bbd90203010001a34d304b300c0603551d13" ++
    "0101ff04023000300e0603551d0f0101ff040403020780302b0603551d11042430228620" ++
    "75726e3a7a69672d6c6962733a6f706375613a676f6c64656e2d636c69656e74300d06092a864886f70d0" ++
    "1010b05000341008b20ad1fb69041d8127a36cf28647f192912277502bf4a6042a39a8d9e232a66f3896d" ++
    "2ea73144be309b5566264a304afed1fbf618ca3cbadd4e02ed8a15009d140000000a217643bd4fe67aa32" ++
    "e2226257a61374f442aef1c5a47c197cca95553c5fb13b1bcb3e51793d55ed743e7e74f5e91b4039a437d" ++
    "57af291e09b258b8103542b39a6fa9d8cddfa83ce4f4e63931401625bb8523c3620b66d0fc4de6f0b797f" ++
    "3de026432a393588bb3123ba3e714392d102357c77e5deaf264779fea3781bef74227f26af310521877aa" ++
    "2351d3593aaf45e892f31ebce097f66b1031736f60a334266a391d61d0ef0a369bdd50f6af8f681d5729d" ++
    "cb1f11f779c21f3b754bf8a630721c8391ab60715032dc5e12a5569d297c8bbf202de9607ead691516a27" ++
    "2e5b8076ac617573b8012dd995f85b848490cb0eff96e48d80ff03b514eb195f0f7888d2766cfc27796c4" ++
    "2f77d37aeb0f57597973e28673759260ae25f519cd02bd98ee981d56493a3784af5cbee36fcdbfb4dcfdd" ++
    "6c5d10e32dd72126ecd7636dfb78f8d0b99b55026af3ef71e5a67bd20b9b2a60fa";

test "golden (self-derived): the Basic256Sha256 asymmetric OpenSecureChannel handshake" {
    const gpa = testing.allocator;

    // 1. The key material is reproducible from its seed, certificates included.
    var prng = std.Random.DefaultCsprng.init(golden_key_seed);
    const rnd = prng.random();
    const client = try security.Credentials.generateSelfSigned(gpa, rnd, .{
        .modulus_bits = 512,
        .common_name = "golden client",
        .not_before = "200101000000Z",
        .not_after = "350101000000Z",
        .application_uri = "urn:zig-libs:opcua:golden-client",
    });
    defer client.deinit(gpa);
    const srv = try security.Credentials.generateSelfSigned(gpa, rnd, .{
        .modulus_bits = 512,
        .common_name = "golden server",
        .not_before = "200101000000Z",
        .not_after = "350101000000Z",
        .application_uri = "urn:zig-libs:opcua:golden-server",
    });
    defer srv.deinit(gpa);

    var cert_buf: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&cert_buf, golden_client_cert_hex), client.certificate_der);
    var cert_buf2: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&cert_buf2, golden_server_cert_hex), srv.certificate_der);

    // 2. Rebuild the plaintext OPN body and seal it with the same OAEP seed.
    var bw = std.Io.Writer.Allocating.init(gpa);
    defer bw.deinit();
    var e = encoding.Encoder.init(&bw.writer);
    try bw.writer.writeInt(u32, 0, .little); // SecureChannelId: 0 on a fresh channel
    const thumbprint = security.certificateThumbprint(srv.certificate_der);
    try security.encodeAsymmetricAlgorithmSecurityHeader(&e, .{
        .security_policy_uri = security.SecurityPolicy.basic256sha256.uri(),
        .sender_certificate = client.certificate_der,
        .receiver_certificate_thumbprint = &thumbprint,
    });
    const encrypted_region_offset = bw.writer.buffered().len;
    try bw.writer.writeInt(u32, 1, .little); // SequenceNumber
    try bw.writer.writeInt(u32, 1, .little); // RequestId
    try bw.writer.writeAll("OPN-REQUEST-PAYLOAD-GOLDEN");
    const plain_body = bw.writer.buffered();

    var seal_prng = std.Random.DefaultCsprng.init(golden_seal_seed);
    const produced = try security.sealAsymmetricMessage(
        gpa,
        seal_prng.random(),
        "OPN",
        plain_body,
        encrypted_region_offset,
        client,
        srv.certificate_der,
    );
    defer gpa.free(produced);

    var expected_buf: [1024]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_buf, golden_opn_hex);
    try testing.expectEqualSlices(u8, expected, produced);
    try testing.expectEqual(@as(usize, 791), expected.len);
    try testing.expectEqual(expected.len, std.mem.readInt(u32, expected[4..8], .little));
    // The security header rides in the clear so a receiver can pick a key
    // before it can decrypt anything (§6.7.2.3).
    try testing.expectEqualSlices(u8, plain_body[0..encrypted_region_offset], expected[8..][0..encrypted_region_offset]);
    // …and the encrypted region is a whole number of 64-byte RSA blocks.
    try testing.expectEqual(@as(usize, 0), (expected.len - 8 - encrypted_region_offset) % 64);

    // 3. The receiving side: the frozen bytes must open back to exactly the
    //    plaintext body, verified against the sender certificate the header
    //    carried.
    const view = security.viewAsymmetricHeader(expected[8..]).?;
    try testing.expectEqualStrings(security.SecurityPolicy.basic256sha256.uri(), view.security_policy_uri);
    try testing.expectEqualSlices(u8, client.certificate_der, view.sender_certificate.?);
    try testing.expectEqualSlices(u8, &thumbprint, view.receiver_certificate_thumbprint.?);
    try testing.expectEqual(encrypted_region_offset, view.encrypted_region_offset);

    const opened = try security.openAsymmetricMessage(gpa, expected[0..8], expected[8..], srv.private_key, client.certificate_der);
    defer gpa.free(opened);
    try testing.expectEqualSlices(u8, plain_body, opened);
}

// ── CAPTURED Basic256Sha256 goldens (live open62541 server_ctt) ────────────
//
// The self-derived goldens above pin exact byte-for-byte stack behavior from
// fixed, deterministic inputs, with only the *live interop above* as their
// third-party cross-check — no committed bytes actually came from a real
// peer. These close that gap: real wire bytes from `root.zig`'s "LIVE
// open62541 secure interop" test, a genuine `open62541 server_ctt` container
// (not this repository's own code) exercising both Sign and SignAndEncrypt.
//
// Captured with `OPCUA_CAPTURE_DIR=<dir> zig build test-opcua` — the test's
// own `dumpSecureCapture` (raw c2s/s2c byte streams) and `dumpSecureKeys`
// (the ACTUAL derived session keys, read straight out of
// `ch.io.security.?.keys` right after the real OPN handshake succeeded).
// The keys have to be captured this way rather than re-derived here: the
// client's RSA keypair is generated from a real OS-entropy CSPRNG for that
// test (deliberately — it is the strongest real-world security test this
// module has), so it is not reproducible, and the OPN response is encrypted
// to it. Freezing the resulting keys is safe: they belong to one already-
// closed channel to a local, single-run container, with no life beyond this
// test file.
//
// The four MSG chunks below are all the same request: `Read` of
// `Server_ServerStatus_CurrentTime` (i=2258) — small enough to read
// comfortably, and exercised at both modes so the size delta (Sign only
// signs; SignAndEncrypt also pads and encrypts) is a real, not asserted,
// number.
//
// Not covered here: no live capture triggered multi-chunk ('C'-type)
// framing (every message here fit in one 'F' chunk under the negotiated
// 64KB limits) — multi-chunk secured framing already has offline coverage
// elsewhere in this module (see `server.zig`'s "a bigger response" comment
// near its Browse tests), just not from a live third-party peer.

const captured_opn_sign_req_hex =
    "4f504e46840500000000000039000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572" ++
    "697479506f6c6963792342617369633235365368613235361f0300003082031b30820203a003020102020101300d06092a" ++
    "864886f70d01010b0500302d312b302906035504030c227a69672d6c696273206f706375612073656375726520696e7465" ++
    "726f702074657374301e170d3236303130313030303030305a170d3237303130313030303030305a302d312b3029060355" ++
    "04030c227a69672d6c696273206f706375612073656375726520696e7465726f70207465737430820122300d06092a8648" ++
    "86f70d01010105000382010f003082010a0282010100b52bcb8c54abfe3f96468e8c3879d16311021d006ae432fa34ceda" ++
    "ae0005fda15f7b768154754a8a83c566dbddffa9e60efba4437278789d784ac344cf3b5410e4e50748dbb1f274277b3ebb" ++
    "781ee4c846974fb54dd79367282819ccff9f1557947764bdf38594d663efbc30f9f82dc27872dc62605a7b57b0b28ab0cc" ++
    "6da32fc83fac5fde88c6ba526a353a77666cc6a82ebcc95eec67629f1eb350518c16d0923d95706d3d6790de732de74d5f" ++
    "e2d4eca107526c573c608eb8381c2d16d720fbea7f5be8aa6cf67f3c1275f95342c8891628ebd52143b2b9fa2e663f69e2" ++
    "19565e1d81fd5cc92b717bc223bdc3dba2409b1ba01d20980a23abad54adf3f7530203010001a3463044300c0603551d13" ++
    "0101ff04023000300e0603551d0f0101ff04040302078030240603551d11041d301b861975726e3a7a69672d6c6962733a" ++
    "6f706375613a636c69656e74300d06092a864886f70d01010b050003820101001fea8299856ebf260899c72cc7cd77e8d4" ++
    "5d38dbd2cefcc69e407ea72fed99661077288f6ef08e0db075715a43d61acd671591a7aaaa4fc98134d1effead1750199c" ++
    "0ec42f4e60c1081bbd2b8647b0ac1d9094064feede47330e12afb2280071fcec42cc154ada79d5f76179d0cb25ccc67d5a" ++
    "703559819158177ab1461e41da61faf3083b5b3e572efaa607f38be974aa24b2ca58df24e9a26caa4c82f3a4ab480e7587" ++
    "afd9b0b77181efefba16febe6130d7fac70b9c3aefeac827805fa14e5c782eaf2b4264f231ea137523ad596416a85ffc6c" ++
    "96a19457da76010be71006afe3dfe1b3ce5c476ab63612e1dfe235bb2650032a50d73d3256bbff5576d9a9140000002937" ++
    "5bce4cd4c180d910d7a8777a5398b5bdcdd93e5a149c305e6c3e9b3b68efb268d4cec089bdaeee99976739f0b7e3a38b46" ++
    "8bf1e6a2c7f3bb70a14c5f4178511046e959a69413214e8d877273e3813ee901819cee4e5b1ec968d346b5d96af4c8bd8d" ++
    "b1e1496fe5114e9078d9d96a5c1dc5bfa87715fe620cb8cf01d9927981f5d516274cc3354a1f049e735573247a8f656da3" ++
    "d44d1d1d183a54bed5e8a820860e4613315bc3a629f05ddcbf976829133fdeb05b63f7ec1230f30f14bc50c3aac84ffeb4" ++
    "9fa1bc9b4678f980638b82e43d0df95112536cf26520b1088c6ed5f025f952cfa7cc8f00e0bf7e294bbb79a5949b0d3434" ++
    "272c02db62526c920c01a702d18ba663957b30f5a499fb7ea42bd2912c9625612a1519d9749b5b00a2186d437e0fc67470" ++
    "02ea4926a5d4049b34e676643c33a5a7f6d7634e850f3aa342072c015fa93ebd3badd67f8579a42d5a012d563dc7ab5a6b" ++
    "cb2cc6af9ef8c0a3d8d4c4195299dfb1962dd6e83affdcabed9bfe7becf77b55c11bfa6ae414889030969ff2353c200768" ++
    "1bd6c2ddeaf5f8923f58c9f173e3a2c3185d292606150e2f1b78c18d670bfa803c2f154a4d6059c947ad639e7a98589f4b" ++
    "92e792df0a302d41a011fa4a447af0eb0515dc91e23b674ce00c3e5a7d5912eabe9c4123988c4432e6188ad2203c7cefa3" ++
    "8bf958cffbd8c0735d58dfcb1dd9b643e042a1cf9c6072868c6842018ba39dd5d70a3c5a79ccfe62";
const captured_opn_sign_resp_hex =
    "4f504e46510600000200000039000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572" ++
    "697479506f6c696379234261736963323536536861323536ec030000308203e8308202d0a0030201020214199bfaf0958e" ++
    "b262bad7202a2bc9ae1483e57a49300d06092a864886f70d01010b05003045310b30090603550406130244453112301006" ++
    "0355040a0c096f70656e36323534313122302006035504030c196f70656e3632353431536572766572406c6f63616c686f" ++
    "7374301e170d3231303130353133343131365a170d3232303130353133343131365a3045310b3009060355040613024445" ++
    "31123010060355040a0c096f70656e36323534313122302006035504030c196f70656e3632353431536572766572406c6f" ++
    "63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100c0600ee9769406fddd" ++
    "21ebf8911d6a57a7e794439c2c59b2cec064f221ffd3cd2360e530d18c21809bfa6c37d307fc6be7680f85df26e411d0f8" ++
    "3f47b50dbaec6cc1a1be8efad019f9e5308787a4f8b06ba7ca55f149a49da84bf0620343f26d3d7b1140c37fda91f3b0f6" ++
    "7b9d63be503518860df1ddfed1447467c6a38a7866559c2d2c2b0c417782a703aa19718646bed3c2d3f04032e1b676b871" ++
    "5a500ece408d7764ab97355a43bd65511c778378482fb1b8addd4004aed93fd3dbedce9b0a6a249c331c626b5b1fa9707b" ++
    "74679e36db53b7950214a2db54b68bfc0bbc6c7523b3f0625d8d24a9f47137a76e2d13aeeb0de5e2cd3d9b180b8211e277" ++
    "835b0203010001a381cf3081cc301d0603551d0e0416041437e2b4ea617b94526a81b2eb2bf12e2924e0ed22301f060355" ++
    "1d2304183016801437e2b4ea617b94526a81b2eb2bf12e2924e0ed2230090603551d1304023000300b0603551d0f040403" ++
    "0202f4301d0603551d250416301406082b0601050507030106082b0601050507030230530603551d11044c304a820c6635" ++
    "30313062363766336435820c6635303130623637663364358704ac11000387047f000001862075726e3a6f70656e363235" ++
    "34312e7365727665722e6170706c69636174696f6e300d06092a864886f70d01010b05000382010100a42f874dccae2975" ++
    "c128fa26a49569304ec255665a34bffd1d08f375d203b020fc123aeb0f0b5359470268ff483bf75d490a87129ca9c17da3" ++
    "3957be69829b9381e9d1b856ee650884628db6e9e34e7575a38df0f0953173b483deceb5cfa424ccfb8d6b18bad9faf6cc" ++
    "8e6e13a54bca04e9aeec7d52674f7cf84cde750634cf50b9ba9f586904502acf6bbf47938e61b3689a986cb7bb6accc2ef" ++
    "d0d5f6cfdb40fa133ef24d20eb17e104a0884f595ac57fdb1bb94b772d5d6851d1d229000d07119744a854912b248fdd40" ++
    "9abe0a2b95ef63ee3ed5989305394661e72d7c98d6f9bc6702f3520f6f2d285a6c137985129fa7d4c83ed2889d87e9eb5b" ++
    "21f85e140000000483a990dc18cb53bc21a630bcc94446d566dcf1a0f43a65cda49a164f6b1000c3935a9c1dc682e832b8" ++
    "df2b14456c6250d9d3a56b9e213e7cb22594372562e425011a98984956ea30c513e53107367f3b6fea79a52bab0f57afe5" ++
    "3ad98d990ca6ef21d6058280aaf4fa66b82e7fc9f07ad117eb019dce090791782c7a6d32cde8a33ab105114647a30d71be" ++
    "16c77559628b9b99f1f70d8aa87f5a0b272393e25d418a753646fad759c110a61dfcb9224ab42bc153b10213307b2b125d" ++
    "ee7ea4eccfb37f38227d0943222a02519a30762828954df5ba441a13f757cee3fbfc8840733306e5cd0cdcc336067d2403" ++
    "4297e8ce7355f762693f6e4b5db93b55dca757b7697736e68070634cd5c9601ca98f6ab4d94b1ff56a6c75929922721431" ++
    "af840ebbe983d56798bd674d88e9e9c8bd744d0f60143257101c326f56c3ca59f1da3c379ac3c16e4e4a38dca6e0784391" ++
    "f655798240ef36d2e9f0861e33535112f177be2d2cf88cdbd1c5695440a66230e33121b5a6ce7649be7352e6975127cd1e" ++
    "4c8a7fa478da21f43d927b05d63dbc4ba50126eb86da4aaa0431fa9205c94b1e6293042f68925153418b193b03689f3a8b" ++
    "925126b0e9358b96d946354dd9680fda41f26476ffe95fd3618ae896815d6c341e610ba2f4eaea9e5d61822ddbffd171d9" ++
    "0f42f2980b321f62b55619de0bf37f48ba919b7866f9aa2c7ff7a865462ad0d86200d0be932a407fb801b7eb8efc49da89";
const captured_msg_sign_req_hex =
    "4d5347468c000000020000000200000004000000040000000100770204010048a40d1eb5b4ef92388358c559c58c080000" ++
    "0000000000000400000000000000ffffffff10270000000000000000000000000002000000010000000100d2080d000000" ++
    "ffffffff0000ffffffff2b597809ec1a6b1096b4802bcc1357b7cc5fd7c815ec21f00adb31a965cb47c9";
const captured_msg_sign_resp_hex =
    "4d534746760000000200000002000000040000000400000001007a02725c2b4ca521dd01040000000000000000ffffffff" ++
    "000000010000000d0d685c2b4ca521dd01725c2b4ca521dd01725c2b4ca521dd01ffffffffa3987c188f64c426176c8412" ++
    "c27023968471a68c6ef7be72aa7bc1fd617e7331";
const captured_msg_sign_and_encrypt_req_hex =
    "4d534746900000000100000001000000b19c1d018d02cfe8a7433d55e2f0fb2ecc9e8a599f959b1a3948bc95ad82d1f3ff" ++
    "f764c61dab90afb713e829710f2964135c588b77d4cd5d4c3f2166a0c198a6138533bc2bb80a0b1532896e3e27a2b3513c" ++
    "20a0365b0d1918eb8b812b42b44a2e4b07d044ab0dd953e456c2d892d3d368aaa684764d81efaa6cf4e850a10e31";
const captured_msg_sign_and_encrypt_resp_hex =
    "4d534746800000000100000001000000164c43066f68261571d26b85161ff9a81f2e2e89d2c219f07d5429f222ed10befb" ++
    "e1b30701f134ec5bbef1a6e5662c3902b41b9b065ffa42ce6063bcb52bbf24ff1d2b8a86336e5ffc18bdd6b40e2270cdc3" ++
    "9d4d430fa1a4c9c77c11cd1e3c5eee206018a9ad99de14bcc76fdc48e7b2";
const captured_sign_keys_hex =
    "1c3f8456622f4cec9194060293e61cdad45c50f396f294908e65c2e9d11fb99f688d934744d4846f0ae69d5cbedcf87265" ++
    "d3d18a822770ff02fbd3da641db7bb8805258b97a670def6bfabe8cbc8c1db042e16110de7b1dd16f72073d498fb10c604" ++
    "1b83d8b49cb08b5df7c3de49c51c129b3c497a9bf6821d212e627e8e95c44709c5aa3d3dc2f60e1c819a5a4bb966026dd5" ++
    "5fac47c9ab049a704444005f64";
const captured_sign_and_encrypt_keys_hex =
    "f5ee3432e84bd7408609feb80aa68eaa5c893c7062fcbe870135f47018a74fa56575b258bc0355a359e6861343a6333d7b" ++
    "93a981a000fbcf9afc09bc94397d447ebd999a1a39aee40e9c5b2b02883b803cac50761af3548c3f08c2412bd7c5527776" ++
    "34bc8c51867ec1a305e67ab2c76cfea18b1d40d9984f929a4fb798b4cea169ae15a4425a7e99661d7f57a32b329feb2dad" ++
    "1fc2f4fb5ced2cebc461c6a596";

/// Unpack a `dumpSecureKeys`-format 160-byte hex blob (client
/// signing/encrypting/iv, then server signing/encrypting/iv) into a
/// `security.ChannelKeys` — the exact keys one live captured exchange
/// actually derived.
fn channelKeysFromHex(hex: []const u8) security.ChannelKeys {
    var buf: [160]u8 = undefined;
    const b = std.fmt.hexToBytes(&buf, hex) catch unreachable;
    return .{
        .client_signing_key = b[0..32].*,
        .client_encrypting_key = b[32..64].*,
        .client_iv = b[64..80].*,
        .server_signing_key = b[80..112].*,
        .server_encrypting_key = b[112..144].*,
        .server_iv = b[144..160].*,
    };
}

test "golden (captured, live open62541 server_ctt): OpenSecureChannel request+response (Basic256Sha256/Sign)" {
    const gpa = testing.allocator;

    var req_buf: [1412]u8 = undefined;
    const req = try std.fmt.hexToBytes(&req_buf, captured_opn_sign_req_hex);
    var resp_buf: [1617]u8 = undefined;
    const resp = try std.fmt.hexToBytes(&resp_buf, captured_opn_sign_resp_hex);

    try testing.expectEqualStrings("OPN", req[0..3]);
    try testing.expectEqual(@as(u8, 'F'), req[3]);
    try testing.expectEqual(@as(u32, @intCast(req.len)), std.mem.readInt(u32, req[4..8], .little));
    try testing.expectEqualStrings("OPN", resp[0..3]);
    try testing.expectEqual(@as(u32, @intCast(resp.len)), std.mem.readInt(u32, resp[4..8], .little));

    // The plaintext security header rides in the clear (§6.7.2.3) — this is
    // the MessageSecurityMode negotiation's cert exchange, both certificates
    // genuine (this client's own generated one; open62541's real one, pulled
    // straight out of the running container by the live test). The mode
    // field itself lives in the encrypted OpenSecureChannelRequest/Response
    // body, which needs the matching RSA private key to open — the symmetric
    // MSG goldens below are what a chosen mode then does to the wire.
    const req_view = security.viewAsymmetricHeader(req[8..]).?;
    const resp_view = security.viewAsymmetricHeader(resp[8..]).?;
    try testing.expectEqualStrings(security.SecurityPolicy.basic256sha256.uri(), req_view.security_policy_uri);
    try testing.expectEqualStrings(security.SecurityPolicy.basic256sha256.uri(), resp_view.security_policy_uri);

    // Each side's ReceiverCertificateThumbprint is the SHA-1 of the OTHER
    // side's SenderCertificate — the two independently-generated real
    // certificates cross-reference each other correctly.
    const client_cert = req_view.sender_certificate.?;
    const server_cert = resp_view.sender_certificate.?;
    const client_thumb = security.certificateThumbprint(client_cert);
    const server_thumb = security.certificateThumbprint(server_cert);
    try testing.expectEqualSlices(u8, &server_thumb, req_view.receiver_certificate_thumbprint.?);
    try testing.expectEqualSlices(u8, &client_thumb, resp_view.receiver_certificate_thumbprint.?);
    // A real X.509 DER certificate open62541 generated at container start —
    // not one of this repository's own fixtures.
    try testing.expect(server_cert.len > 500);

    // Re-encoding the decoded envelope fields reproduces the real bytes
    // exactly, up to the encrypted region: full OAEP fidelity would need the
    // ephemeral (OS-entropy-seeded, never persisted) client private key —
    // see the module docs on why that is not carried here.
    var bw = std.Io.Writer.Allocating.init(gpa);
    defer bw.deinit();
    {
        var e = encoding.Encoder.init(&bw.writer);
        try bw.writer.writeInt(u32, 0, .little); // SecureChannelId: 0 on a fresh channel
        try security.encodeAsymmetricAlgorithmSecurityHeader(&e, .{
            .security_policy_uri = req_view.security_policy_uri,
            .sender_certificate = req_view.sender_certificate,
            .receiver_certificate_thumbprint = req_view.receiver_certificate_thumbprint,
        });
        try testing.expectEqualSlices(u8, req[8..][0..req_view.encrypted_region_offset], bw.writer.buffered());
    }
    bw.clearRetainingCapacity();
    {
        var e = encoding.Encoder.init(&bw.writer);
        try bw.writer.writeInt(u32, std.mem.readInt(u32, resp[8..12], .little), .little); // the server-assigned SecureChannelId
        try security.encodeAsymmetricAlgorithmSecurityHeader(&e, .{
            .security_policy_uri = resp_view.security_policy_uri,
            .sender_certificate = resp_view.sender_certificate,
            .receiver_certificate_thumbprint = resp_view.receiver_certificate_thumbprint,
        });
        try testing.expectEqualSlices(u8, resp[8..][0..resp_view.encrypted_region_offset], bw.writer.buffered());
    }

    // The encrypted region is a whole number of 64-byte RSA blocks either way.
    try testing.expectEqual(@as(usize, 0), (req.len - 8 - req_view.encrypted_region_offset) % 64);
    try testing.expectEqual(@as(usize, 0), (resp.len - 8 - resp_view.encrypted_region_offset) % 64);
}

test "golden (captured, live open62541 server_ctt): symmetric MSG chunks (Read i=2258) at Sign and SignAndEncrypt" {
    const gpa = testing.allocator;

    const Case = struct {
        mode: services.MessageSecurityMode,
        keys: security.ChannelKeys,
        req_hex: []const u8,
        resp_hex: []const u8,
    };
    const cases = [_]Case{
        .{ .mode = .sign, .keys = channelKeysFromHex(captured_sign_keys_hex), .req_hex = captured_msg_sign_req_hex, .resp_hex = captured_msg_sign_resp_hex },
        .{
            .mode = .sign_and_encrypt,
            .keys = channelKeysFromHex(captured_sign_and_encrypt_keys_hex),
            .req_hex = captured_msg_sign_and_encrypt_req_hex,
            .resp_hex = captured_msg_sign_and_encrypt_resp_hex,
        },
    };

    for (cases) |c| {
        var req_buf: [256]u8 = undefined;
        const req = try std.fmt.hexToBytes(&req_buf, c.req_hex);
        var resp_buf: [256]u8 = undefined;
        const resp = try std.fmt.hexToBytes(&resp_buf, c.resp_hex);

        // Decode + verify + decrypt real `open62541 server_ctt` bytes with
        // the ACTUAL session keys this exchange derived (dumped straight out
        // of `ch.io.security.?.keys` — see `root.zig`'s `dumpSecureKeys`).
        const opened_req = try security.symmetricDecryptAndVerify(gpa, req[0..8], req[8..], c.mode, c.keys, .client_to_server);
        defer gpa.free(opened_req);
        const opened_resp = try security.symmetricDecryptAndVerify(gpa, resp[0..8], resp[8..], c.mode, c.keys, .server_to_client);
        defer gpa.free(opened_resp);

        // Re-encode: AES-256-CBC/HMAC-SHA256 are deterministic given the same
        // key/IV/plaintext, so this reproduces the real wire bytes exactly —
        // a true byte-identical round trip against genuine third-party
        // ciphertext, not just a decode check.
        const produced_req = try security.symmetricSignAndEncrypt(gpa, "MSG", opened_req, c.mode, c.keys, .client_to_server);
        defer gpa.free(produced_req);
        try testing.expectEqualSlices(u8, req, produced_req);
        const produced_resp = try security.symmetricSignAndEncrypt(gpa, "MSG", opened_resp, c.mode, c.keys, .server_to_client);
        defer gpa.free(produced_resp);
        try testing.expectEqualSlices(u8, resp, produced_resp);
    }

    // Sign carries only the HMAC-SHA256 MAC; SignAndEncrypt pads to a whole
    // AES block first and encrypts — the size delta this real exchange
    // actually produced, not a self-derived arithmetic claim.
    try testing.expect(captured_msg_sign_and_encrypt_req_hex.len > captured_msg_sign_req_hex.len);
    try testing.expect(captured_msg_sign_and_encrypt_resp_hex.len > captured_msg_sign_resp_hex.len);
}
