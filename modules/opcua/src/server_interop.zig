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

const testing = std.testing;

/// The open62541 example binaries connect to a hard-coded
/// `opc.tcp://localhost:4840`, and glibc's resolver hands them **::1** first
/// — so the interop listener binds IPv6 loopback, with IPv4 loopback as the
/// fallback for hosts without IPv6.
const live_hosts = [_][]const u8{ "::1", "127.0.0.1" };
const live_port: u16 = 4840;
const live_endpoint_url = "opc.tcp://localhost:4840";
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

    const endpoints = [_]services.EndpointDescription{server.noneEndpoint(live_endpoint_url, .{
        .application_uri = "urn:zig-libs:opcua:interop-server",
        .product_uri = "urn:zig-libs:opcua",
        .application_name = .{ .locale = "en", .text = "zig-libs opcua interop server" },
        .application_type = .server,
        .gateway_server_uri = null,
        .discovery_profile_uri = null,
        .discovery_urls = null,
    })};

    /// open62541's `client` example connects with `UA_Client_connect_username
    /// ("user1", "password")`, so the interop server accepts exactly that pair
    /// — a test fixture, not a credential of anything real.
    const users = [_]server.UserCredential{.{ .user_name = "user1", .password = "password" }};

    fn init(d: *Driver, gpa: std.mem.Allocator, io: std.Io) !void {
        var bound_host: []const u8 = live_hosts[0];
        const listener = blk: {
            var last_err: anyerror = error.AddressInUse;
            for (live_hosts) |host| {
                const addr = std.Io.net.IpAddress.parse(host, live_port) catch continue;
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

        d.srv = server.Server.init(gpa, &d.store, .{
            .application_uri = "urn:zig-libs:opcua:interop-server",
            .application_name = .{ .locale = "en", .text = "zig-libs opcua interop server" },
            .endpoints = &endpoints,
            .users = &users,
        }, d.prng.random());
        // `now_ms` is measured from `start_ms`, so the wall clock's zero point
        // is the server's start instant.
        d.srv.wall_clock_epoch = d.start_time;
    }

    fn deinit(d: *Driver) void {
        d.listener.socket.close(d.io);
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
        std.debug.print("\nSKIPPED: LIVE opcua server interop needs Linux (podman --network host).\n", .{});
        return error.SkipZigTest;
    }
    stopContainer(gpa, io, name); // leftover cleanup from a crashed run

    var driver: Driver = undefined;
    driver.init(gpa, io) catch |err| {
        std.debug.print("\nSKIPPED: LIVE opcua server interop cannot bind loopback:{d} ({t}).\n", .{ live_port, err });
        return error.SkipZigTest;
    };
    errdefer driver.deinit();

    var run_result = startClient(gpa, io, name, example) catch |err| switch (err) {
        error.SkipZigTest => {
            std.debug.print("\nSKIPPED: LIVE opcua server interop: `podman` is not available here.\n", .{});
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer run_result.deinit(gpa);
    if (run_result.exit_code != 0) {
        std.debug.print(
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
        std.debug.print(
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
        std.debug.print("\nSKIPPED: loopback server test needs Linux sockets.\n", .{});
        return error.SkipZigTest;
    }
    const gpa = testing.allocator;
    const root = @import("root.zig");

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var driver: Driver = undefined;
    driver.init(gpa, io) catch |err| {
        std.debug.print("\nSKIPPED: loopback server test cannot bind loopback:{d} ({t}).\n", .{ live_port, err });
        return error.SkipZigTest;
    };
    defer driver.deinit();

    var ctx: LoopbackCtx = .{ .driver = &driver };
    const thread = std.Thread.spawn(.{}, loopbackServeThread, .{&ctx}) catch {
        std.debug.print("\nSKIPPED: loopback server test cannot spawn a thread.\n", .{});
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
        std.debug.print("\nSKIPPED: loopback server test could not connect.\n", .{});
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
