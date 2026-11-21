// SPDX-License-Identifier: MIT

//! Pilot: the `opcua` server (`Server` + `Connection`, driven by a loop of
//! the pilot's own, as any embedding must) and its client (`SecureChannel` +
//! `Session`, unchanged) over a simulated network. A server publishes a
//! counter that moves with its process; a client keeps a session open and
//! reads it. The client side has no read timeout of its own (a read waits for
//! the server, as a Publish long-poll must), so a dead connection ends when
//! the server hangs up on a silent client or the transport fails; the client
//! then builds a new channel and session. Under loss, duplication and
//! partitions:
//!
//! - the client never reads a value the process has not reached yet;
//! - once the network is quiet the client's last reading equals the process,
//!   which needs a new channel and session after the old ones died. The
//!   broken variant that never reconnects is caught.

const std = @import("std");
const opcua = @import("opcua");
const sched = @import("../sched.zig");
const search = @import("../search.zig");

const Io = std.Io;
const net = Io.net;
const Sim = sched.Sim;
const Host = sched.Host;
const testing = std.testing;

const encoding = opcua.encoding;
const nodestore = opcua.nodestore;
const services = opcua.services;
const server = opcua.server;

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

const port: u16 = 4840;
const endpoint_url = "opc.tcp://10.0.0.1:4840";
const process_stop_ms = 4500;
/// The server drops a connection it has heard nothing on for this long.
const idle_limit_ms = 3000;

const answer_node: encoding.NodeId = .{ .string = .{ .namespace = 1, .id = "the.answer" } };

const State = struct {
    truth: i32 = 0,
    seen: i32 = -1,
    /// The broken variant: never build a new channel and session.
    reconnect: bool = true,
    sessions: u32 = 0,
};

fn nowMs(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .awake).nanoseconds, ns_per_ms));
}

/// OPC UA `DateTime`: 100 ns ticks since 1601-01-01 on the host's real clock.
fn opcUaNow(io: Io) encoding.DateTime {
    const ns = Io.Timestamp.now(io, .real).nanoseconds;
    return @intCast(@divFloor(ns, 100) + 11_644_473_600 * 10_000_000);
}

// ── the server ─────────────────────────────────────────────────────────────

fn process(io: Io, st: *State) !void {
    while (nowMs(io) < process_stop_ms) {
        try io.sleep(.fromMilliseconds(200), .awake);
        st.truth += 1;
    }
}

const app: services.ApplicationDescription = .{
    .application_uri = "urn:zig-libs:opcua:pilot",
    .product_uri = "urn:zig-libs:opcua",
    .application_name = .{ .locale = "en", .text = "pilot" },
    .application_type = .server,
    .gateway_server_uri = null,
    .discovery_profile_uri = null,
    .discovery_urls = null,
};
const endpoints = [_]services.EndpointDescription{server.noneEndpoint(endpoint_url, app)};

fn serverMain(io: Io, gpa: std.mem.Allocator, st: *State) !void {
    var store = nodestore.NodeStore.init(gpa);
    defer store.deinit();
    const start = opcUaNow(io);
    try store.addStandardNodes(.{ .start_time = start });
    const ns = try store.addNamespace("urn:zig-libs:opcua:pilot");
    std.debug.assert(ns == 1);
    try store.refreshNamespaceArray();
    try store.addVariable(.{
        .node_id = answer_node,
        .parent_id = nodestore.n0(nodestore.id.objects_folder),
        .reference_type_id = nodestore.n0(nodestore.id.organizes),
        .browse_name = .{ .namespace_index = 1, .name = "the.answer" },
        .value = .{ .scalar = .{ .int32 = 0 } },
        .data_type = nodestore.n0(nodestore.id.int32),
        .access_level = nodestore.access_level.current_read,
        .timestamp = start,
    });
    var prng = std.Random.DefaultPrng.init(1);
    var srv = server.Server.init(gpa, &store, .{
        .application_uri = "urn:zig-libs:opcua:pilot",
        .endpoints = &endpoints,
    }, prng.random());
    defer srv.deinit();
    srv.wall_clock_epoch = start;

    var listener = try net.IpAddress.listen(&.{ .ip4 = .unspecified(port) }, io, .{ .reuse_address = true });
    defer listener.deinit(io);
    while (true) {
        const stream = try listener.accept(io);
        serve(io, gpa, stream, st, &srv, &store, start) catch {};
    }
}

fn serve(io: Io, gpa: std.mem.Allocator, stream: net.Stream, st: *State, srv: *server.Server, store: *nodestore.NodeStore, start: encoding.DateTime) !void {
    defer stream.close(io);
    const recv_buf = try gpa.alloc(u8, 128 * 1024);
    defer gpa.free(recv_buf);
    const msg_buf = try gpa.alloc(u8, 256 * 1024);
    defer gpa.free(msg_buf);
    var conn = try server.Connection.init(srv, recv_buf, msg_buf);
    defer conn.deinit();
    var out = Io.Writer.Allocating.init(gpa);
    defer out.deinit();
    var wbuf: [16 * 1024]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var in: [16 * 1024]u8 = undefined;
    const t0 = nowMs(io);
    var heard = t0;
    var last_truth: i32 = -1;
    while (nowMs(io) - heard < idle_limit_ms and !conn.isClosed()) {
        const now = nowMs(io) - t0;
        if (st.truth != last_truth) {
            last_truth = st.truth;
            _ = try store.setValue(answer_node, .{ .scalar = .{ .int32 = last_truth } }, opcUaNow(io));
        }
        srv.refreshTime(now, start) catch {};
        var data: [1][]u8 = .{&in};
        const op: Io.Operation = .{ .net_read = .{ .socket_handle = stream.socket.handle, .data = &data } };
        const timeout: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
        if (io.operateTimeout(op, timeout)) |res| {
            const got = res.net_read catch return;
            if (got.data_len == 0) return;
            heard = nowMs(io);
            try conn.feed(in[0..got.data_len], &out.writer, nowMs(io) - t0);
        } else |err| switch (err) {
            error.Timeout => {},
            else => return err,
        }
        try conn.tick(&out.writer, nowMs(io) - t0);
        const bytes = out.written();
        if (bytes.len > 0) {
            try w.interface.writeAll(bytes);
            try w.interface.flush();
            out.clearRetainingCapacity();
        }
    }
}

// ── the client ─────────────────────────────────────────────────────────────

fn clientMain(io: Io, gpa: std.mem.Allocator, server_addr: net.IpAddress, st: *State) !void {
    while (true) {
        session(io, gpa, server_addr, st) catch {};
        try io.sleep(.fromMilliseconds(300), .awake);
    }
}

fn session(io: Io, gpa: std.mem.Allocator, server_addr: net.IpAddress, st: *State) !void {
    const stream = try server_addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var read_buf: [64 * 1024]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);
    var conn = opcua.transport.Connection.init(&reader.interface, &writer.interface);
    _ = try conn.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = endpoint_url,
    });
    var channel: opcua.SecureChannel = undefined;
    try opcua.SecureChannel.open(&conn, gpa, .{}, &channel);
    defer channel.close() catch {};
    var s = try opcua.Session.create(&channel, gpa, .{
        .client_description = .{
            .application_uri = "urn:zig-libs:opcua:pilot-client",
            .product_uri = "urn:zig-libs:opcua",
            .application_name = .{ .locale = "en", .text = "pilot client" },
            .application_type = .client,
            .gateway_server_uri = null,
            .discovery_profile_uri = null,
            .discovery_urls = null,
        },
        .endpoint_url = endpoint_url,
    });
    defer s.deinit();
    try s.activate(null);
    st.sessions += 1;
    while (true) {
        try io.sleep(.fromMilliseconds(100), .awake);
        const dv = s.readAttribute(answer_node, services.attribute_id.value) catch |e| {
            if (st.reconnect) return e;
            continue;
        };
        defer encoding.freeDataValue(gpa, dv);
        st.seen = dv.value.?.scalar.int32;
    }
}

// ── the world ──────────────────────────────────────────────────────────────

fn setup(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    const srv_host = try sim.addHost(.{}); // 10.0.0.1
    const client = try sim.addHost(.{});
    try sim.link(srv_host, client, .{ .latency_ns = 5 * ns_per_ms, .jitter_ns = 2 * ns_per_ms });
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = srv_host.ip4, .port = port } };
    try srv_host.spawnBoot(serverMain, .{ srv_host.io(), srv_host.allocator(), st });
    try srv_host.spawnBoot(process, .{ srv_host.io(), st });
    try client.spawnBoot(clientMain, .{ client.io(), client.allocator(), addr, st });
}

fn invariant(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.seen > st.truth) return error.ValueFromTheFuture;
}

fn final(sim: *Sim, ctx: ?*anyopaque) anyerror!void {
    _ = sim;
    const st: *const State = @ptrCast(@alignCast(ctx.?));
    if (st.seen != st.truth) return error.ClientDiverged;
}

fn reset(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx.?));
    st.* = .{ .reconnect = st.reconnect };
}

fn case(st: *State) search.Case {
    return .{
        .options = .{ .seed = 0, .stack_size = 2 * 1024 * 1024 },
        .setup = setup,
        .invariant = invariant,
        .final = final,
        .reset = reset,
        .ctx = st,
        .duration_ns = 40 * ns_per_s,
    };
}

fn at(time_ms: u64, kind: @FieldType(search.TraceEvent, "kind")) search.TraceEvent {
    return .{ .time = time_ms, .kind = kind };
}

test "pilot opcua: on a healthy network the client follows the process over one session" {
    var st: State = .{};
    const r = try search.replay(testing.allocator, case(&st), &.{}, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expectEqual(@as(u32, 1), st.sessions);
    try testing.expect(st.truth > 0);
}

test "pilot opcua: after an outage the client builds a new session and converges" {
    var st: State = .{};
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(3000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(9000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(?search.Violation, null), r.violation);
    try testing.expect(st.sessions >= 2);
}

test "pilot opcua: a client that never reconnects diverges, and the check sees it" {
    var st: State = .{ .reconnect = false };
    const cut = [_]u32{1};
    const r = try search.replay(testing.allocator, case(&st), &.{
        at(3000, .{ .net = .{ .partition = .{ .id = 1, .cut = &cut } } }),
        at(9000, .{ .net = .{ .heal = .{ .id = 1 } } }),
    }, ns_per_ms);
    try testing.expectEqual(@as(anyerror, error.ClientDiverged), r.violation.?.err);
}

test "pilot opcua: the client converges across seeds of loss, duplication and partitions" {
    var st: State = .{};
    const faults: search.FaultConfig = .{
        .schedule = .{
            .max_events = 6,
            .horizon = 8000,
            .repair_permille = 1000,
            .enable_crash = false,
            .enable_clock_jump = false,
        },
    };
    if (try search.findFailing(testing.allocator, case(&st), faults, 0, 12)) |*failing| {
        defer @constCast(failing).deinit();
        std.debug.print("seed {d}: {t} at {d} ms\n", .{ failing.case.seed, failing.violation.err, failing.violation.at_ns / ns_per_ms });
        return error.TestUnexpectedResult;
    }
}
