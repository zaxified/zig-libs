// SPDX-License-Identifier: MIT

//! What a test harness does with `fleetsim`: stand up a simulated Modbus
//! slave with no socket at all (the module's own doc calls this out: "the
//! core is usable with no I/O"), poll a holding register over the fleet's
//! in-process event queue, inject a device fault, and watch the SAME master
//! request come back as a Modbus exception instead of data. This is the
//! shape a protocol-conformance test suite drives directly — animate N
//! simulated devices, submit wire frames, advance simulated time, read
//! whatever came out.
//!
//! Built against the PUBLISHED module (`@import("fleetsim")`), plus the
//! `modbus` dependency it declares — a real consumer needs `modbus`'s own
//! request/response codec to talk to the node `fleetsim` is animating.

const std = @import("std");
const fleetsim = @import("fleetsim");
const modbus = @import("modbus");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    // `fleetsim-example serve fleet.zon [--host 127.0.0.1] [--run-ms N]` starts a declared
    // fleet on TCP; `check fleet.zon` only parses it. No arguments: the poll demo below.
    if (args.len >= 3) return cli(init, args);
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    // Running the published surface under a leak-checking allocator is the
    // only leak check this module has OUTSIDE its own test suite (the suite
    // itself runs on `std.testing.allocator`). Discarding the verdict throws
    // that away: measured 2026-09-01, a deliberate 64-byte leak printed
    // `error(DebugAllocator): memory address 0x… leaked` and still exited 0.
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    // A holding-register bank the simulated device reports from. Nothing
    // copies this — `fleetsim`/`modbus` read it live, so animating the
    // device (a driver, a test step) is just writing into this array.
    var holding = [_]u16{ 0, 0, 0, 0 };
    holding[0] = 4200; // e.g. a tank level sensor, in tenths of a unit

    var slave = fleetsim.ModbusNode.init(
        .{ .unit_id = 1, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holding } },
    );

    var fleet = try fleetsim.Fleet.init(gpa, .{ .seed = 1 });
    defer fleet.deinit();

    const node_id = try fleet.addNode(.{ .node = slave.node() });

    // ── a normal poll ────────────────────────────────────────────────────
    var req_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    var pdu_buf: [8]u8 = undefined;
    const read_pdu = try modbus.pdu.encodeReadRequest(&pdu_buf, .read_holding_registers, 0, 1);
    const req = try modbus.tcp.encodeAdu(&req_buf, 1, 1, read_pdu);

    try fleet.submit(node_id, req, 0);
    _ = try fleet.advance(50);

    var out = fleet.outbound();
    if (out.len != 1) return error.UnexpectedReplyCount;
    const reply1 = try modbus.tcp.decodeAdu(fleet.frameBytes(out[0]));
    var reg: [1]u16 = undefined;
    try modbus.pdu.parseReadRegistersResponse(reply1.pdu, .read_holding_registers, &reg);
    std.debug.print("poll 1: holding[0] = {d}\n", .{reg[0]});

    // ── inject a device fault at t=100, then submit the SAME request again ──
    // `addFault` schedules the perturbation through the fleet's own event
    // queue (deterministic ordering with everything else, replayable from the
    // trace) rather than mutating the node out of band; `.trouble` is honored
    // by every one of the seven protocol adapters in its own protocol's
    // vocabulary — for Modbus that is exception 0x04 `SlaveDeviceFailure`.
    try fleet.addFault(.{ .at_ms = 100, .node = node_id, .kind = .{ .trouble = .{ .on = true } } });
    try fleet.submit(node_id, req, 100);
    _ = try fleet.advance(150);

    out = fleet.outbound();
    if (out.len != 1) return error.UnexpectedReplyCount;
    const reply2_bytes = fleet.frameBytes(out[0]);
    const reply2 = try modbus.tcp.decodeAdu(reply2_bytes);
    const result = modbus.pdu.parseReadRegistersResponse(reply2.pdu, .read_holding_registers, &reg);
    result catch |err| switch (err) {
        // The master's own exception vocabulary -- handled by name, not just
        // "it didn't parse".
        error.ServerDeviceFailure => std.debug.print("poll 2: device reports SlaveDeviceFailure (injected)\n", .{}),
        else => return err,
    };

    const stats = fleet.stats(node_id);
    std.debug.print("node stats: delivered={d} replied={d} responder_errors={d}\n", .{
        stats.delivered, stats.replied, stats.responder_errors,
    });
}

const usage =
    \\usage: fleetsim-example serve <fleet.zon> [--host A.B.C.D] [--run-ms N]
    \\       fleetsim-example check <fleet.zon>
    \\
    \\A fleet.zon describes Modbus devices, their link faults and a fault schedule
    \\(see `fleetsim.declare`). `serve` listens on each node's `listen_port`
    \\(default host 127.0.0.1) until every master has gone, or N ms have passed.
    \\
;

/// The declarative CLI: parse a description, report it, optionally serve it.
fn cli(init: std.process.Init, args: []const [:0]const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const serve = std.mem.eql(u8, args[1], "serve");
    if (!serve and !std.mem.eql(u8, args[1], "check")) {
        std.debug.print("{s}", .{usage});
        return error.BadArguments;
    }
    var host: [4]u8 = .{ 127, 0, 0, 1 };
    var run_ms: u64 = 0;
    var i: usize = 3;
    while (i + 1 < args.len) : (i += 2) {
        if (std.mem.eql(u8, args[i], "--host")) {
            var it = std.mem.splitScalar(u8, args[i + 1], '.');
            for (&host) |*b| b.* = try std.fmt.parseInt(u8, it.next() orelse return error.BadArguments, 10);
        } else if (std.mem.eql(u8, args[i], "--run-ms")) {
            run_ms = try std.fmt.parseInt(u64, args[i + 1], 10);
        } else {
            std.debug.print("{s}", .{usage});
            return error.BadArguments;
        }
    }
    const source = try std.Io.Dir.cwd().readFileAllocOptions(io, args[2], gpa, .limited(1 << 20), .of(u8), 0);
    defer gpa.free(source);
    var text: []u8 = &.{};
    defer gpa.free(text);
    const declared = fleetsim.declare.Declared.parse(gpa, source, &text) catch |err| {
        if (text.len > 0) std.debug.print("{s}\n", .{text});
        return err;
    };
    defer declared.deinit();
    for (declared.description.nodes) |n| {
        std.debug.print("node {s}: unit {d}, port {?d}\n", .{ n.name, n.unit_id, n.listen_port });
    }
    if (!serve) return;
    const bindings = try declared.bindings(host);
    if (bindings.len == 0) {
        std.debug.print("no node declares a listen_port\n", .{});
        return error.NothingToServe;
    }
    const report = try fleetsim.serveTcpMulti(gpa, io, &declared.fleet, bindings, .{ .run_ms = run_ms });
    std.debug.print("served {d} peer(s), {d} frames in\n", .{ report.peers_accepted, report.frames_in });
}
