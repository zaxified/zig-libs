// SPDX-License-Identifier: MIT

//! A declarative fleet: a ZON description of Modbus devices, their link faults
//! and a fault schedule, turned into a running `Fleet` with no code. This is
//! what ModbusPal and the pymodbus simulator give people who do not write Zig:
//! describe the register map, start it, point a master at it. ZON is Zig's own
//! data syntax, so the parser is `std.zon` and the schema is the structs below.
//!
//! ```zon
//! .{
//!     .seed = 7,
//!     .nodes = .{
//!         .{
//!             .name = "tank",
//!             .unit_id = 1,
//!             .listen_port = 5020,
//!             .holding = .{ .base = 0, .values = .{ 4200, 0, 0, 0 } },
//!             .coils = .{ .values = .{ true, false } },
//!             .link = .{ .delay_ms = 5 },
//!         },
//!     },
//!     .faults = .{
//!         .{ .at_ms = 100, .node = "tank", .kind = .{ .trouble = .{ .on = true } } },
//!     },
//! }
//! ```
//!
//! Only Modbus nodes are described: the other six protocols' responders keep
//! their data in caller-owned object models (BACnet objects, an OPC UA
//! `NodeStore`, DNP3 point tables) that a flat register map cannot stand for.
//! Everything a `Fault` can do is available by name in `.faults`.

const std = @import("std");
const fleet_mod = @import("fleet.zig");
const adapters = @import("adapters.zig");
const modbus = @import("modbus");

pub const RegisterDesc = struct {
    base: u16 = 0,
    values: []const u16 = &.{},
};

pub const BitDesc = struct {
    base: u16 = 0,
    values: []const bool = &.{},
};

pub const NodeDesc = struct {
    /// The name faults and the TCP bindings refer to; unique.
    name: []const u8,
    unit_id: u8 = 1,
    framing: enum { tcp, rtu } = .tcp,
    /// Answer any unit id (a gateway).
    accept_any_unit: bool = false,
    holding: RegisterDesc = .{},
    input: RegisterDesc = .{},
    coils: BitDesc = .{},
    discrete: BitDesc = .{},
    link: fleet_mod.LinkFaults = .{},
    /// A TCP port for `serveTcpMulti` (see `Declared.bindings`); null = in-process only.
    listen_port: ?u16 = null,
};

pub const FaultDesc = struct {
    at_ms: fleet_mod.Time,
    /// A `NodeDesc.name`.
    node: []const u8,
    kind: fleet_mod.FaultKind,
};

pub const Description = struct {
    seed: u64 = 0,
    nodes: []const NodeDesc,
    faults: []const FaultDesc = &.{},
};

pub const Error = error{
    /// The ZON did not parse as a `Description` (see the diagnostics).
    ParseZon,
    DuplicateName,
    /// A fault names a node that is not declared.
    UnknownNode,
    /// An area holds more than 65 536 entries or runs past address 65 535.
    AreaTooLarge,
    OutOfMemory,
};

/// A parsed description and the fleet built from it. Heap-pinned (the Modbus
/// nodes' addresses are in the fleet's vtables): create with `parse`, free with `deinit`.
pub const Declared = struct {
    arena: std.heap.ArenaAllocator,
    fleet: fleet_mod.Fleet,
    description: Description,
    /// The Modbus responders, one per `description.nodes` entry, in order (node id = index).
    servers: []adapters.Modbus,
    gpa: std.mem.Allocator,

    /// Parse `source` and build the fleet. On `error.ParseZon`, `error_text` (when given) receives a
    /// human-readable description of the ZON errors, `gpa`-owned: the caller frees it.
    pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, error_text: ?*[]u8) Error!*Declared {
        const self = try gpa.create(Declared);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.arena = .init(gpa);
        errdefer self.arena.deinit();
        const a = self.arena.allocator();
        var diag: std.zon.parse.Diagnostics = undefined;
        self.description = std.zon.parse.fromSlice(Description, .{ .gpa = gpa, .arena = a, .source = source, .diagnostics = &diag }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseZon => {
                // The diagnostics live in the arena the errdefer frees: render them first.
                if (error_text) |out| out.* = std.fmt.allocPrint(gpa, "{f}", .{diag.fmt("description")}) catch return error.OutOfMemory;
                return error.ParseZon;
            },
        };
        const d = self.description;
        for (d.nodes, 0..) |n, i| for (d.nodes[0..i]) |m| if (std.mem.eql(u8, n.name, m.name)) return error.DuplicateName;
        for (d.faults) |f| if (self.indexOf(f.node) == null) return error.UnknownNode;

        self.servers = try a.alloc(adapters.Modbus, d.nodes.len);
        for (d.nodes, self.servers) |n, *s| {
            const bank: modbus.server.DataBank = .{
                .holding_registers = .{ .base = n.holding.base, .values = try regs(a, n.holding) },
                .input_registers = .{ .base = n.input.base, .values = try regs(a, n.input) },
                .coils = .{ .base = n.coils.base, .values = try bits(a, n.coils) },
                .discrete_inputs = .{ .base = n.discrete.base, .values = try bits(a, n.discrete) },
            };
            s.* = adapters.Modbus.init(.{
                .unit_id = n.unit_id,
                .framing = switch (n.framing) {
                    .tcp => .tcp,
                    .rtu => .rtu,
                },
                .accept_any_unit = n.accept_any_unit,
            }, bank);
        }
        self.fleet = try fleet_mod.Fleet.init(gpa, .{ .seed = d.seed });
        errdefer self.fleet.deinit();
        for (d.nodes, self.servers, 0..) |n, *s, i| {
            _ = try self.fleet.addNode(.{ .node = s.node(), .link = n.link, .tag = i });
        }
        for (d.faults) |f| try self.fleet.addFault(.{ .at_ms = f.at_ms, .node = @intCast(self.indexOf(f.node).?), .kind = f.kind });
        return self;
    }

    pub fn deinit(self: *Declared) void {
        self.fleet.deinit();
        self.arena.deinit();
        self.gpa.destroy(self);
    }

    /// The node id of a declared name.
    pub fn indexOf(self: *const Declared, name: []const u8) ?usize {
        for (self.description.nodes, 0..) |n, i| if (std.mem.eql(u8, n.name, name)) return i;
        return null;
    }

    /// One `serveTcpMulti` binding per node that declares a `listen_port`, on `host`.
    /// Allocated from the description's arena; valid until `deinit`.
    pub fn bindings(self: *Declared, host: [4]u8) Error![]const @import("tcp.zig").Binding {
        const a = self.arena.allocator();
        var out: std.ArrayList(@import("tcp.zig").Binding) = .empty;
        for (self.description.nodes, 0..) |n, i| if (n.listen_port) |p| {
            try out.append(a, .{ .node = @intCast(i), .address = .{ .ip4 = .{ .bytes = host, .port = p } } });
        };
        return out.items;
    }
};

fn regs(a: std.mem.Allocator, r: RegisterDesc) Error![]u16 {
    if (r.values.len > 65536 or @as(usize, r.base) + r.values.len > 65536) return error.AreaTooLarge;
    return a.dupe(u16, r.values);
}

fn bits(a: std.mem.Allocator, r: BitDesc) Error![]bool {
    if (r.values.len > 65536 or @as(usize, r.base) + r.values.len > 65536) return error.AreaTooLarge;
    return a.dupe(bool, r.values);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const sample =
    \\.{
    \\    .seed = 7,
    \\    .nodes = .{
    \\        .{ .name = "tank", .unit_id = 1, .listen_port = 5020, .holding = .{ .base = 0, .values = .{ 4200, 7 } }, .coils = .{ .values = .{ true, false } } },
    \\        .{ .name = "pump", .unit_id = 2, .input = .{ .base = 10, .values = .{ 1, 2, 3 } } },
    \\    },
    \\    .faults = .{
    \\        .{ .at_ms = 100, .node = "tank", .kind = .{ .trouble = .{ .on = true } } },
    \\        .{ .at_ms = 300, .node = "tank", .kind = .heal },
    \\    },
    \\}
;

fn readReq(buf: []u8, unit: u8, fc: modbus.FunctionCode, addr: u16, n: u16) ![]const u8 {
    var pdu: [8]u8 = undefined;
    const p = try modbus.pdu.encodeReadRequest(&pdu, fc, addr, n);
    return modbus.tcp.encodeAdu(buf, 1, unit, p);
}

test "a described fleet answers like the hand-built one, faults included" {
    const d = try Declared.parse(testing.allocator, sample, null);
    defer d.deinit();
    try testing.expectEqual(@as(usize, 2), d.fleet.nodeCount());
    var buf: [modbus.tcp.max_adu_len]u8 = undefined;
    var regs_out: [2]u16 = undefined;
    // tank, before the fault
    try d.fleet.submit(0, try readReq(&buf, 1, .read_holding_registers, 0, 2), 0);
    _ = try d.fleet.advance(50);
    var reply = try modbus.tcp.decodeAdu(d.fleet.frameBytes(d.fleet.outbound()[0]));
    try modbus.pdu.parseReadRegistersResponse(reply.pdu, .read_holding_registers, &regs_out);
    try testing.expectEqualSlices(u16, &.{ 4200, 7 }, &regs_out);
    // pump: the base of an area is honoured
    try d.fleet.submit(1, try readReq(&buf, 2, .read_input_registers, 11, 2), 60);
    _ = try d.fleet.advance(90);
    reply = try modbus.tcp.decodeAdu(d.fleet.frameBytes(d.fleet.outbound()[0]));
    try modbus.pdu.parseReadRegistersResponse(reply.pdu, .read_input_registers, &regs_out);
    try testing.expectEqualSlices(u16, &.{ 2, 3 }, &regs_out);
    // the scheduled fault: trouble at 100, healed at 300
    try d.fleet.submit(0, try readReq(&buf, 1, .read_holding_registers, 0, 2), 150);
    _ = try d.fleet.advance(200);
    reply = try modbus.tcp.decodeAdu(d.fleet.frameBytes(d.fleet.outbound()[0]));
    try testing.expectError(error.ServerDeviceFailure, modbus.pdu.parseReadRegistersResponse(reply.pdu, .read_holding_registers, &regs_out));
    try d.fleet.submit(0, try readReq(&buf, 1, .read_holding_registers, 0, 2), 350);
    _ = try d.fleet.advance(400);
    reply = try modbus.tcp.decodeAdu(d.fleet.frameBytes(d.fleet.outbound()[0]));
    try modbus.pdu.parseReadRegistersResponse(reply.pdu, .read_holding_registers, &regs_out);
    // the declared TCP bindings
    const bs = try d.bindings(.{ 127, 0, 0, 1 });
    try testing.expectEqual(@as(usize, 1), bs.len);
    try testing.expectEqual(@as(u16, 5020), bs[0].address.ip4.port);
}

test "a description with a duplicate name, an unknown fault node, a bad field or a too-large area is refused" {
    const cases = [_]struct { src: [:0]const u8, err: Error }{
        .{ .src = ".{ .nodes = .{ .{ .name = \"a\" }, .{ .name = \"a\" } } }", .err = error.DuplicateName },
        .{ .src = ".{ .nodes = .{ .{ .name = \"a\" } }, .faults = .{ .{ .at_ms = 1, .node = \"b\", .kind = .restart } } }", .err = error.UnknownNode },
        .{ .src = ".{ .nodes = .{ .{ .name = \"a\", .bogus = 1 } } }", .err = error.ParseZon },
        .{ .src = ".{ .nodes = .{ .{ .name = \"a\", .holding = .{ .base = 65535, .values = .{ 1, 2 } } } } }", .err = error.AreaTooLarge },
        .{ .src = ".{ .nodes = 3 }", .err = error.ParseZon },
    };
    for (cases) |c| {
        var text: []u8 = &.{};
        const r = Declared.parse(testing.allocator, c.src, &text);
        defer testing.allocator.free(text);
        try testing.expectError(c.err, r);
        if (c.err == error.ParseZon) try testing.expect(text.len > 0);
    }
}
