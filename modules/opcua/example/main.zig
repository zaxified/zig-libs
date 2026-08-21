// SPDX-License-Identifier: MIT

//! What an OPC-UA client does with `opcua`: complete the opc.tcp Hello/
//! Acknowledge handshake against a server, then decode a value the way a
//! Read service response would carry one — a `NodeId` naming the variable
//! plus a `Variant` holding its current reading — freeing everything the
//! decoder allocated. Then show the same handshake correctly reporting a
//! server-side rejection instead of hanging or panicking.
//!
//! `transport.Connection` is deliberately transport-agnostic (its own doc
//! comment names "a `.fixed` buffer pair for offline tests" as a first-class
//! use, not a special case) — this example wires it over `std.Io.Reader`/
//! `Writer` `.fixed` buffers rather than a real socket, with the
//! Acknowledge/Error replies built through the same `sendChunk` a real
//! server uses, so the bytes the client parses are genuine wire frames.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const opcua = @import("opcua");
const transport = opcua.transport;
const encoding = opcua.encoding;

/// Builds a real "ACK" wire chunk (via the same `sendChunk` a live server
/// uses) into `out`, returning the bytes written.
fn buildAckWire(out: []u8) ![]const u8 {
    var body_buf: [20]u8 = undefined;
    var bw: std.Io.Writer = .fixed(&body_buf);
    try bw.writeInt(u32, 0, .little); // protocol_version
    try bw.writeInt(u32, 65536, .little); // receive_buffer_size
    try bw.writeInt(u32, 65536, .little); // send_buffer_size
    try bw.writeInt(u32, 0, .little); // max_message_size (0 = unbounded)
    try bw.writeInt(u32, 0, .little); // max_chunk_count (0 = unbounded)

    var no_reader: std.Io.Reader = .fixed(&.{});
    var ow: std.Io.Writer = .fixed(out);
    var side: transport.Connection = .init(&no_reader, &ow);
    try side.sendChunk(.{ .message_type = .acknowledge, .chunk_type = .final, .message_size = 28 }, bw.buffered());
    return ow.buffered();
}

/// Builds a real "ERR" wire chunk with an empty body, as a server refusing
/// the connection would send.
fn buildErrWire(out: []u8) ![]const u8 {
    var no_reader: std.Io.Reader = .fixed(&.{});
    var ow: std.Io.Writer = .fixed(out);
    var side: transport.Connection = .init(&no_reader, &ow);
    try side.sendChunk(.{ .message_type = .error_msg, .chunk_type = .final, .message_size = 8 }, &.{});
    return ow.buffered();
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── a successful Hello/Acknowledge handshake ────────────────────────
    var ack_wire_buf: [64]u8 = undefined;
    const ack_wire = try buildAckWire(&ack_wire_buf);

    var client_out_buf: [512]u8 = undefined;
    var client_writer: std.Io.Writer = .fixed(&client_out_buf);
    var client_reader: std.Io.Reader = .fixed(ack_wire);
    var conn: transport.Connection = .init(&client_reader, &client_writer);

    const ack = try conn.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = "opc.tcp://plant-historian:4840",
    });
    std.debug.print("handshake ok: server receive_buffer_size={d}\n", .{ack.receive_buffer_size});
    std.debug.print("HEL bytes sent: {d}\n", .{client_writer.buffered().len});

    // ── decode a value the way a Read service response carries one: a
    //    NodeId naming the variable, and a Variant holding its reading ────
    var wire_buf: [64]u8 = undefined;
    var ew: std.Io.Writer = .fixed(&wire_buf);
    var enc: encoding.Encoder = .init(&ew);
    try enc.encodeNodeId(.{ .numeric = .{ .namespace = 2, .id = 1001 } });
    try enc.encodeVariant(.{ .scalar = .{ .double = 21.7 } }); // reactor-1 temperature, °C

    var er: std.Io.Reader = .fixed(ew.buffered());
    var dec: encoding.Decoder = .init(&er, gpa);
    const node_id = try dec.decodeNodeId();
    const value = try dec.decodeVariant();
    defer encoding.freeVariant(gpa, value); // decodeVariant may allocate (String/array payloads)

    switch (node_id) {
        .numeric => |n| std.debug.print("node ns={d};i={d} = {d:.1}\n", .{ n.namespace, n.id, value.scalar.double }),
        else => return error.UnexpectedNodeIdForm,
    }

    // ── the server refuses the connection: hello() must report it by
    //    name, not hang waiting for an Acknowledge that never comes ──────
    var err_wire_buf: [16]u8 = undefined;
    const err_wire = try buildErrWire(&err_wire_buf);
    var out_buf2: [512]u8 = undefined;
    var writer2: std.Io.Writer = .fixed(&out_buf2);
    var reader2: std.Io.Reader = .fixed(err_wire);
    var conn2: transport.Connection = .init(&reader2, &writer2);

    _ = conn2.hello(.{
        .protocol_version = 0,
        .receive_buffer_size = 65536,
        .send_buffer_size = 65536,
        .max_message_size = 0,
        .max_chunk_count = 0,
        .endpoint_url = "opc.tcp://plant-historian:4840",
    }) catch |err| switch (err) {
        error.ServerError => {
            std.debug.print("server rejection correctly reported\n", .{});
            return;
        },
        else => return err,
    };
    return error.ExpectedServerError;
}
