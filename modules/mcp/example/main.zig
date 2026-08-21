// SPDX-License-Identifier: MIT

//! What a consumer does with `mcp`: register one tool, run the MCP lifecycle
//! (`initialize`, `notifications/initialized`) and one `tools/call` through
//! newline-delimited JSON-RPC exactly as a stdio transport would frame it,
//! and read the tool's textual result back off the wire.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to drive a tool call is not public, or an error cannot be named
//! from outside, this file stops compiling.

const std = @import("std");
const mcp = @import("mcp");

/// A trivial "echo" tool: requires a string `text` argument, writes it back
/// uppercased. Demonstrates the required-argument-missing failure path via
/// `ToolCall.fail`.
fn echoHandler(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const text = call.strArg("text") orelse return call.fail("missing 'text'");
    for (text) |c| call.write(&.{std.ascii.toUpper(c)});
    return false; // not a tool failure — this is the answer
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var server = mcp.Server.init(gpa, .{ .name = "example-srv", .version = "1.0.0" });
    defer server.deinit();

    server.addTool(.{
        .name = "echo",
        .description = "Echo text back, uppercased.",
        .input_schema =
        \\{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}
        ,
        .handler = echoHandler,
    }) catch |err| switch (err) {
        // Named from outside: a second registration under the same name is
        // rejected rather than silently shadowing the first.
        error.DuplicateTool => unreachable, // this is the only registration
        error.OutOfMemory => return err,
    };

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();

    // The lifecycle handshake: initialize, then the notification that has no
    // response (handleMessage writes nothing for it).
    try server.handleMessage(
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-client","version":"1"}}}
    , &out.writer);
    try server.handleMessage(
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    , &out.writer);

    // A well-formed call.
    try server.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}
    , &out.writer);

    // A call missing the required argument — exercises the `call.fail` path
    // and comes back as a JSON-RPC *result* with `isError:true` (MCP tool
    // failures are not JSON-RPC errors; only protocol-level problems are).
    try server.handleMessage(
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}
    , &out.writer);

    // A request naming a tool that was never registered — this one IS a
    // JSON-RPC error, distinguishing "no such tool" from "tool ran and
    // failed".
    try server.handleMessage(
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nonexistent"}}
    , &out.writer);

    const written = out.writer.buffered();
    std.debug.print("wire output ({d} bytes):\n{s}", .{ written.len, written });
}
