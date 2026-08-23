// SPDX-License-Identifier: MIT

//! What a remote MCP host does with `mcp-http`: register an `mcp.Server`
//! tool, front it with the Streamable HTTP `Transport` as `router`
//! middleware, and drive one `initialize` + one `tools/call` request through
//! the real HTTP wire codec (`http.Server.serveStream`) — no socket needed,
//! `std.Io.Reader`/`Writer.fixed` stand in for the connection, the same way
//! this module's own tests exercise it end to end.

const std = @import("std");
const mcphttp = @import("mcp-http");
const router = @import("router");
const http = @import("http");
const mcp = @import("mcp");

/// The one tool this demo server exposes: uppercase the `text` argument.
fn shoutTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const text = call.strArg("text") orelse return call.fail("missing 'text'");
    var buf: [256]u8 = undefined;
    if (text.len > buf.len) return call.fail("text too long");
    for (text, 0..) |c, i| buf[i] = std.ascii.toUpper(c);
    call.print("{{\"result\":\"{s}\"}}", .{buf[0..text.len]});
    return false;
}

fn bodyOf(response: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return "";
    return response[i + 4 ..];
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var server = mcp.Server.init(gpa, .{ .name = "shout-demo", .version = "1.0" });
    defer server.deinit();
    try server.addTool(.{
        .name = "shout",
        .description = "Uppercase the given text.",
        .input_schema = "{\"type\":\"object\"}",
        .handler = shoutTool,
    });

    // Registering the same tool name twice is a caller mistake the server
    // has to reject by name, not silently overwrite the first registration.
    if (server.addTool(.{
        .name = "shout",
        .description = "duplicate",
        .input_schema = "{\"type\":\"object\"}",
        .handler = shoutTool,
    })) |_| {
        return error.DuplicateToolUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.DuplicateTool => std.debug.print("addTool(\"shout\" again): DuplicateTool (expected)\n", .{}),
        error.OutOfMemory => return err,
    }

    var transport = mcphttp.Transport{ .gpa = gpa, .server = &server };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [4096]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    var out_buf: [4096]u8 = undefined;

    const init_request =
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}
    ;
    const init_wire = std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ init_request.len, init_request },
    );

    var in1: std.Io.Reader = .fixed(init_wire);
    var out1: std.Io.Writer = .fixed(&out_buf);
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = &r,
        .server_name = null,
    }, &in1, &out1, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    std.debug.print("initialize response body: {s}\n", .{bodyOf(out1.buffered())});

    const call_request =
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shout","arguments":{"text":"hello"}}}
    ;
    const call_wire = std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ call_request.len, call_request },
    );

    var in2: std.Io.Reader = .fixed(call_wire);
    var out2_buf: [4096]u8 = undefined;
    var out2: std.Io.Writer = .fixed(&out2_buf);
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = &r,
        .server_name = null,
    }, &in2, &out2, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    const call_body = bodyOf(out2.buffered());
    std.debug.print("tools/call response body: {s}\n", .{call_body});
    if (std.mem.indexOf(u8, call_body, "\"HELLO\"") == null) return error.ToolCallResultMissingUppercasedText;
}
