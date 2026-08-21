// SPDX-License-Identifier: MIT

//! What a consumer does with `llmclient`'s request/response vocabulary:
//! build a tool-augmented `MessageRequest`, serialize it to the exact wire
//! JSON `POST /v1/messages` expects, then parse a response body (as
//! `http.Client.Response.reader()` would hand it to `Client.create`)
//! carrying a tool-use block, and finally walk a streaming event sequence
//! the way `Client.stream`'s `EventIterator` would deliver it.
//!
//! Deliberately offline: this exercises the request/response codec, which
//! is the part every consumer must get right regardless of transport
//! (`Client.create`/`Client.stream` are thin wrappers over it, wired to a
//! real `http.Client` — the module's own tests reach those with a
//! `base_url` override, not a live API call).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to build/parse a message is not public, or an error cannot be
//! named from outside, this file stops compiling.

const std = @import("std");
const llmclient = @import("llmclient");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── build + serialize a tool-augmented request ──────────────────────────
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var props: std.json.ObjectMap = .empty;
    var city_type: std.json.ObjectMap = .empty;
    try city_type.put(arena, "type", .{ .string = "string" });
    try props.put(arena, "city", .{ .object = city_type });
    var schema: std.json.ObjectMap = .empty;
    try schema.put(arena, "type", .{ .string = "object" });
    try schema.put(arena, "properties", .{ .object = props });

    const request: llmclient.MessageRequest = .{
        .max_tokens = 256,
        .system = "Answer tersely.",
        .messages = &.{llmclient.MessageParam.user(&.{llmclient.textBlock("What's the weather in Prague?")})},
        .tools = &.{.{
            .name = "get_weather",
            .description = "Look up current weather for a city",
            .input_schema = .{ .object = schema },
        }},
    };
    const wire_body = try llmclient.stringifyRequestAlloc(gpa, request);
    defer gpa.free(wire_body);
    std.debug.print("request body ({d} bytes): {s}\n", .{ wire_body.len, wire_body });

    // ── parse a non-streaming response carrying a tool call ─────────────────
    // Stands in for the body `http.Client.Response.reader()` would hand
    // `Client.create` — this example never opens a socket.
    const response_body =
        \\{"id":"msg_01ABC","model":"claude-opus-4-8","role":"assistant",
        \\"content":[
        \\  {"type":"text","text":"Let me check that."},
        \\  {"type":"tool_use","id":"toolu_01XYZ","name":"get_weather","input":{"city":"Prague"}}
        \\],
        \\"stop_reason":"tool_use","usage":{"input_tokens":42,"output_tokens":18}}
    ;
    const message = try llmclient.parseMessage(arena, response_body);
    for (message.content) |block| switch (block) {
        .text => |t| std.debug.print("assistant said: {s}\n", .{t.text}),
        .tool_use => |tu| std.debug.print("tool call: {s}({s})\n", .{ tu.name, tu.input.object.get("city").?.string }),
        else => {},
    };
    if (message.stop_reason != .tool_use) @panic("expected the model to stop for a tool call");

    // ── walk a streaming event sequence ──────────────────────────────────────
    const stream_events = [_][]const u8{
        \\{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
        ,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"7"}}
        ,
        \\{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"C, cloudy"}}
        ,
        \\{"type":"content_block_stop","index":0}
        ,
        \\{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}
        ,
        \\{"type":"message_stop"}
        ,
    };
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    for (stream_events) |raw| {
        const ev = try llmclient.parseStreamEvent(arena, raw);
        switch (ev) {
            .content_block_delta => |d| switch (d.delta) {
                .text_delta => |t| try text.appendSlice(gpa, t.text),
                else => {},
            },
            .message_stop => std.debug.print("stream complete\n", .{}),
            else => {},
        }
    }
    std.debug.print("streamed text: {s}\n", .{text.items});

    // A malformed event (unrecognized top-level "type") is a named error, not
    // a crash — the boundary a consumer feeding untrusted SSE bytes relies on.
    _ = llmclient.parseStreamEvent(arena, "{\"type\":\"some_future_event\"}") catch |err| switch (err) {
        error.MalformedResponse => std.debug.print("unrecognized event type correctly rejected\n", .{}),
        error.OutOfMemory => return err,
    };
}
