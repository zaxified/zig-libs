// SPDX-License-Identifier: MIT

//! Response-side vocabulary for the Anthropic Messages API: the
//! non-streaming `Message` shape and the streaming `StreamEvent` union
//! (`message_start` / `content_block_start` / `content_block_delta` /
//! `content_block_stop` / `message_delta` / `message_stop`), plus the
//! parsers that build them from raw JSON bytes.
//!
//! Anthropic's polymorphic wire shapes (content blocks, deltas, stream
//! events) are all `{"type": "...", ...}` objects — a shape `std.json`'s
//! automatic `union(enum)` parsing does not support (it expects
//! `{"tagname": value}`). So parsing goes through `std.json.Value` first
//! (one arena-owned parse of the whole payload), then a manual walk
//! dispatching on each object's `"type"` string field — the same idiom
//! `acme.Client` and `jwt` use for ACME/JWT's polymorphic JSON.
//!
//! All parsed strings borrow from the `std.json.Value` tree, so every
//! entry point here takes an `arena: std.mem.Allocator` and the result is
//! only valid as long as that arena lives (`Client.create` /
//! `Client.EventIterator.next` manage this for you).

const std = @import("std");
const types = @import("types.zig");

pub const Role = types.Role;

pub const ParseError = error{
    OutOfMemory,
    /// The body was not the expected Anthropic Messages API JSON shape.
    MalformedResponse,
};

pub const Usage = struct {
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    cache_creation_input_tokens: ?u64 = null,
    cache_read_input_tokens: ?u64 = null,
};

/// `stop_reason`. `.unknown` absorbs any value this client doesn't
/// recognize yet (forward compatibility with new API stop reasons).
pub const StopReason = enum {
    end_turn,
    max_tokens,
    stop_sequence,
    tool_use,
    pause_turn,
    refusal,
    unknown,
};

/// `stop_details` — populated only when `stop_reason == .refusal`.
pub const StopDetails = struct {
    category: ?[]const u8 = null,
    explanation: ?[]const u8 = null,
};

/// An object whose `"type"` this client doesn't model yet — the whole
/// parsed object, for forward compatibility instead of a hard parse
/// failure.
pub const OtherBlock = struct { object: std.json.ObjectMap };

/// One entry of `Message.content`.
pub const ContentBlock = union(enum) {
    text: struct { text: []const u8 },
    thinking: struct { thinking: []const u8, signature: []const u8 },
    tool_use: struct { id: []const u8, name: []const u8, input: std.json.Value },
    other: OtherBlock,
};

/// A complete (non-streaming) `POST /v1/messages` response, or the
/// `message` object embedded in a `message_start` stream event (in which
/// case `content` is empty and `stop_reason` is null — it fills in over
/// the stream).
pub const Message = struct {
    id: []const u8,
    model: []const u8,
    role: Role,
    content: []const ContentBlock,
    stop_reason: ?StopReason,
    stop_sequence: ?[]const u8,
    stop_details: ?StopDetails,
    usage: Usage,
};

/// The initial state of a content block as announced by
/// `content_block_start` (text/thinking start empty; `tool_use` carries
/// its `id`/`name` immediately, `input` filling in via
/// `input_json_delta`s).
pub const ContentBlockStart = union(enum) {
    text: struct { text: []const u8 = "" },
    thinking: struct { thinking: []const u8 = "" },
    tool_use: struct { id: []const u8, name: []const u8, input: std.json.Value },
    other: OtherBlock,
};

pub const Delta = union(enum) {
    text_delta: struct { text: []const u8 },
    thinking_delta: struct { thinking: []const u8 },
    signature_delta: struct { signature: []const u8 },
    input_json_delta: struct { partial_json: []const u8 },
};

pub const MessageDelta = struct {
    stop_reason: ?StopReason = null,
    stop_sequence: ?[]const u8 = null,
};

pub const ErrorDetail = struct {
    type: []const u8 = "",
    message: []const u8 = "",
};

/// One parsed SSE `data:` payload, dispatched on its JSON `"type"` field.
pub const StreamEvent = union(enum) {
    message_start: struct { message: Message },
    content_block_start: struct { index: u32, content_block: ContentBlockStart },
    content_block_delta: struct { index: u32, delta: Delta },
    content_block_stop: struct { index: u32 },
    message_delta: struct { delta: MessageDelta, usage: ?Usage = null },
    message_stop,
    ping,
    @"error": struct { @"error": ErrorDetail },
};

// ── ObjectMap field helpers (mirrors acme.Client / jwt's manual-extraction
//    idiom for polymorphic JSON) ─────────────────────────────────────────────

fn strField(obj: std.json.ObjectMap, name: []const u8) []const u8 {
    const v = obj.get(name) orelse return "";
    return if (v == .string) v.string else "";
}

fn optStrField(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

fn u64Field(obj: std.json.ObjectMap, name: []const u8) u64 {
    const v = obj.get(name) orelse return 0;
    return switch (v) {
        .integer => |i| if (i < 0) 0 else @intCast(i),
        .float => |f| if (f < 0) 0 else @intFromFloat(f),
        else => 0,
    };
}

fn optU64Field(obj: std.json.ObjectMap, name: []const u8) ?u64 {
    if (obj.get(name) == null) return null;
    return u64Field(obj, name);
}

fn objField(obj: std.json.ObjectMap, name: []const u8) ?std.json.ObjectMap {
    const v = obj.get(name) orelse return null;
    return if (v == .object) v.object else null;
}

fn arrField(obj: std.json.ObjectMap, name: []const u8) []const std.json.Value {
    const v = obj.get(name) orelse return &.{};
    return if (v == .array) v.array.items else &.{};
}

fn stopReasonFromString(s: ?[]const u8) ?StopReason {
    const str = s orelse return null;
    return std.meta.stringToEnum(StopReason, str) orelse .unknown;
}

fn parseUsage(obj: std.json.ObjectMap) Usage {
    return .{
        .input_tokens = u64Field(obj, "input_tokens"),
        .output_tokens = u64Field(obj, "output_tokens"),
        .cache_creation_input_tokens = optU64Field(obj, "cache_creation_input_tokens"),
        .cache_read_input_tokens = optU64Field(obj, "cache_read_input_tokens"),
    };
}

fn parseContentBlock(obj: std.json.ObjectMap) ContentBlock {
    const t = strField(obj, "type");
    if (std.mem.eql(u8, t, "text")) return .{ .text = .{ .text = strField(obj, "text") } };
    if (std.mem.eql(u8, t, "thinking")) return .{ .thinking = .{
        .thinking = strField(obj, "thinking"),
        .signature = strField(obj, "signature"),
    } };
    if (std.mem.eql(u8, t, "tool_use")) return .{ .tool_use = .{
        .id = strField(obj, "id"),
        .name = strField(obj, "name"),
        .input = obj.get("input") orelse .null,
    } };
    return .{ .other = .{ .object = obj } };
}

fn parseContentBlockStart(obj: std.json.ObjectMap) ContentBlockStart {
    const t = strField(obj, "type");
    if (std.mem.eql(u8, t, "text")) return .{ .text = .{ .text = strField(obj, "text") } };
    if (std.mem.eql(u8, t, "thinking")) return .{ .thinking = .{ .thinking = strField(obj, "thinking") } };
    if (std.mem.eql(u8, t, "tool_use")) return .{ .tool_use = .{
        .id = strField(obj, "id"),
        .name = strField(obj, "name"),
        .input = obj.get("input") orelse .null,
    } };
    return .{ .other = .{ .object = obj } };
}

fn parseDelta(obj: std.json.ObjectMap) ParseError!Delta {
    const t = strField(obj, "type");
    if (std.mem.eql(u8, t, "text_delta")) return .{ .text_delta = .{ .text = strField(obj, "text") } };
    if (std.mem.eql(u8, t, "thinking_delta")) return .{ .thinking_delta = .{ .thinking = strField(obj, "thinking") } };
    if (std.mem.eql(u8, t, "signature_delta")) return .{ .signature_delta = .{ .signature = strField(obj, "signature") } };
    if (std.mem.eql(u8, t, "input_json_delta")) return .{ .input_json_delta = .{ .partial_json = strField(obj, "partial_json") } };
    return error.MalformedResponse;
}

fn messageFromObject(arena: std.mem.Allocator, obj: std.json.ObjectMap) Message {
    const items = arrField(obj, "content");
    var content: []ContentBlock = &.{};
    if (items.len != 0) {
        // `obj`'s strings/arrays already live in the caller's arena (they
        // came from one `std.json.Value` parse); the content slice we
        // build here just needs the same arena to allocate into.
        const buf: []ContentBlock = arena.alloc(ContentBlock, items.len) catch &.{};
        for (items, 0..) |item, i| {
            buf[i] = if (item == .object) parseContentBlock(item.object) else .{ .other = .{ .object = .empty } };
        }
        content = buf;
    }

    var stop_details: ?StopDetails = null;
    if (objField(obj, "stop_details")) |sd| {
        stop_details = .{
            .category = optStrField(sd, "category"),
            .explanation = optStrField(sd, "explanation"),
        };
    }

    var usage: Usage = .{};
    if (objField(obj, "usage")) |u| usage = parseUsage(u);

    return .{
        .id = strField(obj, "id"),
        .model = strField(obj, "model"),
        .role = if (std.mem.eql(u8, strField(obj, "role"), "user")) .user else .assistant,
        .content = content,
        .stop_reason = stopReasonFromString(optStrField(obj, "stop_reason")),
        .stop_sequence = optStrField(obj, "stop_sequence"),
        .stop_details = stop_details,
        .usage = usage,
    };
}

/// Parse a complete `POST /v1/messages` JSON response body. `arena` backs
/// every string/slice in the result (they borrow from the parsed
/// `std.json.Value` tree).
pub fn parseMessage(arena: std.mem.Allocator, body: []const u8) ParseError!Message {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (root != .object) return error.MalformedResponse;
    return messageFromObject(arena, root.object);
}

/// Parse one SSE `data:` payload (already joined/trimmed by `sse_parse`)
/// into the matching `StreamEvent` variant, dispatching on its `"type"`
/// field.
pub fn parseStreamEvent(arena: std.mem.Allocator, data: []const u8) ParseError!StreamEvent {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, data, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (root != .object) return error.MalformedResponse;
    const obj = root.object;
    const t = strField(obj, "type");

    if (std.mem.eql(u8, t, "message_start")) {
        const msg_obj = objField(obj, "message") orelse return error.MalformedResponse;
        return .{ .message_start = .{ .message = messageFromObject(arena, msg_obj) } };
    }
    if (std.mem.eql(u8, t, "content_block_start")) {
        const cb = objField(obj, "content_block") orelse return error.MalformedResponse;
        return .{ .content_block_start = .{
            .index = @intCast(u64Field(obj, "index")),
            .content_block = parseContentBlockStart(cb),
        } };
    }
    if (std.mem.eql(u8, t, "content_block_delta")) {
        const d = objField(obj, "delta") orelse return error.MalformedResponse;
        return .{ .content_block_delta = .{
            .index = @intCast(u64Field(obj, "index")),
            .delta = try parseDelta(d),
        } };
    }
    if (std.mem.eql(u8, t, "content_block_stop")) {
        return .{ .content_block_stop = .{ .index = @intCast(u64Field(obj, "index")) } };
    }
    if (std.mem.eql(u8, t, "message_delta")) {
        const d = objField(obj, "delta") orelse return error.MalformedResponse;
        const usage: ?Usage = if (objField(obj, "usage")) |u| parseUsage(u) else null;
        return .{ .message_delta = .{
            .delta = .{
                .stop_reason = stopReasonFromString(optStrField(d, "stop_reason")),
                .stop_sequence = optStrField(d, "stop_sequence"),
            },
            .usage = usage,
        } };
    }
    if (std.mem.eql(u8, t, "message_stop")) return .message_stop;
    if (std.mem.eql(u8, t, "ping")) return .ping;
    if (std.mem.eql(u8, t, "error")) {
        const e = objField(obj, "error") orelse return error.MalformedResponse;
        return .{ .@"error" = .{ .@"error" = .{ .type = strField(e, "type"), .message = strField(e, "message") } } };
    }
    return error.MalformedResponse;
}

// ── tests (offline, canned response bodies) ─────────────────────────────────

const testing = std.testing;

test "parseMessage: tool_use block and stop_reason refusal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const body =
        \\{"id":"msg_01ABC","type":"message","role":"assistant","model":"claude-opus-4-8",
        \\"content":[
        \\  {"type":"text","text":"Let me check that."},
        \\  {"type":"tool_use","id":"toolu_01XYZ","name":"get_weather","input":{"location":"Paris"}}
        \\],
        \\"stop_reason":"refusal","stop_sequence":null,
        \\"stop_details":{"type":"refusal","category":"cyber","explanation":"policy"},
        \\"usage":{"input_tokens":15,"output_tokens":32,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}
    ;
    const msg = try parseMessage(arena.allocator(), body);

    try testing.expectEqualStrings("msg_01ABC", msg.id);
    try testing.expectEqualStrings("claude-opus-4-8", msg.model);
    try testing.expectEqual(Role.assistant, msg.role);
    try testing.expectEqual(@as(usize, 2), msg.content.len);
    try testing.expectEqualStrings("Let me check that.", msg.content[0].text.text);
    try testing.expectEqualStrings("toolu_01XYZ", msg.content[1].tool_use.id);
    try testing.expectEqualStrings("get_weather", msg.content[1].tool_use.name);
    try testing.expectEqualStrings("Paris", msg.content[1].tool_use.input.object.get("location").?.string);
    try testing.expectEqual(StopReason.refusal, msg.stop_reason.?);
    try testing.expect(msg.stop_sequence == null);
    try testing.expectEqualStrings("cyber", msg.stop_details.?.category.?);
    try testing.expectEqualStrings("policy", msg.stop_details.?.explanation.?);
    try testing.expectEqual(@as(u64, 15), msg.usage.input_tokens);
    try testing.expectEqual(@as(u64, 32), msg.usage.output_tokens);
}

test "parseMessage: unrecognized content block type falls back to .other" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":"msg_2","model":"claude-opus-4-8","role":"assistant",
        \\"content":[{"type":"some_future_block","weird":"field"}],
        \\"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}
    ;
    const msg = try parseMessage(arena.allocator(), body);
    try testing.expectEqual(StopReason.end_turn, msg.stop_reason.?);
    try testing.expect(msg.content[0] == .other);
}

test "parseStreamEvent: full sequence via sse_parse (message_start .. message_stop)" {
    const sse_parse = @import("sse_parse.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const wire = "event: message_start\n" ++
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\"," ++
        "\"role\":\"assistant\",\"model\":\"claude-opus-4-8\",\"content\":[],\"stop_reason\":null," ++
        "\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n" ++
        "\n" ++
        "event: content_block_start\n" ++
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n" ++
        "\n" ++
        "event: content_block_delta\n" ++
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n" ++
        "\n" ++
        "event: content_block_stop\n" ++
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n" ++
        "\n" ++
        "event: message_delta\n" ++
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":12}}\n" ++
        "\n" ++
        "event: message_stop\n" ++
        "data: {\"type\":\"message_stop\"}\n" ++
        "\n";

    var reader: std.Io.Reader = .fixed(wire);
    var p = sse_parse.Parser.init(&reader, testing.allocator);
    defer p.deinit();

    const raw1 = (try p.next()).?;
    const ev1 = try parseStreamEvent(arena.allocator(), raw1.data);
    try testing.expectEqualStrings("msg_1", ev1.message_start.message.id);
    try testing.expectEqual(@as(usize, 0), ev1.message_start.message.content.len);

    const raw2 = (try p.next()).?;
    const ev2 = try parseStreamEvent(arena.allocator(), raw2.data);
    try testing.expect(ev2.content_block_start.content_block == .text);

    const raw3 = (try p.next()).?;
    const ev3 = try parseStreamEvent(arena.allocator(), raw3.data);
    try testing.expectEqualStrings("Hello", ev3.content_block_delta.delta.text_delta.text);

    const raw4 = (try p.next()).?;
    const ev4 = try parseStreamEvent(arena.allocator(), raw4.data);
    try testing.expectEqual(@as(u32, 0), ev4.content_block_stop.index);

    const raw5 = (try p.next()).?;
    const ev5 = try parseStreamEvent(arena.allocator(), raw5.data);
    try testing.expectEqual(StopReason.end_turn, ev5.message_delta.delta.stop_reason.?);
    try testing.expectEqual(@as(u64, 12), ev5.message_delta.usage.?.output_tokens);

    const raw6 = (try p.next()).?;
    const ev6 = try parseStreamEvent(arena.allocator(), raw6.data);
    try testing.expect(ev6 == .message_stop);

    try testing.expect((try p.next()) == null);
}

test "parseStreamEvent: tool_use content_block_start + input_json_delta + error event" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const start = try parseStreamEvent(a,
        \\{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_9","name":"get_weather","input":{}}}
    );
    try testing.expectEqualStrings("toolu_9", start.content_block_start.content_block.tool_use.id);

    const delta = try parseStreamEvent(a,
        \\{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"Paris\"}"}}
    );
    try testing.expectEqualStrings("{\"location\": \"Paris\"}", delta.content_block_delta.delta.input_json_delta.partial_json);

    const err_ev = try parseStreamEvent(a,
        \\{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}
    );
    try testing.expectEqualStrings("overloaded_error", err_ev.@"error".@"error".type);

    const ping_ev = try parseStreamEvent(a, "{\"type\":\"ping\"}");
    try testing.expect(ping_ev == .ping);
}
