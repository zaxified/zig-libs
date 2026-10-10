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
    /// `citations` is the block's raw citation objects (`char_location`,
    /// `page_location`, `content_block_location`, …, each dispatched on its
    /// own `"type"`), empty when the response carries none — present only
    /// when a request document had `citations = .{ .enabled = true }`.
    text: struct { text: []const u8, citations: []const std.json.Value = &.{} },
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
    /// One citation to append to the current `text` block's citations
    /// (the streaming form of `ContentBlock.text.citations`): the raw
    /// citation object, dispatched on its own `"type"`.
    citations_delta: struct { citation: std.json.ObjectMap },
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

/// A non-negative integer field (token counts, block indexes). Absent or
/// non-numeric → 0 (the field is optional on the wire); present but not
/// representable — negative, a float at or above 2^64, NaN — →
/// `MalformedResponse`. These used to be `@intCast`/`@intFromFloat` on the
/// raw value, which is a panic in Debug/ReleaseSafe and a silently wrong
/// number in ReleaseFast — on `index` (what a caller indexes its content
/// blocks by) and on `usage` (what it bills by). Measured 2026-09-06 with
/// `"index":4294967296` and `"input_tokens":1e300`: exit 134 in both safe
/// modes, `index=0` / `input_tokens=9223372036854775808` in ReleaseFast.
fn u64Field(obj: std.json.ObjectMap, name: []const u8) ParseError!u64 {
    const v = obj.get(name) orelse return 0;
    return switch (v) {
        .integer => |i| if (i < 0) error.MalformedResponse else @intCast(i),
        .float => |f| blk: {
            // 2^64 as f64 is exact; anything at or above it, or negative,
            // or NaN (which fails every comparison) has no u64 value.
            if (!(f >= 0.0 and f < 18446744073709551616.0)) return error.MalformedResponse;
            break :blk @intFromFloat(f);
        },
        // `1e400` parses as +inf under `std.json` → rejected above; a
        // number too long for the parser's own limits arrives as
        // `.number_string` and is not a count this client can use.
        .number_string => error.MalformedResponse,
        else => 0,
    };
}

fn optU64Field(obj: std.json.ObjectMap, name: []const u8) ParseError!?u64 {
    if (obj.get(name) == null) return null;
    return try u64Field(obj, name);
}

/// A content-block `index`: `u64Field` narrowed to the `u32` the
/// `StreamEvent` carries, `MalformedResponse` past it.
fn indexField(obj: std.json.ObjectMap) ParseError!u32 {
    const v = try u64Field(obj, "index");
    if (v > std.math.maxInt(u32)) return error.MalformedResponse;
    return @intCast(v);
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

fn parseUsage(obj: std.json.ObjectMap) ParseError!Usage {
    return .{
        .input_tokens = try u64Field(obj, "input_tokens"),
        .output_tokens = try u64Field(obj, "output_tokens"),
        .cache_creation_input_tokens = try optU64Field(obj, "cache_creation_input_tokens"),
        .cache_read_input_tokens = try optU64Field(obj, "cache_read_input_tokens"),
    };
}

fn parseContentBlock(obj: std.json.ObjectMap) ContentBlock {
    const t = strField(obj, "type");
    if (std.mem.eql(u8, t, "text")) return .{ .text = .{
        .text = strField(obj, "text"),
        .citations = arrField(obj, "citations"),
    } };
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
    if (std.mem.eql(u8, t, "citations_delta")) return .{ .citations_delta = .{
        .citation = objField(obj, "citation") orelse return error.MalformedResponse,
    } };
    return error.MalformedResponse;
}

fn messageFromObject(arena: std.mem.Allocator, obj: std.json.ObjectMap) ParseError!Message {
    const items = arrField(obj, "content");
    var content: []ContentBlock = &.{};
    if (items.len != 0) {
        // `obj`'s strings/arrays already live in the caller's arena (they
        // came from one `std.json.Value` parse); the content slice we
        // build here just needs the same arena to allocate into.
        const buf: []ContentBlock = try arena.alloc(ContentBlock, items.len);
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
    if (objField(obj, "usage")) |u| usage = try parseUsage(u);

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
    return try messageFromObject(arena, root.object);
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
        return .{ .message_start = .{ .message = try messageFromObject(arena, msg_obj) } };
    }
    if (std.mem.eql(u8, t, "content_block_start")) {
        const cb = objField(obj, "content_block") orelse return error.MalformedResponse;
        return .{ .content_block_start = .{
            .index = try indexField(obj),
            .content_block = parseContentBlockStart(cb),
        } };
    }
    if (std.mem.eql(u8, t, "content_block_delta")) {
        const d = objField(obj, "delta") orelse return error.MalformedResponse;
        return .{ .content_block_delta = .{
            .index = try indexField(obj),
            .delta = try parseDelta(d),
        } };
    }
    if (std.mem.eql(u8, t, "content_block_stop")) {
        return .{ .content_block_stop = .{ .index = try indexField(obj) } };
    }
    if (std.mem.eql(u8, t, "message_delta")) {
        const d = objField(obj, "delta") orelse return error.MalformedResponse;
        const usage: ?Usage = if (objField(obj, "usage")) |u| try parseUsage(u) else null;
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

/// A `POST /v1/messages/count_tokens` response: `{"input_tokens": N}`.
pub const TokenCount = struct {
    input_tokens: u64,
};

/// Parse a `count_tokens` response body. `input_tokens` is required here
/// (it is the whole answer — a body without it is not a count, and 0 would
/// be a wrong one): absent, non-numeric, negative, ≥ 2^64 or not finite
/// is `MalformedResponse`. Other fields are ignored (forward
/// compatibility). Nothing in the result borrows from `arena`.
pub fn parseTokenCount(arena: std.mem.Allocator, body: []const u8) ParseError!TokenCount {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedResponse,
    };
    if (root != .object) return error.MalformedResponse;
    const v = root.object.get("input_tokens") orelse return error.MalformedResponse;
    if (v != .integer and v != .float and v != .number_string) return error.MalformedResponse;
    return .{ .input_tokens = try u64Field(root.object, "input_tokens") };
}

// ── tests (offline, canned response bodies) ─────────────────────────────────

const testing = std.testing;

test "external anchor: token-counting docs outputs parse to the documented counts" {
    // The `json Output` blocks of
    // platform.claude.com/docs/en/build-with-claude/token-counting.md
    // (fetched 2026-10-06), verbatim.
    const cases = [_]struct { body: []const u8, want: u64 }{
        .{ .body = "{ \"input_tokens\": 14 }", .want = 14 },
        .{ .body = "{ \"input_tokens\": 403 }", .want = 403 },
        .{ .body = "{ \"input_tokens\": 1028 }", .want = 1028 },
        .{ .body = "{ \"input_tokens\": 88 }", .want = 88 },
        .{ .body = "{ \"input_tokens\": 2188 }", .want = 2188 },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        try testing.expectEqual(c.want, (try parseTokenCount(arena.allocator(), c.body)).input_tokens);
    }
}

test "parseTokenCount: a body that is not a count is MalformedResponse, never 0 or a panic" {
    const bad = [_][]const u8{
        "{}",
        "{\"input_tokens\":null}",
        "{\"input_tokens\":\"14\"}",
        "{\"input_tokens\":-1}",
        "{\"input_tokens\":1e300}",
        "{\"input_tokens\":18446744073709551616}",
        "[14]",
        "14",
        "{\"input_tokens\":14",
        "",
    };
    for (bad) |body| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        try testing.expectError(error.MalformedResponse, parseTokenCount(arena.allocator(), body));
    }
    // Unknown extra fields are tolerated; 0 and u64 max are counts.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(@as(u64, 0), (try parseTokenCount(arena.allocator(), "{\"input_tokens\":0,\"future\":{}}")).input_tokens);
    try testing.expectEqual(@as(u64, 7), (try parseTokenCount(arena.allocator(), "{\"input_tokens\":7.0}")).input_tokens);
}

test "parseMessage: image and document blocks echoed in a response are tolerated as .other (SELF-DERIVED body)" {
    // The block shapes are the ones this module sends (anchored in
    // types.zig); a response carrying them back must not fail the parse.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":"msg_4","model":"claude-opus-5-5","role":"assistant","content":[
        \\{"type":"image","source":{"type":"base64","media_type":"image/png","data":"QUJD"}},
        \\{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"QUJD"},"title":"t"},
        \\{"type":"text","text":"after"}],
        \\"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}
    ;
    const msg = try parseMessage(arena.allocator(), body);
    try testing.expectEqual(@as(usize, 3), msg.content.len);
    try testing.expectEqualStrings("image", msg.content[0].other.object.get("type").?.string);
    try testing.expectEqualStrings("document", msg.content[1].other.object.get("type").?.string);
    try testing.expectEqualStrings("after", msg.content[2].text.text);

    const ev = try parseStreamEvent(arena.allocator(),
        \\{"type":"content_block_start","index":0,"content_block":{"type":"image","source":{"type":"url","url":"https://x"}}}
    );
    try testing.expect(ev.content_block_start.content_block == .other);
}

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

test "parseMessage: unrecognized stop_reason forward-compats to .unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":"msg_3","model":"claude-opus-4-8","role":"assistant","content":[],
        \\"stop_reason":"some_future_reason","usage":{"input_tokens":1,"output_tokens":1}}
    ;
    const msg = try parseMessage(arena.allocator(), body);
    try testing.expectEqual(StopReason.unknown, msg.stop_reason.?);
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

// ── external anchor: Anthropic's own published SSE example ─────────────────
//
// Every other stream-parsing test above uses a hand-built wire string this
// module's own author wrote to match a mental model of the docs — an
// in-house re-derivation, not an external anchor. The test below instead
// embeds, byte-for-byte, the "Basic streaming request" response example
// published at https://platform.claude.com/docs/en/build-with-claude/streaming.md
// (fetched 2026-08-01), including its `ping` event (not exercised by any
// hand-built fixture above) and runs it through this module's own
// sse_parse.Parser + parseStreamEvent, asserting the documented literal
// values (message id, model, token counts, delta text, stop_reason). This
// is a genuine external anchor for the SSE wire format and this module's
// parsing of it — not an in-house re-derivation, and not a paid API call
// (no network access, no API key, this is a frozen copy of public
// documentation). RFC/spec citation for the SSE framing itself lives in
// sse_parse.zig's own doc comment (WHATWG "server-sent events").
test "external anchor: Anthropic's own published basic-streaming SSE example parses byte-exact" {
    const sse_parse = @import("sse_parse.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Copied verbatim (whitespace and all) from the "Basic streaming
    // request" -> "Response" code block, streaming.md, fetched 2026-08-01.
    const wire = "event: message_start\n" ++
        "data: {\"type\": \"message_start\", \"message\": {\"id\": \"msg_1nZdL29xx5MUA1yADyHTEsnR8uuvGzszyY\", \"type\": \"message\", \"role\": \"assistant\", \"content\": [], \"model\": \"claude-opus-5\", \"stop_reason\": null, \"stop_sequence\": null, \"usage\": {\"input_tokens\": 25, \"output_tokens\": 1}}}\n" ++
        "\n" ++
        "event: content_block_start\n" ++
        "data: {\"type\": \"content_block_start\", \"index\": 0, \"content_block\": {\"type\": \"text\", \"text\": \"\"}}\n" ++
        "\n" ++
        "event: ping\n" ++
        "data: {\"type\": \"ping\"}\n" ++
        "\n" ++
        "event: content_block_delta\n" ++
        "data: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"Hello\"}}\n" ++
        "\n" ++
        "event: content_block_delta\n" ++
        "data: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"!\"}}\n" ++
        "\n" ++
        "event: content_block_stop\n" ++
        "data: {\"type\": \"content_block_stop\", \"index\": 0}\n" ++
        "\n" ++
        "event: message_delta\n" ++
        "data: {\"type\": \"message_delta\", \"delta\": {\"stop_reason\": \"end_turn\", \"stop_sequence\":null}, \"usage\": {\"output_tokens\": 15}}\n" ++
        "\n" ++
        "event: message_stop\n" ++
        "data: {\"type\": \"message_stop\"}\n" ++
        "\n";

    var reader: std.Io.Reader = .fixed(wire);
    var p = sse_parse.Parser.init(&reader, testing.allocator);
    defer p.deinit();

    const raw1 = (try p.next()).?;
    const ev1 = try parseStreamEvent(arena.allocator(), raw1.data);
    try testing.expectEqualStrings("msg_1nZdL29xx5MUA1yADyHTEsnR8uuvGzszyY", ev1.message_start.message.id);
    try testing.expectEqualStrings("claude-opus-5", ev1.message_start.message.model);
    try testing.expectEqual(@as(u64, 25), ev1.message_start.message.usage.input_tokens);
    try testing.expectEqual(@as(u64, 1), ev1.message_start.message.usage.output_tokens);
    try testing.expectEqual(@as(usize, 0), ev1.message_start.message.content.len);

    const raw2 = (try p.next()).?;
    const ev2 = try parseStreamEvent(arena.allocator(), raw2.data);
    try testing.expect(ev2.content_block_start.content_block == .text);

    // The published example's `ping` event, not present in any hand-built
    // fixture above -- proves this module handles a real documented
    // keep-alive event, not just ones its own author thought to write.
    const raw3 = (try p.next()).?;
    const ev3 = try parseStreamEvent(arena.allocator(), raw3.data);
    try testing.expect(ev3 == .ping);

    const raw4 = (try p.next()).?;
    const ev4 = try parseStreamEvent(arena.allocator(), raw4.data);
    try testing.expectEqualStrings("Hello", ev4.content_block_delta.delta.text_delta.text);

    const raw5 = (try p.next()).?;
    const ev5 = try parseStreamEvent(arena.allocator(), raw5.data);
    try testing.expectEqualStrings("!", ev5.content_block_delta.delta.text_delta.text);

    const raw6 = (try p.next()).?;
    const ev6 = try parseStreamEvent(arena.allocator(), raw6.data);
    try testing.expectEqual(@as(u32, 0), ev6.content_block_stop.index);

    const raw7 = (try p.next()).?;
    const ev7 = try parseStreamEvent(arena.allocator(), raw7.data);
    try testing.expectEqual(StopReason.end_turn, ev7.message_delta.delta.stop_reason.?);
    try testing.expectEqual(@as(u64, 15), ev7.message_delta.usage.?.output_tokens);

    const raw8 = (try p.next()).?;
    const ev8 = try parseStreamEvent(arena.allocator(), raw8.data);
    try testing.expect(ev8 == .message_stop);

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

test "parseStreamEvent/parseMessage: an index or count the type cannot hold is MalformedResponse, never a panic or a wrong number (A1 F2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The edge that fits, then the four shapes that used to panic in
    // Debug/ReleaseSafe and truncate in ReleaseFast.
    const ok = try parseStreamEvent(a, "{\"type\":\"content_block_stop\",\"index\":4294967295}");
    try testing.expectEqual(@as(u32, 4294967295), ok.content_block_stop.index);
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"content_block_stop\",\"index\":4294967296}"));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"content_block_stop\",\"index\":9223372036854775807}"));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"content_block_delta\",\"index\":1000000000000000000,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}"));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1e300}}}"));
    // Negative and non-finite counts are not counts; `1e400` is +inf.
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"content_block_stop\",\"index\":-1}"));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":-5}}"));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "{\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":1e400}}"));
    try testing.expectError(error.MalformedResponse, parseMessage(a, "{\"id\":\"m\",\"content\":[],\"usage\":{\"input_tokens\":1e300}}"));
    // A float that is a whole number in range is accepted as that number.
    const f = try parseStreamEvent(a, "{\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":12.0}}");
    try testing.expectEqual(@as(u64, 12), f.message_delta.usage.?.output_tokens);
}

test "parseStreamEvent: unrecognized top-level type is a MalformedResponse error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.MalformedResponse,
        parseStreamEvent(arena.allocator(), "{\"type\":\"some_future_event\"}"),
    );
}

test "parseStreamEvent: missing content_block on content_block_start is a MalformedResponse error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.MalformedResponse,
        parseStreamEvent(arena.allocator(), "{\"type\":\"content_block_start\",\"index\":0}"),
    );
}

// ── regression: mutation-ladder gaps from A1 (F18, F19) ─────────────────────
//
// Each guard below already existed in the code; none had a test that would
// fail if the guard were deleted or weakened (the A1 mutational ladder
// M25/M27/M29/M32/M33 all survived — the check ran, but nothing was
// watching it run).

test "parseMessage/parseStreamEvent: a non-object top-level JSON value is MalformedResponse, not a union-tag confusion (A1 F18, M25)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "[1,2,3]"));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "\"just a string\""));
    try testing.expectError(error.MalformedResponse, parseStreamEvent(a, "42"));
    try testing.expectError(error.MalformedResponse, parseMessage(a, "[1,2,3]"));
}

test "parseStreamEvent: an unrecognized delta type is MalformedResponse, not an empty text_delta (A1 F18, M27)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.MalformedResponse,
        parseStreamEvent(arena.allocator(),
            \\{"type":"content_block_delta","index":0,"delta":{"type":"some_future_delta"}}
        ),
    );
}

// Review 2026-10-06 (PR #5): `DocumentBlock.citations` let a request turn
// citations on, but the parser knew neither form the answer comes back in —
// a streamed `citations_delta` was `MalformedResponse` (the stream died at the
// first citation) and a non-streaming text block's `citations` array was
// dropped. Both shapes below are the citations docs' own examples
// (`build-with-claude/citations.md`, § Response structure / Streaming support;
// the streaming one's elided `...` filled with the char_location fields).

test "parseStreamEvent: a citations_delta carries its citation object" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ev = try parseStreamEvent(arena.allocator(),
        \\{"type": "content_block_delta", "index": 0,
        \\ "delta": {"type": "citations_delta",
        \\           "citation": {
        \\               "type": "char_location",
        \\               "cited_text": "The grass is green.",
        \\               "document_index": 0,
        \\               "document_title": "Example Document",
        \\               "start_char_index": 0,
        \\               "end_char_index": 20
        \\           }}}
    );
    const c = ev.content_block_delta.delta.citations_delta.citation;
    try testing.expectEqual(@as(u32, 0), ev.content_block_delta.index);
    try testing.expectEqualStrings("char_location", c.get("type").?.string);
    try testing.expectEqualStrings("The grass is green.", c.get("cited_text").?.string);
    try testing.expectEqual(@as(i64, 20), c.get("end_char_index").?.integer);
    // A citations_delta without its citation object is malformed, not empty.
    try testing.expectError(error.MalformedResponse, parseStreamEvent(arena.allocator(),
        \\{"type":"content_block_delta","index":0,"delta":{"type":"citations_delta"}}
    ));
}

test "parseMessage: a text block keeps its citations array" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":"m","model":"m","role":"assistant","usage":{"input_tokens":1,"output_tokens":1},
        \\ "content": [
        \\    { "type": "text", "text": "According to the document, " },
        \\    {
        \\      "type": "text",
        \\      "text": "the grass is green",
        \\      "citations": [
        \\        {
        \\          "type": "char_location",
        \\          "cited_text": "The grass is green.",
        \\          "document_index": 0,
        \\          "document_title": "Example Document",
        \\          "start_char_index": 0,
        \\          "end_char_index": 20
        \\        }
        \\      ]
        \\    },
        \\    {
        \\      "type": "text",
        \\      "text": "water is essential",
        \\      "citations": [
        \\        {
        \\          "type": "page_location",
        \\          "cited_text": "Water is essential for life.",
        \\          "document_index": 1,
        \\          "document_title": "PDF Document",
        \\          "start_page_number": 5,
        \\          "end_page_number": 6
        \\        }
        \\      ]
        \\    }
        \\ ]}
    ;
    const msg = try parseMessage(arena.allocator(), body);
    try testing.expectEqual(@as(usize, 3), msg.content.len);
    try testing.expectEqual(@as(usize, 0), msg.content[0].text.citations.len);
    const c1 = msg.content[1].text.citations;
    try testing.expectEqual(@as(usize, 1), c1.len);
    try testing.expectEqualStrings("char_location", c1[0].object.get("type").?.string);
    try testing.expectEqualStrings("the grass is green", msg.content[1].text.text);
    const c2 = msg.content[2].text.citations;
    try testing.expectEqualStrings("page_location", c2[0].object.get("type").?.string);
    try testing.expectEqual(@as(i64, 5), c2[0].object.get("start_page_number").?.integer);
}

test "parseStreamEvent: message_start with no message object is a MalformedResponse error (A1 F18, M29)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.MalformedResponse,
        parseStreamEvent(arena.allocator(), "{\"type\":\"message_start\"}"),
    );
}

test "parseMessage: role \"user\" parses to .user, not the .assistant fallback (A1 F19, M32)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":"m","model":"m","role":"user","content":[],
        \\"usage":{"input_tokens":1,"output_tokens":1}}
    ;
    const msg = try parseMessage(arena.allocator(), body);
    try testing.expectEqual(Role.user, msg.role);
}

test "parseMessage: a non-string JSON value on a string field is treated as empty, not stringified (A1 F19, M33)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"id":123,"model":"m","role":"assistant","content":[],
        \\"usage":{"input_tokens":1,"output_tokens":1}}
    ;
    const msg = try parseMessage(arena.allocator(), body);
    try testing.expectEqualStrings("", msg.id);
}

// ── fuzz: untrusted JSON bytes never panic ──────────────────────────────────

// `smith.slice`, not `bytes` + a ranged length (that pair always yields the
// empty input), and seeds that reach the typed walk — without them the
// harnesses saw one empty string each (A1 F9).
const fz = @import("fuzz_test.zig");
const MsgMark = fz.Marker(enum { accepted, refused, text_block, tool_block, genuine });
const EvMark = fz.Marker(enum { accepted, refused, delta, start, stop, message_delta, error_event, genuine });
const TokMark = fz.Marker(enum { accepted, refused, genuine });

const message_corpus = [_][]const u8{
    "{\"id\":\"msg_1\",\"model\":\"m\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}",
    "{\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"n\",\"input\":{}}],\"usage\":{\"input_tokens\":1e300}}",
    "{\"content\":[1,2,3],\"stop_details\":{\"category\":5}}",
};
const event_corpus = [_][]const u8{
    "{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}",
    "{\"type\":\"content_block_stop\",\"index\":4294967296}",
    "{\"type\":\"content_block_stop\",\"index\":3}",
    "{\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":-1}}}",
    "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":12}}",
    "{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"x\"}}",
    "{\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
};
const token_corpus = [_][]const u8{
    "{ \"input_tokens\": 14 }",
    "{\"input_tokens\":1e300}",
    "{\"input_tokens\":-1,\"x\":[1,{\"y\":null}]}",
    "{\"input_tokens\":18446744073709551615}",
};

fn fuzzParseMessageSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParseMessage(std.testing.Smith, smith, testing.allocator);
}
fn fuzzParseStreamEventSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParseStreamEvent(std.testing.Smith, smith, testing.allocator);
}
fn fuzzParseTokenCountSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParseTokenCount(std.testing.Smith, smith, testing.allocator);
}

const word_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ ";

fn drawWord(comptime S: type, src: *S, out: []u8) []u8 {
    const l = src.valueRangeAtMost(u8, 0, @intCast(out.len));
    for (out[0..l]) |*c| c.* = word_chars[src.index(word_chars.len)];
    return out[0..l];
}

// `smith.slice`, not `bytes` + a ranged length (that pair always yields the
// empty input), and seeds that reach the typed walk — without them the
// harnesses saw one empty string each (A1 F9). Each harness is also run with a
// well-formed document the module's grammar admits, whose fields must come back.
fn fuzzParseMessage(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len = fz.drawRaw(S, src, &buf, &message_corpus);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    if (parseMessage(arena.allocator(), buf[0..len])) |m| {
        MsgMark.mark(.accepted);
        for (m.content) |b| switch (b) {
            .text => MsgMark.mark(.text_block),
            .tool_use => MsgMark.mark(.tool_block),
            else => {},
        };
    } else |_| MsgMark.mark(.refused);

    // A well-formed message must round-trip its fields.
    var idb: [16]u8 = undefined;
    var tb: [24]u8 = undefined;
    const id = drawWord(S, src, &idb);
    const text = drawWord(S, src, &tb);
    const tin = src.value(u32);
    const tout = src.value(u32);
    var jb: [512]u8 = undefined;
    const doc = try std.fmt.bufPrint(&jb, "{{\"id\":\"{s}\",\"model\":\"m\",\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"{s}\"}}],\"stop_reason\":\"end_turn\",\"usage\":{{\"input_tokens\":{d},\"output_tokens\":{d}}}}}", .{ id, text, tin, tout });
    const m = parseMessage(arena.allocator(), doc) catch return error.GenuineMessageRefused;
    if (!std.mem.eql(u8, m.id, id) or m.usage.input_tokens != tin or m.usage.output_tokens != tout) return error.GenuineMessageChanged;
    if (m.content.len != 1 or m.content[0] != .text or !std.mem.eql(u8, m.content[0].text.text, text)) return error.GenuineMessageChanged;
    if (m.stop_reason != .end_turn) return error.GenuineMessageChanged;
    MsgMark.mark(.genuine);
}

test "fuzz driver: LLMCLIENT_FUZZ (message)" {
    try fz.fuzz_driver.run(fuzzParseMessage, .{ .prefix = "LLMCLIENT_FUZZ", .name = "llmclient-message" });
}
test "fuzz harness: message, 300 seeds, reaches every outcome" {
    try MsgMark.reach(fuzzParseMessage, "llmclient-message", 300);
}
test "fuzz parseMessage never panics" {
    try testing.fuzz({}, fuzzParseMessageSmith, .{ .corpus = &message_corpus });
}

fn fuzzParseStreamEvent(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len = fz.drawRaw(S, src, &buf, &event_corpus);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    if (parseStreamEvent(arena.allocator(), buf[0..len])) |ev| {
        EvMark.mark(.accepted);
        switch (ev) {
            .content_block_delta => EvMark.mark(.delta),
            .content_block_start, .message_start => EvMark.mark(.start),
            .content_block_stop => EvMark.mark(.stop),
            .message_delta => EvMark.mark(.message_delta),
            .@"error" => EvMark.mark(.error_event),
            else => {},
        }
    } else |_| EvMark.mark(.refused);

    // A well-formed text delta returns its index and text.
    var tb: [24]u8 = undefined;
    const text = drawWord(S, src, &tb);
    const index = src.value(u32);
    var jb: [256]u8 = undefined;
    const doc = try std.fmt.bufPrint(&jb, "{{\"type\":\"content_block_delta\",\"index\":{d},\"delta\":{{\"type\":\"text_delta\",\"text\":\"{s}\"}}}}", .{ index, text });
    const ev = parseStreamEvent(arena.allocator(), doc) catch return error.GenuineEventRefused;
    if (ev != .content_block_delta or ev.content_block_delta.index != index or ev.content_block_delta.delta != .text_delta or
        !std.mem.eql(u8, ev.content_block_delta.delta.text_delta.text, text)) return error.GenuineEventChanged;
    EvMark.mark(.genuine);
}

test "fuzz driver: LLMCLIENT_FUZZ (stream event)" {
    try fz.fuzz_driver.run(fuzzParseStreamEvent, .{ .prefix = "LLMCLIENT_FUZZ", .name = "llmclient-stream-event" });
}
test "fuzz harness: stream event, 300 seeds, reaches every outcome" {
    try EvMark.reach(fuzzParseStreamEvent, "llmclient-stream-event", 300);
}
test "fuzz parseStreamEvent never panics" {
    try testing.fuzz({}, fuzzParseStreamEventSmith, .{ .corpus = &event_corpus });
}

fn fuzzParseTokenCount(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len = fz.drawRaw(S, src, &buf, &token_corpus);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    if (parseTokenCount(arena.allocator(), buf[0..len])) |_| TokMark.mark(.accepted) else |_| TokMark.mark(.refused);

    // `std.json` hands a count above i64 max over as a `number_string`, which
    // `u64Field` refuses by design ("not a count this client can use").
    const n: u64 = src.value(u64) & std.math.maxInt(i64);
    var jb: [64]u8 = undefined;
    const doc = try std.fmt.bufPrint(&jb, "{{ \"input_tokens\": {d} }}", .{n});
    const tc = parseTokenCount(arena.allocator(), doc) catch return error.GenuineCountRefused;
    if (tc.input_tokens != n) return error.GenuineCountChanged;
    TokMark.mark(.genuine);
}

test "fuzz driver: LLMCLIENT_FUZZ (token count)" {
    try fz.fuzz_driver.run(fuzzParseTokenCount, .{ .prefix = "LLMCLIENT_FUZZ", .name = "llmclient-token-count" });
}
test "fuzz harness: token count, 300 seeds, reaches every outcome" {
    try TokMark.reach(fuzzParseTokenCount, "llmclient-token-count", 300);
}
test "fuzz parseTokenCount never panics" {
    try testing.fuzz({}, fuzzParseTokenCountSmith, .{ .corpus = &token_corpus });
}
