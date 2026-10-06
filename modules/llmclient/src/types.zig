// SPDX-License-Identifier: MIT

//! Request-side vocabulary for the Anthropic Messages API (`POST
//! /v1/messages`): the `MessageRequest` body and its nested
//! message/content-block/tool/thinking param shapes, plus
//! `stringifyAlloc` to render one to wire JSON.
//!
//! Polymorphic wire shapes (`ContentBlockParam`, `ToolChoice`,
//! `ThinkingConfig`) are Zig tagged unions with a hand-written
//! `jsonStringify` — `std.json.Stringify`'s default union encoding is
//! `{"tagname": payload}`, but Anthropic's wire shape is a flat
//! `{"type": "...", ...fields}` object, so each variant's payload struct
//! carries its own literal `type` field and the union's `jsonStringify`
//! just delegates to it (`try jw.write(payload)`).
//!
//! Image and document content blocks take a `base64` or `url` source (a
//! document also a plain-`text` one); `file` sources belong to the Files
//! API and stay out (see the module README's DEFER list). `system` goes
//! out as the plain string or as an array of text blocks
//! (`system_blocks`, each with an optional `cache_control`).
//! `CountTokensRequest` is the body subset `POST
//! /v1/messages/count_tokens` accepts. Deliberately excluded: the string
//! shorthand for `MessageParam.content` (always the block-array form here
//! — a strict superset of what the string shorthand can express).

const std = @import("std");

/// A message turn's author. Serializes as its lowercase tag name (Zig's
/// default enum→string encoding already matches the wire values).
pub const Role = enum { user, assistant };

/// `cache_control: {"type": "ephemeral", "ttl"?: "5m"|"1h"}` — attach to a
/// content block to mark the prefix ending there as a prompt-cache
/// breakpoint.
pub const CacheControl = struct {
    /// `"5m"` (default) or `"1h"`; null omits the field (server default).
    ttl: ?[]const u8 = null,

    pub fn jsonStringify(self: CacheControl, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("type");
        try jw.write("ephemeral");
        if (self.ttl) |t| {
            try jw.objectField("ttl");
            try jw.write(t);
        }
        try jw.endObject();
    }
};

/// One entry of a message's `content` array. Construct via the
/// `textBlock`/`thinkingBlock`/`toolUseBlock`/`toolResultBlock` helpers
/// below, or the union literals directly.
pub const ContentBlockParam = union(enum) {
    text: struct {
        type: []const u8 = "text",
        text: []const u8,
        cache_control: ?CacheControl = null,
    },
    /// Echoing a prior `thinking` block back verbatim (same-model
    /// multi-turn continuation) — `signature` must be passed through
    /// unmodified.
    thinking: struct {
        type: []const u8 = "thinking",
        thinking: []const u8,
        signature: []const u8,
    },
    /// The assistant's tool call, echoed back in the next turn's history.
    tool_use: struct {
        type: []const u8 = "tool_use",
        id: []const u8,
        name: []const u8,
        input: std.json.Value,
    },
    /// An image: `{"type":"image","source":{...}}` — see `ImageSource`.
    image: struct {
        type: []const u8 = "image",
        source: ImageSource,
        cache_control: ?CacheControl = null,
    },
    /// A document (PDF, plain text): `{"type":"document","source":{...}}`
    /// with the optional `title`, `context` (neither is cited from) and
    /// `citations: {"enabled": true}`.
    document: struct {
        type: []const u8 = "document",
        source: DocumentSource,
        title: ?[]const u8 = null,
        context: ?[]const u8 = null,
        citations: ?CitationsConfig = null,
        cache_control: ?CacheControl = null,
    },
    /// The result your application computed for a `tool_use`, sent back
    /// as a `user` turn. `content` is plain text (the string shorthand —
    /// block-array tool results are out of scope for v1).
    tool_result: struct {
        type: []const u8 = "tool_result",
        tool_use_id: []const u8,
        content: []const u8 = "",
        is_error: ?bool = null,
        cache_control: ?CacheControl = null,
    },

    pub fn jsonStringify(self: ContentBlockParam, jw: anytype) !void {
        switch (self) {
            inline else => |payload| try jw.write(payload),
        }
    }
};

/// The image formats the API accepts (`media_type` on a base64 source).
/// Serializes as the MIME string itself.
pub const ImageMediaType = enum {
    @"image/jpeg",
    @"image/png",
    @"image/gif",
    @"image/webp",
};

/// An image block's `source`. `.base64.data` is the image already
/// base64-encoded (standard alphabet, padded, no line breaks — e.g.
/// `std.base64.standard.Encoder.encode`); it goes on the wire verbatim.
/// `.url` is fetched by the API, not by this client.
pub const ImageSource = union(enum) {
    base64: struct { media_type: ImageMediaType, data: []const u8 },
    url: []const u8,

    pub fn jsonStringify(self: ImageSource, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .base64 => |b| {
                try jw.write("base64");
                try jw.objectField("media_type");
                try jw.write(@tagName(b.media_type));
                try jw.objectField("data");
                try jw.write(b.data);
            },
            .url => |u| {
                try jw.write("url");
                try jw.objectField("url");
                try jw.write(u);
            },
        }
        try jw.endObject();
    }
};

/// A document block's `source`: a base64-encoded PDF
/// (`{"type":"base64","media_type":"application/pdf","data":...}`), plain
/// text (`{"type":"text","media_type":"text/plain","data":...}` — the text
/// itself, not encoded), or a URL the API fetches. `count_tokens` accepts
/// only the first two (the API's rule, not checked here).
pub const DocumentSource = union(enum) {
    base64_pdf: []const u8,
    text: []const u8,
    url: []const u8,

    pub fn jsonStringify(self: DocumentSource, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .base64_pdf => |d| {
                try jw.write("base64");
                try jw.objectField("media_type");
                try jw.write("application/pdf");
                try jw.objectField("data");
                try jw.write(d);
            },
            .text => |d| {
                try jw.write("text");
                try jw.objectField("media_type");
                try jw.write("text/plain");
                try jw.objectField("data");
                try jw.write(d);
            },
            .url => |u| {
                try jw.write("url");
                try jw.objectField("url");
                try jw.write(u);
            },
        }
        try jw.endObject();
    }
};

/// `citations: {"enabled": bool}` on a document block.
pub const CitationsConfig = struct { enabled: bool };

/// One entry of the `system` array form: a text block, optionally a
/// prompt-cache breakpoint (`cache_control`) — how a system prompt is
/// cached.
pub const SystemBlock = struct {
    type: []const u8 = "text",
    text: []const u8,
    cache_control: ?CacheControl = null,
};

pub fn systemBlock(text: []const u8) SystemBlock {
    return .{ .text = text };
}

pub fn systemBlockCached(text: []const u8) SystemBlock {
    return .{ .text = text, .cache_control = .{} };
}

/// An image from already-base64-encoded bytes.
pub fn imageBlock(media_type: ImageMediaType, base64_data: []const u8) ContentBlockParam {
    return .{ .image = .{ .source = .{ .base64 = .{ .media_type = media_type, .data = base64_data } } } };
}

pub fn imageUrlBlock(url: []const u8) ContentBlockParam {
    return .{ .image = .{ .source = .{ .url = url } } };
}

/// A PDF from already-base64-encoded bytes.
pub fn pdfBlock(base64_data: []const u8) ContentBlockParam {
    return .{ .document = .{ .source = .{ .base64_pdf = base64_data } } };
}

pub fn pdfUrlBlock(url: []const u8) ContentBlockParam {
    return .{ .document = .{ .source = .{ .url = url } } };
}

/// A plain-text document (the text itself, not encoded).
pub fn textDocumentBlock(text: []const u8) ContentBlockParam {
    return .{ .document = .{ .source = .{ .text = text } } };
}

pub fn textBlock(text: []const u8) ContentBlockParam {
    return .{ .text = .{ .text = text } };
}

pub fn textBlockCached(text: []const u8) ContentBlockParam {
    return .{ .text = .{ .text = text, .cache_control = .{} } };
}

pub fn thinkingBlock(thinking: []const u8, signature: []const u8) ContentBlockParam {
    return .{ .thinking = .{ .thinking = thinking, .signature = signature } };
}

pub fn toolUseBlock(id: []const u8, name: []const u8, input: std.json.Value) ContentBlockParam {
    return .{ .tool_use = .{ .id = id, .name = name, .input = input } };
}

pub fn toolResultBlock(tool_use_id: []const u8, content: []const u8) ContentBlockParam {
    return .{ .tool_result = .{ .tool_use_id = tool_use_id, .content = content } };
}

pub fn toolErrorBlock(tool_use_id: []const u8, content: []const u8) ContentBlockParam {
    return .{ .tool_result = .{ .tool_use_id = tool_use_id, .content = content, .is_error = true } };
}

/// One turn: `{"role": "user"|"assistant", "content": [...]}`.
pub const MessageParam = struct {
    role: Role,
    content: []const ContentBlockParam,

    pub fn user(content: []const ContentBlockParam) MessageParam {
        return .{ .role = .user, .content = content };
    }

    pub fn assistant(content: []const ContentBlockParam) MessageParam {
        return .{ .role = .assistant, .content = content };
    }
};

/// A client-defined tool declaration. `input_schema` is an arbitrary JSON
/// Schema object — `std.json.Value` already has its own `jsonStringify`,
/// so it serializes transparently as a nested field.
pub const Tool = struct {
    name: []const u8,
    description: []const u8 = "",
    input_schema: std.json.Value,
};

/// `tool_choice`: let Claude decide (`.auto`, the API default), force some
/// tool call (`.any`), forbid tool use (`.none`), or force one specific
/// tool (`.tool`).
pub const ToolChoice = union(enum) {
    auto,
    any,
    none,
    tool: struct { name: []const u8 },

    pub fn jsonStringify(self: ToolChoice, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .auto => try jw.write("auto"),
            .any => try jw.write("any"),
            .none => try jw.write("none"),
            .tool => try jw.write("tool"),
        }
        if (self == .tool) {
            try jw.objectField("name");
            try jw.write(self.tool.name);
        }
        try jw.endObject();
    }
};

/// `thinking`: off, adaptive (model decides depth; optionally request a
/// `display: "summarized"` rendering), or a fixed `budget_tokens` (older
/// models only — see the `claude-api` skill for which models accept
/// which variant; this client does not police that, callers do).
pub const ThinkingConfig = union(enum) {
    disabled,
    adaptive: struct { display: ?Display = null },
    enabled: struct { budget_tokens: u32 },

    pub const Display = enum { summarized, omitted };

    pub fn jsonStringify(self: ThinkingConfig, jw: anytype) !void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .disabled => try jw.write("disabled"),
            .adaptive => try jw.write("adaptive"),
            .enabled => try jw.write("enabled"),
        }
        switch (self) {
            .adaptive => |v| if (v.display) |d| {
                try jw.objectField("display");
                try jw.write(@tagName(d));
            },
            .enabled => |v| {
                try jw.objectField("budget_tokens");
                try jw.write(v.budget_tokens);
            },
            .disabled => {},
        }
        try jw.endObject();
    }
};

/// `POST /v1/messages` request body. Optional fields are omitted from the
/// wire (never sent as `null`).
///
/// `system` is the plain-string form; `system_blocks` the array-of-text-
/// blocks form (per-block `cache_control` — prompt caching of a system
/// prompt). Both go out under the one wire key `system`: only `system` →
/// the string; `system_blocks` non-empty → the array; both → the array,
/// with `system` as an uncached first text block ahead of `system_blocks`.
pub const MessageRequest = struct {
    model: []const u8 = "claude-opus-4-8",
    max_tokens: u32,
    messages: []const MessageParam,
    system: ?[]const u8 = null,
    system_blocks: ?[]const SystemBlock = null,
    tools: ?[]const Tool = null,
    tool_choice: ?ToolChoice = null,
    thinking: ?ThinkingConfig = null,
    stream: bool = false,

    pub fn jsonStringify(self: MessageRequest, jw: anytype) !void {
        try writeRequestObject(MessageRequest, self, jw);
    }
};

/// `POST /v1/messages/count_tokens` request body: the subset of
/// `MessageRequest` that endpoint accepts (no `max_tokens`, no `stream` —
/// the API rejects fields it does not know). `fromMessageRequest` counts
/// exactly what a `MessageRequest` would send.
pub const CountTokensRequest = struct {
    model: []const u8 = "claude-opus-4-8",
    messages: []const MessageParam,
    system: ?[]const u8 = null,
    system_blocks: ?[]const SystemBlock = null,
    tools: ?[]const Tool = null,
    tool_choice: ?ToolChoice = null,
    thinking: ?ThinkingConfig = null,

    pub fn fromMessageRequest(req: MessageRequest) CountTokensRequest {
        return .{
            .model = req.model,
            .messages = req.messages,
            .system = req.system,
            .system_blocks = req.system_blocks,
            .tools = req.tools,
            .tool_choice = req.tool_choice,
            .thinking = req.thinking,
        };
    }

    pub fn jsonStringify(self: CountTokensRequest, jw: anytype) !void {
        try writeRequestObject(CountTokensRequest, self, jw);
    }
};

/// The two request bodies' shared writer: fields in declaration order, a
/// null optional left out, `system`/`system_blocks` merged under `system`.
fn writeRequestObject(comptime T: type, self: T, jw: anytype) !void {
    try jw.beginObject();
    inline for (std.meta.fields(T)) |f| {
        if (comptime std.mem.eql(u8, f.name, "system_blocks")) continue;
        if (comptime std.mem.eql(u8, f.name, "system")) {
            try writeSystem(self.system, self.system_blocks, jw);
        } else if (@typeInfo(f.type) == .optional) {
            if (@field(self, f.name)) |v| {
                try jw.objectField(f.name);
                try jw.write(v);
            }
        } else {
            try jw.objectField(f.name);
            try jw.write(@field(self, f.name));
        }
    }
    try jw.endObject();
}

fn writeSystem(text: ?[]const u8, blocks: ?[]const SystemBlock, jw: anytype) !void {
    const bs = blocks orelse &.{};
    if (bs.len == 0) {
        if (text) |t| {
            try jw.objectField("system");
            try jw.write(t);
        }
        return;
    }
    try jw.objectField("system");
    try jw.beginArray();
    if (text) |t| try jw.write(SystemBlock{ .text = t });
    for (bs) |b| try jw.write(b);
    try jw.endArray();
}

/// Render `req` to a compact (no whitespace) JSON request body, allocated
/// from `gpa`.
pub fn stringifyAlloc(gpa: std.mem.Allocator, req: MessageRequest) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, req, .{ .emit_null_optional_fields = false });
}

/// Render a `count_tokens` body, as `stringifyAlloc` does a messages one.
pub fn stringifyCountTokensAlloc(gpa: std.mem.Allocator, req: CountTokensRequest) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, req, .{ .emit_null_optional_fields = false });
}

// ── tests (offline, golden JSON) ────────────────────────────────────────────

const testing = std.testing;

test "MessageRequest: golden JSON for a minimal request" {
    const req: MessageRequest = .{
        .max_tokens = 1024,
        .messages = &.{MessageParam.user(&.{textBlock("Hello, Claude")})},
    };
    const json = try stringifyAlloc(testing.allocator, req);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"model\":\"claude-opus-4-8\",\"max_tokens\":1024,\"messages\":[{\"role\":\"user\"," ++
            "\"content\":[{\"type\":\"text\",\"text\":\"Hello, Claude\"}]}],\"stream\":false}",
        json,
    );
}

test "MessageRequest: golden JSON with system, tools, tool_choice, thinking, cache_control" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var loc_type: std.json.ObjectMap = .empty;
    try loc_type.put(a, "type", .{ .string = "string" });
    var props: std.json.ObjectMap = .empty;
    try props.put(a, "location", .{ .object = loc_type });
    var required = std.json.Array.init(a);
    try required.append(.{ .string = "location" });
    var schema: std.json.ObjectMap = .empty;
    try schema.put(a, "type", .{ .string = "object" });
    try schema.put(a, "properties", .{ .object = props });
    try schema.put(a, "required", .{ .array = required });

    const req: MessageRequest = .{
        .max_tokens = 4096,
        .system = "You are a helpful assistant.",
        .messages = &.{MessageParam.user(&.{textBlockCached("What's the weather in Paris?")})},
        .tools = &.{.{
            .name = "get_weather",
            .description = "Get the current weather",
            .input_schema = .{ .object = schema },
        }},
        .tool_choice = .{ .tool = .{ .name = "get_weather" } },
        .thinking = .{ .adaptive = .{} },
        .stream = true,
    };

    const json = try stringifyAlloc(testing.allocator, req);
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"model\":\"claude-opus-4-8\",\"max_tokens\":4096," ++
            "\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\"," ++
            "\"text\":\"What's the weather in Paris?\",\"cache_control\":{\"type\":\"ephemeral\"}}]}]," ++
            "\"system\":\"You are a helpful assistant.\"," ++
            "\"tools\":[{\"name\":\"get_weather\",\"description\":\"Get the current weather\"," ++
            "\"input_schema\":{\"type\":\"object\",\"properties\":{\"location\":{\"type\":\"string\"}}," ++
            "\"required\":[\"location\"]}}]," ++
            "\"tool_choice\":{\"type\":\"tool\",\"name\":\"get_weather\"}," ++
            "\"thinking\":{\"type\":\"adaptive\"}," ++
            "\"stream\":true}",
        json,
    );
}

test "MessageRequest: tool_use + tool_result round-trip blocks serialize flat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var input_obj: std.json.ObjectMap = .empty;
    try input_obj.put(a, "city", .{ .string = "Paris" });

    const req: MessageRequest = .{
        .max_tokens = 512,
        .messages = &.{
            MessageParam.user(&.{textBlock("weather?")}),
            MessageParam.assistant(&.{toolUseBlock("toolu_1", "get_weather", .{ .object = input_obj })}),
            MessageParam.user(&.{toolResultBlock("toolu_1", "72F sunny")}),
        },
    };
    const json = try stringifyAlloc(testing.allocator, req);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"get_weather\",\"input\":{\"city\":\"Paris\"}") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"type\":\"tool_result\",\"tool_use_id\":\"toolu_1\",\"content\":\"72F sunny\"") != null);
}

// ── image / document blocks, the `system` array form, count_tokens ─────────
//
// EXTERNAL anchor: the request bodies below are the cURL examples Anthropic
// publishes, copied verbatim (fetched 2026-10-06 from
// platform.claude.com/docs/en/build-with-claude/{vision,pdf-support,
// citations,prompt-caching,token-counting}.md; no API key, no call made by
// the test). Shell placeholders (`$BASE64_IMAGE_DATA`, ...) are replaced by
// one fixed value on both sides. The comparison is JSON-semantic (object
// key order free, everything else exact) because the docs are
// pretty-printed with their keys in a human order; the byte-exact field
// order this module emits is pinned separately by the SELF-DERIVED golden
// test after them. Only examples whose `messages` use the block-array form
// can be compared whole (this module never emits the string shorthand);
// for the one system-array example the `system` value alone is compared.

fn jsonValueEql(a: std.json.Value, b: std.json.Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .integer => |x| return b == .integer and b.integer == x,
        .float => |x| return b == .float and b.float == x,
        .number_string => |x| return b == .number_string and std.mem.eql(u8, x, b.number_string),
        .string => |x| return b == .string and std.mem.eql(u8, x, b.string),
        .array => |x| {
            if (b != .array or b.array.items.len != x.items.len) return false;
            for (x.items, b.array.items) |l, r| if (!jsonValueEql(l, r)) return false;
            return true;
        },
        .object => |x| {
            if (b != .object or b.object.count() != x.count()) return false;
            var it = x.iterator();
            while (it.next()) |e| {
                const r = b.object.get(e.key_ptr.*) orelse return false;
                if (!jsonValueEql(e.value_ptr.*, r)) return false;
            }
            return true;
        },
    }
}

/// `expected` and `actual` are the same JSON value. `drop_stream` removes
/// `"stream":false` from `actual` first (the docs' bodies leave it out;
/// this module always sends it on /v1/messages).
fn expectJsonEqual(expected: []const u8, actual: []const u8, drop_stream: bool) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const e = try std.json.parseFromSliceLeaky(std.json.Value, a, expected, .{});
    var got = try std.json.parseFromSliceLeaky(std.json.Value, a, actual, .{});
    if (drop_stream) {
        const s = got.object.fetchSwapRemove("stream") orelse return error.TestExpectedStreamField;
        try testing.expect(s.value == .bool and s.value.bool == false);
    }
    if (!jsonValueEql(e, got)) {
        std.debug.print("expected: {s}\nactual:   {s}\n", .{ expected, actual });
        return error.TestJsonMismatch;
    }
}

/// A stand-in for real image/PDF bytes, substituted into the docs'
/// placeholder and passed to the builder alike.
const fake_b64 = "JVBERi0xLjQKJcOkw7zDtsOfCg==";

test "external anchor: vision docs base64 image example — same JSON as imageBlock" {
    const docs =
        \\  {
        \\    "model": "claude-opus-5-5",
        \\    "max_tokens": 1024,
        \\    "messages": [
        \\      {
        \\        "role": "user",
        \\        "content": [
        \\          {
        \\            "type": "image",
        \\            "source": {
        \\              "type": "base64",
        \\              "media_type": "image/jpeg",
        \\              "data": "$BASE64_IMAGE_DATA"
        \\            }
        \\          },
        \\          {
        \\            "type": "text",
        \\            "text": "Describe this image."
        \\          }
        \\        ]
        \\      }
        \\    ]
        \\  }
    ;
    const expected = try std.mem.replaceOwned(u8, testing.allocator, docs, "$BASE64_IMAGE_DATA", fake_b64);
    defer testing.allocator.free(expected);
    const json = try stringifyAlloc(testing.allocator, .{
        .model = "claude-opus-5-5",
        .max_tokens = 1024,
        .messages = &.{MessageParam.user(&.{ imageBlock(.@"image/jpeg", fake_b64), textBlock("Describe this image.") })},
    });
    defer testing.allocator.free(json);
    try expectJsonEqual(expected, json, true);
}

test "external anchor: vision docs URL image example — same JSON as imageUrlBlock" {
    const expected =
        \\{
        \\      "model": "claude-opus-5-5",
        \\      "max_tokens": 1024,
        \\      "messages": [
        \\        {
        \\          "role": "user",
        \\          "content": [
        \\            {
        \\              "type": "image",
        \\              "source": {
        \\                "type": "url",
        \\                "url": "https://platform.claude.com/docs/images/vision-example.jpg"
        \\              }
        \\            },
        \\            {
        \\              "type": "text",
        \\              "text": "Describe this image."
        \\            }
        \\          ]
        \\        }
        \\      ]
        \\    }
    ;
    const json = try stringifyAlloc(testing.allocator, .{
        .model = "claude-opus-5-5",
        .max_tokens = 1024,
        .messages = &.{MessageParam.user(&.{
            imageUrlBlock("https://platform.claude.com/docs/images/vision-example.jpg"),
            textBlock("Describe this image."),
        })},
    });
    defer testing.allocator.free(json);
    try expectJsonEqual(expected, json, true);
}

test "external anchor: PDF docs URL document example — same JSON as pdfUrlBlock" {
    const expected =
        \\{
        \\      "model": "claude-opus-5-5",
        \\      "max_tokens": 1024,
        \\      "messages": [{
        \\          "role": "user",
        \\          "content": [{
        \\              "type": "document",
        \\              "source": {
        \\                  "type": "url",
        \\                  "url": "https://assets.anthropic.com/m/1cd9d098ac3e6467/original/Claude-3-Model-Card-October-Addendum.pdf"
        \\              }
        \\          },
        \\          {
        \\              "type": "text",
        \\              "text": "What are the key findings in this document?"
        \\          }]
        \\      }]
        \\  }
    ;
    const json = try stringifyAlloc(testing.allocator, .{
        .model = "claude-opus-5-5",
        .max_tokens = 1024,
        .messages = &.{MessageParam.user(&.{
            pdfUrlBlock("https://assets.anthropic.com/m/1cd9d098ac3e6467/original/Claude-3-Model-Card-October-Addendum.pdf"),
            textBlock("What are the key findings in this document?"),
        })},
    });
    defer testing.allocator.free(json);
    try expectJsonEqual(expected, json, true);
}

test "external anchor: citations docs plain-text document example — title, context, citations" {
    const expected =
        \\{
        \\      "model": "claude-opus-5-5",
        \\      "max_tokens": 1024,
        \\      "messages": [
        \\        {
        \\          "role": "user",
        \\          "content": [
        \\            {
        \\              "type": "document",
        \\              "source": {
        \\                "type": "text",
        \\                "media_type": "text/plain",
        \\                "data": "The grass is green. The sky is blue."
        \\              },
        \\              "title": "My Document",
        \\              "context": "This is a trustworthy document.",
        \\              "citations": {"enabled": true}
        \\            },
        \\            {
        \\              "type": "text",
        \\              "text": "What color is the grass and sky?"
        \\            }
        \\          ]
        \\        }
        \\      ]
        \\    }
    ;
    var doc = textDocumentBlock("The grass is green. The sky is blue.");
    doc.document.title = "My Document";
    doc.document.context = "This is a trustworthy document.";
    doc.document.citations = .{ .enabled = true };
    const json = try stringifyAlloc(testing.allocator, .{
        .model = "claude-opus-5-5",
        .max_tokens = 1024,
        .messages = &.{MessageParam.user(&.{ doc, textBlock("What color is the grass and sky?") })},
    });
    defer testing.allocator.free(json);
    try expectJsonEqual(expected, json, true);
}

test "external anchor: prompt-caching docs system array — same `system` value as system_blocks" {
    // The docs' pre-warm example; its `messages` uses the string shorthand,
    // so only the `system` value is compared.
    const expected =
        \\[
        \\        {
        \\          "type": "text",
        \\          "text": "You are an expert software engineer with deep knowledge of distributed systems...",
        \\          "cache_control": {"type": "ephemeral"}
        \\        }
        \\      ]
    ;
    const json = try stringifyAlloc(testing.allocator, .{
        .max_tokens = 0,
        .system_blocks = &.{systemBlockCached("You are an expert software engineer with deep knowledge of distributed systems...")},
        .messages = &.{MessageParam.user(&.{textBlock("warmup")})},
    });
    defer testing.allocator.free(json);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const got = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), json, .{});
    const sys = try std.json.Stringify.valueAlloc(arena.allocator(), got.object.get("system").?, .{});
    try expectJsonEqual(expected, sys, false);
}

test "external anchor: token-counting docs image example — CountTokensRequest body, no max_tokens/stream" {
    const docs =
        \\  {
        \\    "model": "claude-opus-5-5",
        \\    "messages": [
        \\      {"role": "user", "content": [
        \\        {"type": "image", "source": {
        \\          "type": "base64",
        \\          "media_type": "$IMAGE_MEDIA_TYPE",
        \\          "data": "$IMAGE_BASE64"
        \\        }},
        \\        {"type": "text", "text": "Describe this image"}
        \\      ]}
        \\    ]
        \\  }
    ;
    const step = try std.mem.replaceOwned(u8, testing.allocator, docs, "$IMAGE_MEDIA_TYPE", "image/jpeg");
    defer testing.allocator.free(step);
    const expected = try std.mem.replaceOwned(u8, testing.allocator, step, "$IMAGE_BASE64", fake_b64);
    defer testing.allocator.free(expected);
    // Built from a full MessageRequest, the way a caller counts what it is
    // about to send: max_tokens and stream must not reach the wire (the
    // comparison is whole-object, so an extra key fails it).
    const full: MessageRequest = .{
        .model = "claude-opus-5-5",
        .max_tokens = 4096,
        .stream = true,
        .messages = &.{MessageParam.user(&.{ imageBlock(.@"image/jpeg", fake_b64), textBlock("Describe this image") })},
    };
    const json = try stringifyCountTokensAlloc(testing.allocator, .fromMessageRequest(full));
    defer testing.allocator.free(json);
    try expectJsonEqual(expected, json, false);
}

test "external anchor: token-counting docs PDF example — CountTokensRequest with pdfBlock" {
    const docs =
        \\  {
        \\    "model": "claude-opus-5-5",
        \\    "messages": [{
        \\      "role": "user",
        \\      "content": [
        \\        {
        \\          "type": "document",
        \\          "source": {
        \\            "type": "base64",
        \\            "media_type": "application/pdf",
        \\            "data": "$PDF_BASE64"
        \\          }
        \\        },
        \\        {
        \\          "type": "text",
        \\          "text": "Please summarize this document."
        \\        }
        \\      ]
        \\    }]
        \\  }
    ;
    const expected = try std.mem.replaceOwned(u8, testing.allocator, docs, "$PDF_BASE64", fake_b64);
    defer testing.allocator.free(expected);
    const json = try stringifyCountTokensAlloc(testing.allocator, .{
        .model = "claude-opus-5-5",
        .messages = &.{MessageParam.user(&.{ pdfBlock(fake_b64), textBlock("Please summarize this document.") })},
    });
    defer testing.allocator.free(json);
    try expectJsonEqual(expected, json, false);
}

test "golden (SELF-DERIVED): byte-exact field order of image/document blocks and every ImageMediaType" {
    var doc = pdfBlock("QUJD");
    doc.document.cache_control = .{ .ttl = "1h" };
    const json = try stringifyAlloc(testing.allocator, .{
        .max_tokens = 8,
        .messages = &.{MessageParam.user(&.{
            imageBlock(.@"image/png", "QUJD"),
            imageBlock(.@"image/gif", "QUJD"),
            imageBlock(.@"image/webp", "QUJD"),
            doc,
        })},
    });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"model\":\"claude-opus-4-8\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":[" ++
            "{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"QUJD\"}}," ++
            "{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/gif\",\"data\":\"QUJD\"}}," ++
            "{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/webp\",\"data\":\"QUJD\"}}," ++
            "{\"type\":\"document\",\"source\":{\"type\":\"base64\",\"media_type\":\"application/pdf\",\"data\":\"QUJD\"}," ++
            "\"cache_control\":{\"type\":\"ephemeral\",\"ttl\":\"1h\"}}]}],\"stream\":false}",
        json,
    );
}

test "system: string only, blocks only, both (string first, uncached), empty blocks fall back to the string" {
    const msgs: []const MessageParam = &.{MessageParam.user(&.{textBlock("q")})};
    const Case = struct { req: MessageRequest, want: []const u8 };
    const cases = [_]Case{
        .{ .req = .{ .max_tokens = 1, .messages = msgs, .system = "S" }, .want = "\"system\":\"S\"," },
        .{
            .req = .{ .max_tokens = 1, .messages = msgs, .system_blocks = &.{ systemBlock("A"), systemBlockCached("B") } },
            .want = "\"system\":[{\"type\":\"text\",\"text\":\"A\"},{\"type\":\"text\",\"text\":\"B\",\"cache_control\":{\"type\":\"ephemeral\"}}],",
        },
        .{
            .req = .{ .max_tokens = 1, .messages = msgs, .system = "S", .system_blocks = &.{systemBlockCached("B")} },
            .want = "\"system\":[{\"type\":\"text\",\"text\":\"S\"},{\"type\":\"text\",\"text\":\"B\",\"cache_control\":{\"type\":\"ephemeral\"}}],",
        },
        .{ .req = .{ .max_tokens = 1, .messages = msgs, .system = "S", .system_blocks = &.{} }, .want = "\"system\":\"S\"," },
    };
    for (cases) |c| {
        const json = try stringifyAlloc(testing.allocator, c.req);
        defer testing.allocator.free(json);
        try testing.expect(std.mem.indexOf(u8, json, c.want) != null);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, json, "\"system\""));
        // Placement unchanged: right after messages.
        try testing.expect(std.mem.indexOf(u8, json, "]}],\"system\":") != null);
    }
    // Neither set, or only an empty array: no `system` key at all.
    for ([_]?[]const SystemBlock{ null, &.{} }) |blocks| {
        const json = try stringifyAlloc(testing.allocator, .{ .max_tokens = 1, .messages = msgs, .system_blocks = blocks });
        defer testing.allocator.free(json);
        try testing.expect(std.mem.indexOf(u8, json, "system") == null);
    }
}

test "CountTokensRequest: carries system, tool_choice, thinking through; never max_tokens or stream" {
    const full: MessageRequest = .{
        .model = "claude-opus-5-5",
        .max_tokens = 99,
        .stream = true,
        .system = "You are a scientist",
        .tool_choice = .auto,
        .thinking = .{ .adaptive = .{} },
        .messages = &.{MessageParam.user(&.{textBlock("Hello, Claude")})},
    };
    const json = try stringifyCountTokensAlloc(testing.allocator, .fromMessageRequest(full));
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"model\":\"claude-opus-5-5\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\"," ++
            "\"text\":\"Hello, Claude\"}]}],\"system\":\"You are a scientist\",\"tool_choice\":{\"type\":\"auto\"}," ++
            "\"thinking\":{\"type\":\"adaptive\"}}",
        json,
    );
}
