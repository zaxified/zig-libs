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
//! Deliberately excluded (see the module README's DEFER list): image/file
//! content blocks (vision), the `system` array-of-blocks form (only the
//! plain-string shorthand is supported), and the string shorthand for
//! `MessageParam.content` (always the block-array form here — a strict
//! superset of what the string shorthand can express).

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
/// wire (not sent as `null`) via `stringifyAlloc`'s
/// `emit_null_optional_fields = false`.
pub const MessageRequest = struct {
    model: []const u8 = "claude-opus-4-8",
    max_tokens: u32,
    messages: []const MessageParam,
    system: ?[]const u8 = null,
    tools: ?[]const Tool = null,
    tool_choice: ?ToolChoice = null,
    thinking: ?ThinkingConfig = null,
    stream: bool = false,
};

/// Render `req` to a compact (no whitespace) JSON request body, allocated
/// from `gpa`.
pub fn stringifyAlloc(gpa: std.mem.Allocator, req: MessageRequest) ![]u8 {
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
