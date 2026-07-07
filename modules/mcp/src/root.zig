// SPDX-License-Identifier: MIT

//! mcp — Model Context Protocol server transport: JSON-RPC 2.0 + the MCP
//! handshake, tools, resources and prompts over a generic reader/writer
//! (stdio built in).
//!
//! The split this module enforces: **server = transport, app = primitives**.
//! The server owns the protocol (JSON-RPC framing, `initialize` version
//! negotiation, `tools/*`/`resources/*`/`prompts/*` dispatch, progress
//! notifications); the application registers tools, resources and prompts —
//! each a name + metadata + a handler that threads **app state via a `ctx`
//! pointer**. That ctx threading is the point of this module versus thin MCP
//! libs: a tool call (or a resource read, or a prompt get) is a plain
//! function call into your live application, not a stateless echo.
//!
//! Framing: **newline-delimited JSON** (the MCP stdio transport). Every
//! message written to the output is exactly one JSON object followed by one
//! `\n`; every input line is one JSON-RPC message. No Content-Length headers.
//! JSON-RPC **batch arrays are not supported** — MCP does not use them; an
//! array input gets a -32600 Invalid request.
//!
//! Protocol surface (per the MCP spec revision 2025-11-25):
//!   * `initialize` — protocol-version negotiation (echo the client's
//!     requested revision when supported, else answer with our latest) +
//!     server capabilities (`tools`) + serverInfo + optional instructions.
//!   * `notifications/initialized` — accepted, sets `client_initialized`.
//!   * `tools/list` — built from the registered tool catalog (name,
//!     description, inputSchema, optional outputSchema).
//!   * `tools/call` — dispatch by name to the registered handler; the result
//!     carries a text content block, plus `structuredContent` when the tool
//!     allows it and its output is a single JSON object; `isError` marks tool
//!     failures (a domain `{"ok":false}` answer stays `isError:false`).
//!   * `resources/list` / `resources/templates/list` — built from the
//!     registered resource + resource-template catalogs.
//!   * `resources/read` — dispatch by uri: an exact match on a registered
//!     resource first, then each registered template's handler in order (a
//!     template handler inspects the requested uri itself and declines with
//!     `false`); the handler fills text and/or base64-blob contents. An
//!     unresolvable uri answers -32002 Resource not found (the MCP-defined
//!     code).
//!   * `prompts/list` — built from the registered prompt catalog (name,
//!     description, argument declarations).
//!   * `prompts/get` — dispatch by name; the server validates the declared
//!     required arguments (-32602 when missing), then the handler renders
//!     the messages from the arguments + ctx.
//!   * `ping` — `{}`.
//!   * `notifications/progress` — server→client, emitted during a `tools/call`
//!     when the client opted in via `params._meta.progressToken`.
//!
//! Subscriptions and list-change notifications are NOT implemented — the
//! advertised capabilities say so (`subscribe:false`, `listChanged:false`),
//! which the spec allows. Pagination is likewise not implemented: list
//! results never carry a `nextCursor` (the whole catalog is one page).
//!
//! Error behavior: malformed input NEVER panics — it produces the proper
//! JSON-RPC error (-32700 parse, -32600 invalid request, -32601 method not
//! found, -32602 invalid params, -32603 internal). A request (has `id`) gets
//! exactly one response; a notification (no `id`) gets none — an id-less line
//! for a request-only method is a stray notification and is dropped.
//!
//! Transports:
//!   * generic: `serve(in: *std.Io.Reader, out: *std.Io.Writer)` loops over
//!     newline-delimited messages; `handleMessage` processes exactly one.
//!   * stdio built in: `serveStdio(io)` wires stdin/stdout into `serve`.
//!   * HTTP: no dependency here — wire it yourself in one line inside an
//!     `http`/`router` handler: `try server.handleMessage(request_body, w);`
//!     (each HTTP POST body is one JSON-RPC message; the response line is the
//!     reply body).
//!
//! Allocation: the `Server` takes an explicit allocator; each message is
//! handled on a per-message arena that is freed when the response has been
//! written, so a long-lived server does not accumulate per-request garbage.

const std = @import("std");

pub const meta = .{
    .status = .extract, // extracted from bxp bxp-mcp/src/server.zig (same authors);
    // resources + prompts added clean-room from the MCP spec (no SDK source)
    .platform = .any,
    .role = .server,
    .concurrency = .reentrant, // no globals; one Server instance = one owner
    .model_after = "MCP spec 2025-11-25 + JSON-RPC 2.0",
    .deps = .{}, // std only (std.json + std.Io reader/writer)
};

/// Latest MCP protocol revision we advertise. Older revisions we also accept
/// (and echo back) are listed in `supported_versions`.
pub const protocol_version = "2025-11-25";

/// Revisions the server is compatible with — the tool surface exposed here is
/// identical across them. On `initialize` we echo the client's requested
/// version when it is one of these (spec requirement), otherwise we answer
/// with the latest (`protocol_version`).
pub const supported_versions = [_][]const u8{ "2025-11-25", "2025-06-18" };

/// JSON-RPC 2.0 standard error codes + the MCP-defined resource error (the
/// only codes this server emits).
pub const error_code = struct {
    pub const parse_error: i32 = -32700;
    pub const invalid_request: i32 = -32600;
    pub const method_not_found: i32 = -32601;
    pub const invalid_params: i32 = -32602;
    pub const internal_error: i32 = -32603;
    /// MCP spec: `resources/read` on a uri no resource resolves.
    pub const resource_not_found: i32 = -32002;
};

/// Everything `handleMessage`/`serve` can fail with. Malformed *input* never
/// surfaces here (it becomes a JSON-RPC error response); only allocation
/// failure and transport write failure do.
pub const Error = error{ OutOfMemory, WriteFailed };

/// Pick the protocol version to answer with: the client's requested one if we
/// support it, else our latest. `requested` is null when the client omits it.
pub fn negotiateVersion(requested: ?[]const u8) []const u8 {
    if (requested) |req| {
        for (supported_versions) |v| {
            if (std.mem.eql(u8, v, req)) return req;
        }
    }
    return protocol_version;
}

// ── JSON-RPC 2.0 encode (public: reusable when wiring custom transports) ────

/// Write one JSON-RPC error response as a single line: `{"jsonrpc":"2.0",
/// "id":<id>,"error":{"code":<code>,"message":<msg>}}\n`. The id is
/// re-serialized verbatim from its parsed Value (an integer stays an integer,
/// a string keeps its quotes); null/absent => `null`. The message is properly
/// JSON-escaped.
pub fn writeErrorLine(w: *std.Io.Writer, id: ?std.json.Value, code: i32, message: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
    try std.json.Stringify.encodeJsonString(message, .{}, w);
    try w.writeAll("}}\n");
}

/// Write one JSON-RPC success response as a single line, splicing
/// `raw_result_json` in verbatim as the `result` value (raw `\n`/`\r` inside
/// it are stripped so a multi-line JSON literal never breaks the
/// one-object-per-line framing invariant).
pub fn writeResultLine(w: *std.Io.Writer, id: ?std.json.Value, raw_result_json: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.writeAll(",\"result\":");
    try writeStrippingNewlines(w, raw_result_json);
    try w.writeAll("}\n");
}

/// Append the request id verbatim (re-serialized from its parsed Value).
/// Null => `null`.
fn writeId(w: *std.Io.Writer, id: ?std.json.Value) std.Io.Writer.Error!void {
    if (id) |v| {
        try std.json.Stringify.value(v, .{}, w);
    } else {
        try w.writeAll("null");
    }
}

/// Write `data`, skipping raw \n and \r so a multi-line raw JSON literal
/// never breaks the one-object-per-line invariant.
fn writeStrippingNewlines(w: *std.Io.Writer, data: []const u8) std.Io.Writer.Error!void {
    var i: usize = 0;
    while (i < data.len) {
        const start = i;
        while (i < data.len and data[i] != '\n' and data[i] != '\r') : (i += 1) {}
        if (i > start) try w.writeAll(data[start..i]);
        if (i < data.len) i += 1;
    }
}

// ── progress notifications ──────────────────────────────────────────────────

/// Server→client `notifications/progress` reporter for a long-running tool.
/// Per the MCP spec a notification is only sent when the caller supplied a
/// `progressToken` in the request's `params._meta` — when absent, the
/// `ToolCall.progress` field is null and `reportProgress` is a no-op.
///
/// Notifications and the eventual tool result share the transport writer;
/// each is one complete JSON object on its own line, so interleaving is safe
/// (the progress lines precede the result line because the tool runs before
/// the server serializes its response).
pub const Progress = struct {
    /// The transport output — the same writer the JSON-RPC responses use.
    out: *std.Io.Writer,
    /// The client's progressToken, already serialized to JSON text (a quoted
    /// string like `"abc"` or a bare number like `42`), embedded verbatim.
    token_json: []const u8,

    /// Emit one `notifications/progress`. The message is JSON-escaped, so any
    /// text is safe; progress/total are step counters. Best-effort: a
    /// formatting or write failure is silently dropped — a missed progress
    /// note must never derail the tool run. (The whole line must fit 1024
    /// bytes; longer messages are dropped, not truncated.)
    pub fn report(self: Progress, progress: u64, total: u64, message: []const u8) void {
        var buf: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        w.print(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":{s},\"progress\":{d},\"total\":{d},\"message\":",
            .{ self.token_json, progress, total },
        ) catch return;
        std.json.Stringify.encodeJsonString(message, .{}, &w) catch return;
        w.writeAll("}}\n") catch return;
        self.out.writeAll(w.buffered()) catch return;
        self.out.flush() catch {};
    }
};

// ── tool registration ───────────────────────────────────────────────────────

/// Everything a tool handler gets for one `tools/call`: the per-request arena
/// (freed after the response is written — allocate freely, never store), the
/// parsed `arguments` object (`.null` when the client sent none), the
/// progress reporter (null unless the client opted in via a progressToken),
/// and the output buffer the textual result accumulates into.
pub const ToolCall = struct {
    /// Per-request arena; everything allocated here dies with the response.
    arena: std.mem.Allocator,
    /// The parsed `arguments` value (`.null` when absent).
    args: std.json.Value,
    /// Progress reporter — present only when the client sent a progressToken.
    progress: ?Progress,
    /// The tool's textual result (JSON text or plain text) accumulates here.
    out: *std.ArrayList(u8),

    /// Append raw bytes to the result. OOM is swallowed (a truncated tool
    /// result surfaces to the agent as malformed output, never as a crash).
    pub fn write(self: *ToolCall, bytes: []const u8) void {
        self.out.appendSlice(self.arena, bytes) catch {};
    }

    /// Append formatted text to the result (same OOM policy as `write`).
    pub fn print(self: *ToolCall, comptime fmt: []const u8, args: anytype) void {
        const text = std.fmt.allocPrint(self.arena, fmt, args) catch return;
        self.out.appendSlice(self.arena, text) catch {};
    }

    /// Fetch a required/optional string argument, or null when absent or not
    /// a string.
    pub fn strArg(self: *const ToolCall, key: []const u8) ?[]const u8 {
        if (self.args != .object) return null;
        return switch (self.args.object.get(key) orelse return null) {
            .string => |s| s,
            else => null,
        };
    }

    /// Write a tool-failure message and return `true` (the handler's isError
    /// flag), so handlers can `return call.fail("missing 'x'")` on every
    /// failure path.
    pub fn fail(self: *ToolCall, msg: []const u8) bool {
        self.write("error: ");
        self.write(msg);
        return true;
    }

    /// Emit one `notifications/progress` — a no-op when the client did not
    /// supply a progressToken.
    pub fn reportProgress(self: *const ToolCall, progress: u64, total: u64, message: []const u8) void {
        if (self.progress) |p| p.report(progress, total, message);
    }
};

/// A tool handler: `ctx` is the opaque app-state pointer given at
/// registration (this is how one live application object serves every call);
/// `call` carries the arguments/arena/progress/output. Return `true` for a
/// tool *failure* (missing required argument, unexpected internal error) so
/// the response is marked `isError:true`; a domain answer the tool produced
/// on purpose — e.g. `{"ok":false,...}` — is *not* a failure (return `false`):
/// it is a valid result the agent should read.
pub const Handler = *const fn (ctx: ?*anyopaque, call: *ToolCall) bool;

/// One registered MCP tool. `input_schema`/`output_schema` are JSON-Schema
/// **text** (object literals; pretty-printed is fine — `tools/list` re-emits
/// them compact through the JSON serializer). `output_schema` = "" declares
/// none. `allow_structured` gates MCP `structuredContent`: when true and the
/// tool's textual output is a single top-level JSON object, the result also
/// carries it parsed as `structuredContent`; set false for tools whose output
/// is a stream (e.g. NDJSON) so a trivially single-object output never
/// changes the contract.
pub const Tool = struct {
    name: []const u8,
    description: []const u8,
    input_schema: []const u8,
    output_schema: []const u8 = "",
    allow_structured: bool = true,
    handler: Handler,
    /// Opaque app-state pointer threaded to every call of this tool.
    ctx: ?*anyopaque = null,
};

// ── resource registration ───────────────────────────────────────────────────

/// Everything a resource handler gets for one `resources/read`: the requested
/// uri (so one template handler can serve a whole uri family), the
/// per-request arena (freed after the response is written — allocate freely,
/// never store), and the contents accumulator the handler fills via `text`/
/// `blob`.
pub const ResourceRequest = struct {
    /// Per-request arena; everything allocated here dies with the response.
    arena: std.mem.Allocator,
    /// The uri the client asked to read (verbatim from params).
    uri: []const u8,
    /// Accumulated content items (internal; fill via `text`/`blob`).
    contents: std.ArrayList(ContentItem) = .empty,

    const ContentItem = struct {
        uri: []const u8,
        mime_type: []const u8, // "" = omitted from the response
        data: []const u8, // text, or already-base64 blob
        is_blob: bool,
    };

    /// Append one text content item. `mime_type` "" omits the field. OOM is
    /// swallowed (a truncated resource surfaces as short contents, never as a
    /// crash — same policy as `ToolCall.write`).
    pub fn text(self: *ResourceRequest, uri: []const u8, mime_type: []const u8, data: []const u8) void {
        self.contents.append(self.arena, .{ .uri = uri, .mime_type = mime_type, .data = data, .is_blob = false }) catch {};
    }

    /// Append one binary content item: `bytes` are base64-encoded (standard
    /// alphabet, padded) into the arena and emitted as `blob` (same OOM
    /// policy as `text`).
    pub fn blob(self: *ResourceRequest, uri: []const u8, mime_type: []const u8, bytes: []const u8) void {
        const enc = std.base64.standard.Encoder;
        const buf = self.arena.alloc(u8, enc.calcSize(bytes.len)) catch return;
        const encoded = enc.encode(buf, bytes);
        self.contents.append(self.arena, .{ .uri = uri, .mime_type = mime_type, .data = encoded, .is_blob = true }) catch {};
    }
};

/// A resource read handler: `ctx` is the opaque app-state pointer given at
/// registration; `req` carries the requested uri + arena + contents
/// accumulator. Return `true` when the uri was served; `false` means "not
/// mine / gone" and the read answers -32002 Resource not found (for a static
/// resource that is a vanished backing store; for a template handler simply a
/// uri it does not match).
pub const ResourceHandler = *const fn (ctx: ?*anyopaque, req: *ResourceRequest) bool;

/// One registered MCP resource: a static uri + the handler that produces its
/// contents on `resources/read`. `description`/`mime_type` = "" omit the
/// field from `resources/list`.
pub const Resource = struct {
    uri: []const u8,
    name: []const u8,
    description: []const u8 = "",
    mime_type: []const u8 = "",
    handler: ResourceHandler,
    /// Opaque app-state pointer threaded to every read of this resource.
    ctx: ?*anyopaque = null,
};

/// One registered MCP resource template (RFC 6570 uriTemplate, advertised via
/// `resources/templates/list`). When `handler` is set, `resources/read` tries
/// it for any uri that matched no static resource — the handler inspects
/// `req.uri` itself (this module does not evaluate uri templates) and returns
/// `false` to decline. A null handler is advertise-only.
pub const ResourceTemplate = struct {
    uri_template: []const u8,
    name: []const u8,
    description: []const u8 = "",
    mime_type: []const u8 = "",
    handler: ?ResourceHandler = null,
    /// Opaque app-state pointer threaded to every read this template serves.
    ctx: ?*anyopaque = null,
};

// ── prompt registration ─────────────────────────────────────────────────────

/// One declared prompt argument (advertised in `prompts/list`; `required`
/// ones are validated by the server before the handler runs).
pub const PromptArgument = struct {
    name: []const u8,
    description: []const u8 = "", // "" = omitted from prompts/list
    required: bool = false,
};

/// Everything a prompt handler gets for one `prompts/get`: the per-request
/// arena, the parsed `arguments` object (`.null` when the client sent none;
/// declared required arguments are already validated as present strings), and
/// the messages accumulator filled via `message`.
pub const PromptRequest = struct {
    /// Per-request arena; everything allocated here dies with the response.
    arena: std.mem.Allocator,
    /// The parsed `arguments` value (`.null` when absent).
    args: std.json.Value,
    /// Accumulated messages (internal; fill via `message`).
    messages: std.ArrayList(Message) = .empty,

    /// MCP prompt message roles.
    pub const Role = enum { user, assistant };

    const Message = struct {
        role: Role,
        text: []const u8,
    };

    /// Fetch a string argument, or null when absent or not a string.
    pub fn strArg(self: *const PromptRequest, key: []const u8) ?[]const u8 {
        if (self.args != .object) return null;
        return switch (self.args.object.get(key) orelse return null) {
            .string => |s| s,
            else => null,
        };
    }

    /// Append one text message to the rendered prompt (OOM swallowed — same
    /// policy as `ToolCall.write`).
    pub fn message(self: *PromptRequest, role: Role, msg_text: []const u8) void {
        self.messages.append(self.arena, .{ .role = role, .text = msg_text }) catch {};
    }

    /// Append one formatted text message (same OOM policy as `message`).
    pub fn printMessage(self: *PromptRequest, role: Role, comptime fmt: []const u8, fmt_args: anytype) void {
        const rendered = std.fmt.allocPrint(self.arena, fmt, fmt_args) catch return;
        self.message(role, rendered);
    }
};

/// A prompt handler: `ctx` is the opaque app-state pointer given at
/// registration; `req` carries the arguments/arena/messages. Return `true` on
/// success; `false` signals an internal rendering failure and the get answers
/// -32603 (missing *declared required* arguments never reach the handler —
/// the server already answered -32602).
pub const PromptHandler = *const fn (ctx: ?*anyopaque, req: *PromptRequest) bool;

/// One registered MCP prompt: name + declared arguments + the handler that
/// renders the messages on `prompts/get`. `description` = "" omits the field.
pub const Prompt = struct {
    name: []const u8,
    description: []const u8 = "",
    arguments: []const PromptArgument = &.{},
    handler: PromptHandler,
    /// Opaque app-state pointer threaded to every get of this prompt.
    ctx: ?*anyopaque = null,
};

/// Server identity for the `initialize` result. `title` defaults to `name`;
/// `instructions` (spec: usage hints for the agent) is omitted when null.
pub const Info = struct {
    name: []const u8,
    version: []const u8,
    title: ?[]const u8 = null,
    instructions: ?[]const u8 = null,
};

// ── server ──────────────────────────────────────────────────────────────────

pub const Server = struct {
    gpa: std.mem.Allocator,
    info: Info,
    tools: std.ArrayList(Tool) = .empty,
    resources: std.ArrayList(Resource) = .empty,
    resource_templates: std.ArrayList(ResourceTemplate) = .empty,
    prompts: std.ArrayList(Prompt) = .empty,
    /// Set when the client sends `notifications/initialized`.
    client_initialized: bool = false,

    pub fn init(gpa: std.mem.Allocator, info: Info) Server {
        return .{ .gpa = gpa, .info = info };
    }

    pub fn deinit(self: *Server) void {
        self.tools.deinit(self.gpa);
        self.resources.deinit(self.gpa);
        self.resource_templates.deinit(self.gpa);
        self.prompts.deinit(self.gpa);
    }

    /// Register a tool. All slices in `tool` (name, description, schemas) must
    /// outlive the server — typically they are static literals or app-owned.
    pub fn addTool(self: *Server, tool: Tool) error{ OutOfMemory, DuplicateTool }!void {
        if (self.findTool(tool.name) != null) return error.DuplicateTool;
        try self.tools.append(self.gpa, tool);
    }

    fn findTool(self: *const Server, name: []const u8) ?*const Tool {
        for (self.tools.items) |*t| {
            if (std.mem.eql(u8, t.name, name)) return t;
        }
        return null;
    }

    /// Register a static resource. All slices must outlive the server (same
    /// contract as `addTool`). Duplicate uris are rejected.
    pub fn addResource(self: *Server, resource: Resource) error{ OutOfMemory, DuplicateResource }!void {
        if (self.findResource(resource.uri) != null) return error.DuplicateResource;
        try self.resources.append(self.gpa, resource);
    }

    fn findResource(self: *const Server, uri: []const u8) ?*const Resource {
        for (self.resources.items) |*r| {
            if (std.mem.eql(u8, r.uri, uri)) return r;
        }
        return null;
    }

    /// Register a resource template. All slices must outlive the server.
    /// Duplicate uriTemplates are rejected.
    pub fn addResourceTemplate(self: *Server, template: ResourceTemplate) error{ OutOfMemory, DuplicateResourceTemplate }!void {
        for (self.resource_templates.items) |*t| {
            if (std.mem.eql(u8, t.uri_template, template.uri_template)) return error.DuplicateResourceTemplate;
        }
        try self.resource_templates.append(self.gpa, template);
    }

    /// Register a prompt. All slices (including the `arguments` slice) must
    /// outlive the server. Duplicate names are rejected.
    pub fn addPrompt(self: *Server, prompt: Prompt) error{ OutOfMemory, DuplicatePrompt }!void {
        if (self.findPrompt(prompt.name) != null) return error.DuplicatePrompt;
        try self.prompts.append(self.gpa, prompt);
    }

    fn findPrompt(self: *const Server, name: []const u8) ?*const Prompt {
        for (self.prompts.items) |*p| {
            if (std.mem.eql(u8, p.name, name)) return p;
        }
        return null;
    }

    /// Serve newline-delimited JSON-RPC until EOF: read one line, handle it,
    /// repeat. Works over any reader/writer pair — stdio, an in-memory pipe,
    /// a socket. A read failure ends the loop like EOF (the seed behavior: a
    /// dying peer is a session end, not a server error).
    pub fn serve(self: *Server, in: *std.Io.Reader, out: *std.Io.Writer) Error!void {
        var line_buf: std.ArrayList(u8) = .empty;
        defer line_buf.deinit(self.gpa);
        while (try readLine(self.gpa, in, &line_buf)) |line| {
            try self.handleMessage(line, out);
        }
    }

    /// Built-in stdio transport: newline-delimited JSON-RPC over
    /// stdin/stdout — the MCP stdio framing. Buffers are internal; every
    /// response line is flushed before the next read.
    pub fn serveStdio(self: *Server, io: std.Io) Error!void {
        var read_buf: [64 * 1024]u8 = undefined;
        var write_buf: [64 * 1024]u8 = undefined;
        var stdin_reader = std.Io.File.stdin().readerStreaming(io, &read_buf);
        var stdout_writer = std.Io.File.stdout().writerStreaming(io, &write_buf);
        return self.serve(&stdin_reader.interface, &stdout_writer.interface);
    }

    /// Handle exactly one JSON-RPC message: parse it, dispatch it, write the
    /// response line (if any — notifications get none) to `out` and flush.
    /// Malformed input becomes a JSON-RPC error response, never a panic or a
    /// Zig error; only OOM and transport write failure surface as errors.
    /// All transient work lives on a per-message arena freed before return.
    pub fn handleMessage(self: *Server, msg: []const u8, out: *std.Io.Writer) Error!void {
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const input = std.mem.trim(u8, msg, " \t\r\n");
        if (input.len == 0) return;

        const root = std.json.parseFromSliceLeaky(std.json.Value, arena, input, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return sendError(arena, out, null, error_code.parse_error, "Parse error"),
        };

        // A batch array (or any non-object) is -32600: MCP does not use
        // JSON-RPC batching, so it is deliberately unsupported here.
        if (root != .object) {
            return sendError(arena, out, null, error_code.invalid_request, "Invalid request");
        }
        const obj = root.object;
        const id: ?std.json.Value = obj.get("id"); // absent => notification, no response

        const method_v = obj.get("method") orelse {
            if (id != null) return sendError(arena, out, id, error_code.invalid_request, "Missing method");
            return;
        };
        if (method_v != .string) {
            if (id != null) return sendError(arena, out, id, error_code.invalid_request, "Invalid method");
            return;
        }
        const method = method_v.string;

        // A request (has `id`) gets exactly one response; a notification (no
        // `id`) must get none. `notifications/initialized` is the only method
        // accepted without an id — every other id-less line is a stray
        // notification we drop.
        if (eql(method, "notifications/initialized")) {
            self.client_initialized = true;
        } else if (id == null) {
            // notification for a request-only method: ignore, never respond.
        } else if (eql(method, "initialize")) {
            try self.handleInitialize(arena, out, id, obj.get("params"));
        } else if (eql(method, "tools/list")) {
            const list = self.buildToolsList(arena) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // A registered schema literal that is not valid JSON is a
                // server-side defect — surface it as -32603, don't crash.
                else => return sendError(arena, out, id, error_code.internal_error, "failed to build tools/list"),
            };
            try sendResultRaw(arena, out, id, list);
        } else if (eql(method, "ping")) {
            try sendResultRaw(arena, out, id, "{}");
        } else if (eql(method, "tools/call")) {
            try self.handleCall(arena, out, id, obj.get("params"));
        } else if (eql(method, "resources/list")) {
            try self.handleResourcesList(arena, out, id);
        } else if (eql(method, "resources/read")) {
            try self.handleResourcesRead(arena, out, id, obj.get("params"));
        } else if (eql(method, "resources/templates/list")) {
            try self.handleTemplatesList(arena, out, id);
        } else if (eql(method, "prompts/list")) {
            try self.handlePromptsList(arena, out, id);
        } else if (eql(method, "prompts/get")) {
            try self.handlePromptsGet(arena, out, id, obj.get("params"));
        } else {
            try sendError(arena, out, id, error_code.method_not_found, "Method not found");
        }
    }

    fn handleInitialize(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value) Error!void {
        // Extract the client's requested protocolVersion (if any) and echo it
        // back when supported; otherwise answer with our latest.
        var requested: ?[]const u8 = null;
        if (params_opt) |params| {
            if (params == .object) {
                if (params.object.get("protocolVersion")) |pv| {
                    if (pv == .string) requested = pv.string;
                }
            }
        }
        const version = negotiateVersion(requested);

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        self.buildInitializeResult(&jw, version) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn buildInitializeResult(self: *const Server, jw: *std.json.Stringify, version: []const u8) std.Io.Writer.Error!void {
        try jw.beginObject();
        try jw.objectField("protocolVersion");
        try jw.write(version);
        try jw.objectField("capabilities");
        try jw.beginObject();
        try jw.objectField("tools");
        try jw.beginObject();
        try jw.objectField("listChanged");
        try jw.write(false);
        try jw.endObject();
        try jw.objectField("resources");
        try jw.beginObject();
        try jw.objectField("subscribe");
        try jw.write(false);
        try jw.objectField("listChanged");
        try jw.write(false);
        try jw.endObject();
        try jw.objectField("prompts");
        try jw.beginObject();
        try jw.objectField("listChanged");
        try jw.write(false);
        try jw.endObject();
        try jw.endObject();
        try jw.objectField("serverInfo");
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(self.info.name);
        try jw.objectField("title");
        try jw.write(self.info.title orelse self.info.name);
        try jw.objectField("version");
        try jw.write(self.info.version);
        try jw.endObject();
        if (self.info.instructions) |instr| {
            try jw.objectField("instructions");
            try jw.write(instr);
        }
        try jw.endObject();
    }

    /// Assemble the JSON-RPC `tools/list` result from the registered catalog
    /// via the JSON serializer, so the serializer handles all string escaping.
    /// The `input_schema`/`output_schema` literals are parsed to a Value and
    /// re-emitted, so they flow through the same serializer (single source:
    /// the registered Tool) and an invalid literal is caught here.
    fn buildToolsList(self: *const Server, arena: std.mem.Allocator) ![]u8 {
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        try jw.beginObject();
        try jw.objectField("tools");
        try jw.beginArray();
        for (self.tools.items) |t| {
            try jw.beginObject();
            try jw.objectField("name");
            try jw.write(t.name);
            try jw.objectField("description");
            try jw.write(t.description);
            try jw.objectField("inputSchema");
            try writeRawJson(arena, &jw, t.input_schema);
            if (t.output_schema.len != 0) {
                try jw.objectField("outputSchema");
                try writeRawJson(arena, &jw, t.output_schema);
            }
            try jw.endObject();
        }
        try jw.endArray();
        try jw.endObject();
        return aw.written();
    }

    fn handleCall(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value) Error!void {
        const params = params_opt orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Missing params");
        };
        if (params != .object) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        }
        const name_v = params.object.get("name") orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Missing tool name");
        };
        if (name_v != .string) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid tool name");
        }
        // Unknown tool => -32602 (the seed's choice; MCP treats an unknown
        // tool name as invalid params on tools/call, not a missing method).
        const tool = self.findTool(name_v.string) orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Unknown tool");
        };

        const args: std.json.Value = params.object.get("arguments") orelse .null;

        // MCP progress: a `params._meta.progressToken` opts the call into
        // server→client `notifications/progress`. Serialize the token
        // verbatim (string or number) so the reporter can echo it on every
        // notification.
        const prog: ?Progress = blk: {
            const meta_v = params.object.get("_meta") orelse break :blk null;
            if (meta_v != .object) break :blk null;
            const token = meta_v.object.get("progressToken") orelse break :blk null;
            if (token != .string and token != .integer) break :blk null;
            const token_json = std.json.Stringify.valueAlloc(arena, token, .{}) catch break :blk null;
            break :blk Progress{ .out = out, .token_json = token_json };
        };

        var tool_buf: std.ArrayList(u8) = .empty;
        var call = ToolCall{ .arena = arena, .args = args, .progress = prog, .out = &tool_buf };
        const is_error = tool.handler(tool.ctx, &call);
        try sendToolResult(arena, out, id, tool_buf.items, tool.allow_structured, is_error);
    }

    /// Assemble + send the `resources/list` result from the registered
    /// catalog (no pagination — never emits `nextCursor`).
    fn handleResourcesList(self: *const Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value) Error!void {
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        self.buildResourcesList(&jw) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn buildResourcesList(self: *const Server, jw: *std.json.Stringify) std.Io.Writer.Error!void {
        try jw.beginObject();
        try jw.objectField("resources");
        try jw.beginArray();
        for (self.resources.items) |r| {
            try jw.beginObject();
            try jw.objectField("uri");
            try jw.write(r.uri);
            try jw.objectField("name");
            try jw.write(r.name);
            if (r.description.len != 0) {
                try jw.objectField("description");
                try jw.write(r.description);
            }
            if (r.mime_type.len != 0) {
                try jw.objectField("mimeType");
                try jw.write(r.mime_type);
            }
            try jw.endObject();
        }
        try jw.endArray();
        try jw.endObject();
    }

    /// Assemble + send the `resources/templates/list` result from the
    /// registered template catalog.
    fn handleTemplatesList(self: *const Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value) Error!void {
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        self.buildTemplatesList(&jw) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn buildTemplatesList(self: *const Server, jw: *std.json.Stringify) std.Io.Writer.Error!void {
        try jw.beginObject();
        try jw.objectField("resourceTemplates");
        try jw.beginArray();
        for (self.resource_templates.items) |t| {
            try jw.beginObject();
            try jw.objectField("uriTemplate");
            try jw.write(t.uri_template);
            try jw.objectField("name");
            try jw.write(t.name);
            if (t.description.len != 0) {
                try jw.objectField("description");
                try jw.write(t.description);
            }
            if (t.mime_type.len != 0) {
                try jw.objectField("mimeType");
                try jw.write(t.mime_type);
            }
            try jw.endObject();
        }
        try jw.endArray();
        try jw.endObject();
    }

    /// `resources/read`: validate params, resolve the uri (exact resource
    /// match first, then template handlers in registration order), and send
    /// the contents the handler filled. Unresolvable uri => -32002.
    fn handleResourcesRead(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value) Error!void {
        const params = params_opt orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Missing params");
        };
        if (params != .object) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        }
        const uri_v = params.object.get("uri") orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Missing uri");
        };
        if (uri_v != .string) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid uri");
        }

        var req = ResourceRequest{ .arena = arena, .uri = uri_v.string };
        const found = blk: {
            if (self.findResource(req.uri)) |r| break :blk r.handler(r.ctx, &req);
            for (self.resource_templates.items) |*t| {
                const handler = t.handler orelse continue;
                if (handler(t.ctx, &req)) break :blk true;
                // A declining template may have written partial contents
                // before bailing — discard them before trying the next one.
                req.contents.clearRetainingCapacity();
            }
            break :blk false;
        };
        if (!found) {
            return sendError(arena, out, id, error_code.resource_not_found, "Resource not found");
        }

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildReadResult(&jw, &req) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    /// Assemble + send the `prompts/list` result from the registered catalog
    /// (no pagination — never emits `nextCursor`).
    fn handlePromptsList(self: *const Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value) Error!void {
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        self.buildPromptsList(&jw) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn buildPromptsList(self: *const Server, jw: *std.json.Stringify) std.Io.Writer.Error!void {
        try jw.beginObject();
        try jw.objectField("prompts");
        try jw.beginArray();
        for (self.prompts.items) |p| {
            try jw.beginObject();
            try jw.objectField("name");
            try jw.write(p.name);
            if (p.description.len != 0) {
                try jw.objectField("description");
                try jw.write(p.description);
            }
            if (p.arguments.len != 0) {
                try jw.objectField("arguments");
                try jw.beginArray();
                for (p.arguments) |a| {
                    try jw.beginObject();
                    try jw.objectField("name");
                    try jw.write(a.name);
                    if (a.description.len != 0) {
                        try jw.objectField("description");
                        try jw.write(a.description);
                    }
                    if (a.required) {
                        try jw.objectField("required");
                        try jw.write(true);
                    }
                    try jw.endObject();
                }
                try jw.endArray();
            }
            try jw.endObject();
        }
        try jw.endArray();
        try jw.endObject();
    }

    /// `prompts/get`: validate params + the declared required arguments
    /// (-32602 on any miss, so a handler never sees an incomplete required
    /// set), dispatch to the handler, send the rendered messages.
    fn handlePromptsGet(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value) Error!void {
        const params = params_opt orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Missing params");
        };
        if (params != .object) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        }
        const name_v = params.object.get("name") orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Missing prompt name");
        };
        if (name_v != .string) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid prompt name");
        }
        // Unknown prompt => -32602, mirroring the tools/call choice for an
        // unknown tool name (the method exists; the params point nowhere).
        const prompt = self.findPrompt(name_v.string) orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Unknown prompt");
        };

        const args: std.json.Value = params.object.get("arguments") orelse .null;
        if (args != .null and args != .object) {
            return sendError(arena, out, id, error_code.invalid_params, "Invalid arguments");
        }
        for (prompt.arguments) |a| {
            if (!a.required) continue;
            const present = blk: {
                if (args != .object) break :blk false;
                const v = args.object.get(a.name) orelse break :blk false;
                break :blk v == .string; // MCP prompt argument values are strings
            };
            if (!present) {
                return sendError(arena, out, id, error_code.invalid_params, "Missing required argument");
            }
        }

        var req = PromptRequest{ .arena = arena, .args = args };
        if (!prompt.handler(prompt.ctx, &req)) {
            return sendError(arena, out, id, error_code.internal_error, "Prompt failed");
        }

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildPromptResult(&jw, prompt, &req) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }
};

/// Serialize one `resources/read` result: `{"contents":[{uri, mimeType?,
/// text|blob}, …]}` — `blob` carries the base64 the handler's `blob()` call
/// already encoded.
fn buildReadResult(jw: *std.json.Stringify, req: *const ResourceRequest) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("contents");
    try jw.beginArray();
    for (req.contents.items) |c| {
        try jw.beginObject();
        try jw.objectField("uri");
        try jw.write(c.uri);
        if (c.mime_type.len != 0) {
            try jw.objectField("mimeType");
            try jw.write(c.mime_type);
        }
        try jw.objectField(if (c.is_blob) "blob" else "text");
        try jw.write(c.data);
        try jw.endObject();
    }
    try jw.endArray();
    try jw.endObject();
}

/// Serialize one `prompts/get` result: `{description?, messages:[{role,
/// content:{type:"text", text}}, …]}` — description comes from the
/// registration (omitted when "").
fn buildPromptResult(jw: *std.json.Stringify, prompt: *const Prompt, req: *const PromptRequest) std.Io.Writer.Error!void {
    try jw.beginObject();
    if (prompt.description.len != 0) {
        try jw.objectField("description");
        try jw.write(prompt.description);
    }
    try jw.objectField("messages");
    try jw.beginArray();
    for (req.messages.items) |m| {
        try jw.beginObject();
        try jw.objectField("role");
        try jw.write(@tagName(m.role));
        try jw.objectField("content");
        try jw.beginObject();
        try jw.objectField("type");
        try jw.write("text");
        try jw.objectField("text");
        try jw.write(m.text);
        try jw.endObject();
        try jw.endObject();
    }
    try jw.endArray();
    try jw.endObject();
}

// ── response senders (build one line on the arena, write it, flush) ─────────

fn flushLine(out: *std.Io.Writer, line: []const u8) Error!void {
    try out.writeAll(line);
    try out.flush();
}

fn sendError(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, code: i32, msg: []const u8) Error!void {
    var aw: std.Io.Writer.Allocating = .init(arena);
    writeErrorLine(&aw.writer, id, code, msg) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

fn sendResultRaw(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, raw: []const u8) Error!void {
    var aw: std.Io.Writer.Allocating = .init(arena);
    writeResultLine(&aw.writer, id, raw) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

/// Serialize + send one `tools/call` result: a text content block (the tool's
/// textual output, JSON-escaped), plus MCP 2025-06-18+ `structuredContent`
/// when the tool allows it and the output is a single JSON object — gated on
/// the tool's declared shape (`allow_structured`) AND a structural re-check,
/// so an error/text blob never emits invalid structure. `isError:true` marks
/// a tool failure so the agent notices; a domain `{"ok":false}` answer keeps
/// `isError:false`.
fn sendToolResult(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, text: []const u8, allow_structured: bool, is_error: bool) Error!void {
    var aw: std.Io.Writer.Allocating = .init(arena);
    buildToolResultLine(&aw.writer, id, text, allow_structured, is_error) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

fn buildToolResultLine(w: *std.Io.Writer, id: ?std.json.Value, text: []const u8, allow_structured: bool, is_error: bool) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.writeAll(",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try std.json.Stringify.encodeJsonString(text, .{}, w);
    try w.writeAll("}]");
    if (allow_structured and isSingleJsonObject(text)) {
        try w.writeAll(",\"structuredContent\":");
        try writeStrippingNewlines(w, text);
    }
    try w.writeAll(if (is_error) ",\"isError\":true}}\n" else ",\"isError\":false}}\n");
}

/// Emit a raw JSON-Schema literal through the serializer: parse it to a Value
/// and `write` it, so it is validated and re-serialized in the same stream
/// (keeping `jw`'s object/array state consistent).
fn writeRawJson(arena: std.mem.Allocator, jw: *std.json.Stringify, raw: []const u8) !void {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{});
    try jw.write(v);
}

// ── line framing ────────────────────────────────────────────────────────────

/// Read one newline-terminated line into the reusable buffer (grows as
/// needed, so a tools/call line carrying a large payload is handled). Returns
/// the line slice (without '\n'), or null at EOF. A read failure counts as
/// EOF.
fn readLine(gpa: std.mem.Allocator, reader: *std.Io.Reader, buf: *std.ArrayList(u8)) Error!?[]u8 {
    buf.clearRetainingCapacity();
    while (true) {
        const byte = reader.takeByte() catch {
            if (buf.items.len == 0) return null;
            return buf.items;
        };
        if (byte == '\n') return buf.items;
        try buf.append(gpa, byte);
    }
}

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// True when `text` is exactly one top-level JSON object (`{ … }`) followed
/// by nothing but whitespace — the only shape MCP `structuredContent`
/// accepts. Brace-matches with string/escape awareness so NDJSON (many `{…}`
/// lines) and bare arrays are correctly rejected, not concatenated into
/// invalid JSON by the later newline-strip.
fn isSingleJsonObject(text: []const u8) bool {
    var i: usize = 0;
    while (i < text.len and isWs(text[i])) : (i += 1) {}
    if (i >= text.len or text[i] != '{') return false;

    var depth: usize = 0;
    var in_str = false;
    var escaped = false;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (in_str) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '{', '[' => depth += 1,
            '}', ']' => {
                if (depth == 0) return false; // unbalanced
                depth -= 1;
                if (depth == 0) {
                    // top-level value closed: the remainder must be whitespace.
                    i += 1;
                    while (i < text.len) : (i += 1) {
                        if (!isWs(text[i])) return false;
                    }
                    return true;
                }
            },
            else => {},
        }
    }
    return false; // unterminated
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// App state for ctx-threading tests: the whole point of the module is that a
/// tool handler reaches live application state through the ctx pointer.
const TestApp = struct {
    calls: u32 = 0,
    last_text: [64]u8 = @splat(0),
    last_text_len: usize = 0,
};

fn echoHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    const app: *TestApp = @ptrCast(@alignCast(ctx.?));
    app.calls += 1;
    const text = call.strArg("text") orelse return call.fail("missing 'text'");
    const n = @min(text.len, app.last_text.len);
    @memcpy(app.last_text[0..n], text[0..n]);
    app.last_text_len = n;
    call.print("{{\"echo\":\"{s}\",\"calls\":{d}}}", .{ text, app.calls });
    return false;
}

fn ndjsonHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("{\"line\":1}\n{\"line\":2}\n");
    return false;
}

fn slowHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.reportProgress(1, 2, "halfway");
    call.reportProgress(2, 2, "done");
    call.write("{\"done\":true}");
    return false;
}

fn plainTextHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("hello, plain text");
    return false;
}

const echo_tool = Tool{
    .name = "echo",
    .description = "Echo the 'text' argument back.",
    .input_schema =
    \\{
    \\  "type": "object",
    \\  "properties": { "text": { "type": "string" } },
    \\  "required": ["text"]
    \\}
    ,
    .output_schema =
    \\{ "type": "object", "properties": { "echo": { "type": "string" }, "calls": { "type": "integer" } } }
    ,
    .handler = &echoHandler,
};

fn testServer(app: ?*TestApp) Server {
    var s = Server.init(testing.allocator, .{
        .name = "test-srv",
        .version = "1.2.3",
        .instructions = "use echo",
    });
    var tool = echo_tool;
    tool.ctx = app;
    s.addTool(tool) catch unreachable;
    return s;
}

/// Feed one message, assert the exact response bytes (or "" for no response).
fn expectResponse(s: *Server, msg: []const u8, expected: []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(msg, &aw.writer);
    try testing.expectEqualStrings(expected, aw.written());
}

test "jsonrpc: malformed JSON -> -32700, no panic" {
    var s = testServer(null);
    defer s.deinit();
    try expectResponse(&s, "{oops",
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\
    );
    try expectResponse(&s, "\x00\xff\xfe",
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\
    );
}

test "jsonrpc: non-object (incl. batch array) -> -32600" {
    var s = testServer(null);
    defer s.deinit();
    // Batch arrays are deliberately unsupported — MCP does not use them.
    try expectResponse(&s, "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]",
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request"}}
        \\
    );
    try expectResponse(&s, "\"hello\"",
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request"}}
        \\
    );
}

test "jsonrpc: missing/invalid method -> -32600 (only when id present)" {
    var s = testServer(null);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Missing method"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":42}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid method"}}
        \\
    );
    // No id => notification => no response, even when malformed.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\"}", "");
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"method\":7}", "");
}

test "jsonrpc: unknown method -> -32601; id-less unknown -> dropped" {
    var s = testServer(null);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"bogus/method\"}",
        \\{"jsonrpc":"2.0","id":9,"error":{"code":-32601,"message":"Method not found"}}
        \\
    );
    // Stray notification for a request-only method: no response.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}", "");
}

test "jsonrpc: string id is echoed with quotes; ping answers {}" {
    var s = testServer(null);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":"abc","result":{}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":7,"result":{}}
        \\
    );
}

test "jsonrpc: encode all standard error codes" {
    const cases = [_]struct { code: i32, msg: []const u8 }{
        .{ .code = error_code.parse_error, .msg = "Parse error" },
        .{ .code = error_code.invalid_request, .msg = "Invalid request" },
        .{ .code = error_code.method_not_found, .msg = "Method not found" },
        .{ .code = error_code.invalid_params, .msg = "Invalid params" },
        .{ .code = error_code.internal_error, .msg = "Internal error" },
    };
    inline for (cases) |c| {
        var buf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try writeErrorLine(&w, .{ .integer = 3 }, c.code, c.msg);
        const expected = try std.fmt.allocPrint(
            testing.allocator,
            "{{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{{\"code\":{d},\"message\":\"{s}\"}}}}\n",
            .{ c.code, c.msg },
        );
        defer testing.allocator.free(expected);
        try testing.expectEqualStrings(expected, w.buffered());
    }
}

test "jsonrpc: writeResultLine strips raw newlines from spliced result" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeResultLine(&w, null, "{\n  \"a\": 1\r\n}");
    try testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":{  \"a\": 1}}\n",
        w.buffered(),
    );
}

test "initialize: version negotiation + capabilities + serverInfo golden" {
    var s = testServer(null);
    defer s.deinit();
    // Client requests a supported older revision -> echoed back.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}
    ,
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\
    );
    // Unsupported revision -> answer with our latest.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\
    );
    // No params at all -> latest, no crash.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize"}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\
    );
}

test "initialize: instructions omitted when null; title override" {
    var s = Server.init(testing.allocator, .{ .name = "bare", .version = "0.1.0", .title = "Bare Server" });
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"bare","title":"Bare Server","version":"0.1.0"}}}
        \\
    );
}

test "negotiateVersion unit" {
    try testing.expectEqualStrings("2025-11-25", negotiateVersion(null));
    try testing.expectEqualStrings("2025-11-25", negotiateVersion("bogus"));
    try testing.expectEqualStrings("2025-06-18", negotiateVersion("2025-06-18"));
    try testing.expectEqualStrings("2025-11-25", negotiateVersion("2025-11-25"));
}

test "notifications/initialized: no response, flag set" {
    var s = testServer(null);
    defer s.deinit();
    try testing.expect(!s.client_initialized);
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", "");
    try testing.expect(s.client_initialized);
}

test "tools/list: golden JSON from the registered catalog" {
    var s = testServer(null);
    defer s.deinit();
    try s.addTool(.{
        .name = "plain",
        .description = "No output schema.",
        .input_schema = "{\"type\":\"object\",\"properties\":{}}",
        .handler = &plainTextHandler,
    });
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}",
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo the 'text' argument back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]},"outputSchema":{"type":"object","properties":{"echo":{"type":"string"},"calls":{"type":"integer"}}}},{"name":"plain","description":"No output schema.","inputSchema":{"type":"object","properties":{}}}]}}
        \\
    );
}

test "tools/list: invalid registered schema literal -> -32603" {
    var s = Server.init(testing.allocator, .{ .name = "bad", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "broken",
        .description = "schema is not JSON",
        .input_schema = "{not json",
        .handler = &plainTextHandler,
    });
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"failed to build tools/list"}}
        \\
    );
}

test "tools/call: param validation errors -> -32602" {
    var s = testServer(null);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Missing params"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":[]}",
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid params"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{}}",
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Missing tool name"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":5}}",
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Invalid tool name"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"nope\"}}",
        \\{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"Unknown tool"}}
        \\
    );
}

test "tools/call: dispatch threads ctx to app state; structuredContent + text fallback" {
    var app = TestApp{};
    var s = testServer(&app);
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}
    ,
        \\{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"{\"echo\":\"hi\",\"calls\":1}"}],"structuredContent":{"echo":"hi","calls":1},"isError":false}}
        \\
    );
    // The handler reached the live app state through the ctx pointer.
    try testing.expectEqual(@as(u32, 1), app.calls);
    try testing.expectEqualStrings("hi", app.last_text[0..app.last_text_len]);
    // Second call: state persists across calls (same app object).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"text":"yo"}}}
    ,
        \\{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"{\"echo\":\"yo\",\"calls\":2}"}],"structuredContent":{"echo":"yo","calls":2},"isError":false}}
        \\
    );
    try testing.expectEqual(@as(u32, 2), app.calls);
}

test "tools/call: handler failure -> isError:true (missing required arg)" {
    var app = TestApp{};
    var s = testServer(&app);
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":12,"result":{"content":[{"type":"text","text":"error: missing 'text'"}],"isError":true}}
        \\
    );
    try testing.expectEqual(@as(u32, 1), app.calls); // handler was reached
}

test "tools/call: NDJSON tool stays text-only (allow_structured=false)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "trace",
        .description = "NDJSON stream",
        .input_schema = "{\"type\":\"object\"}",
        .allow_structured = false,
        .handler = &ndjsonHandler,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"trace"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"line\":1}\n{\"line\":2}\n"}],"isError":false}}
        \\
    );
}

test "tools/call: non-object text output never emits structuredContent" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "plain",
        .description = "plain text",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &plainTextHandler, // allow_structured defaults true, but output is not an object
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"plain"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello, plain text"}],"isError":false}}
        \\
    );
}

test "tools/call: progress notifications interleave before the result" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "slow",
        .description = "reports progress",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &slowHandler,
    });
    // String progressToken: echoed with quotes on every notification.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow","_meta":{"progressToken":"tok-1"}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"tok-1","progress":1,"total":2,"message":"halfway"}}
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"tok-1","progress":2,"total":2,"message":"done"}}
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"done\":true}"}],"structuredContent":{"done":true},"isError":false}}
        \\
    );
    // Integer progressToken: embedded bare.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow","_meta":{"progressToken":42}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":42,"progress":1,"total":2,"message":"halfway"}}
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":42,"progress":2,"total":2,"message":"done"}}
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"done\":true}"}],"structuredContent":{"done":true},"isError":false}}
        \\
    );
    // No progressToken: reportProgress is a no-op, only the result appears.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"slow"}}
    ,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"done\":true}"}],"structuredContent":{"done":true},"isError":false}}
        \\
    );
}

test "tools/call: text with quotes/newlines is JSON-escaped in the content block" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    const H = struct {
        fn h(ctx: ?*anyopaque, call: *ToolCall) bool {
            _ = ctx;
            call.write("say \"hi\"\nline2");
            return false;
        }
    };
    try s.addTool(.{
        .name = "quirky",
        .description = "special chars",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &H.h,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quirky"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"say \"hi\"\nline2"}],"isError":false}}
        \\
    );
}

test "addTool: duplicate name rejected" {
    var s = testServer(null);
    defer s.deinit();
    try testing.expectError(error.DuplicateTool, s.addTool(echo_tool));
}

test "isSingleJsonObject unit" {
    try testing.expect(isSingleJsonObject("{}"));
    try testing.expect(isSingleJsonObject("  {\"a\":1}  \n"));
    try testing.expect(isSingleJsonObject("{\"s\":\"}{\",\"e\":\"\\\"}\"}")); // braces inside strings
    try testing.expect(!isSingleJsonObject("")); // empty
    try testing.expect(!isSingleJsonObject("[1,2]")); // array
    try testing.expect(!isSingleJsonObject("\"str\"")); // string
    try testing.expect(!isSingleJsonObject("{\"a\":1}\n{\"b\":2}")); // NDJSON
    try testing.expect(!isSingleJsonObject("{\"a\":1")); // unterminated
    try testing.expect(!isSingleJsonObject("}{")); // unbalanced
}

test "integration: full round-trip over an in-memory pipe (serve)" {
    var app = TestApp{};
    var s = testServer(&app);
    defer s.deinit();

    // The canonical MCP session: initialize -> initialized -> tools/list ->
    // tools/call, plus a malformed line mid-stream (the loop must survive it)
    // and a final line without a trailing newline.
    const input =
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cli","version":"1.0"}}}
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
        \\this is not json
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"round-trip"}}}
    ;
    var in: std.Io.Reader = .fixed(input);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try s.serve(&in, &aw.writer);

    const expected =
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"Echo the 'text' argument back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]},"outputSchema":{"type":"object","properties":{"echo":{"type":"string"},"calls":{"type":"integer"}}}}]}}
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"echo\":\"round-trip\",\"calls\":1}"}],"structuredContent":{"echo":"round-trip","calls":1},"isError":false}}
        \\
    ;
    try testing.expectEqualStrings(expected, aw.written());

    // The session reached the app: handshake flag + ctx-threaded state.
    try testing.expect(s.client_initialized);
    try testing.expectEqual(@as(u32, 1), app.calls);
    try testing.expectEqualStrings("round-trip", app.last_text[0..app.last_text_len]);
}

// ── resource + prompt test fixtures ─────────────────────────────────────────

/// App state for resource/prompt ctx-threading: the read/get handlers must
/// reach live application state, exactly like tool handlers do.
const TestLibrary = struct {
    reads: u32 = 0,
    gets: u32 = 0,
};

fn readmeReader(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    const lib: *TestLibrary = @ptrCast(@alignCast(ctx.?));
    lib.reads += 1;
    req.text(req.uri, "text/plain", "hello resource");
    return true;
}

fn logoReader(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    // First four bytes of the PNG magic — a known base64 answer: "iVBORw==".
    req.blob(req.uri, "image/png", &[_]u8{ 0x89, 'P', 'N', 'G' });
    return true;
}

fn goneReader(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    _ = req;
    return false; // registered, but the backing store is gone => -32002
}

/// Template handler: serves every `mem://file/{name}` uri. Matching is the
/// handler's job (the module does not evaluate uri templates) — decline
/// non-matching uris with `false`.
fn fileTemplateReader(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    const prefix = "mem://file/";
    if (!std.mem.startsWith(u8, req.uri, prefix)) return false;
    const name = req.uri[prefix.len..];
    if (name.len == 0) return false;
    const body = std.fmt.allocPrint(req.arena, "contents of {s}", .{name}) catch return false;
    req.text(req.uri, "text/plain", body);
    return true;
}

fn greetPromptHandler(ctx: ?*anyopaque, req: *PromptRequest) bool {
    const lib: *TestLibrary = @ptrCast(@alignCast(ctx.?));
    lib.gets += 1;
    const who = req.strArg("who") orelse return false; // server-validated: cannot happen
    const tone = req.strArg("tone") orelse "warm";
    req.printMessage(.user, "Please greet {s} in a {s} tone.", .{ who, tone });
    req.message(.assistant, "Understood.");
    return true;
}

fn failingPromptHandler(ctx: ?*anyopaque, req: *PromptRequest) bool {
    _ = ctx;
    _ = req;
    return false;
}

const greet_args = [_]PromptArgument{
    .{ .name = "who", .description = "Who to greet.", .required = true },
    .{ .name = "tone", .description = "Optional tone." },
};

/// Server with two static resources, a gone resource, a template and a
/// prompt — the fixture every resources/prompts test drives.
fn libraryServer(lib: *TestLibrary) !Server {
    var s = Server.init(testing.allocator, .{ .name = "lib-srv", .version = "0.1.0" });
    errdefer s.deinit();
    try s.addResource(.{
        .uri = "mem://readme",
        .name = "readme",
        .description = "Project readme.",
        .mime_type = "text/plain",
        .handler = &readmeReader,
        .ctx = lib,
    });
    try s.addResource(.{
        .uri = "mem://logo",
        .name = "logo",
        .handler = &logoReader,
    });
    try s.addResource(.{
        .uri = "mem://gone",
        .name = "gone",
        .handler = &goneReader,
    });
    try s.addResourceTemplate(.{
        .uri_template = "mem://file/{name}",
        .name = "file",
        .description = "Any file by name.",
        .mime_type = "text/plain",
        .handler = &fileTemplateReader,
    });
    try s.addResourceTemplate(.{
        .uri_template = "mem://opaque/{id}",
        .name = "advertise-only",
        // no handler: listed, never readable through this template
    });
    try s.addPrompt(.{
        .name = "greet",
        .description = "Render a greeting request.",
        .arguments = &greet_args,
        .handler = &greetPromptHandler,
        .ctx = lib,
    });
    try s.addPrompt(.{
        .name = "broken",
        .handler = &failingPromptHandler,
    });
    return s;
}

test "resources/list: golden JSON from the registered catalog" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}",
        \\{"jsonrpc":"2.0","id":1,"result":{"resources":[{"uri":"mem://readme","name":"readme","description":"Project readme.","mimeType":"text/plain"},{"uri":"mem://logo","name":"logo"},{"uri":"mem://gone","name":"gone"}]}}
        \\
    );
}

test "resources/templates/list: golden JSON from the registered catalog" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/templates/list\"}",
        \\{"jsonrpc":"2.0","id":2,"result":{"resourceTemplates":[{"uriTemplate":"mem://file/{name}","name":"file","description":"Any file by name.","mimeType":"text/plain"},{"uriTemplate":"mem://opaque/{id}","name":"advertise-only"}]}}
        \\
    );
}

test "resources/read: text contents + ctx threading to app state" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"mem://readme"}}
    ,
        \\{"jsonrpc":"2.0","id":3,"result":{"contents":[{"uri":"mem://readme","mimeType":"text/plain","text":"hello resource"}]}}
        \\
    );
    try testing.expectEqual(@as(u32, 1), lib.reads);
}

test "resources/read: blob contents are base64-encoded" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"mem://logo"}}
    ,
        \\{"jsonrpc":"2.0","id":4,"result":{"contents":[{"uri":"mem://logo","mimeType":"image/png","blob":"iVBORw=="}]}}
        \\
    );
}

test "resources/read: template handler resolves a parameterized uri" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"mem://file/notes.txt"}}
    ,
        \\{"jsonrpc":"2.0","id":5,"result":{"contents":[{"uri":"mem://file/notes.txt","mimeType":"text/plain","text":"contents of notes.txt"}]}}
        \\
    );
}

test "resources/read: unresolvable uri -> -32002 Resource not found" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    // No static match, every template declines.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"mem://nope"}}
    ,
        \\{"jsonrpc":"2.0","id":6,"error":{"code":-32002,"message":"Resource not found"}}
        \\
    );
    // Static match whose handler reports the backing store gone.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"mem://gone"}}
    ,
        \\{"jsonrpc":"2.0","id":7,"error":{"code":-32002,"message":"Resource not found"}}
        \\
    );
}

test "resources/read: param validation errors -> -32602" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\"}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Missing params"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":[]}",
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid params"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{}}",
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Missing uri"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/read\",\"params\":{\"uri\":7}}",
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Invalid uri"}}
        \\
    );
}

test "prompts/list: golden JSON with argument declarations" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/list\"}",
        \\{"jsonrpc":"2.0","id":1,"result":{"prompts":[{"name":"greet","description":"Render a greeting request.","arguments":[{"name":"who","description":"Who to greet.","required":true},{"name":"tone","description":"Optional tone."}]},{"name":"broken"}]}}
        \\
    );
}

test "prompts/get: renders messages with arguments substituted + ctx threading" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    // Both arguments supplied.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greet","arguments":{"who":"Ada","tone":"brisk"}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"description":"Render a greeting request.","messages":[{"role":"user","content":{"type":"text","text":"Please greet Ada in a brisk tone."}},{"role":"assistant","content":{"type":"text","text":"Understood."}}]}}
        \\
    );
    // Optional argument omitted -> handler default applies.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"greet","arguments":{"who":"Bob"}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"description":"Render a greeting request.","messages":[{"role":"user","content":{"type":"text","text":"Please greet Bob in a warm tone."}},{"role":"assistant","content":{"type":"text","text":"Understood."}}]}}
        \\
    );
    try testing.expectEqual(@as(u32, 2), lib.gets);
}

test "prompts/get: validation errors -> -32602; handler failure -> -32603" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\"}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Missing params"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"prompts/get\",\"params\":{}}",
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Missing prompt name"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"prompts/get\",\"params\":{\"name\":5}}",
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid prompt name"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"prompts/get\",\"params\":{\"name\":\"nope\"}}",
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Unknown prompt"}}
        \\
    );
    // Required argument missing entirely / arguments object absent / wrong type.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"greet","arguments":{"tone":"curt"}}}
    ,
        \\{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"Missing required argument"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":6,"method":"prompts/get","params":{"name":"greet"}}
    ,
        \\{"jsonrpc":"2.0","id":6,"error":{"code":-32602,"message":"Missing required argument"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":7,"method":"prompts/get","params":{"name":"greet","arguments":{"who":42}}}
    ,
        \\{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"Missing required argument"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":8,"method":"prompts/get","params":{"name":"greet","arguments":[1]}}
    ,
        \\{"jsonrpc":"2.0","id":8,"error":{"code":-32602,"message":"Invalid arguments"}}
        \\
    );
    // Handler-side failure (no declared-required miss involved) -> -32603.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":9,"method":"prompts/get","params":{"name":"broken"}}
    ,
        \\{"jsonrpc":"2.0","id":9,"error":{"code":-32603,"message":"Prompt failed"}}
        \\
    );
    try testing.expectEqual(@as(u32, 0), lib.gets); // greet handler never reached
}

test "resources/prompts: empty catalogs list as empty arrays" {
    var s = testServer(null); // tools-only server
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}",
        \\{"jsonrpc":"2.0","id":1,"result":{"resources":[]}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/templates/list\"}",
        \\{"jsonrpc":"2.0","id":2,"result":{"resourceTemplates":[]}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"prompts/list\"}",
        \\{"jsonrpc":"2.0","id":3,"result":{"prompts":[]}}
        \\
    );
}

test "addResource/addResourceTemplate/addPrompt: duplicates rejected" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try testing.expectError(error.DuplicateResource, s.addResource(.{
        .uri = "mem://readme",
        .name = "readme-again",
        .handler = &readmeReader,
    }));
    try testing.expectError(error.DuplicateResourceTemplate, s.addResourceTemplate(.{
        .uri_template = "mem://file/{name}",
        .name = "file-again",
    }));
    try testing.expectError(error.DuplicatePrompt, s.addPrompt(.{
        .name = "greet",
        .handler = &failingPromptHandler,
    }));
}

test "serve: blank lines and CRLF line endings are tolerated" {
    var s = testServer(null);
    defer s.deinit();
    const input = "\r\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n\n";
    var in: std.Io.Reader = .fixed(input);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.serve(&in, &aw.writer);
    try testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        aw.written(),
    );
}
