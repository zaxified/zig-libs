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
//! Server→client **requests** (the other direction) are supported as a
//! non-blocking seam: `sendSamplingRequest` (`sampling/createMessage` — ask the
//! client's LLM) and `sendElicitationRequest` (`elicitation/create` — ask the
//! client to collect user input) issue a request and register it as pending;
//! `handleMessage` correlates the client's eventual JSON-RPC response back to
//! it and invokes the registered `ResponseHandler`. Both are gated on the
//! capabilities the client declared at `initialize` (stored in
//! `client_capabilities`), elicitation schemas are validated against the spec's
//! restricted JSON-Schema subset, and form-mode elicitation **refuses**
//! credential-shaped fields. A handler does NOT block waiting for the answer —
//! see the "server→client requests" section for why that is not implementable
//! here and what to do instead.
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
    /// MCP spec (sampling): the client's user rejected the sampling request.
    /// Received, never emitted — this server is the requester there.
    pub const user_rejected: i32 = -1;
    /// MCP spec 2025-11-25 (elicitation): a server tells the client the request
    /// cannot proceed until a URL-mode elicitation completes. Emitted by the
    /// application, not by this module's dispatch.
    pub const url_elicitation_required: i32 = -32042;
};

/// Everything `handleMessage`/`serve` can fail with. Malformed *input* never
/// surfaces here (it becomes a JSON-RPC error response); only allocation
/// failure and transport write failure do.
pub const Error = error{ OutOfMemory, WriteFailed };

/// Pick the protocol version to answer with: the client's requested one if we
/// support it, else our latest. `requested` is null when the client omits it.
///
/// The returned slice is always one of our own static literals, **never the
/// caller's** — `handleMessage` parses the request onto a per-message arena
/// that is freed before the next message, so echoing the client's slice back
/// would hand out a dangling pointer to anything that stores it (as
/// `Server.negotiated_version` does).
pub fn negotiateVersion(requested: ?[]const u8) []const u8 {
    if (requested) |req| {
        for (supported_versions) |v| {
            if (std.mem.eql(u8, v, req)) return v;
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

// ── client capabilities (what the client declared at `initialize`) ──────────

/// What the **client** advertised in its `initialize` params. Captured on every
/// `initialize` (replacing any earlier value) because the two server→client
/// requests this module can issue are gated on it: the spec says a server
/// **MUST NOT** send `sampling/createMessage` to a client that did not declare
/// `sampling`, nor `elicitation/create` without `elicitation` (and MUST NOT use
/// an elicitation *mode* the client did not declare). `sendSamplingRequest` /
/// `sendElicitationRequest` enforce that here rather than trusting the caller.
///
/// Everything defaults to false, so a server that never saw an `initialize`
/// can issue nothing — fail closed.
pub const ClientCapabilities = struct {
    /// `sampling` — client will run `sampling/createMessage` against its LLM.
    sampling: bool = false,
    /// `sampling.tools` — client accepts tool-enabled sampling requests. (This
    /// module does not build tool-enabled requests; the flag is reported for
    /// completeness.)
    sampling_tools: bool = false,
    /// `sampling.context` — client honors `includeContext` (soft-deprecated).
    sampling_context: bool = false,
    /// `elicitation` — client will collect user input.
    elicitation: bool = false,
    /// `elicitation.form` — in-band structured collection. Per the spec an
    /// **empty** `elicitation:{}` object means form mode only, so this is true
    /// for a bare declaration and for a 2025-06-18 client (which has no modes).
    elicitation_form: bool = false,
    /// `elicitation.url` — out-of-band URL navigation (2025-11-25+). The only
    /// sanctioned way to collect a secret; see `ElicitationRequest`.
    elicitation_url: bool = false,
    /// `roots` — client exposes filesystem roots (not used by this module).
    roots: bool = false,
    /// `roots.listChanged`.
    roots_list_changed: bool = false,

    /// Parse the `capabilities` value from `initialize` params. Anything
    /// unparseable yields all-false (fail closed) — a malformed handshake must
    /// never *grant* a capability.
    pub fn parse(caps_opt: ?std.json.Value) ClientCapabilities {
        var c: ClientCapabilities = .{};
        const caps = present(caps_opt) orelse return c;
        if (caps != .object) return c;

        if (present(caps.object.get("sampling"))) |s| {
            c.sampling = true;
            c.sampling_tools = present(sub(s, "tools")) != null;
            c.sampling_context = present(sub(s, "context")) != null;
        }
        if (present(caps.object.get("elicitation"))) |e| {
            c.elicitation = true;
            const has_form = present(sub(e, "form")) != null;
            const has_url = present(sub(e, "url")) != null;
            // Spec backwards compatibility: `elicitation:{}` ≡ `{"form":{}}`.
            // Only an explicit url-only declaration turns form mode off.
            c.elicitation_form = has_form or !has_url;
            c.elicitation_url = has_url;
        }
        if (present(caps.object.get("roots"))) |r| {
            c.roots = true;
            c.roots_list_changed = present(sub(r, "listChanged")) != null;
        }
        return c;
    }
};

/// JSON `null` is "absent" for capability purposes — a declared-but-null
/// capability must not grant anything.
fn present(v: ?std.json.Value) ?std.json.Value {
    const x = v orelse return null;
    if (x == .null) return null;
    return x;
}

fn sub(v: std.json.Value, key: []const u8) ?std.json.Value {
    if (v != .object) return null;
    return v.object.get(key);
}

// ── server→client requests: sampling + elicitation ──────────────────────────
//
// Everything above flows client→server: a message arrives, a handler runs, one
// result goes back. `sampling/createMessage` and `elicitation/create` flow the
// other way — the *server* is the requester and the client answers later, in
// its own time, as a separate inbound JSON-RPC message.
//
// This module deliberately does NOT make a tool handler block waiting for that
// answer. It cannot: `handleMessage` is given one message and one writer, has
// no reader, and under `mcp-http` the client's answer arrives on a *different
// HTTP request* (possibly a different thread) which cannot be serviced while
// the first one is parked. Building a "handler blocks on sampling" API would
// mean shipping an async runtime inside a transport module and would deadlock
// the HTTP transport outright.
//
// What is provided instead is the seam that is actually implementable:
//
//   1. **Issue** — `Server.sendSamplingRequest` / `sendElicitationRequest`
//      allocate a server-side request id, validate the payload against the
//      spec, check the client's declared capability, write one JSON-RPC
//      request line to the transport, and record it as *pending*.
//   2. **Correlate** — `handleMessage` recognizes an inbound JSON-RPC
//      *response* (an `id` with `result`/`error` and no `method`), matches it
//      against the pending table, and invokes the `ResponseHandler` registered
//      with that request. Nothing is written back: JSON-RPC forbids responding
//      to a response.
//   3. **Resume** — the embedder decides what "resume" means. A stdio server
//      driving its own loop can set a flag and continue; a tool that needs the
//      answer *within* one call must be structured as two calls (ask, then act
//      on the next call) — which is also the only shape the HTTP transport can
//      express.
//
// Ids are allocated from a counter that is **never reused**, not even when the
// send fails: a burnt id can never collide with a live one.

/// MCP message role (`user`/`assistant`) — sampling messages and results.
pub const Role = enum { user, assistant };

/// File-scope alias so `PromptRequest.Role` can stay the name it always was.
const RoleAlias = Role;

/// One content block of a sampling message or result. Tool-use / tool-result
/// blocks (2025-11-25 sampling-with-tools) are **not** modelled: this module
/// never builds them and `SamplingResult.parse` rejects them explicitly rather
/// than silently mangling them.
pub const SamplingContent = union(enum) {
    text: []const u8,
    image: Media,
    audio: Media,

    /// Binary content: `data` is **already base64** (the wire form), `mime_type`
    /// e.g. "image/jpeg" / "audio/wav".
    pub const Media = struct {
        data: []const u8,
        mime_type: []const u8,
    };
};

/// One message in a `sampling/createMessage` conversation.
pub const SamplingMessage = struct {
    role: Role,
    content: SamplingContent,
};

/// A model-name hint. Treated by the client as a *substring* match, evaluated
/// in order, and advisory only — the client picks the model.
pub const ModelHint = struct { name: []const u8 };

/// The spec's model-preference structure: abstract priorities plus optional
/// name hints. Each priority is normalized to 0..1 and rejected outside that
/// range (`error.InvalidPriority`) — an out-of-range priority is a server bug
/// that would otherwise be silently reinterpreted by the client.
pub const ModelPreferences = struct {
    hints: []const ModelHint = &.{},
    cost_priority: ?f64 = null,
    speed_priority: ?f64 = null,
    intelligence_priority: ?f64 = null,
};

/// A `sampling/createMessage` request: the server asks the CLIENT's LLM for a
/// completion.
///
/// **Trust boundary.** The *server* (this process) chooses the prompt; the
/// *client* owns the model access, the API key, the user's money and the final
/// say. That asymmetry is the whole point of sampling — a server needs no LLM
/// credentials — and it is also its hazard: everything here is attacker-visible
/// input if any part of the prompt is built from tool arguments or fetched
/// content. The spec expects a human in the loop on the client side (the user
/// SHOULD be able to review, edit and deny the request, and review the answer),
/// but a server MUST NOT rely on that: treat the returned completion as
/// untrusted text, never as an instruction, and never smuggle data the user has
/// not seen into a prompt the user is asked to approve.
///
/// Not modelled: `tools`/`toolChoice` (sampling-with-tools), `includeContext`
/// (soft-deprecated), `metadata` (opaque provider passthrough).
pub const SamplingRequest = struct {
    /// Conversation so far. Must be non-empty (`error.NoMessages`).
    messages: []const SamplingMessage,
    /// Spec-required token ceiling. Must be non-zero (`error.InvalidMaxTokens`).
    max_tokens: u32,
    system_prompt: ?[]const u8 = null,
    model_preferences: ?ModelPreferences = null,
    temperature: ?f64 = null,
    stop_sequences: []const []const u8 = &.{},
};

/// A decoded `sampling/createMessage` result.
pub const SamplingResult = struct {
    role: Role,
    content: SamplingContent,
    /// The model the client actually used — advisory, chosen by the client.
    model: []const u8,
    /// e.g. "endTurn", "maxTokens", "stopSequence"; absent is legal.
    stop_reason: ?[]const u8 = null,

    pub const ParseError = error{ MalformedResult, UnsupportedContent };

    /// Decode the `result` value of a `sampling/createMessage` response.
    /// A content *array* (the tool-use shape) is `error.UnsupportedContent`,
    /// never a partial decode.
    pub fn parse(v: std.json.Value) ParseError!SamplingResult {
        if (v != .object) return error.MalformedResult;
        const o = v.object;

        const role_v = o.get("role") orelse return error.MalformedResult;
        if (role_v != .string) return error.MalformedResult;
        const role: Role = if (eql(role_v.string, "assistant"))
            .assistant
        else if (eql(role_v.string, "user"))
            .user
        else
            return error.MalformedResult;

        const model_v = o.get("model") orelse return error.MalformedResult;
        if (model_v != .string) return error.MalformedResult;

        const content_v = o.get("content") orelse return error.MalformedResult;
        if (content_v == .array) return error.UnsupportedContent; // tool_use blocks
        if (content_v != .object) return error.MalformedResult;
        const content = try parseContentBlock(content_v.object);

        var stop: ?[]const u8 = null;
        if (present(o.get("stopReason"))) |s| {
            if (s != .string) return error.MalformedResult;
            stop = s.string;
        }
        return .{ .role = role, .content = content, .model = model_v.string, .stop_reason = stop };
    }
};

fn parseContentBlock(o: std.json.ObjectMap) SamplingResult.ParseError!SamplingContent {
    const type_v = o.get("type") orelse return error.MalformedResult;
    if (type_v != .string) return error.MalformedResult;
    if (eql(type_v.string, "text")) {
        const t = o.get("text") orelse return error.MalformedResult;
        if (t != .string) return error.MalformedResult;
        return .{ .text = t.string };
    }
    const is_image = eql(type_v.string, "image");
    if (!is_image and !eql(type_v.string, "audio")) return error.UnsupportedContent;
    const data = o.get("data") orelse return error.MalformedResult;
    const mime = o.get("mimeType") orelse return error.MalformedResult;
    if (data != .string or mime != .string) return error.MalformedResult;
    const media: SamplingContent.Media = .{ .data = data.string, .mime_type = mime.string };
    return if (is_image) .{ .image = media } else .{ .audio = media };
}

/// Elicitation mode. `form` collects structured data **through** the client;
/// `url` (2025-11-25+) sends the user out of band to a page the client never
/// sees the contents of.
pub const ElicitationMode = enum { form, url };

/// An `elicitation/create` request: the server asks the client to collect input
/// from the user.
///
/// ## Security: form mode is not for secrets — this is enforced, not advised
///
/// The spec is unambiguous: a server **MUST NOT** use form mode to request
/// sensitive information (passwords, API keys, access tokens, payment
/// credentials) and **MUST** use URL mode for those. The reason is that form
/// mode is a *phishing primitive*: the prompt text is chosen by the server but
/// rendered by a client the user already trusts, so "MyCorp needs your password
/// to continue" arrives wearing the client's UI. The secret would then pass
/// through the client, its logs, and potentially an LLM context.
///
/// So this module does more than document it: `sendElicitationRequest`
/// **rejects** a form-mode schema whose property names or titles look like
/// credentials (`error.SchemaSensitiveField`, see `looksLikeSecretField`).
/// That check is a name heuristic, not a proof — it cannot see intent hidden in
/// a `message` string, and it has no view of what the collected value is later
/// used for. It exists to make the wrong thing *fail loudly at the seam* rather
/// than ship. If you are collecting a credential, use `url` mode: the value
/// then never transits the client at all.
///
/// The counterpart honesty: a *client* cannot verify any of this. It sees only
/// the message and the schema the server sent. The trust the user places in the
/// dialog belongs to the client; a server borrowing it is borrowing something
/// it did not earn.
pub const ElicitationRequest = union(ElicitationMode) {
    form: Form,
    url: Url,

    /// In-band structured collection. `requested_schema` is JSON-Schema **text**
    /// (same idiom as `Tool.input_schema`), validated against the spec's
    /// restricted subset before it is sent — see `validateElicitationSchema`.
    pub const Form = struct {
        message: []const u8,
        requested_schema: []const u8,
    };

    /// Out-of-band navigation. Requires the client's `elicitation.url`
    /// capability. `elicitation_id` correlates the later
    /// `notifications/elicitation/complete`; the URL must not carry credentials
    /// or be pre-authenticated (spec: safe URL handling) — this module can only
    /// check the scheme, the rest is on you.
    pub const Url = struct {
        message: []const u8,
        url: []const u8,
        elicitation_id: []const u8,
    };
};

/// The user's answer to an elicitation. **Declining is not an error** — it is a
/// normal, expected outcome that a server must handle (offer an alternative,
/// proceed without the data). Neither is cancelling. Only a JSON-RPC `error`
/// object is an error, and it arrives as `ClientResponse.payload.err`.
pub const ElicitationAction = enum { accept, decline, cancel };

/// A decoded `elicitation/create` result.
pub const ElicitationResult = struct {
    action: ElicitationAction,
    /// The submitted object — **only ever non-null for `.accept`**. On
    /// `decline`/`cancel` this is forced to null even if the client sent a
    /// `content` field, so a server cannot accidentally consume "data" from an
    /// answer the user refused to give.
    content: ?std.json.Value = null,

    pub const ParseError = error{MalformedResult};

    pub fn parse(v: std.json.Value) ParseError!ElicitationResult {
        if (v != .object) return error.MalformedResult;
        const a = v.object.get("action") orelse return error.MalformedResult;
        if (a != .string) return error.MalformedResult;
        const action: ElicitationAction = if (eql(a.string, "accept"))
            .accept
        else if (eql(a.string, "decline"))
            .decline
        else if (eql(a.string, "cancel"))
            .cancel
        else
            return error.MalformedResult;

        if (action != .accept) return .{ .action = action, .content = null };
        const c = present(v.object.get("content")) orelse return .{ .action = .accept };
        if (c != .object) return error.MalformedResult;
        return .{ .action = .accept, .content = c };
    }
};

// ── elicitation schema validation (the spec's restricted JSON-Schema subset) ─

/// Every way a `requestedSchema` can fail the spec's restricted subset.
/// `SchemaSensitiveField` is the security refusal, not a shape problem.
pub const SchemaError = error{
    OutOfMemory,
    SchemaNotJson,
    SchemaNotObject,
    SchemaTypeNotObject,
    SchemaMissingProperties,
    SchemaPropertyNotObject,
    SchemaNestedObject,
    SchemaUnsupportedType,
    SchemaUnsupportedKeyword,
    SchemaBadFormat,
    SchemaBadEnum,
    SchemaBadItems,
    SchemaBadDefault,
    SchemaBadBound,
    SchemaBadRequired,
    SchemaSensitiveField,
};

/// Validate a form-mode `requestedSchema` against the spec's restricted subset:
/// a **flat** object of primitive properties — string / number / integer /
/// boolean, single-select enums, and (2025-11-25) multi-select enum arrays.
/// Nesting, arrays of objects and general JSON Schema are intentionally out.
///
/// The validator is *strict*: an unrecognized keyword is rejected rather than
/// passed through, because a client that does not understand it renders a form
/// that does not match what the server thinks it asked for. It also refuses a
/// schema whose property names or titles look like credentials (see
/// `ElicitationRequest`).
///
/// Both enum spellings are accepted: `enum` + `enumNames` (2025-06-18) and
/// `oneOf: [{const,title}]` (2025-11-25). Multi-select arrays only exist in
/// 2025-11-25; this function is version-agnostic and accepts the union, so a
/// server targeting an older client should not build one.
pub fn validateElicitationSchema(arena: std.mem.Allocator, schema_text: []const u8) SchemaError!void {
    const root_v = std.json.parseFromSliceLeaky(std.json.Value, arena, schema_text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.SchemaNotJson,
    };
    if (root_v != .object) return error.SchemaNotObject;
    const root = root_v.object;
    if (!keysAllowed(root, &.{ "type", "properties", "required", "title", "description" }))
        return error.SchemaUnsupportedKeyword;

    const t = root.get("type") orelse return error.SchemaTypeNotObject;
    if (t != .string or !eql(t.string, "object")) return error.SchemaTypeNotObject;

    const props_v = root.get("properties") orelse return error.SchemaMissingProperties;
    if (props_v != .object) return error.SchemaMissingProperties;

    var it = props_v.object.iterator();
    while (it.next()) |e| {
        if (looksLikeSecretField(e.key_ptr.*)) return error.SchemaSensitiveField;
        try validateProperty(e.value_ptr.*);
    }

    if (present(root.get("required"))) |req| {
        if (req != .array) return error.SchemaBadRequired;
        for (req.array.items) |r| {
            if (r != .string) return error.SchemaBadRequired;
            // A required name with no declared property is a schema the client
            // cannot satisfy.
            if (props_v.object.get(r.string) == null) return error.SchemaBadRequired;
        }
    }
}

fn keysAllowed(obj: std.json.ObjectMap, allowed: []const []const u8) bool {
    var it = obj.iterator();
    outer: while (it.next()) |e| {
        for (allowed) |a| {
            if (eql(a, e.key_ptr.*)) continue :outer;
        }
        return false;
    }
    return true;
}

fn optString(o: std.json.ObjectMap, key: []const u8) SchemaError!?[]const u8 {
    const v = present(o.get(key)) orelse return null;
    if (v != .string) return error.SchemaUnsupportedKeyword;
    return v.string;
}

/// A non-negative integer bound (minLength/maxLength/minItems/maxItems).
fn checkCountBound(o: std.json.ObjectMap, key: []const u8) SchemaError!void {
    const v = present(o.get(key)) orelse return;
    if (v != .integer or v.integer < 0) return error.SchemaBadBound;
}

fn isNumber(v: std.json.Value) bool {
    return v == .integer or v == .float;
}

fn validateProperty(v: std.json.Value) SchemaError!void {
    if (v != .object) return error.SchemaPropertyNotObject;
    const o = v.object;
    if (try optString(o, "title")) |title| {
        if (looksLikeSecretField(title)) return error.SchemaSensitiveField;
    }
    _ = try optString(o, "description");

    const t = present(o.get("type")) orelse return error.SchemaUnsupportedType;
    if (t != .string) return error.SchemaUnsupportedType;
    const kind = t.string;
    if (eql(kind, "object")) return error.SchemaNestedObject;
    if (eql(kind, "string")) return validateStringProperty(o);
    if (eql(kind, "number") or eql(kind, "integer")) return validateNumberProperty(o, eql(kind, "integer"));
    if (eql(kind, "boolean")) return validateBooleanProperty(o);
    if (eql(kind, "array")) return validateArrayProperty(o);
    return error.SchemaUnsupportedType;
}

fn validateStringProperty(o: std.json.ObjectMap) SchemaError!void {
    if (!keysAllowed(o, &.{ "type", "title", "description", "minLength", "maxLength", "pattern", "format", "default", "enum", "enumNames", "oneOf" }))
        return error.SchemaUnsupportedKeyword;
    try checkCountBound(o, "minLength");
    try checkCountBound(o, "maxLength");
    _ = try optString(o, "pattern");

    if (try optString(o, "format")) |f| {
        const ok = eql(f, "email") or eql(f, "uri") or eql(f, "date") or eql(f, "date-time");
        if (!ok) return error.SchemaBadFormat;
    }

    const enum_v = present(o.get("enum"));
    const one_of_v = present(o.get("oneOf"));
    if (enum_v != null and one_of_v != null) return error.SchemaBadEnum; // pick one spelling

    if (enum_v) |ev| {
        if (ev != .array or ev.array.items.len == 0) return error.SchemaBadEnum;
        for (ev.array.items) |item| {
            if (item != .string) return error.SchemaBadEnum;
        }
        if (present(o.get("enumNames"))) |names| {
            if (names != .array or names.array.items.len != ev.array.items.len) return error.SchemaBadEnum;
            for (names.array.items) |n| {
                if (n != .string) return error.SchemaBadEnum;
            }
        }
    } else if (present(o.get("enumNames")) != null) {
        return error.SchemaBadEnum; // names without values
    }

    if (one_of_v) |ov| try validateConstChoices(ov);

    if (present(o.get("default"))) |d| {
        if (d != .string) return error.SchemaBadDefault;
    }
}

/// `[{ "const": <string>, "title": <string>? }, …]` — the 2025-11-25 titled-enum
/// spelling, used both for single-select `oneOf` and multi-select `items.anyOf`.
fn validateConstChoices(v: std.json.Value) SchemaError!void {
    if (v != .array or v.array.items.len == 0) return error.SchemaBadEnum;
    for (v.array.items) |choice| {
        if (choice != .object) return error.SchemaBadEnum;
        if (!keysAllowed(choice.object, &.{ "const", "title" })) return error.SchemaBadEnum;
        const c = choice.object.get("const") orelse return error.SchemaBadEnum;
        if (c != .string) return error.SchemaBadEnum;
        if (present(choice.object.get("title"))) |ti| {
            if (ti != .string) return error.SchemaBadEnum;
        }
    }
}

fn validateNumberProperty(o: std.json.ObjectMap, integral: bool) SchemaError!void {
    if (!keysAllowed(o, &.{ "type", "title", "description", "minimum", "maximum", "default" }))
        return error.SchemaUnsupportedKeyword;
    inline for (.{ "minimum", "maximum" }) |key| {
        if (present(o.get(key))) |b| {
            if (!isNumber(b)) return error.SchemaBadBound;
        }
    }
    if (present(o.get("default"))) |d| {
        if (!isNumber(d)) return error.SchemaBadDefault;
        if (integral and d != .integer) return error.SchemaBadDefault;
    }
}

fn validateBooleanProperty(o: std.json.ObjectMap) SchemaError!void {
    if (!keysAllowed(o, &.{ "type", "title", "description", "default" }))
        return error.SchemaUnsupportedKeyword;
    if (present(o.get("default"))) |d| {
        if (d != .bool) return error.SchemaBadDefault;
    }
}

/// The only permitted array: a multi-select **enum**. `items` is either
/// `{type:"string", enum:[…]}` or `{anyOf:[{const,title}…]}` — anything else
/// (notably `items:{type:"object"}`) is an array of objects and is rejected.
fn validateArrayProperty(o: std.json.ObjectMap) SchemaError!void {
    if (!keysAllowed(o, &.{ "type", "title", "description", "minItems", "maxItems", "default", "items" }))
        return error.SchemaUnsupportedKeyword;
    try checkCountBound(o, "minItems");
    try checkCountBound(o, "maxItems");

    const items = present(o.get("items")) orelse return error.SchemaBadItems;
    if (items != .object) return error.SchemaBadItems;
    if (present(items.object.get("anyOf"))) |any_of| {
        if (!keysAllowed(items.object, &.{"anyOf"})) return error.SchemaBadItems;
        validateConstChoices(any_of) catch return error.SchemaBadItems;
    } else {
        if (!keysAllowed(items.object, &.{ "type", "enum" })) return error.SchemaBadItems;
        const it = items.object.get("type") orelse return error.SchemaBadItems;
        if (it != .string or !eql(it.string, "string")) return error.SchemaBadItems;
        const ev = present(items.object.get("enum")) orelse return error.SchemaBadItems;
        if (ev != .array or ev.array.items.len == 0) return error.SchemaBadItems;
        for (ev.array.items) |item| {
            if (item != .string) return error.SchemaBadItems;
        }
    }

    if (present(o.get("default"))) |d| {
        if (d != .array) return error.SchemaBadDefault;
        for (d.array.items) |item| {
            if (item != .string) return error.SchemaBadDefault;
        }
    }
}

/// Names that read as a credential. Compared against the field name with
/// separators and case removed, so `api_key`, `API-Key` and `apiKey` all match
/// `apikey`.
const secret_needles = [_][]const u8{
    "password",     "passwd",      "passphrase", "secret",       "credential",
    "apikey",       "accesskey",   "secretkey",  "privatekey",   "accesstoken",
    "refreshtoken", "bearertoken", "authtoken",  "sessiontoken", "idtoken",
    "securitycode", "pincode",     "seedphrase", "mnemonic",     "cardnumber",
    "creditcard",   "cvv",         "cvc",
};

/// Heuristic: does this elicitation field name/title ask for a secret? Used to
/// refuse form-mode schemas (see `ElicitationRequest`). Public so a consumer
/// can apply the same test to its own inputs — and so its limits are testable:
/// it matches **names**, and a determined phisher can name a field `favourite
/// phrase`. It is a guardrail against the accident, not a defense against the
/// adversary; the structural answer is URL mode.
pub fn looksLikeSecretField(name: []const u8) bool {
    var buf: [128]u8 = undefined;
    var n: usize = 0;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c)) continue;
        if (n == buf.len) break;
        buf[n] = std.ascii.toLower(c);
        n += 1;
    }
    const norm = buf[0..n];
    for (secret_needles) |needle| {
        if (std.mem.indexOf(u8, norm, needle) != null) return true;
    }
    return false;
}

// ── outbound request bookkeeping ────────────────────────────────────────────

/// Which server→client request a pending entry / response belongs to.
pub const RequestKind = enum { sampling, elicitation };

/// The client's answer to one server→client request, handed to the
/// `ResponseHandler` registered when the request was issued.
///
/// **Lifetime:** `arena` and every slice/Value reachable from `payload` live on
/// the per-message arena and are freed as soon as the handler returns. Copy
/// anything you keep.
pub const ClientResponse = struct {
    /// The server-side request id this answers.
    id: u64,
    /// What was asked, so one handler can serve both kinds.
    kind: RequestKind,
    /// Per-message arena — valid only for the duration of the callback.
    arena: std.mem.Allocator,
    payload: union(enum) {
        result: std.json.Value,
        err: RpcError,
    },

    pub const RpcError = struct {
        code: i32,
        message: []const u8,
        data: ?std.json.Value = null,
    };

    /// Decode a `sampling/createMessage` result. `error.MalformedResult` when
    /// the response carried a JSON-RPC error instead (check `payload` first).
    pub fn samplingResult(self: *const ClientResponse) SamplingResult.ParseError!SamplingResult {
        return switch (self.payload) {
            .result => |v| SamplingResult.parse(v),
            .err => error.MalformedResult,
        };
    }

    /// Decode an `elicitation/create` result. A `decline`/`cancel` answer
    /// decodes successfully — it is a user decision, not a failure.
    pub fn elicitationResult(self: *const ClientResponse) ElicitationResult.ParseError!ElicitationResult {
        return switch (self.payload) {
            .result => |v| ElicitationResult.parse(v),
            .err => error.MalformedResult,
        };
    }

    /// The spec's "user rejected sampling request" code (-1).
    pub fn userRejected(self: *const ClientResponse) bool {
        return switch (self.payload) {
            .err => |e| e.code == error_code.user_rejected,
            .result => false,
        };
    }
};

/// Called when the client answers a server→client request. Infallible by
/// design: there is nobody to report a failure to (JSON-RPC forbids responding
/// to a response), so the embedder must absorb its own errors.
pub const ResponseHandler = *const fn (ctx: ?*anyopaque, resp: *const ClientResponse) void;

/// Per-request wiring for `sendSamplingRequest`/`sendElicitationRequest`.
pub const RequestOptions = struct {
    /// Which connected client this request goes to, for transports that
    /// multiplex several (`mcp-http` sessions). A response is only correlated
    /// when it arrives from the **same** peer — otherwise session A's tool could
    /// consume session B's user's answer. 0 = the single-peer default (stdio).
    peer: u64 = 0,
    /// Invoked when the answer arrives. Null = fire-and-forget (the entry is
    /// still tracked, so the response is still consumed rather than answered).
    on_response: ?ResponseHandler = null,
    /// Opaque state threaded to `on_response`.
    ctx: ?*anyopaque = null,
};

/// Everything `sendSamplingRequest`/`sendElicitationRequest` can refuse.
/// The `*NotSupported` set is the spec's capability gate; the `Schema*` set is
/// the elicitation subset check.
pub const SendError = error{
    OutOfMemory,
    WriteFailed,
    /// The pending table is full — a client that never answers must not be able
    /// to grow it without bound.
    TooManyPending,
    SamplingNotSupported,
    ElicitationNotSupported,
    ElicitationFormNotSupported,
    ElicitationUrlNotSupported,
    NoMessages,
    InvalidMaxTokens,
    InvalidPriority,
    InvalidUrl,
    EmptyMessage,
    MissingElicitationId,
} || SchemaError;

const Pending = struct {
    id: u64,
    kind: RequestKind,
    peer: u64,
    on_response: ?ResponseHandler,
    ctx: ?*anyopaque,
};

/// Whether a negotiated protocol revision knows elicitation *modes*. The
/// 2025-06-18 revision has no `mode` field at all (and no URL mode), so a
/// form-mode request to such a client omits it — which 2025-11-25 explicitly
/// blesses ("clients MUST treat requests without a `mode` field as form mode").
fn versionHasElicitationModes(version: []const u8) bool {
    return !eql(version, "2025-06-18");
}

/// Scheme check for a URL-mode elicitation: `https://` anywhere, or `http://`
/// only for loopback (the development case). This blocks `javascript:`,
/// `data:` and `file:` payloads reaching a client that is about to open them;
/// it says nothing about where an https URL points.
fn isSafeElicitationUrl(url: []const u8) bool {
    if (std.ascii.startsWithIgnoreCase(url, "https://")) return url.len > "https://".len;
    if (std.ascii.startsWithIgnoreCase(url, "http://")) {
        const rest = url["http://".len..];
        for ([_][]const u8{ "localhost", "127.0.0.1", "[::1]" }) |host| {
            if (!std.ascii.startsWithIgnoreCase(rest, host)) continue;
            const tail = rest[host.len..];
            if (tail.len == 0 or tail[0] == '/' or tail[0] == ':' or tail[0] == '?') return true;
        }
    }
    return false;
}

// ── server→client request encoding ──────────────────────────────────────────
//
// Field order follows the spec's own `sampling/createMessage` and
// `elicitation/create` examples so the emitted line is byte-identical to them
// (JSON key order is not semantic — this is an anchoring choice, so that the
// golden tests compare against the specification text rather than against
// ourselves).

fn writeContentBlock(jw: *std.json.Stringify, c: SamplingContent) std.Io.Writer.Error!void {
    try jw.beginObject();
    switch (c) {
        .text => |t| {
            try jw.objectField("type");
            try jw.write("text");
            try jw.objectField("text");
            try jw.write(t);
        },
        .image, .audio => |m| {
            try jw.objectField("type");
            try jw.write(if (c == .image) "image" else "audio");
            try jw.objectField("data");
            try jw.write(m.data);
            try jw.objectField("mimeType");
            try jw.write(m.mime_type);
        },
    }
    try jw.endObject();
}

fn writeSamplingParams(jw: *std.json.Stringify, req: SamplingRequest) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("messages");
    try jw.beginArray();
    for (req.messages) |m| {
        try jw.beginObject();
        try jw.objectField("role");
        try jw.write(@tagName(m.role));
        try jw.objectField("content");
        try writeContentBlock(jw, m.content);
        try jw.endObject();
    }
    try jw.endArray();

    if (req.model_preferences) |mp| {
        try jw.objectField("modelPreferences");
        try jw.beginObject();
        if (mp.hints.len != 0) {
            try jw.objectField("hints");
            try jw.beginArray();
            for (mp.hints) |h| {
                try jw.beginObject();
                try jw.objectField("name");
                try jw.write(h.name);
                try jw.endObject();
            }
            try jw.endArray();
        }
        if (mp.cost_priority) |p| {
            try jw.objectField("costPriority");
            try jw.write(p);
        }
        if (mp.intelligence_priority) |p| {
            try jw.objectField("intelligencePriority");
            try jw.write(p);
        }
        if (mp.speed_priority) |p| {
            try jw.objectField("speedPriority");
            try jw.write(p);
        }
        try jw.endObject();
    }
    if (req.system_prompt) |sp| {
        try jw.objectField("systemPrompt");
        try jw.write(sp);
    }
    try jw.objectField("maxTokens");
    try jw.write(req.max_tokens);
    if (req.temperature) |t| {
        try jw.objectField("temperature");
        try jw.write(t);
    }
    if (req.stop_sequences.len != 0) {
        try jw.objectField("stopSequences");
        try jw.beginArray();
        for (req.stop_sequences) |s| try jw.write(s);
        try jw.endArray();
    }
    try jw.endObject();
}

/// One `sampling/createMessage` request line (public: reusable when wiring a
/// custom transport that needs the bytes rather than a writer).
pub fn writeSamplingRequestLine(w: *std.Io.Writer, id: u64, req: SamplingRequest) std.Io.Writer.Error!void {
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"sampling/createMessage\",\"params\":", .{id});
    var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
    try writeSamplingParams(&jw, req);
    try w.writeAll("}\n");
}

/// One `elicitation/create` request line. `emit_mode` is false only for a
/// 2025-06-18 peer (see `versionHasElicitationModes`). `arena` is used to
/// re-serialize the schema literal through the JSON writer.
pub fn writeElicitationRequestLine(
    arena: std.mem.Allocator,
    w: *std.Io.Writer,
    id: u64,
    req: ElicitationRequest,
    emit_mode: bool,
) (std.Io.Writer.Error || error{SchemaNotJson})!void {
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"elicitation/create\",\"params\":", .{id});
    var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
    try jw.beginObject();
    switch (req) {
        // Spec example order: mode, message, requestedSchema.
        .form => |f| {
            if (emit_mode) {
                try jw.objectField("mode");
                try jw.write("form");
            }
            try jw.objectField("message");
            try jw.write(f.message);
            try jw.objectField("requestedSchema");
            writeRawJson(arena, &jw, f.requested_schema) catch |err| switch (err) {
                error.WriteFailed => return error.WriteFailed,
                else => return error.SchemaNotJson,
            };
        },
        // Spec example order: mode, elicitationId, url, message.
        .url => |u| {
            try jw.objectField("mode");
            try jw.write("url");
            try jw.objectField("elicitationId");
            try jw.write(u.elicitation_id);
            try jw.objectField("url");
            try jw.write(u.url);
            try jw.objectField("message");
            try jw.write(u.message);
        },
    }
    try jw.endObject();
    try w.writeAll("}\n");
}

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
    /// The server handling this call — so a tool can issue a server→client
    /// request (`requestSampling`/`requestElicitation`) and read what the
    /// client declared it supports.
    server: *Server,
    /// The transport writer this call's response goes to. A server→client
    /// request written here lands on the wire *before* the tool result, each
    /// its own complete line (same interleaving rule as progress).
    transport: *std.Io.Writer,
    /// Which peer this call came from (see `Server.handleMessageFrom`);
    /// requests issued from this call inherit it, so the answer can only be
    /// correlated back from the same client.
    peer: u64 = 0,

    /// Ask the client's LLM for a completion, from inside a tool call.
    ///
    /// **This does not wait.** The request goes out now; the client's answer
    /// arrives later, as a separate message, and lands in
    /// `opts.on_response` — long after this tool call has returned its result.
    /// A tool that needs the completion to produce its answer must be modelled
    /// as two calls (ask now, act on the next call). There is no way around
    /// that: the answer cannot arrive while this handler owns the loop.
    pub fn requestSampling(self: *ToolCall, req: SamplingRequest, opts: RequestOptions) SendError!u64 {
        var o = opts;
        o.peer = self.peer; // the answer can only come from the caller
        return self.server.sendSamplingRequest(self.transport, req, o);
    }

    /// Ask the client to collect user input, from inside a tool call. Same
    /// non-waiting contract as `requestSampling`.
    pub fn requestElicitation(self: *ToolCall, req: ElicitationRequest, opts: RequestOptions) SendError!u64 {
        var o = opts;
        o.peer = self.peer;
        return self.server.sendElicitationRequest(self.transport, req, o);
    }

    /// What the client declared at `initialize` — check this before offering a
    /// feature that depends on sampling or elicitation, rather than issuing a
    /// request and handling the refusal.
    pub fn clientCapabilities(self: *const ToolCall) ClientCapabilities {
        return self.server.client_capabilities;
    }

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

    /// MCP prompt message roles — the same `Role` the sampling surface uses
    /// (aliased so both spell it the way the spec does).
    pub const Role = RoleAlias;

    const Message = struct {
        role: RoleAlias,
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
    pub fn message(self: *PromptRequest, role: RoleAlias, msg_text: []const u8) void {
        self.messages.append(self.arena, .{ .role = role, .text = msg_text }) catch {};
    }

    /// Append one formatted text message (same OOM policy as `message`).
    pub fn printMessage(self: *PromptRequest, role: RoleAlias, comptime fmt: []const u8, fmt_args: anytype) void {
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
    /// What the client advertised on the last `initialize` — the gate on every
    /// server→client request. All-false until an `initialize` arrives.
    client_capabilities: ClientCapabilities = .{},
    /// The revision `initialize` settled on (see `negotiateVersion`). Defaults
    /// to our latest so a pre-handshake encoder picks the newest shape.
    negotiated_version: []const u8 = protocol_version,
    /// Outbound (server→client) requests awaiting the client's response.
    pending: std.ArrayList(Pending) = .empty,
    /// Next server→client request id. Monotonic and **never reused**: an id is
    /// burnt when it is allocated, even if the send then fails, so a late
    /// answer can never be matched to a different request.
    next_request_id: u64 = 1,
    /// Cap on unanswered server→client requests. A client that simply never
    /// answers must not grow this without bound; past the cap `send*` returns
    /// `error.TooManyPending`.
    max_pending: usize = 256,

    pub fn init(gpa: std.mem.Allocator, info: Info) Server {
        return .{ .gpa = gpa, .info = info };
    }

    pub fn deinit(self: *Server) void {
        self.tools.deinit(self.gpa);
        self.resources.deinit(self.gpa);
        self.resource_templates.deinit(self.gpa);
        self.prompts.deinit(self.gpa);
        self.pending.deinit(self.gpa);
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

    // ── server→client requests ──────────────────────────────────────────────

    /// Issue one `sampling/createMessage`: ask the CLIENT's LLM for a
    /// completion. Returns the server-side request id.
    ///
    /// Refuses with `error.SamplingNotSupported` unless the client declared the
    /// `sampling` capability at `initialize` — the spec's MUST NOT, enforced
    /// here so a server cannot violate it by accident.
    ///
    /// `out` is any writer; for stdio/SSE it is the live transport (the request
    /// line interleaves with progress notifications and the eventual tool
    /// result, each a complete line). For a transport that must *queue* the
    /// request instead (e.g. `mcp-http` sessions), pass a
    /// `std.Io.Writer.Allocating` and push the produced bytes yourself — the
    /// pending entry is registered either way.
    ///
    /// The answer arrives **later**, as its own inbound message, and is
    /// delivered to `opts.on_response` from inside `handleMessage`. This call
    /// never blocks and never waits.
    pub fn sendSamplingRequest(
        self: *Server,
        out: *std.Io.Writer,
        req: SamplingRequest,
        opts: RequestOptions,
    ) SendError!u64 {
        if (!self.client_capabilities.sampling) return error.SamplingNotSupported;
        if (req.messages.len == 0) return error.NoMessages;
        if (req.max_tokens == 0) return error.InvalidMaxTokens;
        if (req.model_preferences) |mp| {
            for ([_]?f64{ mp.cost_priority, mp.speed_priority, mp.intelligence_priority }) |p_opt| {
                const p = p_opt orelse continue;
                if (!(p >= 0.0) or !(p <= 1.0)) return error.InvalidPriority; // NaN too
            }
        }
        if (self.pending.items.len >= self.max_pending) return error.TooManyPending;

        const id = self.allocRequestId();
        try self.pending.append(self.gpa, .{
            .id = id,
            .kind = .sampling,
            .peer = opts.peer,
            .on_response = opts.on_response,
            .ctx = opts.ctx,
        });
        errdefer _ = self.dropPending(id);

        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        writeSamplingRequestLine(&aw.writer, id, req) catch return error.OutOfMemory;
        try flushLine(out, aw.written());
        return id;
    }

    /// Issue one `elicitation/create`: ask the client to collect input from the
    /// user. Returns the server-side request id.
    ///
    /// Gated on the client's `elicitation` capability **and** on the specific
    /// mode (`elicitation.form` / `elicitation.url`). A form-mode schema is
    /// validated against the spec's restricted subset first, which includes
    /// refusing credential-shaped fields — see `ElicitationRequest` for why
    /// that refusal is not merely advisory.
    ///
    /// Same non-blocking contract as `sendSamplingRequest`: the user's answer
    /// (accept / **decline** / cancel — none of which is an error) arrives
    /// later through `opts.on_response`.
    pub fn sendElicitationRequest(
        self: *Server,
        out: *std.Io.Writer,
        req: ElicitationRequest,
        opts: RequestOptions,
    ) SendError!u64 {
        if (!self.client_capabilities.elicitation) return error.ElicitationNotSupported;

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        switch (req) {
            .form => |f| {
                if (!self.client_capabilities.elicitation_form) return error.ElicitationFormNotSupported;
                if (f.message.len == 0) return error.EmptyMessage;
                try validateElicitationSchema(arena, f.requested_schema);
            },
            .url => |u| {
                if (!self.client_capabilities.elicitation_url) return error.ElicitationUrlNotSupported;
                if (u.message.len == 0) return error.EmptyMessage;
                if (u.elicitation_id.len == 0) return error.MissingElicitationId;
                if (!isSafeElicitationUrl(u.url)) return error.InvalidUrl;
            },
        }
        if (self.pending.items.len >= self.max_pending) return error.TooManyPending;

        const id = self.allocRequestId();
        try self.pending.append(self.gpa, .{
            .id = id,
            .kind = .elicitation,
            .peer = opts.peer,
            .on_response = opts.on_response,
            .ctx = opts.ctx,
        });
        errdefer _ = self.dropPending(id);

        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        writeElicitationRequestLine(
            arena,
            &aw.writer,
            id,
            req,
            versionHasElicitationModes(self.negotiated_version),
        ) catch |err| switch (err) {
            error.SchemaNotJson => return error.SchemaNotJson, // unreachable: validated above
            else => return error.OutOfMemory,
        };
        try flushLine(out, aw.written());
        return id;
    }

    /// Give up on an outstanding server→client request: drop the pending entry
    /// (so a late answer is ignored) and tell the client with the MCP-defined
    /// `notifications/cancelled`. A no-op for an id that is not pending —
    /// including one already answered, so cancel-after-answer is safe.
    /// `reason` = "" omits the field.
    pub fn cancelRequest(self: *Server, out: *std.Io.Writer, id: u64, reason: []const u8) Error!void {
        if (!self.dropPending(id)) return;
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        const w = &aw.writer;
        w.print(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{d}",
            .{id},
        ) catch return error.OutOfMemory;
        if (reason.len != 0) {
            w.writeAll(",\"reason\":") catch return error.OutOfMemory;
            std.json.Stringify.encodeJsonString(reason, .{}, w) catch return error.OutOfMemory;
        }
        w.writeAll("}}\n") catch return error.OutOfMemory;
        try flushLine(out, aw.written());
    }

    /// How many server→client requests are still awaiting an answer.
    pub fn pendingCount(self: *const Server) usize {
        return self.pending.items.len;
    }

    /// Burn the next id. Separated so every send path shares the "allocated ⇒
    /// consumed, even on failure" rule.
    fn allocRequestId(self: *Server) u64 {
        const id = self.next_request_id;
        self.next_request_id += 1;
        return id;
    }

    fn dropPending(self: *Server, id: u64) bool {
        for (self.pending.items, 0..) |p, i| {
            if (p.id == id) {
                _ = self.pending.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Correlate an inbound JSON-RPC response with a pending server→client
    /// request and hand it to that request's handler. Silent by contract:
    /// JSON-RPC forbids responding to a response, so every failure mode here
    /// (unknown id, non-integer id, wrong peer) is a drop, never a reply.
    fn deliverResponse(
        self: *Server,
        arena: std.mem.Allocator,
        id_v: std.json.Value,
        obj: std.json.ObjectMap,
        peer: u64,
    ) void {
        // Our outbound ids are always non-negative integers; anything else
        // cannot be an answer to one of ours.
        if (id_v != .integer or id_v.integer < 0) return;
        const id: u64 = @intCast(id_v.integer);

        var found: ?usize = null;
        for (self.pending.items, 0..) |p, i| {
            if (p.id == id) {
                found = i;
                break;
            }
        }
        const idx = found orelse return;
        const p = self.pending.items[idx];
        // A response from a different peer is not an answer to this request —
        // and consuming it would hand one session's user input to another's.
        // Leave the entry pending; the real peer may still answer.
        if (p.peer != peer) return;
        _ = self.pending.orderedRemove(idx);

        const handler = p.on_response orelse return; // fire-and-forget: consumed, ignored
        var resp = ClientResponse{
            .id = id,
            .kind = p.kind,
            .arena = arena,
            .payload = undefined,
        };
        // JSON-RPC forbids both members; prefer `error` when a peer sends both.
        if (present(obj.get("error"))) |e| {
            var rpc: ClientResponse.RpcError = .{ .code = error_code.internal_error, .message = "" };
            if (e == .object) {
                if (e.object.get("code")) |c| {
                    if (c == .integer and c.integer >= std.math.minInt(i32) and c.integer <= std.math.maxInt(i32))
                        rpc.code = @intCast(c.integer);
                }
                if (e.object.get("message")) |m| {
                    if (m == .string) rpc.message = m.string;
                }
                rpc.data = present(e.object.get("data"));
            }
            resp.payload = .{ .err = rpc };
        } else {
            resp.payload = .{ .result = obj.get("result") orelse .null };
        }
        handler(p.ctx, &resp);
    }

    /// Serve newline-delimited JSON-RPC until EOF: read one line, handle it,
    /// repeat. Works over any reader/writer pair — stdio, an in-memory pipe,
    /// a socket. A read failure ends the loop like EOF (a dying peer is a
    /// session end, not a server error).
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
        return self.handleMessageFrom(msg, out, 0);
    }

    /// `handleMessage` for a transport that multiplexes several clients over one
    /// `Server`: `peer` names which one this message came from. It matters for
    /// exactly one thing — a JSON-RPC *response* is only correlated to a pending
    /// server→client request that was issued to the **same** peer, so one
    /// session cannot consume another session's sampling completion or the
    /// user's elicitation answer. Single-peer transports (stdio) pass 0, which
    /// is what `handleMessage` does.
    pub fn handleMessageFrom(self: *Server, msg: []const u8, out: *std.Io.Writer, peer: u64) Error!void {
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
            // No `method` but an `id` plus `result`/`error` is the CLIENT
            // answering one of OUR requests (sampling/elicitation). Correlate
            // it and write nothing: JSON-RPC never responds to a response —
            // answering here would bounce an error back at the client's id
            // forever.
            if (id != null and (obj.get("result") != null or obj.get("error") != null)) {
                self.deliverResponse(arena, id.?, obj, peer);
                return;
            }
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
            try self.handleCall(arena, out, id, obj.get("params"), peer);
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
        var caps: ?std.json.Value = null;
        if (params_opt) |params| {
            if (params == .object) {
                if (params.object.get("protocolVersion")) |pv| {
                    if (pv == .string) requested = pv.string;
                }
                caps = params.object.get("capabilities");
            }
        }
        const version = negotiateVersion(requested);
        // Record what the CLIENT can do: this is the gate on every server→client
        // request (see `ClientCapabilities`). A re-`initialize` replaces it
        // wholesale — capabilities never accumulate across handshakes.
        self.negotiated_version = version;
        self.client_capabilities = ClientCapabilities.parse(caps);

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

    fn handleCall(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64) Error!void {
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
        // Unknown tool => -32602 (MCP treats an unknown tool name as invalid
        // params on tools/call, not a missing method).
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
        var call = ToolCall{
            .arena = arena,
            .args = args,
            .progress = prog,
            .out = &tool_buf,
            .server = self,
            .transport = out,
            .peer = peer,
        };
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
            const supplied = blk: {
                if (args != .object) break :blk false;
                const v = args.object.get(a.name) orelse break :blk false;
                break :blk v == .string; // MCP prompt argument values are strings
            };
            if (!supplied) {
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

/// Upper bound on a single JSON-RPC line (16 MiB). Generous enough for a
/// tools/call payload, but caps the reusable read buffer so a hostile peer that
/// never sends a '\n' cannot drive unbounded memory growth. An over-long line
/// ends the session like a read failure (see `readLine`).
pub const max_line_len: usize = 16 * 1024 * 1024;

/// Read one newline-terminated line into the reusable buffer (grows as
/// needed up to `max_line_len`, so a tools/call line carrying a large payload
/// is handled). Returns the line slice (without '\n'), or null at EOF. A read
/// failure — or a line that would exceed `max_line_len` — counts as EOF, so a
/// peer that never terminates a line cannot exhaust memory.
fn readLine(gpa: std.mem.Allocator, reader: *std.Io.Reader, buf: *std.ArrayList(u8)) Error!?[]u8 {
    buf.clearRetainingCapacity();
    while (true) {
        const byte = reader.takeByte() catch {
            if (buf.items.len == 0) return null;
            return buf.items;
        };
        if (byte == '\n') return buf.items;
        // Cap the buffer: an unterminated/over-long line is treated as a
        // read failure (session end), bounding memory to max_line_len.
        if (buf.items.len >= max_line_len) return null;
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

test "readLine: an over-long unterminated line is capped, not buffered unbounded (audit CRIT)" {
    const alloc = testing.allocator;
    // Batch-10 audit CRIT: readLine grew buf one byte per input byte with no cap,
    // so a peer that never sends '\n' drove unbounded memory growth. Feed more than
    // max_line_len bytes with no newline: readLine must stop (return null) with
    // memory bounded to max_line_len rather than buffering the whole stream.
    const big = try alloc.alloc(u8, max_line_len + 100);
    defer alloc.free(big);
    @memset(big, 'x');
    var in: std.Io.Reader = .fixed(big);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    try testing.expect(try readLine(alloc, &in, &buf) == null);
    try testing.expect(buf.items.len <= max_line_len);
    // A normal short line still round-trips.
    var in2: std.Io.Reader = .fixed("hello\n");
    buf.clearRetainingCapacity();
    const l2 = try readLine(alloc, &in2, &buf);
    try testing.expectEqualStrings("hello", l2.?);
}

// ── sampling + elicitation: client capabilities ─────────────────────────────

/// Feed one message and discard whatever the server answered — for tests that
/// assert on server *state* rather than on the response bytes.
fn feed(s: *Server, msg: []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(msg, &aw.writer);
}

test "initialize: client capabilities are captured (and replaced on re-handshake)" {
    var s = testServer(null);
    defer s.deinit();
    // Nothing declared before a handshake: everything fails closed.
    try testing.expect(!s.client_capabilities.sampling);
    try testing.expect(!s.client_capabilities.elicitation);

    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{"tools":{}},"elicitation":{"form":{},"url":{}},"roots":{"listChanged":true}}}}
    );
    try testing.expect(s.client_capabilities.sampling);
    try testing.expect(s.client_capabilities.sampling_tools);
    try testing.expect(!s.client_capabilities.sampling_context);
    try testing.expect(s.client_capabilities.elicitation);
    try testing.expect(s.client_capabilities.elicitation_form);
    try testing.expect(s.client_capabilities.elicitation_url);
    try testing.expect(s.client_capabilities.roots);
    try testing.expect(s.client_capabilities.roots_list_changed);
    try testing.expectEqualStrings("2025-11-25", s.negotiated_version);

    // A second initialize replaces the set outright — capabilities must never
    // accumulate across handshakes (otherwise a client could never drop one).
    try feed(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}
    );
    try testing.expect(!s.client_capabilities.sampling);
    try testing.expect(!s.client_capabilities.elicitation);
    try testing.expectEqualStrings("2025-06-18", s.negotiated_version);
}

test "ClientCapabilities.parse: the spec's declaration shapes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const parse = struct {
        fn f(a: std.mem.Allocator, txt: []const u8) !ClientCapabilities {
            return ClientCapabilities.parse(try std.json.parseFromSliceLeaky(std.json.Value, a, txt, .{}));
        }
    }.f;

    // Spec (sampling): basic / with tools / with context.
    try testing.expect((try parse(arena, "{\"sampling\":{}}")).sampling);
    try testing.expect((try parse(arena, "{\"sampling\":{\"tools\":{}}}")).sampling_tools);
    try testing.expect((try parse(arena, "{\"sampling\":{\"context\":{}}}")).sampling_context);

    // Spec (elicitation): `{}` is equivalent to form-mode only.
    const bare = try parse(arena, "{\"elicitation\":{}}");
    try testing.expect(bare.elicitation and bare.elicitation_form and !bare.elicitation_url);
    // Explicit both modes.
    const both = try parse(arena, "{\"elicitation\":{\"form\":{},\"url\":{}}}");
    try testing.expect(both.elicitation_form and both.elicitation_url);
    // url-only: form mode is NOT available (the backwards-compat default must
    // not fire when a mode was declared explicitly).
    const url_only = try parse(arena, "{\"elicitation\":{\"url\":{}}}");
    try testing.expect(url_only.elicitation and !url_only.elicitation_form and url_only.elicitation_url);

    // Fail closed on junk / absence / explicit null.
    const none = try parse(arena, "{}");
    try testing.expect(!none.sampling and !none.elicitation);
    const nulled = try parse(arena, "{\"sampling\":null,\"elicitation\":null}");
    try testing.expect(!nulled.sampling and !nulled.elicitation);
    const wrong = ClientCapabilities.parse(.{ .string = "nope" });
    try testing.expect(!wrong.sampling and !wrong.elicitation);
}

// ── sampling: the capability gate + the spec's wire example ─────────────────

/// A server that has completed a handshake with the given client capabilities.
fn serverWithCaps(caps_json: []const u8) !Server {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    errdefer s.deinit();
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    const msg = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{s}}}}}",
        .{caps_json},
    );
    defer testing.allocator.free(msg);
    try s.handleMessage(msg, &sink.writer);
    return s;
}

test "sampling: refused unless the client declared the capability" {
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    const req = SamplingRequest{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 100,
    };

    // No handshake at all.
    var bare = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer bare.deinit();
    try testing.expectError(error.SamplingNotSupported, bare.sendSamplingRequest(&sink.writer, req, .{}));

    // Handshake that declares elicitation but NOT sampling.
    var elic_only = try serverWithCaps("{\"elicitation\":{}}");
    defer elic_only.deinit();
    try testing.expectError(error.SamplingNotSupported, elic_only.sendSamplingRequest(&sink.writer, req, .{}));
    // Nothing was written and nothing was recorded as pending.
    try testing.expectEqualStrings("", sink.written());
    try testing.expectEqual(@as(usize, 0), elic_only.pendingCount());

    // Declared: it goes out.
    var ok = try serverWithCaps("{\"sampling\":{}}");
    defer ok.deinit();
    _ = try ok.sendSamplingRequest(&sink.writer, req, .{});
    try testing.expect(sink.written().len != 0);
    try testing.expectEqual(@as(usize, 1), ok.pendingCount());
}

test "sampling: request line is byte-identical to the spec's createMessage example" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const hints = [_]ModelHint{.{ .name = "claude-3-sonnet" }};
    const id = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "What is the capital of France?" } }},
        .model_preferences = .{ .hints = &hints, .intelligence_priority = 0.8, .speed_priority = 0.5 },
        .system_prompt = "You are a helpful assistant.",
        .max_tokens = 100,
    }, .{});
    try testing.expectEqual(@as(u64, 1), id);

    // Verbatim from the MCP 2025-11-25 sampling page ("Creating Messages"),
    // compacted — this is the external anchor, not a self-consistency check.
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"What is the capital of France?"}}],"modelPreferences":{"hints":[{"name":"claude-3-sonnet"}],"intelligencePriority":0.8,"speedPriority":0.5},"systemPrompt":"You are a helpful assistant.","maxTokens":100}}
        \\
    , aw.written());
}

test "sampling: result decode matches the spec's response example" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Verbatim `result` from the spec's sampling response example.
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"role":"assistant","content":{"type":"text","text":"The capital of France is Paris."},"model":"claude-3-sonnet-20240307","stopReason":"endTurn"}
    , .{});
    const r = try SamplingResult.parse(v);
    try testing.expectEqual(Role.assistant, r.role);
    try testing.expectEqualStrings("The capital of France is Paris.", r.content.text);
    try testing.expectEqualStrings("claude-3-sonnet-20240307", r.model);
    try testing.expectEqualStrings("endTurn", r.stop_reason.?);

    // The tool-use response shape (content is an ARRAY of tool_use blocks) is
    // out of scope and must be refused, not half-decoded.
    const tool_use = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"role":"assistant","content":[{"type":"tool_use","id":"call_abc123","name":"get_weather","input":{"city":"Paris"}}],"model":"m","stopReason":"toolUse"}
    , .{});
    try testing.expectError(error.UnsupportedContent, SamplingResult.parse(tool_use));

    // Missing required members / bad role are malformed, never a default.
    for ([_][]const u8{
        \\{"content":{"type":"text","text":"x"},"model":"m"}
        ,
        \\{"role":"system","content":{"type":"text","text":"x"},"model":"m"}
        ,
        \\{"role":"assistant","content":{"type":"text","text":"x"}}
        ,
        \\{"role":"assistant","content":{"type":"text"},"model":"m"}
        ,
    }) |bad| {
        const bv = try std.json.parseFromSliceLeaky(std.json.Value, arena, bad, .{});
        try testing.expectError(error.MalformedResult, SamplingResult.parse(bv));
    }
}

test "sampling: image/audio blocks + priority validation" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    _ = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{
            .{ .role = .user, .content = .{ .image = .{ .data = "aGk=", .mime_type = "image/jpeg" } } },
            .{ .role = .assistant, .content = .{ .audio = .{ .data = "b28=", .mime_type = "audio/wav" } } },
        },
        .max_tokens = 7,
        .temperature = 0.25,
        .stop_sequences = &.{"STOP"},
    }, .{});
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"image","data":"aGk=","mimeType":"image/jpeg"}},{"role":"assistant","content":{"type":"audio","data":"b28=","mimeType":"audio/wav"}}],"maxTokens":7,"temperature":0.25,"stopSequences":["STOP"]}}
        \\
    , aw.written());

    // Priorities are normalized 0..1 per the spec; out of range is a server bug.
    const msgs = [_]SamplingMessage{.{ .role = .user, .content = .{ .text = "x" } }};
    try testing.expectError(error.InvalidPriority, s.sendSamplingRequest(&aw.writer, .{
        .messages = &msgs,
        .max_tokens = 1,
        .model_preferences = .{ .cost_priority = 1.5 },
    }, .{}));
    try testing.expectError(error.InvalidPriority, s.sendSamplingRequest(&aw.writer, .{
        .messages = &msgs,
        .max_tokens = 1,
        .model_preferences = .{ .speed_priority = -0.1 },
    }, .{}));
    try testing.expectError(error.NoMessages, s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{},
        .max_tokens = 1,
    }, .{}));
    try testing.expectError(error.InvalidMaxTokens, s.sendSamplingRequest(&aw.writer, .{
        .messages = &msgs,
        .max_tokens = 0,
    }, .{}));
}

// ── elicitation: capability gate, modes, schema subset ─────────────────────

const simple_schema =
    \\{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}
;

test "elicitation: refused unless the client declared the capability + the mode" {
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    const form = ElicitationRequest{ .form = .{ .message = "Please provide your GitHub username", .requested_schema = simple_schema } };
    const url = ElicitationRequest{ .url = .{
        .message = "Please provide your API key to continue.",
        .url = "https://mcp.example.com/ui/set_api_key",
        .elicitation_id = "550e8400-e29b-41d4-a716-446655440000",
    } };

    var bare = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer bare.deinit();
    try testing.expectError(error.ElicitationNotSupported, bare.sendElicitationRequest(&sink.writer, form, .{}));

    // Declared sampling only.
    var samp = try serverWithCaps("{\"sampling\":{}}");
    defer samp.deinit();
    try testing.expectError(error.ElicitationNotSupported, samp.sendElicitationRequest(&sink.writer, form, .{}));

    // Form-only client: URL mode must be refused (spec: servers MUST NOT send
    // a mode the client did not declare).
    var form_only = try serverWithCaps("{\"elicitation\":{}}");
    defer form_only.deinit();
    try testing.expectError(error.ElicitationUrlNotSupported, form_only.sendElicitationRequest(&sink.writer, url, .{}));
    _ = try form_only.sendElicitationRequest(&sink.writer, form, .{});

    // URL-only client: form mode must be refused.
    var url_only = try serverWithCaps("{\"elicitation\":{\"url\":{}}}");
    defer url_only.deinit();
    try testing.expectError(error.ElicitationFormNotSupported, url_only.sendElicitationRequest(&sink.writer, form, .{}));
    _ = try url_only.sendElicitationRequest(&sink.writer, url, .{});
}

test "elicitation: form request line is byte-identical to the spec's example" {
    var s = try serverWithCaps("{\"elicitation\":{\"form\":{}}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    _ = try s.sendElicitationRequest(&aw.writer, .{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema = simple_schema,
    } }, .{});
    // Verbatim from the MCP 2025-11-25 elicitation page ("Simple Text Request").
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"form","message":"Please provide your GitHub username","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}
        \\
    , aw.written());
}

test "elicitation: url request line is byte-identical to the spec's example" {
    var s = try serverWithCaps("{\"elicitation\":{\"url\":{}}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    _ = try s.sendElicitationRequest(&aw.writer, .{ .url = .{
        .message = "Please provide your API key to continue.",
        .url = "https://mcp.example.com/ui/set_api_key",
        .elicitation_id = "550e8400-e29b-41d4-a716-446655440000",
    } }, .{});
    // Verbatim from the MCP 2025-11-25 elicitation page ("Request Sensitive
    // Data") — note the id is 3 there; only the JSON-RPC id differs.
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"url","elicitationId":"550e8400-e29b-41d4-a716-446655440000","url":"https://mcp.example.com/ui/set_api_key","message":"Please provide your API key to continue."}}
        \\
    , aw.written());
}

test "elicitation: a 2025-06-18 peer gets no `mode` field (that revision has none)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{}}}}
    , &aw.writer);
    aw.clearRetainingCapacity();

    _ = try s.sendElicitationRequest(&aw.writer, .{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema = simple_schema,
    } }, .{});
    // Verbatim from the MCP 2025-06-18 elicitation page — no `mode` member.
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"message":"Please provide your GitHub username","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}
        \\
    , aw.written());
}

test "elicitation: result decode — accept/decline/cancel, decline is not an error" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const P = struct {
        fn f(a: std.mem.Allocator, txt: []const u8) !ElicitationResult {
            return ElicitationResult.parse(try std.json.parseFromSliceLeaky(std.json.Value, a, txt, .{}));
        }
    }.f;

    // Verbatim results from the spec's examples.
    const acc = try P(arena, "{\"action\":\"accept\",\"content\":{\"name\":\"octocat\"}}");
    try testing.expectEqual(ElicitationAction.accept, acc.action);
    try testing.expectEqualStrings("octocat", acc.content.?.object.get("name").?.string);

    const dec = try P(arena, "{\"action\":\"decline\"}");
    try testing.expectEqual(ElicitationAction.decline, dec.action);
    try testing.expect(dec.content == null);

    const can = try P(arena, "{\"action\":\"cancel\"}");
    try testing.expectEqual(ElicitationAction.cancel, can.action);

    // URL-mode accept carries no content — still an accept.
    const url_acc = try P(arena, "{\"action\":\"accept\"}");
    try testing.expectEqual(ElicitationAction.accept, url_acc.action);
    try testing.expect(url_acc.content == null);

    // A declined answer that nonetheless carries `content` must NOT surface it:
    // the user refused, so there is no data to consume.
    const sneaky = try P(arena, "{\"action\":\"decline\",\"content\":{\"name\":\"octocat\"}}");
    try testing.expectEqual(ElicitationAction.decline, sneaky.action);
    try testing.expect(sneaky.content == null);

    // Unknown/absent action is malformed — never silently an accept.
    try testing.expectError(error.MalformedResult, P(arena, "{\"action\":\"maybe\"}"));
    try testing.expectError(error.MalformedResult, P(arena, "{}"));
    try testing.expectError(error.MalformedResult, P(arena, "{\"action\":\"accept\",\"content\":[1,2]}"));
}

test "elicitation schema: the spec's own examples validate" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // "Structured Data Request" from the spec, verbatim.
    try validateElicitationSchema(arena,
        \\{"type":"object","properties":{"name":{"type":"string","description":"Your full name"},
        \\"email":{"type":"string","format":"email","description":"Your email address"},
        \\"age":{"type":"number","minimum":18,"description":"Your age"}},"required":["name","email"]}
    );
    // Every primitive shape the spec lists, plus both enum spellings and both
    // multi-select spellings.
    try validateElicitationSchema(arena,
        \\{"type":"object","properties":{
        \\ "s":{"type":"string","title":"Display Name","description":"d","minLength":3,"maxLength":50,"pattern":"^[A-Za-z]+$","format":"email","default":"user@example.com"},
        \\ "n":{"type":"number","title":"D","description":"d","minimum":0,"maximum":100,"default":50},
        \\ "i":{"type":"integer","minimum":0,"default":3},
        \\ "b":{"type":"boolean","title":"D","description":"d","default":false},
        \\ "e":{"type":"string","title":"Color Selection","description":"c","enum":["Red","Green","Blue"],"default":"Red"},
        \\ "e18":{"type":"string","enum":["a","b"],"enumNames":["A","B"]},
        \\ "eo":{"type":"string","title":"Color Selection","oneOf":[{"const":"#FF0000","title":"Red"},{"const":"#00FF00","title":"Green"}],"default":"#FF0000"},
        \\ "m":{"type":"array","title":"Colors","minItems":1,"maxItems":2,"items":{"type":"string","enum":["Red","Green"]},"default":["Red"]},
        \\ "mo":{"type":"array","minItems":1,"items":{"anyOf":[{"const":"#FF0000","title":"Red"},{"const":"#0000FF","title":"Blue"}]}}
        \\}}
    );
}

test "elicitation schema: the restricted subset is enforced" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct { schema: []const u8, want: anyerror }{
        // The headline restriction: flat objects only, no nesting.
        .{ .schema =
        \\{"type":"object","properties":{"addr":{"type":"object","properties":{"city":{"type":"string"}}}}}
        , .want = error.SchemaNestedObject },
        // An array of objects is the other way to smuggle nesting in.
        .{ .schema =
        \\{"type":"object","properties":{"xs":{"type":"array","items":{"type":"object","properties":{}}}}}
        , .want = error.SchemaBadItems },
        // An array of plain (non-enum) strings is not in the subset either —
        // only multi-select enums are.
        .{ .schema =
        \\{"type":"object","properties":{"xs":{"type":"array","items":{"type":"string"}}}}
        , .want = error.SchemaBadItems },
        .{ .schema =
        \\{"type":"object","properties":{"x":{"type":"null"}}}
        , .want = error.SchemaUnsupportedType },
        .{ .schema =
        \\{"type":"object","properties":{"x":{}}}
        , .want = error.SchemaUnsupportedType },
        .{ .schema =
        \\{"type":"object","properties":{"x":"string"}}
        , .want = error.SchemaPropertyNotObject },
        // Root shape.
        .{ .schema =
        \\{"type":"array","properties":{}}
        , .want = error.SchemaTypeNotObject },
        .{ .schema =
        \\{"properties":{}}
        , .want = error.SchemaTypeNotObject },
        .{ .schema =
        \\{"type":"object"}
        , .want = error.SchemaMissingProperties },
        .{ .schema =
        \\{"type":"object","properties":{},"$defs":{}}
        , .want = error.SchemaUnsupportedKeyword },
        .{ .schema = "[1,2]", .want = error.SchemaNotObject },
        .{ .schema = "{not json", .want = error.SchemaNotJson },
        // `required` must name declared properties.
        .{ .schema =
        \\{"type":"object","properties":{"a":{"type":"string"}},"required":["b"]}
        , .want = error.SchemaBadRequired },
        .{ .schema =
        \\{"type":"object","properties":{"a":{"type":"string"}},"required":"a"}
        , .want = error.SchemaBadRequired },
        // Per-type keyword hygiene: a keyword from the wrong type is rejected
        // rather than passed through to a client that will ignore it.
        .{ .schema =
        \\{"type":"object","properties":{"n":{"type":"number","minLength":3}}}
        , .want = error.SchemaUnsupportedKeyword },
        .{ .schema =
        \\{"type":"object","properties":{"s":{"type":"string","minimum":3}}}
        , .want = error.SchemaUnsupportedKeyword },
        .{ .schema =
        \\{"type":"object","properties":{"s":{"type":"string","format":"hostname"}}}
        , .want = error.SchemaBadFormat },
        .{ .schema =
        \\{"type":"object","properties":{"e":{"type":"string","enum":[]}}}
        , .want = error.SchemaBadEnum },
        .{ .schema =
        \\{"type":"object","properties":{"e":{"type":"string","enum":[1,2]}}}
        , .want = error.SchemaBadEnum },
        .{ .schema =
        \\{"type":"object","properties":{"e":{"type":"string","enum":["a"],"enumNames":["A","B"]}}}
        , .want = error.SchemaBadEnum },
        .{ .schema =
        \\{"type":"object","properties":{"e":{"type":"string","enumNames":["A"]}}}
        , .want = error.SchemaBadEnum },
        .{ .schema =
        \\{"type":"object","properties":{"e":{"type":"string","enum":["a"],"oneOf":[{"const":"a"}]}}}
        , .want = error.SchemaBadEnum },
        .{ .schema =
        \\{"type":"object","properties":{"e":{"type":"string","oneOf":[{"const":1}]}}}
        , .want = error.SchemaBadEnum },
        // Defaults must match the declared type.
        .{ .schema =
        \\{"type":"object","properties":{"b":{"type":"boolean","default":"yes"}}}
        , .want = error.SchemaBadDefault },
        .{ .schema =
        \\{"type":"object","properties":{"i":{"type":"integer","default":1.5}}}
        , .want = error.SchemaBadDefault },
        .{ .schema =
        \\{"type":"object","properties":{"s":{"type":"string","default":7}}}
        , .want = error.SchemaBadDefault },
        // Bounds must be sane counts / numbers.
        .{ .schema =
        \\{"type":"object","properties":{"s":{"type":"string","minLength":-1}}}
        , .want = error.SchemaBadBound },
        .{ .schema =
        \\{"type":"object","properties":{"n":{"type":"number","maximum":"big"}}}
        , .want = error.SchemaBadBound },
    };
    for (cases) |c| {
        testing.expectError(c.want, validateElicitationSchema(arena, c.schema)) catch |err| {
            std.debug.print("schema case failed: {s}\n", .{c.schema});
            return err;
        };
    }
}

test "elicitation: form mode refuses credential-shaped fields (phishing guard)" {
    var s = try serverWithCaps("{\"elicitation\":{\"form\":{},\"url\":{}}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    // The exact thing the spec forbids: a trusted client dialog asking for a
    // credential on a server's behalf.
    const by_name =
        \\{"type":"object","properties":{"password":{"type":"string"}},"required":["password"]}
    ;
    try testing.expectError(error.SchemaSensitiveField, s.sendElicitationRequest(&aw.writer, .{
        .form = .{ .message = "Sign in to continue", .requested_schema = by_name },
    }, .{}));

    // Also caught when the give-away is in the display title, not the key.
    const by_title =
        \\{"type":"object","properties":{"v":{"type":"string","title":"API Key"}}}
    ;
    try testing.expectError(error.SchemaSensitiveField, s.sendElicitationRequest(&aw.writer, .{
        .form = .{ .message = "Connect", .requested_schema = by_title },
    }, .{}));

    // Nothing went out and nothing is pending — the refusal is at the seam.
    try testing.expectEqualStrings("", aw.written());
    try testing.expectEqual(@as(usize, 0), s.pendingCount());

    // The sanctioned route for the same goal is URL mode, which is allowed.
    _ = try s.sendElicitationRequest(&aw.writer, .{ .url = .{
        .message = "Please provide your API key to continue.",
        .url = "https://mcp.example.com/ui/set_api_key",
        .elicitation_id = "e-1",
    } }, .{});
    try testing.expect(aw.written().len != 0);
}

test "looksLikeSecretField: separator/case forms and the words it does NOT claim" {
    for ([_][]const u8{
        "password", "Password",      "passwd",      "pass_phrase",   "user-password",
        "api_key",  "apiKey",        "API-KEY",     "accessToken",   "refresh_token",
        "secret",   "client secret", "private_key", "session-token", "pin_code",
        "cvv",      "cardNumber",    "seed phrase", "mnemonic",      "id_token",
    }) |name| {
        testing.expect(looksLikeSecretField(name)) catch {
            std.debug.print("expected secret-shaped: {s}\n", .{name});
            return error.TestUnexpectedResult;
        };
    }
    // Ordinary form fields must not be blocked — a guard that fires on
    // "username" makes the module unusable and gets disabled.
    for ([_][]const u8{
        "name",    "username", "email",     "age",       "city",
        "comment", "branch",   "keyword",   "tokenizer", "robot parts",
        "laptop",  "keys",     "passenger", "compass",   "topic",
    }) |name| {
        testing.expect(!looksLikeSecretField(name)) catch {
            std.debug.print("false positive: {s}\n", .{name});
            return error.TestUnexpectedResult;
        };
    }
}

test "elicitation: url mode rejects non-navigable schemes and empty ids" {
    var s = try serverWithCaps("{\"elicitation\":{\"url\":{}}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const bad_urls = [_][]const u8{
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "file:///etc/passwd",
        "http://evil.example/steal", // plain http to a non-loopback host
        "https://",
        "",
    };
    for (bad_urls) |u| {
        testing.expectError(error.InvalidUrl, s.sendElicitationRequest(&aw.writer, .{ .url = .{
            .message = "go here",
            .url = u,
            .elicitation_id = "e-1",
        } }, .{})) catch |err| {
            std.debug.print("url accepted: {s}\n", .{u});
            return err;
        };
    }
    // http is allowed for loopback only (the development case).
    _ = try s.sendElicitationRequest(&aw.writer, .{ .url = .{
        .message = "go here",
        .url = "http://localhost:7717/connect",
        .elicitation_id = "e-1",
    } }, .{});

    try testing.expectError(error.MissingElicitationId, s.sendElicitationRequest(&aw.writer, .{ .url = .{
        .message = "go here",
        .url = "https://ok.example/",
        .elicitation_id = "",
    } }, .{}));
    try testing.expectError(error.EmptyMessage, s.sendElicitationRequest(&aw.writer, .{ .url = .{
        .message = "",
        .url = "https://ok.example/",
        .elicitation_id = "e",
    } }, .{}));
}

// ── correlation: the inbound response path ─────────────────────────────────

const Collector = struct {
    calls: u32 = 0,
    last_id: u64 = 0,
    last_kind: RequestKind = .sampling,
    last_text: [128]u8 = @splat(0),
    last_text_len: usize = 0,
    last_action: ?ElicitationAction = null,
    last_error_code: ?i32 = null,

    fn on(ctx: ?*anyopaque, resp: *const ClientResponse) void {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        self.last_id = resp.id;
        self.last_kind = resp.kind;
        switch (resp.payload) {
            .err => |e| self.last_error_code = e.code,
            .result => switch (resp.kind) {
                .sampling => {
                    const r = resp.samplingResult() catch return;
                    const n = @min(r.content.text.len, self.last_text.len);
                    @memcpy(self.last_text[0..n], r.content.text[0..n]);
                    self.last_text_len = n;
                },
                .elicitation => {
                    const r = resp.elicitationResult() catch return;
                    self.last_action = r.action;
                    if (r.content) |c| {
                        if (c.object.get("name")) |nm| {
                            if (nm == .string) {
                                const n = @min(nm.string.len, self.last_text.len);
                                @memcpy(self.last_text[0..n], nm.string[0..n]);
                                self.last_text_len = n;
                            }
                        }
                    }
                },
            },
        }
    }

    fn text(self: *const Collector) []const u8 {
        return self.last_text[0..self.last_text_len];
    }
};

test "correlation: a client response resolves its pending request and answers nothing" {
    var s = try serverWithCaps("{\"sampling\":{},\"elicitation\":{}}");
    defer s.deinit();
    var col = Collector{};
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const id = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    }, .{ .on_response = &Collector.on, .ctx = &col });
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    aw.clearRetainingCapacity();

    // The client answers. A response must produce NO output line — replying to
    // a response is a JSON-RPC violation (and, with the same id, a loop).
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"The capital of France is Paris."},"model":"m","stopReason":"endTurn"}}
    , &aw.writer);
    try testing.expectEqualStrings("", aw.written());
    try testing.expectEqual(@as(u32, 1), col.calls);
    try testing.expectEqual(id, col.last_id);
    try testing.expectEqual(RequestKind.sampling, col.last_kind);
    try testing.expectEqualStrings("The capital of France is Paris.", col.text());
    try testing.expectEqual(@as(usize, 0), s.pendingCount());

    // The same answer arriving twice must not fire the handler again.
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"again"},"model":"m"}}
    , &aw.writer);
    try testing.expectEqual(@as(u32, 1), col.calls);
    try testing.expectEqualStrings("", aw.written());
}

test "correlation: responses go to the right pending request, out of order" {
    var s = try serverWithCaps("{\"sampling\":{},\"elicitation\":{}}");
    defer s.deinit();
    var samp = Collector{};
    var elic = Collector{};
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const id1 = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "one" } }},
        .max_tokens = 10,
    }, .{ .on_response = &Collector.on, .ctx = &samp });
    const id2 = try s.sendElicitationRequest(&aw.writer, .{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema = simple_schema,
    } }, .{ .on_response = &Collector.on, .ctx = &elic });
    try testing.expectEqual(@as(u64, 1), id1);
    try testing.expectEqual(@as(u64, 2), id2);
    try testing.expectEqual(@as(usize, 2), s.pendingCount());
    aw.clearRetainingCapacity();

    // Answer the SECOND request first: correlation is by id, not by order.
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":2,"result":{"action":"accept","content":{"name":"octocat"}}}
    , &aw.writer);
    try testing.expectEqual(@as(u32, 0), samp.calls);
    try testing.expectEqual(@as(u32, 1), elic.calls);
    try testing.expectEqual(RequestKind.elicitation, elic.last_kind);
    try testing.expectEqual(ElicitationAction.accept, elic.last_action.?);
    try testing.expectEqualStrings("octocat", elic.text());

    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"one-answer"},"model":"m"}}
    , &aw.writer);
    try testing.expectEqual(@as(u32, 1), samp.calls);
    try testing.expectEqualStrings("one-answer", samp.text());
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

test "correlation: a response for an unknown/foreign id is dropped, never answered" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var col = Collector{};
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    _ = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    }, .{ .on_response = &Collector.on, .ctx = &col });
    aw.clearRetainingCapacity();

    for ([_][]const u8{
        // Never-issued numeric id.
        \\{"jsonrpc":"2.0","id":99,"result":{}}
        ,
        // String id: our outbound ids are integers, so this is not ours.
        \\{"jsonrpc":"2.0","id":"1","result":{}}
        ,
        // Negative id.
        \\{"jsonrpc":"2.0","id":-1,"result":{}}
        ,
    }) |msg| {
        try s.handleMessage(msg, &aw.writer);
        try testing.expectEqualStrings("", aw.written()); // silence, not -32600
        try testing.expectEqual(@as(u32, 0), col.calls);
        try testing.expectEqual(@as(usize, 1), s.pendingCount()); // still ours
    }

    // A message with neither result nor error and no method is still a
    // malformed *request* and keeps its -32600.
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":1}", &aw.writer);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Missing method"}}
        \\
    , aw.written());
}

test "correlation: a response from another peer cannot claim the request" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var col = Collector{};
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    // Issued to peer 7 (e.g. one HTTP session).
    _ = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    }, .{ .peer = 7, .on_response = &Collector.on, .ctx = &col });
    aw.clearRetainingCapacity();
    const answer =
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"stolen"},"model":"m"}}
    ;

    // Peer 9 answers with the same id: it must NOT be delivered, and the
    // request must stay pending for its real peer.
    try s.handleMessageFrom(answer, &aw.writer, 9);
    try testing.expectEqual(@as(u32, 0), col.calls);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    // The default (peer 0) path is not a wildcard either.
    try s.handleMessage(answer, &aw.writer);
    try testing.expectEqual(@as(u32, 0), col.calls);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());

    // The real peer answers: delivered.
    try s.handleMessageFrom(answer, &aw.writer, 7);
    try testing.expectEqual(@as(u32, 1), col.calls);
    try testing.expectEqualStrings("stolen", col.text());
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
    try testing.expectEqualStrings("", aw.written());
}

test "correlation: a JSON-RPC error response reaches the handler as an error" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var col = Collector{};
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    _ = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    }, .{ .on_response = &Collector.on, .ctx = &col });
    aw.clearRetainingCapacity();

    // The spec's own example: user rejected the sampling request.
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"User rejected sampling request"}}
    , &aw.writer);
    try testing.expectEqual(@as(u32, 1), col.calls);
    try testing.expectEqual(@as(i32, error_code.user_rejected), col.last_error_code.?);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
    try testing.expectEqualStrings("", aw.written());
}

test "outbound ids: never reused, not even after a failed send or a cancel" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const req = SamplingRequest{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    };

    try testing.expectEqual(@as(u64, 1), try s.sendSamplingRequest(&aw.writer, req, .{}));
    try testing.expectEqual(@as(u64, 2), try s.sendSamplingRequest(&aw.writer, req, .{}));

    // A send that fails at the transport still burns its id: id 3 is gone.
    var full: [8]u8 = undefined;
    var tiny: std.Io.Writer = .fixed(&full);
    try testing.expectError(error.WriteFailed, s.sendSamplingRequest(&tiny, req, .{}));
    try testing.expectEqual(@as(usize, 2), s.pendingCount()); // the failed one was rolled back
    try testing.expectEqual(@as(u64, 4), try s.sendSamplingRequest(&aw.writer, req, .{}));

    // Cancelling frees the slot but never the id.
    aw.clearRetainingCapacity();
    try s.cancelRequest(&aw.writer, 2, "took too long");
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"took too long"}}
        \\
    , aw.written());
    try testing.expectEqual(@as(usize, 2), s.pendingCount());
    try testing.expectEqual(@as(u64, 5), try s.sendSamplingRequest(&aw.writer, req, .{}));

    // Cancelling an unknown/already-cancelled id is a silent no-op.
    aw.clearRetainingCapacity();
    try s.cancelRequest(&aw.writer, 2, "again");
    try s.cancelRequest(&aw.writer, 999, "");
    try testing.expectEqualStrings("", aw.written());
}

test "outbound: a cancelled request's late answer is ignored" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var col = Collector{};
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const id = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    }, .{ .on_response = &Collector.on, .ctx = &col });
    try s.cancelRequest(&aw.writer, id, "");
    aw.clearRetainingCapacity();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"late"},"model":"m"}}
    , &aw.writer);
    try testing.expectEqual(@as(u32, 0), col.calls);
    try testing.expectEqualStrings("", aw.written());
}

test "outbound: the pending table is capped" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    s.max_pending = 2;
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const req = SamplingRequest{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    };
    _ = try s.sendSamplingRequest(&aw.writer, req, .{});
    _ = try s.sendSamplingRequest(&aw.writer, req, .{});
    try testing.expectError(error.TooManyPending, s.sendSamplingRequest(&aw.writer, req, .{}));
    // A resolved request frees a slot.
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"x"},"model":"m"}}
    , &aw.writer);
    _ = try s.sendSamplingRequest(&aw.writer, req, .{});
}

// ── the tool-handler seam ──────────────────────────────────────────────────

/// A tool that asks the user for their name via elicitation. It does NOT wait:
/// it fires the request and returns immediately — the whole point of the seam.
fn askingTool(ctx: ?*anyopaque, call: *ToolCall) bool {
    const seen: *bool = @ptrCast(@alignCast(ctx.?));
    if (!call.clientCapabilities().elicitation) {
        return call.fail("client cannot elicit");
    }
    _ = call.requestElicitation(.{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema = simple_schema,
    } }, .{}) catch return call.fail("elicitation refused");
    seen.* = true;
    call.write("{\"asked\":true}");
    return false;
}

test "tools/call: a tool issues an elicitation; the request precedes the result" {
    var s = try serverWithCaps("{\"elicitation\":{}}");
    defer s.deinit();
    var seen = false;
    try s.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &askingTool,
        .ctx = &seen,
    });
    // The server→client request goes out as its own line first, then the tool
    // result — the same interleaving rule progress notifications follow.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"ask"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"form","message":"Please provide your GitHub username","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}
        \\{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"{\"asked\":true}"}],"structuredContent":{"asked":true},"isError":false}}
        \\
    );
    try testing.expect(seen);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
}

test "tools/call: a tool cannot elicit from a client that never declared it" {
    var s = try serverWithCaps("{}");
    defer s.deinit();
    var seen = false;
    try s.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &askingTool,
        .ctx = &seen,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"ask"}}
    ,
        \\{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"error: client cannot elicit"}],"isError":true}}
        \\
    );
    try testing.expect(!seen);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

test "tools/call: a request issued from a call inherits the caller's peer" {
    var s = try serverWithCaps("{\"elicitation\":{}}");
    defer s.deinit();
    var seen = false;
    try s.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &askingTool,
        .ctx = &seen,
    });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessageFrom(
        \\{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"ask"}}
    , &aw.writer, 42);
    aw.clearRetainingCapacity();

    // Peer 0 answering is not the caller: the entry stays pending.
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"action\":\"decline\"}}", &aw.writer);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    // Peer 42 is.
    try s.handleMessageFrom("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"action\":\"decline\"}}", &aw.writer, 42);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

test "integration: ask on one call, act on the next (the two-call shape)" {
    // The seam's honest usage pattern, driven over `serve` exactly as a stdio
    // client would: tools/call fires an elicitation, the client answers in a
    // later message, and the answer lands in the app state a subsequent call
    // reads. Nothing blocks.
    const App = struct {
        answer: [64]u8 = @splat(0),
        answer_len: usize = 0,
        declined: bool = false,

        fn onAnswer(ctx: ?*anyopaque, resp: *const ClientResponse) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            const r = resp.elicitationResult() catch return;
            switch (r.action) {
                // Declining is a normal outcome, not a failure.
                .decline, .cancel => self.declined = true,
                .accept => {
                    const c = r.content orelse return;
                    const nm = c.object.get("name") orelse return;
                    if (nm != .string) return;
                    const n = @min(nm.string.len, self.answer.len);
                    @memcpy(self.answer[0..n], nm.string[0..n]);
                    self.answer_len = n;
                },
            }
        }

        fn ask(ctx: ?*anyopaque, call: *ToolCall) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            _ = call.requestElicitation(.{ .form = .{
                .message = "Please provide your GitHub username",
                .requested_schema = simple_schema,
            } }, .{ .on_response = &onAnswer, .ctx = self }) catch return call.fail("refused");
            call.write("{\"asked\":true}");
            return false;
        }

        fn whoami(ctx: ?*anyopaque, call: *ToolCall) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (self.answer_len == 0) return call.fail("not answered yet");
            call.print("{{\"user\":\"{s}\"}}", .{self.answer[0..self.answer_len]});
            return false;
        }
    };

    var app = App{};
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "ask", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &App.ask, .ctx = &app });
    try s.addTool(.{ .name = "whoami", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &App.whoami, .ctx = &app });

    const input =
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{"form":{}}}}}
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask"}}
        \\{"jsonrpc":"2.0","id":1,"result":{"action":"accept","content":{"name":"octocat"}}}
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami"}}
    ;
    var in: std.Io.Reader = .fixed(input);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.serve(&in, &aw.writer);

    const expected =
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"t","title":"t","version":"0"}}}
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"error: not answered yet"}],"isError":true}}
        \\{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{"mode":"form","message":"Please provide your GitHub username","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"asked\":true}"}],"structuredContent":{"asked":true},"isError":false}}
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"user\":\"octocat\"}"}],"structuredContent":{"user":"octocat"},"isError":false}}
        \\
    ;
    try testing.expectEqualStrings(expected, aw.written());
    try testing.expectEqualStrings("octocat", app.answer[0..app.answer_len]);
    try testing.expect(!app.declined);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

test "server capabilities do not advertise sampling/elicitation (they are the CLIENT's)" {
    // Sampling and elicitation are declared by the client at initialize; a
    // server that advertised them would be claiming to *serve* them.
    var s = testServer(null);
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{},"elicitation":{}}}}
    , &aw.writer);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "\"sampling\"") == null);
    try testing.expect(std.mem.indexOf(u8, aw.written(), "\"elicitation\"") == null);
}

// ── fuzz: one JSON-RPC message dispatch, never panics ───────────────────────
//
// `handleMessage` is the boundary between a stdio transport (or, via
// `mcp-http`, an HTTP POST body) and this server — a fully untrusted peer
// line reaching every dispatch branch (initialize/tools/resources/prompts),
// not just the JSON parse itself. Drive it against a server with a real
// registered tool so `tools/call`'s param-validation path is reachable too,
// not only the outer parse-error branches.

test "fuzz: handleMessage never panics on an arbitrary JSON-RPC line" {
    try testing.fuzz({}, fuzzHandleMessage, .{});
}

fn fuzzHandleMessage(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var s = testServer(null);
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    s.handleMessage(buf[0..len], &aw.writer) catch return;
}
