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
//! **Two eras, one server** (spec 2026-07-28, basic/versioning.mdx, "dual-era
//! server"). A request whose `params._meta` carries
//! `io.modelcontextprotocol/protocolVersion` is a *modern* (2026-07-28)
//! request and is served statelessly: its version, client capabilities and
//! client identity come from that `_meta`, never from an earlier message; its
//! result carries `resultType`, `_meta.io.modelcontextprotocol/serverInfo` and,
//! on the cacheable methods, `ttlMs`/`cacheScope`; `server/discover` answers
//! it; `ping` does not exist for it. Instead of server→client requests, a
//! modern `tools/call`, `prompts/get` or `resources/read` asks the client for
//! input with an `InputRequiredResult` and is retried with the answers (multi
//! round-trip requests — `InputRound`, `StateSeal`). Every other request takes the
//! `initialize`-session path below, byte-for-byte as before — so an existing
//! client never sees a changed reply.
//!
//! Protocol surface of the session path (spec revision 2025-11-25):
//!   * `initialize` — protocol-version negotiation (echo the client's
//!     requested revision when supported, else answer with our latest) +
//!     server capabilities (`tools` always; `resources`/`prompts` only when
//!     at least one is registered — the spec's own "present if the server
//!     offers any" reading) + serverInfo + optional instructions.
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
/// `x-mcp-header` annotation rules, checked by `Server.addTool`.
pub const header_annotations = @import("header_annotations.zig");
/// The JSON Schema 2020-12 subset `tools/call` checks arguments and
/// `structuredContent` against (`Server.validate_tool_io`).
pub const schema_check = @import("schema_check.zig");
/// RFC 6570 parse/expand/match; `resources/read` matches a request's uri
/// against each template (`ResourceRequest.vars`).
pub const uri_template = @import("uri_template.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Model Context Protocol server (JSON-RPC 2.0) — tools, resources, prompts, plus server→client sampling and elicitation requests.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .server,
    .concurrency = .reentrant, // no globals; one Server instance = one owner
    .model_after = "MCP spec 2026-07-28 (stateless) + 2025-11-25/2025-06-18 (initialize) + JSON-RPC 2.0",
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

/// The stateless revision: a request naming it in `_meta` is served on its
/// own, with no handshake (spec 2026-07-28, basic/index.mdx "Statelessness").
pub const modern_protocol_version = "2026-07-28";

/// Revisions served statelessly — the only ones a `_meta` protocolVersion may
/// name. A `_meta` naming anything else, a session revision included, gets
/// `UnsupportedProtocolVersionError`: those revisions are reached through
/// `initialize`, not through per-request metadata.
pub const modern_versions = [_][]const u8{modern_protocol_version};

/// Every revision this server speaks, newest first: what `server/discover`
/// advertises and what `UnsupportedProtocolVersionError.data.supported`
/// lists (the spec's own example lists a session revision there too).
pub const all_versions = modern_versions ++ supported_versions;

/// The reserved `_meta` keys this module reads or writes (spec 2026-07-28,
/// basic/index.mdx "Per-request protocol fields").
pub const meta_key = struct {
    pub const protocol_version = "io.modelcontextprotocol/protocolVersion";
    pub const client_capabilities = "io.modelcontextprotocol/clientCapabilities";
    pub const client_info = "io.modelcontextprotocol/clientInfo";
    pub const server_info = "io.modelcontextprotocol/serverInfo";
    /// basic/patterns/subscriptions.mdx: the `subscriptions/listen` request's
    /// JSON-RPC id, on every message of that subscription.
    pub const subscription_id = "io.modelcontextprotocol/subscriptionId";
};

/// JSON-RPC 2.0 standard error codes + the MCP-defined ones.
pub const error_code = struct {
    pub const parse_error: i32 = -32700;
    pub const invalid_request: i32 = -32600;
    pub const method_not_found: i32 = -32601;
    pub const invalid_params: i32 = -32602;
    pub const internal_error: i32 = -32603;
    /// MCP spec up to 2025-11-25: `resources/read` on a uri no resource
    /// resolves. Session path only — 2026-07-28 forbids emitting it and uses
    /// `invalid_params` with `data.uri` instead (server/resources.mdx).
    pub const resource_not_found: i32 = -32002;
    /// MCP 2026-07-28: Streamable HTTP headers disagree with the body. A
    /// transport's code (`mcp-http`); never emitted here.
    pub const header_mismatch: i32 = -32020;
    /// MCP 2026-07-28: the request needs a client capability its `_meta` did
    /// not declare (`data.requiredCapabilities`). For the application.
    pub const missing_required_client_capability: i32 = -32021;
    /// MCP 2026-07-28: the `_meta` protocolVersion is not one of
    /// `modern_versions` (`data.supported`, `data.requested`).
    pub const unsupported_protocol_version: i32 = -32022;
    /// MCP spec (sampling): the client's user rejected the sampling request.
    /// Received, never emitted — this server is the requester there.
    pub const user_rejected: i32 = -1;
    /// MCP spec 2025-11-25 (elicitation): a server tells the client the request
    /// cannot proceed until a URL-mode elicitation completes. Emitted by the
    /// application, not by this module's dispatch.
    pub const url_elicitation_required: i32 = -32042;
};

/// How one JSON-RPC method this server sends or dispatches is anchored
/// against the MCP specification's own literal JSON examples (see the "tests"
/// section of each `docs/specification/2025-11-25/**` page) — as opposed to
/// self-consistency (a golden value this module invented and then asserted
/// against itself).
///
///   * `.literal_example` — a spec page embeds a request/response (or
///     notification) whose wire text this module reproduces byte-for-byte in
///     a test: the spec's literal JSON decodes through our parser and/or our
///     encoder's output matches the spec's literal text exactly.
///   * `.partial` — the spec's literal request decodes verbatim (proving
///     format compatibility), but the spec's illustrative response also shows
///     optional fields (`title`, `icons`, `execution`, …) this module does not
///     implement, so the response cannot be byte-identical; `reason` says
///     what is and isn't covered.
///   * `.no_example` — the spec publishes no JSON example for this method, or
///     this module deliberately does not implement the path the example
///     shows; `reason` is mandatory.
pub const SpecAnchor = enum { literal_example, partial, no_example };

pub const MethodAnchor = struct {
    method: []const u8,
    anchor: SpecAnchor,
    reason: []const u8 = "",
};

/// Every method `handleMessage` dispatches, as the enum its dispatch switch is
/// written over. **This is the list, not a copy of it:** the switch is
/// exhaustive, so an arm cannot exist without a tag here and a tag cannot
/// exist without an arm — and the spec-anchor canary reads these tag names
/// instead of a hardcoded count, so a new dispatch arm without a matching
/// `spec_anchor_index` entry turns the suite RED.
///
/// (Re-audit 2026-08-11, F9: the canary used to compare `spec_anchor_index`
/// against the literals 14/8/6 and never read the dispatch chain at all, so it
/// only fired when someone edited the index itself — the one direction that
/// needs no guard. A method added to `handleMessage` was invisible to it,
/// proved by adding one and watching the suite stay green.)
pub const DispatchMethod = enum {
    @"notifications/initialized",
    initialize,
    @"tools/list",
    ping,
    @"tools/call",
    @"resources/list",
    @"resources/read",
    @"resources/templates/list",
    @"prompts/list",
    @"prompts/get",
    @"server/discover",
    @"subscriptions/listen",
    @"completion/complete",
    @"resources/subscribe",
    @"resources/unsubscribe",

    /// Whether a 2026-07-28 (stateless) request may call it. The handshake
    /// pair and `ping` were removed in that revision, so a modern request for
    /// one gets -32601; `server/discover` exists only there. Dispatch and the
    /// modern spec-anchor canary both read this, so a new method is either
    /// answered statelessly *and* anchored, or neither.
    pub fn servedStatelessly(self: DispatchMethod) bool {
        return switch (self) {
            // 2026-07-28 replaced resources/subscribe with subscriptions/listen.
            .initialize, .@"notifications/initialized", .ping, .@"resources/subscribe", .@"resources/unsubscribe" => false,
            .@"tools/list",
            .@"tools/call",
            .@"resources/list",
            .@"resources/read",
            .@"resources/templates/list",
            .@"prompts/list",
            .@"prompts/get",
            .@"server/discover",
            .@"subscriptions/listen",
            .@"completion/complete",
            => true,
        };
    }
};

/// Every method this server ORIGINATES (server→client request or
/// notification). The emitters below print `@tagName` of these rather than
/// their own string literal, so the wire name and this list are the same
/// bytes, and the canary reads it the same way it reads `DispatchMethod`.
pub const OriginatedMethod = enum {
    @"notifications/progress",
    @"notifications/cancelled",
    @"sampling/createMessage",
    @"elicitation/create",
    @"notifications/subscriptions/acknowledged",
    @"notifications/elicitation/complete",
    @"notifications/tools/list_changed",
    @"notifications/prompts/list_changed",
    @"notifications/resources/list_changed",
    @"notifications/resources/updated",

    pub fn wire(self: OriginatedMethod) []const u8 {
        return @tagName(self);
    }
};

/// Every JSON-RPC method this server dispatches or originates, classified per
/// `SpecAnchor`. This is the "nothing silently filtered" index: a method
/// added to (or removed from) `handleMessage`'s dispatch chain, or to the
/// server→client send surface, without a matching update here is a
/// classification bug, not just a missing test — and the canary test
/// ("mcp: spec-anchor classification …") enforces exactly that by checking
/// this index against `DispatchMethod` + `OriginatedMethod` in both
/// directions.
pub const spec_anchor_index = [_]MethodAnchor{
    .{ .method = "initialize", .anchor = .partial, .reason = "spec's lifecycle.mdx request (roots/sampling/elicitation/tasks capabilities, extended clientInfo) decodes verbatim; the response cannot be byte-identical because this server always advertises its own fixed, narrower capability set (no logging, no tasks, listChanged:false) -- a deliberate design choice (SPEC.md), not a gap" },
    .{ .method = "notifications/initialized", .anchor = .literal_example, .reason = "" },
    .{ .method = "ping", .anchor = .literal_example, .reason = "" },
    .{ .method = "tools/list", .anchor = .partial, .reason = "spec's tools.mdx request (with an illustrative pagination cursor, ignored while `page_size` is 0; pagination since 2026-10-20) decodes verbatim; the response is not compared: the spec's example Tool carries an `execution` field (tasks) this module does not produce. title/icons exist since 2026-09-30 and are compared value-for-value on the 2026-07-28 path (modern_spec_anchor_index)" },
    .{ .method = "tools/call", .anchor = .literal_example, .reason = "" },
    .{ .method = "resources/list", .anchor = .partial, .reason = "spec's resources.mdx request (with an illustrative pagination cursor, ignored while `page_size` is 0) decodes verbatim; the response is not compared against the 2025-11-25 example; title/icons exist since 2026-09-30 and the same Resource shape is compared value-for-value on the 2026-07-28 path (modern_spec_anchor_index)" },
    .{ .method = "resources/read", .anchor = .literal_example, .reason = "" },
    .{ .method = "resources/templates/list", .anchor = .partial, .reason = "spec's resources.mdx request (no params) decodes trivially; the response is not compared against the 2025-11-25 example; title/icons exist since 2026-09-30 and the same ResourceTemplate shape is compared value-for-value on the 2026-07-28 path (modern_spec_anchor_index)" },
    .{ .method = "prompts/list", .anchor = .partial, .reason = "spec's prompts.mdx request (with an illustrative pagination cursor, ignored while `page_size` is 0) decodes verbatim; the response is not compared against the 2025-11-25 example; title/icons exist since 2026-09-30 and the same Prompt shape is compared value-for-value on the 2026-07-28 path (modern_spec_anchor_index)" },
    .{ .method = "prompts/get", .anchor = .literal_example, .reason = "" },
    .{ .method = "server/discover", .anchor = .no_example, .reason = "stateless-only (2026-07-28): no session revision defines it, and a session-path request for it lacks the _meta version and is answered -32602. Its anchor is in modern_spec_anchor_index" },
    .{ .method = "subscriptions/listen", .anchor = .no_example, .reason = "stateless-only (2026-07-28): no session revision defines it (resources/subscribe and the GET stream were its predecessors, neither implemented here); a session-path request lacks the _meta version and is answered -32602. Its anchor is in modern_spec_anchor_index" },
    .{ .method = "notifications/subscriptions/acknowledged", .anchor = .no_example, .reason = "stateless-only: written only as the first message of a subscriptions/listen answer, and anchored with it in modern_spec_anchor_index" },
    .{ .method = "notifications/progress", .anchor = .literal_example, .reason = "" },
    .{ .method = "sampling/createMessage", .anchor = .literal_example, .reason = "" },
    .{ .method = "elicitation/create", .anchor = .literal_example, .reason = "" },
    .{ .method = "notifications/elicitation/complete", .anchor = .literal_example, .reason = "" },
    .{ .method = "completion/complete", .anchor = .literal_example, .reason = "" },
    .{ .method = "resources/subscribe", .anchor = .literal_example, .reason = "" },
    .{ .method = "resources/unsubscribe", .anchor = .no_example, .reason = "resources.mdx shows no unsubscribe example; the request is the subscribe one with the other method name (UnsubscribeRequest in the schema), answered {}" },
    .{ .method = "notifications/tools/list_changed", .anchor = .literal_example, .reason = "" },
    .{ .method = "notifications/prompts/list_changed", .anchor = .literal_example, .reason = "" },
    .{ .method = "notifications/resources/list_changed", .anchor = .literal_example, .reason = "" },
    .{ .method = "notifications/resources/updated", .anchor = .literal_example, .reason = "" },
    .{ .method = "notifications/cancelled", .anchor = .partial, .reason = "field order and `reason` text match the spec's cancellation.mdx example exactly; `requestId` is always a bare JSON integer (this server's own monotonic ids), where the spec's illustrative id happens to be a quoted string -- JSON-RPC ids may be either, so this is not a divergence. Inbound (since 2026-10-20): a client's notifications/cancelled marks its running tools/call (ToolCall.cancelled) and suppresses the response; one for a finished or unknown request is ignored, as the spec allows" },
};

/// The same "nothing silently filtered" index for the **stateless** path
/// (spec 2026-07-28): one entry per `DispatchMethod` that
/// `servedStatelessly`, anchored on that revision's own examples
/// (`schema/2026-07-28/examples/**` and the `docs/specification/2026-07-28`
/// pages). Its canary checks it against `servedStatelessly` both ways.
///
/// `.literal_example` here means **value-equal**, not byte-identical: the
/// response parses to the same JSON value as the spec's example, member order
/// aside (the spec's examples are pretty-printed in the author's order; ours
/// puts `resultType` first). `_meta` is dropped from our side only where the
/// example omits it (`serverInfo` is a SHOULD the examples skip); the
/// `server/discover` example carries it and is compared with it.
pub const modern_spec_anchor_index = [_]MethodAnchor{
    .{ .method = "server/discover", .anchor = .partial, .reason = "both the schema example and server/discover.mdx's example match value-for-value except supportedVersions: theirs is a modern-only server listing [\"2026-07-28\"], ours is dual-era and lists the session revisions too -- which basic/versioning.mdx's own UnsupportedProtocolVersionError example does" },
    .{ .method = "tools/list", .anchor = .partial, .reason = "value-equal to the schema example except nextCursor: the example's token is illustrative, ours is an opaque base64url position written only when `page_size` > 0 (pagination since 2026-10-20)" },
    .{ .method = "tools/call", .anchor = .literal_example, .reason = "" },
    .{ .method = "resources/list", .anchor = .partial, .reason = "value-equal to the schema example except nextCursor (an illustrative token there; ours is opaque, see tools/list)" },
    .{ .method = "resources/read", .anchor = .literal_example, .reason = "" },
    .{ .method = "resources/templates/list", .anchor = .literal_example, .reason = "" },
    .{ .method = "prompts/list", .anchor = .partial, .reason = "value-equal to the schema example except nextCursor (an illustrative token there; ours is opaque, see tools/list)" },
    .{ .method = "prompts/get", .anchor = .literal_example, .reason = "" },
    .{ .method = "completion/complete", .anchor = .literal_example, .reason = "" },
    .{ .method = "subscriptions/listen", .anchor = .partial, .reason = "the acknowledgment and the graceful-close response are value-equal to the schema examples (listen-acknowledged.json, listen-closed-response.json) except the acknowledged `notifications` filter: this server emits no change notification of any kind, so it honours none of the requested types, acknowledges `{}` (subscriptions.mdx: unsupported types are omitted) and ends the subscription at once with the completion result; the closing result also carries serverInfo, which the example omits" },
};

/// Everything `handleMessage`/`serve` can fail with. Malformed *input* never
/// surfaces here (it becomes a JSON-RPC error response); only allocation
/// failure, transport write failure, and -- from `serveStdio` only -- a
/// `std.Io` cancelation of the blocked read surface here. `handleMessage`,
/// `handleMessageFrom` and `serve` itself never produce `Canceled`; see
/// `serveStdio`'s doc comment for why only it can.
pub const Error = error{ OutOfMemory, WriteFailed, Canceled };

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
/// a string keeps its quotes); null/absent => `null`; a value that is not a
/// JSON-RPC identifier (array, object, bool, non-finite float) is also written
/// as `null`, never serialized. The message is properly JSON-escaped.
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
/// JSON-RPC 2.0 §4: a request `id` "MUST contain a String, Number, or NULL
/// value if included". `.number_string` is a Number that `std.json` left
/// unparsed (it appears when `parse_numbers` is off), so it counts. Everything
/// else — object, array, bool — is not an identifier.
///
/// A non-finite float (`1e999` parses to inf) has no JSON spelling, so it is
/// not an identifier either (no-panic sweep 2026-10-28 M-6).
fn conformingId(v: std.json.Value) bool {
    return switch (v) {
        .string, .integer, .number_string, .null => true,
        .float => |f| std.math.isFinite(f),
        .object, .array, .bool => false,
    };
}

/// Only an identifier shape is ever echoed: anything else (an array/object, a
/// non-finite float) is written as `null`, JSON-RPC 2.0 section 5's "id could
/// not be determined". Never a recursive serialization of a caller/peer Value.
fn writeId(w: *std.Io.Writer, id: ?std.json.Value) std.Io.Writer.Error!void {
    if (id) |v| if (conformingId(v)) return std.json.Stringify.value(v, .{}, w);
    try w.writeAll("null");
}

/// Deepest `[`/`{` nesting the module parses or re-serializes from JSON text a
/// peer controls: inbound messages, handler and tool output.
/// `std.json.Stringify` recurses once per level, so unbounded depth is a stack
/// overflow, and a deep parse costs heap per level. 128 is far above anything
/// MCP uses (the spec's deepest payloads nest < 10); deeper text is treated as
/// unparsable (-32700 inbound, -32603 for output).
pub const max_json_depth: usize = 128;

/// The same bound for literals the CALLER registers (tool schemas, `_meta`,
/// elicitation schemas): `schema_check`'s compile cap, so every schema it
/// compiles is also listable; deeper is treated as not JSON, as before.
pub const max_literal_depth: usize = schema_check.max_depth;

/// True when `text` nests at most `max_json_depth` arrays/objects.
pub fn jsonDepthOk(text: []const u8) bool {
    return jsonDepthWithin(text, max_json_depth);
}

fn literalDepthOk(text: []const u8) bool {
    return jsonDepthWithin(text, max_literal_depth);
}

/// True when `text` nests at most `limit` arrays/objects. String-aware
/// (brackets inside strings are ignored, backslash escapes honoured), O(n), no
/// allocation; it does not validate the JSON, the parser still does.
fn jsonDepthWithin(text: []const u8, limit: usize) bool {
    var depth: usize = 0;
    var in_str = false;
    var esc = false;
    for (text) |c| {
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '[', '{' => {
                depth += 1;
                if (depth > limit) return false;
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
    return true;
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
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"progressToken\":{s},\"progress\":{d},\"total\":{d},\"message\":",
            .{ OriginatedMethod.@"notifications/progress".wire(), self.token_json, progress, total },
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
    ///
    /// "Unparseable" is judged against the **shape the MCP spec defines**, not
    /// against "is there something here":
    ///   * every capability (`sampling`, `elicitation`, `roots`) is an OBJECT.
    ///     `{"sampling":true}`, `{"roots":"yes"}`, `{"elicitation":5}` are
    ///     malformed declarations and grant nothing.
    ///   * a sub-capability that the spec declares as an object
    ///     (`sampling.tools`, `sampling.context`, `elicitation.form`,
    ///     `elicitation.url`) must be an object, and one it declares as a flag
    ///     (`roots.listChanged`) must be a bool. A wrong-shaped sub-capability
    ///     fails the **whole** parent closed rather than being ignored: it means
    ///     we do not understand what the client declared, and the elicitation
    ///     case shows why guessing is dangerous — `{"elicitation":"url"}` used to
    ///     grant *form* (the phishing-relevant mode) and deny url, the exact
    ///     inverse of what the client tried to say.
    ///   * JSON `null` stays "absent" everywhere (see `present`), and
    ///     `listChanged:false` is a declaration of absence, not a grant.
    pub fn parse(caps_opt: ?std.json.Value) ClientCapabilities {
        var c: ClientCapabilities = .{};
        const caps = present(caps_opt) orelse return c;
        if (caps != .object) return c;

        if (present(caps.object.get("sampling"))) |s| grant: {
            if (s != .object) break :grant;
            const tools = objectSubCap(s.object, "tools");
            const context = objectSubCap(s.object, "context");
            if (tools == .malformed or context == .malformed) break :grant;
            c.sampling = true;
            c.sampling_tools = tools == .present;
            c.sampling_context = context == .present;
        }
        if (present(caps.object.get("elicitation"))) |e| grant: {
            if (e != .object) break :grant;
            const form = objectSubCap(e.object, "form");
            const url = objectSubCap(e.object, "url");
            if (form == .malformed or url == .malformed) break :grant;
            c.elicitation = true;
            // Spec backwards compatibility: `elicitation:{}` ≡ `{"form":{}}`.
            // Only an explicit url-only declaration turns form mode off.
            c.elicitation_form = form == .present or url != .present;
            c.elicitation_url = url == .present;
        }
        if (present(caps.object.get("roots"))) |r| grant: {
            if (r != .object) break :grant;
            const list_changed = boolSubCap(r.object, "listChanged");
            if (list_changed == .malformed) break :grant;
            c.roots = true;
            c.roots_list_changed = list_changed == .present;
        }
        return c;
    }
};

/// How a sub-capability was declared, for the fail-closed parse above.
const SubCap = enum { absent, present, malformed };

/// A sub-capability the spec spells as a nested capability object (`{}`).
fn objectSubCap(o: std.json.ObjectMap, key: []const u8) SubCap {
    const v = present(o.get(key)) orelse return .absent;
    return if (v == .object) .present else .malformed;
}

/// A sub-capability the spec spells as a boolean flag (`"listChanged": true`).
fn boolSubCap(o: std.json.ObjectMap, key: []const u8) SubCap {
    const v = present(o.get(key)) orelse return .absent;
    if (v != .bool) return .malformed;
    return if (v.bool) .present else .absent;
}

/// JSON `null` is "absent" for capability purposes — a declared-but-null
/// capability must not grant anything.
fn present(v: ?std.json.Value) ?std.json.Value {
    const x = v orelse return null;
    if (x == .null) return null;
    return x;
}

/// A client's self-identification from `initialize`'s `clientInfo`: `name`
/// and `version` (both spec-required) plus the optional `title` (a
/// human-readable display name, spec 2025-06-18+). Every field a `PeerState`
/// holds is a copy in `Server`-owned memory — see `dupe` — because the
/// `std.json.Value` this is parsed from lives on the per-message arena and
/// does not outlive `handleMessage`'s call.
pub const ClientInfo = struct {
    name: []const u8,
    version: []const u8,
    title: ?[]const u8 = null,

    /// Parse `clientInfo` from `initialize`'s params. Missing or malformed —
    /// not an object, or `name`/`version` absent or non-string — yields
    /// `null`. Per the MCP spec `clientInfo` is required, but this module
    /// treats an absent or malformed one the same way `ClientCapabilities`
    /// treats a malformed capability: **leniently**. `clientInfo` is
    /// self-reported metadata this module never gates a decision on (unlike
    /// `capabilities`, which is the sampling/elicitation permission gate), so
    /// there is nothing to fail closed *against* — a client that gets this
    /// wrong still gets to initialize. A present-but-non-string `title` is
    /// treated as absent rather than failing the whole `clientInfo`.
    fn parse(value: ?std.json.Value) ?ClientInfo {
        const v = present(value) orelse return null;
        if (v != .object) return null;
        const name_v = present(v.object.get("name")) orelse return null;
        const version_v = present(v.object.get("version")) orelse return null;
        if (name_v != .string or version_v != .string) return null;
        var title: ?[]const u8 = null;
        if (present(v.object.get("title"))) |t| {
            if (t == .string) title = t.string;
        }
        return .{ .name = name_v.string, .version = version_v.string, .title = title };
    }

    /// Copy `self` into memory owned by `gpa`, one allocation per field, each
    /// truncated to at most `max_len` bytes at a UTF-8 codepoint boundary
    /// (`truncateUtf8` — JSON strings are always valid UTF-8; an unsafe byte
    /// cut could hand back invalid UTF-8 in a `[]const u8` every other string
    /// in this module assumes is text). The bound exists because `name`/
    /// `version`/`title` are attacker-controlled and, unlike a JSON-RPC
    /// line's `max_line_len`, have no framing limit of their own — over-long
    /// fields are silently truncated, never a reason to refuse the
    /// handshake (see `parse`'s leniency note).
    fn dupe(self: ClientInfo, gpa: std.mem.Allocator, max_len: usize) error{OutOfMemory}!ClientInfo {
        const name = try gpa.dupe(u8, truncateUtf8(self.name, max_len));
        errdefer gpa.free(name);
        const version = try gpa.dupe(u8, truncateUtf8(self.version, max_len));
        errdefer gpa.free(version);
        return .{
            .name = name,
            .version = version,
            .title = if (self.title) |t| try gpa.dupe(u8, truncateUtf8(t, max_len)) else null,
        };
    }

    /// Release a copy made by `dupe`.
    fn free(self: ClientInfo, gpa: std.mem.Allocator) void {
        gpa.free(self.name);
        gpa.free(self.version);
        if (self.title) |t| gpa.free(t);
    }
};

/// `s[0..max_len]`, backed off so the cut never lands inside a multi-byte
/// UTF-8 sequence. `s` is a no-op (returned as-is) when it already fits, or
/// when it somehow fails UTF-8 validation (defensive only — a
/// `std.json.Value.string` is already validated by the parser).
fn truncateUtf8(s: []const u8, max_len: usize) []const u8 {
    if (s.len <= max_len) return s;
    const view = std.unicode.Utf8View.init(s) catch return s[0..max_len];
    var it = view.iterator();
    var end: usize = 0;
    while (it.nextCodepointSlice()) |cp| {
        const next_end = end + cp.len;
        if (next_end > max_len) break;
        end = next_end;
    }
    return s[0..end];
}

// ── the stateless (2026-07-28) request path ─────────────────────────────────

/// What a 2026-07-28 request declared about itself in `params._meta` — the
/// stateless stand-in for a peer's `initialize`. Built per request and never
/// stored: it lives on the per-message arena, so every slice in it (the
/// `client` strings included) is valid only for the handler call.
///
/// Nothing here reads or writes `PeerState`. The spec's rule is that a server
/// "MUST NOT rely on prior requests over the same connection to establish
/// context", and the converse holds too: a modern request must not move the
/// gate of a session that shares its peer handle.
pub const ModernRequest = struct {
    /// One of `modern_versions` — our static literal, not the request's slice.
    version: []const u8,
    /// `_meta` clientCapabilities, parsed with the same fail-closed rules as
    /// an `initialize` (`ClientCapabilities.parse`).
    capabilities: ClientCapabilities,
    /// `_meta` clientInfo (optional; SHOULD be sent). Lenient like the
    /// session path: missing or malformed is null, never a refusal.
    client: ?ClientInfo,
};

/// How one request asks to be served.
const Era = union(enum) {
    /// No `_meta` protocolVersion: the `initialize`-session path.
    legacy,
    modern: ModernRequest,
    /// Names a protocolVersion but breaks the per-request field rules — the
    /// spec's "malformed" (-32602). The payload is the error message.
    malformed: []const u8,
    /// A protocolVersion outside `modern_versions` (-32022). The payload is
    /// the requested version, echoed in `data.requested`.
    unsupported: []const u8,
};

/// Sort a request into its era (spec 2026-07-28, basic/versioning.mdx: "a
/// request carrying modern per-request `_meta` is served statelessly").
///
/// The **presence of the protocolVersion key** is the switch, and nothing
/// weaker: a session-era client already sends `_meta` (a `progressToken`), so
/// "has `_meta`" would misfile it. Once the key is there the request has opted
/// into the modern rules and is held to them — both required fields present
/// (clientCapabilities an object, as its schema type says), or -32602.
/// Presence is checked before the version so a request that is malformed *and*
/// names an unknown version is told the thing it can fix without a retry
/// loop.
fn classifyRequest(params_opt: ?std.json.Value) Era {
    const params = params_opt orelse return .legacy;
    if (params != .object) return .legacy;
    const meta_v = params.object.get("_meta") orelse return .legacy;
    if (meta_v != .object) return .legacy;
    const pv = meta_v.object.get(meta_key.protocol_version) orelse return .legacy;
    if (pv != .string) return .{ .malformed = "Invalid " ++ meta_key.protocol_version };
    const caps = meta_v.object.get(meta_key.client_capabilities) orelse
        return .{ .malformed = "Missing " ++ meta_key.client_capabilities };
    if (caps != .object) return .{ .malformed = "Invalid " ++ meta_key.client_capabilities };
    const version = for (modern_versions) |v| {
        if (eql(v, pv.string)) break v;
    } else return .{ .unsupported = pv.string };
    return .{ .modern = .{
        .version = version,
        .capabilities = ClientCapabilities.parse(caps),
        .client = ClientInfo.parse(meta_v.object.get(meta_key.client_info)),
    } };
}

/// `cacheScope` of a 2026-07-28 cacheable result (server/utilities/caching.mdx).
pub const CacheScope = enum { public, private };

/// The `ttlMs` + `cacheScope` hint a 2026-07-28 cacheable result MUST carry
/// (`server/discover`, the four list methods, `resources/read`).
///
/// The default — 0 ms, private — is exactly what a client assumes when the
/// hint is absent ("immediately stale", never shared across authorization
/// contexts), so a server that configures nothing promises nothing. Raise it
/// only for what really is stable, and use `.public` only for results that are
/// the same for every caller: a shared cache will serve a `.public` answer to
/// a different access token.
pub const CacheHint = struct {
    ttl_ms: u64 = 0,
    scope: CacheScope = .private,
};

/// One display icon for a tool, resource, template or prompt (spec
/// 2025-11-25+ `Icon`). `src` should be an `https:` or `data:` URI; the
/// spec makes the *client* reject anything else, this module passes it
/// through as registered.
pub const Icon = struct {
    src: []const u8,
    mime_type: ?[]const u8 = null,
    /// e.g. `"48x48"`, or `"any"` for a scalable format.
    sizes: []const []const u8 = &.{},
    theme: ?Theme = null,

    pub const Theme = enum { light, dark };
};

/// Tool behaviour hints (spec `ToolAnnotations`). Every field is optional and
/// omitted when null. They are **hints**: a client may use `read_only_hint`
/// to auto-approve a call, so set it only when it is true.
pub const ToolAnnotations = struct {
    title: ?[]const u8 = null,
    read_only_hint: ?bool = null,
    destructive_hint: ?bool = null,
    idempotent_hint: ?bool = null,
    open_world_hint: ?bool = null,
};

/// `title` + `icons` of a primitive, each omitted when unset.
fn writeTitleIcons(jw: *std.json.Stringify, title: ?[]const u8, icons: []const Icon) std.Io.Writer.Error!void {
    if (title) |t| {
        try jw.objectField("title");
        try jw.write(t);
    }
    if (icons.len == 0) return;
    try jw.objectField("icons");
    try jw.beginArray();
    for (icons) |icon| {
        try jw.beginObject();
        try jw.objectField("src");
        try jw.write(icon.src);
        if (icon.mime_type) |m| {
            try jw.objectField("mimeType");
            try jw.write(m);
        }
        if (icon.sizes.len != 0) {
            try jw.objectField("sizes");
            try jw.write(icon.sizes);
        }
        if (icon.theme) |th| {
            try jw.objectField("theme");
            try jw.write(@tagName(th));
        }
        try jw.endObject();
    }
    try jw.endArray();
}

fn writeToolAnnotations(jw: *std.json.Stringify, a: ToolAnnotations) std.Io.Writer.Error!void {
    try jw.objectField("annotations");
    try jw.beginObject();
    if (a.title) |t| {
        try jw.objectField("title");
        try jw.write(t);
    }
    const hints = [_]struct { []const u8, ?bool }{
        .{ "readOnlyHint", a.read_only_hint },
        .{ "destructiveHint", a.destructive_hint },
        .{ "idempotentHint", a.idempotent_hint },
        .{ "openWorldHint", a.open_world_hint },
    };
    for (hints) |h| {
        if (h[1]) |b| {
            try jw.objectField(h[0]);
            try jw.write(b);
        }
    }
    try jw.endObject();
}

/// The spec's `Implementation` for this server, as the 2026-07-28
/// `_meta.io.modelcontextprotocol/serverInfo` carries it: `name`, `version`,
/// and `title` only when one was set (the session path's `initialize` keeps
/// its own `title`-defaults-to-`name` shape).
fn writeImplementation(jw: *std.json.Stringify, info: *const Info) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("name");
    try jw.write(info.name);
    if (info.title) |t| {
        try jw.objectField("title");
        try jw.write(t);
    }
    try jw.objectField("version");
    try jw.write(info.version);
    try writeImplementationExtras(jw, info);
    try jw.endObject();
}

/// `Implementation`'s optional `description`, `websiteUrl` and `icons`, on
/// both the session `serverInfo` and the 2026-07-28 `_meta` one.
fn writeImplementationExtras(jw: *std.json.Stringify, info: *const Info) std.Io.Writer.Error!void {
    if (info.description) |d| {
        try jw.objectField("description");
        try jw.write(d);
    }
    if (info.website_url) |u| {
        try jw.objectField("websiteUrl");
        try jw.write(u);
    }
    if (info.icons.len != 0) try writeTitleIcons(jw, null, info.icons);
}

/// Open a result object: `{`, plus the `resultType` a 2026-07-28 result MUST
/// carry — `"complete"` here; the one other kind this module writes,
/// `"input_required"`, has its own builder (`buildInputRequiredResult`).
fn beginResult(jw: *std.json.Stringify, modern: bool) std.Io.Writer.Error!void {
    try jw.beginObject();
    if (modern) {
        try jw.objectField("resultType");
        try jw.write("complete");
    }
}

/// Close a result object. For a 2026-07-28 request it first adds
/// `_meta.io.modelcontextprotocol/serverInfo` (SHOULD, basic/index.mdx) and,
/// on a cacheable method, `ttlMs` + `cacheScope` (MUST, caching.mdx). A
/// session-path result gets neither, so its bytes do not change.
fn endResult(jw: *std.json.Stringify, info: *const Info, modern: bool, cache: ?CacheHint) std.Io.Writer.Error!void {
    if (modern) {
        try jw.objectField("_meta");
        try jw.beginObject();
        try jw.objectField(meta_key.server_info);
        try writeImplementation(jw, info);
        try jw.endObject();
        if (cache) |c| {
            try jw.objectField("ttlMs");
            try jw.write(c.ttl_ms);
            try jw.objectField("cacheScope");
            try jw.write(@tagName(c.scope));
        }
    }
    try jw.endObject();
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
    if (!literalDepthOk(schema_text)) return error.SchemaNotJson;
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
    // No length limit: the normalized name is scanned through a sliding window
    // exactly as long as the longest needle, so a name of ANY length is
    // searched in full without allocating. (Re-audit 2026-08-11, F8: this used
    // to normalize into a fixed `[128]u8` and `break` on overflow, so a
    // credential word past the 128th alphanumeric character — a 130-character
    // label ending in `password` — was never seen. An attacker-supplied field
    // name is exactly where a padded label costs nothing.)
    const window_len = comptime blk: {
        var longest: usize = 0;
        for (secret_needles) |needle| longest = @max(longest, needle.len);
        break :blk longest;
    };
    var win: [window_len]u8 = undefined;
    var n: usize = 0;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c)) continue;
        if (n == win.len) {
            std.mem.copyForwards(u8, win[0 .. win.len - 1], win[1..]);
            n -= 1;
        }
        win[n] = std.ascii.toLower(c);
        n += 1;
        const seen = win[0..n];
        for (secret_needles) |needle| {
            if (needle.len <= seen.len and std.mem.eql(u8, seen[seen.len - needle.len ..], needle)) return true;
        }
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
    InvalidTemperature,
    InvalidUrl,
    EmptyMessage,
    MissingElicitationId,
    /// The call arrived as a stateless 2026-07-28 request. That revision
    /// removed server→client requests — the multi round-trip pattern
    /// (`InputRequiredResult`) replaces them — so there is nothing to send
    /// one on, and a modern client would not recognise it.
    StatelessRequest,
} || SchemaError;

const Pending = struct {
    id: u64,
    kind: RequestKind,
    peer: u64,
    on_response: ?ResponseHandler,
    ctx: ?*anyopaque,
};

/// One peer's handshake state.
///
/// `initialize` is a **per-connection** act: the capabilities a client
/// declares, the revision it settled on and its lifecycle flag all belong to
/// the peer that sent them. Holding them as three fields on the `Server` made
/// them global, and a `Server` is deliberately shared — `mcp-http` serves
/// every session from one (`Transport.server`). So any party that could POST
/// could open a session, declare `elicitation`/`sampling`, and thereby lift
/// the gate for **every other session**: `elicitation/create` — the phishing
/// primitive this module documents at length — was then written to a client
/// that had declared nothing, in a revision it never negotiated. The same
/// handle in reverse: a session declaring `capabilities:{}` revoked everyone
/// else's. Peer scoping already existed for response *correlation*; the gate
/// is the other half of it.
pub const PeerState = struct {
    peer: u64,
    /// Set when this peer sends `notifications/initialized`.
    initialized: bool = false,
    /// What this peer advertised on its last `initialize`. All-false until
    /// one arrives, so the gate is closed before a handshake.
    capabilities: ClientCapabilities = .{},
    /// The revision this peer's `initialize` settled on. Defaults to our
    /// latest so a pre-handshake encoder picks the newest shape.
    negotiated_version: []const u8 = protocol_version,
    /// This peer's `initialize`.`clientInfo` — `name`/`version`/optional
    /// `title`, copied into `Server`-owned memory (see `ClientInfo.dupe`).
    /// Null before any `initialize`, or when the client's `clientInfo` was
    /// missing or malformed (see `ClientInfo.parse`; never fails the
    /// handshake). A re-`initialize` frees the old copy and replaces it
    /// wholesale, same as `capabilities`; `Server.forgetPeer` and
    /// `Server.deinit` free it too — see both for why a `PeerState` cannot
    /// just be dropped once this field is non-null.
    client: ?ClientInfo = null,
};

/// Whether a negotiated protocol revision knows elicitation *modes*. The
/// 2025-06-18 revision has no `mode` field at all (and no URL mode), so a
/// form-mode request to such a client omits it — which 2025-11-25 explicitly
/// blesses ("clients MUST treat requests without a `mode` field as form mode").
fn versionHasElicitationModes(version: []const u8) bool {
    return !eql(version, "2025-06-18");
}

/// The `host[:port]` of an RFC 3986 authority, with any `userinfo@` stripped.
const HostPort = struct {
    /// Case-preserved host. An IPv6 literal keeps its brackets (`[::1]`).
    host: []const u8,
    /// Digits only, `""` when no `:` was present.
    port: []const u8,
};
/// Split the part of a URL after `scheme://` into its authority's host and
/// port. Returns null when it is not a well-formed `[userinfo@]host[:port]`.
///
/// **Userinfo ends at the LAST `@` of the authority** (RFC 3986 §3.2.1: the
/// userinfo subcomponent may itself contain `@`-free characters only, so the
/// final `@` is the delimiter). This is the whole point of parsing rather than
/// prefix-matching: in `http://localhost:8080@evil.example/steal` the host is
/// `evil.example`, and `localhost:8080` is merely a username — a
/// prefix/first-delimiter check reads that as loopback and lets an arbitrary
/// plaintext-http host through.
///
/// The authority ends at the first `/`, `?`, `#` **or `\`**, so an `@` in the
/// *path* (`http://evil.example/@localhost`) cannot pull the host apart
/// either. The backslash is not RFC 3986 — it is the WHATWG URL Standard's
/// rule for *special* schemes, and it is in this set because the party that
/// finally opens the URL is the MCP **client**: a browser or a JS runtime,
/// every one of which parses by WHATWG. Under RFC 3986 alone the authority of
/// `http://evil.example\@localhost/` is `evil.example\@localhost`, whose last
/// `@` makes the host `localhost` — loopback, allowed — while the client that
/// opens it navigates to `http://evil.example/@localhost/`. Agreeing with the
/// parser that acts on the answer matters more here than agreeing with the RFC.
fn splitAuthority(after_scheme: []const u8) ?HostPort {
    const end = std.mem.findAny(u8, after_scheme, "/?#\\") orelse after_scheme.len;
    var authority = after_scheme[0..end];
    if (std.mem.findScalarLast(u8, authority, '@')) |at| authority = authority[at + 1 ..];

    var host = authority;
    var port: []const u8 = "";
    const bracketed = host.len != 0 and host[0] == '[';
    if (bracketed) {
        // IPv6 literal: the host ends at ']' and only ":port" may follow it.
        const close = std.mem.findScalar(u8, host, ']') orelse return null;
        const after = host[close + 1 ..];
        host = host[0 .. close + 1];
        if (after.len != 0) {
            if (after[0] != ':') return null;
            port = after[1..];
        }
    } else if (std.mem.findScalar(u8, host, ':')) |colon| {
        port = host[colon + 1 ..];
        host = host[0..colon];
    }
    if (host.len == 0) return null;
    // `port = *DIGIT` — anything else (a second ':', an '@' we somehow kept,
    // a hostname) means this is not the authority shape we think it is.
    for (port) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    // A bracket in a *registered-name* host is malformed (a bracketed literal
    // was consumed above and keeps exactly its own two).
    if (!bracketed and std.mem.findAny(u8, host, "[]") != null) return null;
    return .{ .host = host, .port = port };
}

/// Scheme check for a URL-mode elicitation: `https://` anywhere, or `http://`
/// only for loopback (the development case). This blocks `javascript:`,
/// `data:` and `file:` payloads reaching a client that is about to open them;
/// it says nothing about where an https URL points.
///
/// The loopback allowance compares the **parsed host** (see `splitAuthority`)
/// against the three loopback spellings, exactly — not a prefix, so neither
/// userinfo (`http://localhost:8080@evil.example/`) nor a longer name that
/// merely starts with one (`http://localhost.evil.example/`) is loopback.
fn isSafeElicitationUrl(url: []const u8) bool {
    if (std.ascii.startsWithIgnoreCase(url, "https://")) return url.len > "https://".len;
    if (std.ascii.startsWithIgnoreCase(url, "http://")) {
        const hp = splitAuthority(url["http://".len..]) orelse return false;
        for ([_][]const u8{ "localhost", "127.0.0.1", "[::1]" }) |host| {
            if (std.ascii.eqlIgnoreCase(hp.host, host)) return true;
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
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":", .{ id, OriginatedMethod.@"sampling/createMessage".wire() });
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
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":", .{ id, OriginatedMethod.@"elicitation/create".wire() });
    var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
    try writeElicitationParams(arena, &jw, req, emit_mode);
    try w.writeAll("}\n");
}

/// The `params` object of an `elicitation/create` — shared by the session
/// request line and a 2026-07-28 `inputRequests` entry.
fn writeElicitationParams(
    arena: std.mem.Allocator,
    jw: *std.json.Stringify,
    req: ElicitationRequest,
    emit_mode: bool,
) (std.Io.Writer.Error || error{SchemaNotJson})!void {
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
            writeRawJson(arena, jw, f.requested_schema) catch |err| switch (err) {
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
}

/// Everything a sampling or elicitation request can be refused for before it
/// goes anywhere — the capability gate plus the payload checks. Shared by the
/// session path (`Server.send*Request`) and the 2026-07-28 path
/// (`InputRound.ask`), so neither can drift from the other.
pub const RequestCheckError = error{
    SamplingNotSupported,
    ElicitationNotSupported,
    ElicitationFormNotSupported,
    ElicitationUrlNotSupported,
    NoMessages,
    InvalidMaxTokens,
    InvalidPriority,
    InvalidTemperature,
    InvalidUrl,
    EmptyMessage,
    MissingElicitationId,
} || SchemaError;

fn checkSamplingRequest(caps: ClientCapabilities, req: SamplingRequest) RequestCheckError!void {
    if (!caps.sampling) return error.SamplingNotSupported;
    if (req.messages.len == 0) return error.NoMessages;
    if (req.max_tokens == 0) return error.InvalidMaxTokens;
    if (req.model_preferences) |mp| {
        for ([_]?f64{ mp.cost_priority, mp.speed_priority, mp.intelligence_priority }) |p_opt| {
            const p = p_opt orelse continue;
            if (!(p >= 0.0) or !(p <= 1.0)) return error.InvalidPriority; // NaN too
        }
    }
    // `std.json.Stringify` writes +-inf bare (`inf`, not JSON) and NaN as a
    // string: either way the request line is not what the client expects
    // (review 2026-10-24).
    if (req.temperature) |t| if (!std.math.isFinite(t)) return error.InvalidTemperature;
}

fn checkElicitationRequest(arena: std.mem.Allocator, caps: ClientCapabilities, req: ElicitationRequest) RequestCheckError!void {
    if (!caps.elicitation) return error.ElicitationNotSupported;
    switch (req) {
        .form => |f| {
            if (!caps.elicitation_form) return error.ElicitationFormNotSupported;
            if (f.message.len == 0) return error.EmptyMessage;
            try validateElicitationSchema(arena, f.requested_schema);
        },
        .url => |u| {
            if (!caps.elicitation_url) return error.ElicitationUrlNotSupported;
            if (u.message.len == 0) return error.EmptyMessage;
            if (u.elicitation_id.len == 0) return error.MissingElicitationId;
            if (!isSafeElicitationUrl(u.url)) return error.InvalidUrl;
        },
    }
}

// ── multi round-trip requests (2026-07-28, basic/patterns/mrtr.mdx) ─────────
//
// The 2026-07-28 revision removed server→client requests. A `tools/call`,
// `prompts/get` or `resources/read` that needs something from the client —
// an LLM completion, user input — now *answers* with an `InputRequiredResult`
// (`resultType: "input_required"`) listing what it needs under keys it picks,
// and the client **retries the original request** with a new JSON-RPC id,
// carrying the answers under the same keys in `params.inputResponses` and the
// server's opaque `requestState` echoed verbatim.
//
// That is exactly the shape the session path could not offer: the handler
// runs to completion on every round, and the answer arrives as input to the
// next run, so a tool that needs a completion to produce its result is now
// one tool, not the "ask on this call, act on the next" pair the session API
// forces (see the server→client section above). Nothing is pending on the
// server between rounds — which is the revision's point: the retry may land
// on a different server instance.
//
// Each round is independent. The handler reads what it has (`response`,
// `elicitation`, `sampling`, `receivedState`), and either produces its normal
// result or asks again (`ask`, `setState`). Whatever it asked for wins: once
// any request or state is set, the response is an `InputRequiredResult` and
// the handler's normal output is discarded.
//
// **`requestState` comes back from the client and is attacker-controlled**
// (the spec's MUST). A handler that lets it influence authorization, resource
// access or business logic must protect it; `StateSeal` does that (HMAC over
// the state plus the request it belongs to, the principal and an expiry).

/// One entry of `InputRequiredResult.inputRequests`. `roots/list` (the third
/// kind the spec allows) is not offered: roots are deprecated in 2026-07-28 and
/// this module never implemented them on the session path either.
pub const InputRequest = union(enum) {
    sampling: SamplingRequest,
    elicitation: ElicitationRequest,
};

/// What `InputRound.ask`/`setState` can refuse.
pub const InputError = error{
    OutOfMemory,
    /// The request came in on the `initialize`-session path, which has no
    /// multi round-trip pattern — use `ToolCall.requestSampling`/
    /// `requestElicitation` there.
    SessionRequest,
    /// Keys are the client's only link between a request and its answer
    /// (mrtr.mdx: "MUST be unique within the scope of the request").
    EmptyInputKey,
    DuplicateInputKey,
    /// `setState("")`: an empty state cannot be told apart from none on retry.
    EmptyRequestState,
} || RequestCheckError;

/// The multi round-trip side of one 2026-07-28 `tools/call`, `prompts/get` or
/// `resources/read` — present on `ToolCall.input`, `PromptRequest.input` and
/// `ResourceRequest.input`.
///
/// **Received** (this round's retry, if it is one): `response`/`elicitation`/
/// `sampling` read `params.inputResponses`; `receivedState` is
/// `params.requestState`. Both are null on a first attempt, and always on the
/// session path (earlier revisions have neither field; a stray one is
/// ignored, not interpreted).
///
/// **Asked** (the next round): `ask` adds an `inputRequests` entry, `setState`
/// sets `requestState`. Either one turns this round's reply into an
/// `InputRequiredResult`. Everything is serialized when it is called, so the
/// request's strings need not outlive the call.
///
/// A client may omit an answer, send one the server did not ask for, or send a
/// malformed one. The spec's advice for a missing answer the handler needs is
/// to ask again rather than fail, which is what the typed accessors' `null`
/// makes natural: `if (call.input.elicitation("login")) |r| … else try
/// call.input.ask("login", …)`. The client is the user's agent, so an answer
/// that arrives unasked is no less trustworthy than one that was asked for —
/// the client could have accepted either way.
pub const InputRound = struct {
    /// Per-request arena; everything here dies with the response.
    arena: std.mem.Allocator = std.mem.Allocator.failing,
    /// Null on the session path: `ask`/`setState` refuse with
    /// `error.SessionRequest`, the accessors return null.
    modern: ?*const ModernRequest = null,
    /// The method this round belongs to (`tools/call`, …) and its target (the
    /// tool or prompt name, the resource uri) — what `StateSeal` binds a state
    /// to.
    method: []const u8 = "",
    target: []const u8 = "",
    /// `params.inputResponses` of this retry.
    responses: ?std.json.ObjectMap = null,
    /// `params.requestState` of this retry. Attacker-controlled.
    state_in: ?[]const u8 = null,

    /// Serialized `"key":{method,params}` members, comma-joined.
    requests_json: std.ArrayList(u8) = .empty,
    keys: std.ArrayList([]const u8) = .empty,
    state_out: ?[]const u8 = null,

    /// This retry's raw answer under `key`, or null.
    // secret-api-ok: `key` is a JSON object key (an input-request / argument name), not a secret
    pub fn response(self: *const InputRound, key: []const u8) ?std.json.Value {
        const r = self.responses orelse return null;
        return r.get(key);
    }

    /// The `ElicitResult` under `key`; null when absent or not decodable —
    /// ask again. A `decline`/`cancel` decodes: it is the user's answer.
    // secret-api-ok: `key` is a JSON object key (an input-request / argument name), not a secret
    pub fn elicitation(self: *const InputRound, key: []const u8) ?ElicitationResult {
        const v = self.response(key) orelse return null;
        return ElicitationResult.parse(v) catch null;
    }

    /// The `CreateMessageResult` under `key`; null when absent or not
    /// decodable (a tool-use content array included, as on the session path).
    // secret-api-ok: `key` is a JSON object key (an input-request / argument name), not a secret
    pub fn sampling(self: *const InputRound, key: []const u8) ?SamplingResult {
        const v = self.response(key) orelse return null;
        return SamplingResult.parse(v) catch null;
    }

    /// The `requestState` the client echoed, verbatim and **unverified**. Use
    /// `StateSeal.open` when the state carries anything the client must not
    /// be able to choose.
    pub fn receivedState(self: *const InputRound) ?[]const u8 {
        return self.state_in;
    }

    /// Ask the client for one more input before this request can finish.
    /// The same checks as the session path apply, against the capabilities
    /// this request's `_meta` declared (mrtr.mdx: a server "MUST NOT send an
    /// `inputRequests` that the client has not declared support for").
    // secret-api-ok: `key` is a JSON object key (an input-request / argument name), not a secret
    pub fn ask(self: *InputRound, key: []const u8, req: InputRequest) InputError!void {
        const modern = self.modern orelse return error.SessionRequest;
        if (key.len == 0) return error.EmptyInputKey;
        for (self.keys.items) |k| {
            if (eql(k, key)) return error.DuplicateInputKey;
        }
        switch (req) {
            .sampling => |s| try checkSamplingRequest(modern.capabilities, s),
            .elicitation => |e| try checkElicitationRequest(self.arena, modern.capabilities, e),
        }

        var aw: std.Io.Writer.Allocating = .init(self.arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        writeInputRequestMember(self.arena, &jw, key, req) catch |err| switch (err) {
            error.SchemaNotJson => return error.SchemaNotJson, // unreachable: validated above
            error.WriteFailed => return error.OutOfMemory,
        };
        const member = aw.written();
        // `jw` opened no object of its own, so the member is `"key":{…}`
        // without the separator the enclosing object would have written.
        if (self.requests_json.items.len != 0) try self.requests_json.append(self.arena, ',');
        try self.requests_json.appendSlice(self.arena, member);
        try self.keys.append(self.arena, try self.arena.dupe(u8, key));
    }

    /// Set the `requestState` the client must echo on its retry. Alone (no
    /// `ask`) it is the spec's load-shedding shape: "retry, and bring this".
    pub fn setState(self: *InputRound, state: []const u8) InputError!void {
        if (self.modern == null) return error.SessionRequest;
        if (state.len == 0) return error.EmptyRequestState;
        self.state_out = try self.arena.dupe(u8, state);
    }

    /// `StateSeal.seal` bound to this round's method and target, then
    /// `setState`.
    pub fn sealState(self: *InputRound, seal: *const StateSeal, payload: []const u8, opts: StateSeal.SealOptions) InputError!void {
        if (self.modern == null) return error.SessionRequest;
        const token = try seal.seal(self.arena, self.binding(opts.principal), payload, opts.now_sec, opts.ttl_sec);
        try self.setState(token);
    }

    /// `StateSeal.open` on the received state, bound to this round's method
    /// and target. Null when there is no received state; an error when there
    /// is one and it fails verification — the spec's "MUST reject".
    pub fn openState(self: *const InputRound, seal: *const StateSeal, principal: []const u8, now_sec: i64) StateSeal.OpenError!?[]const u8 {
        const token = self.state_in orelse return null;
        return try seal.open(self.arena, self.binding(principal), token, now_sec);
    }

    fn binding(self: *const InputRound, principal: []const u8) StateSeal.Binding {
        return .{ .method = self.method, .target = self.target, .principal = principal };
    }

    /// Forget everything asked so far (a declining resource template).
    fn resetAsked(self: *InputRound) void {
        self.requests_json.clearRetainingCapacity();
        self.keys.clearRetainingCapacity();
        self.state_out = null;
    }

    /// Whether this round's reply is an `InputRequiredResult`.
    pub fn inputRequired(self: *const InputRound) bool {
        return self.keys.items.len != 0 or self.state_out != null;
    }

    /// Read `inputResponses`/`requestState` from a 2026-07-28 request's params.
    /// A wrong type is the caller's -32602 (mrtr.mdx "Error Handling": a
    /// malformed `InputResponses` is a protocol error).
    fn fromParams(
        arena: std.mem.Allocator,
        modern: ?*const ModernRequest,
        method: []const u8,
        target: []const u8,
        params: std.json.ObjectMap,
    ) error{ InvalidInputResponses, InvalidRequestState }!InputRound {
        var r: InputRound = .{ .arena = arena, .modern = modern, .method = method, .target = target };
        if (modern == null) return r;
        if (present(params.get("inputResponses"))) |v| {
            if (v != .object) return error.InvalidInputResponses;
            r.responses = v.object;
        }
        if (present(params.get("requestState"))) |v| {
            if (v != .string) return error.InvalidRequestState;
            r.state_in = v.string;
        }
        return r;
    }
};

/// One `"key":{"method":…,"params":…}` member of `inputRequests`, in the
/// member order of the spec's `InputRequests` example.
fn writeInputRequestMember(arena: std.mem.Allocator, jw: *std.json.Stringify, key: []const u8, req: InputRequest) (std.Io.Writer.Error || error{SchemaNotJson})!void {
    // A bare member: `jw` must not add the comma of an enclosing object, so
    // write the key through the raw writer.
    try std.json.Stringify.encodeJsonString(key, .{}, jw.writer);
    try jw.writer.writeByte(':');
    try jw.beginObject();
    try jw.objectField("method");
    switch (req) {
        .sampling => |s| {
            try jw.write(OriginatedMethod.@"sampling/createMessage".wire());
            try jw.objectField("params");
            try writeSamplingParams(jw, s);
        },
        .elicitation => |e| {
            try jw.write(OriginatedMethod.@"elicitation/create".wire());
            try jw.objectField("params");
            // 2026-07-28 knows modes, so form mode names itself.
            try writeElicitationParams(arena, jw, e, true);
        },
    }
    try jw.endObject();
}

/// Serialize one `InputRequiredResult` (`resultType` first, like every
/// 2026-07-28 result this module writes).
fn buildInputRequiredResult(jw: *std.json.Stringify, round: *const InputRound, info: *const Info) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("resultType");
    try jw.write("input_required");
    if (round.keys.items.len != 0) {
        try jw.objectField("inputRequests");
        // The members were serialized by `ask`; splice them in verbatim.
        try jw.beginWriteRaw();
        try jw.writer.writeByte('{');
        try jw.writer.writeAll(round.requests_json.items);
        try jw.writer.writeByte('}');
        jw.endWriteRaw();
    }
    if (round.state_out) |st| {
        try jw.objectField("requestState");
        try jw.write(st);
    }
    try endResult(jw, info, true, null);
}

/// Integrity protection for `requestState` (mrtr.mdx, server requirements 4–5):
/// HMAC-SHA-256 over the state **and** what it may be used for — the method,
/// its target (tool/prompt name, resource uri), the authenticated principal,
/// an expiry and any caller-chosen `extra` (e.g. a digest of the arguments
/// that matter) — so a state is refused if it is altered, presented late,
/// presented by a different principal, or replayed onto a different request.
/// Only the expiry and the payload travel; the rest is recomputed on `open`.
///
/// The payload is **not encrypted**: the client can read it. Put nothing in
/// it the client must not see. As the spec warns, this bounds replay but does
/// not make a state single-use; a one-time redemption needs server-side
/// bookkeeping.
///
/// Token: `base64url-nopad( 0x01 ‖ expiry:u64be ‖ mac[32] ‖ payload )`.
/// This module reads no clock — `now_sec` is the caller's.
pub const StateSeal = struct {
    /// Keep it secret, 32 random bytes; every instance that may receive a
    /// retry needs the same key.
    key: [32]u8,

    pub const version: u8 = 1;
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    const header_len = 1 + 8 + Hmac.mac_length;

    pub const Binding = struct {
        method: []const u8,
        target: []const u8,
        principal: []const u8 = "",
        extra: []const u8 = "",
    };

    pub const SealOptions = struct {
        now_sec: i64,
        /// The spec asks for "a short expiry".
        ttl_sec: u32 = 600,
        principal: []const u8 = "",
    };

    pub const OpenError = error{
        OutOfMemory,
        /// Not a token this seal produced: bad encoding, wrong version, a
        /// MAC that does not verify (altered, or bound to another
        /// method/target/principal/extra — indistinguishable by design).
        StateInvalid,
        /// Verified, but presented at or after its expiry.
        StateExpired,
    };

    pub fn seal(self: *const StateSeal, arena: std.mem.Allocator, b: Binding, payload: []const u8, now_sec: i64, ttl_sec: u32) error{OutOfMemory}![]const u8 {
        // Saturating: `now_sec` near maxInt(i64) must not overflow (UB in
        // ReleaseFast); the sum is >= 0, so the bit cast is the value.
        const expiry: u64 = @bitCast(@max(@as(i64, 0), now_sec) +| @as(i64, ttl_sec));
        // A field the MAC cannot length-prefix (>= 4 GiB) cannot be sealed.
        if (payload.len > std.math.maxInt(u32) or b.method.len > std.math.maxInt(u32) or
            b.target.len > std.math.maxInt(u32) or b.principal.len > std.math.maxInt(u32) or
            b.extra.len > std.math.maxInt(u32)) return error.OutOfMemory;
        const raw = try arena.alloc(u8, header_len + payload.len);
        raw[0] = version;
        std.mem.writeInt(u64, raw[1..9], expiry, .big);
        @memcpy(raw[header_len..], payload);
        self.mac(raw[9..header_len], b, raw[0..9], payload);
        const enc = std.base64.url_safe_no_pad.Encoder;
        const out = try arena.alloc(u8, enc.calcSize(raw.len));
        return enc.encode(out, raw);
    }

    /// Verify `token` against `b` and return its payload (arena-owned).
    /// The MAC is checked before the expiry, so an attacker learns nothing
    /// from the difference.
    pub fn open(self: *const StateSeal, arena: std.mem.Allocator, b: Binding, token: []const u8, now_sec: i64) OpenError![]const u8 {
        const dec = std.base64.url_safe_no_pad.Decoder;
        const n = dec.calcSizeForSlice(token) catch return error.StateInvalid;
        if (n < header_len) return error.StateInvalid;
        const raw = try arena.alloc(u8, n);
        dec.decode(raw, token) catch return error.StateInvalid;
        if (raw[0] != version) return error.StateInvalid;
        var want: [Hmac.mac_length]u8 = undefined;
        // A field >= 4 GiB is never one this seal produced.
        if (raw.len > std.math.maxInt(u32) or b.method.len > std.math.maxInt(u32) or
            b.target.len > std.math.maxInt(u32) or b.principal.len > std.math.maxInt(u32) or
            b.extra.len > std.math.maxInt(u32)) return error.StateInvalid;
        self.mac(&want, b, raw[0..9], raw[header_len..]);
        if (!std.crypto.timing_safe.eql([Hmac.mac_length]u8, want, raw[9..header_len].*)) return error.StateInvalid;
        const expiry = std.mem.readInt(u64, raw[1..9], .big);
        if (now_sec < 0 or @as(u64, @intCast(now_sec)) >= expiry) return error.StateExpired;
        return raw[header_len..];
    }

    fn mac(self: *const StateSeal, out: *[Hmac.mac_length]u8, b: Binding, head: *const [9]u8, payload: []const u8) void {
        var h = Hmac.init(&self.key);
        h.update("mcp-request-state");
        h.update(head);
        // Length-prefixed, so no two different bindings share an encoding.
        for ([_][]const u8{ b.method, b.target, b.principal, b.extra, payload }) |field| {
            var len: [4]u8 = undefined;
            // seal/open refuse a field this long before calling (checked there).
            std.mem.writeInt(u32, &len, @truncate(field.len), .big);
            h.update(&len);
            h.update(field);
        }
        h.final(out);
    }
};

// ── tool registration ───────────────────────────────────────────────────────

/// The four paginated list methods (spec server/utilities/pagination.mdx).
const ListKind = enum {
    tools,
    resources,
    templates,
    prompts,

    fn tag(self: ListKind) u8 {
        return switch (self) {
            .tools => 't',
            .resources => 'r',
            .templates => 'u',
            .prompts => 'p',
        };
    }

    fn buildFailure(self: ListKind) []const u8 {
        return switch (self) {
            .tools => "failed to build tools/list",
            .resources => "failed to build resources/list",
            .templates => "failed to build resources/templates/list",
            .prompts => "failed to build prompts/list",
        };
    }

    /// The opaque cursor for "the page starting at entry `start`":
    /// base64url-nopad of `<tag>:<start>`, so one list's cursor is refused by
    /// another. A position, not a snapshot: a catalog that grows or shrinks
    /// between pages shifts what the next page starts with (the spec leaves
    /// cursor stability to the server).
    fn cursor(self: ListKind, arena: std.mem.Allocator, start: usize) ![]const u8 {
        const raw = try arena.print("{c}:{d}", .{ self.tag(), start });
        const enc = std.base64.url_safe_no_pad.Encoder;
        const buf = try arena.alloc(u8, enc.calcSize(raw.len));
        return enc.encode(buf, raw);
    }

    /// The start index a cursor names, or null when it is not one this list
    /// minted (or names a position past the end).
    fn decodeCursor(self: ListKind, text: []const u8, len: usize) ?usize {
        if (text.len == 0 or text.len > 32) return null;
        var buf: [24]u8 = undefined;
        const dec = std.base64.url_safe_no_pad.Decoder;
        const n = dec.calcSizeForSlice(text) catch return null;
        if (n > buf.len or n < 3) return null;
        dec.decode(buf[0..n], text) catch return null;
        const raw = buf[0..n];
        if (raw[0] != self.tag() or raw[1] != ':') return null;
        const digits = raw[2..];
        // Canonical decimal only: no sign, no leading zero, so each position
        // has exactly one cursor.
        if (digits.len > 1 and digits[0] == '0') return null;
        for (digits) |d| if (d < '0' or d > '9') return null;
        const start = std.fmt.parseInt(usize, digits, 10) catch return null;
        if (start > len) return null;
        return start;
    }
};

/// A tool's schemas, parsed and compiled once at `addTool` (on an arena the
/// `Server` owns) so `tools/call` does not re-parse them. A schema that is not
/// JSON, or is outside `schema_check`'s subset, leaves its slot null: that
/// side is not checked (`tools/list` still answers -32603 for non-JSON text).
const ToolCheck = struct {
    arena: *std.heap.ArenaAllocator,
    input: ?schema_check.Schema,
    output: ?schema_check.Schema,
    /// The schemas as `tools/list` writes them -- the literal parsed and
    /// re-serialized -- computed once here instead of on every list (that
    /// re-parse was 95 % of a 20-tool `tools/list`, 2026-10-24). Null when the
    /// literal is not JSON: `buildToolsList` then parses it as before and
    /// fails where it always did.
    input_json: ?[]const u8,
    output_json: ?[]const u8,

    fn init(gpa: std.mem.Allocator, tool: Tool) error{OutOfMemory}!ToolCheck {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = .init(gpa);
        errdefer {
            arena.deinit();
            gpa.destroy(arena);
        }
        return .{
            .arena = arena,
            .input = try compileText(arena.allocator(), tool.input_schema),
            .output = try compileText(arena.allocator(), tool.output_schema),
            .input_json = try canonicalText(arena.allocator(), tool.input_schema),
            .output_json = try canonicalText(arena.allocator(), tool.output_schema),
        };
    }

    /// `writeRawJson`'s bytes for `text`, or null when `text` is empty or not JSON.
    fn canonicalText(arena: std.mem.Allocator, text: []const u8) error{OutOfMemory}!?[]const u8 {
        if (text.len == 0 or !literalDepthOk(text)) return null;
        const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        return try std.json.Stringify.valueAlloc(arena, v, .{});
    }

    fn deinit(self: ToolCheck, gpa: std.mem.Allocator) void {
        self.arena.deinit();
        gpa.destroy(self.arena);
    }

    fn compileText(arena: std.mem.Allocator, text: []const u8) error{OutOfMemory}!?schema_check.Schema {
        if (text.len == 0 or !literalDepthOk(text)) return null;
        const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        return schema_check.Schema.compile(arena, v) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
    }
};

/// Why a successful result breaks the tool's `output_schema`, or null when it
/// conforms. A tool that declares one MUST return conforming structured
/// content (tools.mdx "Output Schema"), so output that is not JSON at all is a
/// failure too, not a quiet text-only result. On the session path
/// `structuredContent` is an object; a 2026-07-28 call takes any JSON value.
fn outputFailure(arena: std.mem.Allocator, schema: *const schema_check.Schema, text: []const u8, modern: bool) error{OutOfMemory}!?[]const u8 {
    if (!jsonDepthOk(text)) return "Output validation error: the tool declares an outputSchema but its output is not JSON";
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return "Output validation error: the tool declares an outputSchema but its output is not JSON",
    };
    if (v != .object and !modern) return "Output validation error: the tool declares an outputSchema but its output is not a JSON object";
    const f = (try schema.validate(arena, v)) orelse return null;
    // Output too large to check within the step budget is the server's own
    // result, not a client's attack: it passes unchecked rather than turning a
    // correct tool into a failing one (review 2026-10-20 M4).
    if (std.mem.eql(u8, f.keyword, "budget")) return null;
    return try arena.print("Output validation error: {s}{s}{s}", .{ f.pointer, if (f.pointer.len != 0) ": " else "", f.message });
}

const Inflight = struct {
    peer: u64,
    /// The request id as compact JSON (`7`, `"abc"`), arena-owned by the call.
    id_json: []const u8,
    flag: *std.atomic.Value(bool),
};

/// What `ToolCall.arg` found for one argument: nothing (absent or JSON
/// `null`), a value of the requested type, or a value of another JSON type —
/// the case a handler reports as "'x' must be a string", not "missing 'x'".
pub fn Arg(comptime T: type) type {
    return union(enum) {
        absent,
        value: T,
        wrong_type,
    };
}

/// A JSON-RPC error a handler answers with instead of its result — the
/// protocol-level failure TS's `ProtocolError` and Python's `MCPError` carry,
/// as opposed to a tool's `isError:true` result (a failure the model reads).
/// `data_json` is JSON text spliced in as `error.data` ("" = no `data`); text
/// that is not one JSON value turns the answer into -32603 rather than a line
/// no client can parse. Set it with `fail*` on the request; it wins over both
/// the normal result and any `input.ask` of the same round.
pub const ProtocolError = struct {
    code: i32,
    message: []const u8,
    data_json: []const u8 = "",
    /// When set, `data_json` is the value of this one member of `data` rather
    /// than `data` itself (`missingClientCapability` uses it).
    wrap_data: []const u8 = "",

    /// `URLElicitationRequiredError` (-32042, spec 2025-11-25 client/
    /// elicitation.mdx): the request cannot proceed until each listed URL-mode
    /// elicitation completes; the client may retry after
    /// `notifications/elicitation/complete` (`Server.sendElicitationComplete`).
    /// Session path only — 2026-07-28 removed it (MRTR's `input.ask` replaces
    /// it), so a stateless call is refused with `error.StatelessRequest`. Each
    /// entry is checked as `requestElicitation` checks a `.url` one (the
    /// client's `elicitation.url` capability, an `elicitation_id`, a safe URL),
    /// and the list may not be empty (the spec's MUST).
    pub fn urlElicitationRequired(
        arena: std.mem.Allocator,
        caps: ClientCapabilities,
        modern: bool,
        message: []const u8,
        elicitations: []const ElicitationRequest.Url,
    ) SendError!ProtocolError {
        if (modern) return error.StatelessRequest;
        if (elicitations.len == 0) return error.NoMessages;
        for (elicitations) |u| try checkElicitationRequest(arena, caps, .{ .url = u });
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField("elicitations") catch return error.OutOfMemory;
        jw.beginArray() catch return error.OutOfMemory;
        for (elicitations) |u| writeUrlElicitation(&jw, u) catch return error.OutOfMemory;
        jw.endArray() catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
        return .{ .code = error_code.url_elicitation_required, .message = message, .data_json = aw.written() };
    }

    /// `MissingRequiredClientCapabilityError` (-32021, spec 2026-07-28): the
    /// request needs client capabilities its `_meta` did not declare.
    /// `required_json` is the `ClientCapabilities` object the server needs,
    /// e.g. `{"elicitation":{}}`.
    pub fn missingClientCapability(message: []const u8, required_json: []const u8) ProtocolError {
        return .{ .code = error_code.missing_required_client_capability, .message = message, .data_json = required_json, .wrap_data = "requiredCapabilities" };
    }
};

fn writeUrlElicitation(jw: *std.json.Stringify, u: ElicitationRequest.Url) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("mode");
    try jw.write("url");
    try jw.objectField("elicitationId");
    try jw.write(u.elicitation_id);
    try jw.objectField("url");
    try jw.write(u.url);
    try jw.objectField("message");
    try jw.write(u.message);
    try jw.endObject();
}

/// Answer `id` with a handler's `ProtocolError`.
fn sendProtocolError(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, pe: ProtocolError) Error!void {
    if (pe.data_json.len == 0) return sendError(arena, out, id, pe.code, pe.message);
    if (!isSingleJsonValue(arena, pe.data_json)) {
        return sendError(arena, out, id, error_code.internal_error, "Handler error data is not JSON");
    }
    var aw: std.Io.Writer.Allocating = .init(arena);
    buildProtocolErrorLine(&aw.writer, id, pe) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

fn buildProtocolErrorLine(w: *std.Io.Writer, id: ?std.json.Value, pe: ProtocolError) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.print(",\"error\":{{\"code\":{d},\"message\":", .{pe.code});
    try std.json.Stringify.encodeJsonString(pe.message, .{}, w);
    try w.writeAll(",\"data\":");
    if (pe.wrap_data.len != 0) {
        try w.writeByte('{');
        try std.json.Stringify.encodeJsonString(pe.wrap_data, .{}, w);
        try w.writeByte(':');
    }
    try writeStrippingNewlines(w, pe.data_json);
    if (pe.wrap_data.len != 0) try w.writeByte('}');
    try w.writeAll("}}\n");
}

fn requestCaps(server: ?*Server, peer: u64, modern: ?*const ModernRequest) ClientCapabilities {
    if (modern) |r| return r.capabilities;
    const s = server orelse return .{};
    return s.clientCapabilities(peer);
}

/// The `params._meta` object of a request (`.null` when absent or not an
/// object), and the progress reporter its `progressToken` opts into.
fn requestMeta(params: std.json.ObjectMap) std.json.Value {
    const m = params.get("_meta") orelse return .null;
    return if (m == .object) m else .null;
}

fn progressFrom(arena: std.mem.Allocator, out: *std.Io.Writer, req_meta: std.json.Value) ?Progress {
    // MCP progress: a `params._meta.progressToken` opts the request into
    // server→client `notifications/progress`. Serialize the token verbatim
    // (string or number) so the reporter can echo it on every notification.
    if (req_meta != .object) return null;
    const token = req_meta.object.get("progressToken") orelse return null;
    if (token != .string and token != .integer) return null;
    const token_json = std.json.Stringify.valueAlloc(arena, token, .{}) catch return null;
    return Progress{ .out = out, .token_json = token_json };
}

fn argTypeName(comptime T: type) []const u8 {
    return switch (T) {
        []const u8 => "a string",
        i64 => "an integer",
        f64 => "a number",
        bool => "a boolean",
        else => @compileError("mcp: arg type must be []const u8, i64, f64 or bool, not " ++ @typeName(T)),
    };
}

fn lookupArg(comptime T: type, args: std.json.Value, key: []const u8) Arg(T) {
    _ = argTypeName(T);
    if (args != .object) return .absent;
    const v = args.object.get(key) orelse return .absent;
    if (v == .null) return .absent;
    switch (T) {
        []const u8 => if (v == .string) return .{ .value = v.string },
        bool => if (v == .bool) return .{ .value = v.bool },
        i64 => switch (v) {
            .integer => |i| return .{ .value = i },
            // `5.0` is an integer to JSON Schema; the bounds are the f64s
            // nearest to i64's range that are inside it.
            .float => |f| if (@floor(f) == f and f >= -9.223372036854775808e18 and f < 9.223372036854775808e18)
                return .{ .value = @intFromFloat(f) },
            else => {},
        },
        f64 => switch (v) {
            .integer => |i| return .{ .value = @floatFromInt(i) },
            .float => |f| return .{ .value = f },
            // std.json keeps an integer too long for i64 as its digits.
            .number_string => |s| return .{ .value = std.fmt.parseFloat(f64, s) catch return .wrong_type },
            else => {},
        },
        else => unreachable,
    }
    return .wrong_type;
}

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
    /// Set when this call arrived as a stateless 2026-07-28 request: what its
    /// `_meta` declared. Null = an `initialize`-session call. Arena lifetime.
    modern: ?*const ModernRequest = null,
    /// The multi round-trip side of a 2026-07-28 call: the answers this retry
    /// carries, and `ask`/`setState` for the next round. Asking anything turns
    /// the reply into an `InputRequiredResult`; the text written to `out` and
    /// the handler's return value are then discarded.
    input: InputRound = .{},
    /// Set by `failWith`/`failProtocol`: answer with this JSON-RPC error
    /// instead of a tool result.
    protocol_error: ?ProtocolError = null,
    /// The request's raw `params._meta` object (`.null` when absent).
    meta: std.json.Value = .null,
    /// Content blocks after the text one (see `add`).
    blocks: std.ArrayList(Content) = .empty,
    /// Set (from any thread) when the client cancels this call; see
    /// `cancelled`.
    cancel_flag: std.atomic.Value(bool) = .init(false),

    /// Whether the client has cancelled this call (`notifications/cancelled`,
    /// or the transport via `Server.cancelInflight`). A long tool polls it and
    /// stops early; whatever it returns is then discarded — a cancelled
    /// request gets no response (basic/utilities/cancellation.mdx). Only a
    /// transport that reads while a handler runs can deliver the cancel in
    /// time: `serve` reads one line at a time, so on stdio a cancel arrives
    /// after the call has finished and is ignored, as the spec allows.
    pub fn cancelled(self: *const ToolCall) bool {
        return self.cancel_flag.load(.acquire);
    }

    /// Append a content block to the result (image, audio, a resource link,
    /// an embedded resource, or a text block with annotations). The text
    /// written with `write`/`print` stays the first block — and still feeds
    /// `structuredContent` — unless it is empty and blocks were added, then
    /// the result is the blocks alone. OOM is swallowed, as for `write`.
    pub fn add(self: *ToolCall, c: Content) void {
        self.blocks.append(self.arena, c) catch {};
    }

    /// `add(.{ .image = ... })` from raw bytes (base64-encoded here).
    pub fn addImage(self: *ToolCall, bytes: []const u8, mime_type: []const u8) void {
        const b64 = base64Alloc(self.arena, bytes) orelse return;
        self.add(.{ .image = .{ .data_base64 = b64, .mime_type = mime_type } });
    }

    /// `add(.{ .audio = ... })` from raw bytes (base64-encoded here).
    pub fn addAudio(self: *ToolCall, bytes: []const u8, mime_type: []const u8) void {
        const b64 = base64Alloc(self.arena, bytes) orelse return;
        self.add(.{ .audio = .{ .data_base64 = b64, .mime_type = mime_type } });
    }

    /// Answer this call with a JSON-RPC error rather than a tool result (a
    /// protocol failure, not a tool failure the model should read). Returns
    /// `true` so a handler can `return call.failWith(...)`.
    pub fn failWith(self: *ToolCall, pe: ProtocolError) bool {
        self.protocol_error = pe;
        return true;
    }

    /// `failWith(.{ .code = code, .message = message, .data_json = data_json })`.
    pub fn failProtocol(self: *ToolCall, code: i32, msg: []const u8, data_json: []const u8) bool {
        return self.failWith(.{ .code = code, .message = msg, .data_json = data_json });
    }

    /// Answer with `URLElicitationRequiredError` (-32042) listing
    /// `elicitations` — see `ProtocolError.urlElicitationRequired`, checked
    /// against this call's client capabilities and era.
    pub fn urlElicitationRequired(self: *ToolCall, msg: []const u8, elicitations: []const ElicitationRequest.Url) SendError!bool {
        return self.failWith(try ProtocolError.urlElicitationRequired(self.arena, self.clientCapabilities(), self.modern != null, msg, elicitations));
    }

    /// Ask the client's LLM for a completion, from inside a tool call.
    ///
    /// **This does not wait.** The request goes out now; the client's answer
    /// arrives later, as a separate message, and lands in
    /// `opts.on_response` — long after this tool call has returned its result.
    /// A tool that needs the completion to produce its answer must be modelled
    /// as two calls (ask now, act on the next call). There is no way around
    /// that: the answer cannot arrive while this handler owns the loop.
    ///
    /// On a 2026-07-28 call this refuses with `error.StatelessRequest`; that
    /// revision asks through `input.ask` instead, and there the answer does
    /// arrive within the same tool (on the client's retry).
    pub fn requestSampling(self: *ToolCall, req: SamplingRequest, opts: RequestOptions) SendError!u64 {
        if (self.modern != null) return error.StatelessRequest;
        var o = opts;
        o.peer = self.peer; // the answer can only come from the caller
        return self.server.sendSamplingRequest(self.transport, req, o);
    }

    /// Ask the client to collect user input, from inside a tool call. Same
    /// non-waiting contract as `requestSampling`.
    pub fn requestElicitation(self: *ToolCall, req: ElicitationRequest, opts: RequestOptions) SendError!u64 {
        if (self.modern != null) return error.StatelessRequest;
        var o = opts;
        o.peer = self.peer;
        return self.server.sendElicitationRequest(self.transport, req, o);
    }

    /// What the client declared — in this request's `_meta` for a 2026-07-28
    /// call, at `initialize` otherwise. Check this before offering a feature
    /// that depends on sampling or elicitation, rather than issuing a request
    /// and handling the refusal.
    pub fn clientCapabilities(self: *const ToolCall) ClientCapabilities {
        if (self.modern) |r| return r.capabilities;
        return self.server.clientCapabilities(self.peer);
    }

    /// What the calling client self-identified as — this request's `_meta`
    /// clientInfo for a 2026-07-28 call (valid for this call only), its
    /// `initialize` otherwise (see `Server.clientInfo`). Null if it sent no
    /// well-formed one.
    pub fn clientInfo(self: *const ToolCall) ?ClientInfo {
        if (self.modern) |r| return r.client;
        return self.server.clientInfo(self.peer);
    }

    /// The protocol revision this call is served under: the request's own
    /// for a 2026-07-28 call, the peer's negotiated one otherwise.
    pub fn protocolVersion(self: *const ToolCall) []const u8 {
        if (self.modern) |r| return r.version;
        return self.server.negotiatedVersion(self.peer);
    }

    /// Append raw bytes to the result. OOM is swallowed (a truncated tool
    /// result surfaces to the agent as malformed output, never as a crash).
    pub fn write(self: *ToolCall, bytes: []const u8) void {
        self.out.appendSlice(self.arena, bytes) catch {};
    }

    /// Append formatted text to the result (same OOM policy as `write`).
    pub fn print(self: *ToolCall, comptime fmt: []const u8, args: anytype) void {
        const text = self.arena.print(fmt, args) catch return;
        self.out.appendSlice(self.arena, text) catch {};
    }

    /// Fetch a required/optional string argument, or null when absent or not
    /// a string.
    // secret-api-ok: `key` is a JSON object key (an input-request / argument name), not a secret
    pub fn strArg(self: *const ToolCall, key: []const u8) ?[]const u8 {
        if (self.args != .object) return null;
        return switch (self.args.object.get(key) orelse return null) {
            .string => |s| s,
            else => null,
        };
    }

    /// Look up argument `key` as a `T` — `[]const u8`, `i64`, `f64` or
    /// `bool` — telling an absent argument apart from one of the wrong JSON
    /// type, which `strArg` folds together. A JSON `null` is absent (the spec's
    /// optional arguments are commonly sent as null). `i64` takes an integral
    /// number in range (`5.0` too, as JSON Schema's `integer` does); `f64`
    /// takes any number.
    // secret-api-ok: `key` is a JSON object key (an argument name), not a secret
    pub fn arg(self: *const ToolCall, comptime T: type, key: []const u8) Arg(T) {
        return lookupArg(T, self.args, key);
    }

    /// `arg([]const u8, key)` (kept for symmetry with `strArg`).
    // secret-api-ok: `key` is a JSON object key (an argument name), not a secret
    pub fn strArgChecked(self: *const ToolCall, key: []const u8) Arg([]const u8) {
        return lookupArg([]const u8, self.args, key);
    }

    /// A required argument of type `T`, or null after writing the tool
    /// failure — "missing '<key>'" or "'<key>' must be <a string|an integer|
    /// a number|a boolean>" — so a handler reads
    /// `const cfg = call.require([]const u8, "config") orelse return true;`.
    // secret-api-ok: `key` is a JSON object key (an argument name), not a secret
    pub fn require(self: *ToolCall, comptime T: type, key: []const u8) ?T {
        switch (lookupArg(T, self.args, key)) {
            .value => |v| return v,
            .absent => self.print("error: missing '{s}'", .{key}),
            .wrong_type => self.print("error: '{s}' must be {s}", .{ key, argTypeName(T) }),
        }
        return null;
    }

    /// `require([]const u8, key)`.
    // secret-api-ok: `key` is a JSON object key (an argument name), not a secret
    pub fn requireStr(self: *ToolCall, key: []const u8) ?[]const u8 {
        return self.require([]const u8, key);
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
///
/// `title`, `icons` and `annotations` are display metadata, emitted in
/// `tools/list` when set and omitted otherwise.
///
/// On a 2026-07-28 call `structuredContent` may be any JSON value, not just an
/// object (tools.mdx "Structured Content"). This module takes that wider
/// reading only for a tool that declares an `output_schema`: for one that does
/// not, a bare `42` or `"ok"` in the output is far more likely text than a
/// structured result, so it stays text-only, as on the session path.
pub const Tool = struct {
    name: []const u8,
    description: []const u8,
    input_schema: []const u8,
    output_schema: []const u8 = "",
    allow_structured: bool = true,
    title: ?[]const u8 = null,
    icons: []const Icon = &.{},
    annotations: ?ToolAnnotations = null,
    /// The definition's `_meta`, as JSON **object** text ("" = none) — where
    /// extensions put their keys, e.g. MCP Apps' `{"ui":{"resourceUri":
    /// "ui://…"}}`. Text that is not one JSON object makes the list that
    /// carries it answer -32603, like an invalid `input_schema`.
    meta_json: []const u8 = "",
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
    /// The caching hint a 2026-07-28 read answers with. Starts as
    /// `Server.read_cache`; a handler that knows better (a per-user document
    /// is `.private`, a static file may live longer) overwrites it. Ignored
    /// on the session path, which has no caching fields.
    cache: CacheHint = .{},
    /// Multi round-trip (2026-07-28): see `InputRound` and `ToolCall.input`.
    /// A template handler that declines (`false`) has its asks discarded with
    /// its contents; any other handler that asked gets an
    /// `InputRequiredResult`, whatever it returned.
    input: InputRound = .{},
    /// Request context (filled by the dispatcher; the same as `ToolCall`'s):
    /// the progress reporter (null unless the client sent a progressToken),
    /// the server and peer the request came from, the stateless request's
    /// `_meta` declarations (null on the session path) and the request's raw
    /// `params._meta` (`.null` when absent).
    progress: ?Progress = null,
    server: ?*Server = null,
    peer: u64 = 0,
    modern: ?*const ModernRequest = null,
    meta: std.json.Value = .null,
    /// Set by `failWith`/`failProtocol`: answer with this JSON-RPC error.
    protocol_error: ?ProtocolError = null,
    /// For a template read: the template's variables matched out of `uri`
    /// (RFC 6570, percent-decoded, arena lifetime), or null when the uri does
    /// not match the template — or the template is not matchable — and the
    /// handler has to judge `uri` itself, as before matching existed. A
    /// handler that serves only its template's uris starts with
    /// `const vars = req.vars orelse return false;`. Null for a static resource.
    vars: ?[]const uri_template.Var = null,

    /// The string value of template variable `name` (see `vars`), or null.
    pub fn variable(self: *const ResourceRequest, name: []const u8) ?[]const u8 {
        for (self.vars orelse return null) |v| {
            if (std.mem.eql(u8, v.name, name)) return switch (v.value) {
                .string => |s| s,
                .list => null,
            };
        }
        return null;
    }

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

    /// What the client declared (see `ToolCall.clientCapabilities`).
    pub fn clientCapabilities(self: *const ResourceRequest) ClientCapabilities {
        return requestCaps(self.server, self.peer, self.modern);
    }

    /// What the client self-identified as (see `ToolCall.clientInfo`).
    pub fn clientInfo(self: *const ResourceRequest) ?ClientInfo {
        if (self.modern) |r| return r.client;
        const s = self.server orelse return null;
        return s.clientInfo(self.peer);
    }

    /// The protocol revision this request is served under.
    pub fn protocolVersion(self: *const ResourceRequest) []const u8 {
        if (self.modern) |r| return r.version;
        const s = self.server orelse return protocol_version;
        return s.negotiatedVersion(self.peer);
    }

    /// Emit one `notifications/progress` — a no-op without a progressToken.
    pub fn reportProgress(self: *const ResourceRequest, progress: u64, total: u64, msg: []const u8) void {
        if (self.progress) |p| p.report(progress, total, msg);
    }

    /// Answer with a JSON-RPC error instead of the result (see
    /// `ProtocolError`); returns `true`, which a resource handler's caller
    /// reads as "mine" — no further template is tried.
    pub fn failWith(self: *ResourceRequest, pe: ProtocolError) bool {
        self.protocol_error = pe;
        return true;
    }

    /// `failWith(.{ .code = code, .message = message, .data_json = data_json })`.
    pub fn failProtocol(self: *ResourceRequest, code: i32, msg: []const u8, data_json: []const u8) bool {
        return self.failWith(.{ .code = code, .message = msg, .data_json = data_json });
    }

    /// Answer with `URLElicitationRequiredError` (-32042); see
    /// `ProtocolError.urlElicitationRequired`.
    pub fn urlElicitationRequired(self: *ResourceRequest, msg: []const u8, elicitations: []const ElicitationRequest.Url) SendError!bool {
        return self.failWith(try ProtocolError.urlElicitationRequired(self.arena, self.clientCapabilities(), self.modern != null, msg, elicitations));
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
    title: ?[]const u8 = null,
    icons: []const Icon = &.{},
    annotations: ?Annotations = null,
    /// Size of the raw content in bytes, when known (before base64).
    size: ?u64 = null,
    /// `_meta` as JSON object text ("" = none); see `Tool.meta_json`.
    meta_json: []const u8 = "",
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
    title: ?[]const u8 = null,
    icons: []const Icon = &.{},
    annotations: ?Annotations = null,
    /// `_meta` as JSON object text ("" = none); see `Tool.meta_json`.
    meta_json: []const u8 = "",
    /// Completes this template's variables (`completion/complete` with a
    /// `ref/resource` naming this `uri_template`).
    completer: ?Completer = null,
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
    /// Multi round-trip (2026-07-28): see `InputRound` and `ToolCall.input`.
    /// Asking anything turns the reply into an `InputRequiredResult`, whatever
    /// the handler returns.
    input: InputRound = .{},
    /// Request context (filled by the dispatcher; the same as `ToolCall`'s):
    /// the progress reporter (null unless the client sent a progressToken),
    /// the server and peer the request came from, the stateless request's
    /// `_meta` declarations (null on the session path) and the request's raw
    /// `params._meta` (`.null` when absent).
    progress: ?Progress = null,
    server: ?*Server = null,
    peer: u64 = 0,
    modern: ?*const ModernRequest = null,
    meta: std.json.Value = .null,
    /// Set by `failWith`/`failProtocol`: answer with this JSON-RPC error.
    protocol_error: ?ProtocolError = null,

    /// MCP prompt message roles — the same `Role` the sampling surface uses
    /// (aliased so both spell it the way the spec does).
    pub const Role = RoleAlias;

    const Message = struct {
        role: RoleAlias,
        content: Content,
    };

    /// Fetch a string argument, or null when absent or not a string.
    // secret-api-ok: `key` is a JSON object key (an input-request / argument name), not a secret
    pub fn strArg(self: *const PromptRequest, key: []const u8) ?[]const u8 {
        if (self.args != .object) return null;
        return switch (self.args.object.get(key) orelse return null) {
            .string => |s| s,
            else => null,
        };
    }

    /// `strArg` that tells an absent argument from a non-string one (prompt
    /// arguments are strings on the wire, so there is no other `T`).
    // secret-api-ok: `key` is a JSON object key (an argument name), not a secret
    pub fn strArgChecked(self: *const PromptRequest, key: []const u8) Arg([]const u8) {
        return lookupArg([]const u8, self.args, key);
    }

    /// Append one text message to the rendered prompt (OOM swallowed — same
    /// policy as `ToolCall.write`).
    pub fn message(self: *PromptRequest, role: RoleAlias, msg_text: []const u8) void {
        self.messages.append(self.arena, .{ .role = role, .content = .{ .text = .{ .text = msg_text } } }) catch {};
    }

    /// Append one message carrying any content block (an image, an embedded
    /// resource, …); same OOM policy as `message`.
    pub fn messageContent(self: *PromptRequest, role: RoleAlias, content: Content) void {
        self.messages.append(self.arena, .{ .role = role, .content = content }) catch {};
    }

    /// Append one formatted text message (same OOM policy as `message`).
    pub fn printMessage(self: *PromptRequest, role: RoleAlias, comptime fmt: []const u8, fmt_args: anytype) void {
        const rendered = self.arena.print(fmt, fmt_args) catch return;
        self.message(role, rendered);
    }

    /// What the client declared (see `ToolCall.clientCapabilities`).
    pub fn clientCapabilities(self: *const PromptRequest) ClientCapabilities {
        return requestCaps(self.server, self.peer, self.modern);
    }

    /// What the client self-identified as (see `ToolCall.clientInfo`).
    pub fn clientInfo(self: *const PromptRequest) ?ClientInfo {
        if (self.modern) |r| return r.client;
        const s = self.server orelse return null;
        return s.clientInfo(self.peer);
    }

    /// The protocol revision this request is served under.
    pub fn protocolVersion(self: *const PromptRequest) []const u8 {
        if (self.modern) |r| return r.version;
        const s = self.server orelse return protocol_version;
        return s.negotiatedVersion(self.peer);
    }

    /// Emit one `notifications/progress` — a no-op without a progressToken.
    pub fn reportProgress(self: *const PromptRequest, progress: u64, total: u64, msg: []const u8) void {
        if (self.progress) |p| p.report(progress, total, msg);
    }

    /// Answer with a JSON-RPC error instead of the result (see
    /// `ProtocolError`); returns `true`, which a resource handler's caller
    /// reads as "mine" — no further template is tried.
    pub fn failWith(self: *PromptRequest, pe: ProtocolError) bool {
        self.protocol_error = pe;
        return true;
    }

    /// `failWith(.{ .code = code, .message = message, .data_json = data_json })`.
    pub fn failProtocol(self: *PromptRequest, code: i32, msg: []const u8, data_json: []const u8) bool {
        return self.failWith(.{ .code = code, .message = msg, .data_json = data_json });
    }

    /// Answer with `URLElicitationRequiredError` (-32042); see
    /// `ProtocolError.urlElicitationRequired`.
    pub fn urlElicitationRequired(self: *PromptRequest, msg: []const u8, elicitations: []const ElicitationRequest.Url) SendError!bool {
        return self.failWith(try ProtocolError.urlElicitationRequired(self.arena, self.clientCapabilities(), self.modern != null, msg, elicitations));
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
    title: ?[]const u8 = null,
    icons: []const Icon = &.{},
    /// `_meta` as JSON object text ("" = none); see `Tool.meta_json`.
    meta_json: []const u8 = "",
    /// Completes this prompt's arguments (`completion/complete`).
    completer: ?Completer = null,
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
    /// Spec `Implementation` extras (2025-11-25+), omitted when unset.
    description: ?[]const u8 = null,
    website_url: ?[]const u8 = null,
    icons: []const Icon = &.{},
};

/// Spec `Annotations` on a resource, template or content block: hints for
/// the client, every field omitted when unset. `priority` is 0..1 (1 = most
/// important); `last_modified` an ISO 8601 timestamp.
pub const Annotations = struct {
    audience: []const RoleAlias = &.{},
    priority: ?f64 = null,
    last_modified: ?[]const u8 = null,
};

fn writeAnnotations(jw: *std.json.Stringify, a: Annotations) std.Io.Writer.Error!void {
    if (a.audience.len == 0 and a.priority == null and a.last_modified == null) return;
    try jw.objectField("annotations");
    try jw.beginObject();
    if (a.audience.len != 0) {
        try jw.objectField("audience");
        try jw.beginArray();
        for (a.audience) |r| try jw.write(@tagName(r));
        try jw.endArray();
    }
    // NaN / inf have no JSON spelling: omitted rather than written as an
    // invalid line (no-panic sweep 2026-10-28 M-10).
    if (a.priority) |pr| if (std.math.isFinite(pr)) {
        try jw.objectField("priority");
        try jw.write(pr);
    };
    if (a.last_modified) |lm| {
        try jw.objectField("lastModified");
        try jw.write(lm);
    }
    try jw.endObject();
}

/// A request or notification method this module does not define — a vendor
/// method (`acme/search`) or an extension's (`skills/list` of
/// `io.modelcontextprotocol/skills`) — registered with `Server.addMethod` /
/// `addNotification`. Without it such a request is -32601 and such a
/// notification is dropped (TS `setRequestHandler`, Python
/// `add_request_handler`). `stateless`/`session` say which era may call it.
pub const Method = struct {
    name: []const u8,
    handler: MethodHandler,
    ctx: ?*anyopaque = null,
    /// Callable by a 2026-07-28 (stateless) request.
    stateless: bool = true,
    /// Callable on an `initialize` session.
    session: bool = true,
};

/// A request handler writes the result **object** (JSON text, e.g.
/// `{"items":[]}`) with `req.write`/`print` — `{}` when it writes nothing —
/// and returns `true`; `false` answers -32603. A 2026-07-28 answer gets
/// `resultType` and `_meta.serverInfo` added. A notification handler's
/// output and return value are ignored (nothing is ever written back).
pub const MethodHandler = *const fn (ctx: ?*anyopaque, req: *MethodRequest) bool;

/// Everything a `Method` handler gets: `params` (`.null` when absent), the
/// per-request arena, the request context `ToolCall` has, and the result
/// accumulator.
pub const MethodRequest = struct {
    arena: std.mem.Allocator,
    /// The method name as received (lets one handler serve several).
    method: []const u8,
    params: std.json.Value,
    out: *std.ArrayList(u8),
    /// True for a notification: there is no response to write.
    notification: bool = false,
    progress: ?Progress = null,
    server: ?*Server = null,
    peer: u64 = 0,
    modern: ?*const ModernRequest = null,
    meta: std.json.Value = .null,
    protocol_error: ?ProtocolError = null,

    /// Append raw result-object text (OOM swallowed; a truncated object turns
    /// into -32603, never a malformed line).
    pub fn write(self: *MethodRequest, bytes: []const u8) void {
        self.out.appendSlice(self.arena, bytes) catch {};
    }

    /// Append formatted result-object text.
    pub fn print(self: *MethodRequest, comptime fmt: []const u8, args: anytype) void {
        const text = self.arena.print(fmt, args) catch return;
        self.out.appendSlice(self.arena, text) catch {};
    }

    /// What the client declared (see `ToolCall.clientCapabilities`).
    pub fn clientCapabilities(self: *const MethodRequest) ClientCapabilities {
        return requestCaps(self.server, self.peer, self.modern);
    }

    /// Emit one `notifications/progress` — a no-op without a progressToken.
    pub fn reportProgress(self: *const MethodRequest, progress: u64, total: u64, msg: []const u8) void {
        if (self.progress) |p| p.report(progress, total, msg);
    }

    /// Answer with a JSON-RPC error instead of the result.
    pub fn failWith(self: *MethodRequest, pe: ProtocolError) bool {
        self.protocol_error = pe;
        return true;
    }

    /// `failWith(.{ .code = code, .message = message, .data_json = data_json })`.
    pub fn failProtocol(self: *MethodRequest, code: i32, msg: []const u8, data_json: []const u8) bool {
        return self.failWith(.{ .code = code, .message = msg, .data_json = data_json });
    }
};

/// Argument autocompletion for a prompt argument or a resource-template
/// variable (`completion/complete`, server/utilities/completion.mdx). The
/// handler `add`s candidate values for `argument` given its partial `value`
/// (and the arguments already chosen, `context_arguments`); the server sends
/// the first 100 and sets `hasMore` when more were added or `has_more` says so.
pub const Completer = *const fn (ctx: ?*anyopaque, req: *CompletionRequest) void;

pub const CompletionRequest = struct {
    arena: std.mem.Allocator,
    /// The prompt argument or template variable being completed.
    argument: []const u8,
    /// What the user has typed so far.
    value: []const u8,
    /// `params.context.arguments` — earlier choices (`.null` when absent).
    context_arguments: std.json.Value = .null,
    values: std.ArrayList([]const u8) = .empty,
    /// The total number of matches, when known (omitted when null).
    total: ?u64 = null,
    /// Set when there are more matches than were added.
    has_more: bool = false,
    server: ?*Server = null,
    peer: u64 = 0,
    modern: ?*const ModernRequest = null,

    /// Add one candidate (OOM swallowed).
    pub fn add(self: *CompletionRequest, v: []const u8) void {
        self.values.append(self.arena, v) catch {};
    }

    /// A string from `context_arguments`, or null.
    pub fn contextArg(self: *const CompletionRequest, name: []const u8) ?[]const u8 {
        if (self.context_arguments != .object) return null;
        const v = self.context_arguments.object.get(name) orelse return null;
        return if (v == .string) v.string else null;
    }
};

/// Which catalog changed, for `Server.notifyListChanged`.
pub const ListChange = enum { tools, prompts, resources };

/// Where push notifications go: the transport's writer for `peer`, or null
/// when that peer has no open channel now (it is then skipped). On stdio
/// that is stdout for peer 0; under `mcp-http` the peer's open stream.
/// Writes happen inside the `notify*` call, so call them under the same
/// lock as `handleMessage` (one `Server` = one owner).
pub const PushSink = struct {
    ctx: ?*anyopaque = null,
    writerFor: *const fn (ctx: ?*anyopaque, peer: u64) ?*std.Io.Writer,
};

/// Subscriptions one peer may hold, each kind (resources/subscribe uris;
/// open subscriptions/listen streams) — a client that never unsubscribes
/// must not grow the tables without bound.
pub const max_subscriptions_per_peer = 1024;
/// Longest uri a subscription may name.
pub const max_subscription_uri_len = 8192;
/// Uri bytes one `subscriptions/listen` filter may carry in all.
pub const max_listen_uri_bytes = 256 * 1024;
/// Open listens and session subscriptions over every peer — the per-peer caps
/// do not bound a transport with many peers (review 2026-10-20 M5).
pub const max_listens = 4096;
pub const max_session_subscriptions = 65536;

const SessionSub = struct { peer: u64, uri: []u8 };

/// One open 2026-07-28 `subscriptions/listen`: its id (the subscription id)
/// and the filter the server agreed to honour. Memory on `Server.gpa`.
const Listen = struct {
    peer: u64,
    id_json: []u8,
    tools: bool,
    prompts: bool,
    resources: bool,
    uris: [][]u8,

    fn free(self: Listen, gpa: std.mem.Allocator) void {
        for (self.uris) |u| gpa.free(u);
        gpa.free(self.uris);
        gpa.free(self.id_json);
    }

    fn wants(self: Listen, change: ListChange) bool {
        return switch (change) {
            .tools => self.tools,
            .prompts => self.prompts,
            .resources => self.resources,
        };
    }
};

/// The most values one completion answer carries (completion.mdx).
pub const max_completion_values = 100;

/// One content block of a tool result or prompt message (spec
/// `ContentBlock`, server/tools.mdx "Tool Result"). Binary data is passed
/// **already base64-encoded** (`ToolCall.addImage`/`addAudio` encode raw
/// bytes for you); every optional field is omitted when unset.
pub const Content = union(enum) {
    text: Text,
    image: Media,
    audio: Media,
    resource_link: ResourceLink,
    resource: Embedded,

    pub const Text = struct {
        text: []const u8,
        annotations: ?Annotations = null,
    };
    pub const Media = struct {
        data_base64: []const u8,
        mime_type: []const u8,
        annotations: ?Annotations = null,
    };
    /// A pointer to a resource the client may read or subscribe to; it need
    /// not appear in `resources/list` (tools.mdx).
    pub const ResourceLink = struct {
        uri: []const u8,
        name: []const u8,
        title: ?[]const u8 = null,
        description: ?[]const u8 = null,
        mime_type: ?[]const u8 = null,
        size: ?u64 = null,
        annotations: ?Annotations = null,
    };
    /// A resource's contents inline: exactly one of `text` / `blob_base64`.
    pub const Embedded = struct {
        uri: []const u8,
        mime_type: ?[]const u8 = null,
        text: ?[]const u8 = null,
        blob_base64: ?[]const u8 = null,
        annotations: ?Annotations = null,
    };
};

fn writeContent(jw: *std.json.Stringify, c: Content) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("type");
    try jw.write(@tagName(c));
    switch (c) {
        .text => |x| {
            try jw.objectField("text");
            try jw.write(x.text);
            if (x.annotations) |a| try writeAnnotations(jw, a);
        },
        .image, .audio => |x| {
            try jw.objectField("data");
            try jw.write(x.data_base64);
            try jw.objectField("mimeType");
            try jw.write(x.mime_type);
            if (x.annotations) |a| try writeAnnotations(jw, a);
        },
        .resource_link => |x| {
            try jw.objectField("uri");
            try jw.write(x.uri);
            try jw.objectField("name");
            try jw.write(x.name);
            if (x.title) |v| {
                try jw.objectField("title");
                try jw.write(v);
            }
            if (x.description) |v| {
                try jw.objectField("description");
                try jw.write(v);
            }
            if (x.mime_type) |v| {
                try jw.objectField("mimeType");
                try jw.write(v);
            }
            if (x.size) |v| {
                try jw.objectField("size");
                try jw.write(v);
            }
            if (x.annotations) |a| try writeAnnotations(jw, a);
        },
        .resource => |x| {
            try jw.objectField("resource");
            try jw.beginObject();
            try jw.objectField("uri");
            try jw.write(x.uri);
            if (x.mime_type) |v| {
                try jw.objectField("mimeType");
                try jw.write(v);
            }
            if (x.text) |v| {
                try jw.objectField("text");
                try jw.write(v);
            } else {
                try jw.objectField("blob");
                try jw.write(x.blob_base64 orelse "");
            }
            if (x.annotations) |a| try writeAnnotations(jw, a);
            try jw.endObject();
        },
    }
    try jw.endObject();
}

fn base64Alloc(arena: std.mem.Allocator, bytes: []const u8) ?[]const u8 {
    const enc = std.base64.standard.Encoder;
    const buf = arena.alloc(u8, enc.calcSize(bytes.len)) catch return null;
    return enc.encode(buf, bytes);
}

/// Emit a definition's `_meta` (see `Tool.meta_json`); refuses text that is
/// not one JSON object.
fn writeMetaField(arena: std.mem.Allocator, jw: *std.json.Stringify, meta_json: []const u8) !void {
    if (meta_json.len == 0) return;
    if (!literalDepthOk(meta_json)) return error.InvalidMeta;
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, meta_json, .{});
    if (v != .object) return error.InvalidMeta;
    try jw.objectField("_meta");
    try jw.write(v);
}

// ── server ──────────────────────────────────────────────────────────────────

pub const Server = struct {
    gpa: std.mem.Allocator,
    info: Info,
    tools: std.ArrayList(Tool) = .empty,
    resources: std.ArrayList(Resource) = .empty,
    resource_templates: std.ArrayList(ResourceTemplate) = .empty,
    prompts: std.ArrayList(Prompt) = .empty,
    /// Per-peer handshake state, one entry per peer that has handshaken.
    /// See `PeerState` for why this is not three fields on the `Server`.
    peers: std.ArrayList(PeerState) = .empty,
    /// Cap on remembered peers. A transport that multiplexes sessions must
    /// call `forgetPeer` when one ends; this bounds the damage when it does
    /// not, and past it an `initialize` from an unknown peer is refused
    /// rather than served.
    max_peers: usize = 4096,
    /// Cap, in bytes, on each field of a peer's recorded `clientInfo`
    /// (`name`, `version`, `title`) — see `ClientInfo.dupe`. An over-long
    /// field is truncated (at a UTF-8 boundary), never a reason to reject
    /// the handshake.
    max_client_info_field_len: usize = 256,
    /// Outbound (server→client) requests awaiting the client's response.
    pending: std.ArrayList(Pending) = .empty,
    /// Next server→client request id. Monotonic and **never reused**: an id is
    /// burnt when it is allocated, even if the send then fails, so a late
    /// answer can never be matched to a different request.
    next_request_id: u64 = 1,
    /// Caching hint on the 2026-07-28 `server/discover` and list results
    /// (`tools/list`, `resources/list`, `resources/templates/list`,
    /// `prompts/list`). See `CacheHint` for why the default caches nothing.
    list_cache: CacheHint = .{},
    /// Entries per page of the four list methods; 0 (the default) = the whole
    /// catalog in one answer, never a `nextCursor`. See `handleList`.
    page_size: usize = 0,
    /// Check `tools/call` arguments against each tool's `input_schema`, and a
    /// successful structured result against its `output_schema`, before
    /// either crosses (TS and Python SDKs do both). A failure is a tool result
    /// with `isError:true` naming the offending location. Only schemas inside
    /// `schema_check`'s subset are checked; a tool whose schema uses anything
    /// else (`patternProperties`, `$anchor`, …) runs unchecked, as before.
    validate_tool_io: bool = true,
    /// Parallel to `tools`: each tool's compiled schemas.
    tool_checks: std.ArrayList(ToolCheck) = .empty,
    /// Parallel to `resource_templates`: the parsed, matchable template, or
    /// null when it is not valid RFC 6570 or has no deterministic inverse.
    template_parsed: std.ArrayList(?uri_template.Template) = .empty,
    catalog_arena: ?*std.heap.ArenaAllocator = null,
    custom_methods: std.ArrayList(Method) = .empty,
    /// The `tools/call`s now running, so a cancel can find them. Guarded by
    /// its own lock — not the caller's lock on the `Server` — because a
    /// transport delivers a cancel while a handler holds that one.
    inflight: std.ArrayList(Inflight) = .empty,
    inflight_lock: std.atomic.Mutex = .unlocked,
    /// Change notifications (R12): when true the server advertises
    /// `listChanged` on tools/prompts/resources and `resources.subscribe`,
    /// answers `resources/subscribe`/`unsubscribe`, and holds a 2026-07-28
    /// `subscriptions/listen` open with the filter honoured; the application
    /// then calls `notifyListChanged`/`notifyResourceUpdated` when its catalog
    /// or a resource changes. False (the default): none of that is offered,
    /// `listen` acknowledges nothing and closes at once, as before.
    push: bool = false,
    session_subs: std.ArrayList(SessionSub) = .empty,
    listens: std.ArrayList(Listen) = .empty,
    custom_notifications: std.ArrayList(Method) = .empty,
    /// `capabilities.extensions` / `.experimental` (JSON object text, ""
    /// = none), set through `setCapabilityExtras`.
    extensions_json: []const u8 = "",
    experimental_json: []const u8 = "",
    /// Default caching hint on a 2026-07-28 `resources/read`; a handler can
    /// override it per read (`ResourceRequest.cache`).
    read_cache: CacheHint = .{},
    /// Cap on unanswered server→client requests **per peer**. A client that
    /// simply never answers must not grow this without bound; past the cap
    /// `send*` returns `error.TooManyPending`. Counted per peer so one
    /// session cannot exhaust the budget of every other session sharing this
    /// `Server`.
    max_pending: usize = 256,

    pub fn init(gpa: std.mem.Allocator, info: Info) Server {
        return .{ .gpa = gpa, .info = info };
    }

    pub fn deinit(self: *Server) void {
        if (self.catalog_arena) |a| {
            a.deinit();
            self.gpa.destroy(a);
        }
        self.template_parsed.deinit(self.gpa);
        self.custom_methods.deinit(self.gpa);
        self.inflight.deinit(self.gpa);
        for (self.session_subs.items) |sub| self.gpa.free(sub.uri);
        self.session_subs.deinit(self.gpa);
        for (self.listens.items) |l| l.free(self.gpa);
        self.listens.deinit(self.gpa);
        self.custom_notifications.deinit(self.gpa);
        for (self.tool_checks.items) |c| c.deinit(self.gpa);
        self.tool_checks.deinit(self.gpa);
        self.tools.deinit(self.gpa);
        self.resources.deinit(self.gpa);
        self.resource_templates.deinit(self.gpa);
        self.prompts.deinit(self.gpa);
        for (self.peers.items) |p| {
            if (p.client) |ci| ci.free(self.gpa);
        }
        self.peers.deinit(self.gpa);
        self.pending.deinit(self.gpa);
    }

    /// This peer's handshake state, or the pre-handshake default (all-false
    /// capabilities, our latest revision) when it has not handshaken. Never
    /// another peer's.
    pub fn peerState(self: *const Server, peer: u64) PeerState {
        for (self.peers.items) |p| {
            if (p.peer == peer) return p;
        }
        return .{ .peer = peer };
    }

    /// What `peer` advertised at `initialize` — the gate on every
    /// server→client request to it.
    pub fn clientCapabilities(self: *const Server, peer: u64) ClientCapabilities {
        return self.peerState(peer).capabilities;
    }

    /// Whether `peer` has sent `notifications/initialized`.
    pub fn clientInitialized(self: *const Server, peer: u64) bool {
        return self.peerState(peer).initialized;
    }

    /// The revision `peer`'s `initialize` settled on (see `negotiateVersion`).
    pub fn negotiatedVersion(self: *const Server, peer: u64) []const u8 {
        return self.peerState(peer).negotiated_version;
    }

    /// What `peer` self-identified as at `initialize` (`clientInfo`'s
    /// `name`/`version`/optional `title`). Null before a handshake, or when
    /// the client's `clientInfo` was missing or malformed — see
    /// `ClientInfo.parse`. The returned slices are owned by this `Server` and
    /// valid until the next `initialize` from the same peer or `forgetPeer`.
    pub fn clientInfo(self: *const Server, peer: u64) ?ClientInfo {
        return self.peerState(peer).client;
    }

    /// Forget everything about `peer`: its handshake state and every pending
    /// server→client request issued to it. A multiplexing transport calls
    /// this when a session ends, so a `Server` that outlives many sessions
    /// does not accumulate them. Dropped pending entries are *not* handed to
    /// their `on_response` handler — the peer is gone, there is no answer.
    pub fn forgetPeer(self: *Server, peer: u64) void {
        self.dropPeerSubscriptions(peer);
        var i: usize = self.pending.items.len;
        while (i > 0) {
            i -= 1;
            if (self.pending.items[i].peer == peer) _ = self.pending.orderedRemove(i);
        }
        for (self.peers.items, 0..) |p, j| {
            if (p.peer == peer) {
                if (p.client) |ci| ci.free(self.gpa);
                _ = self.peers.orderedRemove(j);
                return;
            }
        }
    }

    /// This peer's mutable slot, created on demand. The returned pointer is
    /// invalidated by the next `peerSlot`, so write through it immediately.
    fn peerSlot(self: *Server, peer: u64) error{ OutOfMemory, TooManyPeers }!*PeerState {
        for (self.peers.items) |*p| {
            if (p.peer == peer) return p;
        }
        if (self.peers.items.len >= self.max_peers) return error.TooManyPeers;
        try self.peers.append(self.gpa, .{ .peer = peer });
        return &self.peers.items[self.peers.items.len - 1];
    }

    /// Unanswered server→client requests issued to `peer`.
    fn pendingFor(self: *const Server, peer: u64) usize {
        var n: usize = 0;
        for (self.pending.items) |p| {
            if (p.peer == peer) n += 1;
        }
        return n;
    }

    /// Register a tool. All slices in `tool` (name, description, schemas) must
    /// outlive the server — typically they are static literals or app-owned.
    ///
    /// The `inputSchema`'s `x-mcp-header` annotations are checked against the
    /// spec's rules (`header_annotations`): a tool that breaks them is one a
    /// Streamable HTTP client must drop from its list, so it is refused here,
    /// where its author sees it, instead.
    pub fn addTool(self: *Server, tool: Tool) (error{DuplicateTool} || header_annotations.Error)!void {
        if (self.findTool(tool.name) != null) return error.DuplicateTool;
        try header_annotations.validate(self.gpa, tool.input_schema);
        const check = try ToolCheck.init(self.gpa, tool);
        errdefer check.deinit(self.gpa);
        try self.tool_checks.ensureUnusedCapacity(self.gpa, 1);
        try self.tools.append(self.gpa, tool);
        self.tool_checks.appendAssumeCapacity(check);
    }

    fn findTool(self: *const Server, name: []const u8) ?usize {
        for (self.tools.items, 0..) |*t, i| {
            if (std.mem.eql(u8, t.name, name)) return i;
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
        // A template outside RFC 6570 (or one with no deterministic inverse)
        // still registers, as before; its reads just carry no `vars`.
        const arena = try self.catalogArena();
        const parsed: ?uri_template.Template = uri_template.Template.parse(arena, template.uri_template) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidTemplate => null,
        };
        try self.template_parsed.ensureUnusedCapacity(self.gpa, 1);
        try self.resource_templates.append(self.gpa, template);
        self.template_parsed.appendAssumeCapacity(if (parsed) |pt| (if (pt.unmatchable == null) pt else null) else null);
    }

    /// Whether any prompt or template can complete — the `completions`
    /// capability, and whether `completion/complete` exists at all here.
    fn offersCompletions(self: *const Server) bool {
        for (self.prompts.items) |p| if (p.completer != null) return true;
        for (self.resource_templates.items) |rt| if (rt.completer != null) return true;
        return false;
    }

    fn handleComplete(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64, modern: ?*const ModernRequest) Error!void {
        // completion.mdx: a server without the capability answers -32601.
        if (!self.offersCompletions()) return sendError(arena, out, id, error_code.method_not_found, "Method not found");
        const params = params_opt orelse return sendError(arena, out, id, error_code.invalid_params, "Missing params");
        if (params != .object) return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        const ref = params.object.get("ref") orelse return sendError(arena, out, id, error_code.invalid_params, "Missing ref");
        const arg = params.object.get("argument") orelse return sendError(arena, out, id, error_code.invalid_params, "Missing argument");
        if (ref != .object or arg != .object) return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        const ref_type = ref.object.get("type") orelse .null;
        const arg_name = arg.object.get("name") orelse .null;
        const arg_value = arg.object.get("value") orelse .null;
        if (ref_type != .string or arg_name != .string or arg_value != .string)
            return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        var ctx_args: std.json.Value = .null;
        if (params.object.get("context")) |c| if (c == .object) if (c.object.get("arguments")) |a| {
            ctx_args = a;
        };

        var completer: ?Completer = null;
        var cctx: ?*anyopaque = null;
        if (std.mem.eql(u8, ref_type.string, "ref/prompt")) {
            const name = ref.object.get("name") orelse .null;
            if (name != .string) return sendError(arena, out, id, error_code.invalid_params, "Invalid ref");
            const p = self.findPrompt(name.string) orelse return sendError(arena, out, id, error_code.invalid_params, "Unknown prompt");
            completer = p.completer;
            cctx = p.ctx;
        } else if (std.mem.eql(u8, ref_type.string, "ref/resource")) {
            const uri = ref.object.get("uri") orelse .null;
            if (uri != .string) return sendError(arena, out, id, error_code.invalid_params, "Invalid ref");
            const rt = for (self.resource_templates.items) |*x| {
                if (std.mem.eql(u8, x.uri_template, uri.string)) break x;
            } else return sendError(arena, out, id, error_code.invalid_params, "Unknown resource template");
            completer = rt.completer;
            cctx = rt.ctx;
        } else return sendError(arena, out, id, error_code.invalid_params, "Invalid ref type");

        var req = CompletionRequest{
            .arena = arena,
            .argument = arg_name.string,
            .value = arg_value.string,
            .context_arguments = ctx_args,
            .server = self,
            .peer = peer,
            .modern = modern,
        };
        // A known target without a completer simply has no suggestions.
        if (completer) |f| f(cctx, &req);

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildCompleteResult(&jw, &req, &self.info, modern != null) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn lockInflight(self: *Server) void {
        while (!self.inflight_lock.tryLock()) std.atomic.spinLoopHint();
    }

    /// Mark the running `tools/call` that `peer` sent with `request_id` as
    /// cancelled (`ToolCall.cancelled`); a no-op when none is running — it
    /// finished, or never existed, which the spec says to ignore. **Safe to
    /// call from another thread while a handler runs** (it takes only the
    /// in-flight lock): this is the seam a transport uses when it learns of a
    /// cancel by other means, e.g. `mcp-http` when the client closes the
    /// response stream of a 2026-07-28 request. Returns whether a call was
    /// found.
    pub fn cancelInflight(self: *Server, peer: u64, request_id: std.json.Value) bool {
        // An array/object/non-finite id was never issued (and would recurse in
        // the serializer): nothing to cancel.
        if (!conformingId(request_id)) return false;
        var buf: [128]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        std.json.Stringify.value(request_id, .{}, &w) catch return false;
        const key = w.buffered();
        self.lockInflight();
        defer self.inflight_lock.unlock();
        for (self.inflight.items) |e| {
            if (e.peer == peer and std.mem.eql(u8, e.id_json, key)) {
                e.flag.store(true, .release);
                return true;
            }
        }
        return false;
    }

    fn registerInflight(self: *Server, peer: u64, id_json: []const u8, flag: *std.atomic.Value(bool)) bool {
        self.lockInflight();
        defer self.inflight_lock.unlock();
        self.inflight.append(self.gpa, .{ .peer = peer, .id_json = id_json, .flag = flag }) catch return false;
        return true;
    }

    fn unregisterInflight(self: *Server, flag: *std.atomic.Value(bool)) void {
        self.lockInflight();
        defer self.inflight_lock.unlock();
        for (self.inflight.items, 0..) |e, i| {
            if (e.flag == flag) {
                _ = self.inflight.swapRemove(i);
                return;
            }
        }
    }

    pub const MethodError = error{ OutOfMemory, DuplicateMethod, ReservedMethod };

    /// Register a request method this module does not define (see `Method`).
    /// A name this module dispatches itself (`tools/call`, …) is refused, so
    /// a custom handler can never shadow the protocol. Slices must outlive
    /// the server.
    pub fn addMethod(self: *Server, method: Method) MethodError!void {
        try checkCustomName(self.custom_methods.items, method.name);
        try self.custom_methods.append(self.gpa, method);
    }

    /// Register a notification handler (`notifications/acme/...`); the same
    /// rules as `addMethod`. `notifications/initialized` and
    /// `notifications/cancelled` are this module's own.
    pub fn addNotification(self: *Server, method: Method) MethodError!void {
        if (std.mem.eql(u8, method.name, "notifications/cancelled")) return error.ReservedMethod;
        try checkCustomName(self.custom_notifications.items, method.name);
        try self.custom_notifications.append(self.gpa, method);
    }

    fn checkCustomName(existing: []const Method, name: []const u8) MethodError!void {
        if (name.len == 0 or std.meta.stringToEnum(DispatchMethod, name) != null) return error.ReservedMethod;
        for (existing) |m| if (std.mem.eql(u8, m.name, name)) return error.DuplicateMethod;
    }

    fn findCustom(list: []const Method, name: []const u8) ?*const Method {
        for (list) |*m| if (std.mem.eql(u8, m.name, name)) return m;
        return null;
    }

    /// Advertise `capabilities.extensions` (SEP-2133: extension id → its
    /// settings object, e.g. `{"io.modelcontextprotocol/ui":{}}`) and
    /// `capabilities.experimental`, in both `initialize` and
    /// `server/discover`. Each must be a JSON object ("" = none). The text is
    /// borrowed and must outlive the server.
    pub fn setCapabilityExtras(self: *Server, extensions_json: []const u8, experimental_json: []const u8) error{ OutOfMemory, InvalidCapabilityJson }!void {
        for ([_][]const u8{ extensions_json, experimental_json }) |text| {
            if (text.len == 0) continue;
            const parsed = std.json.parseFromSlice(std.json.Value, self.gpa, text, .{}) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidCapabilityJson,
            };
            defer parsed.deinit();
            if (parsed.value != .object) return error.InvalidCapabilityJson;
        }
        self.extensions_json = extensions_json;
        self.experimental_json = experimental_json;
    }

    fn writeCapabilityExtras(self: *const Server, jw: *std.json.Stringify) std.Io.Writer.Error!void {
        const pairs = [_]struct { []const u8, []const u8 }{ .{ "extensions", self.extensions_json }, .{ "experimental", self.experimental_json } };
        for (pairs) |pair| {
            if (pair[1].len == 0) continue;
            try jw.objectField(pair[0]);
            try jw.beginWriteRaw();
            try writeStrippingNewlines(jw.writer, pair[1]);
            jw.endWriteRaw();
        }
    }

    fn handleCustom(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, method: *const Method, obj: std.json.ObjectMap, peer: u64, modern: ?*const ModernRequest) Error!void {
        const params: std.json.Value = obj.get("params") orelse .null;
        const req_meta: std.json.Value = if (params == .object) requestMeta(params.object) else .null;
        var buf: std.ArrayList(u8) = .empty;
        var req = MethodRequest{
            .arena = arena,
            .method = method.name,
            .params = params,
            .out = &buf,
            .notification = id == null,
            .progress = progressFrom(arena, out, req_meta),
            .server = self,
            .peer = peer,
            .modern = modern,
            .meta = req_meta,
        };
        const ok = method.handler(method.ctx, &req);
        if (id == null) return; // a notification: nothing is ever written back
        if (req.protocol_error) |pe| return sendProtocolError(arena, out, id, pe);
        if (!ok) return sendError(arena, out, id, error_code.internal_error, "Method failed");
        const text = if (buf.items.len == 0) "{}" else buf.items;
        // Handler output is re-serialized recursively: bound its nesting first
        // (no-panic sweep 2026-10-28 M-2).
        if (!jsonDepthOk(text)) return sendError(arena, out, id, error_code.internal_error, "Method result is not a JSON object");
        const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return sendError(arena, out, id, error_code.internal_error, "Method result is not a JSON object"),
        };
        if (v != .object) return sendError(arena, out, id, error_code.internal_error, "Method result is not a JSON object");
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildCustomResult(&jw, v.object, &self.info, modern != null) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    /// Long-lived storage for what registration derives from the catalog
    /// (parsed uri templates); freed by `deinit`.
    fn catalogArena(self: *Server) error{OutOfMemory}!std.mem.Allocator {
        if (self.catalog_arena == null) {
            const a = try self.gpa.create(std.heap.ArenaAllocator);
            a.* = .init(self.gpa);
            self.catalog_arena = a;
        }
        return self.catalog_arena.?.allocator();
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
        const peer_state = self.peerState(opts.peer);
        try checkSamplingRequest(peer_state.capabilities, req);
        if (self.pendingFor(opts.peer) >= self.max_pending) return error.TooManyPending;

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
        const peer_state = self.peerState(opts.peer);

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        try checkElicitationRequest(arena, peer_state.capabilities, req);
        if (self.pendingFor(opts.peer) >= self.max_pending) return error.TooManyPending;

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
            versionHasElicitationModes(peer_state.negotiated_version),
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
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"requestId\":{d}",
            .{ OriginatedMethod.@"notifications/cancelled".wire(), id },
        ) catch return error.OutOfMemory;
        if (reason.len != 0) {
            w.writeAll(",\"reason\":") catch return error.OutOfMemory;
            std.json.Stringify.encodeJsonString(reason, .{}, w) catch return error.OutOfMemory;
        }
        w.writeAll("}}\n") catch return error.OutOfMemory;
        try flushLine(out, aw.written());
    }

    /// Tell `peer` that the out-of-band interaction of a URL-mode elicitation
    /// it started has completed (`notifications/elicitation/complete`, spec
    /// 2025-11-25 client/elicitation.mdx), so it may retry a request that got
    /// `URLElicitationRequiredError`. The spec's MUST "only to the client that
    /// initiated the elicitation" is why `peer` is required; a peer that did
    /// not declare `elicitation.url` is refused, as `sendElicitationRequest`
    /// refuses it. Session path only: 2026-07-28 has no such notification.
    pub fn sendElicitationComplete(self: *Server, out: *std.Io.Writer, peer: u64, elicitation_id: []const u8) SendError!void {
        if (!self.clientCapabilities(peer).elicitation_url) return error.ElicitationUrlNotSupported;
        if (elicitation_id.len == 0) return error.MissingElicitationId;
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        const w = &aw.writer;
        w.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"elicitationId\":", .{OriginatedMethod.@"notifications/elicitation/complete".wire()}) catch return error.OutOfMemory;
        std.json.Stringify.encodeJsonString(elicitation_id, .{}, w) catch return error.OutOfMemory;
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
    /// session end, not a server error); an unterminated trailing fragment
    /// (the stream ends, or is canceled, mid-line) is discarded rather than
    /// handed to `handleMessage` as if it were a complete line — see
    /// `readLine`'s doc comment.
    ///
    /// `serve` takes a *foreign* `*std.Io.Reader` — an interface, not a
    /// concrete reader — so it cannot itself tell a `std.Io` cancelation of
    /// the blocked read apart from the peer actually hanging up: both simply
    /// end `readLine`'s loop, and `serve` returns `{}` either way, exactly as
    /// for a clean EOF. A caller driving `serve` on a cancelable task and
    /// needing to tell "canceled" from "peer disconnected" has to inspect its
    /// own concrete reader's out-of-band `err` field after `serve` returns
    /// (e.g. `std.Io.net.Stream.Reader.err` / `std.Io.File.Reader.err`) —
    /// `serve` is handed only the interface and has no such field to consult
    /// on the caller's behalf. `serveStdio`, which owns its reader, does
    /// exactly this and surfaces `error.Canceled` instead of `{}`; see its
    /// doc comment.
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
    ///
    /// Unlike `serve`, this function owns its reader (`stdin_reader` is a
    /// concrete `std.Io.File.Reader`, never exposed to the caller), so it is
    /// the one place in this module that *can* recover a `std.Io` cancelation
    /// of the blocked read: after `serve` returns -- which, per its own doc
    /// comment, cannot distinguish "canceled" from "stdin closed" and always
    /// returns `{}` -- `recoverFileCancel` inspects `stdin_reader.err` and
    /// surfaces `error.Canceled` instead of the ordinary session-end `{}`. A
    /// plain EOF (stdin closed) still returns `{}`, and any other read
    /// failure keeps meaning session end.
    pub fn serveStdio(self: *Server, io: std.Io) Error!void {
        var read_buf: [64 * 1024]u8 = undefined;
        var write_buf: [64 * 1024]u8 = undefined;
        var stdin_reader = std.Io.File.stdin().readerStreaming(io, &read_buf);
        var stdout_writer = std.Io.File.stdout().writerStreaming(io, &write_buf);
        try self.serve(&stdin_reader.interface, &stdout_writer.interface);
        try recoverFileCancel(&stdin_reader);
    }

    /// Distinguish a canceled wait from a genuine EOF/read failure on a
    /// `std.Io.File.Reader` that `serve` has already swallowed into a plain
    /// `{}` return. `std.Io.Reader.Error` is exactly `{ReadFailed,
    /// EndOfStream}` and cannot carry `Canceled`; the concrete reader records
    /// the real cause in its own out-of-band `err` field instead. Split out
    /// of `serveStdio` so this recovery step -- the one line the whole
    /// change is about -- can be exercised in a test against any
    /// `std.Io.File.Reader`, not only the real process stdin `serveStdio`
    /// hard-codes.
    fn recoverFileCancel(reader: *const std.Io.File.Reader) Error!void {
        if (reader.err) |e| if (e == error.Canceled) return error.Canceled;
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

        // Before the parse: a 16 MiB line of `[` would otherwise build ~1 GB of
        // Values, and a deep echo overflows the serializer (M-3).
        if (!jsonDepthOk(input)) return sendError(arena, out, null, error_code.parse_error, "Parse error");
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
        // JSON-RPC 2.0 §4: `id` MUST be a String, Number or NULL if present.
        // Anything else — an object, an array, a bool — is not an identifier,
        // and echoing it back verbatim (which `writeId` will happily do, the
        // serializer being shape-agnostic) hands a strict client a response it
        // cannot match against any request it made, or must reject outright.
        // Checked once, here, so no later path can echo a shape we did not
        // vet.
        const id_conforms = if (id) |v| conformingId(v) else true;
        // §5: when the id cannot be determined, the error response carries a
        // NULL id. A non-conforming id is exactly that case — we must not
        // mirror it — so every rejection below answers with null.

        const method_v = obj.get("method") orelse {
            // No `method` but an `id` plus `result`/`error` is the CLIENT
            // answering one of OUR requests (sampling/elicitation). Correlate
            // it and write nothing: JSON-RPC never responds to a response —
            // answering here would bounce an error back at the client's id
            // forever.
            if (id != null and id_conforms and (obj.get("result") != null or obj.get("error") != null)) {
                self.deliverResponse(arena, id.?, obj, peer);
                return;
            }
            // A response-shaped message with a non-conforming id correlates to
            // nothing we ever sent (we only issue conforming ids), and JSON-RPC
            // forbids answering a response — so it falls through to the
            // request path below and is refused there, or dropped if id-less.
            if (id != null) return sendError(
                arena,
                out,
                if (id_conforms) id else null,
                error_code.invalid_request,
                if (id_conforms) "Missing method" else "Invalid request id",
            );
            return;
        };
        if (method_v != .string) {
            if (!id_conforms) return sendError(arena, out, null, error_code.invalid_request, "Invalid request id");
            if (id != null) return sendError(arena, out, id, error_code.invalid_request, "Invalid method");
            return;
        }
        // Every remaining path answers with `id`, so the shape gate closes
        // here — one place, in front of all of them, rather than at each
        // `writeId` call site.
        if (!id_conforms) return sendError(arena, out, null, error_code.invalid_request, "Invalid request id");
        const method = method_v.string;

        // A request (has `id`) gets exactly one response; a notification (no
        // `id`) must get none. `notifications/initialized` is the only method
        // accepted without an id — every other id-less line is a stray
        // notification we drop.
        //
        // The chain is a switch over `DispatchMethod` rather than a ladder of
        // `eql` literals so that the method NAMES are a comptime list the
        // spec-anchor canary can read (see `DispatchMethod`): the switch is
        // exhaustive, so an arm cannot exist without a tag, and the canary
        // fails when a tag has no `spec_anchor_index` entry.
        const dm = std.meta.stringToEnum(DispatchMethod, method);
        if (dm == .@"notifications/initialized") {
            // A notification by definition — carrying an `id` makes it a
            // *request*, and "a request gets exactly one response" is a
            // stated invariant of this module. Answering it here (rather than
            // taking the notification path and returning silently) is what
            // keeps that true; a client that sends this shape would otherwise
            // wait forever for a reply that is never written. The flag is not
            // set for a message we are rejecting.
            if (id != null) {
                return sendError(arena, out, id, error_code.invalid_request, "notifications/initialized is a notification and takes no id");
            }
            const slot = self.peerSlot(peer) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Past `max_peers` there is nowhere to record it, and a
                // notification has no response to carry the refusal.
                error.TooManyPeers => return,
            };
            slot.initialized = true;
            return;
        }
        // Notification for a request-only method (or for one we do not know at
        // all): ignore, never respond — unless the application registered it.
        if (id == null) {
            // The client gives up on one of its requests (cancellation.mdx).
            // A malformed one has no one to be told, so it is just dropped.
            if (std.mem.eql(u8, method, "notifications/cancelled")) {
                const params = obj.get("params") orelse return;
                if (params != .object) return;
                const rid = params.object.get("requestId") orelse return;
                if (rid != .string and rid != .integer) return;
                if (!self.cancelInflight(peer, rid)) _ = self.cancelListen(peer, rid);
                return;
            }
            if (dm == null) if (findCustom(self.custom_notifications.items, method)) |cm| {
                const modern_n: ?*const ModernRequest = switch (classifyRequest(obj.get("params"))) {
                    .modern => |*r| r,
                    .legacy => null,
                    else => return, // a malformed notification has no one to tell
                };
                if (if (modern_n != null) !cm.stateless else !cm.session) return;
                return self.handleCustom(arena, out, null, cm, obj, peer, modern_n);
            };
            return;
        }
        const m = dm orelse {
            const cm = findCustom(self.custom_methods.items, method) orelse
                return sendError(arena, out, id, error_code.method_not_found, "Method not found");
            const modern_c: ?*const ModernRequest = switch (classifyRequest(obj.get("params"))) {
                .legacy => null,
                .modern => |*r| r,
                .malformed => |why| return sendError(arena, out, id, error_code.invalid_params, why),
                .unsupported => |requested| return sendErrorWithData(arena, out, id, error_code.unsupported_protocol_version, "Unsupported protocol version", .{ .supported = all_versions[0..], .requested = requested }),
            };
            if (if (modern_c != null) !cm.stateless else !cm.session)
                return sendError(arena, out, id, error_code.method_not_found, "Method not found");
            return self.handleCustom(arena, out, id, cm, obj, peer, modern_c);
        };

        // Which era this request speaks — see `classifyRequest`. `initialize`
        // is the session opener whatever its `_meta` says: a dual-era server
        // "selects legacy semantics" on it (basic/versioning.mdx).
        const era: Era = if (m == .initialize) .legacy else classifyRequest(obj.get("params"));
        const modern: ?*const ModernRequest = switch (era) {
            .legacy => null,
            .modern => |*r| r,
            .malformed => |why| return sendError(arena, out, id, error_code.invalid_params, why),
            .unsupported => |requested| return sendErrorWithData(
                arena,
                out,
                id,
                error_code.unsupported_protocol_version,
                "Unsupported protocol version",
                .{ .supported = all_versions[0..], .requested = requested },
            ),
        };

        if (modern != null and !m.servedStatelessly())
            return sendError(arena, out, id, error_code.method_not_found, "Method not found");

        switch (m) {
            // Handled above, before the id check — a notification by definition.
            .@"notifications/initialized" => unreachable,
            .initialize => try self.handleInitialize(arena, out, id, obj.get("params"), peer),
            // Stateless-only, and the spec makes it mandatory. Without the
            // `_meta` version it is a malformed modern request, not a session
            // one — no session-era client sends it.
            .@"server/discover" => {
                if (modern == null) return sendError(arena, out, id, error_code.invalid_params, "Missing " ++ meta_key.protocol_version);
                try self.handleDiscover(arena, out, id);
            },
            // Stateless-only, like `server/discover`.
            .@"subscriptions/listen" => {
                if (modern == null) return sendError(arena, out, id, error_code.invalid_params, "Missing " ++ meta_key.protocol_version);
                try self.handleListen(arena, out, id.?, obj.get("params"), peer);
            },
            .@"tools/list" => try self.handleList(arena, out, id, obj.get("params"), modern != null, .tools),
            // Session-only: 2026-07-28 removed it (changelog "Major changes"
            // 5), and `servedStatelessly` has already refused a modern one.
            .ping => try sendResultRaw(arena, out, id, "{}"),
            .@"tools/call" => try self.handleCall(arena, out, id, obj.get("params"), peer, modern),
            .@"resources/list" => try self.handleList(arena, out, id, obj.get("params"), modern != null, .resources),
            .@"resources/read" => try self.handleResourcesRead(arena, out, id, obj.get("params"), peer, modern),
            .@"resources/templates/list" => try self.handleList(arena, out, id, obj.get("params"), modern != null, .templates),
            .@"prompts/list" => try self.handleList(arena, out, id, obj.get("params"), modern != null, .prompts),
            .@"prompts/get" => try self.handlePromptsGet(arena, out, id, obj.get("params"), peer, modern),
            .@"completion/complete" => try self.handleComplete(arena, out, id, obj.get("params"), peer, modern),
            .@"resources/subscribe" => try self.handleSubscribe(arena, out, id, obj.get("params"), peer, true),
            .@"resources/unsubscribe" => try self.handleSubscribe(arena, out, id, obj.get("params"), peer, false),
        }
    }

    /// `server/discover` (spec 2026-07-28, server/discover.mdx): every
    /// revision we speak, the capabilities in their stateless shape, our
    /// identity, the instructions, and the caching hint.
    ///
    /// The capabilities follow the session rule (`tools` always, `resources`/
    /// `prompts` only with a non-empty catalog) but drop the `listChanged:false`
    /// / `subscribe:false` members: absent means the same thing, and in this
    /// revision both belong to `subscriptions/listen`, which this module
    /// answers with an empty acknowledgment (see `handleListen`).
    fn handleDiscover(self: *const Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value) Error!void {
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        self.buildDiscoverResult(&jw) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    /// `subscriptions/listen` (basic/patterns/subscriptions.mdx). This server
    /// emits no change notification of any kind — `tools`/`prompts`/
    /// `resources` never change after registration as far as it knows, and
    /// resource subscriptions are not implemented — so it honours none of the
    /// requested types. It says so rather than holding a stream open that
    /// would never carry anything: the acknowledgment (MUST come first)
    /// carries an empty filter ("types the server does not support are
    /// omitted"), and the completion result follows at once, which is the
    /// spec's graceful closure — a client reads it as "ended cleanly", not as
    /// a drop to reconnect after. Two lines on `out`; over HTTP they are the
    /// two events of the request's SSE stream.
    ///
    /// The filter itself must be an object when present (-32602 otherwise);
    /// its members are not interpreted, since none can be honoured.
    fn handleListen(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: std.json.Value, params_opt: ?std.json.Value, peer: u64) Error!void {
        var filter: ?std.json.ObjectMap = null;
        if (params_opt) |params| {
            if (params == .object) {
                if (present(params.object.get("notifications"))) |f| {
                    if (f != .object) return sendError(arena, out, id, error_code.invalid_params, "Invalid notifications filter");
                    filter = f.object;
                }
            }
        }
        if (!self.push) {
            var aw: std.Io.Writer.Allocating = .init(arena);
            buildListenLines(&aw.writer, id, &self.info) catch return error.OutOfMemory;
            return flushLine(out, aw.written());
        }
        // Held open: acknowledge what is honoured (all of it — every type is
        // emitted when the application calls `notify*`), register, and answer
        // the request only when the server ends it (`endSubscriptions`). A
        // client ends it with notifications/cancelled; that gets no response.
        var l: Listen = .{ .peer = peer, .id_json = &.{}, .tools = false, .prompts = false, .resources = false, .uris = &.{} };
        var uris: std.ArrayList([]const u8) = .empty;
        if (filter) |f| {
            l.tools = flagTrue(f, "toolsListChanged");
            l.prompts = flagTrue(f, "promptsListChanged");
            l.resources = flagTrue(f, "resourcesListChanged");
            if (present(f.get("resourceSubscriptions"))) |rs| {
                if (rs != .array) return sendError(arena, out, id, error_code.invalid_params, "Invalid resourceSubscriptions");
                for (rs.array.items) |u| {
                    if (u != .string) return sendError(arena, out, id, error_code.invalid_params, "Invalid resourceSubscriptions");
                    try uris.append(arena, u.string);
                }
            }
        }
        // The id is the subscription id every notification repeats; a bounded
        // one keeps each notification line bounded.
        const id_len = (std.json.Stringify.valueAlloc(arena, id, .{}) catch return error.OutOfMemory).len;
        if (id_len > 128) return sendError(arena, out, id, error_code.invalid_params, "Request id too long for a subscription");
        var uri_bytes: usize = 0;
        for (uris.items) |u| {
            if (u.len > max_subscription_uri_len) return sendError(arena, out, id, error_code.invalid_params, "Subscription uri too long");
            uri_bytes += u.len;
        }
        if (uris.items.len > max_subscriptions_per_peer or uri_bytes > max_listen_uri_bytes or
            self.countListens(peer) >= max_subscriptions_per_peer or self.listens.items.len >= max_listens)
            return sendError(arena, out, id, error_code.invalid_params, "Too many subscriptions");
        l = try self.ownListen(l, id, uris.items);
        // The acknowledgment is built before the entry is registered and the
        // entry dropped again if the write fails: nothing is left behind that
        // the client was never told about, and nothing freed that the table
        // still points to (review 2026-10-20 H1).
        var aw: std.Io.Writer.Allocating = .init(arena);
        buildListenAck(&aw.writer, l) catch {
            l.free(self.gpa);
            return error.OutOfMemory;
        };
        self.listens.append(self.gpa, l) catch {
            l.free(self.gpa);
            return error.OutOfMemory;
        };
        flushLine(out, aw.written()) catch |e| {
            const dropped = self.listens.pop().?;
            dropped.free(self.gpa);
            return e;
        };
    }

    /// `l` with its id and uris copied onto `gpa` (all or nothing).
    fn ownListen(self: *Server, l: Listen, id: std.json.Value, uris: []const []const u8) error{OutOfMemory}!Listen {
        var owned = l;
        owned.id_json = try std.json.Stringify.valueAlloc(self.gpa, id, .{});
        errdefer self.gpa.free(owned.id_json);
        owned.uris = try self.gpa.alloc([]u8, uris.len);
        var copied: usize = 0;
        errdefer {
            for (owned.uris[0..copied]) |u| self.gpa.free(u);
            self.gpa.free(owned.uris);
        }
        for (uris) |u| {
            owned.uris[copied] = try self.gpa.dupe(u8, u);
            copied += 1;
        }
        return owned;
    }

    fn countListens(self: *const Server, peer: u64) usize {
        var n: usize = 0;
        for (self.listens.items) |l| n += @intFromBool(l.peer == peer);
        return n;
    }

    fn writePushFlag(self: *const Server, jw: *std.json.Stringify, name: []const u8) std.Io.Writer.Error!void {
        if (!self.push) return;
        try jw.objectField(name);
        try jw.write(true);
    }

    /// `resources/subscribe` / `unsubscribe` (session path): record or drop
    /// `uri` for this peer; `notifyResourceUpdated` then reaches it. Any uri
    /// is accepted — a resource may exist only behind a template — and a
    /// repeat subscribe is a no-op. Without `push` the method is -32601.
    fn handleSubscribe(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64, subscribe: bool) Error!void {
        if (!self.push) return sendError(arena, out, id, error_code.method_not_found, "Method not found");
        const params = params_opt orelse return sendError(arena, out, id, error_code.invalid_params, "Missing params");
        if (params != .object) return sendError(arena, out, id, error_code.invalid_params, "Invalid params");
        const uri = params.object.get("uri") orelse return sendError(arena, out, id, error_code.invalid_params, "Missing uri");
        if (uri != .string) return sendError(arena, out, id, error_code.invalid_params, "Invalid uri");
        var count: usize = 0;
        for (self.session_subs.items, 0..) |sub, i| {
            if (sub.peer != peer) continue;
            if (std.mem.eql(u8, sub.uri, uri.string)) {
                if (!subscribe) {
                    self.gpa.free(sub.uri);
                    _ = self.session_subs.swapRemove(i);
                }
                return sendResultRaw(arena, out, id, "{}");
            }
            count += 1;
        }
        if (subscribe) {
            if (uri.string.len > max_subscription_uri_len) return sendError(arena, out, id, error_code.invalid_params, "Subscription uri too long");
            if (count >= max_subscriptions_per_peer or self.session_subs.items.len >= max_session_subscriptions)
                return sendError(arena, out, id, error_code.invalid_params, "Too many subscriptions");
            const dup = try self.gpa.dupe(u8, uri.string);
            errdefer self.gpa.free(dup);
            try self.session_subs.append(self.gpa, .{ .peer = peer, .uri = dup });
        }
        try sendResultRaw(arena, out, id, "{}");
    }

    /// Drop the open `subscriptions/listen` of `peer` whose id is
    /// `request_id` (the client cancelled it). Whether one was found.
    fn cancelListen(self: *Server, peer: u64, request_id: std.json.Value) bool {
        // An array/object/non-finite id was never issued (and would recurse in
        // the serializer): nothing to cancel.
        if (!conformingId(request_id)) return false;
        var buf: [128]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        std.json.Stringify.value(request_id, .{}, &w) catch return false;
        for (self.listens.items, 0..) |l, i| {
            if (l.peer == peer and std.mem.eql(u8, l.id_json, w.buffered())) {
                l.free(self.gpa);
                _ = self.listens.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    fn dropPeerSubscriptions(self: *Server, peer: u64) void {
        var i: usize = self.session_subs.items.len;
        while (i > 0) {
            i -= 1;
            if (self.session_subs.items[i].peer == peer) {
                self.gpa.free(self.session_subs.items[i].uri);
                _ = self.session_subs.swapRemove(i);
            }
        }
        i = self.listens.items.len;
        while (i > 0) {
            i -= 1;
            if (self.listens.items[i].peer == peer) {
                self.listens.items[i].free(self.gpa);
                _ = self.listens.swapRemove(i);
            }
        }
    }

    /// Tell every interested peer that a catalog changed: a handshaken
    /// session peer gets `notifications/<kind>/list_changed`, an open
    /// `subscriptions/listen` that asked for it gets the same with its
    /// subscription id. A no-op without `push`. Returns how many messages
    /// were written; a peer whose sink is null or whose write fails is
    /// skipped (its transport will see the failure itself).
    pub fn notifyListChanged(self: *Server, sink: PushSink, change: ListChange) usize {
        if (!self.push) return 0;
        const method = switch (change) {
            .tools => OriginatedMethod.@"notifications/tools/list_changed",
            .prompts => OriginatedMethod.@"notifications/prompts/list_changed",
            .resources => OriginatedMethod.@"notifications/resources/list_changed",
        }.wire();
        var sent: usize = 0;
        for (self.peers.items) |p| {
            if (!p.initialized) continue;
            const w = sink.writerFor(sink.ctx, p.peer) orelse continue;
            // One write of the whole line, as `notifyResourceUpdated` does: a
            // failure between pieces of a `print` left a fragment ahead of
            // the next message (review 2026-10-24).
            var line_buf: [128]u8 = undefined;
            const line = std.mem.print(&line_buf, "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\"}}\n", .{method}) catch unreachable;
            w.writeAll(line) catch continue;
            w.flush() catch continue;
            sent += 1;
        }
        for (self.listens.items) |l| {
            if (!l.wants(change)) continue;
            const w = sink.writerFor(sink.ctx, l.peer) orelse continue;
            writeStreamNotification(w, method, l.id_json, null) catch continue;
            sent += 1;
        }
        return sent;
    }

    /// Tell every peer subscribed to `uri` (`resources/subscribe`, or a
    /// listen's `resourceSubscriptions`) that it changed. Same rules as
    /// `notifyListChanged`.
    pub fn notifyResourceUpdated(self: *Server, sink: PushSink, uri: []const u8) usize {
        if (!self.push) return 0;
        const method = OriginatedMethod.@"notifications/resources/updated".wire();
        var sent: usize = 0;
        for (self.session_subs.items) |sub| {
            if (!std.mem.eql(u8, sub.uri, uri)) continue;
            const w = sink.writerFor(sink.ctx, sub.peer) orelse continue;
            // One write of the whole line: a failure midway must not leave a
            // fragment that corrupts the next message (review 2026-10-20 L3).
            var aw: std.Io.Writer.Allocating = .init(self.gpa);
            defer aw.deinit();
            aw.writer.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"uri\":", .{method}) catch continue;
            std.json.Stringify.encodeJsonString(uri, .{}, &aw.writer) catch continue;
            aw.writer.writeAll("}}\n") catch continue;
            flushLine(w, aw.written()) catch continue;
            sent += 1;
        }
        for (self.listens.items) |l| {
            const hit = for (l.uris) |u| {
                if (std.mem.eql(u8, u, uri)) break true;
            } else false;
            if (!hit) continue;
            const w = sink.writerFor(sink.ctx, l.peer) orelse continue;
            writeStreamNotification(w, method, l.id_json, uri) catch continue;
            sent += 1;
        }
        return sent;
    }

    /// End every open `subscriptions/listen` of `peer` gracefully: the
    /// completion result each request was waiting for (subscriptions.mdx
    /// "Graceful Closure"), e.g. at shutdown. Returns how many were ended.
    pub fn endSubscriptions(self: *Server, out: *std.Io.Writer, peer: u64) Error!usize {
        var n: usize = 0;
        var i: usize = self.listens.items.len;
        while (i > 0) {
            i -= 1;
            const l = self.listens.items[i];
            if (l.peer != peer) continue;
            _ = self.listens.swapRemove(i);
            defer l.free(self.gpa);
            var aw: std.Io.Writer.Allocating = .init(self.gpa);
            defer aw.deinit();
            buildListenClose(&aw.writer, l.id_json, &self.info) catch return error.OutOfMemory;
            try flushLine(out, aw.written());
            n += 1;
        }
        return n;
    }

    /// Remove a tool from the catalog (dynamic servers; follow with
    /// `notifyListChanged(.., .tools)`). Whether it was registered.
    pub fn removeTool(self: *Server, name: []const u8) bool {
        const i = self.findTool(name) orelse return false;
        _ = self.tools.orderedRemove(i);
        self.tool_checks.orderedRemove(i).deinit(self.gpa);
        return true;
    }

    /// Remove a static resource (`notifyListChanged(.., .resources)` after).
    pub fn removeResource(self: *Server, uri: []const u8) bool {
        for (self.resources.items, 0..) |r, i| {
            if (std.mem.eql(u8, r.uri, uri)) {
                _ = self.resources.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Remove a resource template by its `uri_template`.
    pub fn removeResourceTemplate(self: *Server, uri_template_text: []const u8) bool {
        for (self.resource_templates.items, 0..) |rt, i| {
            if (std.mem.eql(u8, rt.uri_template, uri_template_text)) {
                _ = self.resource_templates.orderedRemove(i);
                _ = self.template_parsed.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Remove a prompt (`notifyListChanged(.., .prompts)` after).
    pub fn removePrompt(self: *Server, name: []const u8) bool {
        for (self.prompts.items, 0..) |pr, i| {
            if (std.mem.eql(u8, pr.name, name)) {
                _ = self.prompts.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    fn buildDiscoverResult(self: *const Server, jw: *std.json.Stringify) std.Io.Writer.Error!void {
        try beginResult(jw, true);
        try jw.objectField("supportedVersions");
        try jw.write(all_versions[0..]);
        try jw.objectField("capabilities");
        try jw.beginObject();
        try jw.objectField("tools");
        try jw.beginObject();
        try self.writePushFlag(jw, "listChanged");
        try jw.endObject();
        if (self.resources.items.len != 0 or self.resource_templates.items.len != 0) {
            try jw.objectField("resources");
            try jw.beginObject();
            try self.writePushFlag(jw, "subscribe");
            try self.writePushFlag(jw, "listChanged");
            try jw.endObject();
        }
        if (self.prompts.items.len != 0) {
            try jw.objectField("prompts");
            try jw.beginObject();
            try self.writePushFlag(jw, "listChanged");
            try jw.endObject();
        }
        if (self.offersCompletions()) {
            try jw.objectField("completions");
            try jw.beginObject();
            try jw.endObject();
        }
        try self.writeCapabilityExtras(jw);
        try jw.endObject();
        if (self.info.instructions) |instr| {
            try jw.objectField("instructions");
            try jw.write(instr);
        }
        try endResult(jw, &self.info, true, self.list_cache);
    }

    fn handleInitialize(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64) Error!void {
        // Extract the client's requested protocolVersion (if any) and echo it
        // back when supported; otherwise answer with our latest.
        var requested: ?[]const u8 = null;
        var caps: ?std.json.Value = null;
        var client_info_raw: ?std.json.Value = null;
        if (params_opt) |params| {
            if (params == .object) {
                if (params.object.get("protocolVersion")) |pv| {
                    if (pv == .string) requested = pv.string;
                }
                caps = params.object.get("capabilities");
                client_info_raw = params.object.get("clientInfo");
            }
        }
        const version = negotiateVersion(requested);
        const parsed_client_info = ClientInfo.parse(client_info_raw);
        // Record what the CLIENT can do: this is the gate on every server→client
        // request (see `ClientCapabilities`). A re-`initialize` replaces it
        // wholesale — capabilities never accumulate across handshakes — and it
        // is recorded against THIS peer, never against the `Server` (see
        // `PeerState`): one session's handshake must not move another's gate.
        const slot = self.peerSlot(peer) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooManyPeers => return sendError(arena, out, id, error_code.internal_error, "too many peers"),
        };
        slot.negotiated_version = version;
        slot.capabilities = ClientCapabilities.parse(caps);
        // `clientInfo`'s strings live on this call's arena — dupe onto `gpa`
        // BEFORE touching `slot.client` so a dupe failure (OOM) never frees
        // the peer's previous, still-valid copy.
        var new_client: ?ClientInfo = null;
        if (parsed_client_info) |ci| new_client = try ci.dupe(self.gpa, self.max_client_info_field_len);
        if (slot.client) |old| old.free(self.gpa);
        slot.client = new_client;

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
        try jw.write(self.push);
        try jw.endObject();
        // Spec (basic/lifecycle.mdx capability table + the ServerCapabilities
        // schema doc comments): `resources`/`prompts` are "present if the
        // server offers any" -- so a server with an empty catalog must not
        // advertise the capability at all, or a spec-conformant client (which
        // "MUST only use capabilities that were successfully negotiated") may
        // call `resources/list`/`prompts/list` expecting real content. `tools`
        // is left unconditional on purpose (unchanged behavior); see SPEC.md.
        if (self.resources.items.len != 0 or self.resource_templates.items.len != 0) {
            try jw.objectField("resources");
            try jw.beginObject();
            try jw.objectField("subscribe");
            try jw.write(self.push);
            try jw.objectField("listChanged");
            try jw.write(self.push);
            try jw.endObject();
        }
        if (self.prompts.items.len != 0) {
            try jw.objectField("prompts");
            try jw.beginObject();
            try jw.objectField("listChanged");
            try jw.write(self.push);
            try jw.endObject();
        }
        if (self.offersCompletions()) {
            try jw.objectField("completions");
            try jw.beginObject();
            try jw.endObject();
        }
        try self.writeCapabilityExtras(jw);
        try jw.endObject();
        try jw.objectField("serverInfo");
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(self.info.name);
        try jw.objectField("title");
        try jw.write(self.info.title orelse self.info.name);
        try jw.objectField("version");
        try jw.write(self.info.version);
        try writeImplementationExtras(jw, &self.info);
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
    ///
    /// Tools come out in registration order, which is what 2026-07-28 asks
    /// for ("SHOULD return tools in a deterministic order", for client caches
    /// and LLM prompt-cache hits): the same registrations give the same bytes.
    fn buildToolsList(self: *const Server, arena: std.mem.Allocator, jw: *std.json.Stringify, start: usize, end: usize) !void {
        try jw.objectField("tools");
        try jw.beginArray();
        for (self.tools.items[start..end], self.tool_checks.items[start..end]) |t, check| {
            try jw.beginObject();
            try jw.objectField("name");
            try jw.write(t.name);
            try writeTitleIcons(jw, t.title, t.icons);
            try jw.objectField("description");
            try jw.write(t.description);
            try jw.objectField("inputSchema");
            if (check.input_json) |j| try jw.print("{s}", .{j}) else try writeRawJson(arena, jw, t.input_schema);
            if (t.output_schema.len != 0) {
                try jw.objectField("outputSchema");
                if (check.output_json) |j| try jw.print("{s}", .{j}) else try writeRawJson(arena, jw, t.output_schema);
            }
            if (t.annotations) |a| try writeToolAnnotations(jw, a);
            try writeMetaField(arena, jw, t.meta_json);
            try jw.endObject();
        }
        try jw.endArray();
    }

    /// The four list methods, one path: the request's `cursor` (an opaque
    /// token this server minted, `ListKind.cursor`) picks the first entry,
    /// `page_size` the page, and `nextCursor` is emitted while entries remain.
    /// With `page_size` 0 the whole catalog is one page and no `nextCursor`
    /// is ever written — the answers before pagination existed. A cursor that
    /// is not one of ours for this list is -32602 (pagination.mdx: "Invalid
    /// cursors SHOULD result in an error with code -32602").
    fn handleList(self: *const Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params: ?std.json.Value, modern: bool, kind: ListKind) Error!void {
        const len = switch (kind) {
            .tools => self.tools.items.len,
            .resources => self.resources.items.len,
            .templates => self.resource_templates.items.len,
            .prompts => self.prompts.items.len,
        };
        var start: usize = 0;
        // Pagination off: this server never minted a cursor, so any cursor is
        // ignored, as before pagination existed (the spec's own requests carry
        // an illustrative one).
        if (self.page_size != 0) if (params) |p| if (p == .object) if (p.object.get("cursor")) |c| switch (c) {
            .null => {},
            .string => |s| start = kind.decodeCursor(s, len) orelse
                return sendError(arena, out, id, error_code.invalid_params, "Invalid cursor"),
            else => return sendError(arena, out, id, error_code.invalid_params, "Invalid cursor"),
        };
        const end = if (self.page_size == 0) len else @min(len, start +| self.page_size);

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        self.buildList(arena, &jw, modern, kind, start, end, len) catch |err| switch (err) {
            error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
            // A registered schema or `_meta` literal that is not valid JSON is
            // a server-side defect — surface it as -32603, don't crash.
            else => return sendError(arena, out, id, error_code.internal_error, kind.buildFailure()),
        };
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn buildList(self: *const Server, arena: std.mem.Allocator, jw: *std.json.Stringify, modern: bool, kind: ListKind, start: usize, end: usize, len: usize) !void {
        try beginResult(jw, modern);
        switch (kind) {
            .tools => try self.buildToolsList(arena, jw, start, end),
            .resources => try self.buildResourcesList(arena, jw, start, end),
            .templates => try self.buildTemplatesList(arena, jw, start, end),
            .prompts => try self.buildPromptsList(arena, jw, start, end),
        }
        if (end < len) {
            try jw.objectField("nextCursor");
            try jw.write(try kind.cursor(arena, end));
        }
        try endResult(jw, &self.info, modern, self.list_cache);
    }

    fn handleCall(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64, modern: ?*const ModernRequest) Error!void {
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
        const tool_index = self.findTool(name_v.string) orelse {
            return sendError(arena, out, id, error_code.invalid_params, "Unknown tool");
        };
        const tool = &self.tools.items[tool_index];
        const check = &self.tool_checks.items[tool_index];

        const args: std.json.Value = params.object.get("arguments") orelse .null;
        // `arguments` is an object in every schema revision. Anything else
        // reached a tool with no compiled input schema as `args`, where
        // `lookupArg` reads every argument as absent (review 2026-10-24).
        if (args != .null and args != .object) return sendError(arena, out, id, error_code.invalid_params, "Invalid arguments");

        // The SDKs' convention (TS `tools.md` "Send arguments the schema
        // rejects"): arguments that fail `inputSchema` never reach the handler,
        // and the answer is a tool result with `isError:true`, so the model
        // reads why and retries. Absent arguments are checked as `{}`.
        if (self.validate_tool_io) if (check.input) |*schema| {
            const instance: std.json.Value = if (args == .null) .{ .object = .empty } else args;
            if (try schema.validate(arena, instance)) |f| {
                const msg = try arena.print("Input validation error: Invalid arguments for tool {s}: {s}{s}{s}", .{
                    tool.name, f.pointer, if (f.pointer.len != 0) ": " else "", f.message,
                });
                return sendToolResult(arena, out, id, msg, .{
                    .allow_structured = false,
                    .is_error = true,
                    .server_info = if (modern != null) &self.info else null,
                });
            }
        };

        const req_meta = requestMeta(params.object);
        const prog = progressFrom(arena, out, req_meta);

        const round = InputRound.fromParams(arena, modern, "tools/call", tool.name, params.object) catch |err| {
            return sendInputParamsError(arena, out, id, err);
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
            .modern = modern,
            .input = round,
            .meta = req_meta,
        };
        // Registered only while the handler runs: a cancel that arrives
        // later finds nothing (the spec's "already completed" case). Ids
        // longer than `cancelInflight`'s key buffer cannot be cancelled.
        const id_json: ?[]const u8 = if (id) |v| (std.json.Stringify.valueAlloc(arena, v, .{}) catch null) else null;
        const registered = if (id_json) |k| k.len <= 128 and self.registerInflight(peer, k, &call.cancel_flag) else false;
        // What the answer needs from the registration, copied out: a handler
        // may `addTool`/`removeTool` (a dynamic catalog), which moves or frees
        // `tool` and `check` (review 2026-10-20 M3).
        const tool_name = tool.name;
        const allow_structured = tool.allow_structured;
        const has_output_schema = tool.output_schema.len != 0;
        const is_error = tool.handler(tool.ctx, &call);
        if (registered) self.unregisterInflight(&call.cancel_flag);
        if (call.cancelled()) return; // cancellation.mdx: no response
        if (call.protocol_error) |pe| return sendProtocolError(arena, out, id, pe);
        if (call.input.inputRequired()) return self.sendInputRequired(arena, out, id, &call.input);
        // Re-resolved after the handler; a tool that removed itself answers
        // unchecked.
        const out_check: ?*const schema_check.Schema = if (self.findTool(tool_name)) |i| (if (self.tool_checks.items[i].output) |*sc| sc else null) else null;
        if (!is_error and self.validate_tool_io and allow_structured) if (out_check) |schema| {
            if (try outputFailure(arena, schema, tool_buf.items, modern != null)) |msg| {
                return sendToolResult(arena, out, id, msg, .{
                    .allow_structured = false,
                    .is_error = true,
                    .server_info = if (modern != null) &self.info else null,
                });
            }
        };
        try sendToolResult(arena, out, id, tool_buf.items, .{
            .allow_structured = allow_structured,
            .is_error = is_error,
            .blocks = call.blocks.items,
            .any_structured_value = modern != null and has_output_schema,
            .server_info = if (modern != null) &self.info else null,
        });
    }

    fn buildResourcesList(self: *const Server, arena: std.mem.Allocator, jw: *std.json.Stringify, start: usize, end: usize) !void {
        try jw.objectField("resources");
        try jw.beginArray();
        for (self.resources.items[start..end]) |r| {
            try jw.beginObject();
            try jw.objectField("uri");
            try jw.write(r.uri);
            try jw.objectField("name");
            try jw.write(r.name);
            try writeTitleIcons(jw, r.title, r.icons);
            if (r.description.len != 0) {
                try jw.objectField("description");
                try jw.write(r.description);
            }
            if (r.mime_type.len != 0) {
                try jw.objectField("mimeType");
                try jw.write(r.mime_type);
            }
            if (r.annotations) |a| try writeAnnotations(jw, a);
            if (r.size) |sz| {
                try jw.objectField("size");
                try jw.write(sz);
            }
            try writeMetaField(arena, jw, r.meta_json);
            try jw.endObject();
        }
        try jw.endArray();
    }

    fn buildTemplatesList(self: *const Server, arena: std.mem.Allocator, jw: *std.json.Stringify, start: usize, end: usize) !void {
        try jw.objectField("resourceTemplates");
        try jw.beginArray();
        for (self.resource_templates.items[start..end]) |t| {
            try jw.beginObject();
            try jw.objectField("uriTemplate");
            try jw.write(t.uri_template);
            try jw.objectField("name");
            try jw.write(t.name);
            try writeTitleIcons(jw, t.title, t.icons);
            if (t.description.len != 0) {
                try jw.objectField("description");
                try jw.write(t.description);
            }
            if (t.mime_type.len != 0) {
                try jw.objectField("mimeType");
                try jw.write(t.mime_type);
            }
            if (t.annotations) |a| try writeAnnotations(jw, a);
            try writeMetaField(arena, jw, t.meta_json);
            try jw.endObject();
        }
        try jw.endArray();
    }

    /// `resources/read`: validate params, resolve the uri (exact resource
    /// match first, then template handlers in registration order), and send
    /// the contents the handler filled. Unresolvable uri => -32002 on the
    /// session path; -32602 with `data.uri` on a 2026-07-28 request, which
    /// forbids -32002 (server/resources.mdx "Error Handling").
    fn handleResourcesRead(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64, modern_req: ?*const ModernRequest) Error!void {
        const modern = modern_req != null;
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

        const round = InputRound.fromParams(arena, modern_req, "resources/read", uri_v.string, params.object) catch |err| {
            return sendInputParamsError(arena, out, id, err);
        };

        const req_meta = requestMeta(params.object);
        var req = ResourceRequest{
            .arena = arena,
            .uri = uri_v.string,
            .cache = self.read_cache,
            .input = round,
            .progress = progressFrom(arena, out, req_meta),
            .server = self,
            .peer = peer,
            .modern = modern_req,
            .meta = req_meta,
        };
        const found = blk: {
            if (self.findResource(req.uri)) |r| break :blk r.handler(r.ctx, &req);
            // Indexed, re-read every round: a template handler may add or
            // remove templates, and slices captured once would then be freed
            // or shifted under the loop (review 2026-10-24).
            var k: usize = 0;
            while (k < self.resource_templates.items.len) : (k += 1) {
                const t = self.resource_templates.items[k];
                const parsed = self.template_parsed.items[k];
                const handler = t.handler orelse continue;
                req.vars = if (parsed) |pt| try pt.match(arena, req.uri) else null;
                if (handler(t.ctx, &req) or req.protocol_error != null) break :blk true;
                // A declining template may have written partial contents, a
                // caching hint or an input request before bailing — discard
                // them before trying the next one.
                req.contents.clearRetainingCapacity();
                req.cache = self.read_cache;
                req.input.resetAsked();
            }
            break :blk false;
        };
        if (req.protocol_error) |pe| return sendProtocolError(arena, out, id, pe);
        if (req.input.inputRequired()) return self.sendInputRequired(arena, out, id, &req.input);
        if (!found) {
            if (modern) return sendErrorWithData(arena, out, id, error_code.invalid_params, "Resource not found", .{ .uri = req.uri });
            return sendError(arena, out, id, error_code.resource_not_found, "Resource not found");
        }

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildReadResult(&jw, &req, &self.info, modern) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    fn buildPromptsList(self: *const Server, arena: std.mem.Allocator, jw: *std.json.Stringify, start: usize, end: usize) !void {
        try jw.objectField("prompts");
        try jw.beginArray();
        for (self.prompts.items[start..end]) |p| {
            try jw.beginObject();
            try jw.objectField("name");
            try jw.write(p.name);
            try writeTitleIcons(jw, p.title, p.icons);
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
            try writeMetaField(arena, jw, p.meta_json);
            try jw.endObject();
        }
        try jw.endArray();
    }

    /// `prompts/get`: validate params + the declared required arguments
    /// (-32602 on any miss, so a handler never sees an incomplete required
    /// set), dispatch to the handler, send the rendered messages.
    fn handlePromptsGet(self: *Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, params_opt: ?std.json.Value, peer: u64, modern_req: ?*const ModernRequest) Error!void {
        const modern = modern_req != null;
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

        const round = InputRound.fromParams(arena, modern_req, "prompts/get", prompt.name, params.object) catch |err| {
            return sendInputParamsError(arena, out, id, err);
        };

        const req_meta = requestMeta(params.object);
        var req = PromptRequest{
            .arena = arena,
            .args = args,
            .input = round,
            .progress = progressFrom(arena, out, req_meta),
            .server = self,
            .peer = peer,
            .modern = modern_req,
            .meta = req_meta,
        };
        // A copy, taken before the handler runs: `prompt` points into
        // `self.prompts`, which a handler that calls `addPrompt` (reallocates)
        // or `removePrompt` (shifts) invalidates -- the use-after-free the
        // tools path already guards against (review 2026-10-24). The slices
        // inside are the application's and outlive the server.
        const entry = prompt.*;
        const ok = entry.handler(entry.ctx, &req);
        if (req.protocol_error) |pe| return sendProtocolError(arena, out, id, pe);
        if (req.input.inputRequired()) return self.sendInputRequired(arena, out, id, &req.input);
        if (!ok) {
            return sendError(arena, out, id, error_code.internal_error, "Prompt failed");
        }

        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildPromptResult(&jw, &entry, &req, &self.info, modern) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }

    /// Answer a request whose handler asked for input with an
    /// `InputRequiredResult` instead of its normal result.
    fn sendInputRequired(self: *const Server, arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, round: *const InputRound) Error!void {
        var aw: std.Io.Writer.Allocating = .init(arena);
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        buildInputRequiredResult(&jw, round, &self.info) catch return error.OutOfMemory;
        try sendResultRaw(arena, out, id, aw.written());
    }
};

/// The two lines of a `subscriptions/listen` answer (see `Server.handleListen`):
/// the acknowledgment with an empty filter, then the completion result, both
/// carrying the request's id as `subscriptionId`.
fn flagTrue(obj: std.json.ObjectMap, key: []const u8) bool {
    const v = obj.get(key) orelse return false;
    return v == .bool and v.bool;
}

/// The acknowledgment of a held-open listen, echoing the honoured filter.
fn buildListenAck(w: *std.Io.Writer, l: Listen) std.Io.Writer.Error!void {
    try w.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"_meta\":{{", .{OriginatedMethod.@"notifications/subscriptions/acknowledged".wire()});
    try std.json.Stringify.encodeJsonString(meta_key.subscription_id, .{}, w);
    try w.print(":{s}}},\"notifications\":", .{l.id_json});
    var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
    try jw.beginObject();
    if (l.tools) {
        try jw.objectField("toolsListChanged");
        try jw.write(true);
    }
    if (l.prompts) {
        try jw.objectField("promptsListChanged");
        try jw.write(true);
    }
    if (l.resources) {
        try jw.objectField("resourcesListChanged");
        try jw.write(true);
    }
    if (l.uris.len != 0) {
        try jw.objectField("resourceSubscriptions");
        try jw.write(l.uris);
    }
    try jw.endObject();
    try w.writeAll("}}\n");
}

/// One notification on a listen stream: `_meta.subscriptionId` first, then
/// `uri` for a resource update.
fn writeStreamNotification(out: *std.Io.Writer, method: []const u8, id_json: []const u8, uri: ?[]const u8) std.Io.Writer.Error!void {
    // Built whole, then written once (review 2026-10-20 L3); a uri is at most
    // `max_subscription_uri_len` (escaping can grow it 6×, still bounded).
    var buf: [6 * max_subscription_uri_len + 512]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&buf);
    const w = &fw;
    try w.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"_meta\":{{", .{method});
    try std.json.Stringify.encodeJsonString(meta_key.subscription_id, .{}, w);
    try w.print(":{s}}}", .{id_json});
    if (uri) |u| {
        try w.writeAll(",\"uri\":");
        try std.json.Stringify.encodeJsonString(u, .{}, w);
    }
    try w.writeAll("}}\n");
    try flushLine(out, w.buffered());
}

/// The graceful-close result of a listen (subscriptions.mdx).
fn buildListenClose(w: *std.Io.Writer, id_json: []const u8, info: *const Info) std.Io.Writer.Error!void {
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{{\"resultType\":\"complete\",\"_meta\":{{", .{id_json});
    try std.json.Stringify.encodeJsonString(meta_key.subscription_id, .{}, w);
    try w.print(":{s},", .{id_json});
    try std.json.Stringify.encodeJsonString(meta_key.server_info, .{}, w);
    try w.writeByte(':');
    var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
    try writeImplementation(&jw, info);
    try w.writeAll("}}}\n");
}

fn buildListenLines(w: *std.Io.Writer, id: std.json.Value, info: *const Info) std.Io.Writer.Error!void {
    try w.print("{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{{\"_meta\":{{", .{OriginatedMethod.@"notifications/subscriptions/acknowledged".wire()});
    try std.json.Stringify.encodeJsonString(meta_key.subscription_id, .{}, w);
    try w.writeByte(':');
    try writeId(w, id);
    try w.writeAll("},\"notifications\":{}}}\n");

    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.writeAll(",\"result\":{\"resultType\":\"complete\",\"_meta\":{");
    try std.json.Stringify.encodeJsonString(meta_key.subscription_id, .{}, w);
    try w.writeByte(':');
    try writeId(w, id);
    try w.writeByte(',');
    try std.json.Stringify.encodeJsonString(meta_key.server_info, .{}, w);
    try w.writeByte(':');
    var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
    try writeImplementation(&jw, info);
    try w.writeAll("}}}\n");
}

/// -32602 for an `inputResponses` that is not an object or a `requestState`
/// that is not a string (mrtr.mdx "Error Handling").
fn sendInputParamsError(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, err: error{ InvalidInputResponses, InvalidRequestState }) Error!void {
    return sendError(arena, out, id, error_code.invalid_params, switch (err) {
        error.InvalidInputResponses => "Invalid inputResponses",
        error.InvalidRequestState => "Invalid requestState",
    });
}

/// Serialize one `resources/read` result: `{"contents":[{uri, mimeType?,
/// text|blob}, …]}` — `blob` carries the base64 the handler's `blob()` call
/// already encoded.
fn buildReadResult(jw: *std.json.Stringify, req: *const ResourceRequest, info: *const Info, modern: bool) std.Io.Writer.Error!void {
    try beginResult(jw, modern);
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
    try endResult(jw, info, modern, req.cache);
}

/// Serialize one `prompts/get` result: `{description?, messages:[{role,
/// content:{type:"text", text}}, …]}` — description comes from the
/// registration (omitted when "").
fn buildCompleteResult(jw: *std.json.Stringify, req: *const CompletionRequest, info: *const Info, modern: bool) std.Io.Writer.Error!void {
    try beginResult(jw, modern);
    try jw.objectField("completion");
    try jw.beginObject();
    try jw.objectField("values");
    const n = @min(req.values.items.len, max_completion_values);
    try jw.write(req.values.items[0..n]);
    if (req.total) |tot| {
        try jw.objectField("total");
        try jw.write(tot);
    }
    try jw.objectField("hasMore");
    try jw.write(req.has_more or req.values.items.len > max_completion_values);
    try jw.endObject();
    try endResult(jw, info, modern, null);
}

fn buildCustomResult(jw: *std.json.Stringify, members: std.json.ObjectMap, info: *const Info, modern: bool) std.Io.Writer.Error!void {
    try beginResult(jw, modern);
    var it = members.iterator();
    while (it.next()) |e| {
        // `endResult` writes the 2026-07-28 `_meta` (serverInfo); a handler's
        // own `_meta` and `resultType` give way to it there.
        if (modern and (std.mem.eql(u8, e.key_ptr.*, "_meta") or std.mem.eql(u8, e.key_ptr.*, "resultType"))) continue;
        try jw.objectField(e.key_ptr.*);
        try jw.write(e.value_ptr.*);
    }
    try endResult(jw, info, modern, null);
}

fn buildPromptResult(jw: *std.json.Stringify, prompt: *const Prompt, req: *const PromptRequest, info: *const Info, modern: bool) std.Io.Writer.Error!void {
    try beginResult(jw, modern);
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
        try writeContent(jw, m.content);
        try jw.endObject();
    }
    try jw.endArray();
    // Not a cacheable method: `prompts/get` renders from the caller's
    // arguments, and the spec lists no caching hint for it.
    try endResult(jw, info, modern, null);
}

// ── response senders (build one line on the arena, write it, flush) ─────────

// Deliberately `std.Io.Writer.Error!void`, not the module's `Error`: this
// only ever calls writer functions, so it must not carry `Canceled` -- doing
// so would force it into every caller's error set, including `SendError`
// (sampling/elicitation senders), which never touches a canceled read.
fn flushLine(out: *std.Io.Writer, line: []const u8) std.Io.Writer.Error!void {
    try out.writeAll(line);
    try out.flush();
}

fn sendError(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, code: i32, msg: []const u8) Error!void {
    var aw: std.Io.Writer.Allocating = .init(arena);
    writeErrorLine(&aw.writer, id, code, msg) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

/// An error response with a `data` member — the 2026-07-28 shapes that carry
/// one (`UnsupportedProtocolVersionError`, resource-not-found's `uri`).
/// `data` is any value `std.json.Stringify` can write, so every string in it
/// is escaped the same way as the rest of the line.
fn sendErrorWithData(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, code: i32, msg: []const u8, data: anytype) Error!void {
    var aw: std.Io.Writer.Allocating = .init(arena);
    buildErrorWithData(&aw.writer, id, code, msg, data) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

fn buildErrorWithData(w: *std.Io.Writer, id: ?std.json.Value, code: i32, msg: []const u8, data: anytype) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
    try std.json.Stringify.encodeJsonString(msg, .{}, w);
    try w.writeAll(",\"data\":");
    try std.json.Stringify.value(data, .{}, w);
    try w.writeAll("}}\n");
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
const ToolResultOptions = struct {
    allow_structured: bool,
    is_error: bool,
    /// `ToolCall.add`'s blocks, after the text one.
    blocks: []const Content = &.{},
    /// 2026-07-28 call to a tool with an `output_schema`: `structuredContent`
    /// may be any JSON value, not only an object (see `Tool`).
    any_structured_value: bool = false,
    /// Non-null exactly for a 2026-07-28 call: adds `resultType` and
    /// `_meta.serverInfo`.
    server_info: ?*const Info = null,
};

fn sendToolResult(arena: std.mem.Allocator, out: *std.Io.Writer, id: ?std.json.Value, text: []const u8, opts: ToolResultOptions) Error!void {
    var aw: std.Io.Writer.Allocating = .init(arena);
    buildToolResultLine(arena, &aw.writer, id, text, opts) catch return error.OutOfMemory;
    try flushLine(out, aw.written());
}

fn buildToolResultLine(gpa: std.mem.Allocator, w: *std.Io.Writer, id: ?std.json.Value, text: []const u8, opts: ToolResultOptions) std.Io.Writer.Error!void {
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeId(w, id);
    try w.writeAll(",\"result\":{");
    if (opts.server_info != null) try w.writeAll("\"resultType\":\"complete\",");
    try w.writeAll("\"content\":[");
    const text_block = text.len != 0 or opts.blocks.len == 0;
    if (text_block) {
        try w.writeAll("{\"type\":\"text\",\"text\":");
        try std.json.Stringify.encodeJsonString(text, .{}, w);
        try w.writeAll("}");
    }
    for (opts.blocks, 0..) |b, i| {
        if (text_block or i != 0) try w.writeAll(",");
        var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
        try writeContent(&jw, b);
    }
    try w.writeAll("]");
    const structured = opts.allow_structured and
        (isSingleJsonObject(gpa, text) or (opts.any_structured_value and isSingleJsonValue(gpa, text)));
    if (structured) {
        try w.writeAll(",\"structuredContent\":");
        try writeStrippingNewlines(w, text);
    }
    try w.writeAll(if (opts.is_error) ",\"isError\":true" else ",\"isError\":false");
    if (opts.server_info) |info| {
        try w.writeAll(",\"_meta\":{");
        try std.json.Stringify.encodeJsonString(meta_key.server_info, .{}, w);
        try w.writeAll(":");
        var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
        try writeImplementation(&jw, info);
        try w.writeAll("}");
    }
    try w.writeAll("}}\n");
}

/// Emit a raw JSON-Schema literal through the serializer: parse it to a Value
/// and `write` it, so it is validated and re-serialized in the same stream
/// (keeping `jw`'s object/array state consistent).
fn writeRawJson(arena: std.mem.Allocator, jw: *std.json.Stringify, raw: []const u8) !void {
    if (!literalDepthOk(raw)) return error.SyntaxError;
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
/// is handled). Returns the line slice (without '\n'), or null when no
/// *complete* line is available: EOF, a read failure (including a `std.Io`
/// cancelation reaching `takeByte` as an ordinary error -- see `serve`'s doc
/// comment for how a caller recovers that distinction), or a line that would
/// exceed `max_line_len`.
///
/// In every one of those cases any partial line already buffered is
/// discarded, never handed back as though it were complete. A truncated
/// fragment is not valid JSON-RPC; answering it would turn it into a
/// `-32700` parse-error response written to a peer that, in the EOF/cancel
/// case, is already gone -- matching the official Python SDK (silently
/// discards a trailing unterminated fragment on EOF) and the ecosystem
/// consensus the Rust SDK arrived at the hard way: it briefly answered
/// unparseable stdio input (PR #833) and reverted it (PR #940) after that
/// produced an error-bounce loop with the peer (issue #938).
fn readLine(gpa: std.mem.Allocator, reader: *std.Io.Reader, buf: *std.ArrayList(u8)) Error!?[]u8 {
    buf.clearRetainingCapacity();
    while (true) {
        const byte = reader.takeByte() catch return null;
        if (byte == '\n') return buf.items;
        // Cap the buffer: an unterminated/over-long line is discarded like
        // any other read failure, bounding memory to max_line_len.
        if (buf.items.len >= max_line_len) return null;
        try buf.append(gpa, byte);
    }
}

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// True when `text` is exactly one top-level JSON object (`{ … }`) followed
/// by nothing but whitespace — the only shape MCP `structuredContent`
/// accepts — **and the whole of it is valid JSON**.
///
/// The second half is why this delegates to `std.json` instead of matching
/// brackets by hand. A depth counter cannot distinguish the bracket *kinds*,
/// so `{]`, `{"a":1]` and `{[}]` all counted as one balanced top-level object
/// and were spliced verbatim into `structuredContent`, emitting a response
/// line no client can parse — reachable from any pass-through tool, because
/// `allow_structured` defaults to true and the text is the tool's output.
/// Nor can a counter see a raw control character inside a string: that is
/// invalid JSON which the later newline-strip silently *repaired* into valid
/// JSON carrying a different value than the text block beside it.
///
/// Validating here is what makes the strip safe: in a document `std.json`
/// accepts, a `\n`/`\r` can only be insignificant whitespace between tokens
/// (RFC 8259 §7 forbids unescaped %x00-1F inside a string), so removing it
/// cannot change the value.
fn isSingleJsonObject(gpa: std.mem.Allocator, text: []const u8) bool {
    var i: usize = 0;
    while (i < text.len and isWs(text[i])) : (i += 1) {}
    if (i >= text.len or text[i] != '{') return false;
    // `validate` accepts exactly one top-level value plus trailing
    // whitespace, so NDJSON and any trailing garbage are refused here too.
    return std.json.validate(gpa, text) catch false;
}

/// True when `text` is exactly one JSON value of any kind plus whitespace —
/// the 2026-07-28 `structuredContent` shape. Same `std.json` check as
/// `isSingleJsonObject`, for the same reasons (it is what makes the newline
/// strip safe), minus the leading-`{` requirement.
fn isSingleJsonValue(gpa: std.mem.Allocator, text: []const u8) bool {
    return std.json.validate(gpa, text) catch false;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ── tests ───────────────────────────────────────────────────────────────────

test "truncateUtf8 cuts at a codepoint boundary, and at the bound itself when the bytes are not UTF-8" {
    try testing.expectEqualStrings("ab", truncateUtf8("ab\u{e9}", 3)); // é is 2 bytes
    try testing.expectEqualStrings("ab\u{e9}", truncateUtf8("ab\u{e9}x", 4));
    // A `std.json` string is valid UTF-8, so no peer reaches this today; the
    // bound is the point of the function and must not depend on that.
    try testing.expectEqual(@as(usize, 3), truncateUtf8("\xff\xfe\xfd\xfc\xfb", 3).len);
}

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

// A bare `pub const x = @import(...)` does not pull x's tests in (CONVENTIONS §6).
test {
    _ = header_annotations;
    _ = schema_check;
    _ = uri_template;
    _ = @import("sdk_oracle.zig");
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

test "jsonrpc: a non-conforming id shape is -32600 with a NULL id, never echoed back" {
    // JSON-RPC 2.0 §4 allows String | Number | NULL. The serializer will
    // happily mirror an object or an array, which is what made this worth
    // checking at the boundary instead of trusting the shape.
    var s = testServer(null);
    defer s.deinit();
    const bad_ids = [_][]const u8{
        "{}",
        "{\"a\":1}",
        "[]",
        "[1,2]",
        "true",
        "false",
    };
    inline for (bad_ids) |bad| {
        // As a request…
        try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":" ++ bad ++ ",\"method\":\"ping\"}",
            \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request id"}}
            \\
        );
        // …and as a message with no method at all, where the id used to be
        // echoed verbatim in the "Missing method" error.
        try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":" ++ bad ++ "}",
            \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request id"}}
            \\
        );
        // …and as a response-shaped message, which must never be answered
        // with anything that could bounce: it correlates to no request of
        // ours, so it is refused once, with a null id.
        try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":" ++ bad ++ ",\"result\":{}}",
            \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request id"}}
            \\
        );
    }

    // The three legal shapes still pass through untouched — this is the half
    // that fails if the check is written too strictly.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":\"s-1\",\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":"s-1","result":{}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":-12,\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":-12,"result":{}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":1.5,"result":{}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":null,"result":{}}
        \\
    );
    // A notification (no id at all) is still silent, not an id error.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}", "");
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
        const expected = try testing.allocator.print(
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
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\
    );
    // Unsupported revision -> answer with our latest.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\
    );
    // No params at all -> latest, no crash.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize"}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\
    );
}

test "initialize: instructions omitted when null; title override" {
    var s = Server.init(testing.allocator, .{ .name = "bare", .version = "0.1.0", .title = "Bare Server" });
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"bare","title":"Bare Server","version":"0.1.0"}}}
        \\
    );
}

test "initialize: resources capability advertised only when a resource is registered" {
    var lib = TestLibrary{};
    var s = Server.init(testing.allocator, .{ .name = "res-srv", .version = "0.1.0" });
    defer s.deinit();
    try s.addResource(.{
        .uri = "mem://readme",
        .name = "readme",
        .handler = &readmeReader,
        .ctx = &lib,
    });
    // No tool, no prompt registered: `tools` stays unconditional (unchanged
    // behavior), `resources` now appears because the catalog is non-empty,
    // `prompts` stays absent because that catalog is empty.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false}},"serverInfo":{"name":"res-srv","title":"res-srv","version":"0.1.0"}}}
        \\
    );
}

test "initialize: resources capability advertised when only a resource TEMPLATE is registered" {
    // A server may offer nothing but a resource template (no static
    // resource) -- the `resources` capability must still appear, since
    // `resources/templates/list` is part of what it promises.
    var s = Server.init(testing.allocator, .{ .name = "tmpl-srv", .version = "0.1.0" });
    defer s.deinit();
    try s.addResourceTemplate(.{
        .uri_template = "mem://file/{name}",
        .name = "file",
        .handler = &fileTemplateReader,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false}},"serverInfo":{"name":"tmpl-srv","title":"tmpl-srv","version":"0.1.0"}}}
        \\
    );
}

test "initialize: prompts capability advertised only when a prompt is registered" {
    var lib = TestLibrary{};
    var s = Server.init(testing.allocator, .{ .name = "prompt-srv", .version = "0.1.0" });
    defer s.deinit();
    try s.addPrompt(.{
        .name = "greet",
        .description = "Render a greeting request.",
        .arguments = &greet_args,
        .handler = &greetPromptHandler,
        .ctx = &lib,
    });
    // No tool, no resource registered: `resources` stays absent, `prompts`
    // now appears because the catalog is non-empty.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"prompt-srv","title":"prompt-srv","version":"0.1.0"}}}
        \\
    );
}

test "initialize: all three capabilities advertised together when all three catalogs are non-empty" {
    var app = TestApp{};
    var lib = TestLibrary{};
    var s = try libraryServer(&lib); // resources + resource templates + prompts
    defer s.deinit();
    var tool = echo_tool;
    tool.ctx = &app;
    try s.addTool(tool);
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"lib-srv","title":"lib-srv","version":"0.1.0"}}}
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
    try testing.expect(!s.clientInitialized(0));
    // This line is already the spec's own (basic/lifecycle.mdx) verbatim, byte
    // for byte -- a full spec-literal anchor, no adaptation needed.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", "");
    try testing.expect(s.clientInitialized(0));
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
    // The inputSchema requires `text`: the call is refused before the handler.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":12,"result":{"content":[{"type":"text","text":"Input validation error: Invalid arguments for tool echo: missing required property \"text\""}],"isError":true}}
        \\
    );
    try testing.expectEqual(@as(u32, 0), app.calls);
    // With validation off the handler sees the call and fails it itself.
    s.validate_tool_io = false;
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"echo","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":13,"result":{"content":[{"type":"text","text":"error: missing 'text'"}],"isError":true}}
        \\
    );
    try testing.expectEqual(@as(u32, 1), app.calls);
}

fn postsResource(_: ?*anyopaque, req: *ResourceRequest) bool {
    const id = req.variable("id") orelse return false;
    const page = req.variable("page") orelse "1";
    req.text(req.uri, "", req.arena.print("{s}:{s}", .{ id, page }) catch return false);
    return true;
}

test "resource templates: the uri's variables reach the handler (RFC 6570)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addResourceTemplate(.{ .uri_template = "users://{id}/posts{?page}", .name = "posts", .handler = postsResource });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"users://a%20b/posts?page=3"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"contents":[{"uri":"users://a%20b/posts?page=3","text":"a b:3"}]}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"users://7/posts"}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"contents":[{"uri":"users://7/posts","text":"7:1"}]}}
        \\
    );
    // Not this template's shape: the handler sees `vars == null` and declines.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"users://7/8/posts"}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32002,"message":"Resource not found"}}
        \\
    );
}

fn searchTool(_: ?*anyopaque, call: *ToolCall) bool {
    call.write(call.strArg("out") orelse "{\"hits\":1}");
    return false;
}

test "tools/call: session output must be an object; output past the step budget passes unchecked (mutation 2026-10-24)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "search",
        .description = "",
        .input_schema = "{\"type\":\"object\",\"properties\":{\"out\":{\"type\":\"string\"}}}",
        .output_schema = "{\"type\":\"object\",\"properties\":{\"xs\":{\"type\":\"array\",\"uniqueItems\":true}}}",
        .handler = searchTool,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"out":"[1]"}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Output validation error: the tool declares an outputSchema but its output is not a JSON object"}],"isError":true}}
        \\
    );
    // 3000 items are 4.5e6 pairwise compares, past the 1e6 budget: the
    // server's own output is not refused for being too big to check (M4).
    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(testing.allocator);
    try big.appendSlice(testing.allocator, "{\"xs\":[");
    for (0..3000) |k| try big.print(testing.allocator, "{s}{d}", .{ if (k == 0) "" else ",", k });
    try big.appendSlice(testing.allocator, "]}");
    var esc: std.Io.Writer.Allocating = .init(testing.allocator);
    defer esc.deinit();
    try std.json.Stringify.value(big.items, .{}, &esc.writer);
    const line = try std.fmt.allocPrint(testing.allocator, "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"search\",\"arguments\":{{\"out\":{s}}}}}}}", .{esc.written()});
    defer testing.allocator.free(line);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(line, &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(), "\"isError\":false") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "structuredContent") != null);
}

test "tools/call: arguments and structured output are checked against the tool's schemas" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "search",
        .description = "",
        .input_schema =
        \\{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","maximum":50},"out":{"type":"string"}},"required":["query"]}
        ,
        .output_schema =
        \\{"type":"object","properties":{"hits":{"type":"integer"}},"required":["hits"]}
        ,
        .handler = searchTool,
    });
    // An argument the schema rejects never reaches the handler (TS tools.md).
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"mug","limit":999}}}
    , &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(), "Input validation error: Invalid arguments for tool search: /limit: ") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"isError\":true") != null);
    // Conforming output passes with its structuredContent.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"query":"mug"}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"hits\":1}"}],"structuredContent":{"hits":1},"isError":false}}
        \\
    );
    // Output that breaks the declared outputSchema, or is not JSON at all, is
    // a tool failure, never a structuredContent the client would reject.
    aw.clearRetainingCapacity();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"query":"q","out":"{\"hits\":\"many\"}"}}}
    , &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(), "Output validation error: /hits: ") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "structuredContent") == null);
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search","arguments":{"query":"q","out":"plain text"}}}
    ,
        \\{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Output validation error: the tool declares an outputSchema but its output is not JSON"}],"isError":true}}
        \\
    );
    // A schema outside the checked subset leaves the tool unchecked.
    try s.addTool(.{ .name = "loose", .description = "", .input_schema = "{\"type\":\"object\",\"patternProperties\":{\"^x\":{\"type\":\"integer\"}},\"required\":[\"q\"]}", .handler = pageTool });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"loose","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":""}],"isError":false}}
        \\
    );
}

fn blocksTool(_: ?*anyopaque, call: *ToolCall) bool {
    // The four examples of 2025-11-25 server/tools.mdx "Tool Result", in order.
    call.add(.{ .image = .{ .data_base64 = "base64-encoded-data", .mime_type = "image/png", .annotations = .{ .audience = &.{.user}, .priority = 0.9 } } });
    call.add(.{ .audio = .{ .data_base64 = "base64-encoded-audio-data", .mime_type = "audio/wav" } });
    call.add(.{ .resource_link = .{ .uri = "file:///project/src/main.rs", .name = "main.rs", .description = "Primary application entry point", .mime_type = "text/x-rust" } });
    call.add(.{ .resource = .{
        .uri = "file:///project/src/main.rs",
        .mime_type = "text/x-rust",
        .text = "fn main() {\n    println!(\"Hello world!\");\n}",
        .annotations = .{ .audience = &.{ .user, .assistant }, .priority = 0.7, .last_modified = "2025-05-03T14:30:00Z" },
    } });
    if (call.strArg("caption")) |c| call.write(c);
    return false;
}

test "tools/call: content blocks are byte-identical to the spec's examples (tools.mdx)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "blocks", .description = "", .input_schema = "{}", .handler = blocksTool });
    // No text written: the blocks alone (each compacted from the spec page).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocks","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":"base64-encoded-data","mimeType":"image/png","annotations":{"audience":["user"],"priority":0.9}},{"type":"audio","data":"base64-encoded-audio-data","mimeType":"audio/wav"},{"type":"resource_link","uri":"file:///project/src/main.rs","name":"main.rs","description":"Primary application entry point","mimeType":"text/x-rust"},{"type":"resource","resource":{"uri":"file:///project/src/main.rs","mimeType":"text/x-rust","text":"fn main() {\n    println!(\"Hello world!\");\n}","annotations":{"audience":["user","assistant"],"priority":0.7,"lastModified":"2025-05-03T14:30:00Z"}}}],"isError":false}}
        \\
    );
    // Text written: it leads, then the blocks.
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"blocks","arguments":{"caption":"see"}}}
    , &aw.writer);
    try testing.expect(std.mem.startsWith(u8, aw.written(),
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"see"},{"type":"image",
    ));
}

fn imagePrompt(_: ?*anyopaque, req: *PromptRequest) bool {
    req.message(.user, "What is in this picture?");
    req.messageContent(.user, .{ .image = .{ .data_base64 = "iVBORw0KGgo=", .mime_type = "image/png" } });
    return true;
}

test "prompts/get: a message may carry an image block" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addPrompt(.{ .name = "pic", .handler = imagePrompt });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"pic"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"messages":[{"role":"user","content":{"type":"text","text":"What is in this picture?"}},{"role":"user","content":{"type":"image","data":"iVBORw0KGgo=","mimeType":"image/png"}}]}}
        \\
    );
}

fn searchMethod(_: ?*anyopaque, req: *MethodRequest) bool {
    const q = if (req.params == .object) (if (req.params.object.get("q")) |v| (if (v == .string) v.string else "") else "") else "";
    if (std.mem.eql(u8, q, "bad")) {
        req.write("[1]");
        return true;
    }
    if (std.mem.eql(u8, q, "boom")) return false;
    req.print("{{\"hits\":[\"{s}\"]}}", .{q});
    return true;
}

fn countNotification(ctx: ?*anyopaque, _: *MethodRequest) bool {
    const n: *u32 = @ptrCast(@alignCast(ctx.?));
    n.* += 1;
    return true;
}

test "custom methods: a vendor request is dispatched in both eras; notifications reach their handler" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    var pings: u32 = 0;
    try s.addMethod(.{ .name = "acme/search", .handler = searchMethod });
    try s.addMethod(.{ .name = "acme/legacy", .handler = searchMethod, .stateless = false });
    try s.addNotification(.{ .name = "notifications/acme/ping", .handler = countNotification, .ctx = &pings });
    try testing.expectError(error.ReservedMethod, s.addMethod(.{ .name = "tools/call", .handler = searchMethod }));
    try testing.expectError(error.DuplicateMethod, s.addMethod(.{ .name = "acme/search", .handler = searchMethod }));
    try testing.expectError(error.ReservedMethod, s.addNotification(.{ .name = "notifications/cancelled", .handler = countNotification }));

    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"acme/search","params":{"q":"mug"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"hits":["mug"]}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"acme/search","params":{"q":"mug","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","hits":["mug"],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"t","version":"0"}}}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"acme/legacy","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"acme/search","params":{"q":"bad"}}
    ,
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32603,"message":"Method result is not a JSON object"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"acme/search","params":{"q":"boom"}}
    ,
        \\{"jsonrpc":"2.0","id":5,"error":{"code":-32603,"message":"Method failed"}}
        \\
    );
    // A notification is handled and never answered; an unknown one is dropped.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","method":"notifications/acme/ping"}
    , "");
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","method":"notifications/acme/other"}
    , "");
    try testing.expectEqual(@as(u32, 1), pings);
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":6,"method":"acme/nope"}
    ,
        \\{"jsonrpc":"2.0","id":6,"error":{"code":-32601,"message":"Method not found"}}
        \\
    );
}

test "capabilities: extensions and experimental are advertised in both eras" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try testing.expectError(error.InvalidCapabilityJson, s.setCapabilityExtras("[1]", ""));
    try testing.expectError(error.InvalidCapabilityJson, s.setCapabilityExtras("{", ""));
    try s.setCapabilityExtras("{\"io.modelcontextprotocol/ui\":{}}", "{\"acme\":{\"v\":1}}");
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false},"extensions":{"io.modelcontextprotocol/ui":{}},"experimental":{"acme":{"v":1}}},"serverInfo":{"name":"t","title":"t","version":"0"}}}
        \\
    );
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    , &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(), "\"capabilities\":{\"tools\":{},\"extensions\":{\"io.modelcontextprotocol/ui\":{}},\"experimental\":{\"acme\":{\"v\":1}}}") != null);
}

fn codeReviewCompleter(_: ?*anyopaque, req: *CompletionRequest) void {
    if (std.mem.eql(u8, req.argument, "language") and std.mem.eql(u8, req.value, "py")) {
        for ([_][]const u8{ "python", "pytorch", "pyside" }) |v| req.add(v);
        req.total = 10;
        req.has_more = true;
    } else if (std.mem.eql(u8, req.argument, "framework")) {
        const lang = req.contextArg("language") orelse return;
        if (std.mem.eql(u8, lang, "python") and std.mem.startsWith(u8, "flask", req.value)) {
            req.add("flask");
            req.total = 1;
        }
    } else if (std.mem.eql(u8, req.argument, "many")) {
        for (0..150) |_| req.add("x");
    }
}

test "completion/complete: the spec's examples, both eras" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    // No completer anywhere: the capability is absent and the method is -32601.
    try s.addPrompt(.{ .name = "code_review", .handler = imagePrompt });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"code_review"},"argument":{"name":"language","value":"py"}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}
        \\
    );

    var c = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer c.deinit();
    try c.addPrompt(.{ .name = "code_review", .handler = imagePrompt, .completer = codeReviewCompleter });
    try c.addResourceTemplate(.{ .uri_template = "file:///{path}", .name = "f" });
    // 2025-11-25 server/utilities/completion.mdx, both request/response pairs, compacted.
    try expectResponse(&c,
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"code_review"},"argument":{"name":"language","value":"py"}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"completion":{"values":["python","pytorch","pyside"],"total":10,"hasMore":true}}}
        \\
    );
    try expectResponse(&c,
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"code_review"},"argument":{"name":"framework","value":"fla"},"context":{"arguments":{"language":"python"}}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"completion":{"values":["flask"],"total":1,"hasMore":false}}}
        \\
    );
    // 2026-07-28: the same plus resultType; `_meta.serverInfo` (which the
    // example omits, a SHOULD) is the only other member.
    try expectResponse(&c,
        \\{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"code_review"},"argument":{"name":"language","value":"py"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","completion":{"values":["python","pytorch","pyside"],"total":10,"hasMore":true},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"t","version":"0"}}}}
        \\
    );
    // A template without a completer has no suggestions; an unknown target is -32602.
    try expectResponse(&c,
        \\{"jsonrpc":"2.0","id":2,"method":"completion/complete","params":{"ref":{"type":"ref/resource","uri":"file:///{path}"},"argument":{"name":"path","value":"s"}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"completion":{"values":[],"hasMore":false}}}
        \\
    );
    try expectResponse(&c,
        \\{"jsonrpc":"2.0","id":3,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"nope"},"argument":{"name":"a","value":""}}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Unknown prompt"}}
        \\
    );
    // At most 100 values; more means hasMore.
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try c.handleMessage(
        \\{"jsonrpc":"2.0","id":4,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"code_review"},"argument":{"name":"many","value":""}}}
    , &aw.writer);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const comp = parsed.value.object.get("result").?.object.get("completion").?.object;
    try testing.expectEqual(@as(usize, 100), comp.get("values").?.array.items.len);
    try testing.expect(comp.get("hasMore").?.bool);
    // The capability is advertised once a completer exists.
    aw.clearRetainingCapacity();
    try c.handleMessage(
        \\{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}
    , &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(), "\"completions\":{}") != null);
}

fn selfCancellingTool(_: ?*anyopaque, call: *ToolCall) bool {
    // Stands in for the transport: the cancel arrives while the handler runs.
    const before = call.cancelled();
    _ = call.server.handleMessage(
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"user"}}
    , call.transport) catch {};
    call.print("{} {}", .{ before, call.cancelled() });
    return false;
}

const SlowState = struct {
    started: std.atomic.Value(bool) = .init(false),
};

fn slowTool(ctx: ?*anyopaque, call: *ToolCall) bool {
    const st: *SlowState = @ptrCast(@alignCast(ctx.?));
    st.started.store(true, .release);
    var spins: u64 = 0;
    while (!call.cancelled()) : (spins += 1) {
        if (spins > 2_000_000_000) return call.fail("never cancelled");
        std.atomic.spinLoopHint();
    }
    call.write("stopped");
    return false;
}

fn cancelFromThread(s: *Server, st: *SlowState) void {
    while (!st.started.load(.acquire)) std.atomic.spinLoopHint();
    _ = s.cancelInflight(0, .{ .string = "job-1" });
}

test "cancellation: a client's notifications/cancelled reaches the running tool, and no response is sent" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "self", .description = "", .input_schema = "{}", .handler = selfCancellingTool });
    // Cancelled mid-call: the handler saw it flip, and nothing is answered.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"self","arguments":{}}}
    , "");
    // A cancel for another id (or for a finished call) changes nothing.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"self","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":8,"result":{"content":[{"type":"text","text":"false false"}],"isError":false}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}
    , "");
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":"x"}
    , "");
    try testing.expectEqual(@as(usize, 0), s.inflight.items.len);
}

test "cancellation: Server.cancelInflight from another thread stops a running tool" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    var st: SlowState = .{};
    try s.addTool(.{ .name = "slow", .description = "", .input_schema = "{}", .handler = slowTool, .ctx = &st });
    const th = try std.Thread.spawn(.{}, cancelFromThread, .{ &s, &st });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":"job-1","method":"tools/call","params":{"name":"slow","arguments":{}}}
    , "");
    th.join();
    try testing.expect(!s.cancelInflight(0, .{ .string = "job-1" })); // gone once finished
}

const TestSink = struct {
    aw: std.Io.Writer.Allocating,

    fn writerFor(ctx: ?*anyopaque, peer: u64) ?*std.Io.Writer {
        const self: *TestSink = @ptrCast(@alignCast(ctx.?));
        return if (peer == 0) &self.aw.writer else null;
    }

    fn sink(self: *TestSink) PushSink {
        return .{ .ctx = self, .writerFor = writerFor };
    }
};

test "push: subscription limits -- a listen id over 128 bytes, a subscribe uri over the cap (mutation 2026-10-24)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.push = true;
    const long_id: [130]u8 = @splat('i');
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ long_id ++ "\",\"method\":\"subscriptions/listen\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"c\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}},\"notifications\":{}}}", "{\"jsonrpc\":\"2.0\",\"id\":\"" ++ long_id ++ "\",\"error\":{\"code\":-32602,\"message\":\"Request id too long for a subscription\"}}\n");
    const long_uri: [max_subscription_uri_len + 1]u8 = @splat('u');
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/subscribe\",\"params\":{\"uri\":\"" ++ long_uri ++ "\"}}",
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Subscription uri too long"}}
        \\
    );
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/subscribe\",\"params\":{\"uri\":\"" ++ long_uri[1..] ++ "\"}}",
        \\{"jsonrpc":"2.0","id":2,"result":{}}
        \\
    );
}

test "push: session list_changed + resources/subscribe, byte-identical to the spec's examples" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addResource(.{ .uri = "file:///project/src/main.rs", .name = "main.rs", .handler = contextResource });
    var ts: TestSink = .{ .aw = .init(testing.allocator) };
    defer ts.aw.deinit();
    // Off by default: no subscribe method, nothing pushed.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"resources/subscribe","params":{"uri":"file:///project/src/main.rs"}}
    ,
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"Method not found"}}
        \\
    );
    s.push = true;
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}
    ,
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true},"resources":{"subscribe":true,"listChanged":true}},"serverInfo":{"name":"t","title":"t","version":"0"}}}
        \\
    );
    // Not yet initialized: list_changed waits for notifications/initialized.
    try testing.expectEqual(@as(usize, 0), s.notifyListChanged(ts.sink(), .tools));
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    , "");
    // resources.mdx "Subscriptions" request verbatim.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"resources/subscribe","params":{"uri":"file:///project/src/main.rs"}}
    ,
        \\{"jsonrpc":"2.0","id":4,"result":{}}
        \\
    );
    try testing.expectEqual(@as(usize, 1), s.notifyListChanged(ts.sink(), .tools));
    try testing.expectEqual(@as(usize, 1), s.notifyListChanged(ts.sink(), .prompts));
    try testing.expectEqual(@as(usize, 1), s.notifyListChanged(ts.sink(), .resources));
    try testing.expectEqual(@as(usize, 1), s.notifyResourceUpdated(ts.sink(), "file:///project/src/main.rs"));
    try testing.expectEqual(@as(usize, 0), s.notifyResourceUpdated(ts.sink(), "file:///other"));
    // tools.mdx / prompts.mdx / resources.mdx examples, compacted.
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
        \\{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}
        \\{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}
        \\{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///project/src/main.rs"}}
        \\
    , ts.aw.written());
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"resources/unsubscribe","params":{"uri":"file:///project/src/main.rs"}}
    ,
        \\{"jsonrpc":"2.0","id":5,"result":{}}
        \\
    );
    try testing.expectEqual(@as(usize, 0), s.notifyResourceUpdated(ts.sink(), "file:///project/src/main.rs"));
    // Dynamic catalog: a removed tool disappears from the list.
    try s.addTool(.{ .name = "gone", .description = "", .input_schema = "{}", .handler = pageTool });
    try testing.expect(s.removeTool("gone"));
    try testing.expect(!s.removeTool("gone"));
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":6,"method":"tools/list"}
    ,
        \\{"jsonrpc":"2.0","id":6,"result":{"tools":[]}}
        \\
    );
    // forgetPeer drops the peer's subscriptions.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":7,"method":"resources/subscribe","params":{"uri":"x://a"}}
    ,
        \\{"jsonrpc":"2.0","id":7,"result":{}}
        \\
    );
    s.forgetPeer(0);
    try testing.expectEqual(@as(usize, 0), s.session_subs.items.len);
}

test "push: a 2026-07-28 subscriptions/listen is held open, carries its id, ends on cancel or gracefully" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    s.push = true;
    var ts: TestSink = .{ .aw = .init(testing.allocator) };
    defer ts.aw.deinit();
    // subscriptions.mdx "Opening a Stream" request verbatim (compacted): only
    // the acknowledgment comes back, value-equal to the spec's.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ExampleClient","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":true,"resourceSubscriptions":["file:///project/config.json"]}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":1},"notifications":{"toolsListChanged":true,"resourceSubscriptions":["file:///project/config.json"]}}}
        \\
    );
    try testing.expectEqual(@as(usize, 1), s.notifyResourceUpdated(ts.sink(), "file:///project/config.json"));
    try testing.expectEqual(@as(usize, 1), s.notifyListChanged(ts.sink(), .tools));
    try testing.expectEqual(@as(usize, 0), s.notifyListChanged(ts.sink(), .prompts)); // not asked for
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":1},"uri":"file:///project/config.json"}}
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":1}}}
        \\
    , ts.aw.written());
    // The client cancels: no response, nothing more on the stream.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}
    , "");
    try testing.expectEqual(@as(usize, 0), s.notifyListChanged(ts.sink(), .tools));
    // A second listen ended by the server: the graceful-close result.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":"s2","method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"promptsListChanged":true}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"s2"},"notifications":{"promptsListChanged":true}}}
        \\
    );
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try testing.expectEqual(@as(usize, 1), try s.endSubscriptions(&aw.writer, 0));
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":"s2","result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":"s2","io.modelcontextprotocol/serverInfo":{"name":"srv","version":"1"}}}}
        \\
    , aw.written());
    try testing.expectEqual(@as(usize, 0), s.listens.items.len);
}

test "push: a listen whose acknowledgment cannot be written leaves nothing behind (review 2026-10-20 H1)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.push = true;
    var tiny: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&tiny);
    try testing.expectError(error.WriteFailed, s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":true,"resourceSubscriptions":["a://x"]}}}
    , &w));
    try testing.expectEqual(@as(usize, 0), s.listens.items.len);
    // Oversized filters and ids are refused before anything is kept.
    var long_uri: [max_subscription_uri_len + 1]u8 = @splat('a');
    const msg = try std.fmt.allocPrint(testing.allocator,
        \\{{"jsonrpc":"2.0","id":2,"method":"subscriptions/listen","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{{}}}},"notifications":{{"resourceSubscriptions":["{s}"]}}}}}}
    , .{&long_uri});
    defer testing.allocator.free(msg);
    try expectResponse(&s, msg,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Subscription uri too long"}}
        \\
    );
    try testing.expectEqual(@as(usize, 0), s.listens.items.len);
}

fn selfRemovingTool(_: ?*anyopaque, call: *ToolCall) bool {
    _ = call.server.removeTool("ephemeral");
    // Grow the catalog too, so `tools` reallocates under the running call.
    inline for (.{ "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9" }) |n| {
        call.server.addTool(.{ .name = n, .description = "", .input_schema = "{}", .output_schema = "{\"type\":\"object\"}", .handler = pageTool }) catch {};
    }
    call.write("{\"done\":true}");
    return false;
}

test "dynamic catalog: a tool that removes itself mid-call answers from copies (review 2026-10-20 M3)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "ephemeral", .description = "", .input_schema = "{}", .output_schema = "{\"type\":\"object\",\"required\":[\"done\"]}", .handler = selfRemovingTool });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ephemeral","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"done\":true}"}],"structuredContent":{"done":true},"isError":false}}
        \\
    );
    try testing.expectEqual(@as(usize, 9), s.tools.items.len);
}

fn pageTool(_: ?*anyopaque, _: *ToolCall) bool {
    return false;
}

fn growingPrompt(_: ?*anyopaque, req: *PromptRequest) bool {
    const server = req.server.?;
    _ = server.removePrompt("grow");
    inline for (.{ "g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8", "g9" }) |n| {
        server.addPrompt(.{ .name = n, .handler = imagePrompt }) catch {};
    }
    req.message(.user, "hi");
    return true;
}

test "dynamic catalog: a prompt that changes the catalog mid-get answers from a copy (review 2026-10-24)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addPrompt(.{ .name = "grow", .description = "Grows the catalog.", .handler = growingPrompt });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"grow"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"description":"Grows the catalog.","messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}}
        \\
    );
    try testing.expectEqual(@as(usize, 9), s.prompts.items.len);
}

fn growingTemplate(_: ?*anyopaque, req: *ResourceRequest) bool {
    const server = req.server.?;
    inline for (.{ "t://g1/{x}", "t://g2/{x}", "t://g3/{x}", "t://g4/{x}", "t://g5/{x}", "t://g6/{x}", "t://g7/{x}", "t://g8/{x}", "t://g9/{x}" }) |u| {
        server.addResourceTemplate(.{ .uri_template = u, .name = "g", .handler = decliningTemplate }) catch {};
    }
    return false;
}

fn decliningTemplate(_: ?*anyopaque, _: *ResourceRequest) bool {
    return false;
}

test "dynamic catalog: a template handler that grows the catalog mid-read (review 2026-10-24)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addResourceTemplate(.{ .uri_template = "t://a/{x}", .name = "a", .handler = growingTemplate });
    try s.addResourceTemplate(.{ .uri_template = "t://b/{x}", .name = "b", .handler = decliningTemplate });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"t://c/1"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"Resource not found"}}
        \\
    );
    try testing.expectEqual(@as(usize, 11), s.resource_templates.items.len);
}

test "tools/call: arguments that are not an object are -32602 (review 2026-10-24)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "p", .description = "", .input_schema = "", .handler = pageTool });
    inline for (.{ "\"x\"", "[1]", "5", "true" }) |bad| {
        try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"p\",\"arguments\":" ++ bad ++ "}}",
            \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid arguments"}}
            \\
        );
    }
}

test "pagination: page_size pages the list, nextCursor until the last page, then none" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.page_size = 2;
    inline for (.{ "a", "b", "c", "d", "e" }) |n| {
        try s.addTool(.{ .name = n, .description = "", .input_schema = "{}", .handler = pageTool });
    }
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","description":"","inputSchema":{}},{"name":"b","description":"","inputSchema":{}}],"nextCursor":"dDoy"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"dDoy"}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"c","description":"","inputSchema":{}},{"name":"d","description":"","inputSchema":{}}],"nextCursor":"dDo0"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"dDo0"}}
    ,
        \\{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"e","description":"","inputSchema":{}}]}}
        \\
    );
    // One past the end is not a position this server minted (mutation 2026-10-24).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"cursor":"dDo2"}}
    ,
        \\{"jsonrpc":"2.0","id":9,"error":{"code":-32602,"message":"Invalid cursor"}}
        \\
    );
    // The end position itself is a valid (empty) page; a null cursor is none.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"cursor":"dDo1"}}
    ,
        \\{"jsonrpc":"2.0","id":4,"result":{"tools":[]}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"cursor":null}}
    ,
        \\{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"a","description":"","inputSchema":{}},{"name":"b","description":"","inputSchema":{}}],"nextCursor":"dDoy"}}
        \\
    );
    // Not ours, another list's, past the end, non-canonical, not a string: -32602.
    inline for (.{ "\"zzz\"", "\"cDoy\"", "\"dDo5\"", "\"dDowMg\"", "\"\"", "7" }) |c| {
        try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/list\",\"params\":{\"cursor\":" ++ c ++ "}}",
            \\{"jsonrpc":"2.0","id":6,"error":{"code":-32602,"message":"Invalid cursor"}}
            \\
        );
    }
}

test "pagination: the 2026-07-28 list keeps resultType/ttl/serverInfo around nextCursor" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.page_size = 1;
    try s.addPrompt(.{ .name = "p1", .handler = protoErrPrompt });
    try s.addPrompt(.{ .name = "p2", .handler = protoErrPrompt });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    , &aw.writer);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const result = parsed.value.object.get("result").?.object;
    try testing.expectEqualStrings("complete", result.get("resultType").?.string);
    try testing.expectEqual(@as(usize, 1), result.get("prompts").?.array.items.len);
    try testing.expectEqualStrings("cDox", result.get("nextCursor").?.string);
    try testing.expect(result.get("ttlMs") != null);
}

test "definitions: _meta, resource annotations/size and Implementation extras on the wire" {
    var s = Server.init(testing.allocator, .{
        .name = "srv",
        .version = "1",
        .description = "does things",
        .website_url = "https://srv.example/",
        .icons = &.{.{ .src = "https://srv.example/i.png", .mime_type = "image/png" }},
    });
    defer s.deinit();
    try s.addTool(.{ .name = "app", .description = "", .input_schema = "{}", .meta_json = "{\"ui\":{\"resourceUri\":\"ui://app\"}}", .handler = pageTool });
    try s.addResource(.{
        .uri = "file:///a",
        .name = "a",
        .annotations = .{ .audience = &.{ .user, .assistant }, .priority = 0.5, .last_modified = "2026-10-20T00:00:00Z" },
        .size = 42,
        .meta_json = "{\"k\":1}",
        .handler = contextResource,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"app","description":"","inputSchema":{},"_meta":{"ui":{"resourceUri":"ui://app"}}}]}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"resources/list"}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"resources":[{"uri":"file:///a","name":"a","annotations":{"audience":["user","assistant"],"priority":0.5,"lastModified":"2026-10-20T00:00:00Z"},"size":42,"_meta":{"k":1}}]}}
        \\
    );
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}
    , &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(),
        \\"serverInfo":{"name":"srv","title":"srv","version":"1","description":"does things","websiteUrl":"https://srv.example/","icons":[{"src":"https://srv.example/i.png","mimeType":"image/png"}]}
    ) != null);
    // `_meta` that is not one JSON object is a server-side defect: -32603.
    var bad = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer bad.deinit();
    try bad.addPrompt(.{ .name = "p", .meta_json = "[1]", .handler = protoErrPrompt });
    try expectResponse(&bad,
        \\{"jsonrpc":"2.0","id":4,"method":"prompts/list"}
    ,
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32603,"message":"failed to build prompts/list"}}
        \\
    );
}

test "ToolCall.arg: absent, null, wrong type and each value type apart (bxp request 2026-10-19)" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator,
        \\{"s":"x","n":null,"i":5,"f":2.5,"fi":5.0,"b":true,"big":123456789012345678901234567890,"huge":1e300}
    , .{});
    defer parsed.deinit();
    const a = parsed.value;
    try testing.expectEqualStrings("x", lookupArg([]const u8, a, "s").value);
    try testing.expect(lookupArg([]const u8, a, "nope") == .absent);
    try testing.expect(lookupArg([]const u8, a, "n") == .absent);
    try testing.expect(lookupArg([]const u8, a, "i") == .wrong_type);
    try testing.expectEqual(@as(i64, 5), lookupArg(i64, a, "i").value);
    try testing.expectEqual(@as(i64, 5), lookupArg(i64, a, "fi").value);
    try testing.expect(lookupArg(i64, a, "f") == .wrong_type);
    try testing.expect(lookupArg(i64, a, "s") == .wrong_type);
    try testing.expect(lookupArg(i64, a, "huge") == .wrong_type);
    try testing.expect(lookupArg(i64, a, "big") == .wrong_type);
    try testing.expectEqual(@as(f64, 2.5), lookupArg(f64, a, "f").value);
    try testing.expectEqual(@as(f64, 5), lookupArg(f64, a, "i").value);
    try testing.expectEqual(@as(f64, 1.2345678901234568e29), lookupArg(f64, a, "big").value);
    try testing.expect(lookupArg(f64, a, "b") == .wrong_type);
    try testing.expect(lookupArg(bool, a, "b").value);
    try testing.expect(lookupArg(bool, a, "i") == .wrong_type);
    // Not an object: everything is absent, never wrong_type.
    try testing.expect(lookupArg([]const u8, .null, "s") == .absent);
}

fn requireTool(_: ?*anyopaque, call: *ToolCall) bool {
    const path = call.requireStr("path") orelse return true;
    const depth = call.require(i64, "depth") orelse return true;
    call.print("{s}:{d}", .{ path, depth });
    return false;
}

test "ToolCall.require: 'missing' and 'must be' are told apart on the wire" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "req", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = requireTool });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"req","arguments":{"path":5}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"error: 'path' must be a string"}],"isError":true}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"req","arguments":{"path":"/a"}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"error: missing 'depth'"}],"isError":true}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"req","arguments":{"path":"/a","depth":2.0}}}
    ,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"/a:2"}],"isError":false}}
        \\
    );
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

fn objectTextHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("{\"a\":1}");
    return false;
}

test "tools/call: allow_structured=false keeps even a single JSON object text-only" {
    // The NDJSON test above cannot tell: its text is not one object, so it
    // stays text-only either way. A tool that opted out of structured output
    // must not get it because its text happens to parse.
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "obj",
        .description = "prints one object",
        .input_schema = "{\"type\":\"object\"}",
        .allow_structured = false,
        .handler = &objectTextHandler,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"obj"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"a\":1}"}],"isError":false}}
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
    try testing.expect(isSingleJsonObject(testing.allocator, "{}"));
    try testing.expect(isSingleJsonObject(testing.allocator, "  {\"a\":1}  \n"));
    try testing.expect(isSingleJsonObject(testing.allocator, "{\"s\":\"}{\",\"e\":\"\\\"}\"}")); // braces inside strings
    try testing.expect(!isSingleJsonObject(testing.allocator, "")); // empty
    try testing.expect(!isSingleJsonObject(testing.allocator, "[1,2]")); // array
    try testing.expect(!isSingleJsonObject(testing.allocator, "\"str\"")); // string
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":1}\n{\"b\":2}")); // NDJSON
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":1")); // unterminated
    try testing.expect(!isSingleJsonObject(testing.allocator, "}{")); // unbalanced
    // Re-audit F10: the bracket KINDS have to agree, not merely the count. A
    // single depth counter shared by `{}` and `[]` returned true for all of
    // these, and the caller then spliced them verbatim.
    try testing.expect(!isSingleJsonObject(testing.allocator, "{]"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":1]"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "{[}]"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":[1,2}"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "[}"));
    // Re-audit F13: valid-looking, but a raw control character inside a
    // string is not valid JSON (RFC 8259 §7) — and it is exactly the shape
    // the newline-strip silently rewrote into a different value.
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":\"x\ny\"}"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":\"x\ry\"}"));
    // Whitespace newlines between tokens stay fine: they carry no value.
    try testing.expect(isSingleJsonObject(testing.allocator, "{\n\"a\":\n1\n}"));
    // Other things a brace count cannot see.
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":}"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\" 1}"));
    try testing.expect(!isSingleJsonObject(testing.allocator, "{\"a\":01}"));
}

fn echoTextTool(_: ?*anyopaque, call: *ToolCall) bool {
    call.write(call.strArg("text") orelse "");
    return false;
}

test "tools/call: structuredContent is spliced only when the text is genuinely valid JSON (re-audit F10/F13)" {
    // Reachable from ONE ordinary request against any pass-through tool:
    // `allow_structured` defaults to true and the text is the tool's output,
    // so a remote peer chose these bytes. Two properties are pinned here —
    // the emitted line always parses, and when `structuredContent` IS present
    // it carries the same value as the text block beside it.
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "echo",
        .description = "echoes its argument verbatim",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &echoTextTool,
    });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const cases = [_]struct { text: []const u8, structured: bool }{
        .{ .text = "{]", .structured = false },
        .{ .text = "{\"a\":1]", .structured = false },
        .{ .text = "{[}]", .structured = false },
        .{ .text = "{\"a\":[1,2}", .structured = false },
        .{ .text = "{\"a\":\"x\ny\"}", .structured = false }, // raw LF inside a string
        .{ .text = "{\"a\":1}\n{\"b\":2}", .structured = false }, // NDJSON
        .{ .text = "not json at all", .structured = false },
        .{ .text = "{\"ok\":true}", .structured = true },
        .{ .text = "{\n  \"a\": [1, 2],\n  \"b\": {\"c\": null}\n}", .structured = true },
    };
    for (cases) |c| {
        aw.clearRetainingCapacity();
        var req: std.Io.Writer.Allocating = .init(testing.allocator);
        defer req.deinit();
        try req.writer.writeAll(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":",
        );
        try std.json.Stringify.encodeJsonString(c.text, .{}, &req.writer);
        try req.writer.writeAll("}}}");
        try s.handleMessage(req.written(), &aw.writer);

        const line = std.mem.trimEnd(u8, aw.written(), "\n");
        // Whatever we emit, the client must be able to parse it.
        var parsed = std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{}) catch |err| {
            std.debug.print("emitted an unparseable line for {s}: {s}\n", .{ c.text, line });
            return err;
        };
        defer parsed.deinit();
        const result = parsed.value.object.get("result").?.object;
        const structured = result.get("structuredContent");
        try testing.expectEqual(c.structured, structured != null);
        if (structured) |sv| {
            // One state, two readers: the spliced copy must agree with the
            // text block. (The strip only removes insignificant whitespace,
            // which re-serializing normalises away on both sides.)
            const from_text = try std.json.parseFromSlice(std.json.Value, testing.allocator, c.text, .{});
            defer from_text.deinit();
            const a = try std.json.Stringify.valueAlloc(testing.allocator, from_text.value, .{});
            defer testing.allocator.free(a);
            const b = try std.json.Stringify.valueAlloc(testing.allocator, sv, .{});
            defer testing.allocator.free(b);
            try testing.expectEqualStrings(a, b);
        }
    }
}

test "integration: full round-trip over an in-memory pipe (serve)" {
    var app = TestApp{};
    var s = testServer(&app);
    defer s.deinit();

    // The canonical MCP session: initialize -> initialized -> tools/list ->
    // tools/call, plus a malformed line mid-stream (the loop must survive
    // it). The last line is newline-terminated like every other -- an
    // unterminated final line is its own edge case, covered separately by
    // "serve: an unterminated trailing fragment produces no parse-error
    // response (no error-bounce)".
    const input =
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cli","version":"1.0"}}}
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
        \\this is not json
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"round-trip"}}}
        \\
    ;
    var in: std.Io.Reader = .fixed(input);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try s.serve(&in, &aw.writer);

    const expected =
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"test-srv","title":"test-srv","version":"1.2.3"},"instructions":"use echo"}}
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"Echo the 'text' argument back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]},"outputSchema":{"type":"object","properties":{"echo":{"type":"string"},"calls":{"type":"integer"}}}}]}}
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"echo\":\"round-trip\",\"calls\":1}"}],"structuredContent":{"echo":"round-trip","calls":1},"isError":false}}
        \\
    ;
    try testing.expectEqualStrings(expected, aw.written());

    // The session reached the app: handshake flag + ctx-threaded state.
    try testing.expect(s.clientInitialized(0));
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
    const body = req.arena.print("contents of {s}", .{name}) catch return false;
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

test "lead: prompts/get without a required argument is -32602, the handler never runs" {
    // The card's `**Ahead:**` line. prompts.mdx "Error Handling": servers
    // SHOULD answer "Missing required arguments" with -32602. The Go SDK
    // v1.8.0 calls the handler with the argument absent and returns what it
    // renders ("Hello, !"; probe `tools/go_lead`, 2026-10-24).
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greet","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Missing required argument"}}
        \\
    );
    try testing.expectEqual(@as(u32, 0), lib.gets);
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

test "readLine: an unterminated final fragment is discarded on EOF, not returned as a line" {
    // Evidence for this behavior (cited in readLine's doc comment, not
    // re-measured here): the official MCP Python SDK 2.0.0 silently
    // discards a trailing unterminated fragment on EOF; the Rust SDK
    // answered it instead (PR #833) and reverted after that produced an
    // error-bounce loop with the peer (issue #938, PR #940). A stream that
    // ends mid-line must be treated like the max_line_len overflow path
    // already is: readLine returns null, never the partial bytes.
    const alloc = testing.allocator;
    var in: std.Io.Reader = .fixed("{\"jsonrpc\":\"2.0\",\"id\":1,\"meth");
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    try testing.expect(try readLine(alloc, &in, &buf) == null);
}

test "serve: an unterminated trailing fragment produces no parse-error response (no error-bounce)" {
    var s = testServer(null);
    defer s.deinit();
    // The second "line" never gets its trailing '\n' -- the stream just ends
    // mid-message, exactly as it would on a cancel or a peer that dies
    // mid-write.
    const input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"meth";
    var in: std.Io.Reader = .fixed(input);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.serve(&in, &aw.writer);
    // Only the complete first line gets a response. The truncated second
    // line must not become a -32700 parse-error line written to a peer that,
    // on a real EOF/cancel, is already gone.
    try testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
        aw.written(),
    );
}

test "serveStdio's cancel recovery: a canceled blocked read surfaces error.Canceled (mutation-critical)" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;

    // `serveStdio` hard-codes `std.Io.File.stdin()`, so it cannot be driven
    // from a test without hijacking the real process stdin. Instead this
    // exercises the exact two production calls `serveStdio` makes -- `serve`
    // then `recoverFileCancel` -- against a `std.Io.File.Reader` backed by a
    // pipe nobody writes to, so the blocked read is a real syscall a
    // `std.Io.Threaded` cancel can interrupt. Measured with a standalone
    // probe first (same shape as CANCEL-SPEC.md's socket probe, adapted to a
    // pipe): the blocked `takeByte` returns in 0ms once `Future.cancel` is
    // called, with `reader.err == error.Canceled` while the interface-level
    // result is the ordinary `error.ReadFailed` -- `std.Io.Reader.Error`
    // cannot carry `Canceled`, only the concrete reader's out-of-band field
    // can.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.PipeFailed;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]); // never written to: keeps the read genuinely blocked

    var s = testServer(null);
    defer s.deinit();

    const Ctx = struct {
        fn run(server: *Server, rfd: i32, io_: std.Io) Error!void {
            var read_buf: [64]u8 = undefined;
            var reader = (std.Io.File{ .handle = rfd, .flags = .{ .nonblocking = false } })
                .readerStreaming(io_, &read_buf);
            var aw: std.Io.Writer.Allocating = .init(testing.allocator);
            defer aw.deinit();
            try server.serve(&reader.interface, &aw.writer);
            try Server.recoverFileCancel(&reader);
        }
    };

    var fut = try io.concurrent(Ctx.run, .{ &s, fds[0], io });
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectError(error.Canceled, fut.cancel(io));
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

test "readLine: the cap is 16 MiB exactly, and it is the delivered value (re-audit F5)" {
    // Re-audit 2026-08-11 F5: the test above is written entirely in terms of
    // `max_line_len`, so it stays green for ANY value of it — `16 * 1024 * 1024`
    // → `1024` was a green mutation (exit 0), i.e. the DoS bound this constant
    // exists for was unpinned on the very line the previous audit's CRIT was
    // closed with. Everything here is an absolute number on purpose.
    try testing.expectEqual(@as(usize, 16 * 1024 * 1024), max_line_len);
    try testing.expectEqual(@as(usize, 16777216), max_line_len);

    const alloc = testing.allocator;
    // A 1 MiB line — far above any plausible "small" cap, far below 16 MiB —
    // must be DELIVERED, not refused. This is the half a shrunken cap breaks.
    {
        const big = try alloc.alloc(u8, 1024 * 1024 + 1);
        defer alloc.free(big);
        @memset(big, 'x');
        big[big.len - 1] = '\n';
        var in: std.Io.Reader = .fixed(big);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(alloc);
        const line = try readLine(alloc, &in, &buf);
        try testing.expectEqual(@as(usize, 1024 * 1024), line.?.len);
    }
    // 17 MiB unterminated must be REFUSED, with the buffer bounded by the cap.
    // This is the half an enlarged (or removed) cap breaks.
    {
        const big = try alloc.alloc(u8, 17 * 1024 * 1024);
        defer alloc.free(big);
        @memset(big, 'x');
        var in: std.Io.Reader = .fixed(big);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(alloc);
        try testing.expect(try readLine(alloc, &in, &buf) == null);
        try testing.expectEqual(@as(usize, 16777216), buf.items.len);
    }
    // And the boundary itself: exactly 16 MiB of payload plus its newline is
    // the longest line that still arrives.
    {
        const exact = try alloc.alloc(u8, 16 * 1024 * 1024 + 1);
        defer alloc.free(exact);
        @memset(exact, 'x');
        exact[exact.len - 1] = '\n';
        var in: std.Io.Reader = .fixed(exact);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(alloc);
        const line = try readLine(alloc, &in, &buf);
        try testing.expectEqual(@as(usize, 16777216), line.?.len);
    }
    // One byte more of payload, and the line is refused outright.
    {
        const over = try alloc.alloc(u8, 16 * 1024 * 1024 + 2);
        defer alloc.free(over);
        @memset(over, 'x');
        over[over.len - 1] = '\n';
        var in: std.Io.Reader = .fixed(over);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(alloc);
        try testing.expect(try readLine(alloc, &in, &buf) == null);
    }
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
    try testing.expect(!s.clientCapabilities(0).sampling);
    try testing.expect(!s.clientCapabilities(0).elicitation);

    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{"tools":{}},"elicitation":{"form":{},"url":{}},"roots":{"listChanged":true}}}}
    );
    try testing.expect(s.clientCapabilities(0).sampling);
    try testing.expect(s.clientCapabilities(0).sampling_tools);
    try testing.expect(!s.clientCapabilities(0).sampling_context);
    try testing.expect(s.clientCapabilities(0).elicitation);
    try testing.expect(s.clientCapabilities(0).elicitation_form);
    try testing.expect(s.clientCapabilities(0).elicitation_url);
    try testing.expect(s.clientCapabilities(0).roots);
    try testing.expect(s.clientCapabilities(0).roots_list_changed);
    try testing.expectEqualStrings("2025-11-25", s.negotiatedVersion(0));

    // A second initialize replaces the set outright — capabilities must never
    // accumulate across handshakes (otherwise a client could never drop one).
    try feed(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}
    );
    try testing.expect(!s.clientCapabilities(0).sampling);
    try testing.expect(!s.clientCapabilities(0).elicitation);
    try testing.expectEqualStrings("2025-06-18", s.negotiatedVersion(0));
}

fn dupeAndFreeClientInfo(gpa: std.mem.Allocator, ci: ClientInfo) !void {
    const c = try ci.dupe(gpa, 256);
    c.free(gpa);
}

test "ClientInfo.dupe frees what it copied when a later copy fails" {
    const ci: ClientInfo = .{ .name = "n", .version = "v", .title = "t" };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, dupeAndFreeClientInfo, .{ci});
}

test "initialize: clientInfo is recorded (name, version, title present/absent)" {
    var s = testServer(null);
    defer s.deinit();
    try testing.expect(s.clientInfo(0) == null);

    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"acme-cli","version":"1.0.0","title":"Acme CLI"}}}
    );
    var ci = s.clientInfo(0).?;
    try testing.expectEqualStrings("acme-cli", ci.name);
    try testing.expectEqualStrings("1.0.0", ci.version);
    try testing.expectEqualStrings("Acme CLI", ci.title.?);

    // A second initialize replaces it wholesale, same as capabilities. No
    // `title` this time -> absent, not the previous one lingering.
    try feed(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"other-cli","version":"2.0.0"}}}
    );
    ci = s.clientInfo(0).?;
    try testing.expectEqualStrings("other-cli", ci.name);
    try testing.expectEqualStrings("2.0.0", ci.version);
    try testing.expect(ci.title == null);
}

test "initialize: missing or malformed clientInfo never fails the handshake" {
    var s = testServer(null);
    defer s.deinit();

    // No `clientInfo` field at all.
    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}
    );
    try testing.expect(s.clientInfo(0) == null);

    // `clientInfo` present but malformed (missing the spec-required
    // `version`) -- per `ClientCapabilities`'s leniency convention this fails
    // the recorded info closed (null), never the handshake itself: the
    // negotiated version is still returned, not an error.
    try feed(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"only-a-name"}}}
    );
    try testing.expect(s.clientInfo(0) == null);
    try testing.expectEqualStrings("2025-11-25", s.negotiatedVersion(0));

    // `clientInfo` not even an object.
    try feed(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":"nope"}}
    );
    try testing.expect(s.clientInfo(0) == null);
}

test "initialize: an over-long clientInfo field is truncated, not rejected" {
    var s = testServer(null);
    defer s.deinit();
    try testing.expect(s.max_client_info_field_len < 300); // the test assumes the default cap

    const long_name = strRepeat("a", 300);
    const msg = try testing.allocator.print(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"{s}\",\"version\":\"{s}\",\"title\":\"{s}\"}}}}}}",
        .{ long_name, long_name, long_name },
    );
    defer testing.allocator.free(msg);
    try feed(&s, msg);

    // Every field: each is the peer's to choose, and each is kept.
    const ci = s.clientInfo(0).?;
    for ([_][]const u8{ ci.name, ci.version, ci.title.? }) |field| {
        try testing.expectEqual(s.max_client_info_field_len, field.len);
        try testing.expect(std.mem.allEqual(u8, field, 'a'));
    }
}

test "initialize: re-handshake frees the previous clientInfo copy (no leak)" {
    // Regression: `slot.client` used to be overwritten directly, so a second
    // `initialize` from the same peer leaked the first `dupe`'d copy.
    // `testing.allocator` (the gpa `testServer` builds `Server` on) catches
    // that as a leak if `handleInitialize` ever regresses.
    var s = testServer(null);
    defer s.deinit();
    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"first","version":"1","title":"First"}}}
    );
    try feed(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"second","version":"2"}}}
    );
    const ci = s.clientInfo(0).?;
    try testing.expectEqualStrings("second", ci.name);
    // `s.deinit()` (deferred above) must free this last copy too, and
    // `testing.allocator` fails the test on any leftover allocation.
}

test "forgetPeer frees the peer's clientInfo copy too (no leak)" {
    var s = testServer(null);
    defer s.deinit();
    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"gone","version":"1"}}}
    );
    try testing.expect(s.clientInfo(0) != null);
    s.forgetPeer(0);
    try testing.expect(s.clientInfo(0) == null);
    // `s.deinit()` must not double-free or trip `testing.allocator` here.
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

test "ClientCapabilities.parse: a malformed declaration grants nothing (re-audit F7)" {
    // Re-audit 2026-08-11 F7: `parse` granted a capability on ANY non-null
    // value, so it failed OPEN — contradicting its own doc ("Anything
    // unparseable yields all-false (fail closed) — a malformed handshake must
    // never *grant* a capability"). Worst shape: `{"elicitation":"url"}` used
    // to grant FORM (the phishing-relevant mode) and deny url, the inverse of
    // the declaration.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const parse = struct {
        fn f(a: std.mem.Allocator, txt: []const u8) !ClientCapabilities {
            return ClientCapabilities.parse(try std.json.parseFromSliceLeaky(std.json.Value, a, txt, .{}));
        }
    }.f;

    // The re-audit's own reproduction line: every capability granted by junk.
    const junk = try parse(arena, "{\"elicitation\":true,\"sampling\":5,\"roots\":\"yes\"}");
    try testing.expect(!junk.elicitation and !junk.elicitation_form and !junk.elicitation_url);
    try testing.expect(!junk.sampling and !junk.sampling_tools and !junk.sampling_context);
    try testing.expect(!junk.roots and !junk.roots_list_changed);

    // The inverse-grant shape: a non-object elicitation must not hand out form.
    for ([_][]const u8{
        "{\"elicitation\":\"url\"}",
        "{\"elicitation\":\"form\"}",
        "{\"elicitation\":true}",
        "{\"elicitation\":1}",
        "{\"elicitation\":[]}",
        "{\"elicitation\":[\"url\"]}",
    }) |txt| {
        const c = try parse(arena, txt);
        testing.expect(!c.elicitation and !c.elicitation_form and !c.elicitation_url) catch {
            std.debug.print("granted elicitation on: {s}\n", .{txt});
            return error.TestUnexpectedResult;
        };
    }

    // A wrong-shaped SUB-capability fails the whole parent closed: we do not
    // know what was declared, so we grant none of it.
    for ([_][]const u8{
        "{\"sampling\":{\"tools\":true}}",
        "{\"sampling\":{\"context\":\"yes\"}}",
        "{\"elicitation\":{\"url\":true}}",
        "{\"elicitation\":{\"form\":1}}",
        "{\"roots\":{\"listChanged\":{}}}",
        "{\"roots\":{\"listChanged\":\"true\"}}",
    }) |txt| {
        const c = try parse(arena, txt);
        testing.expect(!c.sampling and !c.elicitation and !c.roots) catch {
            std.debug.print("granted on malformed sub-capability: {s}\n", .{txt});
            return error.TestUnexpectedResult;
        };
    }

    // `listChanged:false` is a declaration of absence, not a grant; the roots
    // capability itself is still validly declared.
    const lc_false = try parse(arena, "{\"roots\":{\"listChanged\":false}}");
    try testing.expect(lc_false.roots and !lc_false.roots_list_changed);

    // …and the gate the capability feeds really refuses: a client that
    // declared `elicitation` as a bare `true` gets no form-mode request.
    var s = try serverWithCaps("{\"elicitation\":true}");
    defer s.deinit();
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    try testing.expectError(error.ElicitationNotSupported, s.sendElicitationRequest(&sink.writer, .{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema = simple_schema,
    } }, .{}));
    try testing.expectEqualStrings("", sink.written());
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

// ── sampling: the capability gate + the spec's wire example ─────────────────

/// A server that has completed a handshake with the given client capabilities.
fn serverWithCaps(caps_json: []const u8) !Server {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    errdefer s.deinit();
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    const msg = try testing.allocator.print(
        "{{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{s}}}}}",
        .{caps_json},
    );
    defer testing.allocator.free(msg);
    try s.handleMessage(msg, &sink.writer);
    return s;
}

/// Run an `initialize` handshake **as `peer`**, so a test that issues a
/// server→client request to that peer passes the (per-peer) capability gate.
/// `serverWithCaps` handshakes peer 0 only, which is what a stdio transport
/// has and what a multiplexing one does not.
fn handshakePeer(s: *Server, peer: u64, caps_json: []const u8) !void {
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    const msg = try testing.allocator.print(
        "{{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{s}}}}}",
        .{caps_json},
    );
    defer testing.allocator.free(msg);
    try s.handleMessageFrom(msg, &sink.writer, peer);
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

test "sampling: a non-finite temperature is refused, not written as invalid JSON (review 2026-10-24)" {
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    for ([_]f64{ std.math.inf(f64), -std.math.inf(f64), std.math.nan(f64) }) |t| {
        const req = SamplingRequest{
            .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
            .max_tokens = 100,
            .temperature = t,
        };
        try testing.expectError(error.InvalidTemperature, s.sendSamplingRequest(&sink.writer, req, .{}));
    }
    try testing.expectEqualStrings("", sink.written());
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
    // NaN is in no range: `p < 0 or p > 1` is false for it, so the check is
    // written as "not inside", which NaN fails.
    try testing.expectError(error.InvalidPriority, s.sendSamplingRequest(&aw.writer, .{
        .messages = &msgs,
        .max_tokens = 1,
        .model_preferences = .{ .intelligence_priority = std.math.nan(f64) },
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

test "elicitation: notifications/elicitation/complete is byte-identical to the spec's example" {
    var s = try serverWithCaps("{\"elicitation\":{\"url\":{}}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.sendElicitationComplete(&aw.writer, 0, "550e8400-e29b-41d4-a716-446655440000");
    // Verbatim from the MCP 2025-11-25 elicitation page ("Completion Notifications
    // for URL Mode Elicitation"), compacted.
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/elicitation/complete","params":{"elicitationId":"550e8400-e29b-41d4-a716-446655440000"}}
        \\
    , aw.written());
    // Only to a client that can have started one, and never without an id.
    try testing.expectError(error.MissingElicitationId, s.sendElicitationComplete(&aw.writer, 0, ""));
    try testing.expectError(error.ElicitationUrlNotSupported, s.sendElicitationComplete(&aw.writer, 7, "x"));
    var form_only = try serverWithCaps("{\"elicitation\":{}}");
    defer form_only.deinit();
    try testing.expectError(error.ElicitationUrlNotSupported, form_only.sendElicitationComplete(&aw.writer, 0, "x"));
}

const spec_url_elicitation = [_]ElicitationRequest.Url{.{
    .message = "Authorization is required to access your Example Co files.",
    .url = "https://mcp.example.com/connect?elicitationId=550e8400-e29b-41d4-a716-446655440000",
    .elicitation_id = "550e8400-e29b-41d4-a716-446655440000",
}};

fn urlRequiredTool(_: ?*anyopaque, call: *ToolCall) bool {
    return call.urlElicitationRequired("This request requires more information.", &spec_url_elicitation) catch call.fail("refused");
}

test "URLElicitationRequiredError: a tool's -32042 is byte-identical to the spec's example" {
    var s = try serverWithCaps("{\"elicitation\":{\"url\":{}}}");
    defer s.deinit();
    try s.addTool(.{ .name = "files", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = urlRequiredTool });
    // MCP 2025-11-25 client/elicitation.mdx "URL Elicitation Required Error",
    // compacted, its `// URL_ELICITATION_REQUIRED` comment dropped.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32042,"message":"This request requires more information.","data":{"elicitations":[{"mode":"url","elicitationId":"550e8400-e29b-41d4-a716-446655440000","url":"https://mcp.example.com/connect?elicitationId=550e8400-e29b-41d4-a716-446655440000","message":"Authorization is required to access your Example Co files."}]}}}
        \\
    );
    // A client without `elicitation.url` gets no -32042 (it could not act on
    // one): the builder refuses, and this tool falls back to a tool failure.
    var form_only = try serverWithCaps("{\"elicitation\":{}}");
    defer form_only.deinit();
    try form_only.addTool(.{ .name = "files", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = urlRequiredTool });
    try expectResponse(&form_only,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"error: refused"}],"isError":true}}
        \\
    );
}

test "URLElicitationRequiredError: the builder's refusals" {
    const url_caps: ClientCapabilities = .{ .elicitation = true, .elicitation_url = true };
    try testing.expectError(error.StatelessRequest, ProtocolError.urlElicitationRequired(testing.allocator, url_caps, true, "m", &spec_url_elicitation));
    try testing.expectError(error.NoMessages, ProtocolError.urlElicitationRequired(testing.allocator, url_caps, false, "m", &.{}));
    try testing.expectError(error.ElicitationNotSupported, ProtocolError.urlElicitationRequired(testing.allocator, .{}, false, "m", &spec_url_elicitation));
    const bad = [_]ElicitationRequest.Url{.{ .message = "m", .url = "javascript:alert(1)", .elicitation_id = "1" }};
    try testing.expectError(error.InvalidUrl, ProtocolError.urlElicitationRequired(testing.allocator, url_caps, false, "m", &bad));
    const no_id = [_]ElicitationRequest.Url{.{ .message = "m", .url = "https://x.example/", .elicitation_id = "" }};
    try testing.expectError(error.MissingElicitationId, ProtocolError.urlElicitationRequired(testing.allocator, url_caps, false, "m", &no_id));
}

fn needsElicitationTool(_: ?*anyopaque, call: *ToolCall) bool {
    if (call.clientCapabilities().elicitation) return call.fail("unexpected");
    return call.failWith(ProtocolError.missingClientCapability("Server requires the elicitation capability for this request", "{\"elicitation\":{}}"));
}

test "MissingRequiredClientCapabilityError: value-equal to the 2026-07-28 schema example" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "ask", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = needsElicitationTool });
    // schema/2026-07-28/examples/MissingRequiredClientCapabilityError/
    // missing-elicitation-capability.json, compacted (same member order).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ask","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32021,"message":"Server requires the elicitation capability for this request","data":{"requiredCapabilities":{"elicitation":{}}}}}
        \\
    );
}

fn protoErrResource(_: ?*anyopaque, req: *ResourceRequest) bool {
    if (std.mem.eql(u8, req.uri, "x://bad-data")) return req.failProtocol(-32000, "custom", "{not json");
    if (std.mem.eql(u8, req.uri, "x://gone")) return req.failProtocol(-32000, "gone for good", "{\"uri\":\"x://gone\"}");
    return false;
}

fn protoErrPrompt(_: ?*anyopaque, req: *PromptRequest) bool {
    req.message(.user, "never sent");
    return req.failProtocol(error_code.invalid_params, "unknown dialect", "");
}

test "ProtocolError: resource templates and prompts answer the handler's own error" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addResourceTemplate(.{ .uri_template = "x://{name}", .name = "x", .handler = protoErrResource });
    try s.addPrompt(.{ .name = "p", .handler = protoErrPrompt });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"x://gone"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"gone for good","data":{"uri":"x://gone"}}}
        \\
    );
    // Data that is not JSON never reaches the wire as such.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"x://bad-data"}}
    ,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"Handler error data is not JSON"}}
        \\
    );
    // A template that only declines still means "not found".
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"x://other"}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32002,"message":"Resource not found"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"p"}}
    ,
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"unknown dialect"}}
        \\
    );
}

fn contextPrompt(_: ?*anyopaque, req: *PromptRequest) bool {
    req.reportProgress(1, 2, "rendering");
    const who = if (req.clientInfo()) |c| c.name else "?";
    req.printMessage(.user, "{s} {s} {}", .{ who, req.protocolVersion(), req.clientCapabilities().elicitation });
    return true;
}

fn contextResource(_: ?*anyopaque, req: *ResourceRequest) bool {
    req.reportProgress(1, 1, "");
    const tag = if (req.meta == .object) "meta" else "none";
    req.text(req.uri, "", tag);
    return true;
}

test "request context: prompt and resource handlers see progress, client and version" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addPrompt(.{ .name = "ctx", .handler = contextPrompt });
    try s.addResource(.{ .uri = "x://r", .name = "r", .handler = contextResource });
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{}},"clientInfo":{"name":"cli","version":"1"}}}
    , &sink.writer);
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"ctx","_meta":{"progressToken":"t1"}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"t1","progress":1,"total":2,"message":"rendering"}}
        \\{"jsonrpc":"2.0","id":1,"result":{"messages":[{"role":"user","content":{"type":"text","text":"cli 2025-11-25 true"}}]}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"x://r","_meta":{"progressToken":7}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":7,"progress":1,"total":1,"message":""}}
        \\{"jsonrpc":"2.0","id":2,"result":{"contents":[{"uri":"x://r","text":"meta"}]}}
        \\
    );
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
        // A multi-select enum is an array of STRINGS (the spec's
        // `items: {type: "string", enum}`): an enum of another item type is
        // not in the subset, whatever its values look like.
        .{ .schema =
        \\{"type":"object","properties":{"xs":{"type":"array","items":{"type":"number","enum":["1"]}}}}
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

test "looksLikeSecretField: every documented needle is individually caught" {
    // The truth-table test below exercises a hand-picked SAMPLE of the
    // needles in various separator/case forms, which cannot notice a needle
    // silently dropped from (or mistyped in) `secret_needles` — every needle
    // is matched by the exact same substring-search loop, so a missing one
    // is invisible unless something asks about that specific word. This list
    // is independent of `secret_needles` (not derived from it — iterating
    // the mutated array over itself would trivially "pass" no matter what
    // got deleted) and must be kept in sync with it by hand.
    const expected_needles = [_][]const u8{
        "password",   "passwd",       "passphrase",   "secret",
        "credential", "apikey",       "accesskey",    "secretkey",
        "privatekey", "accesstoken",  "refreshtoken", "bearertoken",
        "authtoken",  "sessiontoken", "idtoken",      "securitycode",
        "pincode",    "seedphrase",   "mnemonic",     "cardnumber",
        "creditcard", "cvv",          "cvc",
    };
    for (expected_needles) |needle| {
        testing.expect(looksLikeSecretField(needle)) catch {
            std.debug.print("expected needle not recognized: {s}\n", .{needle});
            return error.TestUnexpectedResult;
        };
    }
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

test "looksLikeSecretField: a long name is searched in full, not truncated (re-audit F8)" {
    // Re-audit 2026-08-11 F8: normalization ran into a fixed [128]u8 and
    // `break`ed on overflow, so only the first 128 alphanumeric characters
    // were ever searched — a padded label ending in a credential word slipped
    // through the form-mode refusal entirely. Pad lengths straddle the old
    // buffer from every side, including the case where the needle STRADDLES
    // the old boundary (partially inside, partially past it).
    const alloc = testing.allocator;
    for ([_]usize{ 0, 1, 120, 121, 126, 127, 128, 129, 200, 1000 }) |pad| {
        const name = try alloc.alloc(u8, pad + "password".len);
        defer alloc.free(name);
        @memset(name[0..pad], 'a');
        @memcpy(name[pad..], "password");
        testing.expect(looksLikeSecretField(name)) catch {
            std.debug.print("missed a credential word after {d} padding characters\n", .{pad});
            return error.TestUnexpectedResult;
        };
    }
    // Separators do not count towards the name's length, so the same must hold
    // for a human-shaped label: "a a a … a password".
    {
        var name: std.ArrayList(u8) = .empty;
        defer name.deinit(alloc);
        for (0..300) |_| try name.appendSlice(alloc, "a ");
        try name.appendSlice(alloc, "Pass Phrase");
        try testing.expect(looksLikeSecretField(name.items));
    }
    // ...and a long name that really contains no needle is still not a hit —
    // a sliding window must not manufacture one across its own wrap point.
    {
        const name = try alloc.alloc(u8, 4096);
        defer alloc.free(name);
        @memset(name, 'a');
        try testing.expect(!looksLikeSecretField(name));
    }
    {
        // "pass" + 200 filler + "word" must NOT match: the window may only
        // ever see contiguous characters.
        var name: std.ArrayList(u8) = .empty;
        defer name.deinit(alloc);
        try name.appendSlice(alloc, "pass");
        for (0..200) |_| try name.append(alloc, 'x');
        try name.appendSlice(alloc, "word");
        try testing.expect(!looksLikeSecretField(name.items));
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
        // Host-confusion: a prefix match on "localhost"/"127.0.0.1" alone
        // would accept these — the loopback host name must end exactly at
        // '/', ':', '?' or the URL's end, not run on into a real hostname.
        "http://localhost.evil.example/steal",
        "http://127.0.0.1.evil.example/steal",
        "http://localhostage.example/steal",
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

test "elicitation: userinfo cannot smuggle a host past the http loopback allowance (re-audit F3)" {
    // Re-audit 2026-08-11 F3: the loopback check matched a host PREFIX and
    // accepted the tail as soon as its first byte was '/', ':' or '?'. The ':'
    // branch swallowed the rest of the authority, so RFC 3986 userinfo defeated
    // it: in `http://localhost:8080@evil.example/steal` the real host is
    // `evil.example` and `localhost:8080` is a username. Every URL below was
    // ACCEPTED before the fix (except where noted) and points at a non-loopback
    // host over plaintext http, inside a dialog the client renders as trusted.
    var s = try serverWithCaps("{\"elicitation\":{\"url\":{}}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const smuggled = [_][]const u8{
        // The four shapes the re-audit reproduced.
        "http://localhost:@evil.example/steal",
        "http://localhost:8080@evil.example/steal",
        "http://127.0.0.1:1@evil.example/steal",
        "http://[::1]:80@evil.example/steal",
        // The '@'-directly-after-host form was already caught; keep it pinned.
        "http://localhost@evil.example/steal",
        "http://127.0.0.1@evil.example/steal",
        "http://[::1]@evil.example/steal",
        // Userinfo containing its own '@' — the delimiter is the LAST one.
        "http://localhost@127.0.0.1@evil.example/steal",
        "http://user:localhost@evil.example/steal",
        // Userinfo plus the '.'-suffix host confusion the existing test knows:
        // both halves must fail, in either order.
        "http://localhost@localhost.evil.example/steal",
        "http://localhost:80@localhostage.example/steal",
        "http://[::1]@[::1].evil.example/steal",
        // A trailing-dot FQDN is not one of the three loopback spellings, and
        // this guard is deliberately fail-closed about it.
        "http://localhost./steal",
        "http://127.0.0.1.:8080/steal",
        // An IPv6 literal that is not ::1, and a malformed one.
        "http://[2001:db8::1]/steal",
        "http://[::1/steal",
        "http://[::1]x/steal",
        // Not an authority shape at all: a non-numeric port, an empty host.
        "http://localhost:80x/steal",
        "http://localhost:8080:9090/steal",
        "http:///steal",
        // '@' in the PATH must not be read as a userinfo delimiter.
        "http://evil.example/@localhost",
        "http://evil.example/?x=@127.0.0.1",
        // Re-audit F12: a BACKSLASH also ends the authority — not per RFC
        // 3986, but per the WHATWG URL Standard, which is what the party that
        // finally opens this URL (a browser, a JS-SDK client) uses. Reading
        // these the RFC way puts the last '@' inside the authority and makes
        // the host `localhost`; the client navigates to `evil.example` over
        // plaintext http. Confirmed against WHATWG: `new URL(...).host` is
        // `evil.example` for every one of them.
        "http://evil.example\\@localhost/steal",
        "http://evil.example\\@127.0.0.1/steal",
        "http://evil.example\\@[::1]/steal",
        "http://evil.example\\@localhost:80/steal",
        "http://evil.example\\localhost/steal",
    };
    for (smuggled) |u| {
        testing.expectError(error.InvalidUrl, s.sendElicitationRequest(&aw.writer, .{ .url = .{
            .message = "go here",
            .url = u,
            .elicitation_id = "e-1",
        } }, .{})) catch |err| {
            std.debug.print("url accepted: {s}\n", .{u});
            return err;
        };
    }

    // The loopback development case must still work in all three spellings,
    // with and without a port, an IPv6 literal, a query, and (legitimately)
    // userinfo whose host really is loopback.
    for ([_][]const u8{
        "http://localhost/connect",
        "http://localhost:7717/connect",
        "http://LocalHost:7717/connect",
        "http://127.0.0.1:8080/connect?x=1",
        "http://[::1]/connect",
        "http://[::1]:7717/connect",
        "http://user@localhost:7717/connect",
        // Userinfo ends at the LAST '@', the WHATWG reading too (`new
        // URL(...).host` is `localhost:7717`): the earlier '@' is part of
        // the username, so the client opens loopback.
        "http://user@name@localhost:7717/connect",
        "http://localhost",
        "http://localhost?x=1",
        // The same rule in the other direction: WHATWG reads this host as
        // `localhost` (the rest is path), so refusing it was the mirror-image
        // error — a genuinely loopback URL turned away.
        "http://localhost\\@evil.example/connect",
    }) |u| {
        _ = s.sendElicitationRequest(&aw.writer, .{ .url = .{
            .message = "go here",
            .url = u,
            .elicitation_id = "e-1",
        } }, .{}) catch |err| {
            std.debug.print("loopback url refused: {s}\n", .{u});
            return err;
        };
    }
}

test "capability gate: one peer's initialize does not move another peer's gate (re-audit F11)" {
    // Re-audit 2026-09-02 F11: capabilities, the negotiated revision and the
    // lifecycle flag were three fields on the `Server`, and a `Server` is
    // shared across sessions by `mcp-http`. So any party that could POST
    // could open a session, declare `elicitation`, and thereby lift the gate
    // for EVERY other session — `elicitation/create` was then written to a
    // client that had declared nothing. The reverse handle worked too: a
    // session declaring `capabilities:{}` revoked everyone else's.
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const url_req: ElicitationRequest = .{ .url = .{
        .message = "Sign in to continue",
        .url = "https://corp.example/login",
        .elicitation_id = "e-1",
    } };

    // Peer 1 is an ordinary client that declared nothing.
    try handshakePeer(&s, 1, "{}");
    try testing.expectError(
        error.ElicitationNotSupported,
        s.sendElicitationRequest(&aw.writer, url_req, .{ .peer = 1 }),
    );

    // Peer 2 — the hostile session — declares everything, at an older
    // revision (whose wire shape omits `mode`).
    try handshakePeer(&s, 2, "{\"elicitation\":{\"form\":{},\"url\":{}},\"sampling\":{}}");

    // Peer 1's gate has NOT moved.
    try testing.expectError(
        error.ElicitationNotSupported,
        s.sendElicitationRequest(&aw.writer, url_req, .{ .peer = 1 }),
    );
    try testing.expectError(
        error.SamplingNotSupported,
        s.sendSamplingRequest(&aw.writer, .{
            .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
            .max_tokens = 10,
        }, .{ .peer = 1 }),
    );
    try testing.expectEqualStrings("", aw.written());
    // Peer 2's own request still works — the gate moved for exactly one peer.
    _ = try s.sendElicitationRequest(&aw.writer, url_req, .{ .peer = 2 });
    try testing.expect(aw.written().len > 0);

    // The revocation direction: peer 3 declaring nothing must not close
    // peer 2, and a re-handshake by peer 2 must not open peer 3.
    try handshakePeer(&s, 3, "{}");
    aw.clearRetainingCapacity();
    _ = try s.sendElicitationRequest(&aw.writer, url_req, .{ .peer = 2 });
    try testing.expectError(
        error.ElicitationNotSupported,
        s.sendElicitationRequest(&aw.writer, url_req, .{ .peer = 3 }),
    );

    // The negotiated revision is per-peer too: peer 4 settles on the older
    // one, and that must not reshape peer 2's wire line.
    try handshakePeer(&s, 4, "{\"elicitation\":{\"form\":{},\"url\":{}}}");
    {
        var sink: std.Io.Writer.Allocating = .init(testing.allocator);
        defer sink.deinit();
        const msg =
            \\{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{"form":{},"url":{}}}}}
        ;
        try s.handleMessageFrom(msg, &sink.writer, 4);
    }
    try testing.expectEqualStrings("2025-06-18", s.negotiatedVersion(4));
    try testing.expectEqualStrings("2025-11-25", s.negotiatedVersion(2));
    // `mode` is what the two revisions disagree about, and only the FORM
    // shape can express the difference (a url request must always carry it).
    const form_req: ElicitationRequest = .{ .form = .{
        .message = "Your name?",
        .requested_schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}",
    } };
    aw.clearRetainingCapacity();
    _ = try s.sendElicitationRequest(&aw.writer, form_req, .{ .peer = 2 });
    try testing.expect(std.mem.find(u8, aw.written(), "\"mode\":\"form\"") != null);
    aw.clearRetainingCapacity();
    _ = try s.sendElicitationRequest(&aw.writer, form_req, .{ .peer = 4 });
    try testing.expect(std.mem.find(u8, aw.written(), "\"mode\"") == null);

    // And the lifecycle flag.
    try testing.expect(!s.clientInitialized(1));
    {
        var sink: std.Io.Writer.Allocating = .init(testing.allocator);
        defer sink.deinit();
        try s.handleMessageFrom("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", &sink.writer, 2);
    }
    try testing.expect(s.clientInitialized(2));
    try testing.expect(!s.clientInitialized(1));
}

test "capability gate: the pending budget is per peer (re-audit F11)" {
    // One shared budget meant a session that simply never answered could
    // starve every other session's ability to send at all.
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    try handshakePeer(&s, 1, "{\"sampling\":{}}");
    try handshakePeer(&s, 2, "{\"sampling\":{}}");
    s.max_pending = 2;
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const req: SamplingRequest = .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    };
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 1 });
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 1 });
    try testing.expectError(error.TooManyPending, s.sendSamplingRequest(&aw.writer, req, .{ .peer = 1 }));
    // Peer 2 is unaffected by peer 1 filling its own budget.
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 2 });
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 2 });
    try testing.expectError(error.TooManyPending, s.sendSamplingRequest(&aw.writer, req, .{ .peer = 2 }));
    try testing.expectEqual(@as(usize, 4), s.pendingCount());
}

test "forgetPeer drops the session's handshake state and its pending requests" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try handshakePeer(&s, 1, "{\"sampling\":{}}");
    try handshakePeer(&s, 2, "{\"sampling\":{}}");
    const req: SamplingRequest = .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    };
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 1 });
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 2 });
    _ = try s.sendSamplingRequest(&aw.writer, req, .{ .peer = 1 });
    try testing.expectEqual(@as(usize, 3), s.pendingCount());

    s.forgetPeer(1);
    // Both of peer 1's entries went, peer 2's stayed.
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
    try testing.expect(!s.clientCapabilities(1).sampling);
    try testing.expect(s.clientCapabilities(2).sampling);
    // A forgotten peer is back to the pre-handshake default, gate closed.
    try testing.expectError(
        error.SamplingNotSupported,
        s.sendSamplingRequest(&aw.writer, req, .{ .peer = 1 }),
    );
    // Forgetting an unknown peer is a no-op, not a crash.
    s.forgetPeer(999);
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
}

test "max_peers bounds the state a transport that never forgets can accumulate" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.max_peers = 3;
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    for ([_]u64{ 1, 2, 3 }) |p| try handshakePeer(&s, p, "{\"sampling\":{}}");
    try testing.expectEqual(@as(usize, 3), s.peers.items.len);

    // A fourth peer's handshake is refused rather than served — and refused
    // as a JSON-RPC error, so the client learns of it.
    aw.clearRetainingCapacity();
    try s.handleMessageFrom(
        \\{"jsonrpc":"2.0","id":9,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{}}}}
    , &aw.writer, 4);
    try testing.expect(std.mem.find(u8, aw.written(), "\"error\"") != null);
    try testing.expectEqual(@as(usize, 3), s.peers.items.len);
    try testing.expect(!s.clientCapabilities(4).sampling);

    // Freeing one slot lets the next session in.
    s.forgetPeer(2);
    try handshakePeer(&s, 4, "{\"sampling\":{}}");
    try testing.expect(s.clientCapabilities(4).sampling);
}

test "notifications/initialized carrying an id is answered, not silently absorbed (re-audit F14)" {
    // "A request (has `id`) gets exactly one response" is a stated invariant
    // (README, SPEC, the dispatch doc). This arm sat in front of the id check,
    // so the shape mutated server state and wrote nothing back — a strict
    // client waits forever for a reply that never comes.
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"notifications/initialized\"}", &aw.writer);
    try testing.expect(aw.written().len > 0);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        testing.allocator,
        std.mem.trimEnd(u8, aw.written(), "\n"),
        .{},
    );
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 42), parsed.value.object.get("id").?.integer);
    try testing.expectEqual(
        @as(i64, error_code.invalid_request),
        parsed.value.object.get("error").?.object.get("code").?.integer,
    );
    // A message we are rejecting must not have moved the lifecycle flag.
    try testing.expect(!s.clientInitialized(0));

    // The notification form still works and still gets no response.
    aw.clearRetainingCapacity();
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", &aw.writer);
    try testing.expectEqualStrings("", aw.written());
    try testing.expect(s.clientInitialized(0));
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

test "correlation: error wins over result in an answer carrying both; a code outside i32 is internal_error, never a crash" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const cases = [_]struct { body: []const u8, code: i32 }{
        // JSON-RPC forbids both members; the error is the safer reading —
        // a result read from a message that also says "failed" is a guess.
        .{ .body = "\"result\":{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"x\"},\"model\":\"m\"},\"error\":{\"code\":-1,\"message\":\"no\"}", .code = -1 },
        // The peer's code is any JSON integer; ours is an i32. Out of range
        // it is not the peer's code at all, so the default stands -- an
        // `@intCast` here would let any client crash the server.
        .{ .body = "\"error\":{\"code\":4294967296,\"message\":\"big\"}", .code = error_code.internal_error },
        .{ .body = "\"error\":{\"code\":-2147483649,\"message\":\"small\"}", .code = error_code.internal_error },
        .{ .body = "\"error\":{\"code\":2147483647,\"message\":\"edge\"}", .code = std.math.maxInt(i32) },
        .{ .body = "\"error\":{\"code\":-2147483648,\"message\":\"edge\"}", .code = std.math.minInt(i32) },
    };
    for (cases) |c| {
        var col = Collector{};
        const id = try s.sendSamplingRequest(&aw.writer, .{
            .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
            .max_tokens = 10,
        }, .{ .on_response = &Collector.on, .ctx = &col });
        aw.clearRetainingCapacity();
        const line = try testing.allocator.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},{s}}}", .{ id, c.body });
        defer testing.allocator.free(line);
        try s.handleMessage(line, &aw.writer);
        try testing.expectEqualStrings("", aw.written());
        try testing.expectEqual(@as(u32, 1), col.calls);
        try testing.expectEqual(@as(?i32, c.code), col.last_error_code);
    }
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
    try handshakePeer(&s, 7, "{\"sampling\":{}}");
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

test "outbound: the pending table's DEFAULT cap is 256 (re-audit F6)" {
    // Re-audit 2026-08-11 F6: the test below sets `max_pending = 2` itself, so
    // the DEFAULT — the only value any in-tree consumer actually runs with —
    // was unpinned: `256` → `maxInt(usize)` was a green mutation (exit 0),
    // which is exactly "a client that never answers grows this without bound".
    // Absolute numbers only; the field is never assigned here.
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    try testing.expectEqual(@as(usize, 256), s.max_pending);

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const req = SamplingRequest{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 10,
    };
    // 256 unanswered requests fit; the 257th is refused.
    for (0..256) |i| {
        _ = s.sendSamplingRequest(&aw.writer, req, .{}) catch |err| {
            std.debug.print("refused at request {d}\n", .{i + 1});
            return err;
        };
        aw.clearRetainingCapacity();
    }
    try testing.expectEqual(@as(usize, 256), s.pendingCount());
    try testing.expectError(error.TooManyPending, s.sendSamplingRequest(&aw.writer, req, .{}));
    try testing.expectEqualStrings("", aw.written()); // refused before anything is written
    try testing.expectEqual(@as(usize, 256), s.pendingCount());
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
    try handshakePeer(&s, 42, "{\"elicitation\":{}}");
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
        \\
    ;
    var in: std.Io.Reader = .fixed(input);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.serve(&in, &aw.writer);

    const expected =
        \\{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"t","title":"t","version":"0"}}}
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
    try testing.expect(std.mem.find(u8, aw.written(), "\"sampling\"") == null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"elicitation\"") == null);
}

// ── spec-literal anchors: the rest of the surface ───────────────────────────
//
// Sampling/elicitation were already anchored on the spec's own JSON examples
// (see above). Everything below extends the same treatment to every other
// method this server dispatches or emits — retrieved verbatim from
// modelcontextprotocol/modelcontextprotocol (2025-11-25 spec pages), never
// reconstructed from memory. See `spec_anchor_index` for the classification
// (`.literal_example` / `.partial` / `.no_example`) and why.

test "mcp: spec-anchor classification matches the dispatch surface (canary)" {
    // If this trips, a method was added to/removed from handleMessage's
    // dispatch chain (or the server->client send surface) without updating
    // `spec_anchor_index` -- reclassify, don't just bump the numbers.
    //
    // Re-audit 2026-08-11 F9: this canary used to assert the literals 14/8/6
    // and NEVER READ the dispatch chain, so it could only fire when someone
    // edited the index itself. A dispatch arm added without a spec anchor was
    // invisible (proved by adding `zzprobe/undeclared` to handleMessage: exit
    // 0). It now derives one side from the other -- `DispatchMethod` is the
    // list `handleMessage`'s exhaustive switch is written over, and
    // `OriginatedMethod` supplies the wire name every emitter prints -- and
    // checks both directions, so neither list can drift from the index.
    const dispatched = comptime std.meta.fieldNames(DispatchMethod);
    const originated = comptime std.meta.fieldNames(OriginatedMethod);

    // Direction 1: every method the code really speaks is classified here.
    for (dispatched ++ originated) |name| {
        var found = false;
        for (spec_anchor_index) |m| {
            if (eql(m.method, name)) found = true;
        }
        testing.expect(found) catch {
            std.debug.print("method with no spec_anchor_index entry: {s}\n", .{name});
            return error.TestUnexpectedResult;
        };
    }
    // Direction 2: no stale entry -- everything classified is really spoken.
    for (spec_anchor_index) |m| {
        var found = false;
        for (dispatched ++ originated) |name| {
            if (eql(m.method, name)) found = true;
        }
        testing.expect(found) catch {
            std.debug.print("spec_anchor_index entry for a method nothing speaks: {s}\n", .{m.method});
            return error.TestUnexpectedResult;
        };
    }
    // ...and no duplicate entries, which would let one method's classification
    // stand in for another's in the two loops above.
    for (spec_anchor_index, 0..) |a, i| {
        for (spec_anchor_index[i + 1 ..]) |b| {
            try testing.expect(!eql(a.method, b.method));
        }
    }
    try testing.expectEqual(dispatched.len + originated.len, spec_anchor_index.len);

    // The classification split stays pinned (a downgrade to `.no_example`
    // must be a deliberate edit), and every non-literal entry must say why.
    var literal: usize = 0;
    var partial: usize = 0;
    var no_example: usize = 0;
    for (spec_anchor_index) |m| {
        switch (m.anchor) {
            .literal_example => literal += 1,
            .partial => {
                partial += 1;
                try testing.expect(m.reason.len != 0); // every partial entry must say what's missing and why
            },
            .no_example => {
                no_example += 1;
                try testing.expect(m.reason.len != 0);
            },
        }
    }
    try testing.expectEqual(@as(usize, 15), literal);
    try testing.expectEqual(@as(usize, 6), partial);
    try testing.expectEqual(@as(usize, 4), no_example);
}

test "initialize: decodes the spec's own request verbatim (lifecycle.mdx)" {
    var s = testServer(null);
    defer s.deinit();
    // Verbatim from the MCP 2025-11-25 lifecycle page's "Initialization"
    // section (the client->server initialize request), compacted. Exercises
    // capability shapes and clientInfo fields (title/description/icons/
    // websiteUrl, a `tasks` capability) this module doesn't otherwise
    // register or use, to prove they decode without crashing or mis-parsing
    // the fields we DO read.
    try feed(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true},"sampling":{},"elicitation":{"form":{},"url":{}},"tasks":{"requests":{"elicitation":{"create":{}},"sampling":{"createMessage":{}}}}},"clientInfo":{"name":"ExampleClient","title":"Example Client Display Name","version":"1.0.0","description":"An example MCP client application","icons":[{"src":"https://example.com/icon.png","mimeType":"image/png","sizes":["48x48"]}],"websiteUrl":"https://example.com"}}}
    );
    try testing.expectEqualStrings("2025-11-25", s.negotiatedVersion(0));
    try testing.expect(s.clientCapabilities(0).roots);
    try testing.expect(s.clientCapabilities(0).roots_list_changed);
    try testing.expect(s.clientCapabilities(0).sampling);
    try testing.expect(!s.clientCapabilities(0).sampling_tools);
    try testing.expect(!s.clientCapabilities(0).sampling_context);
    try testing.expect(s.clientCapabilities(0).elicitation);
    try testing.expect(s.clientCapabilities(0).elicitation_form);
    try testing.expect(s.clientCapabilities(0).elicitation_url);
    // The response itself cannot be byte-identical to the spec's (see
    // spec_anchor_index) -- this server's capability shape is fixed and
    // narrower (no `logging`, no `tasks`, listChanged always false).
}

test "ping: byte-identical to the spec's example (basic/utilities/ping.mdx)" {
    var s = testServer(null);
    defer s.deinit();
    // Verbatim from the ping page (the id "123" is the spec's own).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":"123","method":"ping"}
    ,
        \\{"jsonrpc":"2.0","id":"123","result":{}}
        \\
    );
}

test "tools/list: the spec's cursor-bearing request decodes verbatim (cursor ignored while page_size is 0)" {
    var s = testServer(null);
    defer s.deinit();
    // Verbatim request from server/tools.mdx ("Listing Tools"); this module
    // doesn't implement pagination (SPEC.md), so `cursor` is accepted and
    // ignored rather than rejected -- the catalog comes back exactly as it
    // would without the param. The spec's illustrative response (`title`,
    // `icons`, `execution` on the Tool) can't be reproduced byte-for-byte:
    // this module's `Tool` has none of those fields (see spec_anchor_index).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"optional-cursor-value"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"Echo the 'text' argument back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]},"outputSchema":{"type":"object","properties":{"echo":{"type":"string"},"calls":{"type":"integer"}}}}]}}
        \\
    );
}

fn getWeatherHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("Current weather in New York:\nTemperature: 72°F\nConditions: Partly cloudy");
    return false;
}

test "tools/call: byte-identical to the spec's get_weather example (server/tools.mdx)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "get_weather",
        .description = "Get current weather information for a location",
        .input_schema =
        \\{"type":"object","properties":{"location":{"type":"string","description":"City name or zip code"}},"required":["location"]}
        ,
        .handler = &getWeatherHandler,
    });
    // Verbatim request + response from "Calling Tools".
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"New York"}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Current weather in New York:\nTemperature: 72°F\nConditions: Partly cloudy"}],"isError":false}}
        \\
    );
}

fn getWeatherDataHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("{\"temperature\": 22.5, \"conditions\": \"Partly cloudy\", \"humidity\": 65}");
    return false;
}

test "tools/call: structuredContent is byte-identical to the spec's output-schema example" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "get_weather_data",
        .description = "Get current weather data for a location",
        .input_schema =
        \\{"type":"object","properties":{"location":{"type":"string","description":"City name or zip code"}},"required":["location"]}
        ,
        .output_schema =
        \\{"type":"object","properties":{"temperature":{"type":"number","description":"Temperature in celsius"},"conditions":{"type":"string","description":"Weather conditions description"},"humidity":{"type":"number","description":"Humidity percentage"}},"required":["temperature","conditions","humidity"]}
        ,
        .handler = &getWeatherDataHandler,
    });
    // The spec (server/tools.mdx "Output Schema") shows this tool's
    // definition and its response verbatim, but not the triggering request
    // for that specific exchange -- the request's `arguments.location` value
    // is ours; the tool definition and the whole response (content.text +
    // structuredContent, byte-for-byte, including the response's own
    // internal whitespace) are the spec's literal text.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_weather_data","arguments":{"location":"Paris"}}}
    ,
        \\{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"{\"temperature\": 22.5, \"conditions\": \"Partly cloudy\", \"humidity\": 65}"}],"structuredContent":{"temperature": 22.5, "conditions": "Partly cloudy", "humidity": 65},"isError":false}}
        \\
    );
}

test "tools/call: Unknown tool error code matches the spec's example (message text is not spec-mandated)" {
    var s = testServer(null);
    defer s.deinit();
    // Spec's own "Example protocol error" (server/tools.mdx "Error Handling"):
    // {"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Unknown tool:
    // invalid_tool_name"}}. JSON-RPC/MCP fixes the *code* (-32602, invalid
    // params) for an unknown tool name; the message string is human-readable
    // prose, not part of the wire contract -- this module's own "Unknown
    // tool" (no name suffix) is a stylistic choice, not a disagreement.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"invalid_tool_name"}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Unknown tool"}}
        \\
    );
}

fn flightValidationHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("Invalid departure date: must be in the future. Current date is 08/08/2025.");
    return true;
}

test "tools/call: execution-error content is byte-identical to the spec's example (isError:true)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    // The tool name is ours (the spec's "Example tool execution error" names
    // none); the id and the content text are its literal bytes.
    try s.addTool(.{
        .name = "book_flight",
        .description = "d",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &flightValidationHandler,
    });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"book_flight","arguments":{}}}
    ,
        \\{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"Invalid departure date: must be in the future. Current date is 08/08/2025."}],"isError":true}}
        \\
    );
}

const spec_main_rs_body =
    \\fn main() {
    \\    println!("Hello world!");
    \\}
;

fn mainRsReader(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    req.text(req.uri, "text/x-rust", spec_main_rs_body);
    return true;
}

test "resources/read: byte-identical to the spec's example (server/resources.mdx)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addResource(.{
        .uri = "file:///project/src/main.rs",
        .name = "main.rs",
        .mime_type = "text/x-rust",
        .handler = &mainRsReader,
    });
    // Verbatim request + response from "Reading Resources".
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///project/src/main.rs"}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"contents":[{"uri":"file:///project/src/main.rs","mimeType":"text/x-rust","text":"fn main() {\n    println!(\"Hello world!\");\n}"}]}}
        \\
    );
}

test "resources/list: the spec's cursor-bearing request decodes verbatim (cursor ignored while page_size is 0)" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    // Verbatim request from server/resources.mdx ("Listing Resources"). The
    // spec's illustrative response (`title`, `icons` on the Resource) can't
    // be reproduced byte-for-byte: this module's `Resource` has neither (see
    // spec_anchor_index) -- covered instead by the existing golden
    // resources/list test, unmodified.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{"cursor":"optional-cursor-value"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"resources":[{"uri":"mem://readme","name":"readme","description":"Project readme.","mimeType":"text/plain"},{"uri":"mem://logo","name":"logo"},{"uri":"mem://gone","name":"gone"}]}}
        \\
    );
}

test "prompts/list: the spec's cursor-bearing request decodes verbatim (cursor ignored while page_size is 0)" {
    var lib = TestLibrary{};
    var s = try libraryServer(&lib);
    defer s.deinit();
    // Verbatim request from server/prompts.mdx ("Listing Prompts"). The
    // spec's illustrative response (`title`, `icons` on the Prompt) can't be
    // reproduced byte-for-byte: this module's `Prompt` has neither.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{"cursor":"optional-cursor-value"}}
    ,
        \\{"jsonrpc":"2.0","id":1,"result":{"prompts":[{"name":"greet","description":"Render a greeting request.","arguments":[{"name":"who","description":"Who to greet.","required":true},{"name":"tone","description":"Optional tone."}]},{"name":"broken"}]}}
        \\
    );
}

fn codeReviewHandler(ctx: ?*anyopaque, req: *PromptRequest) bool {
    _ = ctx;
    const code = req.strArg("code") orelse return false;
    req.printMessage(.user, "Please review this Python code:\n{s}", .{code});
    return true;
}

test "prompts/get: byte-identical to the spec's code_review example (server/prompts.mdx)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    const args = [_]PromptArgument{.{ .name = "code", .description = "The code to review", .required = true }};
    try s.addPrompt(.{
        .name = "code_review",
        .description = "Code review prompt",
        .arguments = &args,
        .handler = &codeReviewHandler,
    });
    // Verbatim request + response from "Getting a Prompt".
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"code_review","arguments":{"code":"def hello():\n    print('world')"}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"description":"Code review prompt","messages":[{"role":"user","content":{"type":"text","text":"Please review this Python code:\ndef hello():\n    print('world')"}}]}}
        \\
    );
}

fn reticulateHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.reportProgress(50, 100, "Reticulating splines...");
    call.write("{\"done\":true}");
    return false;
}

test "notifications/progress: byte-identical to the spec's example (basic/utilities/progress.mdx)" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{
        .name = "reticulate",
        .description = "d",
        .input_schema = "{\"type\":\"object\"}",
        .handler = &reticulateHandler,
    });
    // The triggering tools/call is ours (the spec's progress page illustrates
    // the token-carrying request generically, as method "some_method", which
    // isn't a dispatchable method here). The notification line the receiver
    // "MAY then send" is the spec's literal text, verbatim; the trailing
    // tools/call result line is this module's own (self-authored) shape.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reticulate","_meta":{"progressToken":"abc123"}}}
    ,
        \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"abc123","progress":50,"total":100,"message":"Reticulating splines..."}}
        \\{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"done\":true}"}],"structuredContent":{"done":true},"isError":false}}
        \\
    );
}

test "notifications/cancelled: field shape matches the spec's example (basic/utilities/cancellation.mdx)" {
    var s = try serverWithCaps("{\"sampling\":{}}");
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    // Force the next outbound id to 123 to line up with the spec's
    // illustrative `requestId` -- this module's ids are always its own
    // monotonic u64s, so the value is ours to pick; the spec's id happens to
    // be a quoted string ("123") where ours is a bare integer (JSON-RPC
    // permits either as a request id; see spec_anchor_index).
    s.next_request_id = 123;
    const id = try s.sendSamplingRequest(&aw.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 1,
    }, .{});
    try testing.expectEqual(@as(u64, 123), id);
    aw.clearRetainingCapacity();

    try s.cancelRequest(&aw.writer, id, "User requested cancellation");
    // Verbatim `params` shape (requestId, reason) and reason text from the
    // cancellation page.
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":123,"reason":"User requested cancellation"}}
        \\
    , aw.written());
}

// ── fuzz: one JSON-RPC message dispatch, never panics ───────────────────────
//
// `handleMessage` is the boundary between a stdio transport (or, via
// `mcp-http`, an HTTP POST body) and this server — a fully untrusted peer
// line reaching every dispatch branch (initialize/tools/resources/prompts),
// not just the JSON parse itself. Drive it against a server with a real
// registered tool so `tools/call`'s param-validation path is reachable too,
// not only the outer parse-error branches.

// ⚠ And it never dispatched one. The harness opened `smith.bytes(&buf)` and
// then drew the length with `smith.valueRangeAtMost`; `bytes` consumes
// `@min(buf.len, in.len)` octets and a ranged draw reads EIGHT more as a
// little-endian `u64`, returning the range MINIMUM when fewer remain, so the
// length was 0 for every input a corpus can carry — and the target had no
// corpus, so the one input it ever ran was empty. `handleMessage("")` is a
// -32700 parse error and not one dispatch branch was entered. The peer id was
// `smith.value(u64)` drawn AFTER the bytes, so it was 0 as well, which means
// the `handleMessageFrom` arm the comment calls out as "the peer arm the
// harness above never exercised" was itself always called with peer 0.
// Measured 2026-09-07: 1 round, 0 non-empty inputs, 0 methods dispatched.

/// `testkit.fuzz.seed`, aliased so the corpus reads as the JSON-RPC lines it
/// is. A corpus entry is not the line: `Smith.slice` reads a little-endian
/// `u32` length first.
const seed = @import("testkit").fuzz.seed;

/// JSON-RPC lines, in the format the length draw reads — one per dispatch
/// branch, because that is what the harness's own comment says it is for and
/// what random bytes cannot reach (a well-formed `"method":"tools/call"` out
/// of noise is not a thing that happens).
const message_seeds = [_][]const u8{
    seed("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"f\",\"version\":\"1\"}}}"),
    seed("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"hi\"}}}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\"}}"), // arguments missing → the param-validation path
    seed("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"nosuchtool\",\"arguments\":{}}}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"resources/list\"}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///nope\"}}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"prompts/list\"}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"ping\"}"),
    seed("{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"no/such/method\"}"), // -32601
    seed("{\"jsonrpc\":\"1.0\",\"id\":12,\"method\":\"ping\"}"), // the wrong protocol version
    seed("{\"jsonrpc\":\"2.0\",\"id\":13}"), // no method at all → -32600
    seed("{\"jsonrpc\":\"2.0\",\"id\":{\"a\":1},\"method\":\"ping\"}"), // an id of a shape the spec forbids
    seed("[{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"ping\"}]"), // a batch, which this server does not accept
    seed("{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"ping\""), // truncated → -32700
    seed("not json at all"),
    seed(""), // zero length: the ONLY input this target ever ran
};

test "fuzz: handleMessage never panics on an arbitrary JSON-RPC line" {
    try testing.fuzz({}, fuzzScript(fuzzHandleMessage), .{ .corpus = &message_seeds });
}

fn fuzzHandleMessage(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    return handleOne(S, src, gpa, false);
}

fn fuzzHandleMessageMutated(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    return handleOne(S, src, gpa, true);
}

fn handleOne(comptime S: type, src: *S, gpa: std.mem.Allocator, mutated: bool) anyerror!void {
    // ⚠ One byte-first draw, and no knob after it: the peer id is no longer
    // drawn at all, because a draw after the bytes is dead on a corpus replay.
    // Both peers run on every input instead, which is more than the single
    // drawn value could give.
    var buf: [512]u8 = undefined;
    var len: usize = undefined;
    if (mutated) {
        // One of `message_seeds`, a few octets damaged, maybe cut short:
        // random bytes never form a request line.
        var smith: std.testing.Smith = .{ .in = message_seeds[src.index(message_seeds.len)] };
        len = smith.slice(&buf);
        if (len != 0) {
            for (0..src.valueRangeAtMost(u8, 0, 3)) |_| buf[src.index(len)] = src.value(u8);
            if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
        }
    } else len = src.slice(&buf);

    // ⭐ A LIVE `TestApp`, not `null`. `testServer(null)` leaves the registered
    // `echo` tool's `ctx` null and `echoHandler` opens with `ctx.?`, so the
    // first `tools/call` for `echo` panics on "attempt to use null value".
    // The harness's own comment says it drives "a server with a real
    // registered tool so `tools/call`'s param-validation path is reachable
    // too" — and with a null ctx that path could not be survived, let alone
    // reached. Nothing noticed, because the collapsed draw meant the target
    // only ever ran `handleMessage("")`; the panic fired on the FIRST seeded
    // run.
    var app: TestApp = .{};
    var s = testServer(&app);
    defer s.deinit();
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    s.handleMessage(buf[0..len], &aw.writer) catch return;
    if (std.mem.find(u8, aw.written(), "\"error\":") != null) fuzz_mark(.error_reply) else fuzz_mark(.ok_reply);
    // The peer arm of the same entry point: `handleMessageFrom` with a
    // non-zero peer, which `handleMessage` does not reach.
    s.handleMessageFrom(buf[0..len], &aw.writer, 7) catch return;
}

test "corpus: every JSON-RPC seed reaches the dispatcher, and the replies are pinned" {
    // ⭐ The measurement, executable. `reply_octets` is the second number and
    // it is the load-bearing one: `handleMessage("")` does not fail — it
    // writes a -32700 parse-error reply and returns cleanly — so a guard
    // counting clean returns, or even replies produced, would have been
    // satisfied by the collapsed harness on every run. Reply octets summed
    // over real methods cannot come from an empty line.
    var nonempty: usize = 0;
    var reply_octets: usize = 0;
    var errors: usize = 0;
    for (message_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;

        var app: TestApp = .{}; // live ctx — see the harness above
        var s = testServer(&app);
        defer s.deinit();
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        s.handleMessage(buf[0..len], &aw.writer) catch continue;
        const out = aw.written();
        reply_octets += out.len;
        if (std.mem.find(u8, out, "\"error\":") != null) errors += 1;
    }
    // Measured 2026-09-07. Before: 1 round, `handleMessage("")`, one -32700.
    try testing.expectEqual(message_seeds.len - 1, nonempty); // the deliberate empty seed
    try testing.expectEqual(@as(usize, 1731), reply_octets);
    try testing.expectEqual(@as(usize, 9), errors);
}

// ── fuzz: the inbound RESPONSE path (re-audit 2026-08-11, F4) ───────────────
//
// The harness above builds `testServer(null)`, which never ISSUES a
// server→client request, so `Server.pending` is empty on every iteration and
// `deliverResponse` returns at its `const idx = found orelse return;` before
// touching one attacker-controlled byte. Everything past that line — the
// JSON-RPC `error`-object decode, `ClientResponse.samplingResult` /
// `elicitationResult` / `userRejected`, `SamplingResult.parse` +
// `parseContentBlock` and `ElicitationResult.parse`, i.e. *every* parser that
// eats client bytes on the newest surface — had zero fuzz coverage.
//
// This harness pre-arms the pending table (both request kinds, two peers) and
// feeds response lines whose id and peer MATCH BY CONSTRUCTION, so the
// correlation always lands and the fuzzer's bytes are spent on the parsers
// instead of on the id lookup. Because the landing is by construction, the
// harness can **assert** it: three hand-written canary deliveries prove the
// aim (handler entered, both result parsers reached, the error branch
// decoded), and every fuzzed round asserts the handler was entered too. If a
// future edit narrows the harness back — arming dropped, the wrong peer, an
// id that cannot match — these assertions fail instead of the suite reading
// green while fuzzing nothing.

const ResponseFuzzProbe = struct {
    calls: u32 = 0,
    sampling_ok: u32 = 0,
    elicitation_ok: u32 = 0,
    err_payloads: u32 = 0,
    rejected: u32 = 0,

    fn on(ctx: ?*anyopaque, resp: *const ClientResponse) void {
        const self: *ResponseFuzzProbe = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        switch (resp.payload) {
            .err => |e| {
                self.err_payloads += 1;
                std.mem.doNotOptimizeAway(e.code);
                std.mem.doNotOptimizeAway(e.message.len);
                if (e.data) |d| std.mem.doNotOptimizeAway(@backingInt(std.meta.activeTag(d)));
                if (resp.userRejected()) self.rejected += 1;
            },
            .result => {},
        }
        // Reach BOTH result parsers on every response, not just the one the
        // request kind implies — a client can answer either shape.
        if (resp.samplingResult()) |r| {
            if (resp.kind == .sampling) self.sampling_ok += 1;
            std.mem.doNotOptimizeAway(r.model.len);
            switch (r.content) {
                .text => |t| std.mem.doNotOptimizeAway(t.len),
                .image, .audio => |m| {
                    std.mem.doNotOptimizeAway(m.data.len);
                    std.mem.doNotOptimizeAway(m.mime_type.len);
                },
            }
        } else |_| {}
        if (resp.elicitationResult()) |r| {
            if (resp.kind == .elicitation) self.elicitation_ok += 1;
            std.mem.doNotOptimizeAway(@backingInt(r.action));
            if (r.content) |c| std.mem.doNotOptimizeAway(c == .object);
        } else |_| {}
    }
};

/// Arm one pending server→client request of `kind` for `peer`, and forget the
/// request line itself — this harness is about the ANSWER.
fn armPending(s: *Server, probe: *ResponseFuzzProbe, kind: RequestKind, peer: u64) !u64 {
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    const opts: RequestOptions = .{ .on_response = &ResponseFuzzProbe.on, .ctx = probe, .peer = peer };
    return switch (kind) {
        .sampling => try s.sendSamplingRequest(&sink.writer, .{
            .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
            .max_tokens = 8,
        }, opts),
        .elicitation => try s.sendElicitationRequest(&sink.writer, .{ .form = .{
            .message = "who are you?",
            .requested_schema = simple_schema,
        } }, opts),
    };
}

/// Feed one response line and assert the JSON-RPC invariant that holds for
/// every one of them: a response is never answered.
fn deliverFuzzLine(s: *Server, line: []const u8, peer: u64) !void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try s.handleMessageFrom(line, &out.writer, peer);
    try testing.expectEqualStrings("", out.written());
}

/// Field names and enum tokens from the spec's own result shapes, so the
/// fuzzer reaches PAST each parser's first type check instead of bouncing off
/// it — the deep branches (`parseContentBlock`'s image/audio arms,
/// `ElicitationResult`'s accept-with-content arm) are the point.
const fuzz_vocab = [_][]const u8{
    "role",    "content", "model",     "stopReason", "type",
    "text",    "data",    "mimeType",  "action",     "accept",
    "decline", "cancel",  "assistant", "user",       "image",
    "audio",   "code",    "message",   "endTurn",    "",
};

/// Printable ASCII only: the LINE must stay valid JSON (the older harness owns
/// the "is this even JSON" question), so fuzzer bytes are spent on structure
/// and on the tag decisions the parsers make, not on UTF-8 validity.
const fuzz_key_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-/.:\\\"{}[]";

fn fuzzJsonString(c: *kit.Cursor, w: *std.Io.Writer) std.Io.Writer.Error!void {
    // Mostly a spec token, otherwise fuzzer text (see `fuzz_key_alphabet`).
    const pick = c.ranged(0, fuzz_vocab.len);
    if (pick < fuzz_vocab.len) {
        try std.json.Stringify.encodeJsonString(fuzz_vocab[pick], .{}, w);
        return;
    }
    const n = c.ranged(0, 32);
    var mapped: [32]u8 = undefined;
    for (mapped[0..n]) |*m| m.* = fuzz_key_alphabet[c.byte() % fuzz_key_alphabet.len];
    try std.json.Stringify.encodeJsonString(mapped[0..n], .{}, w);
}

fn fuzzJsonValue(c: *kit.Cursor, w: *std.Io.Writer, depth: u8) std.Io.Writer.Error!void {
    switch (c.ranged(0, if (depth == 0) 5 else 7)) {
        0 => try fuzzJsonString(c, w),
        1 => try w.print("{d}", .{@as(i32, @bitCast((@as(u32, c.word()) << 16) | c.word()))}),
        2 => try w.writeAll("true"),
        3 => try w.writeAll("false"),
        4 => try w.writeAll("null"),
        5 => try w.print("{d}.5", .{@as(i16, @bitCast(c.word()))}),
        6 => {
            try w.writeByte('{');
            const n = c.ranged(0, 3);
            // Keys must be UNIQUE: `std.json`'s default
            // `duplicate_field_behavior` is `.@"error"`, so a repeated key
            // makes the whole line a -32700 parse error and it never reaches
            // `deliverResponse` at all (measured — this cost the first fuzz
            // run of this harness). A vocab key is skipped when already used;
            // a fuzzer-generated key is prefixed with its slot, so two of them
            // cannot collide either.
            var used: [4]usize = @splat(fuzz_vocab.len);
            var emitted: usize = 0;
            for (0..n) |i| {
                const pick = c.ranged(0, fuzz_vocab.len);
                if (pick < fuzz_vocab.len) {
                    var dup = false;
                    for (used[0..emitted]) |u| {
                        if (u == pick) dup = true;
                    }
                    if (dup) continue;
                }
                if (emitted != 0) try w.writeByte(',');
                used[emitted] = pick;
                emitted += 1;
                if (pick < fuzz_vocab.len) {
                    try std.json.Stringify.encodeJsonString(fuzz_vocab[pick], .{}, w);
                } else {
                    const m = c.ranged(0, 12);
                    var kbuf: [32]u8 = undefined;
                    var key_len: usize = (std.mem.print(&kbuf, "k{d}", .{i}) catch unreachable).len;
                    for (0..m) |_| {
                        kbuf[key_len] = fuzz_key_alphabet[c.byte() % fuzz_key_alphabet.len];
                        key_len += 1;
                    }
                    try std.json.Stringify.encodeJsonString(kbuf[0..key_len], .{}, w);
                }
                try w.writeByte(':');
                try fuzzJsonValue(c, w, depth - 1);
            }
            try w.writeByte('}');
        },
        else => {
            try w.writeByte('[');
            const n = c.ranged(0, 3);
            for (0..n) |i| {
                if (i != 0) try w.writeByte(',');
                try fuzzJsonValue(c, w, depth - 1);
            }
            try w.writeByte(']');
        },
    }
}

/// `{"jsonrpc":"2.0","id":<id>,"result":<fuzz>}` or the `"error"` twin — the
/// exact two shapes `deliverResponse` decodes.
fn buildFuzzResponse(c: *kit.Cursor, w: *std.Io.Writer, id: u64) std.Io.Writer.Error!void {
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},", .{id});
    if (c.ranged(0, 3) == 0) {
        try w.writeAll("\"error\":");
        // Mostly the spec's error-object shape, sometimes an arbitrary value,
        // so both the `e == .object` arm and its else are exercised.
        if (c.ranged(0, 3) != 0) {
            try w.writeAll("{\"code\":");
            try fuzzJsonValue(c, w, 0);
            try w.writeAll(",\"message\":");
            try fuzzJsonValue(c, w, 0);
            try w.writeAll(",\"data\":");
            try fuzzJsonValue(c, w, 1);
            try w.writeByte('}');
        } else {
            try fuzzJsonValue(c, w, 2);
        }
    } else {
        try w.writeAll("\"result\":");
        try fuzzJsonValue(c, w, 2);
    }
    try w.writeByte('}');
}

/// `testkit.fuzz.Cursor`. This harness draws a SHAPE — which request kind,
/// which peer, and the JSON tree of the answer — not a byte string, so there
/// is no frame to be faithful to. `Cursor` reads every choice out of ONE
/// byte-first `smith.slice`, which makes the draw honest and makes a seed a
/// readable script; a short script CYCLES rather than running out. Under
/// `--fuzz` the fuzzer still drives every choice, because it drives the slice.
const kit = @import("testkit").fuzz;

/// Scripts for the fuzzed rounds: kind, peer, then the JSON tree.
const response_scripts = [_][]const u8{
    // ⛔ The empty script reproduces the collapsed harness EXACTLY: every read
    //    is 0, so all four rounds were `.sampling` on peer 0 carrying
    //    `"result":<the first vocab string>` — four identical answers.
    seed(""),
    seed("\x01\x02\x04"), // elicitation on peer 2, a null result
    seed("\x00\x01\x06\x02\x00\x01\x02"), // sampling on peer 1, an object result with two keys
    seed("\x01\x00\x07\x03\x00\x02\x04"), // elicitation on peer 0, an array result
    seed("\x00\x02\x00\x00"), // the `"error"` twin: `c.ranged(0, 3)` reads 0, so the error arm runs
    seed("\x00\x00\x01\x7f\xff\x7f\xff"), // a large integer result
    seed("\x01\x01\x05\x80\x00"), // a fractional result
    seed("\x00\x02\x06\x03\x0e\x0e\x0e"), // an object whose keys all come from the fuzzer alphabet, not the vocab
};

test "corpus: every response script builds a distinct line, and the octets are pinned" {
    // ⭐ The measurement, executable. It drives `buildFuzzResponse` through a
    // `Cursor` exactly the way the harness does.
    //
    // `distinct` is the second number and it is the load-bearing one: the
    // harness's per-round `before + 1 == probe.calls` assertion was TRUE on
    // every collapsed run — all four rounds did reach the handler — while the
    // four answers were byte-identical. Reaching the handler was never the
    // question; carrying different payloads there was.
    var octets: usize = 0;
    var distinct: usize = 0;
    var seen: [response_scripts.len][256]u8 = undefined;
    var seen_len: [response_scripts.len]usize = undefined;
    for (response_scripts, 0..) |sd, si| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [64]u8 = undefined;
        const n: usize = smith.slice(&script);
        var c = kit.Cursor{ .bytes = script[0..n] };

        var line: std.Io.Writer.Allocating = .init(testing.allocator);
        defer line.deinit();
        try buildFuzzResponse(&c, &line.writer, 1);
        const out = line.written();
        octets += out.len;

        var dup = false;
        for (0..si) |j| {
            if (std.mem.eql(u8, seen[j][0..seen_len[j]], out)) dup = true;
        }
        if (!dup) distinct += 1;
        seen_len[si] = @min(out.len, 256);
        @memcpy(seen[si][0..seen_len[si]], out[0..seen_len[si]]);
    }
    // Measured 2026-09-07. Before: the four fuzzed rounds built ONE distinct
    // line, repeated.
    try testing.expectEqual(@as(usize, 8), distinct); // all eight scripts, none repeating another
    try testing.expectEqual(@as(usize, 470), octets);
}

test "fuzz: an arbitrary client RESPONSE never panics and always reaches the parsers" {
    try testing.fuzz({}, fuzzScript(fuzzClientResponse), .{ .corpus = &response_scripts });
}

fn fuzzClientResponse(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // ⚠ ONE byte-first draw, then a `Cursor` over it. What stood here drew
    // every choice from `smith` directly, opening with `smith.index(2)`. A
    // `Smith` ranged draw returns the range MINIMUM when fewer than eight
    // octets remain, and this target carried no corpus, so outside `--fuzz`
    // the single input it ever ran was empty and EVERY choice collapsed: all
    // four "fuzzed rounds" were `.sampling` on peer 0 carrying the same
    // `"result"` value, and the miss-path round used id 0 and peer 0 — which
    // is a peer that IS armed, so even that was not the miss it is named for.
    // The aim canary below is hand-written and did keep working, which is why
    // this target looked healthy: it asserted three correlating answers that
    // do not depend on the fuzzer at all. Measured 2026-09-07: 1 round,
    // 4 identical fuzzed answers, 1 distinct JSON shape.
    var script: [64]u8 = undefined;
    const script_len: usize = src.slice(&script);
    var c = kit.Cursor{ .bytes = script[0..script_len] };
    var s = try serverWithCaps("{\"sampling\":{},\"elicitation\":{\"form\":{},\"url\":{}}}");
    defer s.deinit();
    // Every peer this harness arms a request for must have handshaken:
    // the capability gate is per-peer, and `smith.index(3)` picks 0..2.
    for ([_]u64{ 1, 2, 7 }) |p| {
        try handshakePeer(&s, p, "{\"sampling\":{},\"elicitation\":{\"form\":{},\"url\":{}}}");
    }
    var probe: ResponseFuzzProbe = .{};
    var line: std.Io.Writer.Allocating = .init(testing.allocator);
    defer line.deinit();

    // ── aim canary: three hand-written, correlating answers. These do not
    // depend on the fuzzer at all — they fail the moment this harness stops
    // reaching the surface it exists for.
    {
        const id = try armPending(&s, &probe, .sampling, 0);
        line.clearRetainingCapacity();
        try line.writer.print(
            "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{{\"role\":\"assistant\",\"content\":{{\"type\":\"text\",\"text\":\"ok\"}},\"model\":\"m\"}}}}",
            .{id},
        );
        try deliverFuzzLine(&s, line.written(), 0);
    }
    {
        const id = try armPending(&s, &probe, .elicitation, 7);
        line.clearRetainingCapacity();
        try line.writer.print(
            "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{{\"action\":\"accept\",\"content\":{{\"name\":\"z\"}}}}}}",
            .{id},
        );
        try deliverFuzzLine(&s, line.written(), 7);
    }
    {
        const id = try armPending(&s, &probe, .sampling, 0);
        line.clearRetainingCapacity();
        try line.writer.print(
            "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"error\":{{\"code\":-1,\"message\":\"User rejected\",\"data\":{{\"k\":1}}}}}}",
            .{id},
        );
        try deliverFuzzLine(&s, line.written(), 0);
    }
    try testing.expectEqual(@as(u32, 3), probe.calls);
    try testing.expectEqual(@as(u32, 1), probe.sampling_ok); // SamplingResult.parse + parseContentBlock
    try testing.expectEqual(@as(u32, 1), probe.elicitation_ok); // ElicitationResult.parse
    try testing.expectEqual(@as(u32, 1), probe.err_payloads); // the error-object decode
    try testing.expectEqual(@as(u32, 1), probe.rejected); // ClientResponse.userRejected
    try testing.expectEqual(@as(usize, 0), s.pendingCount());

    // ── the fuzzed rounds: arbitrary result/error payloads on a correlating
    // id + peer, so every one of them MUST reach the handler.
    for (0..4) |_| {
        const kind: RequestKind = if (c.ranged(0, 1) == 0) .sampling else .elicitation;
        const peer: u64 = c.ranged(0, 2);
        const id = try armPending(&s, &probe, kind, peer);
        line.clearRetainingCapacity();
        try buildFuzzResponse(&c, &line.writer, id);
        const before = probe.calls;
        const err_before = probe.err_payloads;
        try deliverFuzzLine(&s, line.written(), peer);
        try testing.expectEqual(before + 1, probe.calls);
        if (probe.err_payloads != err_before) fuzz_mark(.error_payload) else fuzz_mark(.result_unparsed);
        try testing.expectEqual(@as(usize, 0), s.pendingCount());
    }

    // ── and the miss paths: an id/peer the fuzzer chose freely, against one
    // armed entry. No assertion on `calls` — the point here is that a
    // non-matching id, a foreign peer or a junk id shape is a silent drop.
    {
        _ = try armPending(&s, &probe, .sampling, 1);
        line.clearRetainingCapacity();
        try buildFuzzResponse(&c, &line.writer, c.word());
        try deliverFuzzLine(&s, line.written(), c.word());
    }
}

// ── spec 2026-07-28: the stateless path ─────────────────────────────────────
//
// The oracle strings below are quoted verbatim from the MCP specification
// repository (`schema/2026-07-28/examples/**` and the
// `docs/specification/2026-07-28/**` pages) — the same citation relationship,
// and the same provenance reasoning, as the 2025-11-25 anchors above. Where a
// test changes one byte of a quoted request (an `id`), it says so.

/// JSON value equality with object members compared as a set: the spec's
/// examples are pretty-printed in their author's member order, ours puts
/// `resultType` first, and neither order carries meaning.
fn jsonValueEql(a: std.json.Value, b: std.json.Value) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .integer, .float, .number_string => {
            const fa = jsonNumber(a) orelse return false;
            const fb = jsonNumber(b) orelse return false;
            return fa == fb;
        },
        .string => |x| return b == .string and eql(x, b.string),
        .array => |x| {
            if (b != .array or b.array.items.len != x.items.len) return false;
            for (x.items, b.array.items) |ea, eb| {
                if (!jsonValueEql(ea, eb)) return false;
            }
            return true;
        },
        .object => |x| {
            if (b != .object or b.object.count() != x.count()) return false;
            var it = x.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse return false;
                if (!jsonValueEql(e.value_ptr.*, other)) return false;
            }
            return true;
        },
    }
}

fn jsonNumber(v: std.json.Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |str| std.fmt.parseFloat(f64, str) catch null,
        else => null,
    };
}

/// Feed the spec's literal `request`; our reply must be exactly one line and
/// value-equal to the spec's literal `expected` response, after two
/// adjustments, both visible at the call site: each field in `drop_expected`
/// is removed from both `result`s (a field this module does not produce, or
/// produces differently — named in the anchor's reason and checked on its own
/// by the test; it must really be in the example, so a stale drop list
/// fails), and our `result._meta` is removed when the example has none
/// (`serverInfo` is a SHOULD the examples skip).
fn expectSpecResponse(s: *Server, request: []const u8, expected: []const u8, drop_expected: []const []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(request, &aw.writer);
    const line = aw.written();
    try testing.expect(line.len != 0 and line[line.len - 1] == '\n');
    try testing.expect(std.mem.findScalar(u8, line[0 .. line.len - 1], '\n') == null);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var got = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
    var want = try std.json.parseFromSliceLeaky(std.json.Value, arena, expected, .{});
    if (want.object.getPtr("result")) |wr| {
        const got_result: ?*std.json.Value = if (got == .object) got.object.getPtr("result") else null;
        const gr: ?*std.json.Value = if (got_result) |r| (if (r.* == .object) r else null) else null;
        for (drop_expected) |k| {
            try testing.expect(wr.object.orderedRemove(k));
            if (gr) |r| _ = r.object.orderedRemove(k);
        }
        if (wr.object.get("_meta") == null) {
            if (gr) |r| _ = r.object.orderedRemove("_meta");
        }
    }
    if (!jsonValueEql(got, want)) {
        std.debug.print("\n got: {s}\nwant: {s}\n", .{ line, expected });
        return error.TestExpectedEqual;
    }
}

/// Feed one message and return our reply line (caller frees).
fn replyTo(s: *Server, msg: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer aw.deinit();
    try s.handleMessage(msg, &aw.writer);
    return aw.toOwnedSlice();
}

/// The `_meta` every modern request in these tests carries, minus the
/// closing brace so a test can add members. `clientCapabilities` is `{}`.
const modern_meta_open =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ExampleClient","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}
;

fn specWeatherHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    const loc = call.strArg("location") orelse return call.fail("missing 'location'");
    call.print("Current weather in {s}:\nTemperature: 72°F\nConditions: Partly cloudy", .{loc});
    return false;
}

/// The `get_weather` tool exactly as schema/2026-07-28's ListToolsResult
/// example describes it.
const spec_weather_tool = Tool{
    .name = "get_weather",
    .title = "Weather Information Provider",
    .description = "Get current weather information for a location",
    .input_schema =
    \\{"type":"object","properties":{"location":{"type":"string","description":"City name or zip code"}},"required":["location"]}
    ,
    .icons = &.{.{ .src = "https://example.com/weather-icon.png", .mime_type = "image/png", .sizes = &.{"48x48"} }},
    .handler = &specWeatherHandler,
};

fn specMainRsHandler(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    req.text(req.uri, "text/x-rust", "fn main() {\n    println!(\"Hello world!\");\n}");
    return true;
}

fn specMainRsPrivateHandler(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    if (!specMainRsHandler(ctx, req)) return false;
    req.cache = .{ .ttl_ms = 60000, .scope = .private };
    return true;
}

fn specCodeReviewHandler(ctx: ?*anyopaque, req: *PromptRequest) bool {
    _ = ctx;
    const code = req.strArg("code") orelse return false;
    req.printMessage(.user, "Please review this Python code:\n{s}", .{code});
    return true;
}

const spec_discover_request =
    \\{
    \\  "jsonrpc": "2.0",
    \\  "id": "discover-1",
    \\  "method": "server/discover",
    \\  "params": {
    \\    "_meta": {
    \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    \\      "io.modelcontextprotocol/clientInfo": {
    \\        "name": "ExampleClient",
    \\        "version": "1.0.0"
    \\      },
    \\      "io.modelcontextprotocol/clientCapabilities": {}
    \\    }
    \\  }
    \\}
;

test "2026-07-28 anchor: server/discover (schema example + discover.mdx example)" {
    var s = Server.init(testing.allocator, .{ .name = "ExampleServer", .version = "1.0.0" });
    defer s.deinit();
    try s.addTool(spec_weather_tool);
    try s.addResource(.{ .uri = "file:///project/src/main.rs", .name = "main.rs", .handler = &specMainRsHandler });
    s.list_cache = .{ .ttl_ms = 3600000, .scope = .public };

    // schema/2026-07-28/examples/DiscoverResultResponse/discover-result-response.json
    try expectSpecResponse(&s, spec_discover_request,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "discover-1",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "supportedVersions": ["2026-07-28"],
        \\    "capabilities": {
        \\      "tools": {},
        \\      "resources": {}
        \\    },
        \\    "_meta": {
        \\      "io.modelcontextprotocol/serverInfo": {
        \\        "name": "ExampleServer",
        \\        "version": "1.0.0"
        \\      }
        \\    },
        \\    "ttlMs": 3600000,
        \\    "cacheScope": "public"
        \\  }
        \\}
    , &.{"supportedVersions"});

    // docs/specification/2026-07-28/server/discover.mdx "Response" (adds
    // `instructions`).
    s.info.instructions = "This server provides weather and resource utilities.";
    try expectSpecResponse(&s, spec_discover_request,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "discover-1",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "supportedVersions": ["2026-07-28"],
        \\    "capabilities": {
        \\      "tools": {},
        \\      "resources": {}
        \\    },
        \\    "_meta": {
        \\      "io.modelcontextprotocol/serverInfo": {
        \\        "name": "ExampleServer",
        \\        "version": "1.0.0"
        \\      }
        \\    },
        \\    "instructions": "This server provides weather and resource utilities.",
        \\    "ttlMs": 3600000,
        \\    "cacheScope": "public"
        \\  }
        \\}
    , &.{"supportedVersions"});

    // The dropped member, pinned: a dual-era server lists every revision it
    // speaks, stateless first.
    const line = try replyTo(&s, spec_discover_request);
    defer testing.allocator.free(line);
    try testing.expect(std.mem.find(u8, line,
        \\"supportedVersions":["2026-07-28","2025-11-25","2025-06-18"]
    ) != null);
}

test "2026-07-28 anchor: tools/list and tools/call (schema examples)" {
    var s = Server.init(testing.allocator, .{ .name = "ExampleServer", .version = "1.0.0" });
    defer s.deinit();
    try s.addTool(spec_weather_tool);
    s.list_cache = .{ .ttl_ms = 3600000, .scope = .public };

    // ListToolsRequest/list-tools-request.json → ListToolsResultResponse/list-tools-result-response.json
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-tools-example",
        \\  "method": "tools/list",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    }
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-tools-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "tools": [
        \\      {
        \\        "name": "get_weather",
        \\        "title": "Weather Information Provider",
        \\        "description": "Get current weather information for a location",
        \\        "inputSchema": {
        \\          "type": "object",
        \\          "properties": {
        \\            "location": {
        \\              "type": "string",
        \\              "description": "City name or zip code"
        \\            }
        \\          },
        \\          "required": ["location"]
        \\        },
        \\        "icons": [
        \\          {
        \\            "src": "https://example.com/weather-icon.png",
        \\            "mimeType": "image/png",
        \\            "sizes": ["48x48"]
        \\          }
        \\        ]
        \\      }
        \\    ],
        \\    "nextCursor": "next-page-cursor",
        \\    "ttlMs": 3600000,
        \\    "cacheScope": "public"
        \\  }
        \\}
    , &.{"nextCursor"});

    // CallToolRequest/call-tool-request.json → CallToolResultResponse/call-tool-result-response.json
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "call-tool-example",
        \\  "method": "tools/call",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    },
        \\    "name": "get_weather",
        \\    "arguments": {
        \\      "location": "New York"
        \\    }
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "call-tool-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "content": [
        \\      {
        \\        "type": "text",
        \\        "text": "Current weather in New York:\nTemperature: 72°F\nConditions: Partly cloudy"
        \\      }
        \\    ],
        \\    "isError": false
        \\  }
        \\}
    , &.{});
}

test "2026-07-28 anchor: resources/list, resources/templates/list, resources/read (schema examples)" {
    var s = Server.init(testing.allocator, .{ .name = "ExampleServer", .version = "1.0.0" });
    defer s.deinit();
    try s.addResource(.{
        .uri = "file:///project/src/main.rs",
        .name = "main.rs",
        .title = "Rust Software Application Main File",
        .description = "Primary application entry point",
        .mime_type = "text/x-rust",
        .icons = &.{.{ .src = "https://example.com/rust-file-icon.png", .mime_type = "image/png", .sizes = &.{"48x48"} }},
        .handler = &specMainRsPrivateHandler,
    });
    try s.addResourceTemplate(.{
        .uri_template = "file:///{path}",
        .name = "Project Files",
        .title = "Project Files",
        .description = "Access files in the project directory",
        .mime_type = "application/octet-stream",
        .icons = &.{.{ .src = "https://example.com/folder-icon.png", .mime_type = "image/png", .sizes = &.{"48x48"} }},
    });

    // ListResourcesRequest → ListResourcesResultResponse
    s.list_cache = .{ .ttl_ms = 600000, .scope = .private };
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-resources-example",
        \\  "method": "resources/list",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    }
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-resources-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "resources": [
        \\      {
        \\        "uri": "file:///project/src/main.rs",
        \\        "name": "main.rs",
        \\        "title": "Rust Software Application Main File",
        \\        "description": "Primary application entry point",
        \\        "mimeType": "text/x-rust",
        \\        "icons": [
        \\          {
        \\            "src": "https://example.com/rust-file-icon.png",
        \\            "mimeType": "image/png",
        \\            "sizes": ["48x48"]
        \\          }
        \\        ]
        \\      }
        \\    ],
        \\    "nextCursor": "eyJwYWdlIjogM30=",
        \\    "ttlMs": 600000,
        \\    "cacheScope": "private"
        \\  }
        \\}
    , &.{"nextCursor"});

    // ListResourceTemplatesRequest → ListResourceTemplatesResultResponse
    s.list_cache = .{ .ttl_ms = 3600000, .scope = .public };
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-resource-templates-example",
        \\  "method": "resources/templates/list",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    }
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-resource-templates-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "resourceTemplates": [
        \\      {
        \\        "uriTemplate": "file:///{path}",
        \\        "name": "Project Files",
        \\        "title": "Project Files",
        \\        "description": "Access files in the project directory",
        \\        "mimeType": "application/octet-stream",
        \\        "icons": [
        \\          {
        \\            "src": "https://example.com/folder-icon.png",
        \\            "mimeType": "image/png",
        \\            "sizes": ["48x48"]
        \\          }
        \\        ]
        \\      }
        \\    ],
        \\    "ttlMs": 3600000,
        \\    "cacheScope": "public"
        \\  }
        \\}
    , &.{});

    // ReadResourceRequest/read-resource-request.json →
    // ReadResourceResultResponse/read-resource-result-response-with-ttl.json.
    // The two files use different ids; the request's `id` is changed to the
    // response's, nothing else. The TTL comes from the handler overriding the
    // server default (`ResourceRequest.cache`).
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "read-resource-with-ttl-example",
        \\  "method": "resources/read",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    },
        \\    "uri": "file:///project/src/main.rs"
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "read-resource-with-ttl-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "contents": [
        \\      {
        \\        "uri": "file:///project/src/main.rs",
        \\        "mimeType": "text/x-rust",
        \\        "text": "fn main() {\n    println!(\"Hello world!\");\n}"
        \\      }
        \\    ],
        \\    "ttlMs": 60000,
        \\    "cacheScope": "private"
        \\  }
        \\}
    , &.{});

    // server/resources.mdx "Error Handling": the not-found error, compacted —
    // -32602 with data.uri, never the session path's -32002.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{
    ++ modern_meta_open ++
        \\},"uri":"file:///nonexistent.txt"}}
    ,
        \\{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"Resource not found","data":{"uri":"file:///nonexistent.txt"}}}
        \\
    );
    // The session path keeps its revision's code.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"file:///nonexistent.txt"}}
    ,
        \\{"jsonrpc":"2.0","id":6,"error":{"code":-32002,"message":"Resource not found"}}
        \\
    );
}

test "2026-07-28 anchor: prompts/list and prompts/get (schema examples)" {
    var s = Server.init(testing.allocator, .{ .name = "ExampleServer", .version = "1.0.0" });
    defer s.deinit();
    try s.addPrompt(.{
        .name = "code_review",
        .title = "Request Code Review",
        .description = "Asks the LLM to analyze code quality and suggest improvements",
        .arguments = &.{.{ .name = "code", .description = "The code to review", .required = true }},
        .icons = &.{.{ .src = "https://example.com/review-icon.svg", .mime_type = "image/svg+xml", .sizes = &.{"any"} }},
        .handler = &specCodeReviewHandler,
    });
    s.list_cache = .{ .ttl_ms = 600000, .scope = .public };

    // ListPromptsRequest → ListPromptsResultResponse
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-prompts-example",
        \\  "method": "prompts/list",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    }
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "list-prompts-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "prompts": [
        \\      {
        \\        "name": "code_review",
        \\        "title": "Request Code Review",
        \\        "description": "Asks the LLM to analyze code quality and suggest improvements",
        \\        "arguments": [
        \\          {
        \\            "name": "code",
        \\            "description": "The code to review",
        \\            "required": true
        \\          }
        \\        ],
        \\        "icons": [
        \\          {
        \\            "src": "https://example.com/review-icon.svg",
        \\            "mimeType": "image/svg+xml",
        \\            "sizes": ["any"]
        \\          }
        \\        ]
        \\      }
        \\    ],
        \\    "nextCursor": "next-page-cursor",
        \\    "ttlMs": 600000,
        \\    "cacheScope": "public"
        \\  }
        \\}
    , &.{"nextCursor"});

    // GetPromptRequest → GetPromptResultResponse. The two examples describe
    // the prompt differently ("Asks the LLM…" in the list, "Code review
    // prompt" in the get); this module has one description per prompt, so the
    // get runs against a registration carrying the get example's.
    s.prompts.items[0].description = "Code review prompt";
    try expectSpecResponse(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "get-prompt-example",
        \\  "method": "prompts/get",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    },
        \\    "name": "code_review",
        \\    "arguments": {
        \\      "code": "def hello():\n    print('world')"
        \\    }
        \\  }
        \\}
    ,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "get-prompt-example",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "description": "Code review prompt",
        \\    "messages": [
        \\      {
        \\        "role": "user",
        \\        "content": {
        \\          "type": "text",
        \\          "text": "Please review this Python code:\ndef hello():\n    print('world')"
        \\        }
        \\      }
        \\    ]
        \\  }
        \\}
    , &.{});
}

test "2026-07-28: UnsupportedProtocolVersionError lists every revision and echoes the request" {
    var s = testServer(null);
    defer s.deinit();
    // schema example UnsupportedProtocolVersionError/unsupported-version.json
    // is this line with `supported` = ["2026-07-28","2025-11-25"]: a
    // different server's list, not a different shape.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25","2025-06-18"],"requested":"1900-01-01"}}}
        \\
    );
    // A session revision named in `_meta` is not a stateless one: it is
    // reached through `initialize`, and the refusal says which ones exist.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25","2025-06-18"],"requested":"2025-11-25"}}}
        \\
    );
    // The requested string is escaped, not spliced.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"a\"b\n","io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25","2025-06-18"],"requested":"a\"b\n"}}}
        \\
    );
}

test "2026-07-28: malformed per-request metadata is -32602; removed methods are -32601" {
    var s = testServer(null);
    defer s.deinit();
    // Missing the required clientCapabilities.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Missing io.modelcontextprotocol/clientCapabilities"}}
        \\
    );
    // Wrong types for both required fields.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":20260728,"io.modelcontextprotocol/clientCapabilities":{}}}}
    ,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid io.modelcontextprotocol/protocolVersion"}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}
    ,
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid io.modelcontextprotocol/clientCapabilities"}}
        \\
    );
    // Malformed is reported before an unknown version.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}
    ,
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Missing io.modelcontextprotocol/clientCapabilities"}}
        \\
    );
    // server/discover without the version is a malformed modern request.
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":5,"method":"server/discover"}
    ,
        \\{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"Missing io.modelcontextprotocol/protocolVersion"}}
        \\
    );
    // `ping` does not exist in 2026-07-28 …
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"ping\",\"params\":{" ++ modern_meta_open ++ "}}}",
        \\{"jsonrpc":"2.0","id":6,"error":{"code":-32601,"message":"Method not found"}}
        \\
    );
    // … and still answers on the session path.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":7,"result":{}}
        \\
    );
    // `initialize` is the session opener whatever its `_meta` says.
    const line = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"," ++ modern_meta_open ++ "}}}");
    defer testing.allocator.free(line);
    try testing.expect(std.mem.startsWith(u8, line, "{\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{\"protocolVersion\":\"2025-11-25\""));
    // A request whose `_meta` has no protocolVersion stays on the session
    // path — session clients send `_meta` too (progressToken).
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\",\"params\":{\"_meta\":{\"progressToken\":1}}}",
        \\{"jsonrpc":"2.0","id":9,"result":{}}
        \\
    );
}

test "2026-07-28: a modern tools/call result carries resultType and serverInfo; the session one does not" {
    var app = TestApp{};
    var s = testServer(&app);
    defer s.deinit();
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"hi\"}," ++ modern_meta_open ++ "}}}",
        \\{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","content":[{"type":"text","text":"{\"echo\":\"hi\",\"calls\":1}"}],"structuredContent":{"echo":"hi","calls":1},"isError":false,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"test-srv","version":"1.2.3"}}}}
        \\
    );
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}
    ,
        \\{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"{\"echo\":\"hi\",\"calls\":2}"}],"structuredContent":{"echo":"hi","calls":2},"isError":false}}
        \\
    );
    // `title` set → serverInfo carries it.
    s.info.title = "Test Server";
    const line = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\",\"params\":{" ++ modern_meta_open ++ "}}}");
    defer testing.allocator.free(line);
    try testing.expect(std.mem.endsWith(u8, line,
        \\"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"test-srv","title":"Test Server","version":"1.2.3"}},"ttlMs":0,"cacheScope":"private"}}
        \\
    ));
}

const ModernProbe = struct {
    elicitation: bool = false,
    sampling: bool = false,
    version: []const u8 = "",
    client_name: [32]u8 = @splat(0),
    client_name_len: usize = 0,
    send_result: ?SendError!u64 = null,
};

fn modernProbeHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    const p: *ModernProbe = @ptrCast(@alignCast(ctx.?));
    const caps = call.clientCapabilities();
    p.elicitation = caps.elicitation;
    p.sampling = caps.sampling;
    p.version = call.protocolVersion();
    if (call.clientInfo()) |ci| {
        p.client_name_len = @min(ci.name.len, p.client_name.len);
        @memcpy(p.client_name[0..p.client_name_len], ci.name[0..p.client_name_len]);
    }
    p.send_result = call.requestElicitation(.{ .form = .{
        .message = "Your name?",
        .requested_schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}",
    } }, .{});
    call.write("ok");
    return false;
}

test "2026-07-28: capabilities come from the request's _meta, never from (or into) a session" {
    var probe = ModernProbe{};
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "probe", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &modernProbeHandler, .ctx = &probe });

    // A session on peer 0 that declared nothing.
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{}}}", &aw.writer);
    aw.clearRetainingCapacity();

    // A modern request on the same peer declaring elicitation.
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ModernClient","version":"2"},"io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}}}
    , &aw.writer);
    try testing.expect(probe.elicitation);
    try testing.expect(!probe.sampling);
    try testing.expectEqualStrings("2026-07-28", probe.version);
    try testing.expectEqualStrings("ModernClient", probe.client_name[0..probe.client_name_len]);
    // No server→client request exists in that revision — the declared
    // capability does not change that, and nothing went on the wire or into
    // the pending table.
    try testing.expectError(error.StatelessRequest, probe.send_result.?);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
    try testing.expect(std.mem.find(u8, aw.written(), "elicitation/create") == null);
    // The session's gate did not move.
    try testing.expect(!s.clientCapabilities(0).elicitation);
    try testing.expectEqual(@as(usize, 1), s.peers.items.len);

    // And a modern request on a peer that never handshook creates no state.
    aw.clearRetainingCapacity();
    try s.handleMessageFrom("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"probe\"," ++ modern_meta_open ++ "}}}", &aw.writer, 77);
    try testing.expect(!probe.elicitation);
    try testing.expectEqual(@as(usize, 1), s.peers.items.len);
}

fn arrayOutHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.write("[1,2]");
    return false;
}

test "2026-07-28: non-object structuredContent only for a modern call to a tool with an outputSchema" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "typed", .description = "d", .input_schema = "{\"type\":\"object\"}", .output_schema = "{\"type\":\"array\"}", .handler = &arrayOutHandler });
    try s.addTool(.{ .name = "untyped", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &arrayOutHandler });

    const Case = struct { tool: []const u8, modern: bool, structured: bool };
    const cases = [_]Case{
        .{ .tool = "typed", .modern = true, .structured = true },
        .{ .tool = "typed", .modern = false, .structured = false }, // session revisions: objects only
        .{ .tool = "untyped", .modern = true, .structured = false }, // no schema: text stays text
        .{ .tool = "untyped", .modern = false, .structured = false },
    };
    for (cases) |c| {
        var buf: [512]u8 = undefined;
        const msg = if (c.modern)
            try std.mem.print(&buf, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{s}\",{s}}}}}}}", .{ c.tool, modern_meta_open })
        else
            try std.mem.print(&buf, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{s}\"}}}}", .{c.tool});
        const line = try replyTo(&s, msg);
        defer testing.allocator.free(line);
        try testing.expectEqual(c.structured, std.mem.find(u8, line, "\"structuredContent\":[1,2]") != null);
        try testing.expect(c.structured or std.mem.find(u8, line, "structuredContent") == null);
    }
}

fn decliningCacheTemplate(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    req.cache = .{ .ttl_ms = 999, .scope = .public };
    req.text(req.uri, "", "partial");
    return false;
}

fn acceptingTemplate(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    _ = ctx;
    req.text(req.uri, "", "body");
    return true;
}

test "2026-07-28: resources/read caching hint — server default, and a declining template's hint is discarded" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addResourceTemplate(.{ .uri_template = "x:///a/{p}", .name = "a", .handler = &decliningCacheTemplate });
    try s.addResourceTemplate(.{ .uri_template = "x:///b/{p}", .name = "b", .handler = &acceptingTemplate });
    s.read_cache = .{ .ttl_ms = 5, .scope = .private };
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"x:///q\"," ++ modern_meta_open ++ "}}}",
        \\{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","contents":[{"uri":"x:///q","text":"body"}],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"srv","version":"1"}},"ttlMs":5,"cacheScope":"private"}}
        \\
    );
    // The session path has no caching fields at all.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"x:///q\"}}",
        \\{"jsonrpc":"2.0","id":2,"result":{"contents":[{"uri":"x:///q","text":"body"}]}}
        \\
    );
}

test "tools/list: title, icons and annotations are emitted when set (session path too)" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{
        .name = "t",
        .title = "T",
        .description = "d",
        .input_schema = "{\"type\":\"object\"}",
        .icons = &.{.{ .src = "https://e.example/i.png", .mime_type = "image/png", .sizes = &.{"48x48"}, .theme = .dark }},
        .annotations = .{ .read_only_hint = true, .destructive_hint = false },
        .handler = &plainTextHandler,
    });
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
        \\{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","title":"T","icons":[{"src":"https://e.example/i.png","mimeType":"image/png","sizes":["48x48"],"theme":"dark"}],"description":"d","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true,"destructiveHint":false}}]}}
        \\
    );
}

test "mcp: 2026-07-28 spec-anchor classification matches servedStatelessly (canary)" {
    // Both directions, as the session canary: every method a modern request
    // may call is anchored here, and nothing here is unreachable statelessly.
    const dm_info = @typeInfo(DispatchMethod).@"enum";
    inline for (dm_info.field_names, dm_info.field_values) |fname, fvalue| {
        const m: DispatchMethod = @fromBackingInt(@intCast(fvalue));
        var found = false;
        for (modern_spec_anchor_index) |a| {
            if (eql(a.method, fname)) found = true;
        }
        testing.expectEqual(m.servedStatelessly(), found) catch {
            std.debug.print("servedStatelessly/anchor mismatch: {s}\n", .{fname});
            return error.TestUnexpectedResult;
        };
    }
    for (modern_spec_anchor_index, 0..) |a, i| {
        const m = std.meta.stringToEnum(DispatchMethod, a.method) orelse return error.TestUnexpectedResult;
        try testing.expect(m.servedStatelessly());
        for (modern_spec_anchor_index[i + 1 ..]) |b| try testing.expect(!eql(a.method, b.method));
        if (a.anchor != .literal_example) try testing.expect(a.reason.len != 0);
    }
    var literal: usize = 0;
    for (modern_spec_anchor_index) |a| {
        if (a.anchor == .literal_example) literal += 1;
    }
    try testing.expectEqual(@as(usize, 5), literal);
    try testing.expectEqual(@as(usize, 10), modern_spec_anchor_index.len);
}

// ── multi round-trip requests (2026-07-28) ──────────────────────────────────
//
// Anchored on the revision's own MRTR examples: `schema/2026-07-28/examples/
// InputRequests/elicitation-and-sampling-input-requests.json`,
// `InputResponses/elicitation-and-sampling-input-responses.json` and
// `InputRequiredResult/input-required-result-with-request-state-only.json`,
// quoted verbatim below.

/// `_meta` of a modern request whose client declared form elicitation and
/// sampling, closed.
const mrtr_meta =
    \\"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{},"sampling":{}}}
;

/// The spec's weather-like tool made two-round: on the first attempt it asks
/// for the GitHub login and the capital of France (the spec's example pair)
/// plus a state; on the retry it answers from what came back.
const MrtrProbe = struct {
    ask_result: ?InputError!void = null,
    rounds: u32 = 0,
};

fn mrtrHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    const p: *MrtrProbe = @ptrCast(@alignCast(ctx.?));
    p.rounds += 1;
    const login = call.input.elicitation("github_login");
    const capital = call.input.sampling("capital_of_france");
    if (login == null or capital == null) {
        p.ask_result = askSpecPair(call);
        call.write("never sent");
        return false;
    }
    const name = login.?.content.?.object.get("name").?.string;
    call.print("{s}|{s}|{s}", .{ name, capital.?.content.text, call.input.receivedState() orelse "-" });
    return false;
}

fn askSpecPair(call: *ToolCall) InputError!void {
    try call.input.ask("github_login", .{ .elicitation = .{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}",
    } } });
    try call.input.ask("capital_of_france", .{ .sampling = .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "What is the capital of France?" } }},
        .max_tokens = 100,
    } });
    try call.input.setState("eyJsb2NhdGlvbiI6Ik5ldyBZb3JrIn0");
}

test "2026-07-28 MRTR anchor: a tool asks for the spec's InputRequests, then completes from the spec's InputResponses" {
    var probe = MrtrProbe{};
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "login", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &mrtrHandler, .ctx = &probe });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Round 1: the reply is an InputRequiredResult whose `inputRequests` is
    // value-equal to the spec's InputRequests example.
    const first = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"login\"," ++ mrtr_meta ++ "}}");
    defer testing.allocator.free(first);
    try probe.ask_result.?;
    const got = try std.json.parseFromSliceLeaky(std.json.Value, arena, first, .{});
    const result = got.object.get("result").?.object;
    try testing.expectEqualStrings("input_required", result.get("resultType").?.string);
    try testing.expectEqualStrings("eyJsb2NhdGlvbiI6Ik5ldyBZb3JrIn0", result.get("requestState").?.string);
    try testing.expect(result.get("_meta").?.object.get(meta_key.server_info) != null);
    try testing.expect(result.get("content") == null); // the tool's text is discarded
    try testing.expectEqual(@as(usize, 4), result.count());
    const want_requests = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{
        \\  "github_login": {
        \\    "method": "elicitation/create",
        \\    "params": {
        \\      "mode": "form",
        \\      "message": "Please provide your GitHub username",
        \\      "requestedSchema": {
        \\        "type": "object",
        \\        "properties": {
        \\          "name": {
        \\            "type": "string"
        \\          }
        \\        },
        \\        "required": ["name"]
        \\      }
        \\    }
        \\  },
        \\  "capital_of_france": {
        \\    "method": "sampling/createMessage",
        \\    "params": {
        \\      "messages": [
        \\        {
        \\          "role": "user",
        \\          "content": {
        \\            "type": "text",
        \\            "text": "What is the capital of France?"
        \\          }
        \\        }
        \\      ],
        \\      "maxTokens": 100
        \\    }
        \\  }
        \\}
    , .{});
    if (!jsonValueEql(result.get("inputRequests").?, want_requests)) {
        std.debug.print("\n got: {s}\n", .{first});
        return error.TestExpectedEqual;
    }

    // Round 2: the retry (new id) carries the spec's InputResponses example
    // and echoes the state; the same tool now completes.
    const retry = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"login\"," ++ mrtr_meta ++
        \\,"requestState":"eyJsb2NhdGlvbiI6Ik5ldyBZb3JrIn0","inputResponses":{
        \\  "github_login": {
        \\    "action": "accept",
        \\    "content": {
        \\      "name": "octocat"
        \\    }
        \\  },
        \\  "capital_of_france": {
        \\    "role": "assistant",
        \\    "content": {
        \\      "type": "text",
        \\      "text": "The capital of France is Paris."
        \\    },
        \\    "model": "claude-3-sonnet-20240307",
        \\    "stopReason": "endTurn"
        \\  }
        \\}}}
    ;
    const second = try replyTo(&s, retry);
    defer testing.allocator.free(second);
    try testing.expectEqual(@as(u32, 2), probe.rounds);
    try testing.expect(std.mem.find(u8, second, "\"resultType\":\"complete\"") != null);
    try testing.expect(std.mem.find(u8, second, "\"text\":\"octocat|The capital of France is Paris.|eyJsb2NhdGlvbiI6Ik5ldyBZb3JrIn0\"") != null);
    // Nothing was ever pending on the server between the rounds.
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

fn stateOnlyHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    _ = ctx;
    call.input.setState("eyJwcm9ncmVzcyI6IjUwJSIsInN0YXRlIjoicHJvY2Vzc2luZyJ9") catch unreachable;
    return true; // ignored: the state wins
}

test "2026-07-28 MRTR anchor: request state only (load shedding)" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "busy", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &stateOnlyHandler });
    // InputRequiredResult/input-required-result-with-request-state-only.json
    // as the `result` of our reply to a `tools/call` (id 1).
    try expectSpecResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"busy\"," ++ modern_meta_open ++ "}}}",
        \\{"jsonrpc":"2.0","id":1,"result":
        \\{
        \\  "resultType": "input_required",
        \\  "requestState": "eyJwcm9ncmVzcyI6IjUwJSIsInN0YXRlIjoicHJvY2Vzc2luZyJ9"
        \\}
        \\}
    , &.{});
}

const AskOutcome = struct {
    err: ?InputError = null,
    required: bool = false,
    responses_seen: bool = false,
};

fn gateHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    const o: *AskOutcome = @ptrCast(@alignCast(ctx.?));
    o.responses_seen = call.input.response("k") != null or call.input.receivedState() != null;
    call.input.ask("k", .{ .elicitation = .{ .form = .{ .message = "m", .requested_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}}" } } }) catch |e| {
        o.err = e;
    };
    o.required = call.input.inputRequired();
    call.write("plain");
    return false;
}

test "2026-07-28 MRTR: asks are gated by the request's declared capabilities; the session path has no MRTR" {
    var o = AskOutcome{};
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "g", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &gateHandler, .ctx = &o });

    // Modern, but no elicitation declared: refused, and the reply is the
    // tool's normal result.
    const r1 = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"g\"," ++ modern_meta_open ++ "}}}");
    defer testing.allocator.free(r1);
    try testing.expectEqual(@as(?InputError, error.ElicitationNotSupported), o.err);
    try testing.expect(!o.required);
    try testing.expect(std.mem.find(u8, r1, "\"resultType\":\"complete\"") != null);
    try testing.expect(std.mem.find(u8, r1, "\"text\":\"plain\"") != null);

    // Session path: a stray inputResponses/requestState is not read, and
    // asking is refused.
    o = .{};
    const r2 = try replyTo(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"g","inputResponses":{"k":{"action":"accept"}},"requestState":"x"}}
    );
    defer testing.allocator.free(r2);
    try testing.expectEqual(@as(?InputError, error.SessionRequest), o.err);
    try testing.expect(!o.responses_seen);
    try testing.expect(std.mem.find(u8, r2, "input_required") == null);
    try testing.expect(std.mem.find(u8, r2, "\"text\":\"plain\"") != null);

    // Declared: asked.
    o = .{};
    const r3 = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"g\"," ++ mrtr_meta ++ "}}");
    defer testing.allocator.free(r3);
    try testing.expectEqual(@as(?InputError, null), o.err);
    try testing.expect(o.required);
    try testing.expect(std.mem.find(u8, r3, "\"resultType\":\"input_required\"") != null);
    try testing.expect(std.mem.find(u8, r3, "plain") == null);
}

test "2026-07-28 MRTR: a malformed inputResponses or requestState is -32602" {
    var o = AskOutcome{};
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "g", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &gateHandler, .ctx = &o });
    const cases = [_]struct { extra: []const u8, msg: []const u8 }{
        .{ .extra = ",\"inputResponses\":[]", .msg = "Invalid inputResponses" },
        .{ .extra = ",\"inputResponses\":\"k\"", .msg = "Invalid inputResponses" },
        .{ .extra = ",\"requestState\":5", .msg = "Invalid requestState" },
        .{ .extra = ",\"requestState\":{}", .msg = "Invalid requestState" },
    };
    for (cases) |c| {
        var buf: [512]u8 = undefined;
        const msg = try std.mem.print(&buf, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"g\",{s}{s}}}}}", .{ mrtr_meta, c.extra });
        const line = try replyTo(&s, msg);
        defer testing.allocator.free(line);
        try testing.expect(std.mem.find(u8, line, "\"code\":-32602") != null);
        try testing.expect(std.mem.find(u8, line, c.msg) != null);
    }
    // null means absent, as elsewhere in this module.
    const ok = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"g\"," ++ mrtr_meta ++ ",\"inputResponses\":null,\"requestState\":null}}");
    defer testing.allocator.free(ok);
    try testing.expect(std.mem.find(u8, ok, "input_required") != null);
}

fn keyRulesHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    const errs: *[4]?InputError = @ptrCast(@alignCast(ctx.?));
    const req: InputRequest = .{ .sampling = .{ .messages = &.{.{ .role = .user, .content = .{ .text = "q" } }}, .max_tokens = 1 } };
    errs[0] = if (call.input.ask("", req)) |_| null else |e| e;
    call.input.ask("a", req) catch unreachable;
    errs[1] = if (call.input.ask("a", req)) |_| null else |e| e;
    errs[2] = if (call.input.setState("")) |_| null else |e| e;
    errs[3] = if (call.input.ask("b", .{ .sampling = .{ .messages = &.{}, .max_tokens = 1 } })) |_| null else |e| e;
    return false;
}

test "2026-07-28 MRTR: keys are non-empty and unique, the state non-empty, the payload checked as on the session path" {
    var errs: [4]?InputError = @splat(null);
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "k", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &keyRulesHandler, .ctx = &errs });
    const line = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"k\"," ++ mrtr_meta ++ "}}");
    defer testing.allocator.free(line);
    try testing.expectEqual(@as(?InputError, error.EmptyInputKey), errs[0]);
    try testing.expectEqual(@as(?InputError, error.DuplicateInputKey), errs[1]);
    try testing.expectEqual(@as(?InputError, error.EmptyRequestState), errs[2]);
    try testing.expectEqual(@as(?InputError, error.NoMessages), errs[3]);
    // Only the one accepted request went out, once.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "sampling/createMessage"));
    try testing.expect(std.mem.find(u8, line, "requestState") == null);
}

fn askingTemplate(ctx: ?*anyopaque, req: *ResourceRequest) bool {
    const accept = @intFromPtr(ctx) == 1;
    req.input.ask(if (accept) "yes" else "no", .{ .elicitation = .{ .form = .{ .message = "m", .requested_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}}" } } }) catch unreachable;
    return accept;
}

fn askingPrompt(ctx: ?*anyopaque, req: *PromptRequest) bool {
    _ = ctx;
    req.input.setState("s1") catch {}; // error.SessionRequest on the session path
    return false; // ignored when the state was set: the state wins
}

test "2026-07-28 MRTR: resources/read and prompts/get; a declining template's asks are discarded" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addResourceTemplate(.{ .uri_template = "a://{x}", .name = "decliner", .handler = &askingTemplate, .ctx = @ptrFromInt(2) });
    try s.addResourceTemplate(.{ .uri_template = "a://{y}", .name = "acceptor", .handler = &askingTemplate, .ctx = @ptrFromInt(1) });
    try s.addPrompt(.{ .name = "p", .handler = &askingPrompt });

    const r = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"a://1\"," ++ mrtr_meta ++ "}}");
    defer testing.allocator.free(r);
    try testing.expect(std.mem.find(u8, r, "\"resultType\":\"input_required\"") != null);
    try testing.expect(std.mem.find(u8, r, "\"yes\":") != null);
    try testing.expect(std.mem.find(u8, r, "\"no\":") == null);
    // Not a cacheable answer: no ttlMs/cacheScope on an InputRequiredResult.
    try testing.expect(std.mem.find(u8, r, "ttlMs") == null);

    const p = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"," ++ mrtr_meta ++ "}}");
    defer testing.allocator.free(p);
    try testing.expect(std.mem.find(u8, p, "\"resultType\":\"input_required\",\"requestState\":\"s1\"") != null);

    // Session path: the same prompt's setState is refused, so its `false`
    // stands and the get fails as before.
    const legacy = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}");
    defer testing.allocator.free(legacy);
    try testing.expect(std.mem.find(u8, legacy, "\"code\":-32603") != null);
}

test "StateSeal: round trip; tampering, rebinding, expiry and garbage are refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const seal: StateSeal = .{ .key = @splat(7) };
    const b: StateSeal.Binding = .{ .method = "tools/call", .target = "pay", .principal = "alice" };
    const tok = try seal.seal(arena, b, "{\"step\":2}", 1000, 60);

    try testing.expectEqualStrings("{\"step\":2}", try seal.open(arena, b, tok, 1000));
    try testing.expectEqualStrings("{\"step\":2}", try seal.open(arena, b, tok, 1059));
    try testing.expectError(error.StateExpired, seal.open(arena, b, tok, 1060));
    try testing.expectError(error.StateExpired, seal.open(arena, b, tok, -1));

    // Every bound field matters, and so does the key.
    const others = [_]StateSeal.Binding{
        .{ .method = "prompts/get", .target = "pay", .principal = "alice" },
        .{ .method = "tools/call", .target = "refund", .principal = "alice" },
        .{ .method = "tools/call", .target = "pay", .principal = "mallory" },
        .{ .method = "tools/call", .target = "pay", .principal = "alice", .extra = "x" },
        // Length prefixes: moving a byte between fields is a different binding.
        .{ .method = "tools/cal", .target = "lpay", .principal = "alice" },
    };
    for (others) |o| try testing.expectError(error.StateInvalid, seal.open(arena, o, tok, 1000));
    const other_key: StateSeal = .{ .key = @splat(8) };
    try testing.expectError(error.StateInvalid, other_key.open(arena, b, tok, 1000));

    // Flip each byte of the decoded token in turn (version, expiry, MAC,
    // payload): all refused — a later expiry included.
    const dec = std.base64.url_safe_no_pad.Decoder;
    const enc = std.base64.url_safe_no_pad.Encoder;
    const raw = try arena.alloc(u8, try dec.calcSizeForSlice(tok));
    try dec.decode(raw, tok);
    for (0..raw.len) |i| {
        raw[i] ^= 0x01;
        defer raw[i] ^= 0x01;
        const t = try arena.alloc(u8, enc.calcSize(raw.len));
        try testing.expectError(error.StateInvalid, seal.open(arena, b, enc.encode(t, raw), 1000));
    }
    // Truncated to the header, shorter still, not base64 at all.
    const hdr = try arena.alloc(u8, enc.calcSize(StateSeal.header_len));
    try testing.expectError(error.StateInvalid, seal.open(arena, b, enc.encode(hdr, raw[0..StateSeal.header_len]), 1000));
    try testing.expectError(error.StateInvalid, seal.open(arena, b, tok[0..10], 1000));
    try testing.expectError(error.StateInvalid, seal.open(arena, b, "", 1000));
    try testing.expectError(error.StateInvalid, seal.open(arena, b, "!!!!", 1000));
    // An empty payload is a valid state.
    try testing.expectEqualStrings("", try seal.open(arena, b, try seal.seal(arena, b, "", 0, 1), 0));
}

const SealProbe = struct {
    seal: StateSeal = .{ .key = @splat(3) },
    now: i64 = 100,
    opened: ?[]const u8 = null,
    open_err: ?StateSeal.OpenError = null,
    buf: [32]u8 = undefined,
};

fn sealingHandler(ctx: ?*anyopaque, call: *ToolCall) bool {
    const p: *SealProbe = @ptrCast(@alignCast(ctx.?));
    const got = call.input.openState(&p.seal, "alice", p.now) catch |e| {
        p.open_err = e;
        return call.fail("bad state");
    };
    if (got) |payload| {
        @memcpy(p.buf[0..payload.len], payload);
        p.opened = p.buf[0..payload.len];
        call.write("done");
        return false;
    }
    call.input.sealState(&p.seal, "cart=42", .{ .now_sec = p.now, .ttl_sec = 30, .principal = "alice" }) catch unreachable;
    return false;
}

test "2026-07-28 MRTR: sealState/openState bind the state to the round's method and target" {
    var p = SealProbe{};
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    try s.addTool(.{ .name = "pay", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &sealingHandler, .ctx = &p });
    try s.addTool(.{ .name = "refund", .description = "d", .input_schema = "{\"type\":\"object\"}", .handler = &sealingHandler, .ctx = &p });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const first = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"pay\"," ++ mrtr_meta ++ "}}");
    defer testing.allocator.free(first);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, first, .{});
    const token = v.object.get("result").?.object.get("requestState").?.string;

    const retry = struct {
        fn line(a: std.mem.Allocator, tool: []const u8, tok: []const u8) ![]u8 {
            return a.print("{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"{s}\",{s},\"requestState\":\"{s}\"}}}}", .{ tool, mrtr_meta, tok });
        }
    }.line;

    // The same state replayed onto another tool: refused.
    const wrong = try replyTo(&s, try retry(arena, "refund", token));
    defer testing.allocator.free(wrong);
    try testing.expectEqual(@as(?StateSeal.OpenError, error.StateInvalid), p.open_err);
    try testing.expect(p.opened == null);

    // Presented after its expiry: refused.
    p.open_err = null;
    p.now = 130;
    const late = try replyTo(&s, try retry(arena, "pay", token));
    defer testing.allocator.free(late);
    try testing.expectEqual(@as(?StateSeal.OpenError, error.StateExpired), p.open_err);

    // In time, on the tool that issued it: opened.
    p.open_err = null;
    p.now = 129;
    const ok = try replyTo(&s, try retry(arena, "pay", token));
    defer testing.allocator.free(ok);
    try testing.expectEqual(@as(?StateSeal.OpenError, null), p.open_err);
    try testing.expectEqualStrings("cart=42", p.opened.?);
    try testing.expect(std.mem.find(u8, ok, "\"text\":\"done\"") != null);
}

// ── subscriptions/listen (2026-07-28) ───────────────────────────────────────

test "2026-07-28 anchor: subscriptions/listen acknowledges an empty filter and closes gracefully (schema examples)" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    // SubscriptionsListenRequest/listen-for-list-changes.json, verbatim.
    const out = try replyTo(&s,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "listen-1",
        \\  "method": "subscriptions/listen",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        \\      "io.modelcontextprotocol/clientInfo": {
        \\        "name": "ExampleClient",
        \\        "version": "1.0.0"
        \\      },
        \\      "io.modelcontextprotocol/clientCapabilities": {}
        \\    },
        \\    "notifications": {
        \\      "toolsListChanged": true,
        \\      "resourceSubscriptions": ["file:///project/config.json"]
        \\    }
        \\  }
        \\}
    );
    defer testing.allocator.free(out);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, out, "\n"), '\n');
    const ack_line = lines.next().?;
    const close_line = lines.next().?;
    try testing.expect(lines.next() == null);

    // SubscriptionsAcknowledgedNotification/listen-acknowledged.json, with the
    // one difference the anchor index names: nothing is honoured, so `{}`.
    var want_ack = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "method": "notifications/subscriptions/acknowledged",
        \\  "params": {
        \\    "_meta": {
        \\      "io.modelcontextprotocol/subscriptionId": "listen-1"
        \\    },
        \\    "notifications": {
        \\      "toolsListChanged": true,
        \\      "resourceSubscriptions": ["file:///project/config.json"]
        \\    }
        \\  }
        \\}
    , .{});
    try want_ack.object.getPtr("params").?.object.put(arena, "notifications", .{ .object = .empty });
    const got_ack = try std.json.parseFromSliceLeaky(std.json.Value, arena, ack_line, .{});
    try testing.expect(jsonValueEql(got_ack, want_ack));

    // SubscriptionsListenResultResponse/listen-closed-response.json; ours
    // also carries serverInfo (SHOULD), removed before comparing.
    const want_close = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "listen-1",
        \\  "result": {
        \\    "resultType": "complete",
        \\    "_meta": {
        \\      "io.modelcontextprotocol/subscriptionId": "listen-1"
        \\    }
        \\  }
        \\}
    , .{});
    var got_close = try std.json.parseFromSliceLeaky(std.json.Value, arena, close_line, .{});
    const got_meta = got_close.object.getPtr("result").?.object.getPtr("_meta").?;
    try testing.expect(got_meta.object.orderedRemove(meta_key.server_info));
    try testing.expect(jsonValueEql(got_close, want_close));
}

test "subscriptions/listen: integer ids echo as integers; a non-object filter is -32602; the session path has no listen" {
    var s = Server.init(testing.allocator, .{ .name = "srv", .version = "1" });
    defer s.deinit();
    const ok = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"subscriptions/listen\",\"params\":{" ++ modern_meta_open ++ "}}}");
    defer testing.allocator.free(ok);
    try testing.expect(std.mem.startsWith(u8, ok, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":7},\"notifications\":{}}}\n{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"resultType\":\"complete\",\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":7,"));

    const bad = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"subscriptions/listen\",\"params\":{" ++ modern_meta_open ++ "},\"notifications\":[]}}");
    defer testing.allocator.free(bad);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":8,\"error\":{\"code\":-32602,\"message\":\"Invalid notifications filter\"}}\n", bad);

    const legacy = try replyTo(&s, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"subscriptions/listen\",\"params\":{}}");
    defer testing.allocator.free(legacy);
    try testing.expect(std.mem.find(u8, legacy, "\"code\":-32602") != null);
    try testing.expect(std.mem.find(u8, legacy, "acknowledged") == null);
}

// ── deterministic fuzz driver (2026-10-09) ───────────────────────────────────
//
// The harnesses above are generic over their source of choices
// (`fn(comptime S, *S, gpa)`); `testing.fuzz` feeds them through `FuzzScript`,
// `MCP_FUZZ=<runs>[,<first seed>]` through testkit's driver (`_MS`,
// `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). They stay in this file
// because the test server, probe and corpora they use are private. Random
// bytes never form a JSON-RPC request, so `handleMessage` also has a "mutated"
// twin: a corpus line, a few octets damaged, maybe cut short.

const fuzz_driver = @import("testkit").fuzz.driver;

const FuzzLabel = enum { error_reply, ok_reply, error_payload, result_unparsed };
var fuzz_reach: [@typeInfo(FuzzLabel).@"enum".field_names.len]usize = @splat(0);

fn fuzz_mark(comptime l: FuzzLabel) void {
    fuzz_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const FuzzScript = struct {
    cur: kit.Cursor,

    pub fn valueRangeAtMost(self: *FuzzScript, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *FuzzScript, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("FuzzScript.value: unsupported type"),
        };
    }
    pub fn bytes(self: *FuzzScript, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *FuzzScript, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    /// What `Smith.slice` returns for this script: up to `buf.len` of the
    /// remaining script bytes, and their count.
    pub fn slice(self: *FuzzScript, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

fn fuzzScript(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            var script: [1024]u8 = undefined;
            const n = smith.slice(&script);
            var src: FuzzScript = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(FuzzScript, &src, testing.allocator);
        }
    }.f;
}

/// One of `seeds`, a few octets damaged, maybe cut short (the `handleOne`
/// shape): structured inputs that random bytes would never form.
fn damagedSeed(comptime S: type, src: *S, seeds: []const []const u8, buf: []u8) usize {
    const picked = seeds[src.index(seeds.len)];
    var len = @min(picked.len, buf.len);
    @memcpy(buf[0..len], picked[0..len]);
    if (len != 0) {
        for (0..src.valueRangeAtMost(u8, 0, 3)) |_| buf[src.index(len)] = src.value(u8);
        if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    }
    return len;
}

const fuzz_schemas = [_][]const u8{
    \\{"type":"object","properties":{"q":{"type":"string","minLength":1,"maxLength":5},"n":{"type":"integer","minimum":0,"multipleOf":3}},"required":["q"],"additionalProperties":false}
    ,
    \\{"$defs":{"n":{"anyOf":[{"type":"object","properties":{"c":{"$ref":"#/$defs/n"}},"allOf":[{"required":["x"]}]},{"type":"object","properties":{"c":{"$ref":"#/$defs/n"}}}]}},"$ref":"#/$defs/n"}
    ,
    \\{"type":"array","prefixItems":[{"const":1},{"enum":["a",null,[1]]}],"items":{"oneOf":[{"type":"number"},{"type":"string"}]},"uniqueItems":true,"maxItems":6}
    ,
    \\{"if":{"properties":{"k":{"const":"a"}}},"then":{"required":["a"]},"else":{"not":{"required":["a"]}},"minProperties":1}
    ,
};

const fuzz_instances = [_][]const u8{
    \\{"q":"abc","n":9}
    ,
    \\{"c":{"c":{"c":{"c":{"c":{"c":{"c":{"c":{"c":{"c":{"c":{"c":{}}}}}}}}}}}}}
    ,
    \\[1,"a",2,"b",3.5,"é"]
    ,
    \\{"k":"a","a":[1,2,{"x":null}]}
    ,
};

fn fuzzSchemaCheck(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Either side may be the damaged one: the schema text is the server's, but
    // `compile` must still refuse a bad one without a crash.
    var sbuf: [512]u8 = undefined;
    var ibuf: [512]u8 = undefined;
    const schema_text = if (src.value(bool)) sbuf[0..damagedSeed(S, src, &fuzz_schemas, &sbuf)] else fuzz_schemas[src.index(fuzz_schemas.len)];
    const instance_text = ibuf[0..damagedSeed(S, src, &fuzz_instances, &ibuf)];
    const sv = std.json.parseFromSliceLeaky(std.json.Value, arena, schema_text, .{}) catch return fuzz_driver.hit("schema_not_json");
    const schema = schema_check.Schema.compile(arena, sv) catch return fuzz_driver.hit("schema_refused");
    const iv = std.json.parseFromSliceLeaky(std.json.Value, arena, instance_text, .{}) catch return fuzz_driver.hit("instance_not_json");
    if (try schema.validate(arena, iv)) |f| {
        if (std.mem.eql(u8, f.keyword, "budget")) fuzz_driver.hit("budget") else fuzz_driver.hit("invalid");
        // A failure's pointer is a JSON Pointer: empty or starting with '/'.
        try testing.expect(f.pointer.len == 0 or f.pointer[0] == '/');
    } else fuzz_driver.hit("valid");
}

const fuzz_templates = [_][]const u8{
    "users://{id}/posts{?page,limit}{&sort}",
    "file:///{+path}{.ext}",
    "x://a{/seg*}/b{;p}{#frag}",
    "x://{v:3}-{w}",
};

const fuzz_uris = [_][]const u8{
    "users://a%20b/posts?limit=2&page=3&sort=up",
    "file:///src/main.zig",
    "x://a/p/q/b;p=1#top",
    "x://abc-d%C3%A9",
};

fn fuzzUriTemplate(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tbuf: [256]u8 = undefined;
    var ubuf: [256]u8 = undefined;
    const tmpl_text = if (src.value(bool)) tbuf[0..damagedSeed(S, src, &fuzz_templates, &tbuf)] else fuzz_templates[src.index(fuzz_templates.len)];
    const uri = ubuf[0..damagedSeed(S, src, &fuzz_uris, &ubuf)];
    const tmpl = uri_template.Template.parse(arena, tmpl_text) catch |e| switch (e) {
        error.OutOfMemory => return e,
        error.InvalidTemplate => return fuzz_driver.hit("template_invalid"),
    };
    const vars = (try tmpl.match(arena, uri)) orelse return fuzz_driver.hit("no_match");
    fuzz_driver.hit("matched");
    // What matched expands again without failing, and every value is UTF-8
    // (the matcher's own promise).
    for (vars) |v| switch (v.value) {
        .string => |s| try testing.expect(std.unicode.utf8ValidateSlice(s)),
        .list => |l| for (l) |s| try testing.expect(std.unicode.utf8ValidateSlice(s)),
    };
    var aw: std.Io.Writer.Allocating = .init(arena);
    try tmpl.expand(&aw.writer, vars);
}

test "fuzz: handleMessage, damaged corpus lines" {
    try testing.fuzz({}, fuzzScript(fuzzHandleMessageMutated), .{});
}

test "fuzz driver: MCP_FUZZ" {
    try fuzz_driver.run(fuzzHandleMessage, .{ .prefix = "MCP_FUZZ", .name = "mcp-handle-message" });
    try fuzz_driver.run(fuzzHandleMessageMutated, .{ .prefix = "MCP_FUZZ", .name = "mcp-handle-message-mutated" });
    try fuzz_driver.run(fuzzSchemaCheck, .{ .prefix = "MCP_FUZZ", .name = "mcp-schema-check" });
    try fuzz_driver.run(fuzzUriTemplate, .{ .prefix = "MCP_FUZZ", .name = "mcp-uri-template" });
    try fuzz_driver.run(fuzzClientResponse, .{ .prefix = "MCP_FUZZ", .name = "mcp-client-response", .scale = 4 });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    fuzz_reach = @splat(0);
    inline for (.{ fuzzHandleMessage, fuzzHandleMessageMutated, fuzzClientResponse }, 0..) |h, which| {
        for (0..400) |sd| {
            var prng = std.Random.DefaultPrng.init(sd);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("mcp harness {d} seed {d}: {t}\n", .{ which, sd, err });
                return err;
            };
        }
    }
    for (fuzz_reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(FuzzLabel, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── no-panic sweep 2026-10-28 ───────────────────────────────────────────────

/// `{"jsonrpc":"2.0","id":1,"method":<method>,"params":{"a":[[…]]}}` whose
/// total bracket depth is exactly `depth` (outer object + params object + arrays).
fn deepMessage(a: std.mem.Allocator, method: []const u8, depth: usize) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    try b.print(a, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{{\"a\":", .{method});
    for (0..depth - 2) |_| try b.append(a, '[');
    for (0..depth - 2) |_| try b.append(a, ']');
    try b.appendSlice(a, "}}");
    return b.toOwnedSlice(a);
}

fn deepEchoMethod(_: ?*anyopaque, req: *MethodRequest) bool {
    // Prints its own deep JSON (the handler output, not the peer's message).
    req.write("{\"a\":");
    for (0..max_json_depth) |_| req.write("[");
    for (0..max_json_depth) |_| req.write("]");
    req.write("}");
    return true;
}

test "sweep 2026-10-28 M-3: message nesting over max_json_depth is a parse error, at the cap it is handled" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s = testServer(null);
    defer s.deinit();
    try expectResponse(&s, try deepMessage(a, "ping", max_json_depth),
        \\{"jsonrpc":"2.0","id":1,"result":{}}
        \\
    );
    try expectResponse(&s, try deepMessage(a, "ping", max_json_depth + 1),
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\
    );
    // Brackets inside strings (with escaped quotes) do not count.
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"a\":\"[[[[\\\"[[[[\"}}",
        \\{"jsonrpc":"2.0","id":1,"result":{}}
        \\
    );
    // A megabyte of `[`: refused by the scan, not parsed.
    const bomb = try a.alloc(u8, 1 << 20);
    @memset(bomb, '[');
    try expectResponse(&s, bomb,
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}
        \\
    );
}

test "sweep 2026-10-28 M-2: a custom method whose own output nests too deep is -32603" {
    var s = testServer(null);
    defer s.deinit();
    try s.addMethod(.{ .name = "acme/deep", .handler = deepEchoMethod });
    // The handler prints depth max_json_depth + 1 (object + arrays).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"acme/deep"}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Method result is not a JSON object"}}
        \\
    );
}

test "sweep 2026-10-28 M-4: page_size = maxInt does not overflow start + page_size" {
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.page_size = std.math.maxInt(usize);
    inline for (.{ "a", "b", "c" }) |n| {
        try s.addTool(.{ .name = n, .description = "", .input_schema = "{}", .handler = pageTool });
    }
    // "dDoy" is the cursor for position 2 (see the pagination test).
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"dDoy"}}
    ,
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"c","description":"","inputSchema":{}}]}}
        \\
    );
}

test "sweep 2026-10-28 M-5: StateSeal.seal saturates the expiry instead of overflowing" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const seal: StateSeal = .{ .key = @splat(7) };
    const b: StateSeal.Binding = .{ .method = "tools/call", .target = "pay" };
    const now = std.math.maxInt(i64);
    const tok = try seal.seal(arena, b, "x", now, std.math.maxInt(u32));
    // Valid now; expired once the clock reaches the saturated expiry.
    try testing.expectEqualStrings("x", try seal.open(arena, b, tok, 1000));
    try testing.expectError(error.StateExpired, seal.open(arena, b, tok, now));
    // A negative clock reads as 0 (as before).
    _ = try seal.seal(arena, b, "x", std.math.minInt(i64), 5);
}

test "sweep 2026-10-28 M-6: a non-finite float id is non-conforming and never echoed" {
    var s = testServer(null);
    defer s.deinit();
    // Inbound, `std.json` keeps 1e999 as a number_string (valid JSON, echoed
    // verbatim); a non-finite `.float` only comes from a caller-built Value.
    try testing.expect(!conformingId(.{ .float = std.math.inf(f64) }));
    try testing.expect(!conformingId(.{ .float = std.math.nan(f64) }));
    try testing.expect(conformingId(.{ .float = 1.5 }));
    try expectResponse(&s, "{\"jsonrpc\":\"2.0\",\"id\":1e999,\"method\":\"ping\"}",
        \\{"jsonrpc":"2.0","id":1e999,"result":{}}
        \\
    );
    // The public encoders write null for anything that is not an identifier.
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeErrorLine(&aw.writer, .{ .float = std.math.inf(f64) }, -32600, "x");
    const parsed_arr = try std.json.parseFromSlice(std.json.Value, testing.allocator, "[1]", .{});
    defer parsed_arr.deinit();
    try writeResultLine(&aw.writer, parsed_arr.value, "{}");
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"x"}}
        \\{"jsonrpc":"2.0","id":null,"result":{}}
        \\
    , aw.written());
    try testing.expect(!s.cancelInflight(0, .{ .float = std.math.nan(f64) }));
    try testing.expect(!s.cancelInflight(0, parsed_arr.value));
}

test "sweep 2026-10-28 M-10: a non-finite annotation priority is omitted, not written as invalid JSON" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
    try jw.beginObject();
    try writeAnnotations(&jw, .{ .priority = std.math.nan(f64), .audience = &.{.user} });
    try jw.endObject();
    try testing.expectEqualStrings("{\"annotations\":{\"audience\":[\"user\"]}}", aw.written());
    aw.clearRetainingCapacity();
    jw = .{ .writer = &aw.writer, .options = .{} };
    try jw.beginObject();
    try writeAnnotations(&jw, .{ .priority = std.math.inf(f64) });
    try jw.endObject();
    try testing.expectEqualStrings("{\"annotations\":{}}", aw.written());
}

test "sweep 2026-10-28 M-3: a registered schema or _meta literal nested too deep is 'not JSON' (-32603 on list)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var deep: std.ArrayList(u8) = .empty;
    for (0..max_literal_depth + 1) |_| try deep.append(a, '[');
    for (0..max_literal_depth + 1) |_| try deep.append(a, ']');
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "d", .description = "", .input_schema = deep.items, .handler = pageTool });
    try expectResponse(&s,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ,
        \\{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"failed to build tools/list"}}
        \\
    );
}

test "sweep 2026-10-28 M-3: a registered schema deeper than max_json_depth but within max_literal_depth still lists" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // The peer cap (128) must not reach caller literals: schema_check compiles
    // up to 256 levels, so such a tool must still appear in tools/list.
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(a, "{\"type\":\"object\",\"x\":");
    for (0..max_json_depth + 10) |_| try deep.append(a, '[');
    for (0..max_json_depth + 10) |_| try deep.append(a, ']');
    try deep.append(a, '}');
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addTool(.{ .name = "d", .description = "", .input_schema = deep.items, .handler = pageTool });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try s.handleMessage(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    , &aw.writer);
    try testing.expect(std.mem.find(u8, aw.written(), "\"error\"") == null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"name\":\"d\"") != null);
}

test "sweep 2026-10-28 M-3: brackets inside a string do not count toward max_json_depth" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(a, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"s\":\"");
    for (0..2 * max_json_depth) |_| try msg.appendSlice(a, "[{");
    try msg.appendSlice(a, "\\\"[\"}}");
    var s = Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try expectResponse(&s, msg.items,
        \\{"jsonrpc":"2.0","id":1,"result":{}}
        \\
    );
}
