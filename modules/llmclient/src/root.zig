// SPDX-License-Identifier: MIT

//! llmclient — an Anthropic Messages API client over the sibling `http`
//! module: request/response types (`MessageRequest`, `Message`,
//! `StreamEvent`), a buffered `Client.create`, a Server-Sent-Events
//! `Client.stream`, and the `sse_parse` line-accumulator that makes the
//! streaming half possible (there is no client-side SSE consumer
//! anywhere else in this repo — `http.sse` only writes the server side).
//!
//! ```zig
//! const llmclient = @import("llmclient");
//!
//! var transport = http.Client.init(io, gpa, .{});
//! var client = llmclient.Client.init(&transport, api_key);
//!
//! var parsed = try client.create(gpa, .{
//!     .max_tokens = 1024,
//!     .messages = &.{llmclient.MessageParam.user(&.{llmclient.textBlock("Hello, Claude")})},
//! });
//! defer parsed.deinit();
//! // parsed.value: llmclient.Message
//!
//! // Streaming:
//! var it = try client.stream(gpa, .{ .max_tokens = 1024, .messages = &.{...} });
//! defer it.deinit();
//! while (try it.next()) |event| {
//!     switch (event) {
//!         .content_block_delta => |d| switch (d.delta) {
//!             .text_delta => |t| std.debug.print("{s}", .{t.text}),
//!             else => {},
//!         },
//!         else => {},
//!     }
//! }
//! ```
//!
//! **Anthropic first; OpenAI deferred.** This v1 implements the Anthropic
//! Messages API only. See the README's Provenance/DEFER notes for the
//! full deferred-work list (OpenAI-compatible variant, retries/backoff,
//! token counting, prompt-caching tooling, files/vision, batch API,
//! connection reuse).

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .client,
    .concurrency = .single_owner,
    .model_after = "Anthropic Messages API (greenfield; WHATWG SSE grammar for the streaming half)",
    .deps = .{"http"},
};

const types = @import("types.zig");
const response = @import("response.zig");

/// The Anthropic Messages API client (`create` / `stream`).
pub const Client = @import("Client.zig");

/// The reusable client-side SSE line-accumulator `Client.stream` is built
/// on — exposed for reuse (see the README DEFER note about eventually
/// upstreaming this as `http.sse.ClientReader`).
pub const sse_parse = @import("sse_parse.zig");

// ── request-side vocabulary (types.zig) ─────────────────────────────────────

pub const Role = types.Role;
pub const CacheControl = types.CacheControl;
pub const ContentBlockParam = types.ContentBlockParam;
pub const MessageParam = types.MessageParam;
pub const Tool = types.Tool;
pub const ToolChoice = types.ToolChoice;
pub const ThinkingConfig = types.ThinkingConfig;
pub const MessageRequest = types.MessageRequest;
pub const stringifyRequestAlloc = types.stringifyAlloc;

pub const textBlock = types.textBlock;
pub const textBlockCached = types.textBlockCached;
pub const thinkingBlock = types.thinkingBlock;
pub const toolUseBlock = types.toolUseBlock;
pub const toolResultBlock = types.toolResultBlock;
pub const toolErrorBlock = types.toolErrorBlock;

// ── response-side vocabulary (response.zig) ─────────────────────────────────

pub const Usage = response.Usage;
pub const StopReason = response.StopReason;
pub const StopDetails = response.StopDetails;
pub const ContentBlock = response.ContentBlock;
pub const ContentBlockStart = response.ContentBlockStart;
pub const Delta = response.Delta;
pub const MessageDelta = response.MessageDelta;
pub const ErrorDetail = response.ErrorDetail;
pub const Message = response.Message;
pub const StreamEvent = response.StreamEvent;
pub const parseMessage = response.parseMessage;
pub const parseStreamEvent = response.parseStreamEvent;

// ── tests (dark aggregator: force test discovery across all files) ─────────

test {
    _ = types;
    _ = response;
    _ = sse_parse;
    _ = Client;
}
