// SPDX-License-Identifier: MIT
//! Real MCP Streamable HTTP session material, captured from a single live run
//! of the OFFICIAL `mcp` Python SDK (modelcontextprotocol.io, package version
//! 2.0.0) -- both the official CLIENT (`mcp.ClientSession` +
//! `mcp.client.streamable_http.streamable_http_client`) and the official
//! SERVER (`mcp.server.mcpserver.MCPServer.streamable_http_app()`, via
//! uvicorn), talking to each other over a real loopback TCP connection with a
//! raw byte-logging proxy in between (the proxy only observes bytes; it does
//! not participate in or alter the protocol). This anchors the transport this
//! module implements against the specification's own reference SDK, closing the
//! gap the README/NOTICE previously described ("cross-checked for parity")
//! without any captured bytes or live check to back it.
//!
//! Captured once; frozen here. The test suite (see root.zig's "oracle:"
//! tests) replays these exact request bytes through this module's own
//! `Transport` (offline, via the existing in-memory `runWire` harness -- no
//! socket) and asserts the real, meaningful output the official SDK produced
//! for the same exchange is reproduced.
//!
//! Session recap (session id minted by the reference server:
//! `4a63b0c65dd74f508f97a98a744ea04f`): initialize -> notifications/initialized (202) -> GET
//! (200, held-open SSE stream -- see note below) -> tools/list -> tools/call
//! "echo" -> tools/call "work" (2 progress notifications + result) -> DELETE.
//!
//! Two OBSERVED, BENIGN differences from this module's own behavior (neither
//! is a bug -- both are spec-legal implementation choices; recorded here
//! because they were seen, not assumed):
//!
//!   1. The reference server's GET stream never closed on its own (no chunked
//!      terminator was observed even after every other exchange completed) --
//!      it holds the connection open and pushes only when there is something to
//!      send. This module's GET is deliberately drain-and-close instead (see
//!      SPEC.md): a handler in this io-less model cannot park a connection
//!      waiting on a future push, so it replays what is queued and closes,
//!      relying on EventSource auto-reconnect. Confirmed here as a real,
//!      intentional divergence, not an oversight.
//!   2. `DELETE /mcp` got `200 OK` from the reference server; this module
//!      answers `204 No Content`. Both are valid 2xx success codes for a body-
//!      less response and the Streamable HTTP spec does not mandate one over
//!      the other for session teardown.
//!
//! (Two more cosmetic SSE differences, also benign: the reference names every
//! event `event: message` explicitly, where this module omits `event:` --
//! WHATWG SSE defines the absent case as the same default "message" type, so
//! these are wire-identical to any `EventSource`; and the reference's
//! `Cache-Control: no-cache, no-transform` vs. this module's `no-store` are both
//! valid no-cache directives.)

/// The reference server's minted session id for this capture (documentation
/// only -- this module's own `Sessions` mints its own ids; tests don't need
/// this value to match, only to see a well-formed one of its own).
pub const session_id = "4a63b0c65dd74f508f97a98a744ea04f";

/// The real `mcp.ClientSession.initialize()` request, byte-exact.
pub const init_request =
    \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp","version":"0.1.0"},"_meta":{}}}
;

/// The reference server's `initialize` result payload (the SSE `data:` line's
/// JSON, unwrapped), byte-exact.
pub const init_response_json =
    \\{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"experimental":{},"prompts":{"listChanged":false},"resources":{"listChanged":false,"subscribe":false},"tools":{"listChanged":false}},"protocolVersion":"2025-11-25","serverInfo":{"name":"capture-server","version":""}}}
;

/// `notifications/initialized`, byte-exact -- a pure notification (no `id`).
pub const notifications_initialized_request =
    \\{"jsonrpc":"2.0","method":"notifications/initialized"}
;
/// The reference server answered this with (status line, byte-exact).
pub const notifications_initialized_status = "HTTP/1.1 202 Accepted";

/// The reference server's `GET /mcp` response status line (its body was
/// empty at capture time -- see the held-open note above).
pub const get_stream_status = "HTTP/1.1 200 OK";

/// The real client's `tools/list` request, byte-exact.
pub const tools_list_request =
    \\{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{}}}
;

/// The reference server's `tools/list` result payload, byte-exact.
pub const tools_list_response_json =
    \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"description":"Echo the given text back.","inputSchema":{"properties":{"text":{"title":"Text","type":"string"}},"required":["text"],"type":"object","title":"echoArguments"},"name":"echo","outputSchema":{"properties":{"result":{"title":"Result","type":"string"}},"required":["result"],"type":"object","title":"echoOutput"}},{"description":"Do some work, reporting progress twice.","inputSchema":{"properties":{},"type":"object","title":"workArguments"},"name":"work","outputSchema":{"properties":{"result":{"title":"Result","type":"string"}},"required":["result"],"type":"object","title":"workOutput"}}]}}
;

/// The real client's `tools/call "echo"` request, byte-exact (arguments
/// `{"text":"hello-mcp-http-oracle"}` -- an arbitrary marker string chosen for
/// this capture, not special in any way).
pub const echo_call_request =
    \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello-mcp-http-oracle"},"_meta":{}}}
;

/// The reference server's `echo` tool result, byte-exact: the tool echoed
/// `text` back and FastMCP wrapped the scalar return in
/// `{"result": <value>}` for `structuredContent`.
pub const echo_call_response_json =
    \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"hello-mcp-http-oracle","type":"text"}],"isError":false,"structuredContent":{"result":"hello-mcp-http-oracle"}}}
;

/// The real client's `tools/call "work"` request, byte-exact
/// (`_meta.progressToken: 4`, a bare JSON number -- this module echoes a
/// numeric token back unquoted, see `mcp`'s `reportProgress`).
pub const work_call_request =
    \\{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"work","arguments":{},"_meta":{"progressToken":4}}}
;

/// The reference server's two `notifications/progress` events, byte-exact --
/// this module's own `notifications/progress` writer (`mcp`'s
/// `buildToolResultLine`/progress emitter) uses the IDENTICAL field order
/// (`jsonrpc, method, params.{progressToken,progress,total,message}`), so
/// these are asserted as literal substrings of this module's own SSE output,
/// not merely field-by-field.
pub const progress_1_json =
    \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":4,"progress":1,"total":2,"message":"step one"}}
;
pub const progress_2_json =
    \\{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":4,"progress":2,"total":2,"message":"step two"}}
;

/// The reference server's final `work` tool result, byte-exact.
pub const work_call_response_json =
    \\{"jsonrpc":"2.0","id":4,"result":{"content":[{"text":"done","type":"text"}],"isError":false,"structuredContent":{"result":"done"}}}
;

/// The reference server's `DELETE /mcp` response status line (see the
/// 200-vs-204 note above).
pub const delete_status = "HTTP/1.1 200 OK";

test "oracle vectors: captured payloads are well-formed JSON and internally consistent" {
    const std = @import("std");
    const t = std.testing;
    const gpa = t.allocator;
    // Every request/response payload parses as JSON (a canary against a typo
    // introduced while freezing these -- a corrupted capture would fail here,
    // not silently pass a looser check).
    inline for (.{
        init_request, init_response_json, notifications_initialized_request,
        tools_list_request, tools_list_response_json, echo_call_request,
        echo_call_response_json, work_call_request, progress_1_json,
        progress_2_json, work_call_response_json,
    }) |payload| {
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, payload, .{});
        parsed.deinit();
    }
    // The literal marker string this capture threaded through the real echo
    // tool call must appear in both the request and the response.
    try t.expect(std.mem.indexOf(u8, echo_call_request, "hello-mcp-http-oracle") != null);
    try t.expect(std.mem.indexOf(u8, echo_call_response_json, "hello-mcp-http-oracle") != null);
    // protocolVersion echoed by the reference server matches what the real
    // client asked for.
    try t.expect(std.mem.indexOf(u8, init_request, "2025-11-25") != null);
    try t.expect(std.mem.indexOf(u8, init_response_json, "\"protocolVersion\":\"2025-11-25\"") != null);
    try t.expectEqual(@as(usize, 32), session_id.len);
}
