# tracecontext

W3C Trace Context (Level 1) propagation as a `router` middleware — one
distributed-trace identity per request, carried across services via the
`traceparent` header (with opaque `tracestate` passthrough).

A `traceparent` is `version-traceid-parentid-flags`, e.g.
`00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`:

- **version** — two lowercase hex; only `00` (Level 1) is accepted.
- **trace-id** — 16 bytes / 32 hex; the whole-trace identity, kept end to end;
  the all-zero value is invalid.
- **parent-id** (span-id) — 8 bytes / 16 hex; the caller's span; the all-zero
  value is invalid.
- **flags** — one byte / 2 hex; bit 0 (`01`) = sampled.

Per request the middleware:

1. **Continues** a valid incoming trace when `trust_incoming` is set — keeps its
   trace-id and flags, mints a **fresh span-id** for this hop (the child of the
   incoming context).
2. Otherwise **starts a new trace** (fresh trace-id + span-id; flags from
   `sampled`).
3. **Carries `tracestate`** through unchanged (light validation only).
4. Exposes the current hop's context via `tracecontext.current()` and, when
   `echo` is set, writes the outgoing `traceparent`/`tracestate` on the
   response.

Register it **first** (outermost) so every response carries the context.

```zig
var tc = tracecontext.TraceContext{};
try r.use(tc.middleware()); // outermost
// … in a handler or the access log:
if (tracecontext.current()) |cx| {
    var b: [tracecontext.TraceParent.header_len]u8 = undefined;
    log.info("trace={s}", .{cx.write(&b)});
}
```

Also usable standalone: `TraceParent.parse` / `.write` / `.sampled`,
`childOf`, `newTrace`, `newTraceId`, `newSpanId`.

### Generated IDs

trace-ids and span-ids come from the monotonic clock, a per-connection-thread
nonce and a per-thread counter — no allocation, no OS entropy call, fully
portable. They are **correlation** identifiers (unique for tracing), **not**
unpredictable security tokens; W3C requires trace-ids to be unique, not random.
If you need CSPRNG ids, mint them yourself and set `traceparent`.

- **Role:** util. **Platform:** any. **Deps:** `router`,
  `http`. **Concurrency:** threadsafe — per-request state is thread-local (the
  server is task-per-connection: one request at a time per thread, so the
  context and the formatted header live until the response is flushed); the
  config is immutable. `current()` is meaningful only from the connection
  thread handling the request.

Provenance: clean-room from the W3C Trace Context specification (Level 1,
`traceparent`/`tracestate`) — original work of the zig-libs authors (MIT).
No third-party source consulted or copied — see NOTICE.

## Verification

`zig build test-tracecontext` — 8 offline tests through
`http.Server.serveStream`: valid incoming traceparent carried into the child
(fresh span-id) with `current()` agreement, absent and malformed inputs start a
fresh valid trace, `tracestate` passthrough, `echo=false`, parse/write
round-trip, invalid inputs rejected (bad version / length / delimiter /
uppercase hex / all-zero ids), and `childOf` + id uniqueness/non-zero.
