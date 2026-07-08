# SPEC — `tracecontext`

**Purpose** — Distributed tracing needs one trace identity to survive a
request crossing service boundaries. `tracecontext` implements W3C Trace
Context Level 1 (`traceparent`/`tracestate`) as a `router` middleware:
parsing, generating and forwarding the header so every hop shares the same
trace-id while minting its own span-id.

**Model after / Seed** — Clean-room from the W3C Trace Context Level 1
recommendation. No seed project, no third-party source consulted or copied
(NOTICE).

**Design & invariants**
- **`traceparent` shape:** `version-traceid-parentid-flags` (e.g.
  `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`) — `version` two
  lowercase hex (only `00`/Level 1 accepted), `trace-id` 16 bytes/32 hex
  (all-zero invalid), `parent-id`/span-id 8 bytes/16 hex (all-zero invalid),
  `flags` one byte/2 hex (bit 0 = sampled).
- **Per request:** a valid incoming `traceparent` (when `trust_incoming`) is
  *continued* — its trace-id and flags are kept, but a **fresh span-id** is
  minted for this hop (the child context of the incoming one). Absent or
  malformed input **starts a new trace** (fresh trace-id + span-id, flags
  from `sampled`). `tracestate` is carried through unchanged (light
  validation only — opaque passthrough, not reinterpreted).
- **Register first (outermost)** so every response carries the context.
- **`current()` + standalone API:** the current hop's context is exposed via
  `tracecontext.current()` (thread-local, mirroring `requestid.current()`);
  when `echo` is set the outgoing `traceparent`/`tracestate` is written back
  on the response. `TraceParent.parse`/`.write`/`.sampled`, `childOf`,
  `newTrace`, `newTraceId`, `newSpanId` are usable standalone, no HTTP.
- **Generated IDs:** trace-ids and span-ids come from the monotonic clock, a
  per-connection-thread nonce and a per-thread counter — no allocation, no OS
  entropy call. W3C requires trace-ids to be *unique*, not random, so this
  satisfies the spec without a CSPRNG dependency.
- **Memory/concurrency:** the current context is a value in thread-local
  storage owned by the connection task (task-per-connection: one request at a
  time per thread); the outgoing header is formatted into a thread-local
  buffer valid until the response flushes. An adopted `tracestate` borrows
  the request head. Config is immutable after init (threadsafe); `current()`
  is meaningful only from the connection thread handling that request.

**Threat model / out of scope** — Like `requestid`, the generated ids are
**correlation** identifiers, explicitly not unpredictable security tokens —
do not rely on trace-id/span-id being unguessable; mint your own CSPRNG id and
set `traceparent` yourself if that matters. Trusting an incoming
`traceparent` is opt-in (`trust_incoming`) and validated only for wire shape,
not provenance — the trust boundary (only accept it from a trusted upstream
proxy) is the caller's network topology. Only Level 1 is implemented — no
Level 2 (not yet published), no vendor-specific `tracestate` interpretation,
no sampling-decision logic beyond forwarding/setting the `sampled` bit, no
span export/collector integration (this is propagation only, not a tracer).

**Verification** — `zig build test-tracecontext`, 8 offline tests through
`http.Server.serveStream`: valid incoming traceparent carried into the child
(fresh span-id) with `current()` agreement, absent/malformed inputs start a
fresh valid trace, `tracestate` passthrough, `echo=false`, parse/write
round-trip, invalid inputs rejected (bad version, length, delimiter,
uppercase hex, all-zero ids), `childOf` plus id uniqueness/non-zero
generation.

**Status** — `gap · any · util · threadsafe` · deps: `router`, `http`.
