# tracecontext — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
`traceparent` shape: `version-traceid-parentid-flags` — version two lowercase hex (only `00`/Level 1
accepted), trace-id 16 bytes/32 hex (all-zero invalid), parent-id/span-id 8 bytes/16 hex (all-zero
invalid), flags one byte/2 hex (bit 0 = sampled). Per request: a valid incoming `traceparent` (when
`trust_incoming`) is *continued* — its trace-id and flags are kept, but a fresh span-id is minted for
this hop; absent or malformed input starts a new trace. `tracestate` is carried through unchanged
(light validation only — opaque passthrough, not reinterpreted). Register first (outermost) so every
response carries the context. `current()` exposes the current hop's context (thread-local, mirroring
`requestid.current()`); when `echo` is set the outgoing header is written back on the response.
`TraceParent.parse`/`.write`/`.sampled`, `childOf`, `newTrace`, `newTraceId`, `newSpanId` are usable
standalone, no HTTP. Generated IDs come from the monotonic clock, a per-connection-thread nonce and a
per-thread counter — no allocation, no OS entropy call (W3C requires trace-ids to be *unique*, not
random). Memory/concurrency: current context is a value in thread-local storage owned by the
connection task (task-per-connection: one request at a time per thread); the outgoing header is
formatted into a thread-local buffer valid until the response flushes; config is immutable after init
(threadsafe). Clean-room from the W3C Trace Context Level 1 recommendation — see NOTICE.

## Threat model / out of scope
Like `requestid`, the generated ids are **correlation** identifiers, explicitly not unpredictable
security tokens — do not rely on trace-id/span-id being unguessable; mint your own CSPRNG id and set
`traceparent` yourself if that matters. Trusting an incoming `traceparent` is opt-in
(`trust_incoming`) and validated only for wire shape, not provenance — the trust boundary (only
accept it from a trusted upstream proxy) is the caller's network topology. Only Level 1 is
implemented — no Level 2 (not yet published), no vendor-specific `tracestate` interpretation, no
sampling-decision logic beyond forwarding/setting the `sampled` bit, no span export/collector
integration (propagation only, not a tracer).

## Verification
8 offline tests through `http.Server.serveStream`: valid incoming traceparent carried into the child
(fresh span-id) with `current()` agreement, absent/malformed inputs start a fresh valid trace,
`tracestate` passthrough, `echo=false`, parse/write round-trip, invalid inputs rejected (bad version,
length, delimiter, uppercase hex, all-zero ids), `childOf` plus id uniqueness/non-zero generation.
Run: `zig build test-tracecontext`.

## Backlog / deferred
None beyond the documented Level-2/vendor-tracestate/sampling-logic/
tracer-export out-of-scope list above.

## Status
`gap · any · util · threadsafe` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.
