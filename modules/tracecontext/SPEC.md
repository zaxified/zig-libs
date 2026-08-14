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
integration (propagation only, not a tracer). `tracestate` validation is a deliberate light
byte-class guard over the WHOLE combined value (non-empty, within `max_state_len`, printable
ASCII + horizontal tab as OWS) — NOT a per-list-member grammar parser: no key charset/length
checks, no 32-member cap, no duplicate-key detection. A tracing backend that needs those must do
its own parsing; see the W3C conformance corpus's excluded `STRICT_LEVEL >= 2` vectors
(`src/w3c_conformance_test.zig`) for exactly which upstream checks this stops short of.

A `traceparent` version other than `"00"` is rejected outright (same as malformed input — a fresh
trace is started) rather than attempting the spec's own "Versioning of traceparent" forward-compat
fallback parse for higher versions (trust the fixed-position trace-id/parent-id/sampled-bit fields
when the header is long enough and correctly delimited, even for a version this code doesn't
understand). That spec section uses SHOULD, not MUST, for the fallback, so this is a conformant,
deliberately simpler choice — but it does mean the W3C conformance suite's own
`test_traceparent_version_0xcc` does not pass here; see the Backlog entry below and the excluded
vectors in `src/w3c_conformance_test.zig`.

## Verification
11 offline unit tests through `http.Server.serveStream`: valid incoming traceparent carried into the
child (fresh span-id) with `current()` agreement, absent/malformed inputs start a fresh valid trace,
duplicated-traceparent rejection, multi-instance `tracestate` combining + OWS handling, `echo=false`,
parse/write round-trip, invalid inputs rejected (bad version, length, delimiter, uppercase hex,
all-zero ids), `childOf` plus id uniqueness/non-zero generation. PLUS a vendored W3C `trace-context`
conformance corpus (`src/w3c_vectors.zig` + `src/w3c_conformance_test.zig`; provenance in
`../NOTICE`): 73 hand-transcribed request/verdict vectors from the suite's `test/test.py`, 58 driven
both must-accept and must-reject through this module's own middleware, 15 excluded with a recorded
reason apiece (a count canary fails loudly on unreclassified drift). Run: `zig build
test-tracecontext`.

## Backlog / deferred
- Forward-compatible parsing of `traceparent` versions other than `"00"` (see Threat model /
  out of scope above) — a deliberate, spec-conformant (SHOULD-level) scope narrowing, not
  implemented. Revisit if a real upstream actually emits a higher-version `traceparent`.
- Otherwise none beyond the documented Level-2/vendor-tracestate/sampling-logic/
  tracer-export out-of-scope list above.

## Status
`gap · any · util · threadsafe` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/w3c_conformance_test.zig drives the middleware through 73 vendored W3C trace-context conformance vectors (src/w3c_vectors.zig) in both directions over the real offline wire harness; trace-id/parent-id GENERATION and childOf in root.zig have no W3C answer and stay self, as do the forward-compat and STRICT_LEVEL>=2 categories this module does not implement

**How it got there.** The anchoring work landed. DONE e269090: 73 W3C vectors; found MUST-not-parse-tracestate bug; 1 gap logged
