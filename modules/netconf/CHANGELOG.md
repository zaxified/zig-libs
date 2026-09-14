# netconf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **BEHAVIOURAL, not breaking (default on, switch to opt out):**
  `Client.send` now checks, before writing anything to the wire, that the peer's `<hello>`
  actually advertised the capability an operation requires — `lock`/`unlock`/`getConfig`/
  `copyConfig`/`deleteConfig`/`editConfig` against `.candidate` need `:candidate` (RFC 6241
  §8.3), the same group against `.startup` need `:startup` (§8.7), a `Datastore.url`/
  `EditPayload.url` needs `:url` (§8.8), `commit(.{.confirmed = true})` needs
  `:confirmed-commit` (§8.4), `validate` needs `:validate` (§8.6), and `createSubscription`
  needs `:notification` (RFC 5277 §3.1). A missing capability now fails locally with the new
  `error.CapabilityNotAdvertised` instead of a round trip to find out from the peer's
  `<rpc-error>`. Ten of the twelve booleans `capabilities.Capabilities` parses out of a
  `<hello>` were read by nothing in the module before this (2026-09-10 audit,
  `A1/netconf.md` N8). New `Options.check_capabilities` (default `true`) is the escape
  hatch for a server that implements an operation without advertising the capability that
  is supposed to announce it — set it `false` to fall back to the previous "try it, let the
  peer decide" behaviour.
- **2026-09-10** — **BEHAVIOURAL, not breaking:** `parseHello`/`parseReply`/`parseNotification`
  now reject XML with more than 65536 elements (`error.TooManyElements`) instead of inheriting
  `xml`'s own 1<<20 default — closes a 132x wire-to-memory amplification. `Options.max_idle_reads`
  (default 300000) now bounds `Client.receive` against a `Transport.read` that returns 0 without
  ever waiting, failing with the new `error.IdleTimeout` instead of spinning at 100% CPU.
  `<session-id>` parsing (hello and `error-info`) is now strict decimal digits, rejecting
  `1_0`-style input `std.fmt.parseInt` used to accept as 10. `reply.classify` now skips a leading
  UTF-8 BOM, matching `xml.parse`. `parseReply` now enforces RFC 6241 §4.2's "exactly one of
  `<ok/>`/`<data>`/`<rpc-error>`" and rejects a combination with the new `error.AmbiguousReply`.
  An interleaved `<notification>` in a foreign namespace is now rejected at receive time instead
  of being queued and failing later at dequeue. `<capability>` elements are now checked by
  namespace as well as local name, matching the sibling `<session-id>` check. Audit
  `A1/netconf.md`, "Dispozice 2026-09-10": 10 of 18 findings fixed in code (all 3 HIGH), 6 closed
  with regression tests only (guard was already correct), 1 doc-only, 1 out-of-scope
  (inherited from `xml`); 2 left open (one policy question, one deferred pending fuzzer
  instrumentation).
- **2026-09-07** — All three fuzz targets had been running one fixed input for their whole
  existence. `fuzzHello`, `fuzzFramer` and `fuzzReply` each drew their document with
  `smith.bytes(&raw)` and then took a length from `smith.valueRangeAtMost(u16, 0, 512)`; a
  ranged `Smith` draw reads eight octets as a little-endian `u64` and returns the range
  MINIMUM when fewer remain, and `bytes` had already consumed them — so `len` was 0 every
  time and the parsers were handed the empty string, with the document sitting unread in
  `raw`. Now one `smith.slice(&raw)` call each, plus corpora lifted from the value tests (the
  RFC 6241/6242 documents, the frozen live server messages and every hostile case) and a
  corpus guard per target. Measured: **hello 0 of 12 seeds non-empty, 0 parsed, 0
  capabilities → 12/12, 2 parsed, 5 capabilities; framer 0 of 16 non-empty, 0 messages
  framed, 0 typed errors → 16/16, 4 framed, 14 typed errors; reply 0 of 16 non-empty, 0
  replies, 0 notifications, 0 classified → 16/16, 6 replies, 1 notification, 15 classified,
  2 rpc-errors.** Recorded at the reply corpus: the module's largest fixture
  (`rfc_7_1_reply`, 506 octets) sits just under the 512-octet harness buffer, and a seed over
  that buffer reads back EMPTY rather than truncated.
- **2026-08-22** — `TransportError` gained a `Canceled` variant, widening the vtable
  contract so a `Transport` implementation that owns a socket can report a `std.Io`
  cancellation (`Future.cancel`) instead of disguising it as `ReadFailed`/`WriteFailed`.
  No code in this module produces it: the one `Transport` this module ships,
  `SshTransport`, owns no file descriptor — it drives an `ssh.connection.Session`, whose
  own transport holds only a type-erased `*std.Io.Reader`/`*std.Io.Writer`, so the
  concrete reader whose out-of-band `err` field would carry `Canceled` belongs to
  whichever caller built it, several layers below anything this module can see. No test
  added (nothing here to prove); README updated to state the four-member error set.
- **2026-08-06** — Security audit: the RFC 6242 chunked framer was quadratic in the
  number of chunks — 159s of CPU for 655KB of attacker-chosen wire bytes; fixed (down to
  ~0.015s for the same input), along with 5 further findings.
- **2026-07-22** — New module: NETCONF client (RFC 6241) over SSH — RFC 6242
  end-of-message + chunked framing, hello/capability exchange,
  get/get-config/edit-config/commit RPCs with typed replies.
