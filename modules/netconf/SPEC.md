# netconf — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
/NOTICE (this module needs no entry — see "Provenance" below).

## Design & invariants

### Layering, and what each layer is allowed to know

| File | Contents | Knows about I/O? |
|---|---|---|
| `framing.zig` | RFC 6242 §4.2/§4.3 decode (`Framer.feed`/`next`) + encode (`writeMessage`/`writeChunked`) | no |
| `capabilities.zig` | RFC 6241 §8.1 `<hello>`, `Capabilities`, `negotiate` (the dialect decision) | no |
| `rpc.zig` | RFC 6241 §7/§8 + RFC 5277 §2.1.1 request serialisation | no |
| `reply.zig` | RFC 6241 §4.2–§4.3 `<rpc-reply>`, RFC 5277 §2.2.1 `<notification>`, `classify` | no |
| `client.zig` | session state machine, `message-id`, correlation, `Transport`, `SshTransport` | one call |
| `root.zig` | re-exports + `meta` | no |

Only `client.zig` touches a byte stream, and inside it exactly one function blocks:
`Client.pumpOnce`, which performs a single `Transport.read` and feeds the result to the
framer. Everything else is a loop over that call. This is the module's whole concurrency
policy: it has none, and it never starts a thread or a timer.

### The dialect switch is a state, not a flag

RFC 6242 §4.1 puts the switch at exactly one point: after the hello exchange, decided by
whether **both** peers advertised `urn:ietf:params:netconf:base:1.1`. The implementation
mirrors that literally:

* `Framer` starts in `.end_of_message`, because the hello exchange is always
  end-of-message framed.
* `Framer.setDialect` returns `error.MidMessage` unless no message is half-decoded, so
  the transition cannot be applied mid-frame (which would mis-split the stream).
* `capabilities.negotiate` is the only code that decides which dialect to move to, and it
  also enforces §8.1's "MUST verify that the other peer has advertised a common protocol
  version" — no common base version is `error.NoCommonBaseVersion`, not a fallback guess.

### Framing is a hostile-input surface

RFC 6242 §4.2 ends with "Implementations MUST ensure they are not vulnerable for a buffer
overrun". Every one of these is a typed error, tested from both a whole-buffer feed and a
one-byte-at-a-time feed:

| Input | Verdict |
|---|---|
| `\n#0\n…` (zero size) | `error.InvalidChunkSize` |
| `\n#04\n…` (leading zero — §4.2 prohibits) | `error.InvalidChunkSize` |
| `\n#\n`, `\n#4x\n`, `\n#-4\n`, `\n##x` | `error.MalformedChunkHeader` |
| `\n##\n` with no preceding chunk (`Chunked-Message = 1*chunk`) | `error.EmptyChunkedMessage` |
| chunk-size > 4294967295, or > `Limits.max_chunk` | `error.ChunkTooLarge` (refused **before** any buffering) |
| header longer than `\n#` + 10 digits + `\n` | `error.ChunkTooLarge` |
| `]]>]]>` offered while in `.chunked` | `error.ExpectedChunkHeader` |
| `]]>]]>` **inside** chunk data | ordinary data (asserted) |
| assembled message > `Limits.max_message` | `error.MessageTooLarge` |
| un-terminated input > `Limits.max_pending` | `error.PendingTooLarge` |

On the send side, `writeMessage(.end_of_message, payload)` refuses a payload containing
`]]>]]>` (`error.DelimiterInPayload`) — RFC 6242 §4.1 is explicit that the sequence *can*
legally occur inside XML, and a sender that emits it splits its own message at the wrong
place on the peer. `rpc.zig` additionally escapes `>` in every scalar it writes, so no
caller-supplied URL, stream name or timestamp can contribute to a forged delimiter.

Two deliberate deviations from a strict reading of the ABNF, both on the *receive* side
only:

1. After `]]>]]>` nothing is written, and a stray LF left in front of the first chunk
   header by a peer that wrote `]]>]]>\n` is skipped — but only an LF that is *followed by
   another LF*, which can never be the LF that starts a real header. Real implementations
   do print the delimiter on its own line, and the alternative is failing the first
   chunked message of every such session.
2. `Framer.next` hands out a slice into an internal buffer that is valid until the next
   call. This keeps the decode path allocation-light; `Client.receive` copies into its own
   buffer before returning to the caller.

### Correlation, and never dropping a reply

`message-id` is allocated by `Client.send` (monotonic from 1) and checked by
`Reply.expectMessageId`. `Client.receiveReply(id)` rejects a mismatched id with
`error.MessageIdMismatch` rather than accepting a reply to some other request. RFC 5277
notifications may legally arrive between a request and its reply, so `receiveReply` routes
them to a bounded queue (`Options.max_queued_notifications`) instead of treating them as a
malformed reply.

A `<rpc-error>` is a **successful parse of a negative answer**: `Client.call` returns the
`Reply` either way, with every `<rpc-error>` field retained (including `<error-info>` as a
verbatim XML span, because its contents are extension-defined). `Reply.expectOk`/
`expectData` are what raise `error.RpcError`, and `Client.callOk` hands the failed reply
back through an out-parameter so the reason survives the error return.

### Verbatim XML payloads

Filters and `<config>` bodies are YANG-modelled data this module has no model of, so they
are taken as verbatim XML fragments and only re-indented. The consequences are documented
where they bite:

* `Reply.data` / `Reply.body` are raw slices of the message, so namespace declarations
  inherited from `<rpc-reply>` are not repeated on them — re-parsing such a slice
  standalone loses the default namespace. `Reply.data_element` / `body_element` expose the
  same nodes inside the parsed tree, with full namespace scope, and that is what a caller
  walking the content should use. Both the caveat and the behaviour are asserted in tests.
* `Operation.attribute()` emits ` nc:operation="…"`, and `<config>` binds `xmlns:nc` to the
  base namespace so the prefix resolves. A test parses the built request back and looks the
  attribute up **by namespace** to prove it.

### XML parsing is the sibling module's job

`xml` is used with `.doctype = .reject`, so DOCTYPE (and therefore XXE and entity
expansion attacks) is refused before anything else happens; its depth/attribute-count
limits apply too. No second XML parser exists in this module — a NETCONF-specific one
would be a new, unaudited attack surface for no gain.

## Verification

### Live interop — a real, third-party NETCONF server

The live tests in `client.zig` are gated on `NETCONF_TEST_SERVER` / `NETCONF_TEST_USER` /
`NETCONF_TEST_PASSWORD` and print `SKIPPED:` and pass without them (the pattern used by
`ssh` and `tc`).

They were run, and pass, against a **third-party NETCONF server**: the Python `netconf`
2.1.0 package (Christian Hopps' implementation) on `sshutil` 1.5.0 + `paramiko` 3.5.1,
Python 3.14.4, serving a small static configuration on `127.0.0.1:8300`. That server is an
independent implementation of RFC 6241/6242 — including its own chunked framer — and it
advertises both `:base:1.0` and `:base:1.1`, which is what makes the dialect test below
meaningful. The full path exercised is our `ssh` module's transport handshake + RFC 4252
password auth + RFC 4254 `subsystem("netconf")` request, then this module on top.

Two live tests run, differing only in what **we** advertise:

| Test | We advertise | Negotiated framing | What ran |
|---|---|---|---|
| chunked | `:base:1.0` + `:base:1.1` | `.chunked` (asserted) | hello (session-id + 5 peer capabilities) → `get-config` (129 B of `<data>`) → `get` → unsupported op → `close-session` |
| end-of-message | `:base:1.0` only | `.end_of_message` (asserted) | same sequence, legacy framing |

The unsupported-operation step sends `<no-such-operation/>` through the `raw` escape hatch
and asserts the peer's real `<rpc-error>` parses: the live server answers
`error-tag=operation-not-supported`, `error-type=protocol`. So the error path, the
correlation (`expectMessageId(1..3)`) and both framers are validated against foreign
bytes, not only against our own encoder.

Reproducing the server used here (no root needed):

```sh
python3 -m pip install --target ./pylib netconf 'paramiko==3.5.1'
# a ~30-line server subclassing netconf.server.NetconfSSHServer with
# rpc_get/rpc_get_config returning a static <data>, then:
PYTHONPATH=./pylib python3 ncserver.py 8300 hostkey_rsa
```

**What is not available on this machine:** no `netopeer2-server` and no `sysrepo` are
packaged for this distribution, and OpenSSH's `sshd` provides only an `sftp` subsystem, so
"ssh -s localhost netconf" cannot work by itself. yuma123's `netconfd` **is** packaged and
was extracted and run unprivileged, but its `netconf-subsystem` bridge ignores
`--ncxserver-sockname` and its sessions died immediately after `New session created OK`
without emitting a server `<hello>`; that path was abandoned in favour of the Python
server above rather than faked.

### External-anchor investigation: frozen bytes from the live server (2026-08-01, done)

The live tests above prove interop but are gated: without `NETCONF_TEST_SERVER`
they print `SKIPPED:` and the byte-level detail of what actually crossed the
wire is never asserted when no operator supplies a server. To close that gap
per the governing rule ("run the foreign thing once, freeze its bytes, assert
offline"), the Python `netconf` 2.1.0 package was actually stood up using the
recipe already documented above, and this module's own `Client`/`buildRpc`
were driven against it for real, exactly once.

**One environment wrinkle, worked around without installing anything.**
`sshutil` 1.5.0 (2016-era) unconditionally does `import paramiko.dsskey`;
paramiko 5.0.0 (what is actually installed) dropped DSS/DSA key support and
the module no longer exists, so `import netconf.server` raised
`ModuleNotFoundError` outright — the tool did not work out of the box and
needed to be re-verified before anything was built on it. Since only an RSA
host key is used (`from_private_key_file` tries RSA first), a two-line stub
module (`sys.modules["paramiko.dsskey"] = <a dummy class that only exists to
satisfy the import>`) let `netconf.server` import cleanly. Nothing was
installed; nothing in the stub is ever called.

**What ran.** A throwaway RSA host key (`ssh-keygen`, discarded after), a
~40-line script subclassing `netconf.server.NetconfMethods` with
`rpc_get`/`rpc_get_config` returning a static `<probe:top>` element (a
deliberately *prefixed* namespace, `xmlns:probe="urn:example:probe"` — unlike
every RFC-literal golden below, which uses default namespaces, this exercises
the parser's prefixed-namespace path for real), served via
`netconf.server.NetconfSSHServer` on `127.0.0.1:8300`. This module's own
existing (env-gated) live test in `client.zig` was then pointed at it
(`NETCONF_TEST_SERVER=127.0.0.1:8300 NETCONF_TEST_USER=probe
NETCONF_TEST_PASSWORD=probe-pw`) and ran for real, both dialects: hello →
`get-config` → `get` → an intentionally unsupported operation → `close-session`.
All 65 tests passed, live, including the two normally-skipped ones.

**What was frozen.** `Client.receive`/`sendRaw` were temporarily instrumented
(one `std.debug.print` each, `client.zig`, reverted immediately after — no
trace of it remains) to print the exact unframed message bytes crossing the
transport, in both directions, for the whole session. From the `.chunked`
session (session-id 3) three exchanges were captured and are now permanent
offline tests (no socket, no env var):

  - the server's real `<hello>` — `capabilities.zig`, `live_netconf_2_1_0_server_hello`
  - a real `<rpc-reply>` to our own `get-config` request (source `running`,
    no filter), including the prefixed-namespace `<probe:top>` body —
    `reply.zig`, `live_netconf_2_1_0_get_config_reply`
  - a real `<rpc-error>` (`operation-not-supported`/`protocol`) answering a
    deliberately unsupported operation sent through the `raw` escape hatch —
    `reply.zig`, `live_netconf_2_1_0_rpc_error_reply`
  - the exact request bytes `buildRpc` produced for both of the above, which
    the server accepted — `rpc.zig`, "external anchor: buildRpc output is
    exactly what a real NETCONF server accepted"

Together these are strictly stronger than the RFC-literal goldens below: not
"structurally what RFC 6241 describes" (`expectSameStructure`) but "byte-for-
byte what an independent implementation neither authored by nor consulted
during this module's development actually parsed, acted on, and emitted" —
including a real XML prolog (`<?xml version="1.0" encoding="UTF-8"?>`) and a
real prefixed namespace, neither of which any hand-typed RFC excerpt here
happens to exercise. **No disagreement was found**: every byte this module
sent was accepted, and every byte the server sent parses exactly as intended.

No `/NOTICE` entry: exactly the black-box-oracle relationship root `NOTICE`
§0 already describes for `protobuf`/`syslog`/`opcua`/`wireguard`/`xmlsec1` —
the `netconf` package's own behavior was observed, nothing was read from or
copied out of its source.

### Byte-exact goldens, and which RFC section each comes from

Every literal below is copied verbatim out of the RFC text; the section is named next to
each in the source.

| Golden | Section | Used as |
|---|---|---|
| `\n#4\n<rpc\n#18\n…\n#79\n…\n##\n` chunked encoding of a `<close-session>` | RFC 6242 §4.2 | decode input; the decoded message is compared byte-for-byte, and a second test asserts the RFC's own chunk sizes (4/18/79) really are the lengths of the three literal pieces |
| the `get-config` request + reply exchange with `]]>]]>` | RFC 6242 §4.3 | decode input for the end-of-message framer, both messages compared byte-for-byte |
| server `<hello>` with `:base:1.1`, `:startup:1.0` and a vendor capability, `<session-id>4</session-id>` | RFC 6241 §8.1 | `parseHello` input |
| client `<hello>` (no `<session-id>`) | RFC 6242 §3 | `parseHello` input, and the "a client hello with a session-id is rejected" case |
| `get-config` with a subtree filter | RFC 6241 §7.1 | builder oracle |
| `get-config` reply with `<data>` | RFC 6241 §7.1 | `parseReply` input |
| `edit-config` setting an MTU | RFC 6241 §7.2 | builder oracle |
| `copy-config` from a `<url>` | RFC 6241 §7.3 | builder oracle |
| `delete-config` of `<startup>` | RFC 6241 §7.4 | builder oracle |
| `lock`, and `unlock` derived from it | RFC 6241 §7.5–§7.6 | builder oracle |
| the `lock-denied` `<rpc-error>` (with `<error-info><session-id>454</session-id>`) | RFC 6241 §7.5 | `parseReply` input — every field asserted |
| the successful lock reply `<ok/> <!-- lock succeeded -->` | RFC 6241 §7.5 | `parseReply` input (the RFC's trailing comment must not confuse `<ok/>` detection) |
| `get` with a subtree filter over statistics | RFC 6241 §7.7 | builder oracle |
| `close-session`, `kill-session` of session 4 | RFC 6241 §7.8–§7.9 | builder oracle |
| `<commit/>`, `<discard-changes/>` | RFC 6241 §8.3.4.1–§8.3.4.2 | builder oracle |
| confirmed commit with `<confirm-timeout>120</confirm-timeout>` | RFC 6241 §8.4.5.1 | builder oracle |
| `validate` of `<candidate>` | RFC 6241 §8.6.4.1 | builder oracle |
| `create-subscription` (prefixed envelope) | RFC 5277 §2.1.1.1 | builder oracle |

**How the builder goldens are used, honestly.** The RFCs lay their examples out over
multiple lines with the `xmlns` on a continuation line, and a filter's inner XML comes from
the caller, so our serialiser cannot be byte-identical to the RFC text without pretending
the caller pre-indented everything. Instead each builder is checked twice:

1. `expectSameStructure` parses **our output** and **the RFC's literal example** and
   compares the XML infoset — element names, namespace URIs, the attribute set, child
   element order, and whitespace-collapsed text. Prefix differences (RFC 5277 writes
   `<netconf:rpc>`) and line layout are correctly invisible to it; a wrong element,
   namespace, attribute or value is not.
2. A byte-exact golden of **our own canonical output** pins the serialiser against
   accidental change. Those goldens are labelled as ours, not the RFC's.

The reply/hello/framing goldens have no such gap: the RFC literal *is* the input, so those
are byte-exact in the strong sense.

### Round-trips, split reads, fuzzing

* Every framer test runs in **both dialects** and is fed **one byte at a time** as well as
  in one piece, asserting identical results — a framer that only works on whole-datagram
  reads is broken. The whole client session (hello → dialect switch → correlated RPC) also
  runs over a 1-byte-at-a-time transport.
* Every builder's output is parsed back with the `xml` module and its envelope
  (`<rpc>` in the base namespace, the expected `message-id`) asserted.
* A fake NETCONF peer over an in-memory pipe speaks the real framing in both dialects,
  answers real RPCs, can forge a `message-id`, and can inject a notification before a
  reply. It exercises the client state machine; it uses this module's own framer, so it is
  a state-machine oracle, **not** an independent-implementation oracle — that role belongs
  to the live server above.
* Three `std.testing.fuzz` targets: the framer (both dialects, arbitrary bytes),
  `parseHello`, and `parseReply`/`parseNotification`/`classify`.

Without a live server, the live tests print `SKIPPED:` and pass; with
`NETCONF_TEST_SERVER` set, they all run for real. Green in both `Debug` and
`--release=fast`.

## Provenance

Clean-room from RFC 6241 (NETCONF), RFC 6242 (NETCONF over SSH) and RFC 5277 (event
notifications). No third-party source was ported, and no third-party implementation was
studied as a design reference, so per CONVENTIONS.md §5 this module needs **no `/NOTICE`
entry** — the RFC citations live here. The Python `netconf` server used in the live test is
a black-box compatibility oracle only (nothing was read from or copied out of it), which
CONVENTIONS.md §5 also puts outside NOTICE's scope.

## Deferred

Honest list of what this module does **not** do:

* **Server side.** Client only. A `<hello>` *can* be written with a `<session-id>`
  (`capabilities.writeHello`) and the framer is symmetric, so a server is a small addition,
  but nothing here serves.
* **Call Home (RFC 8071), NETCONF over TLS (RFC 7589), RESTCONF.** Only RFC 6242's
  SSH subsystem transport is wired; the `Transport` seam takes anything, but no other
  transport is implemented or tested.
* **YANG.** No schema model, no validation, no `get-schema`/`ietf-netconf-monitoring`
  helpers, no XPath evaluation. Filters and `<config>` bodies are opaque XML fragments; a
  YANG layer belongs above this module, not inside it.
* **`:with-defaults` (RFC 6243), `:url` scheme validation, `:partial-lock` (RFC 5717),
  NMDA `<get-data>`/`<edit-data>` (RFC 8526).** `Rpc.raw` reaches all of them; none has a
  typed builder.
* **Notification replay bookkeeping.** `create-subscription` (incl. `startTime`/`stopTime`)
  is built and `<notification>` is parsed and queued, but nothing tracks subscription
  state, `<replayComplete>`/`<notificationComplete>`, or the `:interleave` rules. This was
  the optional item in the task and it **is** implemented to that depth, no further.
* **Pipelining depth.** `send`/`receiveReply` allow more than one outstanding request, but
  `receiveReply` waits for one specific id and treats any other reply as a mismatch, so
  true out-of-order pipelining needs a small dispatcher on top.
* **Chunk-size tuning on send.** `writeMessage(.chunked, …)` emits one chunk;
  `writeChunked(w, payload, n)` splits at `n` but nothing in the client picks a smaller
  `n`. A peer with a modest input buffer might want that.
* **A timeout implementation.** By design (see above) — the seam is there, the policy is
  the caller's.
