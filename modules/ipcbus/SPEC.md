# ipcbus — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

- **Same-host unix-socket control plane:** one owner process serves request/reply over a
  length-prefixed unix socket, plus a capped in-memory key→bytes scratch `Bus`. Linux, libc-free
  (raw `std.os.linux` syscalls). Original work of the zig-libs authors. Command handling is a
  caller-supplied `dispatch` callback, so this module hosts no application commands.
- **One connection per request.** Every request is a fresh `connect → write one frame → read one
  frame → close`; `acceptOne`/`handleOne` service exactly one connection at a time. No persistent
  or multiplexed connection.
- **Framing delegated to `framing`.** Every message is a length-prefixed frame; an oversize header
  is rejected *before* the body is read, so a bogus length never blocks waiting for a body that
  will not arrive.
- **`Bus(max_keys)` semantics:** `set` dupes key+value (owned); overwriting frees the old value in
  place; inserting a *new* key at `max_keys` evicts an arbitrary existing entry; `version` bumps on
  every mutation (poll to detect change); `get`/`list` return borrowed slices valid until the next
  mutation.
- **Concurrency:** single_owner — one thread/loop owns the listen socket and the `Bus`; the `Bus`
  is lock-free and must be touched from that owning thread only.

## Threat model / out of scope

Access control is entirely filesystem permissions on the socket path — there is no in-band
authentication, and any process that can `connect()` to the socket can issue any `dispatch`
command the app registers. The transport hardens the framing surface (oversize/garbage length
rejected before reading a body, bounded per-request allocation via `limits.max_frame`) but performs
no input validation of the request bytes themselves — that is the caller's `dispatch` function's
job. Out of scope: real push/notify (this is poll-a-shared-map — subscribers poll the `Bus`
`version`, no server-initiated push), persistent/multiplexed connections, multi-connection
concurrency (no thread pool or event loop — one connection serviced at a time), and any
auth/permissions layer on the socket.

## Verification

Tests cover the raw transport (`FdReader`/`FdWriter` `std.Io` adapters over a socket fd,
oversize-frame rejection via `framing.readFrame`, end-of-stream handling) and the framing
integration. Run: `zig build test-ipcbus`.

## Backlog / deferred

- **Real push/notify** — no server-initiated push; subscribers must poll `Bus.version`.
- **Persistent/multiplexed connections** — one connection per request only, by design.
- **Multi-connection concurrency** — no thread pool or event loop; single-owner accept loop.
- **Auth/permissions on the socket** — access is whatever filesystem permissions on the socket path
  grant; no in-band authentication.

## Status

`extract · linux · server · single_owner` + deps: `framing` — canonical source is `pub const meta`
in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** internal unix-socket dispatch loop, framing delegated, no protocol of its own
