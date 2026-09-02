# iec61850 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (window `d163578..HEAD`, +1140/-73 over 14 files). Four findings,
  all fixed and mutation-checked.

  - **CRITICAL, cross-association request injection.** The 2026-08-31 F6 fix added inbound COTP
    reassembly as **per-`Server`** state, and a `Server` is what the module's own live loop
    multiplexes several associations onto, setting `Server.peer` per frame. So a peer could send a
    complete, valid MMS request in a `DT` with `eot` **clear**, leaving it parked in the shared
    buffer, and the next peer to send any terminal `DT` — a legal empty one is enough — caused that
    parked request to be decoded and served with `peer` set to *its* association id. `peer` is the
    only thing arbitrating a select, a setting-group edit and an RCB reservation, so this
    substituted the ownership check outright. Reproduced: peer A's direct operate is refused
    (`AccessFailed`, `stVal=false`), A parks the same operate, B sends an empty `DT` — the breaker
    closes, `operates` goes 1→2, and the positive Operate response is returned to **B**. Identical
    in Debug and ReleaseFast. Fixed by making the buffer single-tenant (`reasm_peer`), and by
    dropping it on `CR`, `DR`, `ABORT`/`FINISH` and `releaseAssociationOf`.

  - **HIGH, one octet parks the read forever with a timeout configured.** `setReadTimeout`
    documents "Bounds how long a read blocks", but the poll guarded only the *entry* to the read:
    once one octet was available, `readSliceAll` blocked in the kernel waiting for the other three
    header octets, with no deadline. Measured 20x past a configured 100 ms bound. The module's own
    multi-peer server loop reads its links serially, so one octet from one unauthenticated
    connection — no association, no authentication — stopped every other association, emitted no
    reports and drained no notifications. `readAllBounded` (the shape proved in the sibling
    `iec104`) now bounds the whole frame; `readVec` rather than `readSliceShort`, because the
    latter is short only at end of stream and reintroduces the block.

  - **MEDIUM, a failed reassembly wedged the connection permanently.** `Reassembler.push` zeroes
    its own `len` on overflow, but the write-back to `Server.reasm_len` sat after the `try`, so the
    abandoned fragment's octets stayed and were prepended to every later request — for the server
    and, in the identical shape, for the client. Nothing reset it on `CR`, `DR`, `ABORT` or
    `FINISH` either.

  - **MEDIUM (test gap), the oversized-TPKT guard had no test.** `if (total > buf.len)` stops
    `readSliceAll(buf[header_len..total])` running to a wire-chosen `total` of up to 65535 past the
    caller's buffer — a trap in Debug, an out-of-bounds write from network data in ReleaseFast. It
    could be deleted with 398/409 green. It was the only one of eight mutations that survived.

  Doc: SPEC's "The multi-association `Server`" entry enumerated the shared state as the context
  table and PDU size and is now accurate about reassembly and `associated`; the `.single_owner`
  concurrency line contradicts the multiplexing pattern the module documents and ships, which is
  recorded rather than resolved because resolving it means deciding whether `Server` gets an
  association table.


- **2026-08-22** — `TcpTransport` now surfaces `error.Canceled` (a new
  `TransportError` variant) instead of `error.ReadFailed`/`error.WriteFailed`
  when a blocked read or write is interrupted by `std.Io`'s `Future.cancel`.
  Covers both the direct blocking read and the `read_timeout_ms` poll path,
  which is not itself a `std.Io` cancellation point and needed an explicit
  `checkCancel` after the wait to see the request at all. Separately,
  `Client.awaitNotification`'s retry loop used to catch every `poll` failure
  — including `Canceled` — and just try again, so a canceled wait came back
  indistinguishable from "no termination arrived yet" (`error.NoResponse`
  after burning through every round). It now propagates `Canceled`
  immediately and leaves every other transient failure retrying as before.
  The `Link`/`LinkError` seam (GOOSE/SV, layer-2) is untouched — this module
  takes no raw socket of its own for it, so there is nothing here that owns
  an fd to recover a cancellation from.
- **2026-08-18** — Portability fix (`check-portable`): `ber.encodeLength`'s multi-byte
  branch shifted its `usize` length by a hardcoded `shift: u6`. On a 32-bit target
  `Log2Int(usize)` is `u5`, so `v >> shift` failed to compile (`u6` doesn't coerce down
  to `u5`). Retyped `shift` as `std.math.Log2Int(usize)` — the value shifted
  (`encodeLength`'s `v: usize`) is genuinely platform-width, so the shift-amount type
  should track it rather than hardcode either width. Compile-only, identical semantics
  on every target that already builds (the actual shift amounts here top out at 24 bits
  for a 4-byte 32-bit `usize`, well inside `u5`); no behavioural test added. Verified:
  `zig build portable-iec61850` still reports unrelated wasi-surface failures (thread
  spawn in single-threaded mode, `os.linux.VDSO`, libc `poll`/`nanosleep`,
  `process.Environ.GlobalBlock.view`) — out of scope for this fix — but the `u5`/`u6`
  diagnostic this fix targeted is gone; `zig build test-iec61850` still 395/406 (11
  pre-existing skips).
- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  `libiec61850` (C, MZ Automation).
- **2026-07-23** — New module: IEC 61850 substation automation — MMS (ISO 9506) client
  over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe encoding and
  SV sampled values.
