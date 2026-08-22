# iec61850 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
