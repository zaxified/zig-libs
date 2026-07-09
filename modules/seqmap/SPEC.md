# seqmap — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Fixed 65536-slot table indexed by a 16-bit id; ids handed out round-robin (`next` wraps at 2^16) so
a freshly released id is not immediately reused. Exactly one allocation, at `init` (the slot table);
`add`/`fetch`/`fetchPtr`/`release`/`clear` never allocate. A slot is freed only by the caller's
engine (on reply/timeout/send-error) — `add` returns `error.Exhausted` when all 65536 slots are
live, so the caller's in-flight cap must stay below 65536. `fetch` on a stale/foreign id returns
`null`, never panics; `release` is idempotent. Reentrant — no shared/global state, but one instance
is single-owner (no cross-thread sharing without external sync). Modeled after fping's `seqmap.c`
(round-robin fixed-table approach) — see NOTICE.

## Threat model / out of scope
Not a security primitive: `fetch` confirms an id maps to a live probe, not that a reply is genuine —
a spoofed reply with a guessed/predictable id lands in the slot. Callers needing anti-spoofing must
add their own token/nonce (e.g. `icmp` payload verification). No timing or memory-safety guarantee
beyond never-panic on unknown ids. Round-robin reuse mitigates but does not eliminate stale-reply
aliasing across a full 2^16 wrap.

## Verification
Unit tests: add/fetch/release lifecycle, round-robin non-reuse, exhaustion at 65536, idempotent
release, `answered` dup-detection flag, `clear` for a new round. 5 tests. Run: `zig build test-seqmap`.

## Backlog / deferred
None recorded in PLAN.md or README beyond the documented round-robin-wrap caveat above.

## Status
`extract · any · util · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
