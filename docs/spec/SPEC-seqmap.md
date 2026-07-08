# SPEC — `seqmap`

**Purpose** — The correlation half of any request/reply protocol engine: a reply carries only a
16-bit id, and matching it back to *which request, sent when* must be O(1) with tens of thousands
of probes in flight. `seqmap` maps a 16-bit sequence number to the `{ target, probe, sent_ns,
answered }` it was issued for. Generic — used by `icmp` (echo) and usable by anything correlating
on a 16-bit id (DNS ids, …).

**Model after / Seed** — fping's `seqmap.c` (the round-robin fixed-table approach). Extracted from
the authors' `zig-fping` `src/seqmap.zig`; the fping/Stanford attribution is in `NOTICE` (shared by
netaddr/dns/icmp/seqmap).

**Design & invariants**
- **Fixed 65536-slot table** indexed by the id; ids handed out **round-robin** (`next` wraps at
  2^16) so a freshly released id is not immediately reused — stale/duplicate replies for a retired
  id resolve to `null` rather than aliasing a live probe.
- **Allocation:** exactly one — the slot table at `init`. `add` / `fetch` / `fetchPtr` / `release`
  / `clear` never allocate.
- **Explicit lifetime:** a slot is freed only by the engine (on reply / timeout / send error).
  `add` returns `error.Exhausted` when all 65536 slots are live — so the caller's in-flight cap
  must stay < 65536; exhaustion is a caller-cap bug, not a runtime surprise.
- **Concurrency:** reentrant, no shared/global state — but one instance is single-owner (do not
  share a `SeqMap` across threads without external sync).
- `fetch` on a stale/foreign id returns `null` (never panics); `release` is idempotent.

**Threat model / out of scope** — Not a security primitive. It does not authenticate replies:
`fetch` tells you an id maps to a live probe, not that the reply is genuine (spoofed replies with a
guessed id land in the slot). Callers needing anti-spoofing add their own token/nonce. No timing or
memory-safety guarantees beyond never-panic on unknown ids. Round-robin reuse mitigates but does
not eliminate stale-reply aliasing across a full 2^16 wrap.

**Verification** — Unit tests: add/fetch/release lifecycle, round-robin non-reuse, exhaustion at
65536, idempotent release, `answered` dup-detection flag, `clear` for a new round.

**Status** — `extract · any · util · reentrant` · deps: none (std only).
