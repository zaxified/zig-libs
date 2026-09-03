# isis-sim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit. **`.event_cap_exceeded` was unreachable from the
  suite and its precedence was pinned by nothing.** `Outcome` documents it and
  `.not_quiescent` as different diagnoses — a runaway versus mere under-convergence —
  but BOTH conditions hold on any run the ceiling stops, so the distinction lives
  entirely in the order of two lines in `runToConvergence`, and the ceiling was a
  hard-coded 200_000 that no scenario here comes within three orders of magnitude of.
  Swapping the two lines left 20/20 green. The ceiling is now `Options.max_events_cap`
  (same default), which is what makes the branch reachable at all, and a new TEETH test
  drives a 4-node line into it with a ceiling of 8 events, asserts the run is also
  genuinely non-quiescent (so `.not_quiescent` would be a TRUE statement about it and
  precedence is the whole content of the check), and carries both controls: the same
  fabric under the default ceiling converges, and one given no simulated time comes back
  as plain `.not_quiescent`. Confirmed red with the order swapped back
  (`expected .event_cap_exceeded, found .not_quiescent`), green restored. 21/21.
- **2026-09-03** — Docs: README's "Termination & quiescence" section and its API sketch
  both still described the pre-`34493c2b` API, where every non-convergence collapsed
  into one `.step_cap_exceeded` value — a variant that has not existed since 2026-08-08.
  The sketch is a sketch (it carries a `0xSEED` placeholder, so no compile gate could
  ever have caught it) but it taught a reader the wrong outcome set for four weeks.
  Both now name the three distinct outcomes and say what each one diagnoses.

- **2026-08-18** — Portability fix (`check-portable`): `Fabric.onTimer` indexed
  `self.failures.items[timer_id - fail_timer_base]` directly; `timer_id` is `u64`
  (`fail_timer_base = 1 << 32` is a tag bit distinguishing this timer class from
  `timer_poll`/`timer_restart`), which fails to compile as a slice index on a 32-bit
  target. The recovered index is bounded by `self.failures.items.len` — a
  scenario-authored list this same process appends via `failLinkAt`, never externally
  supplied — so it cannot reach anywhere near `usize`'s range without exhausting memory
  first; added a documented `@intCast` rather than widening the array, since the value
  genuinely cannot exceed a real `usize` in practice. Compile-only; no new behavioural
  test (the guard is unconditionally safe by construction, not a runtime boundary).
  Verified: `zig build portable-isis-sim` and `zig build test-isis-sim --summary all`
  (20/20) both green.
- **2026-08-08** — ⏪ *Backfilled 2026-09-03; this entry was missing.* **Source-breaking:**
  `Outcome` split from two variants into four (`34493c2b`). It used to collapse three
  distinct causes into one `.step_cap_exceeded` — "invariant violated", "event ceiling
  hit" and "did not quiesce" all reported under a name that says only *needed more
  steps*, including a genuine safety violation. Now `.converged` / `.safety_violated` /
  `.event_cap_exceeded` / `.not_quiescent`, so a caller and a test can tell them apart
  without also inspecting `violation`. Any `switch` over `Outcome` written before this
  fails to compile against it.
- **2026-08-07** — ⏪ *Backfilled 2026-09-03; this entry was missing, and it is the
  largest behavioural change in the module's history.* **The harness stopped driving its
  stack over a perfect network** (`20b8b82a`). `netsim` had always offered loss,
  duplication, reordering, jitter and partitions, and this harness used none of them —
  only `link_down`, one fixed seed per test, with retransmission deliberately inert. So
  everything it certified was certified under the one condition that makes flooding
  trivially correct. Added `Options.link` (a `netsim.LinkConfig` per link), the one-shot
  `drop_once` / `dup_once` / `delay_once` faults and `partition`/`heal`, all merged into
  the fault trace `runToConvergence` builds, plus `Options.retransmit_interval` and
  `Options.csnp_interval` — because a lossy medium with retransmission still inert
  provably cannot converge, which is why those two knobs exist and why the doc comment on
  `retransmit_interval` states the requirement.
- **2026-08-06** — Security audit: five findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-24** — New module: Headless multi-node IS-IS/SPB fabric convergence
  simulator.
