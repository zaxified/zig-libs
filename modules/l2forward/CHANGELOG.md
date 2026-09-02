# l2forward — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (window `d163578..HEAD`, +944/-209 in `src/root.zig` — a rewrite
  of most of the module, not drift). The previous entry recorded only "seven findings fixed, one
  documented" and said nothing about the F1 `Ingress`/`local_only` rewrite, F3 (`UnknownIsid`), F5
  (mobility/quarantine) or F8 (`removeMember` purge) — including `learn`'s return type changing
  from `void` to `LearnOutcome`, a breaking change to a public contract that was invisible here.
  Recorded now, late. **BREAKING (minor):** `LearnError` gains `InvalidSourceMac`, and `forward`
  returns `.flood` rather than `.unicast` when the learned PE is not a member.

  ⭐ The rewrite came back **clean on memory safety and on tenant isolation of entries**: zero
  `unreachable` / `assert` / `.?` / `@intCast` in library code, no clock, no shared state — so
  there is no Debug-vs-ReleaseFast divergence to find, and 22 of 25 mutations went red naming a
  test. The C4 classification still fits: the new code is all state, no wire bytes. Nine behaviours
  were differential-tested against the **live Linux bridge FDB** in a user namespace; six agree
  (including reject-not-evict at the cap, no transmit-refresh of ageing, and a re-confirmed
  `ageing_time` 300 s), one is a documented deliberate difference, and two diverge — F-D below.

  - **HIGH, the attacker's own path was the expensive one.** On a full tenant with nothing
    expired, every frame carrying a novel source MAC paid a complete O(table) reclamation scan that
    reclaimed nothing and still returned `FdbFull` — which is exactly what a source-MAC flood
    drives. Measured at the shipped 8192-entry default: **77.6 us per rejected frame against 21 ns
    for a normal one**, so 6.6 Mbit/s of 64-byte frames saturates one core, and the accepted
    production shape gives one forwarding thread the whole `Table`. SPEC said a flood in one tenant
    "can never evict or starve another tenant's entries" — true of entries, false of the thread.
    Now at most one sweep per tick: expiry depends only on `now`, so a second sweep in the same
    tick cannot find anything the first did not.

  - **HIGH, a forwarding answer naming a PE outside the tenant.** `src_pe` reaches `learn` from
    `l2encap`'s `ingress_pe`, an unauthenticated header field this module already refuses to trust
    in `replicationSet` — but `learn` stored it verbatim as the answer `forward` returns, with no
    membership check. One spoofed frame black-holed a victim's unicast flow for a full
    `aging_ticks`, and if the id named a real PE the customer's frame left the I-SID's member set
    entirely; the outcome was a bare `.moved`, indistinguishable from real mobility. The module's
    own F8 reasoning says exactly this state is bad. Learning stays permissive (membership is
    control-plane and may converge later); the binding now happens at the decision, and a
    non-member answer floods — which still reaches the real station.

  - **MEDIUM, a group or all-zero SOURCE address was learned.** IEEE 802.1D's learning process
    refuses it and the Linux bridge drops the frame outright — verified live: of four
    broadcast-destination frames with sources `02:..`, `01:..`, `ff:..` and `00:..`, exactly one was
    forwarded and none learned. Here all five were learned, and every one is structurally
    unreachable by `forward` (a group destination is BUM *before* the lookup), so they were pure
    dead weight against the tenant's cap — a second free route to the full-table state.

  - **MEDIUM (test gap), the BUM-before-lookup ordering had no test at all.** SPEC states it as
    load-bearing; consulting the FDB for a group destination left 28/28 green. It was invisible
    precisely because of the finding above — nothing ever put a group address in the FDB. Pinned
    now via `learnStatic`, the control-plane route that still can.

  - **LOW (test gap), the move-window boundary** could be flipped from `<=` to `<` with the suite
    green, unlike the quarantine and ageing boundaries, which are both pinned.

  Doc: `aging_ticks = 0` does **not** make entries "immediately stale" (expiry is `age >
  aging_ticks`, so `now == learned_at` is fresh); the move window is **tumbling**, not "sliding" as
  SPEC and the field doc both said; `moveCount` is latched, not live, so a caller polling it as a
  current-rate signal reads a value that never decays; the quarantine flood is attacker-triggerable
  indefinitely at 5 frames per window and costs N-fold replication plus exposure of the victim's
  frames to every remote site, which SPEC described as if it were free; and the module models no
  port state, which the deferred list did not mention.


- **2026-08-06** — Security audit: seven findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: The one anchorable constant
  *is* anchored.
- **2026-07-24** — New module: E-LAN edge forwarding table — per-I-SID customer-MAC
  learning (MAC → remote PE) with time-injected aging + the BUM ingress-replication set
  with split-horizon; forward decision.
