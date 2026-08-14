# isis-dis — SPEC

Auditor/design reference. The consumer-facing purpose, effects API, defaults and
API sketch live in `README.md`; this document is the election algorithm, the
preemption model, the pseudonode LSP-ID derivation, the change-effect semantics,
and the deferred list.

## 1. Scope

The **LAN Designated-IS election** (ISO/IEC 10589 §8.4.5) for ONE broadcast
circuit at one level. Pure, time-injected, single-owner: the caller supplies the
candidate set (local + Up LAN neighbours) and `now`, and reacts to the returned
`Effect`. Out of scope for this increment: everything in §6.

## 2. What `isis` provides, and what this module adds

`isis` (`modules/isis`) is a pure codec. It decodes the LAN IIH (types 15/16) as
`isis.LanHello`, exposing `source_id [6]`, `priority: u7`, and `lan_id [7]` (the
DIS system-id (6) + pseudonode-id (1)). It carries **no election state** — it is
codec only.

This module adds the election *logic* on top: it takes the neighbour view as
plain input (it does **not** parse Hellos or track adjacency — the caller derives
`{ system_id, priority, snpa }` per router from received Hellos + LAN adjacency
state) and produces the elected DIS + the ids the DIS's pseudonode LSP is keyed
by. The `lan_id` it derives is byte-identical to `isis.LanHello.lan_id`, and the
pseudonode LSP-ID is the exact 8-octet shape `isis.Lsp.lsp_id` expects — an
integration test round-trips both through the real codec.

## 3. The election algorithm (ISO 10589 §8.4.5)

The candidate set is `{ local } ∪ neighbours`, where `neighbours` are the routers
with an Up LAN adjacency. `elect` picks the winner by a single, order-independent
rule:

1. **Highest priority wins.** Priority is the 7-bit LAN-IIH field (0–127). A
   higher value outranks a lower one.
2. **Tie-break: highest SNPA wins.** On equal priority, the numerically **higher**
   SNPA (the 6-octet MAC on this LAN, compared as an unsigned 48-bit big-endian
   integer) wins.

Both directions are **highest-wins** — this is the deliberate, cited fact. It is
the classic footgun because it differs from OSPF's DR twice over: OSPF breaks ties
on highest *Router-ID* and its DR is *non-preemptive*; IS-IS breaks on highest
*SNPA* and is preemptive (§4). A permanent positive-control test (`election.zig`)
runs a lowest-SNPA variant and asserts it elects the *opposite* winner, so a
regression to lowest-wins is caught.

### 3.1 Order-independence

`elect` is a single max-scan (`outranks(candidate, best)`) with a **strict** total
order: `outranks` returns false on equal `(priority, snpa)`, so the scan keeps the
first-seen best on a tie. In practice no tie is ever reached — SNPAs are unique per
LAN, so `(priority, snpa)` totally orders distinct candidates and the result is
independent of the neighbour-slice order. A determinism test shuffles the slice and
asserts an identical `Result`. The scan is O(neighbour-count), allocation-free.

### 3.2 Priority 0

Priority 0 means "I would rather not be DIS", but the router still **participates**:
it is a normal candidate that simply loses to any positive-priority peer, and wins
only when it is the sole candidate or the highest-SNPA among equal (zero) priorities.
Tests pin both: a priority-0 local alone is DIS; a priority-0 local loses to a
priority-1 neighbour.

## 4. Preemption model (why no hold-down)

IS-IS DIS election is **preemptive with no backoff** (ISO 10589 §8.4.5). There is
no election wait timer and no hold-down: the DIS is, at every instant, simply the
winner of the *current* candidate set. So a higher-priority (or higher-SNPA) router
that appears takes over immediately, and a DIS that leaves is replaced immediately.

This module models that as a **pure recompute**: `elect` is stateless, and the
`Election` FSM's `recompute` just runs it over whatever candidate set the caller
passes and diffs the winner against the stored one. There is deliberately no timer,
no "settling" state, and no counter here — adding one would contradict the standard.
The caller is expected to `recompute` on every membership/priority change (a new or
departed Up adjacency, a priority reconfiguration).

Contrast with OSPF (RFC 2328 §9.4), whose DR is non-preemptive and gated by a Wait
timer — modelling *that* would need hold-down state; IS-IS explicitly does not.

## 5. Pseudonode LSP-ID derivation + change-effect semantics

### 5.1 Ids

The DIS originates the pseudonode LSP representing the LAN. This module derives the
ids it is keyed by (not its content — §6):

- **`lan_id` = DIS system-id (6) ‖ DIS pseudonode-id (1)** (7 octets). The
  pseudonode-id is per-candidate: for the local system it is the circuit's
  configured pseudonode-id (a nonzero `u8`, unique per LAN circuit on this DIS —
  a router that is DIS on several LANs uses a distinct id per circuit); for a
  neighbour it is the pseudonode-id observed in that neighbour's Hello `lan_id`.
  Only the **winner's** pseudonode-id populates `Result.lan_id`.
- **pseudonode LSP-ID = `lan_id` ‖ LSP-number (0)** (8 octets) — `Result.pseudonodeLspId()`.
  A nonzero pseudonode-id byte is what marks it a pseudonode LSP rather than a
  router's own LSP (whose pseudonode byte is 0). LSP-number 0 is the first
  fragment; fragmentation across LSP-numbers is a later LSP-origination concern.

When a *different* router is DIS the local system is not the origin; `lan_id` then
exposes that DIS's system-id ‖ observed pseudonode-id so the caller can validate
that incoming Hellos' `lan_id` agree with the elected DIS.

### 5.2 Change effect

`Election.recompute` emits a `DisChange` iff the elected **DIS system-id** flips
between calls (identity is the system-id; SNPA and pseudonode-id are fixed to it):

| Prior DIS | New DIS | `change`? | `became_dis` | `resigned_dis` |
|-----------|---------|-----------|--------------|----------------|
| none (first call) | X | yes (`old_dis = null`) | true iff X = local | false |
| local | remote | yes | false | **true** |
| remote | local | yes | **true** | false |
| remote R1 | remote R2 | yes | false | false |
| X | X (unchanged) | no | — | — |

`became_dis` / `resigned_dis` are the caller's triggers to originate / purge the
pseudonode LSP. `at` carries the `now` from that `recompute` (a timestamp only —
the election is independent of it; see §7). A steady recompute with the same winner
returns `change == null`.

## 6. Deferred

- **Pseudonode LSP content** — building the pseudonode LSP body (the IS-Reachability
  entries binding each LAN member to the pseudonode with metric 0, the SPB/area
  TLVs) is an LSP-origination concern for an `isis-lsdb`/`isis-flood` consumer. This
  module supplies only the LSP-ID and the became/resigned trigger.
- **LAN adjacency formation** — the LAN variant of `isis-adj`: a LAN IIH does not
  use the RFC 5303 three-way handshake but the IS-Neighbours (#6) SNPA list to
  confirm two-way reachability, plus per-neighbour hold timers. This module takes
  the resulting Up-neighbour set as input; forming it is separate.
- **Multi-level DIS** — a LAN runs an independent DIS election per level (L1 and
  L2), each with its own priority and pseudonode-id. This module is one election at
  one level; a consumer instantiates two.
- **Hello-timer / holding behaviour** — the LAN Hello cadence and neighbour hold
  expiry belong to the LAN adjacency layer above; the election reacts to the
  candidate set that layer maintains, not to timers.

## 7. Verification

Per CONVENTIONS §7 this is **pure logic** → unit + property tests; the derived
`lan_id` / LSP-ID are validated end-to-end against the sibling `isis` codec
(golden-tested), and — since 2026-08-05 — the election *result itself* is
anchored against a real IS-IS speaker: see "FRR anchor" below. Wire-visible
content (`lan_id`, priority, the Hello type codes) was separately checked
against Wireshark's dissector (`goldens.zig`); that anchor cannot grade the
election outcome, which has no wire form of its own.

- **Priority election**: {10, 64, 64} → the higher-SNPA 64 wins (asserted exactly),
  and the highest-SNPA-but-lower-priority local still loses.
- **SNPA tie-break direction**: equal priority, …:01 vs …:02 → …:02 wins; the
  assertion would go RED under lowest-wins.
- **Local is / isn't DIS**: local highest priority → `is_local_dis`, `lan_id` =
  local id ‖ local pseudonode-id; local lower → the winner's `lan_id`.
- **Preemption**: local DIS → a higher-priority neighbour appears → `resigned_dis`
  and the neighbour is DIS → the neighbour departs → `became_dis` again — the exact
  effect sequence, no hold-down.
- **Priority 0**: participates, wins as the sole candidate, loses to a positive
  priority — no crash.
- **Determinism**: identical results under neighbour-slice shuffling; identical
  `(candidate-set, now)` FSM streams yield identical effects.
- **Single candidate / empty neighbours**: local alone is the DIS.
- **Integration**: the derived `lan_id` round-trips through a real `isis` LAN IIH,
  and `pseudonodeLspId()` through a real `isis` LSP (`lsp_id[6]` nonzero, `[7]`==0).
- **Positive control** (permanent): a deliberately-wrong lowest-SNPA election
  disagrees with the correct one — a regression to lowest-wins is caught.
- **FRR anchor** (permanent, `election.zig`): a real `isisd` 10.3 LAN election
  (3 routers, one shared broadcast segment, in-VM), two independent
  priority/SNPA assignments, `elect()`'s winner matches FRR's own "is/is not
  DIS" verdict both times — first try, no adjustment made to match.

Green in Debug + ReleaseFast; `zig fmt --check` clean; `zig build check-catalog`
green; the sibling `isis` test suite unaffected.

Provenance: clean-room from ISO/IEC 10589 §8.4.5; no third-party implementation
ported or studied. See `/NOTICE` (no entry required — public spec).

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** Wireshark sharkd validated lan_id/priority/Hello codes; DIS election result closed vs 3 real isisd 10.3 instances

**How it got there.** The anchoring work landed. CLOSED 2026-08-05: 3 real isisd 10.3 instances, one shared LAN broadcast segment (netns + veth into one Linux bridge, in-VM), two independent priority/SNPA assignments — run A {10,64,64} decided by priority AND the 64/64 tie by SNPA; run B held priority+system-id fixed and swapped the SNPAs between the two priority-64 routers, and the DIS flipped to match, ruling out an incidental (non-SNPA) cause. `elect()` matched FRR's own "show isis interface detail" is/is-not-DIS verdict both times, first try, no adjustment made — frozen in election.zig, "FRR anchor" test. Mutation-tested (SNPA compare .gt -> .lt: 6/21 tests fail, exit 1; reverted, git diff -U0 shows only the intended addition). Remaining gap unchanged: circuit-type bits and generic PDU framing stay the sibling isis codec's own already-anchored surface.
