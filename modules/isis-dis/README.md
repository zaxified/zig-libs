# isis-dis

A pure-Zig **IS-IS LAN Designated-IS (DIS) election** — for ONE broadcast (LAN)
circuit at one level, it elects the DIS from the set of routers seen on the LAN
(each with its priority + SNPA/MAC) and reports whether THIS system is the DIS.
It is a *pure, time-injected* election: no threads, no owned timers, no sockets,
no allocation. The caller supplies the neighbour view (derived from received LAN
Hellos + adjacency state) plus a monotonic `now`, and acts on the `Effect` it
returns — chiefly the `became_dis` / `resigned_dis` triggers that start or stop
originating the LAN's pseudonode LSP.

Status: **gap** — first increment. Implements the election rule + preemption +
the pseudonode LSP-ID derivation + the DIS-change effect. The pseudonode LSP's
*content*, LAN adjacency formation, and multi-level DIS are deliberately deferred
— see `SPEC.md`.

Model after: **ISO/IEC 10589 §8.4.5** (LAN Designated-IS election).

## The election rule (get it exactly right)

The DIS is the candidate with the **numerically highest priority**; ties are
broken by the **numerically highest SNPA** — the router's MAC on this LAN,
compared as an unsigned 48-bit big-endian integer. **Both directions are
highest-wins.** The candidate set is the local system **plus** every router with
an Up LAN adjacency.

This is the classic footgun, so it is stated precisely and pinned by tests: it is
*not* lowest-SNPA, and priority is a 7-bit field (0–127, matching the LAN IIH
`priority` the sibling `isis` codec decodes). A priority-0 router ("never want to
be DIS") still **participates** and can win when it is the sole/highest candidate.

### Preemptive, no hold-down

Unlike OSPF's DR (highest Router-ID, *non-preemptive*, with a wait timer),
IS-IS DIS election is **preemptive with no backoff** (ISO 10589 §8.4.5): a
newly-appeared higher-priority (or higher-SNPA) router becomes DIS *immediately*,
and a departed DIS is replaced *immediately*. The election is therefore a pure
recompute over the current candidate set — `elect(local, neighbours)` — with the
FSM wrapper diffing successive winners. There is no timer and no hold-down state.

## Pseudonode LSP-ID

When a router is the DIS it originates the **pseudonode LSP** representing the LAN
as a virtual node. This module derives the ids that LSP is keyed by (it does
**not** generate the LSP's content — an LSP-origination concern for an
`isis-lsdb`/`isis-flood` consumer):

- `Result.lan_id` = **DIS system-id (6) ‖ DIS pseudonode-id (1)** — exactly the
  `lan_id` a LAN Hello advertises (`isis.LanHello.lan_id`). When the local system
  is DIS this is our system-id ‖ our configured pseudonode-id; otherwise it is the
  winning neighbour's system-id ‖ its observed pseudonode-id, which the caller can
  compare against incoming Hellos' `lan_id`.
- `Result.pseudonodeLspId()` = **`lan_id` ‖ LSP-number (0)** — the 8-octet id in
  the exact shape `isis.Lsp.lsp_id` expects (a nonzero pseudonode-id byte is what
  distinguishes a pseudonode LSP from a router's own LSP).

The pseudonode-id is supplied per candidate: for the local system it is the
circuit's configured pseudonode-id (a nonzero `u8`, unique per LAN circuit on this
router); for a neighbour it is the pseudonode-id observed in that neighbour's Hello
`lan_id`. Only the winner's value is used.

## Change effects (became / resigned DIS)

The `Election` FSM stores the current DIS and, on each `recompute`, emits a
`DisChange` iff the elected DIS system-id flipped:

- `old_dis` / `new_dis` — the old (or null on the first election) and new DIS ids.
- `became_dis` — the local system just became DIS (was not, now is): originate the
  pseudonode LSP.
- `resigned_dis` — the local system just resigned (was, now is not): purge the
  pseudonode LSP it had been originating.
- `at` — the `now` passed to that `recompute` (a timestamp only; see below).

A steady recompute with the same winner returns no `change`. A flip between two
*remote* routers is still a `change` (with both local flags false).

## Time-injection stance

The FSM never reads a clock. `recompute` takes a caller-supplied monotonic
`now: Time` for **consistency with the sibling `isis-adj` FSM**, but because DIS
election has no timer and no hold-down, `now` is used *only* to timestamp the
emitted `DisChange.at` — the election result itself does not depend on it. Given
the same `(candidate-set, now)` stream the FSM is fully deterministic, and the
election is independent of the neighbour-slice order (SNPAs are unique per LAN, so
`(priority, snpa)` is a strict total order). Permanent tests pin both.

## What's in it

| Layer | Covers |
|-------|--------|
| `election` | The pure `elect(local, neighbours) -> Result`, the `Candidate`/`Result` types, the highest-priority/highest-SNPA rule, and `Result.pseudonodeLspId()`. Order-independent, allocation-free. |
| `fsm` | The `Election` wrapper: `recompute` over the current candidate set, the stored current DIS, and the `DisChange` effect (`became_dis` / `resigned_dis`). |

## Pairing with the isis stack

Builds on the sibling `isis` codec: the derived `lan_id` is exactly
`isis.LanHello.lan_id`, and `pseudonodeLspId()` is exactly the shape
`isis.Lsp.lsp_id` expects (an integration test round-trips both through the real
codec). It is the LAN counterpart to the P2P `isis-adj` adjacency FSM, and feeds
the pseudonode-LSP origination an `isis-lsdb`/`isis-flood` consumer owns.

## API sketch

```zig
const dis = @import("isis-dis");

var e = dis.Election.init(.{
    .system_id = .{ 0, 0, 0, 0, 0, 0xA },
    .priority = 64,               // u7, 0..127
    .snpa = my_mac,               // our MAC on this LAN
    .pseudonode_id = 1,           // this circuit's pseudonode id (nonzero)
});

// On any LAN membership / priority change, recompute over the Up neighbours the
// caller derived from received Hellos + adjacency state:
const eff = e.recompute(up_neighbours, now);
if (eff.change) |c| {
    if (c.became_dis) originatePseudonodeLsp(eff.result.pseudonodeLspId());
    if (c.resigned_dis) purgePseudonodeLsp();
}
// Advertise eff.result.lan_id in our LAN Hellos; validate incoming Hellos'
// lan_id agree with it.
```

## Test

```
zig build test-isis-dis
```

Covers: the priority election ({10, 64, 64} → the higher-SNPA 64 wins), the
**SNPA tie-break direction** (…:01 vs …:02 → …:02, with a case that would go RED
under lowest-wins), local is/isn't DIS with the correct `lan_id`, the
**preemption** sequence (local DIS → higher neighbour appears → `resigned_dis` →
neighbour departs → `became_dis`), **priority 0** (participates; sole winner; loses
to any positive priority), **determinism** under neighbour-slice shuffling, the
single-candidate/empty-neighbour case, and an integration test that round-trips the
derived `lan_id` + pseudonode LSP-ID through the real `isis` LAN-Hello / LSP codec.
A permanent **positive control** runs a deliberately-wrong lowest-SNPA election and
asserts it disagrees with the correct one — so a regression to lowest-wins would go
RED. Green in Debug and ReleaseFast; `zig fmt` clean.

Provenance: clean-room from ISO/IEC 10589 §8.4.5; no third-party IS-IS
implementation (frrouting, IOS, Junos) was ported or studied. See `/NOTICE`
(no entry required — public spec). License: MIT.
