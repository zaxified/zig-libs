# isis-flood — SPEC

Auditor/design reference. The consumer-facing purpose, API sketch, and verify
steps live in `README.md`; this document is the pacing model (with ISO cites), the
SRM/SSN/CSNP output rules, the chunking scheme, the next-wakeup computation, the
bounds, and the deferred list.

## 1. Scope

The IS-IS **flooding transmit scheduler** (ISO/IEC 10589 §7.3.15 SNP generation +
§7.3.16.3/.4 LSP transmission) for **point-to-point** circuits, one level. Pure,
time-injected, single-owner: the caller supplies `now` and the set of Up
interfaces, calls `poll`, and performs the sends; the scheduler decides what to
send when and updates the LSDB flags (clearing SSN). It reads the `isis-lsdb`
SRM/SSN flags + owned LSP bytes + `summarise`, and reconciliation of received
PDUs stays in `isis-lsdb`. Out of scope: §7.

## 2. What the siblings provide, and what this module adds

`isis-lsdb` (`modules/isis-lsdb`) maintains, per stored LSP, the per-interface
**SRM** (flood) and **SSN** (acknowledge/request) bitsets, exposes
`srmIterator(iface)` / `ssnIterator(iface)` (each `next()` → `{ lsp_id, bytes }`),
`get`, `summarise(out, start, end, now)` (fills `isis.tlvs.LspEntry` for a CSNP),
`clearSsn`, and the reconcile entry points (`reconcilePsnp` / `reconcileCsnp`)
that **set and clear** those flags on received PDUs. `isis` (`modules/isis`)
provides the LSP (re-sent verbatim), PSNP/CSNP builders, and the LSP-Entries (#9)
TLV codec.

This module adds the **transmit side**: which flag becomes which PDU, the
retransmit **pacing** and its per-`(lsp, iface)` last-sent bookkeeping, the PSNP
and periodic-CSNP **generation + chunking**, and the **next-wakeup** deadline. It
performs no I/O and holds no clock.

## 3. The pacing model (ISO §7.3.16.3/.4) — and a correction to the brief

**A per-`(lsp, iface)` retransmit gate, not a per-interface throttle.**
`minimumLSPTransmissionInterval` (default 5) is the minimum interval between
retransmissions of **one specific LSP** on a circuit — *not* a "one LSP per 5 s
per interface" rate. (Reading it as a per-interface throttle would make an initial
DB sync of N LSPs take N × 5 s, which is absurd and not what ISO or any production
IS-IS does.) So the scheduler keeps a **last-sent time per `(lsp, iface)`** and an
SRM-flagged LSP is eligible to (re)send iff it was never sent on that circuit or
`now >= last_sent + minimum_lsp_transmission_interval`.

ISO's separate fine-grained **inter-LSP transmit pacing** (a sub-second gap
between successive LSP PDUs on a circuit, to avoid bursting the whole DB at once)
is modeled here by a simpler discretisation: a per-`poll` per-interface **burst
cap** (`max_lsps_per_iface_per_poll`, default 64). It bounds the effect count and,
when hit, sets `truncated` so the caller re-polls immediately. Folding the
fine-grained timer into a burst cap is a documented simplification, not the ISO
timer verbatim.

**Where SRM is actually cleared (P2P).** Sending an LSP does **not** clear SRM.
`isis-lsdb` clears SRM only when a received PSNP acknowledges the LSP
(`reconcilePsnp` → per-entry `compare == same` → `srm.unset(iface)`) or when a
superseding LSP replaces the entry. The scheduler therefore **never** clears SRM;
it relies on retransmission until the ack path clears it. This is the P2P
"implicit/explicit ack retransmit" model. (On a **broadcast** circuit the rule
inverts — SRM is cleared on send and the DIS's periodic CSNP drives sync — which
is why that case is deferred, not hacked into the P2P path; see §7.)

## 4. SRM / SSN / CSNP output rules

For each interface `i` in the caller's `up` set (others are skipped entirely —
the up-interface gate), `poll` emits, in order:

1. **LSP (SRM).** Walk `srmIterator(i)`. For each `(id, bytes)`:
   - eligible (per §3) → emit `{ i, .lsp, bytes }` (bytes point into the LSDB's
     owned copy, zero-copy), record `last_sent[(id,i)] = now`. SRM stays set.
   - not eligible → contribute `last_sent + interval` to the wakeup.
   - burst cap reached → `truncated`, stop this circuit's LSPs.
2. **PSNP (SSN).** Collect the SSN-flagged LSPs' entries via `get` (a request
   placeholder yields the all-zero "please send me this" entry — seq/life/csum 0
   — which is exactly the ISO PSNP-request encoding), sort by LSP-ID, chunk to
   `lsp_entries_per_pdu`, build one PSNP per chunk into `scratch`, emit
   `{ i, .psnp, bytes }`, and **`clearSsn`** for each entry in the chunk (the ack
   has been produced).
3. **CSNP (periodic, §7.3.15.2).** When `now >= csnp_next[i]`: summarise the whole
   DB, chunk into range-tiled CSNPs (§5), emit `{ i, .csnp, bytes }`, and set
   `csnp_next[i] = now + complete_snp_interval`. The first `poll` that sees `i` Up
   primes `csnp_next[i] = now`, so an initial CSNP fires immediately, then only on
   cadence.

`Effect.bytes` for `.lsp` alias the LSDB; for `.psnp`/`.csnp` they alias the
caller's `scratch`. Both are valid until the next `poll` or the next LSDB
mutation — the caller sends them synchronously.

## 5. CSNP range-chunking scheme

`summarise` fills up to `max_summary_entries` (256) LSP-Entries for the full range
`[00…00, FF…FF]`, in map order. The scheduler **sorts** them ascending by LSP-ID
and splits into groups of `lsp_entries_per_pdu`. For group `k` (entries
`[i, j)`):

- `start = (k == 0) ? 00…00 : successor(last_id_of_group_{k-1})`
- `end   = (k == last) ? FF…FF : last_id_of_group_k`

where `successor` is the byte-wise big-endian +1. This **tiles** `[00…00, FF…FF]`
with no gap and no overlap: consecutive ranges abut exactly (`start_k =
end_{k-1} + 1`), the first starts at the bottom, the last ends at the top, and
every summarised LSP-ID lies within exactly one range. A neighbour that runs the
CSNP completeness check per range therefore sees a coherent, gap-free picture. An
empty DB emits one CSNP covering the whole range with no entries (a valid "I hold
nothing" assertion that makes the neighbour flood everything to us).

**Per-PDU cap.** Each emitted PDU carries exactly one #9 TLV, so an 8-bit TLV
length caps it at 255 / 16 = 15 entries; `lsp_entries_per_pdu ∈ [1, 15]`
(asserted at `init`). Packing several #9 TLVs into one PDU to fill an MTU is a
deferred optimisation (§7) — it changes nothing on the reconcile side, which
walks every #9 TLV.

## 6. Next-wakeup computation

`next_wakeup` is the minimum, over all Up interfaces, of:

- the next paced LSP retransmit: `last_sent[(id,i)] + minimum_lsp_transmission_interval`
  for each still-SRM-flagged LSP (for one just sent, `now + interval`), and
- the next periodic CSNP: `csnp_next[i]`.

It is `now` when `truncated` (work remains this instant — poll again immediately)
and `null` when nothing is pending (no Up interface). PSNP acks are emitted
immediately and unpaced, so they contribute to the wakeup only via `truncated`.
Saturating arithmetic (`+|`) guards the interval additions.

## 7. Bounds / DoS

- **Last-sent map** — keyed by `(lsp_id, iface)`, bounded by the currently
  SRM-flagged pairs (≤ LSDB `capacity` × interfaces). Every `poll` prunes entries
  whose SRM is no longer set (LSP acked, cleared, or removed), collecting victims
  in a read-only pass then removing them (no iterator invalidation, no per-poll
  allocation after warmup). It cannot grow without limit.
- **Per-poll output** — the caller's `out` slice bounds the effect count and
  `scratch` bounds the serialised bytes; overrunning either sets `truncated` and
  stops cleanly (SSN is cleared only for PSNPs actually emitted, so an unsent ack
  simply retries next poll). The per-interface burst cap bounds LSP effects.
- **Summary** — a DB larger than `max_summary_entries` is summarised only up to
  that many entries per poll per circuit (a documented cap, sized to the fabric;
  the periodic cadence re-summarises). No per-hostile-input allocation anywhere.

## 8. Deferred (with hooks)

- **LAN / broadcast flooding** — on a broadcast circuit SRM is cleared **on send**
  (no per-neighbour ack), and only the **DIS** sends the periodic CSNP; receivers
  send PSNPs only to request missing LSPs. This scheduler is P2P-only: it would
  take the LSDB's `broadcast_interfaces` set plus a DIS-role input to switch an
  interface to clear-on-send + DIS-gated CSNP. The `up`-set + per-interface timer
  structure is the hook.
- **Fine-grained inter-LSP transmit pacing** — the sub-second per-circuit LSP gap
  is approximated by the per-poll burst cap (§3); a real inter-LSP timer would
  replace it.
- **Multi-TLV PDU packing** — filling a PDU to the link MTU with several #9 TLVs
  (rather than one 15-entry TLV per PDU). Purely an efficiency change.
- **Mesh-groups (RFC 2973)** and **LSP purge-specific flooding** beyond what the
  SRM flag already encodes (a purge is just an LSP with SRM set by the LSDB).
- **Socket I/O** — the scheduler returns effects; the caller owns the wire.

## 9. Verification

Per CONVENTIONS §7 this is **pure logic** → unit + property/round-trip; the wire
format is exercised end-to-end against the sibling `isis` codec (golden-tested)
and the `isis-lsdb` flag machinery, so no external oracle is needed.

- **SRM pace boundary** (injected `now`): send at `t=0`; no re-send at `t∈{1,4}`;
  retransmit at `t=5 = 0 + interval`; SRM never cleared by the scheduler on P2P.
- **Positive control** (permanent): an **unpaced** scheduler
  (`pace_lsp_retransmit = false`) re-sends on the immediate second poll where the
  paced one does not — the exact gate the boundary test depends on. Regressing the
  pacing to "re-send every poll" turns the boundary test RED.
- **Ack clears retransmit**: a PSNP echoing the same version, reconciled via
  `lsdb.reconcilePsnp`, clears SRM; the scheduler then stops re-sending.
- **SSN → PSNP**: two SSN-flagged LSPs → one PSNP whose decoded LSP-Entries are
  exactly those two (id/seq/lifetime), SSN cleared afterward.
- **Periodic CSNP**: emitted on the `complete_snp_interval` cadence (initial fire,
  then silent within the interval, then again at the boundary), decoded and its
  entries checked against the DB.
- **CSNP chunking**: a tiny `lsp_entries_per_pdu` over a few LSPs → multiple
  CSNPs whose `[start, end]` ranges tile `[00…00, FF…FF]` contiguously (each
  start == previous end's successor, first == min, last == max) with full,
  non-overlapping entry coverage.
- **Up-interface gate**: an SRM-set LSP on a Down interface is not sent; it floods
  once that interface is Up.
- **Next-wakeup**: equals min(next retransmit, next CSNP); `null` with no Up
  interface; `now` when truncated.
- **Determinism**: identical `(lsdb ops, now, up)` → identical effect counts and
  wakeup.
- **Truncation / bounds**: a full `out` slice → `truncated`, `next_wakeup == now`;
  the last-sent map is pruned to zero once SRM clears; `std.testing.allocator`
  leak checks.
- **Integration**: two nodes (each a real `Lsdb` + `Scheduler`) flood an LSP and
  acknowledge it back through the `isis` wire codec — the second side is built,
  not assumed — and A's retransmit stops once B's ack lands.

Green in Debug + ReleaseFast; `zig fmt --check` clean; `zig build check-catalog`
green; the sibling `isis` (46) and `isis-lsdb` (24) suites unaffected.

Provenance: pure spec-only clean-room from ISO/IEC 10589 §7.3.15/.16 (a public
spec — merger doctrine); no third-party implementation source consulted or ported.
Like the sibling `isis` codec + `isis-adj` FSM it carries no `/NOTICE` entry.
