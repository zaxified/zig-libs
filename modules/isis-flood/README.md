# isis-flood

A pure-Zig **IS-IS flooding transmit scheduler** for point-to-point circuits
(ISO/IEC 10589 §7.3.15 + §7.3.16.3/.4) — the consumer that drains the
`isis-lsdb` per-interface **SRM** (send LSP) and **SSN** (send PSNP) flag sets
into the concrete, ordered list of PDUs to transmit, paces LSP retransmission,
and emits periodic **CSNPs** for database synchronisation, updating the LSDB
flags as it goes. Like the siblings `isis-adj` and `isis-lsdb` it is
*time-injected*: no threads, no owned timers, no sockets. The caller supplies a
monotonic `now` and the set of interfaces that currently hold an **Up** adjacency
(derived from `isis-adj`), calls `poll`, and physically sends the returned
effects. This module decides **what** to send **when**.

Status: **gap** — first increment, **point-to-point only**. Implements SRM-driven
LSP flooding with retransmit pacing, SSN-driven PSNP acks/requests with chunking,
the periodic CSNP cadence with contiguous range-chunking, the up-interface gate,
and the next-wakeup deadline seam. LAN/DIS-driven flooding, mesh-groups, and the
actual socket I/O are deliberately deferred — see `SPEC.md`.

Model after: **ISO/IEC 10589 §7.3.15** (flooding / SNP generation) + **§7.3.16.3/.4**
(LSP transmission pacing) — pure spec-only clean-room.

## What's in it

| Layer | Covers |
|-------|--------|
| `scheduler` | The `Scheduler`: `poll(now, up, lsdb, out, scratch)` turns the SRM/SSN flags into `Effect`s, paces LSP retransmits via a per-`(lsp, iface)` last-sent map, drains SSN into PSNPs, drives the periodic CSNP cadence, and returns the `next_wakeup` deadline. Holds the pacing/CSNP timers + a positive-control knob. |
| `snp` | The CSNP/PSNP serialisation + chunking leaf: build a PDU into a caller scratch buffer via the `isis` builders, cap entries per PDU (one #9 TLV = 15), and tile a CSNP series into contiguous, gap-free `[start, end]` LSP-ID ranges (`successor`, `sortEntries`, `buildPsnp`, `buildCsnp`). |

## The retransmit / pacing model (P2P)

On a point-to-point circuit an LSP is flooded and then **retransmitted** every
`minimum_lsp_transmission_interval` (ISO `minimumLSPTransmissionInterval`,
default **5**) until the neighbour **acknowledges** it. The crucial rule:

- **Sending an LSP does NOT clear its SRM flag.** `isis-lsdb` clears SRM only on
  the **ack path** — `reconcilePsnp`, whose per-entry `same` result unsets SRM on
  the circuit — or on a superseding update. So this scheduler **never clears SRM
  itself**; it tracks a per-`(lsp, iface)` **last-sent time** and re-emits an
  SRM-flagged LSP once `now - last_sent >= interval`. Feed a received PSNP into
  `lsdb.reconcilePsnp` and the retransmit stops on its own.
- The last-sent map is **bounded** by the currently-SRM-flagged `(lsp, iface)`
  pairs (itself bounded by the LSDB capacity): every `poll` first prunes entries
  whose SRM is no longer set. Nothing grows without limit.

The per-`poll` per-interface **burst cap** (`max_lsps_per_iface_per_poll`,
default 64) stands in for ISO's fine-grained inter-LSP transmit pacing; hitting
it (or filling `out`/`scratch`) sets `truncated` and `next_wakeup == now`.

## PSNP / CSNP generation + chunking + cadence

- **PSNP (SSN):** for each Up interface, the SSN-flagged LSPs (acks for LSPs
  received on that P2P circuit, plus zero-sequence *requests* for LSPs we lack)
  are collected as LSP-Entries, chunked to `lsp_entries_per_pdu`, serialised into
  one PSNP per chunk, and **SSN is cleared** for the entries once the PSNP is
  produced.
- **CSNP (periodic, §7.3.15.2):** on a `complete_snp_interval` cadence per
  interface (default **10**), the DB is summarised (`lsdb.summarise`), sorted,
  and chunked into CSNPs whose `[start, end]` ranges **tile the LSP-ID space
  contiguously** — each chunk's start is one past the previous chunk's last
  LSP-ID, the first starts at `00…00`, the last ends at `FF…FF` — so a
  neighbour's completeness check sees no gap or overlap. Because §7.3.15.2 makes
  an advertised range a **claim** that every in-range LSP is listed (an omitted
  one gets flooded back at us), a database too large for one summary buffer is
  advertised across **several polls**: each poll covers the largest window it can
  enumerate completely, sets `truncated`, and the next poll resumes at
  `end + 1` — the last range says `FF…FF` only when the series really got there.
  An empty DB still emits one covering CSNP. The initial CSNP fires on the first
  `poll` that sees an interface Up; thereafter only on cadence.

## Up-interface gating

An interface is processed only if its bit is set in the `up` set the caller
passes. An LSP whose SRM is set on a currently-Down interface is **not** sent;
when the interface comes Up it floods normally. Deriving `up` from the
`isis-adj` adjacency FSM is the caller's job — this module does not depend on
`isis-adj`.

## The poll / next-wakeup seam

`poll` returns the `effects` to send plus `next_wakeup`: the absolute time the
caller should next call `poll`, computed as the **minimum** over the next paced
LSP retransmit gate and the next periodic CSNP across all Up interfaces (`now`
when truncated, `null` when nothing is pending). This is the classic
compute-the-deadline / caller-sleeps seam.

## API sketch

```zig
const flood = @import("isis-flood");

var sched = flood.Scheduler.init(alloc, .{
    .local_system_id = .{ 0, 0, 0, 0, 0, 0xA },
    .min_lsp_transmission_interval = 5,   // ISO minimumLSPTransmissionInterval
    .complete_snp_interval = 10,          // ISO completeSNPInterval
});
defer sched.deinit();

var out: [64]flood.Effect = undefined;    // caller-owned effect list
var scratch: [4096]u8 = undefined;        // caller-owned SNP serialisation buffer

// `up` = interfaces with an Up adjacency (from isis-adj); `db` = the isis-lsdb.
const r = sched.poll(now, up, &db, &out, &scratch);
for (r.effects) |e| switch (e.kind) {
    .lsp, .psnp, .csnp => sendOnWire(e.iface, e.bytes),
};
// sleep until r.next_wakeup (or until a receive wakes the loop), then poll again.
```

## Test

```
zig build test-isis-flood
```

Covers: **SRM drain + pace** (one send; no re-send within
`minimumLSPTransmissionInterval`; retransmit at the boundary — SRM never cleared
by us on P2P); **ack clears retransmit** (a PSNP reconciled into the LSDB clears
SRM, and the re-send stops); **SSN → PSNP** (exactly the flagged LSPs, decoded
and checked, SSN cleared afterward); **periodic CSNP** (emitted on cadence, not
every poll, summarising the DB — decoded and checked); **CSNP chunking**
(contiguous gap-free `[start, end]` ranges tiling the DB, full entry coverage);
two **hostile-peer** tests over a 300-LSP database (> the 256-entry summary
buffer): no CSNP ever claims a range holding an LSP it did not list, and a peer
LSDB fed the whole series re-floods and requests **nothing** (ISO 10589
§7.3.15.2);
**up-interface gating**; **next-wakeup** = min(next retransmit, next CSNP);
**determinism** (identical inputs → identical effects); **truncation** (full
`out` → `truncated`, `next_wakeup == now`); the **last-sent prune bound**; a
permanent **positive control** (an unpaced scheduler re-sends every poll — the
gate the pace-boundary test depends on); a two-node **integration** test that
floods an LSP and acks it back through both schedulers and the `isis` wire codec;
and `std.testing.allocator` leak checks. Green in Debug and ReleaseFast;
`zig fmt` clean.

Provenance: pure spec-only clean-room from ISO/IEC 10589 §7.3.15/.16 (a public
spec); no third-party implementation consulted or ported. Like `isis`/`isis-adj`
it carries no `/NOTICE` entry. License: MIT.
