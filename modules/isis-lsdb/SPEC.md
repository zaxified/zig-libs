# isis-lsdb — SPEC

Auditor/design reference. The consumer-facing purpose, API sketch, and verify
steps live in `README.md`; this document is the comparison rule (with ISO cites),
the SRM/SSN outcome matrix, the aging/purge state machine, the CSNP/PSNP reconcile
matrix, the capacity/DoS bound, and the deferred list.

## 1. Scope

The IS-IS **update process** (ISO/IEC 10589 §7.3) for ONE level: the LSP-ID-keyed
database, the newer-LSP comparison, aging/purge, and the SRM/SSN flooding flags
plus CSNP/PSNP database synchronisation. Pure, time-injected, single-owner: the
caller supplies `now`, feeds received LSP/CSNP/PSNP PDUs (decoded by `isis`), and
reads/clears the flags to drive flooding and acknowledgement. Out of scope for
this increment: everything in §6.

## 2. What `isis` provides, and what this module adds

`isis` (`modules/isis`) is a pure codec. It decodes the LSP (`isis.Lsp`) exposing
`lsp_id [8]`, `sequence_number u32`, `remaining_lifetime u16`, `checksum u16`,
`flags` (`LspFlags`), `pdu_length`, and a bounds-checked `tlv_bytes` region; and
the CSNP/PSNP (`isis.Csnp`/`isis.Psnp`) with their LSP-Entries (#9) TLVs, walked
by `isis.tlvs.LspEntryIterator` (16-octet records: lifetime, LSP-ID, sequence,
checksum). It computes/verifies **no** state and **no** ISO Fletcher checksum —
the checksum is a raw field.

This module owns the **database** and the **update-process logic**: the store,
the §7.3.16.1 comparison (`compare.zig`), aging, the SRM/SSN flag sets, and the
SNP reconcile (`store.zig`). Stored LSP bytes are **copied** on insert (own the
`[0..pdu_length]` extent), so the caller's receive buffer is free to be reused.

## 3. The newer-LSP comparison (ISO/IEC 10589 §7.3.16.1)

`compare(incoming, stored) → newer | same | older`, oriented incoming-vs-stored.
The rule, in order:

| Step | Condition | Result |
|------|-----------|--------|
| identical | equal sequence **and** equal checksum **and** both lifetimes zero or both non-zero | `same` |
| a) sequence | `incoming.seq > stored.seq` (plain **unsigned**) | `newer` |
| a) sequence | `incoming.seq < stored.seq` | `older` |
| b) purge | equal seq, `stored.life ≠ 0` **and** `incoming.life == 0` | `newer` |
| c) checksum | equal seq, `incoming.csum ≠ stored.csum` **and** `stored.life ≠ 0` | `newer` |
| else | — | `older` |

**Sequence semantics — confirmed plain unsigned, not serial.** ISO 10589 uses a
linear sequence space `[1, 2^32-1]`; a router that would overflow purges the LSP
and waits `MaxAge` before reusing sequence 1. There is no wrap-around comparison
(no RFC 1982 arithmetic). So `>`/`<` on the raw `u32` is correct, and the
high-bit case (`0x8000_0000 > 0x7FFF_FFFF`) is newer — a *signed* compare would
get this backwards. The positive control pins exactly this.

**The tie-break is oriented, not "larger checksum wins."** A common paraphrase of
§7.3.16.1 says the LSP with the larger checksum is more recent. The real rule —
and every production implementation (verified against FRRouting
`isis_lsp.c:lsp_compare`) — conditions the checksum/purge steps on the **stored**
copy being active (`stored.life ≠ 0`): a differing checksum or a zero-lifetime
incoming purge is "more recent" specifically so a corrupt/expiring copy gets
overridden and purged. It is asymmetric by design (this is the mechanism that
forces a purge when two routers hold same-sequence copies with different
checksums). `compare` implements the oriented rule; `compareBroken` (signed
sequence + no purge rule) exists only to keep the positive control honest.

The stored copy's lifetime fed to `compare` is **aged to `now`**
(`Entry.remainingLifetime(now)`), so an entry that has aged past its lifetime is
treated as a purge for the tie-break even before `tick` formally purges it.

## 4. The SRM/SSN outcome matrix

`InterfaceSet` is a fixed-width bitset (`max_interfaces = 32`), so all flag state
is inline — no per-interface allocation. `Config.interface_count` bounds the
"set on all" loops; `Config.broadcast_interfaces` marks LAN circuits.

### 4.1 `insert` (arrival circuit `C`; `C = null` ⇒ locally originated)

| Comparison | SRM | SSN |
|-----------|-----|-----|
| **newer** / new | set on every circuit **except** `C`; cleared on `C` | set on `C` **iff `C` is point-to-point**; cleared elsewhere |
| **same** | cleared on `C` | set on `C` iff point-to-point |
| **older** | set on `C` | cleared on `C` |
| locally originated (`C = null`, always "newer") | set on **every** circuit | none |

"Point-to-point" ≡ `C` ∉ `Config.broadcast_interfaces`. On a broadcast circuit an
LSP is not SSN-acked (the DIS's periodic CSNP synchronises), so SSN is suppressed
there — the only ISO LAN-vs-P2P distinction the flag matrix needs. A newer LSP
that **replaces** an existing entry resets both flag sets before applying the
matrix (the old version's flags are superseded).

### 4.2 The own-LSP rule (ISO §7.3.16.1) — received copies of our own LSPs

IS-IS as built here is **unauthenticated** (§8), so the update process must
defend itself against an on-link peer. An LSP **received on a circuit**
(`arrival_iface != null`) whose LSP-ID's first six octets equal
`Config.local_system_id` is *never* stored, however "newer" it compares. Only
this system may originate its own LSPs. The standard's remedy — mirrored by
FRRouting's `own_lsp` branch in `isis_pdu.c:process_lsp`, which calls
`lsp_inc_seqno` and re-floods — is to **re-originate at the challenger's
sequence + 1**. LSP generation is deferred (§8), so this module reports it:

| Case | Effect |
|------|--------|
| we hold that LSP-ID, comparison says `newer` | copy untouched; `refresh_pending` set; `challenge_sequence` raised to theirs; SRM set on **every** circuit (arrival included — the sender's copy is wrong); SSN cleared; `InsertResult{ stored = false, self_challenge = their_seq }` |
| we hold it, comparison says `same`/`older` | the ordinary matrix (§4.1) — neither touches the stored copy |
| we hold no copy of that LSP-ID | refused outright (FRR purges rather than adopts); `InsertResult{ stored = false, self_challenge = their_seq }` |
| an **SNP** lists one of our LSP-IDs | never SSN, never a placeholder — we do not request our own LSP from a neighbour. `newer` ⇒ `refresh_pending` + `challenge_sequence` + SRM; `older` ⇒ SRM; `same` ⇒ SRM cleared |

Without this rule a peer could purge our own LSP outright (stored, re-flooded,
deleted after `ZeroAgeLifetime`) with `refresh_pending` never set.

### 4.3 Sequence exhaustion (ISO §7.3.16.1)

The sequence space is the **linear** range `[1, 2^32-1]`; a system that would
need to exceed it must purge the LSP and wait `MaxAge` before restarting at 1.
A **local** origination (`arrival_iface == null`) of a self LSP-ID at
`max_sequence_number` is therefore refused with `error.SequenceExhausted`: a copy
at the top of the space could never be superseded. Refusing *at* the top rather
than beyond it is deliberate — there is no "beyond" to detect. A neighbour's LSP
at `2^32-1` is unaffected; the rule is about our own origination. Combined with
§4.2 this closes the lockout: a peer injecting `0xFFFF_FFFF` for one of our
LSP-IDs is refused before it can be stored, so our later re-originations still
compare `.newer`.

### 4.4 Purge for an unknown LSP

An LSP received with zero Remaining Lifetime whose LSP-ID is **not** in the
database is **ignored** — nothing to purge, and it is deliberately not stored, so
a zero-lifetime flood cannot grow the DB. Reported as `{ ordering = .same, stored
= false }`.

## 5. Aging / purge state machine (ISO §7.3.16.4)

`tick(now)`, two passes, allocation-free:

- **Pass 1 (age)** — for each active (non-request, non-purge) entry, re-derive
  `remainingLifetime(now)`:
  - **self-originated** (`lsp_id[0..6] == Config.local_system_id`): if `rem ≤
    refresh_threshold`, set `refresh_pending` (once) — the owner must
    re-originate with a higher sequence number. Never purged by aging.
  - **other**: if `rem == 0`, enter the purge hold — set `purge_deadline = now +
    zero_age_lifetime`, set SRM on **every** circuit (flood the purge). Reported
    in `AgeReport.entered_purge`.
- **Pass 2 (remove)** — any purge-hold entry with `now ≥ purge_deadline` is
  removed and its bytes freed (`AgeReport.removed`). Removal invalidates the map
  iterator, so the pass re-scans after each removal; purge removals are rare (only
  at `ZeroAgeLifetime` expiry), so the cost is negligible and nothing is allocated.

An LSP received *already* purged (zero lifetime) for an LSP-ID we **do** hold is
stored via the newer path directly into the purge hold (so it re-floods and is
held `ZeroAgeLifetime`). Lifecycle:

```
        insert(active)              tick: rem→0 (non-self)        tick: now ≥ deadline
  ∅  ───────────────────►  active  ───────────────────────►  purge-hold  ─────────────────►  ∅
                             ▲  │  self & rem ≤ threshold
                             │  └────────────► refresh_pending (stays active; owner re-originates)
             insert(newer) ──┘
```

## 6. CSNP / PSNP reconcile matrix (ISO §7.3.15.2)

For each LSP-Entry `(id, seq, life, csum)` in a received SNP on circuit `C`, with
`their = {seq, life, csum}` compared against our stored copy:

| Situation | Action |
|-----------|--------|
| we lack `id` (and the entry is not an all-zero purge) | create a zero-sequence **request placeholder**, set SSN on `C` (→ PSNP request) |
| we lack `id`, entry is all-zero (seq/life/csum = 0) | ignore (nothing to request) |
| `compare(their, ours) == newer` | set SSN on `C` (their copy is newer → request it) |
| `compare(their, ours) == older` | set SRM on `C` (ours is newer → flood it to them) |
| `compare(their, ours) == same` | clear SRM on `C` (in sync — implicit ack) |
| `ours` is a request placeholder | keep SSN on `C` (still requesting) |

**CSNP completeness** (a CSNP is a *complete* summary of `[start_lsp_id,
end_lsp_id]`): after processing the listed entries, any LSP we hold in that range
that the CSNP did **not** list — the neighbour lacks it — gets SRM set on `C`
(flood it to them). A PSNP is *partial*, so `reconcilePsnp` makes no completeness
inference. If the SNP's TLV walk hits malformed bytes the walk terminates safely
(the `isis` iterators are bounds-checked, never over-read) and the completeness
sweep is **skipped** — a corrupt CSNP must not trigger a mass re-flood.

Request placeholders carry no PDU bytes, are skipped by aging and by `summarise`,
count toward `capacity`, and are replaced when the real LSP arrives (any real LSP
is newer than a sequence-0 placeholder). They are **not** created for our own
LSP-IDs (§4.2), they are budgeted separately (§7), and they are **timed out**
(§7) — an SNP is unauthenticated, so a placeholder that nothing ever answers must
not be permanent.

## 7. Capacity / DoS bound

The store is bounded by `Config.capacity`. A new distinct LSP-ID is admitted only
while `count() < capacity`; otherwise `insert` returns `error.DatabaseFull` with
the store unchanged. Purges for unknown LSPs are never stored. So no flood grows
the database without limit — the adversarial memory ceiling is `capacity` entries
plus one in-flight decode. Updates to existing LSP-IDs never change membership,
so they always succeed at capacity. (ISO's LSPDBOverload — set the overload bit
and shed — is a hook for the LSP-generation layer, §8.)

**Bounding *size* is not bounding *availability*.** A request placeholder is
minted from an SNP entry, i.e. from bytes any on-link party can send, and it is
indistinguishable from a genuine request. Two further bounds therefore apply to
placeholders specifically:

- **A separate budget.** `Config.request_capacity` (default `max(1, capacity/4)`,
  never above `capacity`) caps how many placeholders may exist at once. Over the
  budget the request is dropped and the next CSNP retries. However many LSP-IDs a
  hostile SNP fabricates, at least `capacity − budget` slots stay available to
  genuine LSPs. The count is maintained incrementally (`Lsdb.request_count`), so
  an SNP with `n` entries costs `O(n)`, not `O(n²)`.
- **A timeout.** `Config.request_timeout` (default 60 `Time` units; ISO's
  `completeSNPInterval` default is 10 s, so this covers several CSNP retries)
  bounds how long a placeholder lives. `tick`'s pass 2 drops expired ones and
  reports them as `AgeReport.requests_expired`. Without it a placeholder for an
  LSP that never arrives is immortal — skipped by pass 1 (`is_request`) and
  invisible to pass 2 (no `purge_deadline`) — so one CSNP listing `capacity`
  fabricated LSP-IDs would wedge the database permanently, returning
  `DatabaseFull` for every genuine LSP thereafter.

## 8. Deferred (with hooks)

- **The flooding transmit loop** — the consumer that drains SRM (paces LSP
  transmission, honours the ISO minimumLSPTransmissionInterval), and the PSNP/CSNP
  emission that drains SSN. This module exposes the flags + iterators + owned
  bytes it needs; it performs no I/O.
- **SPF / route computation** — reading the stored LSPs' reachability TLVs into a
  shortest-path tree. Purely a consumer of the stored bytes.
- **Generating our own LSP** — building/fragmenting the local LSP from adjacency
  + reachability state, sequence-number management, and the ISO Fletcher checksum.
  `refresh_pending` is the trigger hook; `insert(_, null, now)` is how a generated
  LSP enters the DB. LSPDBOverload lives here too.
- **Authentication** — TLV #10 / RFC 5304/5310 HMAC validation of LSP/SNP PDUs.
- **Multi-topology (MT) and multi-level** — this is a single-level database; an
  L1 and an L2 database are two `Lsdb` instances. MT would key/scope entries by
  topology.
- **The ISO Fletcher checksum — a KNOWN, OPEN exposure, not merely "deferred".**
  Neither computed nor verified anywhere in this repo: the `isis` codec carries
  the checksum as a raw field and exports no Fletcher primitive
  (`isis/src/pdu.zig:248-249`), so no consumer *can* verify it. §7.3.16.1(d)
  (§3, row "c) checksum") is safe in ISO only because §7.3.14.2 has already
  **discarded** an LSP whose checksum is invalid — by the time (d) runs, a
  differing checksum can only mean two well-formed copies disagree. Without that
  precondition **clause (d) is an unauthenticated content-replacement
  primitive**: an on-link party needs *no* higher sequence number to overwrite a
  stored LSP, only an arbitrary checksum byte-pair at the *same* sequence; the
  store then replaces the bytes and sets SRM, re-flooding the attacker's content
  onward. Closing it is a two-module change and the halves belong in different
  places:
  - **the primitive → `isis`.** The Fletcher-over-the-PDU computation is a
    property of the PDU encoding, and `isis` is a *dependency* of this module, so
    only a primitive living there is reachable by both the receive path here and
    the (deferred) LSP-generation path that must *stamp* the checksum.
    Re-implementing it here would put it out of reach of its other user and
    duplicate it.
  - **the policy → here.** "Discard an LSP with an invalid checksum before the
    §7.3.16.1 comparison" is receive-process behaviour and belongs in
    `Lsdb.insert`, immediately after `isis.Lsp.decode`.

  Tracked as `isis-lsdb` F4 / `isis` F3 in the wave-2 audit; the `isis` half must
  land first.

## 9. Verification

Per CONVENTIONS §7 this is **pure logic** → unit + property/round-trip; the wire
format is exercised end-to-end against the sibling `isis` codec (itself
golden-tested), so no external oracle is needed. The §7.3.16.1 rule was
cross-checked against FRRouting `isis_lsp.c:lsp_compare`.

- **Comparison KAT table** (`compare.zig`): higher sequence wins incl. the
  high-bit case a signed compare fails; equal-seq incoming purge wins (and the
  reverse is older); equal purge-state → same; the oriented checksum tie-break
  (differing checksum vs an *active* stored → newer, but not vs a stored purge).
- **Positive control** (permanent): `compareBroken` (signed sequence + no purge
  rule) is asserted to *disagree* with `compare` on the purge case and the
  high-bit case — so a regression of `compare` into either mistake goes RED.
- **Insert SRM/SSN matrix**: newer-from-iface-2 → SRM on {0,1,3}, SSN on {2};
  duplicate → SSN on arrival, no SRM; older → SRM on arrival only; locally
  originated → SRM everywhere, no SSN; broadcast circuit → no SSN.
- **Aging boundary** (injected `now`): kept just before expiry; purge at expiry
  with SRM flooded on all circuits; removed after `ZeroAgeLifetime`;
  self-originated near-expiry flagged for refresh and never purged.
- **CSNP reconcile**: lack→SSN(+placeholder), we-newer→SRM, they-newer→SSN,
  completeness-omitted→SRM; and `summarise` filling LSP-Entries for a range.
- **Adversarial / bounds**: malformed LSP bytes → typed error, store unchanged;
  a distinct-LSP-ID flood refused at `capacity` (membership unchanged);
  purge-for-unknown ignored; a `std.testing.fuzz` target over `insert` (hostile
  bytes never panic, an errored insert leaves membership unchanged); no leak
  (`std.testing.allocator`, `deinit` frees all owned bytes).
- **Hostile on-link peer** (each drives the exact input an unauthenticated
  neighbour can send): a CSNP of `capacity` fabricated LSP-IDs leaves the
  request budget bounded and genuine LSPs still admissible; placeholders expire
  at `request_timeout` and return their budget; a peer's zero-lifetime purge of
  our own LSP is refused, our copy survives past `ZeroAgeLifetime`,
  `refresh_pending` + `challenge_sequence` are set and SRM is asserted on every
  circuit; a peer's `2^32-1` for one of our LSP-IDs is refused and we can still
  re-originate; the two combined still leave both fragments re-originable;
  originating at `2^32-1` is `error.SequenceExhausted`; an SNP listing our own
  LSP-IDs never yields SSN or a placeholder. The Wireshark-anchored golden LSP
  additionally pins that the *same anchored bytes* replayed from a circuit at a
  higher sequence are refused with `self_challenge`.
- **Determinism**: identical `(ops, now)` streams yield identical flag state and
  count.
- **Integration**: two `Lsdb` instances reconcile a CSNP and flood the delta into
  each other through the `isis` wire codec, converging.

Green in Debug + ReleaseFast; `zig fmt --check` clean; `zig build check-catalog`
green; the sibling `isis` suite unaffected.

Provenance: clean-room from ISO/IEC 10589 §7.3; §7.3.16.1 cross-checked against
FRRouting `isis_lsp.c` (behaviour reference, no source ported). See `/NOTICE` (no
entry required — public spec + a black-box behaviour cross-check).
