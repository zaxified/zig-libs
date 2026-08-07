# isis-lsdb

A pure-Zig **IS-IS link-state database** for one level (ISO/IEC 10589 §7.3) —
the update process distilled: store LSPs keyed by LSP-ID, apply the §7.3.16.1
newer-LSP comparison, age Remaining Lifetime and purge at `MaxAge`, and maintain
the per-interface **SRM** (flood) / **SSN** (acknowledge) flag sets a flooding
layer drains, plus the **CSNP/PSNP** database-sync reconcile. Like the sibling
`isis-adj` FSM it is *time-injected*: no threads, no owned timers, no sockets.
The caller supplies a monotonic `now`, feeds it received LSP/CSNP/PSNP bytes (via
the `isis` codec), and reads/clears the flags to drive flooding.

Status: **gap** — first increment. Implements the store + the ISO §7.3.16.1
comparison + time-injected aging/purge + the SRM/SSN flag matrix + CSNP/PSNP
reconcile. The flooding transmit loop (the SRM consumer), SPF/route computation,
generating our own LSP (fragmentation), authentication, and MT/multi-level are
deliberately deferred — see `SPEC.md`.

Model after: **ISO/IEC 10589 §7.3** (the update process). The §7.3.16.1 newer
comparison was cross-checked against FRRouting `isis_lsp.c:lsp_compare` for the
oriented purge/checksum tie-break.

## What's in it

| Layer | Covers |
|-------|--------|
| `compare` | The ISO §7.3.16.1 newer-LSP comparison — the correctness core, pure and std-only: `Ordering` (`newer`/`same`/`older`), `LspVersion` (the three header fields it reasons over), `compare`, plus `compareBroken` used only by the permanent positive control. |
| `store` | The `Lsdb`: the LSP-ID-keyed store, `insert` (the update process → SRM/SSN flags), `tick` (aging + purge), the flooding-flag query/clear surface, and the CSNP/PSNP reconcile + CSNP summarise. Owns each stored LSP's PDU bytes (copied on insert). |

## The newer-LSP comparison (ISO §7.3.16.1)

Given an incoming LSP versus the stored copy of the **same LSP-ID**, `compare`
returns `newer` / `same` / `older`. The rule is **oriented incoming-vs-stored** —
it is *not* a symmetric "larger checksum wins" total order (a common misreading):

1. **Sequence number** — a strictly greater sequence number is more recent, by
   **plain unsigned** comparison (**not** RFC 1982 serial arithmetic). ISO 10589
   uses a linear `[1, 2^32-1]` space; on exhaustion the origin purges and waits
   `MaxAge`, so wrap-around ordering never applies.
2. **Equal sequence, incoming purge** — a zero Remaining Lifetime (a purge) is
   more recent than an *active* (non-zero) stored copy of the same sequence. A
   purge authoritatively overrides.
3. **Equal sequence, differing checksum vs an active stored copy** — treated as
   more recent (forces a purge of the possibly-corrupt copy). Conditioned on the
   *stored* copy being active, exactly as ISO/FRR — a differing checksum is not
   an ordering by magnitude.
4. Otherwise **identical** (equal sequence, equal checksum, matching zero-ness)
   or **older**.

A stored entry's Remaining Lifetime for this comparison is the value **aged down
to `now`**, so an entry that has aged to zero is correctly treated as a purge.

## The SRM/SSN model

Per stored LSP, two per-interface bitsets (fixed width `max_interfaces`, no
per-interface allocation):

- **SRM** (Send Routing Message) — this LSP must be *flooded* out the set
  circuits.
- **SSN** (Send Sequence Numbers) — a PSNP entry acknowledging/requesting this
  LSP must be sent out the set circuits.

The store *maintains* these; a flooding layer *reads and clears* them
(`interfacesWithSrm`, `srmIterator`/`ssnIterator`, `clearSrm`/`clearSsn`). The
outcome matrix per `insert` (arrival circuit `C`, or `null` for locally
originated) and per SNP reconcile is in `SPEC.md`. SSN-on-receive is the
point-to-point behaviour; circuits marked `broadcast` in `Config` are not
SSN-acked (the DIS's periodic CSNP does the sync there).

## Aging / purge lifecycle (ISO §7.3.16.4)

`tick(now)` re-derives each active entry's Remaining Lifetime. On reaching zero a
**non-self** LSP enters the purge hold — retained as a zero-lifetime header with
SRM set on every circuit (so the purge floods) — and is removed after
`ZeroAgeLifetime`. A **self-originated** LSP (its LSP-ID begins with our
configured system id) is never purged by aging; nearing/reaching expiry it is
flagged for refresh (`refreshPending`), the signal for the owner to re-originate
it with a higher sequence number.

## Receive-side self-defence (ISO §7.3.16.1)

IS-IS as built here is unauthenticated (auth is deferred, `SPEC.md` §8), so the
update process defends itself against an on-link peer:

- **Own LSPs are never accepted from the wire.** A copy of an LSP whose LSP-ID
  begins with our system id, arriving on a circuit, is refused however "newer" it
  compares — including a zero-lifetime *purge* of our own LSP. `insert` reports
  `InsertResult.self_challenge = <their sequence>`, sets `refreshPending`, records
  `EntryView.challenge_sequence`, and asserts our copy with SRM on every circuit.
  The owner must re-originate at `self_challenge + 1` (FRR's `own_lsp` /
  `lsp_inc_seqno` behaviour). An SNP listing one of our LSP-IDs likewise never
  produces an SSN request or a placeholder.
- **The sequence space cannot be locked.** Originating one of our own LSPs at
  `max_sequence_number` (`2^32-1`) is `error.SequenceExhausted` — a copy at the
  top of ISO's linear `[1, 2^32-1]` space could never be superseded; ISO's remedy
  is purge-and-wait-`MaxAge`, restarting at 1.

- **A corrupt LSP is discarded before it can be compared.** ISO §7.3.14.2 e): a
  **received** LSP whose ISO Fletcher checksum does not check out (including a
  live LSP carrying a zero checksum, RFC 3719 §7) is `error.CorruptedLsp`, store
  unchanged — so §7.3.16.1(d)'s checksum tie-break can no longer be reached with
  arbitrary bytes at an equal sequence number. Purges (§7.3.16.4 note 36) and
  locally originated LSPs are exempt; see `SPEC.md` §8 for why each has to be.

Still open: **authentication** (RFC 5304/5310). The Fletcher checksum is unkeyed,
so it catches corruption, not a deliberate on-link forger — one who computes a
valid checksum for forged content is still only bounded by the sequence-number
and own-LSP rules above. See `SPEC.md` §8.

## Capacity / DoS bound

The store never grows without limit. A new distinct LSP-ID is admitted only while
`count() < Config.capacity`; past that, `insert` returns `error.DatabaseFull`
(store unchanged) rather than evicting a valid link-state record.

Bounding size is not bounding availability, so **request placeholders** — the
zero-sequence stubs minted from unauthenticated SNP entries for LSPs we lack —
are bounded twice more: by their own sub-budget `Config.request_capacity`
(default `capacity/4`, so fabricated LSP-IDs can never deny admission to genuine
LSPs) and by `Config.request_timeout` (default 60), after which `tick` drops them
and reports `AgeReport.requests_expired`. Without the timeout one CSNP listing
`capacity` fabricated LSP-IDs wedges the database permanently. (ISO's
LSPDBOverload response — the overload bit — is a hook, deferred to the
LSP-generation layer.)

## Time-injection contract

The store never reads a clock (same convention as `isis-adj`). Every time-aware
entry point takes a caller-supplied `now: Time` — abstract ticks in the caller's
own unit; `zero_age_lifetime` and `refresh_threshold` are in that same unit. A
stored LSP's Remaining Lifetime is *derived* from the `now` it was set at, so
aging is a comparison, never an owned countdown. Given the same `(ops, now)`
stream the database and its flag state are fully deterministic (a permanent test
pins this).

## API sketch

```zig
const lsdb = @import("isis-lsdb");

var db = lsdb.Lsdb.init(alloc, .{
    .local_system_id = .{ 0, 0, 0, 0, 0, 0xA }, // to detect self-originated LSPs
    .interface_count = 4,
    .capacity = 4096,
});
defer db.deinit();

// on a received LSP (raw link bytes) arriving on circuit 2:
const r = try db.insert(rx_bytes, 2, now);   // decodes via `isis`; malformed → error
if (r.stored) { /* it was newer; SRM/SSN flags are now set */ }

// periodic aging:
_ = db.tick(now);                             // ages, purges, flags self-refresh

// the flooding loop for circuit c:
var it = db.srmIterator(c);
while (it.next()) |lsp| { sendOnWire(lsp.bytes); db.clearSrm(lsp.lsp_id, c); }

// DB sync: process a received CSNP on circuit c:
db.reconcileCsnp(try isis.Csnp.decode(csnp_bytes), c, now);

// build our own CSNP:
var out: [64]isis.tlvs.LspEntry = undefined;
const count = db.summarise(&out, start_id, end_id, now);
```

## Test

```
zig build test-isis-lsdb
```

Covers: the **comparison KAT table** (higher-seq wins incl. the high-bit
signed-vs-unsigned case; equal-seq purge wins; equal purge-state → same; the
oriented checksum tie-break) with a permanent **positive control** (a
deliberately broken compare — signed sequence + no purge rule — diverges from the
correct one); the **insert SRM/SSN matrix** (newer / same / older / locally
originated / broadcast circuit); **aging boundaries** (kept before expiry, purge
at expiry with SRM flooded, removed after `ZeroAgeLifetime`, self-originated
refresh-not-purge); **CSNP reconcile** (lack→SSN, we-newer→SRM, they-newer→SSN,
completeness-omitted→SRM) and summarise; the **capacity bound** and
purge-for-unknown handling; a two-database end-to-end reconcile-and-flood
integration test through the `isis` wire codec; a `std.testing.fuzz` target over
`insert` (hostile bytes never panic, a rejected LSP is inert); a determinism
test; and a `std.testing.allocator` leak check (`deinit` frees all owned bytes).
Green in Debug and ReleaseFast; `zig fmt` clean.

Provenance: clean-room from ISO/IEC 10589 §7.3; the §7.3.16.1 comparison was
cross-checked against FRRouting `isis_lsp.c` for the oriented tie-break (no source
ported). See `/NOTICE` (no entry required — public spec + a behaviour cross-check).
License: MIT.
