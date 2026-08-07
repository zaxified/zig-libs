# isis-adj — SPEC

Auditor/design reference. The consumer-facing purpose, effects API, defaults and
API sketch live in `README.md`; this document is the state machine, the wire
logic, the mismatch rules, and the deferred list.

## 1. Scope

One **point-to-point** IS-IS adjacency (ISO/IEC 10589 §8.2) using the
**RFC 5303** three-way handshake. Pure, time-injected, single-owner: the caller
supplies `now`, feeds received P2P IIH PDUs (types decoded by `isis`), and reacts
to the returned `Effect`. Out of scope for this increment: everything in §6.

## 2. What `isis` provides, and what this module adds

`isis` (`modules/isis`) is a pure codec. It decodes the P2P IIH (PDU type 17) as
`isis.P2pHello`, exposing `source_id [6]`, `holding_time u16`, `circuit_type`,
`local_circuit_id u8`, and a bounds-checked `tlv_bytes` region + `TlvIterator`.
It does **not** model the RFC 5303 Three-Way Adjacency TLV (type 240) typed — its
`tlvs.code` set ends at the SPB TLVs (#144) — so a 240 is reachable only via the
raw escape hatch (`tlv.findFirst(tlv_bytes, 240)` → the value bytes).

This module therefore owns the **240 value codec** (`three_way.zig`) and the
**FSM** (`fsm.zig`). It parses/emits the 240 value with the same discipline as
`isis`: fixed-offset reads guarded by an up-front length check against the four
legal sizes, no over-read, no allocation.

## 3. TLV 240 wire format (RFC 5303 §3)

Value layout (for the modeled 6-octet system id):

| Field | Octets | Present when |
|-------|--------|--------------|
| Adjacency Three-Way State | 1 | always |
| Extended Local Circuit ID | 4 | value length ≥ 5 |
| Neighbour System ID | 6 | value length ≥ 11 |
| Neighbour Extended Local Circuit ID | 4 | value length == 15 |

So the well-formed value lengths are **1, 5, 11, 15**; anything else is
`error.BadLength`. The state byte encoding is **Up = 0, Initializing = 1,
Down = 2** (RFC 5303) — the reverse of intuitive order; an unassigned byte is
`error.BadState`. `ThreeWayState.fromByte` refuses an illegal `@enumFromInt`.

> **CORRECTION (Wireshark-anchored, filed under the anchor task for this
> module):** this section originally said the neighbour block was all-or-
> nothing and that only 1/5/15 were legal — that was wrong. RFC 5303 §3.1
> defines `Length` as "1 to 17 octets" and gives the Neighbour System ID and
> Neighbour Extended Local Circuit ID fields independent "if known" presence
> conditions, not a single combined one. Wireshark 4.6.4's IS-IS dissector
> (`packet-isis-hello.c`, `dissect_hello_ptp_adj_clv`) hardcodes exactly four
> cases — `1`, `5`, `11`, `15` — and decodes the 11-octet form as the Neighbour
> System ID present WITHOUT the Neighbour Extended Local Circuit ID. See
> `three_way.zig`'s file docs and `fsm.zig`'s `echoed` computation for the fix
> and how the FSM still treats that shape as an unconfirmed echo.

## 4. The state machine

Logical states: `down`, `initializing`, `up`. Events: `start(now)`, `stop()`,
`rxHello(rx, now)` / `rxHelloBytes(bytes, now)`, `tick(now)`.

### 4.1 State × event → next-state + effect

| State | `rxHello` accepted, **not** echoed-by-neighbour | `rxHello` accepted, echoed **and** neighbour past-Down | `tick`, `now ≥ hold_deadline` | `stop()` |
|-------|---|---|---|---|
| `down` | → `initializing` (transition) | → `up` (`adjacency_up`) | — (no hold set) | → `down` |
| `initializing` | stay `initializing` | → `up` (`adjacency_up`) | → `down` | → `down` |
| `up` | → `initializing` (`adjacency_down = neighbor_restarted`) | stay `up` | → `down` (`adjacency_down = hold_expired`) | → `down` (`adjacency_down = stopped`) |

- **echoed** ≡ the neighbour's TLV 240 carries a neighbour block whose
  (system-id, extended-local-circuit-id) equals **ours**. This is the loop guard.
  A neighbour block with the system-id but no extended-local-circuit-id (the
  11-octet wire shape, §3) is *not* echoed: a bare system-id cannot
  disambiguate which of possibly several parallel P2P circuits to that
  neighbour the reference is about.
- **neighbour past-Down** ≡ the neighbour's advertised 240 state is not `down`
  (a router that echoes us but claims Down is mid-reset; we hold at
  `initializing` rather than race it to Up). When the neighbour sent no 240,
  past-Down is treated as true but *echoed* is false, so the ceiling is
  `initializing`.
- Any accepted IIH first **refreshes the hold timer** to `now + holding_time` and
  records the neighbour's system-id (from source-id) and extended-local-circuit-id
  (from its 240, if any). The hold deadline is *derived state*, never a timer
  object.
- `start(now)` resets to `down`, primes `next_hello_due = now`, and returns the
  first IIH immediately (so the handshake does not wait a full interval).
- `tick` also emits a `send_hello` whenever `now ≥ next_hello_due`, rescheduling
  by `hello_interval`. Hold-expiry and a due hello can occur in the same `tick`.

### 4.2 Outgoing TLV 240

We advertise `state.wireState()` + our `extended_local_circuit_id`, and — iff we
have heard the neighbour's extended-local-circuit-id — a neighbour block echoing
its (system-id, ext-id). A neighbour that sent no 240 therefore never sees us
claim a completed handshake, which is what keeps *both* sides honest.

## 5. Mismatch / reject rules

Implemented (cheap, and they gate adjacency formation):

- **Loopback / self** — source system-id == ours → `rejected = .looped_back`,
  no state change. Forming here would be a self-adjacency.
- **Level mismatch** — `circuit_type` low bits are a level bitmask (bit0 L1,
  bit1 L2); `(rx & ours) == 0` → `rejected = .level_mismatch`. Catches an
  L1-only vs L2-only P2P pairing.
- **Not started** — `rxHello` before `start` → `rejected = .not_started`.
- **Third neighbour** — a P2P circuit carries exactly one adjacency (ISO/IEC
  10589 §8.2.4). Once `neighbor_system_id` is populated, an IIH from a *different*
  source system-id → `rejected = .other_neighbor`, checked **before** any
  mutation. An IIH is unauthenticated unless TLV 10 is configured, so without
  this check any station on the wire could refresh our hold timer with its own
  `holding_time`, overwrite the recorded neighbour, and — being unable to echo
  our system-id in TLV 240 — flap the adjacency Up→Initializing on every frame,
  while the inflated hold kept the FSM from ever reaching a clean Down. The
  circuit is released only when the incumbent's hold genuinely expires (`tick`
  → Down clears the neighbour), so a real neighbour change converges in one hold.

Malformed input is a typed **error** (not a soft reject) from `rxHelloBytes`:
a bad common header / P2P body surfaces `isis`'s `pdu.DecodeError`
(`BadDiscriminator`, `TruncatedBody`, `BadPduLength`, `WrongPduType`, …); a bad
TLV walk surfaces `tlv.Error`; a bad 240 surfaces `BadLength`/`BadState`. In
every error case the FSM mutates nothing (the decode happens before any state
change) — a hostile PDU cannot corrupt the machine. The fuzz test pins this
"errored ⇒ state unchanged" invariant.

## 6. Deferred (with hooks)

- **LAN adjacency + DIS election** — this module is P2P-only; the LAN Hello
  (types 15/16) three-way/priority/DIS logic is a separate FSM. `isis` already
  decodes the LAN Hello body, so it is additive.
- **Area-address matching** — an L1 P2P adjacency should reject a neighbour whose
  Area Addresses (#1) TLV shares no area with ours. Left as a documented hook: it
  needs the neighbour's #1 TLV compared against local config, which this
  increment does not carry. L2 adjacencies form across areas regardless.
- **Authentication** — TLV #10 / RFC 5304 / 5310 HMAC validation of the IIH.
- **Graceful restart** (RFC 5306) and **adjacency-SID** (segment routing).
- **MTU / padding negotiation** beyond the basics, and full ISO 10589 §8.2
  timer/counter accounting (adjacencyStateChange counters, etc.).

## 7. Verification

**CORRECTION (this task's finding):** this section previously claimed "no
external oracle needed... the wire format is validated end-to-end against the
sibling `isis` codec, which is itself golden-tested." That does not hold: a
sibling's anchor does not transfer — `isis` being golden-tested says nothing
about whether *this* module's adjacency-specific content (the TLV 240 codec,
the states it advertises) is correct, since `isis` treats 240 as an opaque raw
TLV and never looks inside it. The content that is specific to this module —
TLV 240's field layout and the three-way state byte values — needed its own
outside oracle, and (see below) finding one turned up a real bug (§3's
11-octet shape).

Per CONVENTIONS §7 this is pure logic → unit + property/round-trip **plus**,
for the TLV 240 wire format specifically, Wireshark 4.6.4 (sharkd, headless,
via `scripts/dissect.py`) as an external anchor: PDUs produced by this
module's own `start()`/`rxHelloBytes()`/`helloFields()`/`buildHello` were fed
through Wireshark's real IS-IS dissector and the frozen bytes + Wireshark's
printed output are pinned in `root.zig`'s golden tests and `three_way.zig`'s
11-octet golden. This covers the state byte (Up/Initializing/Down) and the
5-/11-/15-octet TLV 240 shapes, all three exercised through this module's own
code paths, not hand-derived. NOT externally covered: the 1-octet (state-only)
form, since `helloFields()` never emits it (this module always advertises at
least its own extended-local-circuit-id) — its behavior rests on Wireshark's
own `case 1` in `packet-isis-hello.c`, read but not independently re-run here.
The P2P Hello *header* framing (length-indicator, PDU length, circuit-type
bits, holding-time, local-circuit-id) is the sibling `isis` codec's own
already-anchored surface (see `modules/isis/ANCHOR-TASKS.tsv` row) — that part
legitimately IS the sibling's job, since this module calls `isis`'s real
builder/decoder rather than re-implementing it, so no separate anchor is owed
for it here.

- **Mutual drive** (the core proof): two `Adjacency` instances fed only each
  other's `isis`-serialized IIH bytes converge to Up on both, asserting the exact
  transition sequence Down → Init → Up and the completed on-wire 240 echo.
- **Hold-timer boundary**: bring Up, `tick` just before the deadline stays Up, a
  refreshing hello moves the deadline, a `tick` at the deadline drops to Down with
  `hold_expired`.
- **Three-way guard**: a neighbour whose 240 omits the neighbour block, or gives
  only a bare system-id with no extended-local-circuit-id (the 11-octet shape),
  holds us at Initializing; only a full echo (system-id + extended-circuit-id,
  and neighbour past-Down) reaches Up.
- **Loopback + level-mismatch + not-started** rejects; **round-trip** of the
  1/5/11/15-octet 240 forms; **malformed** bytes and a bad-length 240 as typed
  errors with state unchanged.
- **Determinism**: identical `(event, now)` streams yield identical transitions.
- **Positive control** (permanent): the FSM run with the three-way guard dropped
  (`three_way_required = false`) wrongly reaches Up on the half-open hello — so if
  the guard in `rxHello` were removed, the three-way-guard test would go RED.
- **Fuzz**: `std.testing.fuzz` over `rxHelloBytes` — hostile bytes never panic,
  the walk terminates, an errored decode is inert.

Green in Debug + ReleaseFast; `zig fmt --check` clean; `zig build check-catalog`
green; the sibling `isis` test suite unaffected.

Provenance: clean-room from ISO/IEC 10589 §8.2 and RFC 5303; no third-party
implementation ported or studied. See `/NOTICE` (no entry required — public
specs).
