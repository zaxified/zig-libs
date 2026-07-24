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
`isis`: fixed-offset reads guarded by an up-front length check against the three
legal sizes, no over-read, no allocation.

## 3. TLV 240 wire format (RFC 5303 §3)

Value layout (for the modeled 6-octet system id):

| Field | Octets | Present when |
|-------|--------|--------------|
| Adjacency Three-Way State | 1 | always |
| Extended Local Circuit ID | 4 | value length ≥ 5 |
| Neighbour System ID | 6 | value length == 15 |
| Neighbour Extended Local Circuit ID | 4 | value length == 15 |

So the only well-formed value lengths are **1, 5, 15**; anything else is
`error.BadLength`. The neighbour block is all-or-nothing. The state byte encoding
is **Up = 0, Initializing = 1, Down = 2** (RFC 5303) — the reverse of intuitive
order; an unassigned byte is `error.BadState`. `ThreeWayState.fromByte` refuses
an illegal `@enumFromInt`.

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

Per CONVENTIONS §7 this is **pure logic** → unit + property/round-trip, no
external oracle needed (the wire format is validated end-to-end against the
sibling `isis` codec, which is itself golden-tested).

- **Mutual drive** (the core proof): two `Adjacency` instances fed only each
  other's `isis`-serialized IIH bytes converge to Up on both, asserting the exact
  transition sequence Down → Init → Up and the completed on-wire 240 echo.
- **Hold-timer boundary**: bring Up, `tick` just before the deadline stays Up, a
  refreshing hello moves the deadline, a `tick` at the deadline drops to Down with
  `hold_expired`.
- **Three-way guard**: a neighbour whose 240 omits the neighbour block holds us at
  Initializing; only an echo (and neighbour past-Down) reaches Up.
- **Loopback + level-mismatch + not-started** rejects; **round-trip** of the
  1/5/15-octet 240 forms; **malformed** bytes and a bad-length 240 as typed errors
  with state unchanged.
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
