# isis-adj

A pure-Zig **IS-IS point-to-point adjacency state machine** — the
Down → Initializing → Up lifecycle of ONE P2P neighbour, driven by the
**RFC 5303 three-way handshake** over the P2P IIH PDUs the sibling `isis` codec
decodes. It is a *time-injected FSM*: no threads, no owned timers, no sockets,
no allocation on the steady path. The caller supplies a monotonic `now`, feeds
it received IIHs, and acts on the `Effect` it returns — send an IIH, raise the
adjacency, tear it down.

Status: **gap** — first increment. Implements the P2P three-way FSM + the
hold/hello timing + TLV 240 (the RFC 5303 Three-Way Adjacency TLV, which `isis`
does not model typed). LAN adjacency + DIS election, authentication,
graceful-restart, and area-address matching are deliberately deferred — see
`SPEC.md`.

Model after: **ISO/IEC 10589 §8.2** (the P2P adjacency lifecycle) and
**RFC 5303** (Three-Way Handshake for IS-IS Point-to-Point Adjacencies).

## What's in it

| Layer | Covers |
|-------|--------|
| `three_way` | The RFC 5303 Point-to-Point Three-Way Adjacency TLV (type 240) value codec: `ThreeWayState` (the `up=0`/`init=1`/`down=2` wire byte), `ThreeWayTlv` (state + extended-local-circuit-id + optional neighbour block), bounds-checked `decode`/`encode` of the 1/5/11/15-octet forms (Wireshark-anchored — the 11-octet shape, neighbour system-id without its extended-circuit-id, was a gap in an earlier revision of this codec; see `three_way.zig`). `isis` exposes 240 only as a raw TLV, so this file parses/emits its value with the same discipline. |
| `fsm` | The `Adjacency` state machine: `start`/`stop`, `rxHello`/`rxHelloBytes`, `tick`, the derived hold timer + hello cadence, the acceptance rejects, and the `Effect` result. Plus `buildHello`, a convenience that serializes an outgoing IIH via the `isis` P2P builder + a raw TLV 240. |

## State table

Three logical states (ISO 10589 §8.2), each mapped to the RFC 5303 wire byte we
advertise in our own TLV 240:

| State | Meaning | Wire byte (TLV 240) |
|-------|---------|---------------------|
| `down` | No neighbour heard (or hold expired / stopped). | `2` |
| `initializing` | Neighbour heard, but it has **not** confirmed hearing us (its 240 does not echo our id, or it is itself Down). | `1` |
| `up` | Neighbour heard **and** its 240 echoes our (system-id, extended-local-circuit-id) and it is past Down — the handshake is complete. | `0` |

Note the wire encoding is **not** in intuitive order: RFC 5303 numbers `Up = 0`,
`Initializing = 1`, `Down = 2`. `ThreeWayState` pins those exact values.

## The three-way handshake (why it exists)

A "I heard a hello, we're Up" rule half-opens on a unidirectional link: A can
hear B while B cannot hear A. RFC 5303 fixes this by having each router carry, in
its IIH's TLV 240, both its own three-way state *and* a reference to the
neighbour it has heard. We reach **Up** only when the neighbour's 240 names *us*
(the loop guard) and the neighbour is past Down; a heard-but-unconfirmed
neighbour holds us at **Initializing**. Two FSMs driven against each other
therefore climb Down → Init → Up in lockstep — the module's core test.

## Time-injection contract

The FSM never reads a clock (the repo removed `std.time` timestamps). Every entry
point that cares about time takes a caller-supplied `now: Time` — abstract ticks
in the caller's own unit. `holding_time` and `hello_interval` are in that **same
unit** (a caller running in seconds sets `holding_time = 30`; one in
milliseconds sets `30_000`). The hold deadline is *derived*: refreshed to
`now + neighbour.holding_time` on every accepted IIH and compared in `tick` — the
FSM owns no timer object. Given the same `(event, now)` stream it is fully
deterministic (a permanent test pins this).

Defaults follow the ISO 10589 relationship **hold = multiplier × hello** with
multiplier 3: `hello_interval = 10`, advertised `holding_time = 30`.

## Effects API

`start`, `stop`, `tick`, and `rxHello`/`rxHelloBytes` each return an `Effect`
whose independent fields tell the caller what to do:

- `transition` — the `{from, to}` state change, if any.
- `adjacency_up` — entered Up this call; the upper layer may start using the link.
- `adjacency_down` — left Up this call, with a `DownReason` (`hold_expired`,
  `stopped` — also `start` over an Up adjacency —, `neighbor_restarted`,
  `circuit_id_changed`).
- `send_hello` — emit a P2P IIH built from the enclosed `HelloFields` now (the
  FSM returns *fields*, not bytes, so it never owns a buffer — hand them to
  `buildHello`, or build the PDU yourself). Besides `start` and `tick`'s
  cadence, `rxHello` returns one whenever it changes state
  (`Config.triggered_hello`, default on), so the handshake converges on events.
- `rejected` — a received IIH was ignored, with a `RejectReason` (see below); no
  state change.

## Acceptance / reject rules

A received IIH is ignored — `Effect.rejected`, no state change — for:
**loopback** (source system-id equals ours, `.looped_back`); **level mismatch**
(disjoint circuit-type level masks, `.level_mismatch`); **not started**
(`.not_started`); **Maximum Area Addresses mismatch** (`.max_area_mismatch`);
**area mismatch** on a pure L1 circuit with `local_areas` configured
(`.area_mismatch`, fail closed on a missing or malformed TLV); **another system
while the adjacency is Up** (`.other_neighbor` — at Initializing a candidate is
simply replaced); a **TLV 240 neighbour block naming someone else** or our
system on another circuit (`.neighbor_mismatch`, RFC 5303 §3.2 discard); and a
**neighbour claiming Up while we are Down** (`.neighbor_up_while_down`, the RFC
5303 table's "Neighbor restarted" cell); and a **`holding_time` below
`Config.min_neighbor_holding_time`** (`.holding_time_too_short`, default refuses
only 0). An accepted IIH from the recorded neighbour with a **different Local
Circuit ID** deletes the adjacency (`Config.detect_circuit_id_change`, default
on). A peer whose TLV 240 never carries neighbour fields stays Initializing
unless `Config.accept_without_neighbor_fields` opts into RFC 5303 §3.2 b).
Malformed bytes, a malformed TLV 240,
or any malformed TLV anywhere in the stream are typed *errors* from
`rxHelloBytes` that leave the FSM state untouched. Details and the reasoning
behind each rule: `SPEC.md` §5.

## API sketch

```zig
const adj = @import("isis-adj");

var a = adj.Adjacency.init(.{
    .system_id = .{ 0, 0, 0, 0, 0, 0xA },
    .extended_local_circuit_id = 0xA1,
    .hello_interval = 10, // same unit as `now`
});

var buf: [128]u8 = undefined;
const first = a.start(0);                        // primes an immediate IIH
if (first.send_hello) |hf| sendOnWire(try adj.buildHello(&buf, hf));

// on a received P2P IIH (raw link bytes):
const e = try a.rxHelloBytes(rx_bytes, now);
if (e.adjacency_up) upperLayer.linkUp();
if (e.adjacency_down) |why| upperLayer.linkDown(why);

// periodically:
const t = a.tick(now);                           // expires hold, emits due IIH
if (t.send_hello) |hf| sendOnWire(try adj.buildHello(&buf, hf));
```

## Test

```
zig build test-isis-adj
```

The core proof is the **mutual-drive** test: two FSMs fed only each other's
serialized IIH bytes (full `isis` encode → `rxHelloBytes` decode) converge to Up
on both with the exact sequence Down → Init → Up. Plus: the hold-timer boundary
(a hello just before the deadline keeps it Up; a tick at the deadline drops it to
Down with `hold_expired`), the three-way guard (a neighbour not echoing us stays
Initializing), loopback + level-mismatch rejects, a `std.testing.fuzz` target
over `rxHelloBytes` (hostile bytes never panic; a rejected PDU is inert), a
determinism test, and a permanent **positive control** (dropping the three-way
guard wrongly reaches Up on the half-open hello — proving the guard has teeth).
Green in Debug and ReleaseFast; `zig fmt` clean.

Provenance: clean-room from the public specifications above; no third-party
IS-IS implementation (frrouting, IOS, Junos) was ported or studied. See
`/NOTICE` (no entry required — public specs). License: MIT.
