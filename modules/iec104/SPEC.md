# iec104 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Five allocation-free layers, mirroring the standard's own decomposition. Every wire struct uses
explicit shifts in `toByte`/`fromByte` rather than a `packed struct`, so the octet layout never
depends on Zig's bitfield-packing rules.

- **`apci` (§5.1–§5.3).** The length octet counts everything *after itself* (four control octets +
  ASDU) and is capped at 253, so an APDU is at most 255 octets and an ASDU at most 249. Both
  boundaries are enforced on encode and decode and tested at exactly 253/254. Format selection is by
  the low bits of the first control octet: bit 0 clear = I, `0b01` = S, `0b11` = U. Reserved octets
  are *checked*, not ignored — an S-format with a dirty second control octet, a U-format with a
  body, an I-format with the N(R) marker bit set, or a U-format with zero or two function bits, all
  return typed errors rather than being silently accepted.
  `Framer` splits the TCP byte stream: it compacts on `feed`, peeks the length octet before
  committing, and returns `null` until a whole APDU is present.
- **`state` (§5.4–§5.6, §9.6).** The seam that matters: **no clock, no thread, no socket**. The
  caller passes `now_ms` into every entry point and performs the I/O `tick` returns. `tick` is
  deliberately *mutating* — it returns the one action the caller must now perform and has already
  accounted for it — which makes it impossible to get an acknowledgement counted twice, at the cost
  of requiring the caller to actually perform the write. On a write failure the connection is dead
  anyway, which is the documented contract.
  Priority inside `tick`: fatal timeouts (t0, t1-on-I, t1-on-U) → owed U-format confirmations →
  acknowledgement (w reached or t2 expired) → idle test frame (t3). `nextDeadline` reports the
  earliest armed timer so an event loop can sleep.
  t1 is tracked as **two** deadlines, one for the oldest unacknowledged I-frame and one for an
  outstanding U-format *act*, because they expire for different reasons and a single deadline would
  conflate a dead peer with a slow acknowledgement.
- **Sequence numbers are `u15`.** This is the single most important type decision in the module:
  `+%` on a `u15` *is* the modulo-32768 arithmetic §5.5 prescribes, and every comparison goes
  through `seqDistance` (wrapping subtraction) rather than `<`. An implementation that widens them
  to `u16`, or compares them ordinally, wedges permanently the first time N(S) rolls over — which is
  after 32767 frames, i.e. days into a deployment, not in a test. `state.zig` drives a full
  32768-frame cycle plus 100 more through both a master and an outstation to prove it does not.
- **`info` (IEC 60870-5-101 §7.2.6).** `CP56Time2a`'s first two octets are a *single* little-endian
  16-bit field holding `second * 1000 + millisecond`; they are not separate second and millisecond
  octets. `validate` runs on both encode and decode, so an impossible time on the wire is a typed
  error rather than a struct a caller might act on. IV (invalid), SU (summer time) and GEN
  (substituted) are orthogonal flags and survive a round trip. The OV bit is reserved in SIQ/DIQ and
  is masked out on encode so a caller that reused a QDS cannot smuggle it onto the wire.
- **`asdu` (§7.2).** Decoding validates up front that the body length is *exactly* what `count`
  objects of this type's element size need, in the layout the SQ bit selects — so
  `ObjectIterator.next` can never run off the end and needs no bounds checks. Element layout is
  factored as (base element, time tag): `M_SP_NA_1`, `M_SP_TA_1` and `M_SP_TB_1` share one `siq`
  base and differ only in the appended tag, which is what keeps the type table small and made the
  30-odd type ids tractable. `TypeId` and `Cot` are non-exhaustive enums — an unknown wire byte
  decodes, it just has no name, and the codec then refuses it with `error.UnsupportedTypeId` rather
  than guessing a size.
  `Builder` patches the VSQ octet on every `add`, so the header is always consistent with what has
  actually been written. With `SQ = 1` it writes the address once and *rejects* a non-consecutive
  address rather than emitting a silently wrong frame.
- **Address sizing.** `Params{ ioa_size, ca_size, cot_size }` is threaded through every entry point.
  An address that does not fit the configured width, or an originator address with a 1-octet cause
  of transmission, is a typed error. The 3/2/with-originator default is what IEC 60870-5-104 fixes
  for the TCP/IP profile; 1- and 2-octet profiles are tested end to end (frames byte-compared).
- **`outstation`.** `Outstation` is a pure ASDU-level responder (one request in, N replies out
  through a `Sink`). `Server` wraps it with the framing, the state machine and a **reply queue**,
  because one general interrogation produces far more ASDUs than `k` allows — the queue drains as
  the master acknowledges. Without that queue a 60-point interrogation against `k = 3` would fail
  with `SendWindowFull`; with it, the round-trip test asserts exactly 62 ASDUs arrive.

Concurrency: `.single_owner` — one `Client`/`Server` owns one connection's framer, counters and
buffers; nothing is shared or global, and the clock and any threading are the caller's.

Error policy: every decode entry point (`apci.decode`, `Framer.next`, `asdu.decodeHeader`,
`asdu.decode`, `ObjectIterator.next`, every `info` element, `state.Connection.onFrame`,
`Outstation.handle`) returns a typed error on malformed input. Nothing panics, allocates or loops
unboundedly.

## Verification

### What is third-party-validated

The strongest evidence here is not a hand-written vector — it is **real traffic between two
independent implementations that are not this module**, plus **live round trips in both
directions**.

**Oracle used:** Python `c104` 2.2.1 (Martin Unkel, Fraunhofer FIT; GPL-3.0) — a binding over the
`lib60870-C` protocol stack, providing both a controlling and a controlled station plus
`explain_bytes`, its own decoder. It was installed in a throwaway virtualenv and used **as a black
box only**: to generate wire traffic, to decode ours, and to act as a live peer. Its source was not
read, and no design decision here was taken from it. Under CONVENTIONS §5 that is a test oracle,
not a design reference, so it needs no `/NOTICE` entry — the same status as diffing against `tar`
or `nft`.

1. **72 byte-exact captured goldens** (`goldens.zig`). A `c104` controlling station was pointed at a
   `c104` controlled station through a recording TCP proxy, and every APDU that crossed the wire was
   logged as hex together with `explain_bytes`'s interpretation. Additional frames (`TESTFR`, the
   negative confirmation, and the unknown-type/unknown-CA/unknown-IOA/unknown-COT causes) were
   produced by driving the same third-party server from a raw socket. Three assertions run over the
   whole table:
   - every frame decodes (APCI, and for I-format also the ASDU under the 3/2/originator profile);
   - every frame **re-encodes to the identical octets** — and the ASDU is rebuilt from the *decoded
     objects* through `asdu.Builder`, so the builder is what is being checked, not a memcpy;
   - a representative subset is asserted field by field against what `c104` said each frame meant
     (values, causes, sequence numbers, quality, time tags, the S/E bit).

   Coverage of the capture: all six U-format functions; S-format at three different N(R); I-format
   sequence numbers; `M_SP_NA_1`, `M_DP_NA_1`, `M_ST_NA_1`, `M_BO_NA_1`, `M_ME_NA_1`, `M_ME_NB_1`,
   `M_ME_NC_1`, `M_IT_NA_1`, `M_SP_TB_1`, `M_DP_TB_1`, `M_ME_TD_1`, `M_ME_TE_1`, `M_ME_TF_1`,
   `M_IT_TB_1`; `C_SC_NA_1`, `C_DC_NA_1`, `C_RC_NA_1`, `C_SE_NA_1`, `C_SE_NB_1`, `C_SE_NC_1`,
   `C_SC_TA_1`, `C_SE_TC_1`; `C_IC_NA_1`, `C_CI_NA_1`, `C_RD_NA_1`, `C_CS_NA_1`, `C_TS_TA_1`; a
   select/execute pair for both `C_SC_NA_1` and `C_SE_NA_1`; an `SQ = 1` frame with **twelve**
   objects behind one address; and the four error causes. A test asserts the capture really does
   contain every one of those type ids, so the table cannot silently rot.

2. **The outstation's replies are byte-compared against the recorded RTU's replies.** Feeding
   `Outstation.handle` the master's captured request frames reproduces the third-party RTU's answers
   octet for octet for: the general-interrogation confirmation and termination, the
   counter-interrogation confirmation/counter/termination, the read-command confirmation and value,
   the clock-synchronisation confirmation, the `C_TS_TA_1` confirmation, the select and execute
   confirmations of a select-before-operate sequence, and all three error-cause replies.

3. **Live round trip, our client → a third-party outstation** (`client.zig`, gated on
   `IEC104_TEST_SERVER`). Against a live `c104`/lib60870 server on `127.0.0.1:2404`, CA 47, the run
   observed: `STARTDT act` confirmed; general interrogation confirmed, **5 monitoring ASDUs**
   received and decoded, activation termination received; select-before-operate on IOA 301 — select
   positively confirmed, execute positively confirmed; `STOPDT act` confirmed. Printed output:
   `live IEC 104: started=true act_con=true act_term=true monitoring_asdus=5` /
   `select_con=true sent_execute=true execute_con=true` / `STOPDT confirmed`.

4. **Live round trip, a third-party master → our outstation** (`root.zig`, gated on
   `IEC104_TEST_LISTEN`). A live `c104`/lib60870 *client* drove `OutstationServer`: it completed
   `STARTDT`, ran a general interrogation and **read our point values back correctly**
   (`101 -> True`, `102 -> Double.ON`, `105 -> 3.141590118408203`), ran a counter interrogation, and
   completed a select-before-operate command (`select+execute C_SC_NA_1: True`). Our side printed
   `startdt=true interrogation=true commands=2 sco_on=true` — two activations, the second of which
   actually operated the output.

Both live tests passed in Debug and in `--release=fast`, and both print `SKIPPED: …` and pass when
no peer is present.

### What is self-derived

- Everything not in the capture: the CP24Time2a/CP16Time2a encodings, `M_ME_ND_1`, `M_PS_NA_1`,
  `C_BO_NA_1`/`C_BO_TA_1`, `C_TS_NA_1`, `C_RP_NA_1`, `C_CD_NA_1`, `M_EI_NA_1`, the group
  interrogation causes, and the 1-/2-octet address profiles. These are encode/decode round-trip
  tests against element sizes and bit positions taken from the standard's documented layouts, not
  against third-party bytes.
- The **k/w and t0..t3 behaviour** is validated against the standard's description with an injected
  clock, not against a third-party stack's timing. The live runs exercise `STARTDT`/`STOPDT`,
  `TESTFR` and the acknowledgement cadence in passing, but no test drives a real peer to a t1
  timeout.
- The 32768-frame wrap cycle is a self-consistency test between two instances of this module. No
  third-party stack was driven through a real sequence-number rollover (that needs 32768 frames on
  one connection, which the live harness does not do).
- `tshark` is **not** installed in this environment, so the `104apci`/`104asdu` dissector
  cross-check named in the task was not run. It was not needed: `c104.explain_bytes` (a lib60870
  decoder) served the same purpose, and the goldens came from a real capture rather than being
  hand-derived.

### Fuzz + hostile input

`std.testing.fuzz` sweeps, all asserting "typed error or valid result, never a panic and never a
hang":

- `apci.decode` over arbitrary bytes — anything that decodes must re-encode to the identical octets.
- `apci.Framer` fed arbitrary stream bytes in chunks, with a guard counter that fails the test if
  `next` ever returns a frame without consuming input (an infinite-loop bug).
- `asdu.decode` + full object iteration over arbitrary bytes **and arbitrary `Params`** (ioa 1–3,
  ca 1–2, cot 1–2).
- `CP56Time2a.decode` — anything that decodes must re-encode and re-decode identically.
- `Outstation.handle` over arbitrary ASDU bytes against a real point database.

Explicit hostile-input tests (not fuzz) cover: an empty and a one-octet APDU; a wrong start byte; a
length octet below 4 and above 253; a truncated body; every reserved-bit violation; an object count
that disagrees with the body in both directions; a zero object count; an out-of-range type id; a
`CP56Time2a` with minute 60, hour 24, day 0, day 32, month 0, month 13, year 100 and a 60000 ms
field; an N(S) that is not the next expected; an N(R) beyond the send window (both just past the
edge and on the far side of the wrap); and an I-frame while data transfer is stopped.

## Threat model

IEC 60870-5-104 is an **unauthenticated, unencrypted** protocol by design: anyone with a path to TCP
port 2404 can issue `C_SC_NA_1` to a breaker. This module's job is therefore robustness and
containment, not confidentiality or integrity against an active attacker:

- Hostile or corrupt bytes from a misbehaving RTU, a hostile master or a MITM resolve to typed
  errors at every decode entry point.
- No allocation anywhere, and every buffer is caller-supplied and bounded, so a hostile peer cannot
  drive memory growth. The APDU ceiling (255 octets) and the object-count ceiling (127) are hard.
- The state machine refuses out-of-sequence and out-of-window frames rather than resynchronising,
  which is what §5.5 requires: an implementation that "recovers" from a bad N(S) is a resequencing
  oracle.
- **Deployments must put transport security under this**, i.e. IEC 62351-3 (TLS on 2404) or a VPN.
  This module does not implement it — see below — and callers should terminate TLS outside and hand
  the `Transport` seam an already-terminated stream, exactly as the repo's BYO-TLS rule (CONVENTIONS
  §2) prescribes.
- Select-before-operate is enforced at the outstation: an execute without a prior positive select is
  refused, and a select is consumed by its execute so a second execute needs a fresh select. This is
  an operational-safety mechanism, **not** a security control — an attacker who can send one
  activation can send two.

## Deferred

Honest list of what a full IEC 60870-5-104 implementation has and this one does not:

- **File transfer** (type ids 120–127, `F_FR_NA_1`/`F_SR_NA_1`/`F_SC_NA_1`/`F_LS_NA_1`/`F_AF_NA_1`/
  `F_SG_NA_1`/`F_DR_TA_1`/`F_SC_NB_1`): not modelled at all. Their elements are variable-length, so
  the fixed (base, tag) shape table cannot express them; they decode as `error.UnsupportedTypeId`.
- **Parameter loading** (110–113, `P_ME_NA_1`/`P_ME_NB_1`/`P_ME_NC_1`/`P_AC_NA_1`): recognised with
  the right element width, but the QPM/QPA qualifier semantics are passed through as raw octets
  rather than typed, and the outstation has no parameter store.
- **IEC 62351-3/-5 security**: no TLS on 2404, no certificate handling, no role-based access
  control. Bring your own terminated stream (see Threat model).
- **Redundancy groups** (§5.2 / the redundancy annex): multiple connections to one controlled
  station with exactly one in the `started` state and the rest standing by. Each `Client`/`Server`
  is one connection; the group-level arbitration is not implemented.
- **Protection-equipment event types** (17–19, 38–40, `M_EP_TA_1` … `M_EP_TF_1`): element widths are
  in the shape table but there are no typed accessors for the SEP/SPE/QDP sub-fields.
- **The controlled-station side of `C_CD_NA_1`** (delay acquisition) beyond echoing it, and the
  background-scan cause (2) as an automatic outstation behaviour.
- **Timer policy is the caller's.** The module tells the caller *when* something is due
  (`nextDeadline`) and *what* to do (`tick`), but it does not sleep, and the `TcpTransport` demo
  adapter blocks on `poll(2)` with a caller-set timeout. A production deployment wires the seam into
  its own event loop.
- **lib60870's activation-termination quirk** was deliberately not replicated: after a
  select-before-operate execute, the observed third-party RTU echoed the *select* element (S/E set)
  in its `ACTIVATION TERMINATION`; this outstation echoes the execute element, which is what the
  standard describes. Likewise, that RTU silently dropped an ASDU with an unknown type id where this
  one replies with cause 44 as §7.2.3 prescribes.
- **`tshark` cross-check** — not run (no `tshark` in this environment); see "What is self-derived".

## Investigated: the "paired Stream.Reader/Writer stops writes" report

A prior agent (see `modules/bacnet/src/sc_interop.zig`) reported that creating a
`std.Io.net.Stream.Reader` on a socket stops subsequent writes through the
**paired** `std.Io.net.Stream.Writer` from reaching the wire under
`std.Io.Threaded`: `writeAll`/`flush` report success but nothing arrives. All
three of `iec104`, `iec61850` and `fleetsim` pair a reader and a writer on one
stream, so the report put them under suspicion.

**Finding: not a std bug, and not present in these modules.** Reproduced on
0.16.0 (x86_64-linux) with four probes over a loopback socket pair under
`Threaded` — single write→read→write, five such cycles, a reader that over-reads
a coalesced second message before the next write, and a full-duplex exchange
with **both** peers buffered — every write reached the peer. The mechanism the
report proposed cannot hold: `Stream.Reader` and `Stream.Writer` each store
their own copy of the two-word `Stream` (just a socket handle) and their own
buffer, so they do not alias; and in `std.Io.Threaded` `netRead`/`netWrite` are
a plain `readv(2)` / `sendmsg(2)` on the shared fd with no change to its flags.
The bacpypes/websocket workaround (`std.posix.read` in place of a
`Stream.Reader`) is therefore unnecessary for write delivery, though it is
harmless where a hand-rolled frame parser wants the raw descriptor.

**The real, adjacent hazard — which these modules already guard against.** A
buffered `Stream.Reader` can hold a whole APDU that a later `poll(2)` on the raw
fd will never report as readable, because the bytes are in the reader's buffer,
not in the socket. A read that always polls before reading would then **stall**
on coalesced frames. `TcpTransport.readFn` avoids this with the
`r.bufferedLen() == 0` check before `waitReadable()`; `fleetsim` does the same in
its serve loops. The regression test
`"TcpTransport delivers write->read->write over a real socket (no env gate)"`
in `src/transport.zig` (and the sibling tests in `iec61850` and `fleetsim`)
pins both properties with no env gate and no external peer: removing the
`bufferedLen()` guard makes the coalesced second read stall and the test fail.
This is worth reporting upstream only as documentation — there is no std defect
to file.

## Status

`gap · any (pure codec + state machine; only the optional TcpTransport touches std.Io.net) ·
both (controlling + controlled station) · single_owner` + deps: none (std only) — canonical source
is `pub const meta` in src/root.zig.
