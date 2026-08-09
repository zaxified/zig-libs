#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drive a `fleetsim`-simulated IEC 60870-5-104 outstation with a REAL c104 master.

The IEC 104 sibling of `fleetsim-modbus-master.py`; that file's docstring
explains why these exist. c104 2.2.1 wraps **lib60870-C** — the reference
IEC 60870-5-104 implementation, developed by people who have never seen this
repository — in pybind11, so every octet on the wire and every decode of a
reply is theirs.

## The write-back channel IEC 104 offers

Commands in the control direction. The simulated outstation binds ten
`C_SE_NB_1` set-point command points at IOA 900..909 and one `C_SC_NA_1`
single command at IOA 910, and `iec104_verdict` in
`modules/fleetsim/src/root.zig` asserts on what the master commanded into
them, against constants recomputed from the fixture.

    900   0x65F8 (26104)   "a real master was here" magic
    901   graded checks
    902   failures
    903   observed bitmap of the PRE-fault snapshot, one bit per fixture point
    904   the M_ME_NC_1 short float, scaled by 10
    905   the M_ME_NB_1 scaled value MINUS mark 904
    906   a checksum over the whole general-interrogation set, mod 30011
    907   the cause the OUTSTATION named for a command to an unbound IOA
    908   the cause the OUTSTATION named for an interrogation of a foreign CA
    909   bitmap of the points reporting Invalid quality AFTER the fault
    910   1 iff no check failed — sent in a SEPARATE, unconditional command so
          it is last, and so "a master was here and is unhappy" stays
          distinguishable from "no master ran"

**A scaled integer, deliberately, and never an echo.** The measured value on
the wire is an IEEE-754 short float; commanding it back as a short float would
be the exact inverse of the read, so an outstation that encoded and decoded
floats with the same wrong convention would round-trip cleanly and the fault
would hide. Mark 904 leaves the float domain entirely. Mark 905 is a
*difference across two different type decodes* (SVA minus scaled R32) and
cannot be produced by handing either operand back. Mark 906 grades the whole
GI set — which points were reported, under which type ids — not one value.
Marks 907 and 908 are causes the outstation itself chose and c104 itself
named; a device that collapsed "no such IOA" and "not my common address" into
one answer would still satisfy any single-error test.

## Things about this pairing worth knowing before editing

* **`c104.Init.NONE` sends no STARTDT**, so the link stays muted, every
  I-frame is ignored and nothing is ever reported. `Init.INTERROGATION` is
  required. It is also what issues the automatic post-connect interrogation
  addressed to the **global common address 0xFFFF** (§7.2.5's broadcast) —
  the path that found a real conformance defect in `modules/iec104`, fixed in
  `4158b1d`: a station answering a global request must identify itself with
  its own common address.
* **c104 validates callback annotations** and raises `ValueError` on a bare
  `def f(a, b, c)`. Every callback below is fully annotated for that reason,
  not for style.
* **`point.value = 215` is refused for a `C_SE_NB_1` point** — it wants a
  `c104.Int16` (or a whole `c104.ScaledCmd`).
* **A refused command reaches no callback, and `transmit()` still returns
  True.** Measured: with the outstation sending `activation_con` with P/N set
  and then cause 47 on the wire, `Point.on_receive` was never invoked and
  `Connection.on_unexpected_message` stayed empty — a message naming a point
  or a station the client knows about is not "unexpected", and the client must
  know about both or c104 will not send the request at all. The two
  named-cause marks are therefore read back through `c104.explain_bytes_dict`,
  c104's own APDU analyser, from the octets it captured.
* **c104 reports a double point as `c104.Double`**, whose `.value` is the
  two-bit DPI code (§7.2.6.2) — `ON` is the integer 2, not the string "ON".
* **c104's `License` metadata field contains the entire GPLv3 text.** Printing
  it verbatim buries any real error in a wall of licence prose; the classifier
  is read instead.
* The outstation is single-connection by construction (one
  `iec104.OutstationServer`, one `state.Connection`), so this master opens
  exactly one connection and never lets c104's auto-reconnect race it. The
  connection state transitions are logged for that reason: a reconnect is a
  finding, not noise.

## Provenance

c104 is **GPL-3.0-or-later** and wraps lib60870-C. It runs here as a separate
process inside a disposable VM guest: nothing is linked against it, nothing
from it is copied, translated or redistributed, and what is frozen into
`modules/fleetsim/src/master_goldens.zig` is the byte output of a session
between two programs exchanging APDUs defined by a public IEC standard, plus
what the master reported it decoded. Recorded in `modules/fleetsim/NOTICE`.

Usage: fleetsim-iec104-master.py <host> <port> [wait-seconds]

Output: a transcript, then one JSON object per operation between
FLEETSIM_CAPTURE_BEGIN/END, then IEC104_MASTER_DONE, then IEC104_MASTER_OK
(exit 0) or IEC104_MASTER_FAIL (exit 1). `run.sh` gates on the _DONE marker —
presence only.
"""

import json
import sys
import threading
import time

# Imported at module scope, not inside `main`, because c104 validates callback
# ANNOTATIONS at registration and rejects string forward references outright:
#   ValueError: Invalid callback signature, expected:
#     (connection:c104.Connection,data:bytes)->None,
#     got: (connection:'c104.Connection',data:bytes)->None
# The real classes therefore have to be in scope where the callbacks are
# defined. Measured, not assumed — it is what the first live run failed on.
import c104

CAPTURE_BEGIN = "FLEETSIM_CAPTURE_BEGIN"
CAPTURE_END = "FLEETSIM_CAPTURE_END"

MAGIC = 26104

# The fixture, mirrored from `test "live: a real IEC 104 master drives a
# simulated outstation, and sees iv quality"`. Restated here only so the master
# can GRADE; the Zig side derives its expectations from the same numbers.
COMMON_ADDRESS = 47
FOREIGN_CA = 99

SP_ON = 101
SP_OFF = 102
DP_ON = 103
FLOAT_IOA = 201
SCALED_IOA = 202
COUNTER_IOA = 301

FLOAT_VALUE = 21.5
SCALED_VALUE = -12345
COUNTER_VALUE = 1234567
COUNTER_SEQUENCE = 5

UNBOUND_IOA = 999

VERDICT_BASE = 900
VERDICT_SLOTS = 10
VERDICT_PASS_IOA = 910

CHECKSUM_MOD = 30011  # prime, and small enough that the sum stays inside i16

# The fault lands at t=15 s of the 60 s live run. The master connects within a
# second of the device binding, so "25 s after connect" is comfortably past it
# and comfortably inside the run.
FAULT_SETTLE_S = 25.0


def main() -> int:
    host = sys.argv[1]
    port = int(sys.argv[2])
    wait_s = float(sys.argv[3]) if len(sys.argv) > 3 else 120.0

    # c104's `License` metadata field is the whole GPLv3 text. Read the
    # classifier instead — one line, and the actual answer.
    version = "?"
    licence = "?"
    try:
        import importlib.metadata as md

        version = md.version("c104")
        classifiers = md.metadata("c104").get_all("Classifier") or []
        for c in classifiers:
            if c.startswith("License ::"):
                licence = c.split("::")[-1].strip()
                break
    except Exception:  # noqa: BLE001
        pass
    print("client: c104 %s (licence: %s) -> %s:%d" % (version, licence, host, port), flush=True)

    lock = threading.Lock()
    wire: list[tuple[str, bytes]] = []
    states: list[str] = []
    # Every unexpected message the outstation sent, as c104 classified it:
    # (io_address, cause-name, cause-value, umc-name).
    unexpected: list[tuple[int, str, int, str]] = []
    # Anything c104 routes to one of OUR points, as c104 decoded it:
    # (io_address, cause-value, cause-name, negative). Kept as a WITNESS, not
    # as a data source: on a run where the outstation demonstrably answered a
    # command with cause 47 on the wire, this stayed empty and so did
    # `unexpected`. Both are left registered so a future c104 that does deliver
    # a refusal makes itself visible in the transcript instead of silently
    # changing which channel is authoritative.
    routed: list[tuple[int, int, str, bool]] = []

    def on_send_raw(connection: c104.Connection, data: bytes) -> None:
        with lock:
            wire.append(("tx", bytes(data)))

    def on_receive_raw(connection: c104.Connection, data: bytes) -> None:
        with lock:
            wire.append(("rx", bytes(data)))

    def on_state_change(connection: c104.Connection, state: c104.ConnectionState) -> None:
        with lock:
            states.append(state.name)
        print("client: connection state -> %s" % state.name, flush=True)

    def on_point_receive(
        point: c104.Point,
        previous_info: c104.Information,
        message: c104.IncomingMessage,
    ) -> c104.ResponseState:
        with lock:
            routed.append(
                (message.io_address, message.cot.value, message.cot.name, message.is_negative)
            )
        print(
            "client: routed ioa=%d cot=%s(%d) negative=%s"
            % (message.io_address, message.cot.name, message.cot.value, message.is_negative),
            flush=True,
        )
        return c104.ResponseState.SUCCESS

    def on_unexpected_message(
        connection: c104.Connection,
        message: c104.IncomingMessage,
        cause: c104.Umc,
    ) -> None:
        with lock:
            unexpected.append(
                (message.io_address, message.cot.name, message.cot.value, cause.name)
            )
        print(
            "client: unexpected message ioa=%d cot=%s(%d) umc=%s"
            % (message.io_address, message.cot.name, message.cot.value, cause.name),
            flush=True,
        )

    client = c104.Client(tick_rate_ms=100, command_timeout_ms=5000)
    # Exactly one connection, and `Init.INTERROGATION` because `Init.NONE`
    # never sends STARTDT and the link would stay muted forever.
    connection = client.add_connection(ip=host, port=port, init=c104.Init.INTERROGATION)
    if connection is None:
        print("client: add_connection refused", flush=True)
        print("IEC104_MASTER_FAIL", flush=True)
        return 1
    connection.on_send_raw(callable=on_send_raw)
    connection.on_receive_raw(callable=on_receive_raw)
    connection.on_state_change(callable=on_state_change)
    connection.on_unexpected_message(callable=on_unexpected_message)

    station = connection.add_station(common_address=COMMON_ADDRESS)
    if station is None:
        print("client: add_station refused", flush=True)
        print("IEC104_MASTER_FAIL", flush=True)
        return 1
    # A station for the FOREIGN common address is added only so c104 will let
    # the interrogation out, and removed again before the reply is graded — see
    # `interrogation_foreign_ca`.

    client.start()
    end = time.monotonic() + wait_s
    while time.monotonic() < end and not connection.is_connected:
        time.sleep(0.2)
    if not connection.is_connected:
        print("client: outstation never accepted a connection", flush=True)
        print("IEC104_MASTER_FAIL", flush=True)
        client.stop()
        return 1
    connected_at = time.monotonic()
    print("client: connected after %.1fs, state=%s" % (wait_s - (end - connected_at), connection.state.name), flush=True)

    records: list[dict] = []
    failures: list[str] = []
    marks: dict[str, int] = {}

    # ── how the two "named error" marks are read ────────────────────────────
    #
    # c104 surfaces the cause of a REFUSAL through neither callback. Measured,
    # both empty on a run where the outstation demonstrably sent cause 47 and
    # cause 46 on the wire: `Point.on_receive` is not invoked for a command
    # confirmation on the client side, and `Connection.on_unexpected_message`
    # does not fire for an ASDU naming a point or a station the client already
    # knows about — and the client has to know about both, or c104 will not let
    # the request out in the first place.
    #
    # What c104 does expose is `explain_bytes_dict`, its own APDU analyser. The
    # octets are handed to it verbatim and the cause is taken from what IT says
    # they mean, so the mark is still the counterpart's reading of the
    # outstation's answer and not ours. Decoding the COT octet here by hand
    # would make this mark our own arithmetic wearing c104's name.
    def named_cause(match) -> tuple[int, dict | None]:
        # Settle first. A refusal is TWO ASDUs — the negative activation
        # confirmation, then the ASDU carrying the cause — and `transmit()`
        # returns as soon as the first one lands. Reading the wire without
        # this delay saw only the confirmation and scored the mark -1, which
        # is what the third live run measured.
        time.sleep(0.3)
        with lock:
            rxs = [d for w, d in wire if w == "rx"]
        for data in reversed(rxs):
            try:
                info = c104.explain_bytes_dict(apdu=data)
            except Exception as e:  # noqa: BLE001
                print("client:   explain(%s) raised %s: %s" % (data.hex(), type(e).__name__, e), flush=True)
                continue
            print("client:   explain(%s) = %r" % (data.hex(), info), flush=True)
            # `explain_bytes_dict` hands back a real `c104.Cot`, not a string —
            # so the cause number below is c104's own decode of the octet the
            # outstation chose, never our arithmetic on it.
            cot = info.get("cot")
            value = getattr(cot, "value", None)
            if value is None:
                member = c104.Cot.__members__.get(
                    str(cot).upper().replace("COT.", "").replace(" ", "_")
                )
                value = None if member is None else member.value
            if value is None or value < 44 or value > 47:
                continue
            if not match(info):
                continue
            return int(value), info
        return -1, None

    # The ORDERED wire log matters as much as the two lists: an offline replay
    # corpus has to know which reply followed which request, and a per-direction
    # split cannot say. `seq` is what a freeze is generated from.
    def drain() -> tuple[list[str], list[str], list[list[str]]]:
        time.sleep(0.05)
        with lock:
            seq = [[w, d.hex()] for w, d in wire]
            wire.clear()
        tx = [h for w, h in seq if w == "tx"]
        rx = [h for w, h in seq if w == "rx"]
        return tx, rx, seq

    def op(name: str, deterministic: bool, fn, check) -> None:
        try:
            rr = fn()
            decoded, problem = check(rr, None)
        except Exception as e:  # noqa: BLE001 - a client-side raise is a result too
            decoded, problem = check(None, e)
        tx, rx, seq = drain()
        records.append(
            {
                "op": name,
                "deterministic": deterministic,
                "request": tx,
                "response": rx,
                "wire": seq,
                "decoded": decoded,
            }
        )
        if problem:
            failures.append("%s: %s" % (name, problem))
        print(
            "client: %-26s tx=%s rx=%s -> %s%s"
            % (
                name,
                ",".join(tx),
                ",".join(rx),
                decoded,
                "" if not problem else "  ** " + problem,
            ),
            flush=True,
        )

    # The STARTDT and c104's own post-connect interrogation of the GLOBAL
    # common address 0xFFFF are not graded, but they are recorded: the frozen
    # corpus replays from the outstation's initial state, and this is what
    # moves it there. It is also the exchange that found the §7.2.4 defect.
    _tx, _rx, _seq = drain()
    records.append(
        {
            "op": "open_connection",
            "deterministic": True,
            "request": _tx,
            "response": _rx,
            "wire": _seq,
            "decoded": {"connected": True, "states": list(states)},
        }
    )

    def snapshot() -> dict:
        """What the master currently holds for every fixture point."""
        out = {}
        for p in station.points:
            info = p.info
            value = p.value
            quality = p.quality
            out[p.io_address] = {
                "type": p.type.name,
                "value": _plain(value),
                "quality": None if quality is None else quality.value,
                "info": type(info).__name__,
            }
        return out

    def _plain(v):
        # c104 hands back fixed-width wrappers (Int16, Double, ...); reduce
        # them to plain Python so the transcript is comparable.
        for attr in ("value",):
            if hasattr(v, attr) and not isinstance(v, (int, float, bool, str)):
                v = getattr(v, attr)
        if hasattr(v, "name"):
            return v.name
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float, str)) or v is None:
            return v
        return str(v)

    # ── the interrogation that gets graded ──────────────────────────────────
    def gi_ok(rr, exc):
        if exc is not None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
        if rr is not True:
            return {"accepted": rr}, "outstation did not confirm the interrogation"
        return {"accepted": True, "points": snapshot()}, None

    op(
        "interrogation_station",
        True,
        lambda: connection.interrogation(common_address=COMMON_ADDRESS, wait_for_response=True),
        gi_ok,
    )
    op(
        "counter_interrogation",
        True,
        lambda: connection.counter_interrogation(
            common_address=COMMON_ADDRESS, wait_for_response=True
        ),
        gi_ok,
    )

    # ── grade the pre-fault snapshot ────────────────────────────────────────
    pre = snapshot()

    def got(ioa: int) -> dict | None:
        return pre.get(ioa)

    observed = 0
    checks = [
        ("sp_on", SP_ON, lambda d: d["type"] == "M_SP_NA_1" and d["value"] is True),
        ("sp_off", SP_OFF, lambda d: d["type"] == "M_SP_NA_1" and d["value"] is False),
        # c104 reports a double point as `c104.Double`, whose `.value` is the
        # two-bit DPI code from §7.2.6.2 — ON is 2, not the string "ON".
        ("dp_on", DP_ON, lambda d: d["type"] == "M_DP_NA_1" and int(d["value"]) == 2),
        (
            "float",
            FLOAT_IOA,
            lambda d: d["type"] == "M_ME_NC_1" and abs(float(d["value"]) - FLOAT_VALUE) < 1e-6,
        ),
        (
            "scaled",
            SCALED_IOA,
            lambda d: d["type"] == "M_ME_NB_1" and int(d["value"]) == SCALED_VALUE,
        ),
        (
            "counter",
            COUNTER_IOA,
            lambda d: d["type"] == "M_IT_NA_1" and int(d["value"]) == COUNTER_VALUE,
        ),
    ]
    for bit, (label, ioa, ok) in enumerate(checks):
        d = got(ioa)
        good = False
        if d is None:
            failures.append("pre-fault: IOA %d (%s) was never reported" % (ioa, label))
        else:
            try:
                good = bool(ok(d))
            except Exception as e:  # noqa: BLE001
                failures.append("pre-fault: IOA %d (%s) undecodable: %s" % (ioa, label, e))
            if not good:
                failures.append("pre-fault: IOA %d (%s) decoded as %r" % (ioa, label, d))
        if good:
            observed |= 1 << bit
    # The seventh bit is about the SET, not any one point: every fixture point
    # present and nothing extra. A device that reported a superset would still
    # pass all six value checks above.
    if set(pre.keys()) == {SP_ON, SP_OFF, DP_ON, FLOAT_IOA, SCALED_IOA, COUNTER_IOA}:
        observed |= 1 << 6
    else:
        failures.append("pre-fault: reported set was %r" % sorted(pre.keys()))
    marks["observed"] = observed

    float_d = got(FLOAT_IOA)
    scaled_d = got(SCALED_IOA)
    marks["measured_x10"] = (
        int(round(float(float_d["value"]) * 10)) if float_d is not None else 0
    )
    marks["scaled_minus_measured"] = (
        int(scaled_d["value"]) - marks["measured_x10"] if scaled_d is not None else 0
    )

    # A checksum over the whole reported set — which IOAs, under which type
    # ids. Grades the interrogation as a whole rather than any one value, and
    # is not the inverse of any read.
    checksum = 0
    for ioa in sorted(pre.keys()):
        type_name = pre[ioa]["type"]
        type_id = int(getattr(c104.Type, type_name).value)
        checksum = (checksum + ioa * 7 + type_id) % CHECKSUM_MOD
    marks["gi_checksum"] = checksum

    # ── the two errors the OUTSTATION names ─────────────────────────────────
    unbound = station.add_point(io_address=UNBOUND_IOA, type=c104.Type.C_SE_NB_1)
    if unbound is None:
        failures.append("client: could not add the unbound-IOA probe point")
    else:
        unbound.on_receive(callable=on_point_receive)

    def refused_command(rr, exc):
        if exc is not None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
        # The CAUSE is what matters, and it comes from the outstation — read
        # back through c104's own `Cot` naming of the ASDU it routed to this
        # point, never by decoding the octet ourselves. `transmit()` alone is
        # not enough: c104 returns True for a *negatively* confirmed command,
        # so the boolean says "answered", not "accepted".
        cause, info = named_cause(
            lambda i: i.get("firstInformationObjectAddress") == UNBOUND_IOA
        )
        marks["unknown_ioa_cause"] = cause
        return (
            {"accepted": rr, "cause": cause, "explained": info},
            None if cause >= 0 else "expected a refusal naming a cause",
        )

    def send_unbound() -> bool:
        unbound.value = c104.Int16(1)
        return unbound.transmit(cause=c104.Cot.ACTIVATION)

    op("command_unbound_ioa", True, send_unbound, refused_command)

    def refused_interrogation(rr, exc):
        if exc is not None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
        cause, info = named_cause(lambda i: i.get("commonAddress") == FOREIGN_CA)
        marks["unknown_ca_cause"] = cause
        return (
            {"accepted": rr, "cause": cause, "explained": info},
            None if cause >= 0 else "expected the outstation to name an unknown common address",
        )

    def interrogate_foreign() -> bool:
        foreign = connection.add_station(common_address=FOREIGN_CA)
        if foreign is None:
            raise RuntimeError("c104 refused a station for the foreign common address")
        try:
            return connection.interrogation(common_address=FOREIGN_CA, wait_for_response=True)
        finally:
            connection.remove_station(common_address=FOREIGN_CA)

    op("interrogation_foreign_ca", True, interrogate_foreign, refused_interrogation)

    # ── the fault, and the quality transition it produces ───────────────────
    settle = connected_at + FAULT_SETTLE_S - time.monotonic()
    if settle > 0:
        print("client: waiting %.1fs for the scheduled fault" % settle, flush=True)
        time.sleep(settle)
    drain()  # anything the outstation said while we waited is not an operation

    op(
        "interrogation_after_fault",
        True,
        lambda: connection.interrogation(common_address=COMMON_ADDRESS, wait_for_response=True),
        gi_ok,
    )

    post = snapshot()
    invalid_mask = 0
    for bit, (label, ioa, _ok) in enumerate(checks):
        d = post.get(ioa)
        if d is None or d["quality"] is None:
            continue
        if d["quality"] & int(c104.Quality.Invalid.value):
            invalid_mask |= 1 << bit
    marks["invalid_after_fault"] = invalid_mask
    if invalid_mask == 0:
        failures.append("post-fault: no point reported Invalid quality")

    # ── the verdict block ───────────────────────────────────────────────────
    graded = len(records)
    verdict = [
        MAGIC,
        graded,
        len(failures),
        marks.get("observed", 0),
        marks.get("measured_x10", 0),
        marks.get("scaled_minus_measured", 0),
        marks.get("gi_checksum", 0),
        marks.get("unknown_ioa_cause", -1),
        marks.get("unknown_ca_cause", -1),
        marks.get("invalid_after_fault", 0),
    ]
    assert len(verdict) == VERDICT_SLOTS
    all_passed = not failures

    def commanded(rr, exc):
        if exc is not None:
            return {"raised": "%s: %s" % (type(exc).__name__, exc)}, "raised %s" % exc
        return {"accepted": rr}, None if rr else "the outstation refused the mark"

    for i, value in enumerate(verdict):
        ioa = VERDICT_BASE + i
        point = station.add_point(io_address=ioa, type=c104.Type.C_SE_NB_1)
        if point is None:
            failures.append("client: could not add verdict point %d" % ioa)
            continue

        def send(p=point, v=value) -> bool:
            p.value = c104.Int16(int(v))
            return p.transmit(cause=c104.Cot.ACTIVATION)

        op("write_verdict_%d" % ioa, True, send, commanded)

    # Sent LAST, in its own command, and in BOTH outcomes.
    pass_point = station.add_point(io_address=VERDICT_PASS_IOA, type=c104.Type.C_SC_NA_1)
    if pass_point is None:
        failures.append("client: could not add the pass point")
    else:

        def send_pass() -> bool:
            pass_point.value = bool(all_passed)
            return pass_point.transmit(cause=c104.Cot.ACTIVATION)

        op("write_verdict_pass", True, send_pass, commanded)

    reconnects = sum(1 for s in states if s == "OPEN") - 1
    print(
        "client: states=%s reconnects=%d unexpected=%d"
        % (",".join(states), max(reconnects, 0), len(unexpected)),
        flush=True,
    )
    if reconnects > 0:
        failures.append("link: the connection was re-established %d time(s)" % reconnects)

    try:
        connection.disconnect()
        client.stop()
    except Exception:  # noqa: BLE001
        pass
    time.sleep(0.2)

    print(CAPTURE_BEGIN, flush=True)
    print(json.dumps({"master": "c104", "version": version, "licence": licence}), flush=True)
    for rec in records:
        print(json.dumps(rec, separators=(",", ":"), default=str), flush=True)
    print(CAPTURE_END, flush=True)

    print("client: verdict %s, all_passed=%s" % (verdict, all_passed), flush=True)
    print("IEC104_MASTER_DONE", flush=True)
    if failures:
        for f in failures:
            print("client: FAILURE %s" % f, flush=True)
        print("IEC104_MASTER_FAIL", flush=True)
        return 1
    print("client: %d operations, all satisfied by c104 %s" % (len(records), version), flush=True)
    print("IEC104_MASTER_OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
