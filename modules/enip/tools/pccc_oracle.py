#!/usr/bin/env python3
"""Differential oracle for PCCC over CIP: a stock pycomm3.SLCDriver (1.2.16,
`pip install --user pycomm3`) against `pccc_serve.zig`. Exits 0 only when every
read returns the served value and every write is read back."""
import sys
from pycomm3 import SLCDriver

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:44818"
bad = 0

def check(label, got, want):
    global bad
    ok = got == want
    print(("ok   " if ok else "FAIL ") + f"{label}: {got!r}" + ("" if ok else f" (want {want!r})"))
    bad += 0 if ok else 1

with SLCDriver(host) as plc:
    check("processor type", plc.get_processor_type(), "1747-L552B")
    t = plc.read("N7:0")
    check("N7:0", (t.value, t.error), (-7, None))
    t = plc.read("N7:1")
    check("N7:1", (t.value, t.error), (1234, None))
    t = plc.read("N7:0{2}")
    check("N7:0{2}", (t.value, t.error), ([-7, 1234], None))
    t = plc.read("F8:0")
    check("F8:0", (t.value, t.error), (3.5, None))
    t = plc.read("T4:0.PRE")
    check("T4:0.PRE", (t.value, t.error), (100, None))
    t = plc.read("T4:0.ACC")
    check("T4:0.ACC", (t.value, t.error), (42, None))
    t = plc.read("N7:0/0")
    check("N7:0/0 (bit)", (t.value, t.error), (True, None))
    t = plc.write(("N7:5", 321))
    check("write N7:5", t.error, None)
    check("read back N7:5", plc.read("N7:5").value, 321)
    t = plc.write(("N7:6{2}", [10, 20]))
    check("write N7:6{2}", t.error, None)
    check("read back N7:6{2}", plc.read("N7:6{2}").value, [10, 20])
    t = plc.write(("N7:0/1", True))
    check("write N7:0/1 (bit)", t.error, None)
    check("read back N7:0", plc.read("N7:0").value, -5)
    t = plc.write(("F8:1", 2.25))
    check("write F8:1", t.error, None)
    check("read back F8:1", plc.read("F8:1").value, 2.25)
    t = plc.read("N99:0")
    check("missing file reports an error", t.error is not None, True)
sys.exit(1 if bad else 0)
