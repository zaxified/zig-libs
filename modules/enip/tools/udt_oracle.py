#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Live oracle for the Template Object: a stock pycomm3 LogixDriver browses the
adapter that udt_serve.zig runs, uploads the tag list, fetches the template of
each structure tag and reads the structures as named members.

    python3 modules/enip/tools/udt_oracle.py 127.0.0.1:44818

Exit 0 only when the decoded members are the ones udt_serve.zig serves.
"""
import sys

from pycomm3 import LogixDriver

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:44818"
with LogixDriver(host, init_tags=True, init_program_tags=False) as plc:
    names = sorted(plc.tags)
    print("tags:", names)
    assert {"Count", "Motor", "Site"} <= set(names), names
    for t in ("Motor", "Site"):
        print(t, "->", plc.tags[t]["data_type_name"] if "data_type_name" in plc.tags[t] else plc.tags[t])
    motor = plc.read("Motor")
    site = plc.read("Site")
    count = plc.read("Count")
    print("Motor =", motor)
    print("Site  =", site)
    print("Count =", count)
    assert count.value == 9, count
    m = motor.value
    assert abs(m["Speed"] - 1.5) < 1e-6 and m["Count"] == 42 and list(m["Flags"]) == [1, 2, 3, 4], m
    s = site.value
    assert abs(s["P1"]["Speed"] - 4.0) < 1e-6 and s["P1"]["Count"] == 7 and s["Total"] == 100, s
print("OK")
