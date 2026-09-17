#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Turn a fleetsim-dnp3-master capture into the Zig `Step` arrays.

Capture-time only: the tests replay the frozen bytes and never run this.

Usage: gen-dnp3-goldens.py <master.log>

Reads the JSON lines between FLEETSIM_CAPTURE_BEGIN and FLEETSIM_CAPTURE_END.
Each record has an `op`, the whole DNP3 link frames the master sent (`tx`) and
the ones the device sent back (`rx`). DNP3 over TCP is strictly alternating on
one connection, so tx[i] pairs with rx[i]; a request with no rx is emitted with
`.response = null`, which `replay` reads as "the protocol says this gets no
reply".
"""
import json
import sys


def zig_bytes(hexstr, indent):
    b = bytes.fromhex(hexstr)
    out = []
    line = []
    for i, c in enumerate(b):
        line.append("0x%02x" % c)
        if len(line) == 12:
            out.append(" " * indent + ", ".join(line) + ",")
            line = []
    if line:
        out.append(" " * indent + ", ".join(line) + ",")
    return "\n".join(out)


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    recs = []
    inside = False
    with open(sys.argv[1], "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line == "FLEETSIM_CAPTURE_BEGIN":
                inside = True
                continue
            if line == "FLEETSIM_CAPTURE_END":
                break
            if not inside or not line.startswith("{"):
                continue
            recs.append(json.loads(line))

    header = recs[0]
    print("// master: %s" % header)
    steps = []
    for r in recs[1:]:
        tx, rx = r["tx"], r["rx"]
        for i, req in enumerate(tx):
            resp = rx[i] if i < len(rx) else None
            label = r["op"] if len(tx) == 1 else "%s [%d]" % (r["op"], i)
            dec = r["decoded"] if i == len(tx) - 1 else ""
            steps.append((label, req, resp, dec))
        if len(rx) > len(tx):
            print("// WARNING: %s has %d rx for %d tx" % (r["op"], len(rx), len(tx)),
                  file=sys.stderr)

    for label, req, resp, dec in steps:
        print("    .{")
        print('        .op = "%s",' % esc(label))
        print("        .request = &.{")
        print(zig_bytes(req, 12))
        print("        },")
        if resp is None:
            print("        .response = null,")
        else:
            print("        .response = &.{")
            print(zig_bytes(resp, 12))
            print("        },")
        if dec:
            print('        .decoded = "%s",' % esc(dec))
        print("    },")
    print("// %d steps" % len(steps), file=sys.stderr)


main()
