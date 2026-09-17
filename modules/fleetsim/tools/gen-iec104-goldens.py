#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Turn one recorded c104 session into the Zig `Step` arrays in
modules/fleetsim/src/master_goldens.zig.

Input: the FLEETSIM_CAPTURE_BEGIN/END block from a `scripts/vm/run.sh fleetsim
debian` run with FLEETSIM_MASTERS=iec104. Each record carries an ORDERED wire
log, so a request can be paired with exactly the replies that followed it —
which a per-direction split cannot express.

Lives here and never in the repo: the repo carries the frozen bytes, not the
machinery that produced them.
"""
import json, sys

SPLIT_AFTER = "interrogation_foreign_ca"  # the scheduled fault lands here

def steps(recs):
    out = []
    for r in recs:
        if "op" not in r:
            continue
        cur = None
        for direction, hexs in r["wire"]:
            if direction == "tx":
                if cur:
                    out.append(cur)
                cur = {"op": r["op"], "request": hexs, "response": []}
            else:
                assert cur is not None, r["op"]
                cur["response"].append(hexs)
        if cur:
            out.append(cur)
        if out:
            out[-1]["decoded"] = json.dumps(r.get("decoded", {}), separators=(",", ":"))
    # number repeated ops
    seen = {}
    for s in out:
        seen[s["op"]] = seen.get(s["op"], 0) + 1
    idx = {}
    for s in out:
        if seen[s["op"]] > 1:
            idx[s["op"]] = idx.get(s["op"], 0)
            s["op"] = "%s[%d]" % (s["op"], idx[s["op"]])
            idx[s["op"].rsplit("[", 1)[0]] += 1
    return out

def emit_bytes(hexs, indent):
    b = bytes.fromhex(hexs)
    pad = " " * indent
    lines, row = [], []
    for i, x in enumerate(b):
        row.append("0x%02X," % x)
        if len(row) == 10:
            lines.append(pad + " ".join(row))
            row = []
    if row:
        lines.append(pad + " ".join(row))
    return "\n".join(lines)

def emit(name, chunk, comment):
    print("%s\nconst %s = [_]Step{" % (comment, name))
    for s in chunk:
        print("    .{")
        print('        .op = "%s",' % s["op"])
        print("        .request = &.{")
        print(emit_bytes(s["request"], 12))
        print("        },")
        joined = "".join(s["response"])
        if joined:
            print("        .response = &.{")
            print(emit_bytes(joined, 12))
            print("        },")
        dec = s.get("decoded", "")
        if dec and dec not in ("{}",) and len(dec) < 400:
            print('        .decoded = "%s",' % dec.replace("\\", "\\\\").replace('"', '\\"'))
        print("    },")
    print("};")

def main():
    recs = json.load(open(sys.argv[1]))
    all_steps = steps(recs)
    cut = 1 + max(i for i, s in enumerate(all_steps) if s["op"].startswith(SPLIT_AFTER))
    emit("iec104_before_fault", all_steps[:cut],
         "/// Everything up to the scheduled device fault.")
    print()
    emit("iec104_after_fault", all_steps[cut:],
         "/// After `trouble_on`: the second interrogation and the eleven marks.")

main()
