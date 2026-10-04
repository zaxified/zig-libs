#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for the emitter: for every yaml-test-suite case with
an `in.json`, this module composes `in.yaml` and EMITS it (`emit_oracle`);
PyYAML (MIT, public API only: `yaml.load_all` with CSafeLoader -- a YAML 1.1
reader) loads the emitted text, and the result must equal `in.json`.
Numbers compare by value (JSON has one number type).

    python3 emit_oracle.py <emit_oracle binary> <yaml-test-suite data checkout>
"""
import glob, json, math, os, subprocess, sys
import yaml

L = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
exe, suite = sys.argv[1], sys.argv[2]
cases = []
for d in sorted(glob.glob(os.path.join(suite, "**", "in.json"), recursive=True)):
    base = os.path.dirname(d)
    if os.path.exists(os.path.join(base, "error")):
        continue
    cases.append(base)

def docs_of_json(text):
    dec, out, i = json.JSONDecoder(), [], 0
    text = text.strip()
    while i < len(text):
        v, j = dec.raw_decode(text, i)
        out.append(v)
        i = j
        while i < len(text) and text[i].isspace():
            i += 1
    return out

def same(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b or (isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b

inp = "".join("." + open(os.path.join(c, "in.yaml"), "rb").read().hex() + "\n" for c in cases)
res = subprocess.run([exe], input=inp.encode(), capture_output=True, check=True).stdout.decode().splitlines()
ok = bad = ours_err = 0
for c, line in zip(cases, res):
    if line.startswith("ERR:"):
        ours_err += 1
        continue
    text = bytes.fromhex(line[1:]).decode("utf-8")
    want = docs_of_json(open(os.path.join(c, "in.json"), encoding="utf-8").read())
    try:
        got = list(yaml.load_all(text, Loader=L))
    except yaml.YAMLError as e:
        bad += 1
        print("PYYAML REFUSED", os.path.relpath(c, suite), str(e).splitlines()[0])
        continue
    if len(got) == len(want) and all(same(g, w) for g, w in zip(got, want)):
        ok += 1
    else:
        bad += 1
        print("DIFFER", os.path.relpath(c, suite))
print(f"same={ok} differ={bad} ours-refused={ours_err} of {len(cases)}")
