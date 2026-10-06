#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corpus for `zig build interop-uci` (tools/interop.zig): the 65 grammar
probes of gen_probes.py plus seeded random configs from diff_fuzz.py (300
statement-valid, 100 free-form), as a JSON list of hex strings.

    python3 modules/uci/tools/libuci_corpus.py > .zig-cache/uci-differential/corpus.json
"""
import importlib.util
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


probes = load("gen_probes").P
fuzz = load("diff_fuzz")
corpus = [body.encode("latin-1") for body in probes.values()]
r = random.Random(20261006)
corpus += [fuzz.gen(r, valid=True) for _ in range(300)]
corpus += [fuzz.gen(r, valid=False) for _ in range(100)]
print(json.dumps([c.hex() for c in corpus]))
