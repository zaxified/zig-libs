#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive `rustls-owed.txt`: the BoGo server tests at TLS 1.3 that rustls
passes — the parity yardstick (DESIGN: our pass set must contain rustls's).

rustls's own result is not published, so it is reconstructed from its two
inputs at the pinned release:

- `bogo/config.json.in` (C-preprocessed as the default build: aws-lc-rs,
  post-quantum on): a test it disables is not owed;
- `bogo/src/main.rs`, its shim: a test with a flag the shim answers "not
  implemented" (exit 89) or does not know (exit 1, so the test is disabled
  or newer than rustls's runner) is not owed.

A test's flags are what the runner passes the shim, captured by running the
reviewed runner once per test against a stub shim that records its argv and
exits 89. TLS 1.2 is out of scope: tests whose name or flags pin TLS 1.2 or
older are dropped. Tests that run at the runner's default TLS 1.2 without
saying so in their name or flags stay listed; tlsserver's `config.json`
disables them with that reason, which `interop.zig --bogo` reports.

Usage (from the repository root, after `zig build interop-tlsserver -- --bogo`
built the runner):

    python3 modules/tlsserver/tools/bogo/rustls_parity.py \\
        --runner .zig-cache/tlsserver-interop/bogo-runner \\
        --bogo-src .zig-cache/bogo-src/<commit> \\
        --rustls-config <rustls>/bogo/config.json.in \\
        --rustls-shim <rustls>/bogo/src/main.rs \\
        --rustls-version 0.23.43

Runs about 3 minutes (one runner process per candidate test, 4 at a time).
"""

import argparse
import concurrent.futures
import fnmatch
import json
import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

STUB = """#!/bin/sh
for a in "$@"; do [ "$a" = "-is-handshaker-supported" ] && { echo No; exit 0; }; done
out=
prev=
for a in "$@"; do [ "$prev" = "-parity-out" ] && out=$a; prev=$a; done
[ -n "$out" ] && printf '%s\\n' "$@" > "$out"
exit 89
"""


def load_rustls_config(path):
    text = subprocess.run(
        ["cpp", "-P", "-undef", "-traditional-cpp", "-DAWS_LC_RS", "-DPOST_QUANTUM", path],
        check=True, capture_output=True, text=True).stdout
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)["DisabledTests"]


def rustls_shim_flags(path):
    """(handled, not_implemented) flag sets of rustls's shim option match."""
    src = open(path).read()
    start = src.index("// Not implemented things")
    end = src.index("process::exit(BOGO_NACK)", start)
    nyi = set(re.findall(r'"(-[a-z0-9-]+)"', src[start:end]))
    arms = set(re.findall(r'^\s*"(-[a-z0-9-]+)"\s*(?:=>|\||if )', src, flags=re.M))
    # `-fips-202205` answers 89 in a non-FIPS build.
    nyi.add("-fips-202205")
    return arms - nyi, nyi


def run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def all_tests(runner, runner_dir, stub, work):
    out = os.path.join(work, "all.json")
    run([runner, "-test.run", "^TestAll$", "-shim-path", stub, "-allow-unimplemented",
         "-pipe", "-json-output", out, "-num-workers", "4"],
        cwd=runner_dir, check=True, capture_output=True, env=dict(os.environ, TMPDIR=work))
    return sorted(json.load(open(out))["tests"])


def argv_of(runner, runner_dir, stub, work, name):
    out = os.path.join(work, "argv", name)
    run([runner, "-test.run", "^TestAll$", "-shim-path", stub, "-allow-unimplemented",
         "-pipe", "-num-workers", "1", "-test", name, "-shim-extra-flags", "-parity-out;" + out],
        cwd=runner_dir, capture_output=True, env=dict(os.environ, TMPDIR=work))
    if not os.path.exists(out):
        return None
    return [a for a in open(out).read().split("\n") if a]


def pins_old_version(name, argv):
    if "-no-tls13" in argv:
        return True
    for i, a in enumerate(argv):
        if a == "-max-version" and i + 1 < len(argv) and int(argv[i + 1]) < 0x0304:
            return True
    return bool(re.search(r"TLS1[12]?($|-)|SSL3|TLS12", name)) and "TLS13" not in name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", required=True)
    ap.add_argument("--bogo-src", required=True)
    ap.add_argument("--rustls-config", required=True)
    ap.add_argument("--rustls-shim", required=True)
    ap.add_argument("--rustls-version", required=True)
    ap.add_argument("--out", default=os.path.join(HERE, "rustls-owed.txt"))
    args = ap.parse_args()

    runner = os.path.abspath(args.runner)
    runner_dir = os.path.join(os.path.abspath(args.bogo_src), "ssl/test/runner")
    disabled = load_rustls_config(args.rustls_config)
    handled, _ = rustls_shim_flags(args.rustls_shim)

    with tempfile.TemporaryDirectory(dir=os.path.dirname(runner)) as work:
        stub = os.path.join(work, "stub.sh")
        with open(stub, "w") as f:
            f.write(STUB)
        os.chmod(stub, stat.S_IRWXU)
        os.mkdir(os.path.join(work, "argv"))

        tests = all_tests(runner, runner_dir, stub, work)
        candidates = [t for t in tests if not any(fnmatch.fnmatchcase(t, p) for p in disabled)]
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            argvs = dict(zip(candidates, pool.map(lambda t: argv_of(runner, runner_dir, stub, work, t), candidates)))

    owed = []
    for name, argv in argvs.items():
        if argv is None:
            sys.exit(f"no argv captured for {name}")
        flags = [a for a in argv if a.startswith("-") and not re.match(r"^-\d", a) and a != "-parity-out"]
        if "-server" not in flags or "-dtls" in flags or "-quic" in flags:
            continue
        if pins_old_version(name, argv):
            continue
        if all(f in handled for f in flags):
            owed.append(name)

    with open(args.out, "w") as f:
        f.write(f"# BoGo server tests at TLS 1.3 that rustls {args.rustls_version} (aws-lc-rs) passes,\n")
        f.write(f"# from its bogo/config.json.in and bogo/src/main.rs over {len(tests)} tests of the\n")
        f.write("# pinned runner (tools/bogo/rustls_parity.py rewrites this). interop.zig --bogo\n")
        f.write("# reports each one tlsserver does not pass.\n")
        for name in sorted(owed):
            f.write(name + "\n")
    print(f"{len(tests)} tests, {len(candidates)} not disabled by rustls, {len(owed)} owed -> {args.out}")


if __name__ == "__main__":
    main()
