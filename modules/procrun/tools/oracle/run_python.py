#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Oracle driver for procrun: run every scenario of src/oracle_scenarios.json
through Python's `subprocess` and write the results to
src/oracle_results.json (the FROZEN file that src/oracle_test.zig replays
procrun against; no Python at test time).

    python3 -I tools/oracle/run_python.py [--out FILE]

The scenario semantics (what each field means for both sides) live in
src/oracle_test.zig's header; this file is the Python half of the same
contract. Re-run it only when the scenario table changes -- the frozen
results are the evidence, so review the diff.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "..", "src")
TEXT_LIMIT = 2048


def gen_stdin(sc):
    if "stdin_len" in sc:
        pattern = bytes((j * 31 + 7) & 255 for j in range(256))
        n = sc["stdin_len"]
        return (pattern * (n // 256 + 1))[:n]
    return sc.get("stdin_text", "").encode()


def post(sc, data):
    mode = sc.get("post", "none")
    if mode == "nul_set":
        prefix = sc.get("prefix", "").encode()
        items = [i for i in data.split(b"\0") if i and i.startswith(prefix)]
        return b"\n".join(sorted(items))
    if mode == "cwd_parent":
        if data.rstrip(b"\n") == os.getcwd().encode():
            return b"PARENT\n"
    return data


def sha(b):
    return hashlib.sha256(b).hexdigest()


def stream(sc, key, data):
    data = post(sc, data) if key == "stdout" else data
    r = {key + "_len": len(data), key + "_sha256": sha(data)}
    if key == "stdout" and "cap" in sc:
        r["stdout_cap_sha256"] = sha(data[: sc["cap"]])
    # Short printable output is kept as text so a diff of the frozen file
    # reads; anything else is pinned by length and hash alone.
    if len(data) <= TEXT_LIMIT and all(c in (9, 10) or 32 <= c < 127 for c in data):
        r[key + "_text"] = data.decode("ascii")
    return r


ERRMAP = {
    FileNotFoundError: "FileNotFound",
    PermissionError: "AccessDenied",
    NotADirectoryError: "NotDir",
}


def run_one(sc, tmp):
    argv = list(sc["argv"])
    fd = None
    if sc.get("marker", "none") != "none":
        path = os.path.join(tmp, "orc_marker")
        with open(path, "w") as f:
            f.write("marker")
        fd = os.open(path, os.O_RDONLY)  # non-inheritable, as Python opens everything
        if sc["marker"] == "inheritable":
            os.set_inheritable(fd, True)
        argv = [a.replace("{FD}", str(fd)) for a in argv]
    kw = {"stdout": subprocess.PIPE, "close_fds": sc.get("py_close_fds", True)}
    kw["stderr"] = subprocess.STDOUT if sc.get("merge_stderr") else subprocess.PIPE
    if sc.get("stdin", "default") == "pipe":
        kw["input"] = gen_stdin(sc)
    else:
        kw["stdin"] = subprocess.DEVNULL  # procrun's default; Python would inherit
    if sc.get("cwd") is not None:
        kw["cwd"] = sc["cwd"]
    mode = sc.get("env_mode", "inherit")
    env = sc.get("env", {})
    if mode == "clear":
        kw["env"] = dict(env)
    elif mode == "merge":
        kw["env"] = {**os.environ, **env}
    if sc.get("new_group"):
        kw["process_group"] = 0
    if sc.get("pass_marker"):
        kw["pass_fds"] = (fd,)
    if "timeout_ms" in sc:
        kw["timeout"] = sc["timeout_ms"] / 1000.0
    res = {}
    try:
        try:
            p = subprocess.run(argv, **kw)
            out, err, rc = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as e:
            out, err, rc = e.stdout or b"", e.stderr or b"", -9
            res["timed_out"] = True
    except OSError as e:
        name = ERRMAP.get(type(e)) or "errno_%d" % (e.errno or 0)
        return {"kind": "error", "err": name}
    finally:
        if fd is not None:
            os.close(fd)
    res["kind"] = "exited" if rc >= 0 else "signal"
    res["code"] = rc if rc >= 0 else -rc
    res.update(stream(sc, "stdout", out or b""))
    res.update(stream(sc, "stderr", err or b""))
    return res


def main():
    out_path = os.path.join(SRC, "oracle_results.json")
    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]
    with open(os.path.join(SRC, "oracle_scenarios.json")) as f:
        scenarios = json.load(f)["scenarios"]
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for sc in scenarios:
            results[sc["name"]] = run_one(sc, tmp)
    doc = {"python": sys.version.split()[0], "results": results}
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    print("%d scenarios -> %s" % (len(results), out_path))


main()
