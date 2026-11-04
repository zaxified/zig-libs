#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the fixtures `src/testdata/store_capture.txt` pins.

Each case writes a config, runs the real `uci` (black box, command line only,
nothing of its source is read) with `batch` or `import -m` against scratch
`-c`/`-t` directories, and records what `uci show` reports with the changes
staged and the file `uci commit` then writes. `src/store_test.zig` replays the
same input through `Session` and must match: the `show` text byte for byte, the
committed file as a parsed model.

    UCI_BIN=/path/to/uci hw run --mem 1G -- python3 -I \
        modules/uci/tools/capture-store.py <scratch-dir> > modules/uci/src/testdata/store_capture.txt

`<scratch-dir>` must be empty or absent; it is filled with `conf/` and `save/`
per case and its files are deleted again (no recursive remove).
"""
import os
import subprocess
import sys

UCI = os.environ["UCI_BIN"]
BASE = sys.argv[1]

CONF = """\
config iface 'lan'
\toption proto 'static'
\tlist dns '1.1.1.1'
\tlist dns '8.8.8.8'

config rule
\toption name 'r0'

config rule
\toption name 'r1'
"""

CASES = [
    ("basic-set-list", "batch",
     "set t.lan.proto=dhcp\nset t.lan.ip=\"10.0.0.1\"\nadd_list t.lan.dns=9.9.9.9\ndel_list t.lan.dns=1.1.1.1\n"),
    ("anonymous-add-rename-reorder", "batch",
     "add t rule\nset t.@rule[-1].name=new\nset t.@rule[0].name=zero\nrename t.@rule[1]=second\nreorder t.second=0\n"),
    ("delete-forms", "batch",
     "delete t.lan.dns=1\ndelete t.lan.proto\ndelete t.@rule[0]\n"),
    ("type-change-new-section", "batch",
     "set t.lan=iface2\nset t.fresh=thing\nset t.fresh.a=1\nrename t.fresh.a=b\n"),
    ("failures-go-on", "batch",
     "set t.lan.m1=1\nset t.nope.x=2\nbogus x\nset t.lan.m3=3\nset t.lan.n\nrename t.lan=\n"),
    ("quoting-comments-semicolon", "batch",
     "# c\n\n  set t.lan.msg=\"hello world\"\nset t.lan.q='it'\\''s'  # trailing\n"
     "set t.lan.a=1; set t.lan.b=2\nset t.lan.c=\"1\"; set t.lan.d=2\r\nset t.lan.e=3\n"),
    ("empty-set-deletes", "batch", "set t.lan.proto=\nset t.lan.nothing=\n"),
    ("list-single-conversions", "batch",
     "set t.lan.dns=single\nadd_list t.lan.proto=more\nadd_list t.lan.fresh=x\n"),
    ("del-list-last-entry", "batch",
     "del_list t.lan.dns=1.1.1.1\ndel_list t.lan.dns=8.8.8.8\nadd_list t.lan.k=a\ndel_list t.lan.k=a\n"),
    ("commit-in-script", "batch",
     "set t.lan.x=1\ncommit t\nset t.lan.y=2\n"),
    ("revert-in-script", "batch",
     "set t.lan.x=1\nrevert t\nset t.lan.y=2\n"),
    ("merge-list-single-anon", "import",
     "config iface 'lan'\n\tlist dns '9.9.9.9'\n\toption proto 'dhcp'\n\toption fresh '1'\n\n"
     "config rule\n\toption name 'r9'\n\nconfig other 'o1'\n\toption k 'v'\n"),
    ("merge-single-over-list", "import",
     "config iface 'lan'\n\toption dns 'single'\n\tlist proto 'p1'\n\tlist proto 'p2'\n"),
    ("merge-type-clash", "import", "config xx 'lan'\n\toption a 'b'\n"),
]


def run(args, cwd_c, cwd_s, stdin=""):
    r = subprocess.run([UCI, "-c", cwd_c, "-t", cwd_s] + args, input=stdin.encode(),
                       capture_output=True, timeout=30)
    return r.returncode, r.stdout.decode(), r.stderr.decode()


def main():
    os.makedirs(BASE, exist_ok=True)
    out = []
    made = []
    for i, (name, kind, text) in enumerate(CASES):
        c = os.path.join(BASE, "c%d" % i)
        s = os.path.join(BASE, "s%d" % i)
        os.makedirs(c, exist_ok=True)
        os.makedirs(s, exist_ok=True)
        cf = os.path.join(c, "t")
        with open(cf, "w") as f:
            f.write(CONF)
        made.append(cf)
        if kind == "batch":
            run(["batch"], c, s, text)
        else:
            run(["-m", "import", "t"], c, s, text)
        rc, show, _ = run(["show", "t"], c, s)
        run(["commit", "t"], c, s)
        with open(cf) as f:
            committed = f.read()
        made.append(os.path.join(s, "t"))
        out.append("=== case %s\n--- kind\n%s\n--- input\n%s--- show\n%s--- committed\n%s=== end\n" % (
            name, kind, text, show, committed))
    sys.stdout.write("".join(out))
    for p in made:
        if os.path.exists(p):
            os.unlink(p)
    for i in range(len(CASES)):
        for d in ("c%d" % i, "s%d" % i):
            try:
                os.rmdir(os.path.join(BASE, d))
            except OSError:
                pass
    try:
        os.rmdir(BASE)
    except OSError:
        pass


main()
