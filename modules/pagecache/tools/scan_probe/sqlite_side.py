#!/usr/bin/env python3
"""Scan-resistance probe, SQLite side. See README.md.

Run under strace so the backend reads are counted from the outside:

    strace -f -e trace=pread64,getppid -o OUT python3 sqlite_side.py N C H PASSES DB
    python3 sqlite_side.py --count OUT

Phase markers are getppid() calls (a syscall strace can see). The database has
one row per leaf page (payload 3000 bytes, 4096-byte pages), so row i is page i
of the table's leaf level; the cache is PRAGMA cache_size = C pages, mmap off.
"""
import os
import sqlite3
import sys


def build(db, n):
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.execute("PRAGMA page_size=4096")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, p BLOB)")
    con.executemany("INSERT INTO t VALUES(?,?)", ((i, bytes([i & 255]) * 3000) for i in range(n)))
    con.commit()
    con.close()


def run(n, c, h, passes, db):
    build(db, n)
    con = sqlite3.connect(db, isolation_level=None)
    con.execute("PRAGMA mmap_size=0")
    con.execute("PRAGMA cache_size=%d" % c)  # positive = pages
    assert con.execute("PRAGMA cache_size").fetchone()[0] == c
    assert con.execute("PRAGMA mmap_size").fetchone()[0] == 0
    stride = n // h
    hot = [k * stride for k in range(h)]
    q = "SELECT length(p) FROM t WHERE id=?"
    os.getppid()  # marker 1: start of warm-up
    for _ in range(passes):
        for i in hot:
            con.execute(q, (i,)).fetchone()
    os.getppid()  # marker 2: start of scan
    total = 0
    for (ln,) in con.execute("SELECT length(p) FROM t"):
        total += ln
    assert total == 3000 * n
    os.getppid()  # marker 3: start of hot-again
    for i in hot:
        con.execute(q, (i,)).fetchone()
    os.getppid()  # marker 4: end
    con.close()


def count(path):
    phase = 0
    counts = [0, 0, 0, 0]
    hdr = [0, 0, 0, 0]
    for line in open(path):
        if "getppid" in line:
            phase += 1
        elif "pread64" in line and "resumed" not in line and phase >= 1:
            # Page reads only: outside a transaction SQLite also preads the
            # 16-byte file-change-counter header once per statement.
            if ", 4096, " in line:
                counts[phase - 1] += 1
            else:
                hdr[phase - 1] += 1
    print("sqlite     backend page reads: warm=%d scan=%d hot-again=%d  (excluded: %d/%d/%d header-check preads)" % (tuple(counts[:3]) + tuple(hdr[:3])))


if __name__ == "__main__":
    if sys.argv[1] == "--count":
        count(sys.argv[2])
    else:
        n, c, h, passes = map(int, sys.argv[1:5])
        run(n, c, h, passes, sys.argv[5])
