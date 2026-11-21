# SPDX-License-Identifier: MIT
"""pyarrow side of `tools/bench.zig`: the same table as the Zig side builds
(1_000_000 rows by default, `ARROW_BENCH_ROWS`) written to / read from an
in-memory IPC stream, timed like benchkit's `timeIt` (the batch doubles past
100 ms, best of five), one workload per call.

Usage: bench.py <work dir> <workload>      (workload: write | read | read_zc)
Prints `<workload>\t<ns per op>\t<rows>` on stdout, the library version on stderr.
Single-threaded (cpu_count and io_thread_count 1).
"""

import os
import sys
import time

import pyarrow as pa
import pyarrow.compute as pc

pa.set_cpu_count(1)
pa.set_io_thread_count(1)

N = int(os.environ.get("ARROW_BENCH_ROWS", "1000000"))
BATCH = 65536


def table():
    i = pa.array(range(N), pa.int64())
    a = pc.modulo(pc.multiply(i, 7919), 1000003)
    a = pc.if_else(pc.equal(pc.modulo(i, 13), 0), pa.scalar(None, pa.int64()), a)
    b = pc.add(pc.multiply(pc.cast(i, pa.float64()), 0.5), pc.cast(pc.modulo(i, 97), pa.float64()))
    c = pc.binary_join_element_wise(pa.scalar("row-"), pc.cast(pc.modulo(pc.multiply(i, 31), 10007), pa.string()), pa.scalar(""))
    return pa.table({"a": a, "b": b, "c": c})


def write(t):
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, t.schema) as w:
        for rb in t.to_batches(max_chunksize=BATCH):
            w.write_batch(rb)
    return sink.getvalue()


def timeit(fn):
    n = 1
    while True:
        t0 = time.perf_counter_ns()
        for _ in range(n):
            fn()
        if time.perf_counter_ns() - t0 > 100_000_000:
            break
        n *= 2
    best = None
    for _ in range(5):
        t0 = time.perf_counter_ns()
        for _ in range(n):
            fn()
        d = (time.perf_counter_ns() - t0) / n
        best = d if best is None else min(best, d)
    return best


def main():
    name = sys.argv[2]
    t = table()
    buf = write(t)
    if name == "write":
        ns = timeit(lambda: write(t))
    elif name == "read":
        # Materialised: the chunks are copied into contiguous columns, as a
        # `dataframe.Frame` holds them.
        ns = timeit(lambda: pa.ipc.open_stream(buf).read_all().combine_chunks())
    elif name == "read_zc":
        ns = timeit(lambda: pa.ipc.open_stream(buf).read_all())
    else:
        print("unknown workload", name, file=sys.stderr)
        return 2
    print(f"pyarrow {pa.__version__}", file=sys.stderr)
    print(f"{name}\t{ns:.1f}\t{N}")
    return 0


sys.exit(main())
