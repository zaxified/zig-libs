# SPDX-License-Identifier: MIT
"""Read the Arrow IPC streams and files `tools/interop.zig` wrote with OUR
writer, using pyarrow (a foreign implementation), and compare every column's
type and values with what the sample frame holds. Exits 0 only when every
file agrees.

Usage: check_ours.py <dir>   (the directory interop.zig filled with *.arrow)
"""

import decimal
import os
import struct
import sys

import pyarrow as pa

D = decimal.Decimal
I64 = 2**63 - 1
SCALE = D(10) ** -12


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


# (name, pyarrow type string, python values; temporal columns are compared as
# their integer storage through a cast)
EXPECT = [
    ("i64", "int64", [1, -2, None, 4, I64]),
    ("f64", "double", [1.5, None, -2.25, 1e300, None]),
    ("b", "bool", [True, False, None, True, True]),
    ("dec", "decimal128(31, 12)", [D("123.45"), D(-1) * SCALE, None, D(I64), D(7) * SCALE]),
    ("s", "string", ["a", "", "héllo", None, "z"]),
    ("bin", "binary", [b"\x00\xff", None, b"", b"bytes", b"\x80"]),
    ("d", "date32[day]", ["2024-02-29", "1970-01-01", None, "0001-01-01", "9999-12-31"]),
    ("ts", "timestamp[us, tz=Europe/Prague]", [0, 1_700_000_000_000_000, -1, None, 86_400_000_000]),
    ("ts_naive", "timestamp[us]", [5, 6, 7, 8, 9]),
    ("dur", "duration[us]", [-1_000_000, 0, 3_600_000_000, None, 1]),
    ("tm", "time64[us]", [0, 86_399_999_999, 43_200_000_000, None, 1]),
    ("cat", "dictionary<values=string, indices=int32, ordered=0>", ["c", "a", "b", None, "c"]),
    ("ord", "dictionary<values=string, indices=int32, ordered=1>", ["lo", "hi", "mid", "mid", "lo"]),
    ("i8", "int8", [-128, 127, None, 1, -1]),
    ("i16", "int16", [-32768, 32767, 0, 1, -1]),
    ("i32", "int32", [-(2**31), 2**31 - 1, 0, 1, -1]),
    ("u8", "uint8", [None, 255, 1, 2, 3]),
    ("u16", "uint16", [0, 65535, 1, 2, 3]),
    ("u32", "uint32", [0, 2**32 - 1, 1, 2, 3]),
    ("u64", "uint64", [0, 2**64 - 1, 2**63, 2, None]),
    ("f32", "float", [0.25, -1.5, f32(3.0e38), 0.0, 1.0]),
    ("l", "list<item: int64>", [[10, 11], None, [], [12, None, 14], [15]]),
    ("arr", "fixed_size_list<item: double>[2]", [[0.5, 1.5], [2.5, 3.5], None, [4.5, 5.5], [6.5, 7.5]]),
    ("st", "struct<a: int64, b: string>", [{"a": 1, "b": "x"}, None, {"a": 3, "b": ""}, {"a": 4, "b": "yy"}, {"a": None, "b": "z"}]),
    ("lcat", "list<item: dictionary<values=string, indices=int32, ordered=0>>", [["q"], [], ["p", "q"], [], None]),
    ("nul", "string", [None] * 5),  # declared text over .nulls storage: Utf8, every row null
]

import datetime

EPOCH = datetime.date(1970, 1, 1)


def day_value(s):
    if s is None:
        return None
    return datetime.date.fromisoformat(s)


def column_values(col):
    t = col.type
    if pa.types.is_temporal(t) and not pa.types.is_date(t):
        return col.cast(pa.int64()).to_pylist()
    return col.to_pylist()


def check(path):
    with open(path, "rb") as f:
        head = f.read(6)
    if head == b"ARROW1":
        table = pa.ipc.open_file(path).read_all()
    else:
        table = pa.ipc.open_stream(path).read_all()
    problems = []
    if table.num_rows != 5:
        problems.append(f"rows {table.num_rows}")
    if table.schema.names != [e[0] for e in EXPECT]:
        problems.append(f"names {table.schema.names}")
        return problems
    for name, typ, want in EXPECT:
        col = table.column(name)
        if str(col.type) != typ:
            problems.append(f"{name}: type {col.type}, expected {typ}")
            continue
        if name == "d":
            want = [day_value(x) for x in want]
        got = column_values(col)
        if name == "dec":
            want = [None if w is None else w for w in want]
        if got != want:
            problems.append(f"{name}: {got!r} != {want!r}")
    return problems


def main():
    d = sys.argv[1]
    names = sorted(n for n in os.listdir(d) if n.endswith(".arrow"))
    if not names:
        print("no files", file=sys.stderr)
        return 2
    bad = 0
    for n in names:
        problems = check(os.path.join(d, n))
        if problems:
            bad += 1
            print(f"FAIL {n}", file=sys.stderr)
            for p in problems:
                print("   ", p, file=sys.stderr)
        else:
            print(f"ok   {n}")
    print(f"pyarrow {pa.__version__}: {len(names) - bad}/{len(names)} files agree")
    return 1 if bad else 0


sys.exit(main())
