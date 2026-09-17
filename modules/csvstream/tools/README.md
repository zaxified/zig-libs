# `csvstream` verification instruments

Three instruments, run by hand. None is wired into `zig build`: `go/` needs a
**foreign toolchain** (Go). `zig build test-csvstream` must require none of it
(`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.
This is the differential-oracle kind: no data is committed, only the recipe and the
two independent readers it is compared against.

Figures below were measured on 2026-09-17 against the tree as it stands (Zig 0.16.0,
Go 1.26.0, Python 3.14.4).

## Three CSV readers over the same ~150 hostile strings

| tool | question it answers |
|---|---|
| `gen.py` | Writes the vectors (`zz_vectors.hex`) and Python's own `csv.reader` verdict on each (`oracle.txt`) — the data recipe. |
| `go/main.go` | The same vectors through Go's `encoding/csv` (`LazyQuotes=true`), one record per input line. |
| `dump.zig` | The same vectors through THIS module's own public API (`LineIterator` + `splitFields`, quote=`"`, delimiter=`,`) — the only one of the three that talks to this repo's code, and only through `@import("csvstream")`'s exports. |
| `compare.py` | Runs the two binaries and loads `oracle.txt`, reports where all three agree and lists what doesn't. |

```bash
W=~/workspace/zig-libs/.zig-cache/o1-csvstream   # scratch, never /tmp
mkdir -p "$W" && cd "$W"
python3 <repo>/modules/csvstream/tools/gen.py

mkdir -p go && cp <repo>/modules/csvstream/tools/go/{main.go,go.mod} go/
( cd go && GOCACHE="$W/go-cache" go build -o oracle . )

zig build-exe -O ReleaseFast --dep csvstream \
    --cache-dir "$W/zc" -femit-bin="$W/dump" \
    -Mmain=<repo>/modules/csvstream/tools/dump.zig \
    -Mcsvstream=<repo>/modules/csvstream/src/root.zig

GOBIN="$W/go/oracle" ZIGBIN="$W/dump" python3 <repo>/modules/csvstream/tools/compare.py "$W"
```

**Measured 2026-09-17, 146 vectors:**

```
python multi-row flag == this module's multi-record flag: 145/146
this module's first record == Go's first record (always comparable): 117/146
Python single-row fields == this module's first record: 105/146
all three agree (single-row cases only): 104/146
rows not in the three-way-agree bucket: 42
```

**41 of the 42 divergent rows are deviations this module's own SPEC.md and
`line.zig` already document as deliberate; the 42nd is the empty input** — this run
is new evidence for existing decisions, not a new finding (counted from `-v` output:
28 + 12 + 1 + 1):

1. **Trailing delimiter does not emit a final empty field.** `"a,b,"` → Python
   `[a,b,'']`, Go `[a,b,'']`, this module `[a,b]` (2 fields, not 3). SPEC.md
   "Backlog / deferred" already lists this as deferred strict-mode item (b); 28 of
   the 42 rows are this case alone (any vector ending in a bare delimiter), and it
   is the one place this module disagrees with BOTH other readers, not just Python.
2. **Junk after a closing quote is a literal quote character, Go-`LazyQuotes` style,
   not silently merged like Python's `csv`.** `"a"b` → Python `ab` (2 bytes), Go and
   this module both `a"b` (3 bytes, quote kept literal). `line.zig`'s own comment
   names this as modelled on Go's `LazyQuotes` rule; 12 rows are this case, and on every one of them this module agrees with Go and differs from
   Python — the design choice working as documented, not a bug.
3. **A bare `\r` (no `\n`) ends a Python row but not a record in this module.**
   `a\rb,c` → Python sees two rows (`MULTIROW`), this module and Go both see one
   record with a literal `\r` inside the first field. The single
   multi-row-flag disagreement above is this vector; SPEC.md's "Deliberate RFC 4180
   deviation" already documents "a `\n` always ends a record" without claiming `\r`
   does, so this is confirmation, not news.
4. **Empty input.** Go's reader reports `EOF` as an error, Python yields nothing and
   this module yields zero records — no reader is wrong, the comparison has no common
   verdict to hold.

Run `python3 compare.py -v` for the full per-vector table.
