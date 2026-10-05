# `csvstream` verification instruments

One differential oracle, run by hand; its answers are frozen in
`src/oracle_vectors.zig` and replayed by `src/oracle_test.zig` in the module's
own lane, with no Python and no Go (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `oracle.py` | Writes the vectors: Python's `csv` (reader, and `csv.writer` QUOTE_MINIMAL/CRLF) answering this module's own inputs, plus Go's answers through `go/`. |
| `go/main.go` | Go's `encoding/csv` (`LazyQuotes`, any field count; writer with `UseCRLF`), stdlib only — every record, where it starts (`FieldPos(0)`), and the bytes it writes. |

```bash
python3 modules/csvstream/tools/oracle.py > modules/csvstream/src/oracle_vectors.zig
python3 modules/csvstream/tools/oracle.py --check   # re-take, compare with the committed file
```

Needs `go` on PATH; `GOPROXY=off` keeps it offline.

**Inputs** (2026-10-05, Python 3.14.4, go1.26.0): a crafted hostile table, every
string up to length 4 over `a , " CR LF SP` (1555), and 250 generated multi-record
documents with quoted delimiters, quotes and line breaks — 1833 reads; 309 field
lists written.

**What the replay holds** (span mode, `trailing_empty_field = true`): 767 inputs
where all three agree, 124 read as Python reads them where Go differs (Go drops the
CR of a CRLF inside a quoted field), 820 as Go reads them where Python differs (the
Go-`LazyQuotes` quote model this module follows, a bare CR), 107 where a quote is
left open to the end of input (Python and Go take the rest of the input into the
field; span mode ends the record at its line break and sets `unbalanced_quote`), 15
that combine Go's blank-line skipping with Python's CRLF content. 1882 record start
offsets equal Go's `FieldPos(0)`. Every written record is Python's bytes, Go reads
them back as the fields (modulo its CRLF normalization), and so does this module.

This replaces the 2026-09-17 three-reader comparison (`gen.py`/`compare.py`/
`dump.zig`, 146 one-line vectors, measured but not frozen).
