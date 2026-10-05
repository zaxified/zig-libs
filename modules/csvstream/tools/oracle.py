#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for csvstream: Python's `csv` and Go's `encoding/csv`,
both black boxes, as readers and as writers.

Writes `src/oracle_vectors.zig`, replayed by `src/oracle_test.zig` with no
Python and no Go at test time:

    python3 modules/csvstream/tools/oracle.py > modules/csvstream/src/oracle_vectors.zig
    python3 modules/csvstream/tools/oracle.py --check   # re-take, compare with the committed file

Needs `go` on PATH (tools/go is stdlib only; GOPROXY=off keeps it offline).

Reading: every input is read to the end by Python (`csv.reader`, default
dialect) and by Go (`LazyQuotes`, any field count). The inputs are a crafted
hostile table, every string up to length 4 over `a , " CR LF SP`, and
generated multi-record documents with quoted delimiters, quotes and line
breaks.

Writing: generated field lists, written by Python (`csv.writer`,
QUOTE_MINIMAL, CRLF) and by Go (`UseCRLF`); recorded with what Go reads back
from Python's bytes, so the replay can require this module's writer to
produce bytes another implementation reads as the fields written.
"""
import csv
import io
import itertools
import os
import platform
import random
import subprocess
import sys

SEED = 4180
HERE = os.path.dirname(os.path.abspath(__file__))

CRAFTED = [
    'a,b,c', 'a,b,', ',a', 'a,,b', '"a,b",c', '"a""b"', '""', '"",""', 'a,"b"', '"a"b', '"a"b"c', '"a"",b",c',
    'a"b,c', '"unterminated', '"unterminated,x', 'a,"unterminated', '"a""', '"', '""""', '"""', 'a,b"',
    '"a" ,b', ' "a",b', '"a" b,c', 'a,b,"c"', '"",a', ',,', ',', '', 'a', '"a",', '"a",,', '"a,b"c,d', 'x"y"z',
    '"\t",b', '"a\rb",c', 'a\rb,c', 'a,b\r\nc,d\r\n', 'a,b\nc,d\n', '"a\nb",c\nd,e', '"a\r\nb",c\r\n',
    'a\n\nb\n', '\n', '\r\n', 'a,b\r\n\r\nc', '"x"\n"y"', '"a""\nb"', 'é,"ü"', ' a , b ', '"a" , "b"',
]


def records_py(text):
    try:
        return [row for row in csv.reader(io.StringIO(text, newline=''))]
    except csv.Error:
        return None


def gen_docs(rnd):
    pieces = ['a', 'b', 'xy', '', ' ', '"', '""', ',', '\n', '\r\n', 'é']
    docs = []
    for _ in range(250):
        recs = []
        for _ in range(rnd.randint(1, 4)):
            fields = []
            for _ in range(rnd.randint(1, 4)):
                f = ''.join(rnd.choice(pieces) for _ in range(rnd.randint(0, 3)))
                if any(c in f for c in ',"\r\n') or (rnd.random() < 0.2):
                    f = '"' + f.replace('"', '""') + '"'
                fields.append(f)
            recs.append(','.join(fields))
        term = rnd.choice(['\n', '\r\n'])
        docs.append(term.join(recs) + (term if rnd.random() < 0.6 else ''))
    return docs


def gen_rows(rnd):
    pieces = ['a', 'b', ' ', '"', ',', '\n', '\r', '\r\n', 'é', '\t', '\\.', '#', '=']
    rows = [[''], ['', ''], [' a'], ['a '], ['\\.'], ['"'], ['a\nb'], ['a\rb'], [',']]
    for _ in range(300):
        rows.append([''.join(rnd.choice(pieces) for _ in range(rnd.randint(0, 4))) for _ in range(rnd.randint(1, 4))])
    return rows


def ask_go(requests):
    env = dict(os.environ, GOPROXY='off', GOFLAGS='-mod=mod')
    r = subprocess.run(['go', 'run', '.'], cwd=os.path.join(HERE, 'go'), input=''.join(q + '\n' for q in requests),
                       capture_output=True, text=True, env=env, check=True)
    return r.stdout.splitlines()


def decode_go(ans, text=None):
    """(records, record start byte offsets) from one Go answer; None on ERR."""
    if ans == 'ERR':
        return None, None
    body = ans[3:]
    if body == '':
        return [], []
    recs, offs = [], []
    line_starts = None
    if text is not None:
        raw = text.encode('utf-8')
        line_starts = [0] + [i + 1 for i, b in enumerate(raw) if b == 0x0A]
    for rec in body.split(';'):
        pos, fields = rec.split('@', 1)
        recs.append([bytes.fromhex(f[1:]).decode('utf-8') for f in fields.split('|')])
        if line_starts is not None:
            line, col = (int(x) for x in pos.split(':'))
            offs.append(line_starts[line - 1] + col - 1)
    return recs, offs


def decode_go_records(ans):
    return decode_go(ans)[0]


def zstr(s):
    out = ['"']
    for b in s.encode('utf-8'):
        c = chr(b)
        if c == '"':
            out.append('\\"')
        elif c == '\\':
            out.append('\\\\')
        elif c == '\n':
            out.append('\\n')
        elif c == '\r':
            out.append('\\r')
        elif c == '\t':
            out.append('\\t')
        elif 0x20 <= b < 0x7f:
            out.append(c)
        else:
            out.append(f'\\x{b:02x}')
    out.append('"')
    return ''.join(out)


def zlist(items):
    items = list(items)
    if not items:
        return '&.{}'
    if len(items) == 1:
        return '&.{' + items[0] + '}'
    return '&.{ ' + ', '.join(items) + ' }'


def zrecords(recs):
    if recs is None:
        return 'null'
    return zlist(zlist(zstr(f) for f in r) for r in recs)


def generate():
    rnd = random.Random(SEED)
    inputs = []
    seen = set()
    for v in CRAFTED + [''.join(t) for n in range(1, 5) for t in itertools.product(['a', ',', '"', '\r', '\n', ' '], repeat=n)] + gen_docs(rnd):
        if v not in seen:
            seen.add(v)
            inputs.append(v)
    rows = gen_rows(rnd)

    py_written = []
    for row in rows:
        buf = io.StringIO(newline='')
        csv.writer(buf, lineterminator='\r\n').writerow(row)
        py_written.append(buf.getvalue())

    reqs = ['R ' + v.encode().hex() for v in inputs]
    reqs += ['W ' + '|'.join(f.encode().hex() for f in row) for row in rows]
    reqs += ['R ' + w.encode().hex() for w in py_written]
    ans = ask_go(reqs)
    assert len(ans) == len(reqs), (len(ans), len(reqs))
    go_read = [decode_go(a, v) for a, v in zip(ans[:len(inputs)], inputs)]
    go_written = [bytes.fromhex(a).decode('utf-8') for a in ans[len(inputs):len(inputs) + len(rows)]]
    go_reads_py = [decode_go_records(a) for a in ans[len(inputs) + len(rows):]]

    goversion = subprocess.run(['go', 'env', 'GOVERSION'], capture_output=True, text=True, check=True).stdout.strip()
    out = []
    w = out.append
    w('// SPDX-License-Identifier: MIT\n')
    w(f'// GENERATED by modules/csvstream/tools/oracle.py (Python {platform.python_version()}, {goversion}) -- do not hand-edit.\n')
    w('//! Python `csv` and Go `encoding/csv` answers to this module\'s own inputs, replayed by\n')
    w('//! `oracle_test.zig`. Regenerate with the command in the script\'s docstring.\n\n')
    w('/// Every record each reader returned for `text`, read to the end; null = the reader raised.\n')
    w('/// `go_offsets`: the byte offset where Go says each record starts (its FieldPos(0)).\n')
    w('pub const ReadCase = struct { text: []const u8, py: ?[]const []const []const u8, go: ?[]const []const []const u8, go_offsets: []const u32 };\n')
    w('/// `fields` written as one record by Python (QUOTE_MINIMAL, CRLF) and by Go (UseCRLF);\n')
    w('/// `go_reads_py`: the records Go reads back from Python\'s bytes.\n')
    w('pub const WriteCase = struct { fields: []const []const u8, py: []const u8, go: []const u8, go_reads_py: ?[]const []const []const u8 };\n\n')
    w('pub const reads = [_]ReadCase{\n')
    for v, (g, offs) in zip(inputs, go_read):
        w(f'    .{{ .text = {zstr(v)}, .py = {zrecords(records_py(v))}, .go = {zrecords(g)}, .go_offsets = {zlist(str(o) for o in (offs or []))} }},\n')
    w('};\n\npub const writes = [_]WriteCase{\n')
    for row, p, g, back in zip(rows, py_written, go_written, go_reads_py):
        w(f'    .{{ .fields = {zlist(zstr(f) for f in row)}, .py = {zstr(p)}, .go = {zstr(g)}, .go_reads_py = {zrecords(back)} }},\n')
    w('};\n')
    return ''.join(out)


def main():
    text = generate()
    if '--check' in sys.argv:
        with open(os.path.join(HERE, '..', 'src', 'oracle_vectors.zig')) as f:
            if f.read() != text:
                sys.exit('oracle_vectors.zig is stale: Python, Go or the case tables moved -- regenerate and re-judge the divergences')
        print('oracle_vectors.zig is fresh')
        return
    sys.stdout.write(text)


if __name__ == '__main__':
    main()
