#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for csvstream: Python's `csv` and Go's `encoding/csv`,
both black boxes, as readers and as writers.

Writes `src/oracle_vectors.zig`, replayed by `src/oracle_test.zig` with no
Python and no Go at test time:

    python3 modules/csvstream/tools/oracle.py > modules/csvstream/src/oracle_vectors.zig
    python3 modules/csvstream/tools/oracle.py --check   # re-take, compare with the committed file
    python3 modules/csvstream/tools/oracle.py --dialect [--check] > modules/csvstream/src/oracle_dialect_vectors.zig

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


def gen_escape_docs(rnd):
    """Documents whose escape bytes all lie INSIDE quoted fields: Python's
    `escapechar` also escapes outside quotes, this module's (rust-csv's) does
    not, so inputs stay where the two are meant to agree."""
    qpieces = ['a', ',', ' ', '\\"', '\\\\', '\\a', '\\,', '\n', 'é']
    docs = []
    for _ in range(300):
        recs = []
        for _ in range(rnd.randint(1, 3)):
            fields = []
            for _ in range(rnd.randint(1, 4)):
                if rnd.random() < 0.6:
                    fields.append('"' + ''.join(rnd.choice(qpieces) for _ in range(rnd.randint(0, 4))) + '"')
                else:
                    fields.append(''.join(rnd.choice(['a', 'b', ' ']) for _ in range(rnd.randint(0, 3))))
            recs.append(','.join(fields))
        docs.append('\n'.join(recs) + ('\n' if rnd.random() < 0.5 else ''))
    return docs


def py_read(text, **kw):
    try:
        return [row for row in csv.reader(io.StringIO(text, newline=''), **kw)]
    except csv.Error:
        return None


def zanswer(recs, asked=True):
    if not asked:
        return '.none'
    if recs is None:
        return '.err'
    return '.{ .ok = ' + zrecords(recs) + ' }'


def generate_dialect():
    rnd = random.Random(SEED + 1)
    small = [''.join(p) for n in range(1, 5) for p in itertools.product(['a', ',', '"', ' ', '#', '\n'], repeat=n)]
    crafted = ['# c "x\na,b', 'a,b\n#,c\n', ' "a,b", c', '  a ,  "b"', '"a"b', 'a"b', '"a', 'a,"b"c', '"a""b"',
               '"a"\n"b"', '#\n#\n', 'x\n # y\n', '"a\nb",c', ' ', ' ,', '" a"', '"a" ,b']
    cases = []  # (dialect, text)
    for v in crafted + small:
        for d in ('comment', 'trim', 'strict'):
            cases.append((d, v))
    for v in gen_escape_docs(rnd):
        cases.append(('escape', v))
    go_flags = {'comment': 'comment', 'trim': 'trim', 'strict': 'strict'}
    reqs = [f'D {go_flags[d]} ' + v.encode().hex() for d, v in cases if d in go_flags]
    ans = iter(ask_go(reqs))
    rows = gen_rows(rnd)
    out = []
    w = out.append
    goversion = subprocess.run(['go', 'env', 'GOVERSION'], capture_output=True, text=True, check=True).stdout.strip()
    w('// SPDX-License-Identifier: MIT\n')
    w(f'// GENERATED by modules/csvstream/tools/oracle.py --dialect (Python {platform.python_version()}, {goversion}) -- do not hand-edit.\n')
    w('//! Python `csv` and Go `encoding/csv` answers under the dialect options this module also has,\n')
    w('//! replayed by `oracle_dialect_test.zig`. Go: `Comment = \'#\'` / `TrimLeadingSpace` / `LazyQuotes = false`;\n')
    w('//! Python: `skipinitialspace=True` (trim) / `escapechar=\'\\\\\', doublequote=False` (escape).\n\n')
    w('pub const Answer = union(enum) { none, err, ok: []const []const []const u8 };\n')
    w('pub const Dialect = enum { comment, trim, strict, escape };\n')
    w('pub const ReadCase = struct { dialect: Dialect, text: []const u8, py: Answer, go: Answer };\n')
    w('/// `fields` written by Python as one record, QUOTE_ALL, LF: plain (`all`) and with\n')
    w('/// `escapechar=\'\\\\\', doublequote=False` (`all_escaped`).\n')
    w('pub const WriteCase = struct { fields: []const []const u8, all: []const u8, all_escaped: []const u8 };\n\n')
    w('pub const reads = [_]ReadCase{\n')
    for d, v in cases:
        py = zanswer(None, False)
        go = zanswer(None, False)
        if d == 'trim':
            py = zanswer(py_read(v, skipinitialspace=True))
        if d == 'escape':
            py = zanswer(py_read(v, escapechar='\\', doublequote=False))
        if d in go_flags:
            go = zanswer(decode_go_records(next(ans)))
        w(f'    .{{ .dialect = .{d}, .text = {zstr(v)}, .py = {py}, .go = {go} }},\n')
    w('};\n\npub const writes = [_]WriteCase{\n')
    for row in rows:
        b1 = io.StringIO(newline='')
        csv.writer(b1, lineterminator='\n', quoting=csv.QUOTE_ALL).writerow(row)
        b2 = io.StringIO(newline='')
        csv.writer(b2, lineterminator='\n', quoting=csv.QUOTE_ALL, escapechar='\\', doublequote=False).writerow(row)
        w(f'    .{{ .fields = {zlist(zstr(f) for f in row)}, .all = {zstr(b1.getvalue())}, .all_escaped = {zstr(b2.getvalue())} }},\n')
    w('};\n')
    return ''.join(out)


def main():
    dialect = '--dialect' in sys.argv
    text = generate_dialect() if dialect else generate()
    name = 'oracle_dialect_vectors.zig' if dialect else 'oracle_vectors.zig'
    if '--check' in sys.argv:
        with open(os.path.join(HERE, '..', 'src', name)) as f:
            if f.read() != text:
                sys.exit(f'{name} is stale: Python, Go or the case tables moved -- regenerate and re-judge the divergences')
        print(f'{name} is fresh')
        return
    sys.stdout.write(text)


if __name__ == '__main__':
    main()
