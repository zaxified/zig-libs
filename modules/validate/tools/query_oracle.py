#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for validate's query decoding and string coercion.

`validateQuery` / `parseQueryLeaky` / `validateParams` take text, not JSON:
a query string is split and percent-decoded, and each value is coerced to the
rule's kind before the shared checks run. This script anchors both steps on
foreign implementations and writes `src/query_oracle_vectors.zig`, replayed by
`src/query_oracle_test.zig` with no Python, Go or bun at test time:

    PY=~/.local/share/zig-libs/oracle-venvs/fastapi/bin/python
    $PY modules/validate/tools/query_oracle.py > modules/validate/src/query_oracle_vectors.zig
    $PY modules/validate/tools/query_oracle.py --check   # re-take, compare with the committed file

Decoding (query string -> the first value of a field, as bytes) is judged by
three parsers: Python's `urllib.parse.parse_qsl` (bytes in, bytes out), Go's
`net/url.ParseQuery` (tools/go_query) and the WHATWG `URLSearchParams` (bun,
tools/urlsearchparams.js). Coercion and constraints (decoded bytes -> accepted,
or the first error code) are judged by pydantic in lax mode -- the model the
module names for its codes -- fed the very bytes the module decodes; Go's
strconv/math.big grammar and Python's own `int()`/`float()` are recorded
beside it as the tie-breakers for a class.

Needs pydantic (the FastAPI oracle venv has it), `go` and `bun`. No network.
Where `want` is not pydantic's answer (coercion) or the parsers' common answer
(decoding), the case carries the class that decided it (see CLASSES).
"""
import base64
import enum
import json
import math
import os
import platform
import subprocess
import sys
from typing import Annotated
from urllib.parse import parse_qsl, quote_from_bytes

import pydantic
from pydantic import Field, TypeAdapter, ValidationError

HERE = os.path.dirname(os.path.abspath(__file__))

CLASSES = {
    'PYDANTIC_STRIPS': 'pydantic strips whitespace around an int/float (` 5`, `1.5 `); Go\'s strconv and the JSON '
                       'number grammar refuse it, and so does the module -- Go decides',
    'INT_FRACTION': 'pydantic takes `5.0` as an int (a zero fraction); Go\'s strconv and Python\'s `int()` refuse '
                    'it, and so does the module, whose typed query decodes ints with an integer parser -- Go and '
                    'Python decide',
    'F64_PRECISION': 'an integer past 2^53 against a bound: pydantic compares exactly, the module in doubles '
                     '(`Rule.min`/`max` are f64, documented) -- the double comparison decides',
    'GO_DROPS_BAD_ESCAPE': "Go's ParseQuery drops a pair with a malformed escape (`%zz`, `%4`, a lone `%`); "
                           'Python and WHATWG keep it literally, and so does the module (documented: lenient, '
                           'like most parsers) -- Python and WHATWG decide',
    'GO_DROPS_SEMICOLON': "Go's ParseQuery drops a pair holding `;` (Go 1.17, CVE-2021-44716 hardening); Python "
                          '3.10+ and WHATWG split on `&` only and keep it -- Python and WHATWG decide',
    'WHATWG_REPLACES': 'WHATWG decodes the bytes as UTF-8 with replacement (`%ff` -> U+FFFD); Python and Go hand '
                       'over the raw bytes, and so does the module, whose string coercion then judges UTF-8 -- '
                       'Python and Go decide',
}

# ── coercion: one rule, one value, query `v=<every byte escaped>` ────────────

U64_MAX = 18446744073709551615
I64_MIN, I64_MAX = -9223372036854775808, 9223372036854775807

RULES = [
    {'kind': 'int'},
    {'kind': 'int', 'min': 0, 'max': 100},
    {'kind': 'int', 'min': I64_MIN, 'max': I64_MAX},
    {'kind': 'int', 'min': 0, 'max': U64_MAX},
    {'kind': 'float'},
    {'kind': 'float', 'min': 0, 'max': 100},
    {'kind': 'bool'},
    {'kind': 'string'},
    {'kind': 'string', 'min_len': 1},
    {'kind': 'string', 'max_len': 2},
    {'kind': 'string', 'one_of': ['a', 'é']},
    {'kind': 'string', 'charset': 'ab'},
]

INT_VALS = ['0', '5', '-5', '+5', '-0', '00012', ' 5', '5 ', '\t5', '1_000', '1__0', '_1', '1_', '5.0', '5.00',
            '5.5', '1e3', '1.0e2', '0x10', '0b1', '99999999999999999999', '-99999999999999999999',
            '9223372036854775807', '9223372036854775808', '-9223372036854775808', '-9223372036854775809',
            '18446744073709551615', '18446744073709551616', '', '-', '+', '٣', '５', 'nan', 'inf', '100',
            '101']
FLOAT_VALS = ['0', '1.5', '-1.5', '+1', '.5', '5.', '1e2', '1E2', '1e-2', '1e400', '-1e400', '1e-400', 'nan',
              'NaN', '-nan', 'inf', '-inf', 'Infinity', 'infinity', 'INF', '0x1p3', '0x10', '1_0.5', '1__0',
              '1_000', ' 1.5', '1.5 ', '', '.', 'e5', '1e', '1.5.5', '100', '100.0000000000001', '101', '-0.0',
              '٣']
BOOL_VALS = ['true', 'True', 'TRUE', 'tRuE', 'false', 'False', '1', '0', 'on', 'off', 'yes', 'no', 't', 'f', 'y',
             'n', 'T', 'F', '', '2', ' true', 'true ', '01', '00']
STR_VALS = [b'', b'a', b'ab', b'abc', 'é'.encode(), 'éé'.encode(), 'ééé'.encode(), b'\xff', b'a\xff', b'\xc3',
            b'\xed\xa0\x80', b'\xc0\xaf', b'a\n', b'\x00', b' a', b'b', b'ba', b'c']


def values_for(kind):
    if kind == 'int':
        return [v.encode() for v in INT_VALS]
    if kind == 'float':
        return [v.encode() for v in FLOAT_VALS]
    if kind == 'bool':
        return [v.encode() for v in BOOL_VALS]
    return STR_VALS


def pydantic_type(rule):
    k = rule['kind']
    if k == 'int':
        return Annotated[int, Field(ge=rule.get('min'), le=rule.get('max'))]
    if k == 'float':
        return Annotated[float, Field(ge=rule.get('min'), le=rule.get('max'))]
    if k == 'bool':
        return bool
    pat = '^[' + rule['charset'] + ']*$' if 'charset' in rule else None
    return Annotated[str, Field(min_length=rule.get('min_len'), max_length=rule.get('max_len'), pattern=pat)]


def pydantic_verdict(rule, raw):
    """(ok, first error type) for `raw` (bytes) against the rule, lax mode."""
    try:
        v = TypeAdapter(pydantic_type(rule)).validate_python(raw)
        if 'one_of' in rule:
            E = enum.Enum('E', {f'm{i}': s for i, s in enumerate(rule['one_of'])}, type=str)
            TypeAdapter(E).validate_python(v)
        return True, ''
    except ValidationError as e:
        return False, e.errors()[0]['type']


def py_builtin(kind, raw):
    """Python's own int()/float() on the text (what Werkzeug's `type=int` does)."""
    if kind not in ('int', 'float'):
        return None
    try:
        (int if kind == 'int' else float)(raw.decode('utf-8'))
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def coerce_want(rule, raw, py_ok, py_code, go, builtin):
    """(want, want_code, class) for one coercion case."""
    k = rule['kind']
    if k in ('int', 'float') and py_ok and raw != raw.strip() and go is False:
        return False, k + '_parsing', 'PYDANTIC_STRIPS'
    if k == 'int' and py_ok and go is False and builtin is False:
        return False, 'int_parsing', 'INT_FRACTION'
    if k == 'int' and py_code in ('greater_than_equal', 'less_than_equal'):
        n = float(int(raw.decode()))
        if float(rule.get('min', -math.inf)) <= n <= float(rule.get('max', math.inf)):
            return True, '', 'F64_PRECISION'
    return py_ok, py_code, ''


# ── decoding: query strings, rule `v` string, the first value as bytes ──────

DECODE_QUERIES = [
    'v=a', 'v=a&v=b', 'v=&v=b', 'w=1&v=2', 'v', 'v=', '&&v=x&&', 'v=a=b', 'v=%41', 'v=%4', 'v=%', 'v=%zz',
    'v=%%41', 'v=%4g', 'v=a+b', 'v=a%2Bb', 'v=a%20b', '%76=x', 'v%3D=x', '+v=x', 'v+=x', 'V=x', 'v=x;w=y',
    'v;w=x', 'v=%00', 'v=%ff', 'v=%e2%82%ac', 'v=%E2%82%AC', 'v=é', 'v=%c3', '%zz=1&v=2', 'v=1&%zz=2',
    'v=a#b', 'v==', 'v=%3D', '=v&v=y', 'vv=1&v=2', 'v=1&vv=2', '',
]


def py_decode(query):
    for k, val in parse_qsl(query.encode(), keep_blank_values=True):
        if k == b'v':
            return val
    return None


def decode_want(query, py, go, whatwg):
    if py == go == whatwg:
        return py, ''
    if py == whatwg and go is None:
        return py, 'GO_DROPS_SEMICOLON' if ';' in query else 'GO_DROPS_BAD_ESCAPE'
    if py == go and whatwg is not None and b'\xef\xbf\xbd' in whatwg:
        return py, 'WHATWG_REPLACES'
    return None, 'UNDECIDED'


def run_go(reqs):
    proc = subprocess.run(['go', 'run', '.'], cwd=os.path.join(HERE, 'go_query'), check=True,
                          input=''.join(json.dumps(r) + '\n' for r in reqs), capture_output=True, text=True)
    return [json.loads(line) for line in proc.stdout.splitlines()]


def run_bun(reqs):
    proc = subprocess.run(['bun', os.path.join(HERE, 'urlsearchparams.js')], check=True,
                          input=json.dumps(reqs), capture_output=True, text=True)
    return [None if h is None else bytes.fromhex(h) for h in json.loads(proc.stdout)]


def tool_version(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.split()[2 if cmd[0] == 'go' else 0]


# ── Zig output ───────────────────────────────────────────────────────────────

def zstr(b):
    if isinstance(b, str):
        b = b.encode()
    out = []
    for c in b:
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5c:
            out.append('\\\\')
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append('\\x%02x' % c)
    return '"' + ''.join(out) + '"'


def zopt_bool(v):
    return 'null' if v is None else ('true' if v else 'false')


def zopt_str(b):
    return 'null' if b is None else zstr(b)


def zf64(x):
    return repr(float(x))


def zrule(rule):
    parts = ['.field = "v"', '.kind = .' + rule['kind']]
    for k in ('min', 'max'):
        if k in rule:
            parts.append(f'.{k} = {zf64(rule[k])}')
    for k in ('min_len', 'max_len'):
        if k in rule:
            parts.append(f'.{k} = {rule[k]}')
    if 'one_of' in rule:
        parts.append('.one_of = &.{ ' + ', '.join(zstr(s) for s in rule['one_of']) + ' }')
    if 'charset' in rule:
        parts.append('.pattern = .{ .charset = ' + zstr(rule['charset']) + ' }')
    return '.{ ' + ', '.join(parts) + ' }'


def generate():
    # Coercion cases.
    coerce = []
    for ri, rule in enumerate(RULES):
        for raw in values_for(rule['kind']):
            coerce.append((ri, rule, raw))
    go = run_go([{'query': 'v=' + quote_from_bytes(raw, safe=''), 'field': 'v', 'kind': rule['kind']}
                 for _, rule, raw in coerce])
    # Decoding cases.
    go_dec = run_go([{'query': q, 'field': 'v', 'kind': 'string'} for q in DECODE_QUERIES])
    bun_dec = run_bun([{'query': q, 'field': 'v'} for q in DECODE_QUERIES])

    o = []
    o.append('// SPDX-License-Identifier: MIT')
    o.append(f'// GENERATED by modules/validate/tools/query_oracle.py (Python {platform.python_version()}, '
             f'pydantic {pydantic.VERSION}, {tool_version(["go", "version"])}, bun {tool_version(["bun", "--version"])}) '
             '-- do not hand-edit.')
    o.append('//! Query decoding and value coercion verdicts, replayed by `query_oracle_test.zig`.')
    o.append('//! Regenerate with the command in the script\'s docstring.')
    o.append('')
    o.append('const Rule = @import("root.zig").Rule;')
    o.append('')
    o.append('/// One rule against query `v=<value, every byte escaped>`. `py`: pydantic (lax) accepts the')
    o.append('/// decoded bytes, `py_code` its first error type; `go`: strconv/math.big parse the text (null:')
    o.append('/// no grammar for the kind); `builtin`: Python `int()`/`float()`. `want`/`want_code`: what')
    o.append('/// `validateQuery` must answer; `class` names the rule that decided it when not pydantic.')
    o.append('pub const Coerce = struct { rule: u8, value: []const u8, py: bool, py_code: []const u8, go: ?bool, '
             'builtin: ?bool, want: bool, want_code: []const u8, class: []const u8 };')
    o.append('')
    o.append('/// The first value of field `v` each parser decodes from `query` (null: absent). `want`: what')
    o.append('/// the module must decode; `class` names the rule that decided it when the parsers split.')
    o.append('pub const Decode = struct { query: []const u8, py: ?[]const u8, go: ?[]const u8, '
             'whatwg: ?[]const u8, want: ?[]const u8, class: []const u8 };')
    o.append('')
    o.append('pub const classes = [_][]const u8{ ' + ', '.join(zstr(c) for c in CLASSES) + ' };')
    o.append('')
    o.append('pub const rules = [_]Rule{')
    for rule in RULES:
        o.append('    ' + zrule(rule) + ',')
    o.append('};')
    o.append('')
    o.append('pub const coerce = [_]Coerce{')
    for (ri, rule, raw), g in zip(coerce, go):
        ok, code = pydantic_verdict(rule, raw)
        want, want_code, cls = coerce_want(rule, raw, ok, code, g['coerce'], py_builtin(rule['kind'], raw))
        o.append(f'    .{{ .rule = {ri}, .value = {zstr(raw)}, .py = {zopt_bool(ok)}, .py_code = {zstr(code)}, '
                 f'.go = {zopt_bool(g["coerce"])}, .builtin = {zopt_bool(py_builtin(rule["kind"], raw))}, '
                 f'.want = {zopt_bool(want)}, .want_code = {zstr(want_code)}, .class = {zstr(cls)} }},')
    o.append('};')
    o.append('')
    o.append('pub const decode = [_]Decode{')
    for q, g, w in zip(DECODE_QUERIES, go_dec, bun_dec):
        p = py_decode(q)
        gv = bytes.fromhex(g['value']) if g['present'] else None
        want, cls = decode_want(q, p, gv, w)
        o.append(f'    .{{ .query = {zstr(q)}, .py = {zopt_str(p)}, .go = {zopt_str(gv)}, .whatwg = {zopt_str(w)}, '
                 f'.want = {zopt_str(want)}, .class = {zstr(cls)} }},')
    o.append('};')
    return '\n'.join(o) + '\n'


def main():
    out = generate()
    if '--check' in sys.argv[1:]:
        path = os.path.join(HERE, '..', 'src', 'query_oracle_vectors.zig')
        with open(path) as f:
            if f.read() != out:
                sys.exit('query_oracle: src/query_oracle_vectors.zig is stale -- regenerate it')
        print('query_oracle: vectors match')
        return
    sys.stdout.write(out)


if __name__ == '__main__':
    main()
