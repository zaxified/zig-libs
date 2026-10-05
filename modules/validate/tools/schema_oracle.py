#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for validate's rule semantics and its JSON Schema export.

A rule set means two things: what `validateJson` answers, and the JSON Schema
2020-12 document `writeJsonSchema` exports for it. This script generates rule
sets and documents from a fixed seed, writes the schema each set must export
(the mapping documented above `writeJsonSchema` in src/root.zig), and asks two
independent 2020-12 validators -- python-jsonschema and ajv 8 under bun, both
black boxes -- for their verdict on every document. Writes
`src/schema_oracle_vectors.zig`, replayed by `src/schema_oracle_test.zig` with
no Python and no bun at test time:

    python3 modules/validate/tools/schema_oracle.py > modules/validate/src/schema_oracle_vectors.zig
    python3 modules/validate/tools/schema_oracle.py --check   # re-take, compare with the committed file

Needs `bun` on PATH with ajv@8.20.0 in its cache (see tools/ajv_verdicts.js)
and the `jsonschema` package. No network.

`format` is left out: its vocabulary is anchored on the official
JSON-Schema-Test-Suite (src/json_schema_format_test.zig), and validators
differ there by profile, not by the semantics tested here. `custom` and
`Pattern.matcher` are code and have no schema form.

Where the two validators disagree, or where the module departs from the
schema by design, `want` is decided here and the case carries the class
that decided it (see CLASSES); every other case must get both validators'
common answer.
"""
import json
import math
import os
import platform
import random
import subprocess
import sys

import jsonschema
from importlib.metadata import version as pkg_version

SEED = 202012
N_SETS = 300
DOCS_PER_SET = 7
HERE = os.path.dirname(os.path.abspath(__file__))

KINDS = ['string', 'int', 'float', 'bool', 'array', 'object', 'any']
NAMES = ['a', 'b', 'c', 'id', 'x.y', 'é']
STRINGS = ['', 'a', 'ab', 'abc', 'abcd', 'abcde', 'é', 'éé', 'ééé', '😀', 'a😀', '😀😀😀', 'x\n', 'ab\n',
           'red', 'green', 'Red', 'a-b', 'a]b', '^a', 'a$', 'a.b', '(a)', 'a/b', 'a\\b', 'â', '¢ü', 'ü¢']
PAT_TEXTS = ['a', 'ab', 'a-b', ']', '^', 'a.b', '(a)', 'a/b', '\\', 'é', '¢ü', 'abc', '[x]', '$', '*']
ENUMS = [['red', 'green'], ['a'], ['', 'a'], ['é', 'e'], ['1', 'true']]
NUMS = [-5, -1, 0, 1, 2, 3, 5, 10, 2.5, -0.5, 9007199254740992, 1e20]
NUM_TOKENS = ['0', '-0', '1', '2', '3', '5', '-1', '-5', '10', '11', '1.0', '2.5', '-0.5', '1e2', '1E1',
              '0.1', '3.0000000000000001', '9007199254740993', '9007199254740992',
              '100000000000000000000000', '-100000000000000000000000', '1e400', '1.5e300']

# Classes: why a case's `want` is not simply the two validators' common answer.
# The first three decide a case the validators split on; the last two are the
# module's documented departures from its own exported schema, applied on top.
CLASSES = {
    'PY_DOLLAR': "python's `re` lets `$` match before a final newline; ECMA-262 (which 2020-12 "
                 "names for `pattern`) does not -- ajv decides",
    'F64_PRECISION': 'an integer beyond 2^53 against a bound: python compares exactly, ajv in doubles, '
                     'and so does the module (`Rule.min`/`max` are f64, documented) -- ajv decides',
    'F64_OVERFLOW': 'a number beyond f64 (`1e400`) as an integer: ajv calls Infinity an integer '
                    '(`Infinity % 1` is NaN, which its check reads as no fraction); python and the module '
                    'refuse a non-finite value as an integer -- python decides',
    'BYTES': '`min_bytes`/`max_bytes` export only as annotations plus the code-point bounds they imply, '
             'so the schema is looser there (documented above `writeJsonSchema`) -- refused by the module',
    'LONE_SURROGATE': 'a string escape with an unpaired surrogate (`\\ud800`): std.json refuses the document '
                      '(RFC 8259 8.2 leaves it unpredictable) -- refused by the module',
}


# Crafted rule sets and documents, ahead of the generated ones: each class above
# and each departure the oracle has found gets a case whatever the seed draws.
CRAFTED = [
    ([{'field': 'a', 'kind': 'string', 'pattern': ('suffix', 'a')}], ['{"a":"a\\n"}', '{"a":"a"}']),
    ([{'field': 'a', 'kind': 'string', 'pattern': ('charset', 'ab')}], ['{"a":"ab\\n"}']),
    ([{'field': 'n', 'kind': 'int', 'max': 9007199254740992}], ['{"n":9007199254740993}', '{"n":9007199254740992}']),
    ([{'field': 'n', 'kind': 'int'}], ['{"n":1e400}', '{"n":100000000000000000000000}', '{"n":1e23}',
                                       '{"n":-100000000000000000000000}', '{"n":18446744073709551615}']),
    ([{'field': 'n', 'kind': 'float', 'max': 1e20}], ['{"n":1e400}', '{"n":100000000000000000000}']),
    ([{'field': 'c', 'kind': 'any', 'one_of': ['red', 'green']}],
     ['{"c":"red"}', '{"c":5}', '{"c":true}', '{"c":null}', '{"c":[]}', '{"c":{}}', '{"c":["red"]}']),
    ([{'field': 'c', 'kind': 'any', 'pattern': ('literal', 'x')}], ['{"c":"x"}', '{"c":0}', '{"c":null}', '{"c":{"x":1}}']),
    ([{'field': 'c', 'kind': 'string', 'allow_null': True, 'one_of': ['red', 'green']}], ['{"c":null}', '{"c":"blue"}']),
    ([{'field': 'c', 'kind': 'any', 'allow_null': True, 'one_of': ['a', 'b'], 'pattern': ('literal', 'a')}],
     ['{"c":null}', '{"c":"a"}', '{"c":"b"}', '{"c":1}']),
    ([{'field': 'c', 'kind': 'string', 'allow_null': True, 'pattern': ('literal', 'x')}], ['{"c":null}', '{"c":"y"}']),
    ([{'field': 's', 'kind': 'string', 'max_bytes': 3}], ['{"s":"éé"}', '{"s":"abc"}']),
    ([{'field': 's', 'kind': 'string', 'pattern': ('charset', '¢ü')}], ['{"s":"â"}', '{"s":"ü¢ü"}', '{"s":"ü¼"}']),
    ([{'field': 's', 'kind': 'string'}], ['{"s":"\\ud800"}', '{"s":"\\uD83D\\uDE00"}']),
]


class Tok:
    """A JSON token written verbatim (numbers, raw string escapes)."""
    def __init__(self, text):
        self.text = text


def zstr(s):
    out = ['"']
    for b in s.encode('utf-8', 'surrogatepass'):
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
            out.append('\\x%02x' % b)
    out.append('"')
    return ''.join(out)


# ── rules ────────────────────────────────────────────────────────────────────

def gen_rule(rng, depth, field):
    r = {'field': field, 'kind': rng.choice(KINDS)}
    k = r['kind']
    if rng.random() < 0.5:
        r['required'] = True
    if rng.random() < 0.2:
        r['allow_null'] = True
    if k in ('int', 'float', 'any'):
        if rng.random() < 0.4:
            r['min'] = rng.choice(NUMS)
        if rng.random() < 0.4:
            r['max'] = rng.choice(NUMS)
    if k in ('string', 'array', 'any'):
        if rng.random() < 0.35:
            r['min_len'] = rng.randint(0, 4)
        if rng.random() < 0.35:
            r['max_len'] = rng.randint(0, 4)
    if k in ('string', 'any'):
        if rng.random() < 0.15:
            r['min_bytes'] = rng.randint(1, 6)
        if rng.random() < 0.15:
            r['max_bytes'] = rng.randint(1, 6)
        if rng.random() < 0.2:
            r['one_of'] = rng.choice(ENUMS)
        if rng.random() < 0.3:
            r['pattern'] = (rng.choice(['literal', 'prefix', 'suffix', 'charset']), rng.choice(PAT_TEXTS))
    if k in ('array', 'any') and depth < 2 and rng.random() < 0.5:
        r['items'] = gen_rule(rng, depth + 1, '')
    if k in ('object', 'any') and depth < 2 and rng.random() < 0.5:
        r['fields'] = gen_rules(rng, depth + 1)
    return r


def gen_rules(rng, depth):
    n = rng.randint(1, 3 if depth else 4)
    rules = [gen_rule(rng, depth, rng.choice(NAMES)) for _ in range(n)]
    return rules


def znum(x):
    if isinstance(x, int) or (isinstance(x, float) and x.is_integer() and abs(x) < 2**53):
        return '%d' % x
    return repr(float(x))


def zrule(r):
    parts = ['.field = ' + zstr(r['field']), '.kind = .' + r['kind']]
    for key in ('required', 'allow_null'):
        if r.get(key):
            parts.append('.%s = true' % key)
    for key in ('min', 'max'):
        if key in r:
            parts.append('.%s = %s' % (key, znum(r[key])))
    for key in ('min_len', 'max_len', 'min_bytes', 'max_bytes'):
        if key in r:
            parts.append('.%s = %d' % (key, r[key]))
    if 'one_of' in r:
        parts.append('.one_of = &.{ %s }' % ', '.join(zstr(s) for s in r['one_of']))
    if 'pattern' in r:
        parts.append('.pattern = .{ .%s = %s }' % (r['pattern'][0], zstr(r['pattern'][1])))
    if 'items' in r:
        parts.append('.items = &.{ %s }' % zrule(r['items']))
    if 'fields' in r:
        parts.append('.fields = &.{ %s }' % ', '.join('.{ %s }' % zrule(f) for f in r['fields']))
    return ', '.join(parts)


# ── the export, as documented above `writeJsonSchema` ────────────────────────

def regex(lead, text, tail, cls):
    special = '\\]^-[' if cls else '\\^$.|?*+()[]{}/'
    return lead + ''.join('\\' + c if c in special else c for c in text) + tail


def schema_num(x):
    if isinstance(x, float) and x.is_integer() and abs(x) < 2**53:
        return int(x)
    return x


def rule_schema(r):
    s = {}
    k = r['kind']
    t = {'string': 'string', 'int': 'integer', 'float': 'number', 'bool': 'boolean', 'array': 'array',
         'object': 'object'}.get(k)
    if t:
        s['type'] = [t, 'null'] if r.get('allow_null') else t
    if 'min' in r:
        s['minimum'] = schema_num(r['min'])
    if 'max' in r:
        s['maximum'] = schema_num(r['max'])
    strings = k in ('string', 'any')
    arrays = k in ('array', 'any')
    cands = [v for v in (r.get('min_len'), (r['min_bytes'] + 3) // 4 if 'min_bytes' in r else None) if v is not None]
    min_chars = max(cands) if cands else None
    cands = [v for v in (r.get('max_len'), r.get('max_bytes')) if v is not None]
    max_chars = min(cands) if cands else None
    if strings and min_chars is not None:
        s['minLength'] = min_chars
    if arrays and 'min_len' in r:
        s['minItems'] = r['min_len']
    if strings and max_chars is not None:
        s['maxLength'] = max_chars
    if arrays and 'max_len' in r:
        s['maxItems'] = r['max_len']
    if 'min_bytes' in r:
        s['x-minBytes'] = r['min_bytes']
    if 'max_bytes' in r:
        s['x-maxBytes'] = r['max_bytes']
    literal = r['pattern'][1] if r.get('pattern', ('',))[0] == 'literal' else None
    if r.get('allow_null') and ('one_of' in r or literal is not None):
        allowed = [a for a in r['one_of'] if literal is None or a == literal] if 'one_of' in r else [literal]
        s['enum'] = allowed + [None]
    elif 'one_of' in r:
        s['enum'] = list(r['one_of'])
    if 'pattern' in r:
        how, text = r['pattern']
        if how == 'literal':
            if not r.get('allow_null'):
                s['const'] = text
        elif how == 'prefix':
            s['pattern'] = regex('^', text, '', False)
        elif how == 'suffix':
            s['pattern'] = regex('', text, '$', False)
        else:
            s['pattern'] = regex('^[', text, ']*$', True)
    if k in ('object', 'any') and 'fields' in r:
        fields_members(s, r['fields'])
    if k in ('array', 'any') and 'items' in r:
        s['items'] = rule_schema(r['items'])
    return s


def fields_members(s, rules):
    if not rules:
        return
    props = {}
    for r in rules:
        if r['field'] in props:
            continue
        same = [o for o in rules if o['field'] == r['field']]
        props[r['field']] = rule_schema(r) if len(same) == 1 else {'allOf': [rule_schema(o) for o in same]}
    s['properties'] = props
    req = []
    for r in rules:
        if r.get('required') and r['field'] not in req:
            req.append(r['field'])
    if req:
        s['required'] = req


def set_schema(rules):
    s = {'type': 'object'}
    fields_members(s, rules)
    return s


# ── documents ────────────────────────────────────────────────────────────────

def gen_value(rng, r, depth):
    """A value aimed at rule `r`: mostly its own type near its bounds, sometimes anything."""
    roll = rng.random()
    if roll < 0.08:
        return None
    if roll < 0.25 or r is None:
        return gen_any(rng, depth)
    k = r['kind']
    if k == 'any':
        k = rng.choice(['string', 'int', 'float', 'array', 'object', 'bool'])
    if k == 'string':
        pool = list(STRINGS)
        if 'one_of' in r:
            pool += r['one_of'] * 3
        if 'pattern' in r:
            t = r['pattern'][1]
            pool += [t, t + 'x', 'x' + t, t + t, t + '\n', t[:-1], t.upper()]
        return rng.choice(pool)
    if k in ('int', 'float'):
        pool = list(NUM_TOKENS)
        for key in ('min', 'max'):
            if key in r:
                b = r[key]
                for d in (-1, 0, 1, -0.5, 0.5):
                    pool.append(znum(b + d) if not (isinstance(b, float) and b >= 1e15) else znum(b))
        return Tok(rng.choice(pool))
    if k == 'bool':
        return rng.choice([True, False])
    if k == 'array':
        n = rng.choice([0, 1, 2, 3, 4, 5]) if depth < 3 else 0
        if 'min_len' in r and rng.random() < 0.5:
            n = max(0, r['min_len'] + rng.choice([-1, 0]))
        if 'max_len' in r and rng.random() < 0.5:
            n = r['max_len'] + rng.choice([0, 1])
        return [gen_value(rng, r.get('items'), depth + 1) for _ in range(n)]
    if k == 'object':
        return gen_object(rng, r.get('fields') or [], depth + 1)
    raise AssertionError(k)


def gen_any(rng, depth):
    c = rng.randrange(7)
    if c == 0:
        return rng.choice(STRINGS)
    if c == 1:
        return Tok(rng.choice(NUM_TOKENS))
    if c == 2:
        return rng.choice([True, False])
    if c == 3:
        return None
    if c == 4 and depth < 3:
        return [gen_any(rng, depth + 1) for _ in range(rng.randint(0, 2))]
    if c == 5 and depth < 3:
        return {rng.choice(NAMES): gen_any(rng, depth + 1)}
    if rng.random() < 0.15:
        return Tok('"\\ud800"')
    return Tok(rng.choice(['"a\\u0000b"', '"\\u00e9"', '"\\uD83D\\uDE00"']))


def gen_object(rng, rules, depth):
    o = {}
    for r in rules:
        if r['field'] in o or rng.random() < 0.15:
            continue
        o[r['field']] = gen_value(rng, r, depth)
    if rng.random() < 0.2:
        o['extra'] = gen_any(rng, depth)
    return o


def dump(v):
    if isinstance(v, Tok):
        return v.text
    if v is None or isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return '[' + ','.join(dump(x) for x in v) + ']'
    return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + dump(x) for k, x in v.items()) + '}'


def gen_doc(rng, rules):
    roll = rng.random()
    if roll < 0.04:
        return dump(gen_any(rng, 1))
    return dump(gen_object(rng, rules, 0))


# ── verdicts ─────────────────────────────────────────────────────────────────

def py_verdict(schema, doc):
    try:
        inst = json.loads(doc)
    except ValueError:
        return None
    return jsonschema.Draft202012Validator(schema).is_valid(inst)


def ajv_verdicts(cases):
    lines = ''.join(json.dumps({'schema': s, 'doc': d}) + '\n' for s, d in cases)
    out = subprocess.run(['bun', os.path.join(HERE, 'ajv_verdicts.js')], input=lines, capture_output=True,
                         text=True, check=True).stdout.split('\n')
    ver = out[0]
    res = []
    for v in out[1:1 + len(cases)]:
        res.append(None if v == 'E' else v == '1')
    assert len(res) == len(cases)
    return ver, res


def strict_dollar_validator():
    """Draft 2020-12 with `pattern` read as ECMA-262 reads `$` (end of input only)."""
    import re

    def pattern(validator, patrn, instance, schema):
        if validator.is_type(instance, 'string') and not re.search(patrn.replace('$', '\\Z'), instance):
            yield jsonschema.ValidationError('%r does not match %r' % (instance, patrn))
    return jsonschema.validators.extend(jsonschema.Draft202012Validator, {'pattern': pattern})


STRICT = strict_dollar_validator()


def has_surrogate(v):
    if isinstance(v, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, list):
        return any(has_surrogate(x) for x in v)
    if isinstance(v, dict):
        return any(has_surrogate(k) or has_surrogate(x) for k, x in v.items())
    return False


def has_nonfinite(v):
    if isinstance(v, float):
        return not math.isfinite(v)
    if isinstance(v, list):
        return any(has_nonfinite(x) for x in v)
    if isinstance(v, dict):
        return any(has_nonfinite(x) for x in v.values())
    return False


def bytes_ok(rules, v):
    """False when a `min_bytes`/`max_bytes` the schema cannot state refuses a string in `v`."""
    if not isinstance(v, dict):
        return True
    for r in rules:
        if r['field'] in v and not rule_bytes_ok(r, v[r['field']]):
            return False
    return True


def rule_bytes_ok(r, v):
    k = r['kind']
    if isinstance(v, str) and k in ('string', 'any'):
        n = len(v.encode('utf-8'))
        return not (('min_bytes' in r and n < r['min_bytes']) or ('max_bytes' in r and n > r['max_bytes']))
    if isinstance(v, list) and k in ('array', 'any') and 'items' in r:
        return all(rule_bytes_ok(r['items'], x) for x in v)
    if isinstance(v, dict) and k in ('object', 'any') and 'fields' in r:
        return bytes_ok(r['fields'], v)
    return True


def decide(rules, schema, doc, py, js):
    """`want` and its class for one case."""
    inst = json.loads(doc)
    if has_surrogate(inst):
        return False, 'LONE_SURROGATE'
    cls = ''
    want = py
    if py != js:
        if STRICT(schema).is_valid(inst) == js:
            want, cls = js, 'PY_DOLLAR'
        elif has_nonfinite(inst):
            want, cls = py, 'F64_OVERFLOW'
        elif jsonschema.Draft202012Validator(schema).is_valid(json.loads(doc, parse_int=float)) == js:
            want, cls = js, 'F64_PRECISION'
        else:
            return None, 'UNDECIDED'
    if want and not bytes_ok(rules, inst):
        return False, 'BYTES'
    return want, cls


def main():
    rng = random.Random(SEED)
    sets = [rules for rules, _ in CRAFTED] + [gen_rules(rng, 0) for _ in range(N_SETS)]
    schemas = [set_schema(r) for r in sets]
    cases = []
    for i, (_, docs) in enumerate(CRAFTED):
        cases += [(i, d) for d in docs]
    for i, rules in enumerate(sets[len(CRAFTED):], len(CRAFTED)):
        seen = set()
        for _ in range(DOCS_PER_SET):
            d = gen_doc(rng, rules)
            if d in seen:
                continue
            seen.add(d)
            cases.append((i, d))
    ver, js = ajv_verdicts([(schemas[i], d) for i, d in cases])
    rows = []
    for (i, d), j in zip(cases, js):
        p = py_verdict(schemas[i], d)
        want, cls = decide(sets[i], schemas[i], d, p, j)
        rows.append((i, d, p, j, want, cls))

    o = []
    o.append('// SPDX-License-Identifier: MIT')
    o.append('// GENERATED by modules/validate/tools/schema_oracle.py (Python %s, jsonschema %s, ajv %s, bun %s)'
             ' -- do not hand-edit.' % (platform.python_version(), pkg_version('jsonschema'), ver,
                                       subprocess.run(['bun', '--version'], capture_output=True, text=True).stdout.strip()))
    o.append('//! Rule sets, the schema each must export, and python-jsonschema / ajv verdicts on documents,')
    o.append('//! replayed by `schema_oracle_test.zig`. Regenerate with the command in the script\'s docstring.')
    o.append('')
    o.append('const Rule = @import("root.zig").Rule;')
    o.append('')
    o.append('/// `schema`: the JSON Schema `writeJsonSchema(rules)` must export (compared as JSON values).')
    o.append('pub const RuleSet = struct { rules: []const Rule, schema: []const u8 };')
    o.append('/// `py`/`ajv`: each validator\'s verdict on `doc` against the set\'s schema, null = it refused')
    o.append('/// the document (py) or the schema (ajv). `want`: what `validateJson` must answer; `class`')
    o.append('/// names the rule in tools/schema_oracle.py that decided it when it is not their common answer.')
    o.append('pub const Case = struct { set: u16, doc: []const u8, py: ?bool, ajv: ?bool, want: ?bool, class: []const u8 };')
    o.append('')
    o.append('/// Every class `want` was decided by, as the generator lists them.')
    o.append('pub const classes = [_][]const u8{ %s };' % ', '.join(zstr(c) for c in CLASSES))
    o.append('')
    o.append('pub const sets = [_]RuleSet{')
    for rules, schema in zip(sets, schemas):
        o.append('    .{ .rules = &.{ %s }, .schema = %s },' % (', '.join('.{ %s }' % zrule(r) for r in rules),
                                                             zstr(json.dumps(schema, ensure_ascii=False))))
    o.append('};')
    o.append('')
    o.append('pub const cases = [_]Case{')

    def zb(b):
        return 'null' if b is None else ('true' if b else 'false')
    for i, d, p, j, want, cls in rows:
        o.append('    .{ .set = %d, .doc = %s, .py = %s, .ajv = %s, .want = %s, .class = %s },' % (
            i, zstr(d), zb(p), zb(j), zb(want), zstr(cls)))
    o.append('};')
    text = '\n'.join(o) + '\n'
    # zig fmt's layout, so the committed file passes the pre-commit hook and `--check` compares like with like.
    text = subprocess.run(['zig', 'fmt', '--stdin'], input=text, capture_output=True, text=True, check=True).stdout

    if '--check' in sys.argv:
        path = os.path.join(HERE, '..', 'src', 'schema_oracle_vectors.zig')
        with open(path, encoding='utf-8') as f:
            old = f.read()
        strip = lambda t: t.split('\n', 2)[2]
        if strip(old) != strip(text):
            sys.stderr.write('schema_oracle: committed vectors differ from a fresh run\n')
            sys.exit(1)
        sys.stderr.write('schema_oracle: vectors fresh (%d sets, %d cases)\n' % (len(sets), len(rows)))
        return
    sys.stdout.write(text)
    from collections import Counter
    c = Counter(cls for *_, cls in rows)
    sys.stderr.write('%d sets, %d cases; classes: %s\n' % (len(sets), len(rows), dict(c)))


if __name__ == '__main__':
    main()
