#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential oracle for the rule vocabulary against go-playground/validator v10.30.5.

`format_oracle.py` covers the `Format` values. This one covers the tags that take a
parameter or combine others, each mapped by hand to the `Rule` that means it: `contains`,
`excludes`, `startsnotwith`, `ne`, `oneofci`, `noneof`, `eq_ignore_case`, `gt`, `lt`, `omitempty`,
`omitzero`, `|`. Go judges every value through `validate.Var(v, tag)` (`go_formats/`); the
verdicts are frozen in `src/go_rule_vectors.zig`, replayed by `src/go_rule_test.zig` on the
tree and the streaming path, with no Go at test time.

    python3 modules/validate/tools/rule_oracle.py > modules/validate/src/go_rule_vectors.zig
    python3 modules/validate/tools/rule_oracle.py --check

A difference from Go is an error here unless a named class in CLASSES decides it.
"""
import base64
import json
import os
import random
import subprocess
import sys
import unicodedata

SEED = 20261105
HERE = os.path.dirname(os.path.abspath(__file__))

# A class names a documented difference; a case in it holds the module's answer.
CLASSES = {}

FOLD = ['K', 'k', 'K', 's', 'S', 'ſ', 'Σ', 'σ', 'ς', 'ß', 'ẞ', 'ss', 'SS', 'é', 'É',
        'İ', 'ı', 'i', 'I', 'Ǆ', 'ǅ', 'ǆ', 'µ', 'μ', 'Μ', 'Å', 'Å', 'å']
STRINGS = ['', 'a', 'ab', 'abc', 'abcd', 'AB', 'aB', 'xaby', 'xy', 'é', 'aé', 'É', 'e', '😀', 'a😀', 'red', 'RED', 'Red', 'green',
           'blue', 'x', 'bab', 'ba', ' ', 'a b', '123', 'abc123', '#fff', 'rgb(1,2,3)'] + FOLD
INTS = ['0', '1', '4', '5', '6', '7', '-1', '-5', '-6', '10', '100']
FLOATS = ['0', '0.5', '2.4', '2.5', '2.6', '-2.5', '1000000']

# (go tag, Zig rule fields); `s` string values, `i` integers, `f` floats.
TAGS = [
    ('s', 'contains=ab', '.pattern = .{ .contains = "ab" }'),
    ('s', 'contains=é', '.pattern = .{ .contains = "é" }'),
    ('s', 'containsrune=é', '.pattern = .{ .contains = "é" }'),
    ('s', 'containsany=xé😀', '.pattern = .{ .contains_any = "xé😀" }'),
    ('s', 'excludes=ab', '.pattern = .{ .excludes = "ab" }'),
    ('s', 'excludesrune=é', '.pattern = .{ .excludes = "é" }'),
    ('s', 'excludesall=xé😀', '.pattern = .{ .excludes_any = "xé😀" }'),
    ('s', 'startswith=ab', '.pattern = .{ .prefix = "ab" }'),
    ('s', 'endswith=ab', '.pattern = .{ .suffix = "ab" }'),
    ('s', 'startsnotwith=ab', '.pattern = .{ .not_prefix = "ab" }'),
    ('s', 'endsnotwith=ab', '.pattern = .{ .not_suffix = "ab" }'),
    ('s', 'ne=abc', '.none_of = &.{"abc"}'),
    ('s', 'ne=', '.none_of = &.{""}'),
    ('s', 'ne_ignore_case=abc', '.none_of = &.{"abc"}, .ignore_case = true'),
    ('s', 'eq_ignore_case=abc', '.one_of = &.{"abc"}, .ignore_case = true'),
    ('s', 'oneof=red green', '.one_of = &.{ "red", "green" }'),
    ('s', 'oneofci=red green', '.one_of = &.{ "red", "green" }, .ignore_case = true'),
    ('s', 'noneof=red green', '.none_of = &.{ "red", "green" }'),
    ('s', 'noneofci=red green', '.none_of = &.{ "red", "green" }, .ignore_case = true'),
    ('s', 'omitempty,min=3', '.omit_empty = true, .min_len = 3'),
    ('s', 'omitempty,contains=ab', '.omit_empty = true, .pattern = .{ .contains = "ab" }'),
    ('s', 'omitempty,alpha', '.omit_empty = true, .format = .alpha'),
    ('s', 'omitzero,min=3', '.omit_zero = true, .min_len = 3'),
    ('s', 'contains=a,excludes=b', '.patterns = &.{ .{ .contains = "a" }, .{ .excludes = "b" } }'),
    ('s', 'startswith=a,endswith=c', '.pattern = .{ .prefix = "a" }, .patterns = &.{.{ .suffix = "c" }}'),
    ('s', 'contains=ab|contains=é',
     '.any_of = &.{ .{ .field = "", .kind = .string, .pattern = .{ .contains = "ab" } }, .{ .field = "", .kind = .string, .pattern = .{ .contains = "é" } } }'),
    ('s', 'alpha|numeric',
     '.any_of = &.{ .{ .field = "", .kind = .string, .format = .alpha }, .{ .field = "", .kind = .string, .format = .numeric } }'),
    ('s', 'hexcolor|rgb',
     '.any_of = &.{ .{ .field = "", .kind = .string, .format = .hexcolor }, .{ .field = "", .kind = .string, .format = .rgb } }'),
    ('s', 'omitempty,alpha|numeric',
     '.omit_empty = true, .any_of = &.{ .{ .field = "", .kind = .string, .format = .alpha }, .{ .field = "", .kind = .string, .format = .numeric } }'),
    ('i', 'ne=5', '.none_of = &.{"5"}'),
    ('i', 'noneof=5 7', '.none_of = &.{ "5", "7" }'),
    ('i', 'oneof=5 7', '.one_of = &.{ "5", "7" }'),
    ('i', 'gt=5', '.gt = 5'),
    ('i', 'lt=5', '.lt = 5'),
    ('i', 'gte=5', '.min = 5'),
    ('i', 'lte=5', '.max = 5'),
    ('i', 'gt=-5,lt=5', '.gt = -5, .lt = 5'),
    ('i', 'omitempty,gt=5', '.omit_empty = true, .gt = 5'),
    ('i', 'omitzero,gt=5', '.omit_zero = true, .gt = 5'),
    ('i', 'omitempty,ne=0', '.omit_empty = true, .none_of = &.{"0"}'),
    ('i', 'gt=5|lt=-5',
     '.any_of = &.{ .{ .field = "", .kind = .int, .gt = 5 }, .{ .field = "", .kind = .int, .lt = -5 } }'),
    ('f', 'gt=2.5', '.gt = 2.5'),
    ('f', 'lt=2.5', '.lt = 2.5'),
    ('f', 'ne=2.5', '.none_of = &.{"2.5"}'),
    ('f', 'omitempty,gt=2.5', '.omit_empty = true, .gt = 2.5'),
]
KINDS = {'s': 'string', 'i': 'int', 'f': 'float'}


def fold_tags(rng):
    """`eq_ignore_case=<c>` over cased code points across the planes, against each single-code-point
    case variant: this is what pins the generated fold table to Go's own."""
    cased = [chr(c) for c in range(0x80, 0x1F000)
             if not 0xD800 <= c <= 0xDFFF and unicodedata.category(chr(c)) in ('Lu', 'Ll', 'Lt')]
    out = [(c, sorted({c, c.lower(), c.upper(), c.title(), c.casefold()})) for c in FOLD if len(c) == 1 and ord(c) >= 0x80]
    out += [(c, sorted({c, c.lower(), c.upper(), c.title(), c.casefold(), 'x'})) for c in rng.sample(cased, 240)]
    return out


def go_verdicts(items):
    payload = json.dumps([{'tag': t, 'v': base64.b64encode(v.encode()).decode(), 'int': k == 'i', 'float': k == 'f'}
                          for k, t, _, v in items])
    env = dict(os.environ)
    env.setdefault('GOPROXY', 'off')
    env.setdefault('GOFLAGS', '-mod=readonly')
    r = subprocess.run(['go', 'run', '.'], cwd=os.path.join(HERE, 'go_formats'), input=payload.encode(),
                       capture_output=True, env=env, check=True)
    return json.loads(r.stdout)


def zstr(s):
    out = ['"']
    for b in s.encode():
        c = chr(b)
        if c == '"':
            out.append('\\"')
        elif c == '\\':
            out.append('\\\\')
        elif 0x20 <= b < 0x7f:
            out.append(c)
        else:
            out.append('\\x%02x' % b)
    out.append('"')
    return ''.join(out)


def main():
    rng = random.Random(SEED)
    items = []
    for k, tag, rule in TAGS:
        pool = {'s': STRINGS, 'i': INTS, 'f': FLOATS}[k]
        items += [(k, tag, rule, v) for v in pool]
    for c, variants in fold_tags(rng):
        if c in ',|=\\':
            continue
        rule = '.one_of = &.{%s}, .ignore_case = true' % zstr(c)
        items += [('s', 'eq_ignore_case=' + c, rule, v) for v in variants if ',' not in v]
    verdicts = go_verdicts(items)

    o = ['// SPDX-License-Identifier: MIT',
         '// GENERATED by modules/validate/tools/rule_oracle.py -- do not hand-edit.',
         '//! go-playground/validator v10.30.5 verdicts on the rule vocabulary, replayed by `go_rule_test.zig`.',
         '',
         'const Rule = @import("root.zig").Rule;',
         '',
         '/// `doc`: a JSON document with the value as member `v`; `go`: `validate.Var(v, tag)` passed.',
         'pub const Case = struct { tag: []const u8, doc: []const u8, go: bool, rule: Rule };',
         '',
         'pub const cases = [_]Case{']
    for (k, tag, rule, v), go in zip(items, verdicts):
        body = '{"v":%s}' % (json.dumps(v, ensure_ascii=False) if k == 's' else v)
        o.append('    .{ .tag = %s, .doc = %s, .go = %s, .rule = .{ .field = "v", .kind = .%s, %s } },' % (
            zstr(tag), zstr(body), 'true' if go else 'false', KINDS[k], rule))
    o.append('};')
    text = '\n'.join(o) + '\n'
    text = subprocess.run(['zig', 'fmt', '--stdin'], input=text, capture_output=True, text=True, check=True).stdout
    if '--check' in sys.argv:
        with open(os.path.join(HERE, '..', 'src', 'go_rule_vectors.zig'), encoding='utf-8') as f:
            if f.read() != text:
                sys.stderr.write('rule_oracle: committed vectors differ from a fresh run\n')
                sys.exit(1)
        sys.stderr.write('rule_oracle: vectors fresh (%d cases)\n' % len(items))
        return
    sys.stdout.write(text)
    sys.stderr.write('%d cases, %d tags\n' % (len(items), len({i[1] for i in items})))


if __name__ == '__main__':
    main()
