#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The openapi oracle: openapi-spec-validator (Apache-2.0, run as a black box)
judges the documents this module generates, and the structural checker it
runs on its own output (`validateOpenApi31`).

Driven by tools/interop.zig (`zig build interop-openapi`):

    spec_oracle.py gen                      route tables (JSON) on stdout
    spec_oracle.py judge TABLES DOCS OUT    verdicts; writes the Zig vectors to OUT

`gen` draws route tables from a fixed seed: patterns with static segments
(UTF-8, dots, tildes, percent signs), `:params`, `{name}` captures (whole and
inside a segment) and a final `*wildcard`, every method, and `RouteDoc` metadata (summary, description,
tags, deprecated, request/query/response schemas). interop.zig registers each
table on a `router.Router` and builds the document; `judge` has the validator
check every document built, then mutates documents into the shapes a
generator bug could produce (a template variable without its parameter, a
parameter without its variable, an optional path parameter, a duplicate
parameter, a bad response key, ...) and records the validator's verdict on
each, which the replay requires `validateOpenApi31` to share -- or a class
in `CLASSES` to explain.
"""
import copy
import json
import os
import platform
import random
import sys
from importlib.metadata import version as pkg_version

from openapi_spec_validator import validate
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError

SEED = 3101
N_TABLES = 100
# Mutations kept per kind (the first tables' documents): enough to pin each verdict, not a corpus.
MUT_PER_KIND = 12
METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']
STATIC = ['users', 'v1', 'a.b', '~x', 'é', 'files', 'x%20y', 'a-b', 'item_2', 'Ünï']
PARAMS = ['id', 'name', 'x', 'userId', 'é']
TAGS = [[], ['users'], ['a', 'b'], ['é']]
TEXTS = [None, 'Plain', 'with "quotes"', 'multi\nline', 'é ünïcode', '']
SCHEMAS = [None, '{"type":"object","properties":{"a":{"type":"integer"}},"required":["a"]}',
           '{"type":"string"}', '{"type":"array","items":{"type":"number"}}', '{}', 'true']
QUERY = [None, '{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer","minimum":1}},"required":["q"]}',
         '{"allOf":[{"type":"object","properties":{"a":{"type":"string"}}},{"type":"object","properties":{"b":{"type":"boolean"}},"required":["b"]}]}',
         '{"type":"object","properties":{"id":{"type":"string"}}}']
STATUSES = [200, 201, 204, 400, 404, 500]

# Mutations of a valid document, and what openapi-spec-validator is expected
# to say (recorded, not assumed: the verdict is the validator's).
# Where `validateOpenApi31` may answer otherwise than the validator, and why.
CLASSES = {
    'SCOPE': 'an unknown top-level member, or an operation member of the wrong type outside parameters/responses: '
             'the checker verifies what a generator bug can break (identity, paths, operations, parameters, '
             'responses), not the closed vocabulary of every object -- it accepts',
    'VALIDATOR_LAX': 'a path parameter whose name is no template expression: OAS 3.1 4.8.12.1 says it MUST be one; '
                     'openapi-spec-validator does not check that direction -- the checker refuses',
    'OPENAPI_30': 'the document relabelled 3.0.3: the validator judges it as 3.0; the checker accepts 3.1.x only -- it refuses',
}


def checker_want(name, valid):
    """What `validateOpenApi31` must answer on a mutation, and the class when that is not `valid`."""
    if name in ('unknown_top_level', 'tags_not_array') and not valid:
        return True, 'SCOPE'
    if name == 'extra_path_param' and valid:
        return False, 'VALIDATOR_LAX'
    if name == 'openapi_30':
        return False, 'OPENAPI_30' if valid else ''
    return valid, ''


def gen_pattern(rng):
    segs = []
    for _ in range(rng.randint(0, 4)):
        r = rng.random()
        if r < 0.55:
            segs.append(rng.choice(STATIC))
        elif r < 0.75:
            segs.append(':' + rng.choice(PARAMS))
        else:
            # router's `{name}` captures, whole or inside a segment (2026-10-07).
            segs.append(rng.choice(['{%s}', '{%s}.json', 'v{%s}', '{%s}-{b}', '{%s:[0-9]+}', '{%s:[a-z]{2}}.json']) % rng.choice(PARAMS))
    if rng.random() < 0.2:
        segs.append('*' + rng.choice(['rest', 'path', 'id']))
    p = '/' + '/'.join(segs)
    if segs and rng.random() < 0.1:
        p += '/'
    return p


def gen_doc(rng):
    if rng.random() < 0.3:
        return None
    d = {}
    for k in ('summary', 'description'):
        t = rng.choice(TEXTS)
        if t is not None:
            d[k] = t
    d['tags'] = rng.choice(TAGS)
    s = rng.choice(SCHEMAS)
    if s is not None:
        d['request_schema'] = s
    q = rng.choice(QUERY)
    if q is not None:
        d['query_schema'] = q
    d['responses'] = []
    for st in rng.sample(STATUSES, rng.randint(0, 3)):
        r = {'status': st, 'description': rng.choice(['OK', 'Created', 'é', 'bad "x"'])}
        sch = rng.choice(SCHEMAS)
        if sch is not None:
            r['schema'] = sch
            if rng.random() < 0.2:
                r['media_type'] = 'application/problem+json'
        d['responses'].append(r)
    d['deprecated'] = rng.random() < 0.2
    return d


def gen():
    rng = random.Random(SEED)
    tables = []
    for _ in range(N_TABLES):
        t = {'title': rng.choice(['API', 'é api']), 'version': rng.choice(['1.0', '0.0.1-é']),
             'description': rng.choice([None, 'desc']), 'bearer': rng.random() < 0.3, 'routes': []}
        for _ in range(rng.randint(1, 6)):
            t['routes'].append({'method': rng.choice(METHODS), 'pattern': gen_pattern(rng), 'doc': gen_doc(rng)})
        tables.append(t)
    # Crafted, whatever the seed draws.
    tables.append({'title': 'T', 'version': '1', 'description': None, 'bearer': False, 'routes': [
        {'method': 'get', 'pattern': '/files/*path', 'doc': None},
        {'method': 'get', 'pattern': '/users/:id/posts/:postId', 'doc': {'query_schema': QUERY[3], 'responses': []}},
        {'method': 'post', 'pattern': '/', 'doc': {'request_schema': SCHEMAS[1], 'responses': [{'status': 201, 'description': 'Created'}]}},
    ]})
    # router's `{name}` captures (2026-10-07): whole, inside a segment, and a
    # a final wildcard -- templates with their parameters, never a literal brace.
    tables.append({'title': 'T', 'version': '1', 'description': None, 'bearer': False, 'routes': [
        {'method': 'get', 'pattern': '/a/{x}', 'doc': None},
        {'method': 'get', 'pattern': '/files/{name}.{ext}', 'doc': None},
        {'method': 'put', 'pattern': '/s/v{n}/*rest', 'doc': None},
    ]})
    json.dump(tables, sys.stdout)


def verdict(doc):
    try:
        validate(doc)
        return True, ''
    except OpenAPIValidationError as e:
        return False, str(e).split('\n')[0][:160]
    except Exception as e:  # the validator refusing outright is a verdict too
        return False, (type(e).__name__ + ': ' + str(e)).split('\n')[0][:160]


def ops(doc):
    for path, item in doc.get('paths', {}).items():
        for m, op in item.items():
            if m in METHODS + ['trace']:
                yield path, m, op


def mutations(doc):
    """(name, mutated document) pairs; only those that apply to this document."""
    out = []

    def m(name, f):
        d = copy.deepcopy(doc)
        if f(d) is not False:
            out.append((name, d))

    def first_param(d, where):
        for path, _, op in ops(d):
            for i, p in enumerate(op.get('parameters', [])):
                if p.get('in') == where:
                    return op, i
        return None, None

    def drop_path_param(d):
        op, i = first_param(d, 'path')
        if op is None:
            return False
        del op['parameters'][i]

    def extra_path_param(d):
        for _, _, op in ops(d):
            op.setdefault('parameters', []).append({'name': 'ghost', 'in': 'path', 'required': True, 'schema': {'type': 'string'}})
            return
        return False

    def optional_path_param(d):
        op, i = first_param(d, 'path')
        if op is None:
            return False
        op['parameters'][i]['required'] = False

    def duplicate_param(d):
        for where in ('path', 'query'):
            op, i = first_param(d, where)
            if op is not None:
                op['parameters'].append(copy.deepcopy(op['parameters'][i]))
                return
        return False

    def bad_response_key(d):
        for _, _, op in ops(d):
            op['responses']['abc'] = {'description': 'x'}
            return
        return False

    def response_no_description(d):
        for _, _, op in ops(d):
            for r in op['responses'].values():
                del r['description']
                return
        return False

    def empty_responses(d):
        for _, _, op in ops(d):
            op['responses'] = {}
            return
        return False

    def path_key_no_slash(d):
        if not d.get('paths'):
            return False
        k = next(iter(d['paths']))
        d['paths']['x' + k] = d['paths'].pop(k)

    def no_title(d):
        del d['info']['title']

    def param_no_schema(d):
        op, i = first_param(d, 'path')
        if op is None:
            return False
        del op['parameters'][i]['schema']

    def param_bad_in(d):
        op, i = first_param(d, 'path')
        if op is None:
            return False
        op['parameters'][i]['in'] = 'body'

    def unknown_top_level(d):
        d['foo'] = 1

    def tags_not_array(d):
        for _, _, op in ops(d):
            op['tags'] = 'x'
            return
        return False

    def openapi_30(d):
        d['openapi'] = '3.0.3'

    for name, f in [('drop_path_param', drop_path_param), ('extra_path_param', extra_path_param),
                    ('optional_path_param', optional_path_param), ('duplicate_param', duplicate_param),
                    ('bad_response_key', bad_response_key), ('response_no_description', response_no_description),
                    ('empty_responses', empty_responses), ('path_key_no_slash', path_key_no_slash), ('no_title', no_title),
                    ('param_no_schema', param_no_schema), ('param_bad_in', param_bad_in),
                    ('unknown_top_level', unknown_top_level), ('tags_not_array', tags_not_array), ('openapi_30', openapi_30)]:
        m(name, f)
    return out


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
        elif 0x20 <= b < 0x7f:
            out.append(c)
        else:
            out.append('\\x%02x' % b)
    out.append('"')
    return ''.join(out)


def zopt(s):
    return 'null' if s is None else zstr(s)


def zdoc(d):
    if d is None:
        return 'null'
    f = []
    for k in ('summary', 'description', 'request_schema', 'query_schema'):
        if d.get(k) is not None:
            f.append('.%s = %s' % (k, zstr(d[k])))
    if d.get('tags'):
        f.append('.tags = &.{ %s }' % ', '.join(zstr(t) for t in d['tags']))
    if d.get('responses'):
        rs = []
        for r in d['responses']:
            g = ['.status = %d' % r['status'], '.description = %s' % zstr(r['description'])]
            if r.get('schema') is not None:
                g.append('.schema = %s' % zstr(r['schema']))
            if r.get('media_type'):
                g.append('.media_type = %s' % zstr(r['media_type']))
            rs.append('.{ %s }' % ', '.join(g))
        f.append('.responses = &.{ %s }' % ', '.join(rs))
    if d.get('deprecated'):
        f.append('.deprecated = true')
    return '.{ %s }' % ', '.join(f)


# FastAPI lives in a virtualenv OUTSIDE the repository: a site-packages tree inside a module would be
# walked by the repo's own gates (check-copyleft reads every licence text under modules/). See tools/README.md.
FASTAPI_PY = os.environ.get('ZIGLIBS_FASTAPI_PY') or os.path.expanduser('~/.local/share/zig-libs/oracle-venvs/fastapi/bin/python')
FASTAPI_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fastapi_oracle', 'fastapi_paths.py')


def reduce_ours(doc):
    return {p: {m: sorted(x['name'] for x in op.get('parameters', []) if x.get('in') == 'path')
                for m, op in item.items() if m in METHODS + ['trace']}
            for p, item in doc.get('paths', {}).items()}


def fastapi(tables, built):
    """FastAPI's reduced document for every table that built (None for the rest)."""
    import subprocess
    accepted = [[r for r, ok in zip(t['routes'], b['accepted']) if ok] for t, b in zip(tables, built)]
    out = subprocess.run([FASTAPI_PY, FASTAPI_SCRIPT], input=json.dumps([{'routes': a} for a in accepted]),
                         capture_output=True, text=True, check=True).stdout
    ver = subprocess.run([FASTAPI_PY, '-c', 'import fastapi; print(fastapi.__version__)'], capture_output=True, text=True).stdout.strip()
    return json.loads(out), ver


def judge(tables_path, docs_path, out_path):
    tables = json.load(open(tables_path, encoding='utf-8'))
    built = json.load(open(docs_path, encoding='utf-8'))
    fa, fa_ver = fastapi(tables, built)
    o = []
    o.append('// SPDX-License-Identifier: MIT')
    o.append('// GENERATED by modules/openapi/tools/spec_oracle.py (Python %s, openapi-spec-validator %s, FastAPI %s) -- do not hand-edit.'
             % (platform.python_version(), pkg_version('openapi-spec-validator'), fa_ver))
    o.append('//! Route tables, the document this module built for each, and openapi-spec-validator\'s verdicts on')
    o.append('//! it and on mutations of it; replayed by `spec_oracle_test.zig`. Regenerate: `zig build interop-openapi`.')
    o.append('')
    o.append('const router = @import("router");')
    o.append('')
    o.append('pub const Route = struct { method: @import("http").Method, pattern: []const u8, doc: ?router.RouteDoc };')
    o.append('/// `routes`: the ones the router accepted, in order. `doc`: the document built, or null with')
    o.append('/// `err` naming the `BuildError`. `valid`/`why`: the validator\'s verdict on `doc`.')
    o.append('pub const Table = struct { title: []const u8, version: []const u8, description: ?[]const u8, bearer: bool,')
    o.append('    routes: []const Route, doc: ?[]const u8, err: []const u8, valid: bool, why: []const u8 };')
    o.append('/// A document from `tables[table]` changed by `mutation`; `valid`: the validator\'s verdict; `want`:')
    o.append('/// what `validateOpenApi31` must answer -- `valid`, unless `class` (tools/spec_oracle.py CLASSES) says otherwise.')
    o.append('pub const Mutation = struct { table: u16, mutation: []const u8, doc: []const u8, valid: bool, why: []const u8, want: bool, class: []const u8 };')
    o.append('pub const classes = [_][]const u8{ %s };' % ', '.join(zstr(c) for c in CLASSES))
    o.append('')
    o.append('pub const tables = [_]Table{')
    bad = 0
    muts = []
    per_kind = {}
    for i, (t, b) in enumerate(zip(tables, built)):
        doc_text = b['doc']
        valid, why = (False, '')
        if doc_text is not None:
            doc = json.loads(doc_text)
            valid, why = verdict(doc)
            if not valid:
                bad += 1
                sys.stderr.write('table %d: the validator refuses the generated document: %s\n' % (i, why))
            # Only a valid document is mutated: on an invalid one the verdict could be the old fault.
            ours_r = reduce_ours(doc)
            if fa[i].get('paths') != ours_r:
                bad += 1
                sys.stderr.write('table %d: FastAPI maps the routes otherwise\n  ours    %r\n  fastapi %r\n' % (
                    i, ours_r, fa[i].get('paths', fa[i])))
            for name, md in (mutations(doc) if valid else []):
                if per_kind.get(name, 0) >= MUT_PER_KIND:
                    continue
                per_kind[name] = per_kind.get(name, 0) + 1
                mv, mwhy = verdict(md)
                want, cls = checker_want(name, mv)
                muts.append((i, name, json.dumps(md, ensure_ascii=False, separators=(',', ':')), mv, mwhy, want, cls))
        accepted = [r for r, ok in zip(t['routes'], b['accepted']) if ok]
        routes = ', '.join('.{ .method = .%s, .pattern = %s, .doc = %s }' % (r['method'], zstr(r['pattern']), zdoc(r['doc']))
                           for r in accepted)
        o.append('    .{ .title = %s, .version = %s, .description = %s, .bearer = %s, .routes = &.{ %s }, .doc = %s, '
                 '.err = %s, .valid = %s, .why = %s },' % (
                     zstr(t['title']), zstr(t['version']), zopt(t['description']), 'true' if t['bearer'] else 'false',
                     routes, zopt(doc_text), zstr(b['err']), 'true' if valid else 'false', zstr(why)))
    o.append('};')
    o.append('')
    o.append('pub const mutations = [_]Mutation{')
    from collections import Counter
    tally = Counter()
    for i, name, text, mv, mwhy, want, cls in muts:
        tally[(name, mv)] += 1
        o.append('    .{ .table = %d, .mutation = %s, .doc = %s, .valid = %s, .why = %s, .want = %s, .class = %s },' % (
            i, zstr(name), zstr(text), 'true' if mv else 'false', zstr(mwhy), 'true' if want else 'false', zstr(cls)))
    o.append('};')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(o) + '\n')
    sys.stderr.write('%d tables, %d documents refused by the validator; %d mutations: %s\n' % (
        len(tables), bad, len(muts), dict(sorted(tally.items()))))
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'gen':
        gen()
    elif len(sys.argv) == 5 and sys.argv[1] == 'judge':
        sys.exit(judge(sys.argv[2], sys.argv[3], sys.argv[4]))
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
