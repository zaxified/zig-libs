#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""FastAPI (MIT, run as a black box) -- the generated-spec shape this module
models -- as the judge of how route patterns become OpenAPI path templates.

Runs in FastAPI's own virtualenv, outside the repository (tools/README.md); reads route tables as JSON on
stdin ({"routes": [{"method", "pattern"}]} each, only the routes the router
accepted) and prints, per table, FastAPI's own document reduced to
{path template: {method: [path parameter names, sorted]}}.

A router pattern becomes a Starlette path: `:name` -> `{name}`, `*name` ->
`{name:path}` (Starlette's converter for a rest-of-path capture), every other
segment verbatim.
"""
import json
import sys
import warnings

warnings.filterwarnings('ignore')
from fastapi import FastAPI  # noqa: E402


def starlette_path(pattern):
    segs = pattern.split('/')
    out = []
    for s in segs:
        if s.startswith(':'):
            out.append('{%s}' % s[1:])
        elif s.startswith('*'):
            out.append('{%s:path}' % s[1:])
        else:
            out.append(s)
    return '/'.join(out)


def endpoint(names, n):
    # FastAPI reads the path parameters off the endpoint's signature.
    ns = {}
    args = ', '.join('%s: str' % x for x in names)
    exec('def route_%d(%s):\n    return None' % (n, args), ns)
    return ns['route_%d' % n]


def reduce(tables):
    out = []
    for t in tables:
        app = FastAPI()
        try:
            for n, r in enumerate(t['routes']):
                names = [s[1:] for s in r['pattern'].split('/') if s[:1] in (':', '*')]
                app.add_api_route(starlette_path(r['pattern']), endpoint(names, n), methods=[r['method'].upper()])
            doc = app.openapi()
        except Exception as e:  # FastAPI refusing the table is its verdict
            out.append({'error': '%s: %s' % (type(e).__name__, str(e).split(chr(10))[0][:160])})
            continue
        paths = {}
        for p, item in doc.get('paths', {}).items():
            paths[p] = {m: sorted(x['name'] for x in op.get('parameters', []) if x.get('in') == 'path') for m, op in item.items()}
        out.append({'paths': paths})
    return out


if __name__ == '__main__':
    json.dump(reduce(json.load(sys.stdin)), sys.stdout)
