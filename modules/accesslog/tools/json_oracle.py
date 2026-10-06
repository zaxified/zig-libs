#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The accesslog JSON Lines oracle: three independent readers -- Python's
`json`, Go's `encoding/json` (tools/go_json) and `jq` -- read every line this
module writes, and each must give back exactly the entry: every field, with
an ill-formed UTF-8 subsequence read as one U+FFFD per maximal subpart --
which is what Python's own `bytes.decode('utf-8', 'replace')` produces, so the
substitution policy is judged by a foreign decoder too.

Driven by tools/interop.zig (`zig build interop-accesslog`):

    json_oracle.py gen                      entries (JSON, strings hex) on stdout
    json_oracle.py judge ENTRIES OURS OUT   verdicts; writes the Zig vectors to OUT
"""
import json
import os
import platform
import random
import subprocess
import sys

SEED = 8259
N = 400
HERE = os.path.dirname(os.path.abspath(__file__))
STRS = [b'', b'GET', b'/a b?x="1"&y=\\', b'\x00\x01\x1f\x7f', b'line\nbreak\r\n', b'tab\there', b'\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80',
        b'\xe2\x82', b'\xed\xa0\x80', b'\xc0\xaf', b'\xf4\x90\x80\x80', b'\x80', b'a\xf0\x9f\x98', b'\xff\xfe', b'"}],{"x":1', b'\\u0000',
        b'Mozilla/5.0 (X11)', b'0af7651916cd43dd8448eb211c80319c', b'b7ad6b7169203331', b'\xe0\x80\x80', b'\xef\xbf\xbf\xf4\x8f\xbf\xbf']
NUMS = [0, 1, 255, 2**53 + 1, 2**63 - 1, 2**64 - 1]
OPT = ['remote_addr', 'user', 'user_agent', 'referer', 'request_id', 'trace_id', 'span_id']


def gen():
    rng = random.Random(SEED)
    out = []
    for i in range(N):
        e = {'timestamp_ns': rng.choice([0, 1, -1, 1759680000123456789, -2**63, 2**63 - 1]),
             'method': rng.choice(STRS).hex(), 'target': rng.choice(STRS).hex(), 'protocol': rng.choice([b'HTTP/1.1', b'HTTP/2', b'\x00']).hex(),
             'status': rng.choice([0, 200, 404, 65535])}
        for k in OPT:
            if rng.random() < 0.6:
                e[k] = rng.choice(STRS).hex()
        for k in ('request_bytes', 'response_bytes', 'latency_ns'):
            if rng.random() < 0.6:
                e[k] = rng.choice(NUMS)
        out.append(e)
    # Every hostile string in every string field at least once, whatever the seed draws.
    for s in STRS:
        e = {'timestamp_ns': 0, 'method': s.hex(), 'target': s.hex(), 'protocol': s.hex(), 'status': 200}
        for k in OPT:
            e[k] = s.hex()
        out.append(e)
    json.dump(out, sys.stdout)


def expected(e):
    """The record a correct reader must see: JSON nulls for absent fields, `user` only when set."""
    s = lambda k: bytes.fromhex(e[k]).decode('utf-8', 'replace') if k in e else None
    r = {'ts': e['timestamp_ns'], 'remote_addr': s('remote_addr')}
    if 'user' in e:
        r['user'] = s('user')
    r.update({'method': s('method'), 'target': s('target'), 'protocol': s('protocol'), 'status': e['status'],
              'request_bytes': e.get('request_bytes'), 'response_bytes': e.get('response_bytes'), 'latency_ns': e.get('latency_ns'),
              'user_agent': s('user_agent'), 'referer': s('referer'), 'request_id': s('request_id'), 'trace_id': s('trace_id'),
              'span_id': s('span_id')})
    return r


def expected_logfmt(e):
    """The (key, value bytes) pairs a correct logfmt reader must see: absent fields have no key."""
    b = lambda k: bytes.fromhex(e[k])
    r = [('ts', str(e['timestamp_ns']).encode())]
    for k in ('remote_addr', 'user'):
        if k in e:
            r.append((k, b(k)))
    r += [('method', b('method')), ('target', b('target')), ('protocol', b('protocol')), ('status', str(e['status']).encode())]
    for k in ('request_bytes', 'response_bytes', 'latency_ns'):
        if k in e:
            r.append((k, str(e[k]).encode()))
    for k in ('user_agent', 'referer', 'request_id', 'trace_id', 'span_id'):
        if k in e:
            r.append((k, b(k)))
    return r


def zstr(b):
    out = ['"']
    for c in b:
        ch = chr(c)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif 0x20 <= c < 0x7f:
            out.append(ch)
        else:
            out.append('\\x%02x' % c)
    out.append('"')
    return ''.join(out)


def judge(entries_path, ours_path, out_path):
    entries = json.load(open(entries_path))
    both = json.load(open(ours_path))
    ours = [bytes.fromhex(j) for j, _ in both]
    logfmt = [bytes.fromhex(l) for _, l in both]
    assert len(entries) == len(ours)
    lines = b''.join(ours)
    go = subprocess.run(['go', '-C', os.path.join(HERE, 'go_json'), 'run', '.'], input=lines, capture_output=True, check=True,
                        env={**os.environ, 'GOPROXY': 'off'}).stdout.decode('utf-8').split('\n')
    jq = subprocess.run(['jq', '-c', '.'], input=lines, capture_output=True, check=True).stdout.decode('utf-8').split('\n')
    # go-logfmt is a third-party module: a fresh runner (the interop lane)
    # has it in no module cache, and GOPROXY=off made `go run` fail there
    # ("module lookup disabled") — tag 2026-10-06. Let Go fetch it; go.sum
    # pins its hash, so a download cannot change what is judged.
    lf_run = subprocess.run(['go', '-C', os.path.join(HERE, 'go_logfmt'), 'run', '.'], input=b''.join(logfmt),
                            capture_output=True)
    if lf_run.returncode != 0:
        sys.stderr.write(lf_run.stderr.decode('utf-8', 'replace'))
        lf_run.check_returncode()
    lf = lf_run.stdout.decode('utf-8').split('\n')
    jq_ver = subprocess.run(['jq', '--version'], capture_output=True, text=True).stdout.strip()
    go_ver = subprocess.run(['go', 'version'], capture_output=True, text=True).stdout.split()[2]
    bad = 0
    for i, (e, line) in enumerate(zip(entries, ours)):
        want = expected(e)
        why = []
        if not line.endswith(b'\n') or line.count(b'\n') != 1:
            why.append('not exactly one line')
        try:
            py = json.loads(line.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as x:
            py = {'error': str(x)}
        for name, got in (('python', py), ('go', json.loads(go[i]) if go[i] else None), ('jq', json.loads(jq[i]) if jq[i] else None)):
            if got != want:
                why.append('%s read %r' % (name, got))
            elif name != 'go' and list(got) != list(want):  # Go decodes into a map: no order to compare
                why.append('%s: key order %r' % (name, list(got)))
        if not logfmt[i].endswith(b'\n') or logfmt[i].count(b'\n') != 1:
            why.append('logfmt: not exactly one line')
        got = json.loads(lf[i]) if lf[i] else None
        if isinstance(got, list):
            got = [(k, bytes.fromhex(v)) for k, v in got]
        if got != expected_logfmt(e):
            why.append('go-logfmt read %r' % (got,))
        if why:
            bad += 1
            sys.stderr.write('entry %d: %s\n  want %r\n' % (i, '; '.join(why)[:600], want))
    o = ['// SPDX-License-Identifier: MIT',
         '// GENERATED by modules/accesslog/tools/json_oracle.py (Python %s, %s, %s, go-logfmt v0.6.1) -- do not hand-edit.' % (platform.python_version(), go_ver, jq_ver),
         '//! Entries and the JSON Lines and logfmt records this module wrote for each, read back exactly by Python json,',
         '//! Go encoding/json and jq (JSON) and go-logfmt (logfmt); replayed by `json_oracle_test.zig`.',
         '//! Regenerate: `zig build interop-accesslog`.',
         '',
         'const Entry = @import("root.zig").Entry;',
         '',
         '/// `line`/`logfmt`: what `writeJsonLines`/`writeLogfmt` wrote -- the bytes the readers judged.',
         'pub const Case = struct { entry: Entry, line: []const u8, logfmt: []const u8 };',
         '',
         'pub const cases = [_]Case{']
    for e, line, lfline in zip(entries, ours, logfmt):
        f = ['.timestamp_ns = %d' % e['timestamp_ns'], '.method = %s' % zstr(bytes.fromhex(e['method'])),
             '.target = %s' % zstr(bytes.fromhex(e['target'])), '.protocol = %s' % zstr(bytes.fromhex(e['protocol'])), '.status = %d' % e['status']]
        for k in OPT:
            if k in e:
                f.append('.%s = %s' % (k, zstr(bytes.fromhex(e[k]))))
        for k in ('request_bytes', 'response_bytes', 'latency_ns'):
            if k in e:
                f.append('.%s = %d' % (k, e[k]))
        o.append('    .{ .entry = .{ %s }, .line = %s, .logfmt = %s },' % (', '.join(f), zstr(line), zstr(lfline)))
    o.append('};')
    with open(out_path, 'w') as fh:
        fh.write('\n'.join(o) + '\n')
    sys.stderr.write('%d entries; %d where a reader did not get the entry back\n' % (len(entries), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'gen':
        gen()
    elif len(sys.argv) == 5 and sys.argv[1] == 'judge':
        sys.exit(judge(*sys.argv[2:]))
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
