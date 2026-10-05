#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The sntp oracle: a real NTP server, a reference client and an independent
offset/delay computation.

Per scenario a fresh chronyd 4.8 (`-x`: it never touches the clock; `-d`; a
throwaway config; loopback of its own in `unshare -rn`) serves: synchronized
at stratum 3 (every request version 1-4, IPv4 and IPv6) and at stratum 10,
unsynchronized (no reference at all), rate limiting with Kiss-o'-Death RATE,
and denying the client. Against each:

- `interop-sntp --live`: this module's `query`;
- `interop-sntp --raw`: the codec path (encode a request, `decodeResponse`,
  `Sample`), recording every reply's bytes with T1 and T4;
- beevik/ntp v1.6.0 (`tools/go_oracle`), the Go reference client, with its
  own `Validate`;
- ntplib, which recomputes offset and delay from the very same raw bytes.

The truth for a synchronized server on the same host: the configured stratum,
no leap warning, the request's version echoed, an offset of about zero (one
clock) and a small positive delay. A server that is not synchronized, rate
limits or denies must not yield a time -- and both clients must agree on it.

Driven by tools/interop.zig (`zig build interop-sntp`):

    ntp_oracle.py judge EXE OUT    run every scenario; write the Zig vectors to OUT
    ntp_oracle.py inner EXE GO     (internal) runs inside `unshare -rn`
"""
import json
import os
import subprocess
import sys
import time

HOME = os.path.expanduser('~')
CHRONYD = os.environ.get('ZIGLIBS_CHRONYD', HOME + '/.local/share/zig-libs/oracle-bin/chrony/usr/sbin/chronyd')
NTPLIB_PY = os.environ.get('ZIGLIBS_NTPLIB_PY', HOME + '/.local/share/zig-libs/oracle-venvs/ntplib/bin/python')
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 11123
KOD_TRIES = 60

# (name, extra chronyd config, request versions, also over IPv6)
SCENARIOS = [
    ('stratum3', 'local stratum 3\n', [1, 2, 3, 4], True),
    ('stratum10', 'local stratum 10\n', [4], False),
    ('unsynchronized', '', [4], False),
    ('kod-rate', 'local stratum 3\nratelimit interval 12 burst 1 leak 4 kod 1\n', [4], False),
    ('denied', 'local stratum 3\ndeny 127.0.0.1\ndeny ::1\n', [4], False),
]


def run(*cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('%s: %s' % (cmd, p.stderr[-400:]))
    return p.stdout


def inner(exe, go):
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    d = os.path.join(os.path.dirname(go), 'chrony')
    os.makedirs(d, exist_ok=True)
    out = []
    for name, extra, versions, v6 in SCENARIOS:
        conf = os.path.join(d, 'chrony.conf')
        with open(conf, 'w') as fh:
            fh.write('port %d\ncmdport 0\nallow 127.0.0.1\nallow ::1\npidfile %s/pid\ndriftfile %s/drift\n%s' % (
                PORT, d, d, extra))
        proc = subprocess.Popen([CHRONYD, '-d', '-x', '-u', 'root', '-f', conf], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.0)
            r = {'name': name, 'live': {}, 'raw': {}}
            kod = name == 'kod-rate'
            if kod:  # the burst is one response: spend it on nothing, then collect what the limiter sends
                r['raw']['4'] = json.loads(run(exe, '--raw', '127.0.0.1', str(PORT), '4', str(KOD_TRIES)))
                r['beevik'] = json.loads(run(go, '127.0.0.1', str(PORT), '4', str(KOD_TRIES), '1'))
            else:
                for v in versions:
                    r['live'][str(v)] = json.loads(run(exe, '--live', '127.0.0.1', str(PORT), str(v), '700'))
                    r['raw'][str(v)] = json.loads(run(exe, '--raw', '127.0.0.1', str(PORT), str(v), '3'))
                if v6:
                    r['live']['v6'] = json.loads(run(exe, '--live', '::1', str(PORT), '4', '700'))
                r['beevik'] = json.loads(run(go, '127.0.0.1', str(PORT), '4', '1', '0'))
            out.append(r)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    json.dump(out, sys.stdout)


NTPLIB_JUDGE = r'''
import json, sys, ntplib
res = []
for x in json.load(sys.stdin):
    s = ntplib.NTPStats()
    s.from_data(bytes.fromhex(x["reply"]))
    t4 = bytes.fromhex(x["t4"])
    s.dest_timestamp = ntplib._to_time(int.from_bytes(t4[:4], "big"), int.from_bytes(t4[4:], "big"))
    res.append({"offset": s.offset, "delay": s.delay, "stratum": s.stratum, "leap": s.leap, "version": s.version})
json.dump(res, sys.stdout)
'''


def ts_to_zig(h):
    b = bytes.fromhex(h)
    return '.{ .seconds = %d, .fraction = %d }' % (int.from_bytes(b[:4], 'big'), int.from_bytes(b[4:], 'big'))


def zbytes(h):
    return '"%s"' % ''.join('\\x%s' % h[i:i + 2] for i in range(0, len(h), 2))


def judge(exe, out_path):
    go = os.path.join(os.path.dirname(os.path.abspath(out_path)), 'go_oracle')
    subprocess.run(['go', 'build', '-o', go, '.'], cwd=os.path.join(HERE, 'go_oracle'), check=True,
                   env=dict(os.environ, GOPROXY='off', GOFLAGS='-mod=mod'))
    p = subprocess.run(['unshare', '-rn', sys.executable, os.path.abspath(__file__), 'inner', os.path.abspath(exe), go],
                       capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if p.returncode != 0:
        return 1
    results = json.loads(p.stdout)
    conf_stratum = {'stratum3': 3, 'stratum10': 10, 'kod-rate': 3}
    bad = 0
    lines = ['// SPDX-License-Identifier: MIT',
             '// GENERATED by modules/sntp/tools/ntp_oracle.py (chronyd 4.8, beevik/ntp v1.6.0, ntplib) -- do not hand-edit.',
             '//! A real chronyd answered every request below; `//= ` lines are the verdicts (this module, beevik/ntp and',
             '//! ntplib agree with the truth), which `zig build interop-sntp -- --check` compares. The exchanges are the raw',
             '//! replies with T1/T4, replayed through `decodeResponse` + `Sample` by `ntp_oracle_test.zig`.',
             '',
             'const root = @import("root.zig");',
             '',
             '/// What this module made of one recorded reply: a time, an error, or a Kiss-o\'-Death code.',
             'pub const Verdict = union(enum) { ok: struct { stratum: u8, offset_ns: i128, roundtrip_ns: i128 }, err: anyerror, kiss: root.KissCode };',
             'pub const Exchange = struct { scenario: []const u8, t1: root.Timestamp, t4: root.Timestamp, reply: []const u8, verdict: Verdict };',
             '',
             'pub const exchanges = [_]Exchange{']
    for r in results:
        name = r['name']
        why = []
        summary = []
        raws = [(v, x) for v, xs in sorted(r['raw'].items()) for x in xs if x is not None]
        judged = json.loads(subprocess.run([NTPLIB_PY, '-c', NTPLIB_JUDGE], input=json.dumps([x for _, x in raws]),
                                           capture_output=True, text=True, check=True).stdout) if raws else []
        bv = r['beevik']
        if name in ('stratum3', 'stratum10'):
            want = conf_stratum[name]
            for v, lv in sorted(r['live'].items()):
                if 'error' in lv:
                    why.append('live %s: %s' % (v, lv['error']))
                    continue
                ver = 4 if v == 'v6' else int(v)
                if lv['stratum'] != want or lv['leap'] != 0 or lv['version'] != ver or lv['refid'] != '7f7f0101':
                    why.append('live %s: %s' % (v, lv))
                if abs(lv['offset_ns']) > 2_000_000 or not 0 <= lv['roundtrip_ns'] < 20_000_000:
                    why.append('live %s: offset %d delay %d on one clock' % (v, lv['offset_ns'], lv['roundtrip_ns']))
            summary.append('query: stratum %d, no leap, version echoed (%s), LOCL, offset ~0' % (want, ' '.join(sorted(r['live']))))
            for (v, x), nl in zip(raws, judged):
                if 'error' in x or not x['originate_ok']:
                    why.append('raw v%s: %s' % (v, x))
                    continue
                if abs(nl['offset'] * 1e9 - x['offset_ns']) > 2000 or abs(nl['delay'] * 1e9 - x['roundtrip_ns']) > 2000:
                    why.append('raw v%s: ours offset %d delay %d, ntplib %.0f %.0f' % (
                        v, x['offset_ns'], x['roundtrip_ns'], nl['offset'] * 1e9, nl['delay'] * 1e9))
                if nl['stratum'] != x['stratum'] or nl['version'] != x['version'] or nl['leap'] != x['leap']:
                    why.append('raw v%s: ntplib reads %s, ours %s' % (v, nl, x))
            summary.append('codec: %d replies, offset/delay = ntplib on the same bytes (+-2 us, its f64)' % len(raws))
            if 'error' in bv or bv['stratum'] != want:
                why.append('beevik: %s' % bv)
            summary.append('beevik/ntp: valid, stratum %d' % want)
        elif name == 'unsynchronized':
            lv = r['live']['4']
            if 'error' not in lv:
                why.append('live: accepted %s' % lv)
            if 'error' not in bv:
                why.append('beevik accepted %s' % bv)
            errs = sorted({x.get('error', 'ok') for _, x in raws})
            if 'ok' in errs:
                why.append('codec accepted an unsynchronized reply')
            summary.append('query: %s; codec: %s; beevik/ntp: %s' % (lv.get('error'), ','.join(errs), bv.get('error')))
        elif name == 'kod-rate':
            kods = [x for _, x in raws if x.get('kiss')]
            if not kods or any(x['kiss'] != 'rate' for x in kods):
                why.append('codec saw no RATE kiss: %s' % [x.get('error', 'ok') for _, x in raws])
            if bv.get('kiss') != 'RATE' or 'error' not in bv:
                why.append('beevik: %s' % bv)
            if any('error' not in x and x['stratum'] != 3 for _, x in raws):
                why.append('a leaked reply is not stratum 3')
            summary.append('codec: KoD RATE among the limited replies; beevik/ntp: RATE, %s' % bv.get('error'))
        else:  # denied
            lv = r['live']['4']
            if lv.get('error') != 'Timeout':
                why.append('live: %s' % lv)
            if raws:
                why.append('denied client got %d replies' % len(raws))
            if 'error' not in bv:
                why.append('beevik: %s' % bv)
            summary.append('query: Timeout; codec: no reply; beevik/ntp: %s' % bv['error'].split(':')[-1].strip())
        if why:
            bad += 1
            sys.stderr.write('%s: %s\n' % (name, '; '.join(why)[:1500]))
        lines.append('    //= %s: %s%s' % (name, '; '.join(summary), '' if not why else ' -- DISAGREES'))
        for v, x in raws:
            if 'error' in x:
                verdict = '.{ .kiss = .%s }' % x['kiss'] if 'kiss' in x else '.{ .err = error.%s }' % x['error']
            else:
                verdict = '.{ .ok = .{ .stratum = %d, .offset_ns = %d, .roundtrip_ns = %d } }' % (
                    x['stratum'], x['offset_ns'], x['roundtrip_ns'])
            lines.append('    .{ .scenario = "%s", .t1 = %s, .t4 = %s, .reply = %s, .verdict = %s },' % (
                name, ts_to_zig(x['t1']), ts_to_zig(x['t4']), zbytes(x['reply']), verdict))
    lines.append('};')
    with open(out_path, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    sys.stderr.write('%d scenarios; %d where a client disagreed with the server or the truth\n' % (len(results), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'judge':
        sys.exit(judge(sys.argv[2], sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == 'inner':
        inner(sys.argv[2], sys.argv[3])
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
