#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The pathmtu oracle: real Linux kernels forward and refuse our probes.

For each scenario a fresh client -> router -> server topology of network
namespaces is built (veth pairs, a forwarding router), with the link MTUs the
scenario names; optionally the router's firewall drops its own ICMP
Fragmentation Needed / Packet Too Big -- an ICMP black hole. Inside the
client namespace `interop-pathmtu --probe` runs `query`, `probe` (recording
every attempt) and `query` again, and iputils `tracepath` measures the same
path its own way. The answer is the smallest configured link MTU on the path;
`probe` must find it, flag a black hole exactly when the router was made one,
and `tracepath` -- a third implementation -- must agree wherever it can see.

Driven by tools/interop.zig (`zig build interop-pathmtu`):

    kernel_oracle.py judge EXE OUT    run every scenario; write the Zig vectors to OUT
    kernel_oracle.py inner EXE        (internal) runs inside `unshare -rmn`

Everything runs in `unshare -rmn` (a tmpfs over /run for `ip netns`); no root,
no network, nothing on the host changes.
"""
import json
import os
import platform
import re
import subprocess
import sys

TIMEOUT_MS = 200
RETRIES = 1

# (name, family, client-link MTU, bottleneck router->server MTU, black hole)
SCENARIOS = []
for fam in ('v4', 'v6'):
    for m in ([576, 1000, 1280, 1300, 1400, 1492, 1499] if fam == 'v4' else [1280, 1300, 1400, 1492, 1499]):
        SCENARIOS.append(('%s-bottleneck-%d' % (fam, m), fam, 1500, m, False))
    SCENARIOS.append(('%s-no-bottleneck' % fam, fam, 1500, 1500, False))
    SCENARIOS.append(('%s-jumbo-4000' % fam, fam, 9000, 4000, False))
    SCENARIOS.append(('%s-jumbo-clean' % fam, fam, 9000, 9000, False))
    SCENARIOS.append(('%s-blackhole-1300' % fam, fam, 1500, 1300, True))
    SCENARIOS.append(('%s-blackhole-1400' % fam, fam, 1500, 1400, True))

DEST = {'v4': '10.0.1.1', 'v6': 'fd01::1'}


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def topology(client_mtu, bottleneck, blackhole):
    for n in ('c', 'r', 's'):
        sh('ip', 'netns', 'del', n, check=False)
    for n in ('c', 'r', 's'):
        sh('ip', 'netns', 'add', n)
        sh('ip', '-n', n, 'link', 'set', 'lo', 'up')
    sh('ip', 'link', 'add', 'vc', 'netns', 'c', 'type', 'veth', 'peer', 'name', 'vr1', 'netns', 'r')
    sh('ip', 'link', 'add', 'vs', 'netns', 's', 'type', 'veth', 'peer', 'name', 'vr2', 'netns', 'r')
    for n, dev, a4, a6, mtu in (('c', 'vc', '10.0.0.1/24', 'fd00::1/64', client_mtu),
                                ('r', 'vr1', '10.0.0.2/24', 'fd00::2/64', client_mtu),
                                ('r', 'vr2', '10.0.1.2/24', 'fd01::2/64', bottleneck),
                                ('s', 'vs', '10.0.1.1/24', 'fd01::1/64', bottleneck)):
        sh('ip', '-n', n, 'link', 'set', dev, 'mtu', str(mtu))
        sh('ip', '-n', n, 'addr', 'add', a4, 'dev', dev)
        if mtu >= 1280:  # below it the kernel turns IPv6 off on the link (v4-only scenarios)
            sh('ip', '-n', n, 'addr', 'add', a6, 'dev', dev, 'nodad')
        sh('ip', '-n', n, 'link', 'set', dev, 'up')
    sh('ip', '-n', 'c', 'route', 'add', 'default', 'via', '10.0.0.2')
    sh('ip', '-n', 'c', '-6', 'route', 'add', 'default', 'via', 'fd00::2')
    sh('ip', '-n', 's', 'route', 'add', 'default', 'via', '10.0.1.2')
    if bottleneck >= 1280:
        sh('ip', '-n', 's', '-6', 'route', 'add', 'default', 'via', 'fd01::2')
    sh('ip', 'netns', 'exec', 'r', 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    if blackhole:
        # The router still refuses to forward the oversized DF packet, but its own error never leaves it.
        rules = ('table inet bh {\n chain out {\n  type filter hook output priority 0;\n'
                 '  icmp type destination-unreachable icmp code frag-needed drop\n'
                 '  icmpv6 type packet-too-big drop\n }\n}\n')
        subprocess.run(['ip', 'netns', 'exec', 'r', 'nft', '-f', '-'], input=rules, text=True, check=True)


def warm(dest):
    """Small pings until one comes back: the first packets of a fresh topology wait on neighbour discovery
    (about a second on the IPv6 hop), longer than the probe's short per-attempt timeout."""
    for _ in range(10):
        if sh('ip', 'netns', 'exec', 'c', 'ping', '-c1', '-W1', '-s', '16', dest, check=False).returncode == 0:
            return
    raise RuntimeError('%s never answered a small ping' % dest)


def tracepath(dest):
    out = sh('ip', 'netns', 'exec', 'c', 'tracepath', '-n', '-m', '4', dest, check=False).stdout
    m = re.search(r'Resume: pmtu (\d+)', out)
    return int(m.group(1)) if m else None


def inner(exe):
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run'], check=True)
    os.makedirs('/run/netns', exist_ok=True)
    results = []
    for name, fam, cmtu, bmtu, bh in SCENARIOS:
        topology(cmtu, bmtu, bh)
        warm(DEST[fam])
        p = sh('ip', 'netns', 'exec', 'c', exe, '--probe', DEST[fam], 'vc', str(TIMEOUT_MS), str(RETRIES), check=False)
        if p.returncode != 0:
            sys.stderr.write('%s: probe exited %d: %s\n' % (name, p.returncode, p.stderr[-500:]))
            results.append({'name': name, 'error': p.returncode})
            continue
        r = json.loads(p.stdout)
        # tracepath on a fresh topology: the probe just taught the kernel the path MTU.
        topology(cmtu, bmtu, bh)
        warm(DEST[fam])
        r['tracepath'] = tracepath(DEST[fam])
        r['name'] = name
        results.append(r)
    for n in ('c', 'r', 's'):
        sh('ip', 'netns', 'del', n, check=False)
    json.dump(results, sys.stdout)


def zopt(v):
    return 'null' if v is None else str(v)


def judge(exe, out_path):
    exe = os.path.abspath(exe)
    p = subprocess.run(['unshare', '-rmn', sys.executable, os.path.abspath(__file__), 'inner', exe],
                       capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if p.returncode != 0:
        return 1
    results = {r['name']: r for r in json.loads(p.stdout)}
    tp_version = sh('tracepath', '-V', check=False).stdout.splitlines()[0].split()[-1]
    kernel = platform.release()
    bad = 0
    o = ['// SPDX-License-Identifier: MIT',
         '// GENERATED by modules/pathmtu/tools/kernel_oracle.py (Linux %s, tracepath %s) -- do not hand-edit.' % (
             kernel, tp_version),
         '//! Real kernels in a client -> router -> server namespace topology answered every probe below; the',
         '//! answer is the smallest configured link MTU, iputils tracepath agreed where it could see.',
         '//! Replayed through `searchWith` by `kernel_oracle_test.zig`. Regenerate: `zig build interop-pathmtu`.',
         '',
         'const root = @import("root.zig");',
         '',
         '/// One attempt the live prober made, in order, and what the kernel answered.',
         'pub const Attempt = struct { size: u16, outcome: root.ProbeOutcome };',
         '/// `truth`: the smallest configured link MTU; `blackhole`: the router dropped its own ICMP errors.',
         '/// `mtu`/`flagged`: what `probe` reported; `query_after`: the kernel cache once `probe` was done;',
         '/// `tracepath`: iputils tracepath\'s pmtu on a fresh copy of the topology (null: it saw none).',
         'pub const Scenario = struct { name: []const u8, v6: bool, client_mtu: u16, truth: u16, blackhole: bool,',
         '    attempts: []const Attempt, mtu: u32, flagged: bool, query_after: u32, tracepath: ?u32 };',
         '',
         'pub const scenarios = [_]Scenario{']
    for name, fam, cmtu, bmtu, bh in SCENARIOS:
        r = results.get(name)
        why = []
        if r is None or 'error' in r:
            why.append('no result')
        else:
            pr = r['probe']
            truth = min(cmtu, bmtu)
            if not isinstance(pr, dict):
                why.append('probe failed: %s' % pr)
            else:
                if pr['mtu'] != truth:
                    why.append('probe mtu %d, link says %d' % (pr['mtu'], truth))
                if pr['blackhole'] != bh:
                    why.append('probe blackhole=%s, router %s' % (pr['blackhole'], 'drops its ICMP' if bh else 'answers'))
            if not bh and r['tracepath'] != truth:
                why.append('tracepath pmtu %s, link says %d' % (r['tracepath'], truth))
            qa = r['query_after']
            if not isinstance(qa, dict):
                why.append('query after: %s' % qa)
            elif not bh and qa['mtu'] != truth:
                why.append('query after probe %d, link says %d' % (qa['mtu'], truth))
        if why:
            bad += 1
            sys.stderr.write('%s: %s\n  %s\n' % (name, '; '.join(why), json.dumps(r)[:600]))
            continue
        att = []
        for size, outcome, hint in r['attempts']:
            if outcome == 'frag_needed':
                att.append('.{ .size = %d, .outcome = .{ .frag_needed = %s } }' % (size, zopt(hint)))
            else:
                att.append('.{ .size = %d, .outcome = .%s }' % (size, outcome))
        o.append('    .{ .name = "%s", .v6 = %s, .client_mtu = %d, .truth = %d, .blackhole = %s, .attempts = &.{ %s }, '
                 '.mtu = %d, .flagged = %s, .query_after = %d, .tracepath = %s },' % (
                     name, 'true' if fam == 'v6' else 'false', cmtu, min(cmtu, bmtu), 'true' if bh else 'false',
                     ', '.join(att), r['probe']['mtu'], 'true' if r['probe']['blackhole'] else 'false',
                     r['query_after']['mtu'], zopt(r['tracepath'])))
    o.append('};')
    with open(out_path, 'w') as fh:
        fh.write('\n'.join(o) + '\n')
    sys.stderr.write('%d scenarios; %d where probe, query or tracepath disagreed with the links\n' % (len(SCENARIOS), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'judge':
        sys.exit(judge(sys.argv[2], sys.argv[3]))
    elif len(sys.argv) == 3 and sys.argv[1] == 'inner':
        inner(sys.argv[2])
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
