#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The traceroute oracle: real Linux routers answer our probes.

Per scenario a fresh chain of network namespaces is built, client -> r1 ->
r2 -> r3 -> server (veth pairs, forwarding routers), and an nft rule shapes
it: clean; r2 drops its own Time Exceeded (a silent hop); r3 rejects
forwarding to the server with Administratively Prohibited; the server drops
everything from the client. Inside the client namespace `interop-traceroute
--trace` runs `traceWith` over the live transport, recording every packet.
The truth is the topology: the hop at TTL n is the address of router n's
interface toward the client, the server answers at TTL 4. traceroute(8) --
a third implementation -- traces the same path and must agree.

Driven by tools/interop.zig (`zig build interop-traceroute`):

    kernel_oracle.py judge EXE OUT    run every scenario; write the Zig vectors to OUT
    kernel_oracle.py inner EXE        (internal) runs inside `unshare -rmn`

Everything runs in `unshare -rmn` (a tmpfs over /run for `ip netns`); no root,
no network, nothing on the host changes.
"""
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys

MAX_HOPS = 8
PROBES = 2
TIMEOUT_MS = 300
NS = ('c', 'r1', 'r2', 'r3', 's')
SCENARIOS = ('clean', 'silent-r2', 'prohibited-r3', 'server-silent')


def a4(link, host):
    return '10.0.%d.%d' % (link, host)


def a6(link, host):
    return 'fd0%d::%d' % (link, host)


def addr(fam, link, host):
    return a4(link, host) if fam == 'v4' else a6(link, host)


DEST = {'v4': a4(3, 2), 'v6': a6(3, 2)}
CLIENT = {'v4': a4(0, 1), 'v6': a6(0, 1)}


def sh(*cmd, check=True, input=None):
    return subprocess.run(cmd, check=check, capture_output=True, text=True, input=input)


def topology():
    for n in NS:
        sh('ip', 'netns', 'del', n, check=False)
    for n in NS:
        sh('ip', 'netns', 'add', n)
        sh('ip', '-n', n, 'link', 'set', 'lo', 'up')
    # link k joins NS[k] (host .1) and NS[k+1] (host .2)
    for k in range(4):
        left, right = NS[k], NS[k + 1]
        sh('ip', 'link', 'add', 'l%d' % k, 'netns', left, 'type', 'veth', 'peer', 'name', 'r%d' % k, 'netns', right)
        for n, dev, host in ((left, 'l%d' % k, 1), (right, 'r%d' % k, 2)):
            sh('ip', '-n', n, 'addr', 'add', a4(k, host) + '/24', 'dev', dev)
            sh('ip', '-n', n, 'addr', 'add', a6(k, host) + '/64', 'dev', dev, 'nodad')
            sh('ip', '-n', n, 'link', 'set', dev, 'up')
    for i, n in enumerate(NS):
        if i < 4:  # toward the server
            sh('ip', '-n', n, 'route', 'add', 'default', 'via', a4(i, 2))
            sh('ip', '-n', n, '-6', 'route', 'add', 'default', 'via', a6(i, 2))
        for j in range(i - 1):  # back toward the client, via the left neighbour
            sh('ip', '-n', n, 'route', 'add', '10.0.%d.0/24' % j, 'via', a4(i - 1, 1))
            sh('ip', '-n', n, '-6', 'route', 'add', 'fd0%d::/64' % j, 'via', a6(i - 1, 1))
        if n.startswith('r'):
            sh('ip', 'netns', 'exec', n, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    # Warm every neighbour cache on the path before any rule can block the warm-up.
    for fam in ('v4', 'v6'):
        for _ in range(10):
            if sh('ip', 'netns', 'exec', 'c', 'ping', '-c1', '-W1', DEST[fam], check=False).returncode == 0:
                break
        else:
            raise RuntimeError('%s unreachable on a clean topology' % DEST[fam])


def shape(scenario):
    rules = {
        'clean': None,
        'silent-r2': ('r2', 'table inet t {\n chain c1 {\n  type filter hook output priority 0;\n'
                            '  icmp type time-exceeded drop\n  icmpv6 type time-exceeded drop\n }\n}\n'),
        'prohibited-r3': ('r3', 'table inet t {\n chain c1 {\n  type filter hook forward priority 0;\n'
                                '  ip daddr %s reject with icmp type admin-prohibited\n'
                                '  ip6 daddr %s reject with icmpv6 type admin-prohibited\n }\n}\n' % (DEST['v4'], DEST['v6'])),
        'server-silent': ('s', 'table inet t {\n chain c1 {\n  type filter hook input priority 0;\n'
                               '  ip saddr %s drop\n  ip6 saddr %s drop\n }\n}\n' % (CLIENT['v4'], CLIENT['v6'])),
    }[scenario]
    if rules:
        sh('ip', 'netns', 'exec', rules[0], 'nft', '-f', '-', input=rules[1])


def truth(scenario, fam, method):
    """[(kind, address, code)] per hop, every probe of a hop answering alike."""
    hop = lambda i: ('time_exceeded', addr(fam, i - 1, 2), None)
    reply_code = None if method == 'icmp' else (3 if fam == 'v4' else 4)
    reply = ('reply', DEST[fam], reply_code)
    if scenario == 'clean':
        return [hop(1), hop(2), hop(3), reply]
    if scenario == 'silent-r2':
        return [hop(1), ('timeout', None, None), hop(3), reply]
    if scenario == 'prohibited-r3':
        # TTL 3 expires at r3 before its forward filter runs; TTL 4 is forwarded and rejected.
        return [hop(1), hop(2), hop(3), ('dest_unreachable', addr(fam, 2, 2), 13 if fam == 'v4' else 1)]
    return [hop(1), hop(2), hop(3)] + [('timeout', None, None)] * (MAX_HOPS - 3)


def is_ip(t):
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def classic(fam, method):
    """traceroute(8)'s hops: [(addresses, flags)] per TTL."""
    args = ['ip', 'netns', 'exec', 'c', 'traceroute', '-n', '-q', str(PROBES), '-w', '%.1f' % (TIMEOUT_MS / 1000),
            '-m', str(MAX_HOPS)]
    if fam == 'v6':
        args.append('-6')
    if method == 'icmp':
        args.append('-I')
    out = sh(*(args + [DEST[fam]]), check=False).stdout
    hops = []
    for line in out.splitlines()[1:]:
        m = re.match(r'\s*(\d+)\s+(.*)$', line)
        if not m:
            continue
        toks = m.group(2).split()
        addrs = [t for t in toks if is_ip(t)]
        flags = [t for t in toks if t.startswith('!')]
        hops.append((sorted(set(addrs)), flags))
    return hops, out


def inner(exe):
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run'], check=True)
    os.makedirs('/run/netns', exist_ok=True)
    results = []
    for scenario in SCENARIOS:
        for fam in ('v4', 'v6'):
            for method in ('icmp', 'udp'):
                name = '%s-%s-%s' % (fam, method, scenario)
                topology()
                shape(scenario)
                p = sh('ip', 'netns', 'exec', 'c', exe, '--trace', DEST[fam], method, str(MAX_HOPS), str(PROBES),
                       str(TIMEOUT_MS), check=False)
                if p.returncode != 0:
                    results.append({'name': name, 'error': p.stderr[-400:]})
                    continue
                r = json.loads(p.stdout)
                topology()
                shape(scenario)
                r['classic'], r['classic_text'] = classic(fam, method)
                r.update(name=name, scenario=scenario, fam=fam, method=method)
                results.append(r)
    for n in NS:
        sh('ip', 'netns', 'del', n, check=False)
    json.dump(results, sys.stdout)


def zip_(ip):
    if ip is None:
        return 'null'
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return '.{ .v4 = .{ %s } }' % ', '.join(str(b) for b in a.packed)
    return '.{ .v6 = .{ %s } }' % ', '.join(str(b) for b in a.packed)


def zbytes(h):
    return '"%s"' % ''.join('\\x%s' % h[i:i + 2] for i in range(0, len(h), 2))


def zopt(v):
    return 'null' if v is None else str(v)


def judge(exe, out_path):
    p = subprocess.run(['unshare', '-rmn', sys.executable, os.path.abspath(__file__), 'inner', os.path.abspath(exe)],
                       capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if p.returncode != 0:
        return 1
    results = json.loads(p.stdout)
    v = sh('traceroute', '-V', check=False)
    version = (v.stdout + v.stderr).strip().split()[-1]
    bad = 0
    o = ['// SPDX-License-Identifier: MIT',
         '// GENERATED by modules/traceroute/tools/kernel_oracle.py (Linux %s, traceroute %s) -- do not hand-edit.' % (
             platform.release(), version),
         '//! Real routers in a client -> r1 -> r2 -> r3 -> server namespace chain answered every probe below; each',
         '//! hop is the router the topology puts at that TTL, and traceroute(8) traced the same hops. `//= ` lines',
         '//! are the verdicts `zig build interop-traceroute -- --check` compares; the transcripts are refreshed.',
         '//! Replayed through `traceWith` by `kernel_oracle_test.zig`. Regenerate: `zig build interop-traceroute`.',
         '',
         'const root = @import("root.zig");',
         'const netaddr = @import("netaddr");',
         '',
         '/// One transport call as it happened: a probe sent, a packet received, or a receive that timed out.',
         'pub const Event = union(enum) {',
         '    send: struct { ttl: u8, bytes: []const u8 },',
         '    send_udp: struct { ttl: u8, port: u16, bytes: []const u8 },',
         '    recv: struct { bytes: []const u8, from: ?netaddr.Ip },',
         '    timeout,',
         '};',
         '/// What one probe came to, as `traceWith` reported it live.',
         'pub const Seen = struct { kind: root.Probe.Kind, address: ?netaddr.Ip, code: ?u8, rtt_ns: ?u64 };',
         'pub const Scenario = struct { name: []const u8, dest: netaddr.Ip, method: root.Method, ident: u16,',
         '    events: []const Event, reached: bool, unreachable_code: ?u8, hops: []const []const Seen };',
         '',
         'pub const max_hops = %d;' % MAX_HOPS,
         'pub const probes_per_hop = %d;' % PROBES,
         'pub const timeout_ms = %d;' % TIMEOUT_MS,
         '',
         'pub const scenarios = [_]Scenario{']
    for r in results:
        name = r['name']
        if 'error' in r:
            bad += 1
            sys.stderr.write('%s: trace failed: %s\n' % (name, r['error']))
            continue
        want = truth(r['scenario'], r['fam'], r['method'])
        why = []
        got = []
        for hop in r['hops']:
            kinds = {(k, a, c) for k, a, c, _ in hop}
            got.append(kinds)
        if len(got) != len(want):
            why.append('%d hops, topology says %d' % (len(got), len(want)))
        for i, (g, w) in enumerate(zip(got, want)):
            if g != {w}:
                why.append('TTL %d: %s, topology says %s' % (i + 1, sorted(g, key=str), w))
        want_reached = want[-1][0] == 'reply'
        if r['reached'] != want_reached:
            why.append('reached=%s' % r['reached'])
        want_code = want[-1][2] if want[-1][0] == 'dest_unreachable' else None
        if r['unreachable_code'] != want_code:
            why.append('unreachable_code=%s' % r['unreachable_code'])
        # traceroute(8): the same responder at every TTL it printed, the same flag on a prohibited hop.
        cl = r['classic']
        for i, w in enumerate(want):
            if i >= len(cl):
                if w[0] != 'timeout':
                    why.append('traceroute(8) stopped before TTL %d' % (i + 1))
                break
            addrs, flags = cl[i]
            if addrs != ([w[1]] if w[1] else []):
                why.append('traceroute(8) TTL %d: %s, topology says %s' % (i + 1, addrs, w[1]))
            if w[0] == 'dest_unreachable' and '!X' not in flags:
                why.append('traceroute(8) TTL %d: flags %s, want !X' % (i + 1, flags))
        if why:
            bad += 1
            sys.stderr.write('%s: %s\n%s\n' % (name, '; '.join(why), r['classic_text']))
            continue
        ev = []
        for e in r['events']:
            if e[0] == 'send':
                ev.append('.{ .send = .{ .ttl = %d, .bytes = %s } }' % (e[1], zbytes(e[2])))
            elif e[0] == 'send_udp':
                ev.append('.{ .send_udp = .{ .ttl = %d, .port = %d, .bytes = %s } }' % (e[1], e[2], zbytes(e[3])))
            elif e[0] == 'recv':
                ev.append('.{ .recv = .{ .bytes = %s, .from = %s } }' % (zbytes(e[1]), zip_(e[2])))
            else:
                ev.append('.timeout')
        hops = []
        for hop in r['hops']:
            hops.append('&.{ %s }' % ', '.join('.{ .kind = .%s, .address = %s, .code = %s, .rtt_ns = %s }' % (
                k, zip_(a), zopt(c), zopt(rtt)) for k, a, c, rtt in hop))
        o.append('    //= %s: %s%s' % (name, ' | '.join('%s %s%s' % (w[0], w[1] or '*', '' if w[2] is None else ' code %d' % w[2])
                                                        for w in want), '; traceroute(8) agrees'))
        o.append('    .{ .name = "%s", .dest = %s, .method = .%s, .ident = %d, .events = &.{ %s }, .reached = %s, '
                 '.unreachable_code = %s, .hops = &.{ %s } },' % (
                     name, zip_(DEST[r['fam']]), r['method'], r['ident'], ', '.join(ev), 'true' if r['reached'] else 'false',
                     zopt(r['unreachable_code']), ', '.join(hops)))
    o.append('};')
    with open(out_path, 'w') as fh:
        fh.write('\n'.join(o) + '\n')
    sys.stderr.write('%d traces; %d where ours or traceroute(8) disagreed with the topology\n' % (len(results), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'judge':
        sys.exit(judge(sys.argv[2], sys.argv[3]))
    elif len(sys.argv) == 3 and sys.argv[1] == 'inner':
        inner(sys.argv[2])
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
