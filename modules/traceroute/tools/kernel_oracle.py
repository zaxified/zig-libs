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
import time

MAX_HOPS = 8
PROBES = 2
TIMEOUT_MS = 300
NS = ('c', 'r1', 'r2', 'r3', 's')
SCENARIOS = ('clean', 'silent-r2', 'prohibited-r3', 'server-silent', 'open-port')
TCP_PORT = 8080  # tools/interop.zig's tcp_port
LISTENER = '''import socket, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(('::', %d))
s.listen()
time.sleep(60)
''' % TCP_PORT


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
    # Ping sockets for the client's group (icmp-dgram); a fresh netns allows none.
    sh('ip', 'netns', 'exec', 'c', 'sysctl', '-qw', 'net.ipv4.ping_group_range=0 0')
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
        'open-port': None,
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
    if method.startswith('tcp'):
        reply_code = 0 if scenario == 'open-port' else 1
    else:
        reply_code = None if method.startswith('icmp') else (3 if fam == 'v4' else 4)
    reply = ('reply', DEST[fam], reply_code)
    if scenario in ('clean', 'open-port'):
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
    if method.startswith('icmp'):
        args.append('-I')
    if method.startswith('tcp'):
        args += ['-T', '-p', str(TCP_PORT)]
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
            for method in ('icmp', 'udp', 'tcp', 'icmp-dgram', 'udp-dgram', 'icmp-flow', 'udp-flow', 'udp-dgram-flow'):
                if method.endswith('flow') and scenario not in ('clean', 'prohibited-r3'):
                    continue
                if scenario == 'open-port' and method != 'tcp':
                    continue
                name = '%s-%s-%s' % (fam, method, scenario)
                topology()
                shape(scenario)
                listener = None
                if scenario == 'open-port':
                    listener = subprocess.Popen(['ip', 'netns', 'exec', 's', sys.executable, '-c', LISTENER])
                    time.sleep(0.5)
                p = sh('ip', 'netns', 'exec', 'c', exe, '--trace', DEST[fam], method, str(MAX_HOPS), str(PROBES),
                       str(TIMEOUT_MS), check=False)
                if p.returncode != 0:
                    results.append({'name': name, 'error': p.stderr[-400:]})
                    if listener:
                        listener.kill()
                        listener.wait()
                    continue
                r = json.loads(p.stdout)
                if listener:
                    listener.kill()
                    listener.wait()
                topology()
                shape(scenario)
                if listener:
                    listener = subprocess.Popen(['ip', 'netns', 'exec', 's', sys.executable, '-c', LISTENER])
                    time.sleep(0.5)
                r['classic'], r['classic_text'] = classic(fam, method)
                if listener:
                    listener.kill()
                    listener.wait()
                r.update(name=name, scenario=scenario, fam=fam, method=method)
                results.append(r)
    results.extend(mtr_scenarios(exe))
    results.extend(parallel_scenarios(exe))
    results.append(ecmp(exe))
    for n in NS + ('r2b',):
        sh('ip', 'netns', 'del', n, check=False)
    json.dump(results, sys.stdout)


def mtr_answerers(fam, method):
    """mtr(8) itself: the addresses of each TTL it reports."""
    args = ['ip', 'netns', 'exec', 'c', 'mtr', '-r', '-n', '-c', '3', '-i', '0.2', '--timeout', '1', '-m', str(MAX_HOPS)]
    if fam == 'v6':
        args.append('-6')
    if method.startswith('udp'):
        args += ['--udp', '-P', '33434']
    elif method.startswith('tcp'):
        args += ['--tcp', '-P', str(TCP_PORT)]
    out = sh(*(args + [DEST[fam]]), check=False)
    hops = {}
    for line in out.stdout.splitlines():
        m = re.match(r'\s*(\d+)\.(?:\|--|`--)\s+(\S+)', line)
        if m and m.group(2) != '???':
            hops[int(m.group(1))] = m.group(2)
    return hops, out.stdout + out.stderr


def mtr_scenarios(exe):
    """Continuous mode over a clean chain: `LiveMtr` against the topology and mtr(8), `LiveMtrSet` with the server and
    r3 as two members (r3 ends a hop earlier)."""
    results = []
    for fam in ('v4', 'v6'):
        for method in ('icmp', 'udp', 'udp-flow', 'udp-dgram-flow', 'tcp', 'icmp-dgram'):
            name = 'mtr-%s-%s' % (fam, method)
            topology()
            p = sh('ip', 'netns', 'exec', 'c', exe, '--mtr', method, str(MAX_HOPS), str(TIMEOUT_MS), DEST[fam], check=False)
            want = [[addr(fam, i, 2)] for i in range(4)]
            why = []
            if p.returncode != 0:
                why.append('failed: ' + p.stderr[-300:])
            else:
                r = json.loads(p.stdout)[0]
                if not r['reached'] or r['hops'] != want:
                    why.append('%s, topology says %s' % (r, want))
            if not method.endswith('dgram') and not method.endswith('flow'):
                topology()
                seen, text = mtr_answerers(fam, method)
                if {k: v for k, v in seen.items()} != {i + 1: w[0] for i, w in enumerate(want)}:
                    why.append('mtr(8) saw %s:\n%s' % (seen, text))
            results.append({'name': name, 'mtr': True, 'why': why})
        for method in ('icmp', 'udp-flow', 'tcp'):
            name = 'mtrset-%s-%s' % (fam, method)
            topology()
            other = addr(fam, 2, 2)
            p = sh('ip', 'netns', 'exec', 'c', exe, '--mtr', method, str(MAX_HOPS), str(TIMEOUT_MS), DEST[fam], other, check=False)
            why = []
            if p.returncode != 0:
                why.append('failed: ' + p.stderr[-300:])
            else:
                a, b = json.loads(p.stdout)
                want_a = [[addr(fam, i, 2)] for i in range(4)]
                want_b = [[addr(fam, i, 2)] for i in range(3)]
                if not a['reached'] or a['hops'] != want_a or not b['reached'] or b['hops'] != want_b:
                    why.append('%s %s' % (a, b))
            results.append({'name': name, 'mtr': True, 'why': why})
    return results


def parallel_scenarios(exe):
    """A window of 4 on the live chain: the same trace, every method, including a filter's errors arriving while more
    probes are out, which is when a socket's pending error meets the next send."""
    results = []
    for fam in ('v4', 'v6'):
        for scenario in ('clean', 'prohibited-r3', 'silent-r2'):
            for method in ('icmp', 'udp', 'tcp', 'icmp-dgram', 'udp-dgram', 'udp-flow'):
                name = 'parallel-%s-%s-%s' % (fam, method, scenario)
                topology()
                shape(scenario)
                p = sh('ip', 'netns', 'exec', 'c', exe, '--trace', DEST[fam], method + '-par', str(MAX_HOPS), str(PROBES), str(TIMEOUT_MS), check=False)
                why = []
                if p.returncode != 0:
                    why.append('failed: ' + p.stderr[-300:])
                else:
                    r = json.loads(p.stdout)
                    want = truth(scenario, fam, method)
                    got = [{(k, a, c) for k, a, c, _ in hop} for hop in r['hops']]
                    if got != [{w} for w in want]:
                        why.append('%s, topology says %s' % (got, want))
                results.append({'name': name, 'mtr': True, 'why': why})
    return results


def ecmp(exe):
    """r1 balances the server's prefix over r2 and r2b by the UDP 5-tuple: classic UDP probes, whose ports differ,
    see both at TTL 2; flow-stable ones must see one. Hash seeds differ per netns, so classic gets three takes."""
    topology()
    sh('ip', 'netns', 'add', 'r2b')
    sh('ip', '-n', 'r2b', 'link', 'set', 'lo', 'up')
    for dev, left, right, net in (('m1', 'r1', 'r2b', 11), ('m2', 'r2b', 'r3', 12)):
        sh('ip', 'link', 'add', dev + 'l', 'netns', left, 'type', 'veth', 'peer', 'name', dev + 'r', 'netns', right)
        for n, d, host in ((left, dev + 'l', 1), (right, dev + 'r', 2)):
            sh('ip', '-n', n, 'addr', 'add', '10.0.%d.%d/24' % (net, host), 'dev', d)
            sh('ip', '-n', n, 'link', 'set', d, 'up')
    sh('ip', 'netns', 'exec', 'r2b', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
    sh('ip', '-n', 'r2b', 'route', 'add', '10.0.3.0/24', 'via', '10.0.12.2')
    sh('ip', '-n', 'r2b', 'route', 'add', 'default', 'via', '10.0.11.1')
    sh('ip', 'netns', 'exec', 'r1', 'sysctl', '-qw', 'net.ipv4.fib_multipath_hash_policy=1')
    sh('ip', '-n', 'r1', 'route', 'add', '10.0.3.0/24', 'nexthop', 'via', a4(1, 2), 'nexthop', 'via', '10.0.11.2')
    for target in (a4(1, 2), '10.0.11.2'):
        sh('ip', 'netns', 'exec', 'r1', 'ping', '-c1', '-W1', target, check=False)
    sh('ip', 'netns', 'exec', 'r2b', 'ping', '-c1', '-W1', '10.0.12.2', check=False)

    def ttl2(method):
        p = sh('ip', 'netns', 'exec', 'c', exe, '--trace', DEST['v4'], method, str(MAX_HOPS), '8', str(TIMEOUT_MS), check=False)
        if p.returncode != 0:
            return None, p.stderr[-400:]
        r = json.loads(p.stdout)
        return {a for _, a, _, _ in r['hops'][1] if a}, r['reached']

    out = {'name': 'ecmp', 'classic': [], 'flow': {}}
    for _ in range(3):
        addrs, _reached = ttl2('udp')
        out['classic'].append(sorted(addrs) if addrs is not None else None)
    for method in ('udp-flow', 'udp-dgram-flow'):
        addrs, reached = ttl2(method)
        out['flow'][method] = [sorted(addrs) if addrs is not None else None, reached]
    # Our checksum arithmetic against the kernel's: with offload off the client's veth computes the real UDP checksum,
    # which the routers quote back. It must be the id the payload also carries.
    sh('ip', 'netns', 'exec', 'c', 'ethtool', '-K', 'l0', 'tx', 'off')
    p = sh('ip', 'netns', 'exec', 'c', exe, '--trace', DEST['v4'], 'udp-flow', str(MAX_HOPS), str(PROBES), str(TIMEOUT_MS), check=False)
    out['checksums'] = []
    if p.returncode == 0:
        for e in json.loads(p.stdout)['events']:
            if e[0] != 'recv':
                continue
            b = bytes.fromhex(e[1])
            udp = (b[0] & 0x0f) * 4 + 8 + 20
            out['checksums'].append([b[udp + 6:udp + 8].hex(), b[udp + 10:udp + 12].hex()])
    return out


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
    version = re.search(r'\d+\.\d+\.\d+', v.stdout + v.stderr).group(0)
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
         '    send_tcp: struct { ttl: u8, port: u16, wire: u16 },',
         '    recv_tcp: root.TcpEvent,',
         '    recv: struct { bytes: []const u8, from: ?netaddr.Ip },',
         '    timeout,',
         '};',
         '/// What one probe came to, as `traceWith` reported it live.',
         'pub const Seen = struct { kind: root.Probe.Kind, address: ?netaddr.Ip, code: ?u8, rtt_ns: ?u64 };',
         'pub const Scenario = struct { name: []const u8, dest: netaddr.Ip, method: root.Method, flow_source: ?netaddr.Ip, ident: u16,',
         '    socket_dgram: bool, strip_ip_header: bool, events: []const Event, reached: bool, unreachable_code: ?u8,',
         '    hops: []const []const Seen };',
         '',
         'pub const max_hops = %d;' % MAX_HOPS,
         'pub const probes_per_hop = %d;' % PROBES,
         'pub const timeout_ms = %d;' % TIMEOUT_MS,
         '',
         'pub const scenarios = [_]Scenario{']
    for r in results:
        name = r['name']
        if r.get('mtr'):
            if r['why']:
                bad += 1
                sys.stderr.write('%s: %s\n' % (name, '; '.join(r['why'])))
            else:
                o.append('    //= %s: every TTL the router the topology puts there%s' % (
                    name, '; mtr(8) agrees' if name.split('-')[0] == 'mtr' and name.split('-', 2)[2] in ('icmp', 'udp', 'tcp') else ''))
            continue
        if name == 'ecmp':
            split = any(c is not None and len(c) == 2 for c in r['classic'])
            stable = all(a is not None and len(a) == 1 and reached is True for a, reached in r['flow'].values())
            solved = r['checksums'] and all(c == i for c, i in r['checksums'])
            if not split or not stable or not solved:
                bad += 1
                sys.stderr.write('ecmp: classic %s, flow %s, checksums %s\n' % (r['classic'], r['flow'], r['checksums']))
            else:
                o.append('    //= ecmp: classic UDP probes see both balanced routers at TTL 2, flow-stable ones see one; '
                         'the kernel computes the UDP checksum the id asks for')
            continue
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
            elif e[0] == 'send_tcp':
                ev.append('.{ .send_tcp = .{ .ttl = %d, .port = %d, .wire = %d } }' % (e[1], e[2], e[3]))
            elif e[0] == 'recv_tcp':
                ev.append('.{ .recv_tcp = .{ .wire = %d, .kind = .%s, .from = %s, .code = %d } }' % (e[1], e[2], zip_(e[3]), e[4]))
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
        o.append('    .{ .name = "%s", .dest = %s, .method = .%s, .flow_source = %s, .ident = %d, .socket_dgram = %s, .strip_ip_header = %s, .events = &.{ %s }, '
                 '.reached = %s, .unreachable_code = %s, .hops = &.{ %s } },' % (
                     name, zip_(DEST[r['fam']]), r['method'].split('-')[0], zip_(CLIENT[r['fam']]) if r['method'].endswith('flow') else 'null', r['ident'],
                     'true' if 'dgram' in r['method'] else 'false',
                     'true' if r['strip_ip_header'] else 'false', ', '.join(ev), 'true' if r['reached'] else 'false',
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
