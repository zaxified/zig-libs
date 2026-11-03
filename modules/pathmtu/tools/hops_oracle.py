#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The pathmtu per-hop oracle: `probeHops` against real kernels and iputils tracepath.

For each scenario a fresh client -> r1 -> r2 -> server topology of network
namespaces is built (veth pairs, forwarding routers) with the link MTUs the
scenario names; optionally r2's firewall drops its own ICMP Fragmentation
Needed / Packet Too Big (an ICMP black hole in front of the server). Inside
the client namespace `interop-pathmtu --hops` walks the path once per ICMP
socket kind (the unprivileged DGRAM one and the RAW one), and iputils
`tracepath -n` walks it its own way. What must hold:

  * the hops are r1, r2, server, in order, the last one flagged as the destination;
  * hop i's mtu is the smallest link MTU in front of it (the configured truth);
  * the hop whose probe was too big names the router in front of the smaller link;
  * on the black-hole path the walk says so (`blackhole`) and still finds the link MTU;
  * a forged Frag-Needed / Packet-Too-Big that lowered the route PMTU first changes nothing;
  * tracepath's per-hop addresses equal ours and, on a path that answers, its
    final pmtu equals ours.

Driven by tools/interop.zig (`zig build interop-pathmtu -- --hops-oracle`):

    hops_oracle.py judge EXE      run every scenario; exit 1 if any disagreed
    hops_oracle.py inner EXE      (internal) runs inside `unshare -rmn`

Everything runs in `unshare -rmn`; no root, no network, nothing on the host changes.
"""
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

TIMEOUT_MS = 200
RETRIES = 1

# (name, family, client link, r1->r2 link, r2->server link, black hole at r2)
SCENARIOS = []
for fam in ('v4', 'v6'):
    SCENARIOS.append(('%s-clean' % fam, fam, 1500, 1500, 1500, False))
    SCENARIOS.append(('%s-narrow-middle' % fam, fam, 1500, 1400, 1500, False))
    SCENARIOS.append(('%s-narrow-twice' % fam, fam, 1500, 1400, 1300, False))
    SCENARIOS.append(('%s-narrow-last' % fam, fam, 1500, 1500, 1280, False))
    SCENARIOS.append(('%s-jumbo' % fam, fam, 9000, 4000, 1500, False))
    SCENARIOS.append(('%s-blackhole-last' % fam, fam, 1500, 1500, 1300, True))
    # A clean path whose route PMTU a forged Frag-Needed lowered before the walk: `forge_ptb`.
    SCENARIOS.append(('%s-forged-route-pmtu' % fam, fam, 1500, 1500, 1500, False))

ADDR = {
    'v4': ('10.0.0.2', '10.0.1.2', '10.0.2.1'),   # r1 (client side), r2 (r1 side), server
    'v6': ('fd00::2', 'fd01::2', 'fd02::1'),
}
CLIENT = {'v4': '10.0.0.1', 'v6': 'fd00::1'}
FORGED_MTU = {'v4': 1000, 'v6': 1300}


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def ns_socket(name, *args):
    """A socket living in namespace `name`; this process stays where it is."""
    home = os.open('/proc/self/ns/net', os.O_RDONLY)
    there = os.open('/run/netns/' + name, os.O_RDONLY)
    os.setns(there, os.CLONE_NEWNET)
    s = socket.socket(*args)
    os.setns(home, os.CLONE_NEWNET)
    os.close(there)
    os.close(home)
    return s


def inet_sum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def forge_ptb(fam, dest):
    """Lower the client's route PMTU to `dest` with a Frag-Needed / Packet-Too-Big no router on the
    path ever sent: r1 quotes a UDP socket's own datagram, as anyone who can see it could. The
    kernel must have taken it, or the scenario proves nothing."""
    client = CLIENT[fam]
    mtu = FORGED_MTU[fam]
    af = socket.AF_INET if fam == 'v4' else socket.AF_INET6
    victim = ns_socket('c', af, socket.SOCK_DGRAM)
    victim.connect((dest, 33434))
    victim.send(b'x')
    udp = struct.pack('!HHHH', victim.getsockname()[1], 33434, 9, 0)
    if fam == 'v4':
        hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 29, 1, 0x4000, 64, socket.IPPROTO_UDP, 0,
                          socket.inet_aton(client), socket.inet_aton(dest))
        hdr = hdr[:10] + struct.pack('!H', inet_sum(hdr)) + hdr[12:]
        body = struct.pack('!BBHHH', 3, 4, 0, 0, mtu) + hdr + udp
        msg = body[:2] + struct.pack('!H', inet_sum(body)) + body[4:]
        raw = ns_socket('r1', af, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    else:
        hdr = struct.pack('!IHBB16s16s', 6 << 28, 9, socket.IPPROTO_UDP, 64,
                          socket.inet_pton(af, client), socket.inet_pton(af, dest))
        msg = struct.pack('!BBHI', 2, 0, 0, mtu) + hdr + udp  # the kernel fills an ICMPv6 checksum in
        raw = ns_socket('r1', af, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    raw.sendto(msg, (client, 0))
    raw.close()
    route = ['ip', '-n', 'c'] + ([] if fam == 'v4' else ['-6']) + ['route', 'get', dest]
    for _ in range(50):
        got = sh(*route).stdout
        if re.search(r'\bmtu %d\b' % mtu, got):
            victim.close()
            return
        time.sleep(0.02)
    raise RuntimeError('the forged message did not lower the route PMTU: %s' % got)


def topology(c_mtu, m1, m2, blackhole):
    for n in ('c', 'r1', 'r2', 's'):
        sh('ip', 'netns', 'del', n, check=False)
    for n in ('c', 'r1', 'r2', 's'):
        sh('ip', 'netns', 'add', n)
        sh('ip', '-n', n, 'link', 'set', 'lo', 'up')
    sh('ip', 'link', 'add', 'vc', 'netns', 'c', 'type', 'veth', 'peer', 'name', 'va', 'netns', 'r1')
    sh('ip', 'link', 'add', 'vb', 'netns', 'r1', 'type', 'veth', 'peer', 'name', 'vc2', 'netns', 'r2')
    sh('ip', 'link', 'add', 'vd', 'netns', 'r2', 'type', 'veth', 'peer', 'name', 'vs', 'netns', 's')
    # (netns, dev, v4 address, v6 address, mtu)
    for n, dev, a4, a6, mtu in (('c', 'vc', '10.0.0.1/24', 'fd00::1/64', c_mtu),
                                ('r1', 'va', '10.0.0.2/24', 'fd00::2/64', c_mtu),
                                ('r1', 'vb', '10.0.1.1/24', 'fd01::1/64', m1),
                                ('r2', 'vc2', '10.0.1.2/24', 'fd01::2/64', m1),
                                ('r2', 'vd', '10.0.2.2/24', 'fd02::2/64', m2),
                                ('s', 'vs', '10.0.2.1/24', 'fd02::1/64', m2)):
        sh('ip', '-n', n, 'link', 'set', dev, 'mtu', str(mtu))
        sh('ip', '-n', n, 'addr', 'add', a4, 'dev', dev)
        sh('ip', '-n', n, 'addr', 'add', a6, 'dev', dev, 'nodad')
        sh('ip', '-n', n, 'link', 'set', dev, 'up')
    sh('ip', '-n', 'c', 'route', 'add', 'default', 'via', '10.0.0.2')
    sh('ip', '-n', 'c', '-6', 'route', 'add', 'default', 'via', 'fd00::2')
    sh('ip', '-n', 'r1', 'route', 'add', '10.0.2.0/24', 'via', '10.0.1.2')
    sh('ip', '-n', 'r1', '-6', 'route', 'add', 'fd02::/64', 'via', 'fd01::2')
    sh('ip', '-n', 'r2', 'route', 'add', '10.0.0.0/24', 'via', '10.0.1.1')
    sh('ip', '-n', 'r2', '-6', 'route', 'add', 'fd00::/64', 'via', 'fd01::1')
    sh('ip', '-n', 's', 'route', 'add', 'default', 'via', '10.0.2.2')
    sh('ip', '-n', 's', '-6', 'route', 'add', 'default', 'via', 'fd02::2')
    for r in ('r1', 'r2'):
        # No ICMP rate limit: a router that limits its Time Exceeded looks silent to a quick walk,
        # which is true to life but not what this oracle measures.
        sh('ip', 'netns', 'exec', r, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
           'net.ipv4.icmp_ratelimit=0', 'net.ipv6.icmp.ratelimit=0')
    # A fresh network namespace starts with the unprivileged ICMP socket switched off.
    sh('ip', 'netns', 'exec', 'c', 'sysctl', '-qw', 'net.ipv4.ping_group_range=0 0')
    if blackhole:
        rules = ('table inet bh {\n chain out {\n  type filter hook output priority 0;\n'
                 '  icmp type destination-unreachable icmp code frag-needed drop\n'
                 '  icmpv6 type packet-too-big drop\n }\n}\n')
        subprocess.run(['ip', 'netns', 'exec', 'r2', 'nft', '-f', '-'], input=rules, text=True, check=True)


def warm(dest):
    for _ in range(10):
        if sh('ip', 'netns', 'exec', 'c', 'ping', '-c1', '-W1', '-s', '16', dest, check=False).returncode == 0:
            return
    raise RuntimeError('%s never answered a small ping' % dest)


def tracepath(dest):
    """([addresses of the hops], final pmtu) from `tracepath -n`."""
    out = sh('ip', 'netns', 'exec', 'c', 'tracepath', '-n', '-m', '6', dest, check=False).stdout
    addrs = []
    for line in out.splitlines():
        m = re.match(r'\s*(\d+)\??:\s+(\S+)', line)
        if m and m.group(2) not in ('[LOCALHOST]', 'no'):
            a = m.group(2)
            if not addrs or addrs[-1] != a:
                addrs.append(a)
    m = re.search(r'Resume: pmtu (\d+)', out)
    return addrs, int(m.group(1)) if m else None


def judge_one(name, fam, c, m1, m2, bh, kind, r, tp):
    """Reasons this walk disagreed with the configured links (empty: agrees)."""
    why = []
    if not isinstance(r, dict):
        return ['walk failed: %s' % r]
    r1, r2, srv = ADDR[fam]
    if not r['reached']:
        why.append('destination not reached')
    hops = r['hops']
    if not bh and (r['uncertain'] or any(not h['proved'] for h in hops)):
        why.append('a clean path reported uncertain or unproved')
    if [h['addr'] for h in hops] != [r1, r2, srv]:
        why.append('hop addresses %s, expected %s' % ([h['addr'] for h in hops], [r1, r2, srv]))
        return why
    if not hops[-1]['destination'] or any(h['destination'] for h in hops[:-1]):
        why.append('destination flag wrong')
    truth = [c, min(c, m1), min(c, m1, m2)]
    # `probe` over the same socket kind: the end-to-end search must agree with the walk, and flag
    # a black hole only where the router made one (on the DGRAM lane it used to flag every path).
    pr = r['probe']
    if not isinstance(pr, dict):
        why.append('probe failed: %s' % pr)
    else:
        if pr['mtu'] != truth[2]:
            why.append('probe mtu %d, link says %d' % (pr['mtu'], truth[2]))
        if pr['blackhole'] != bh:
            why.append('probe blackhole=%s, router %s' % (pr['blackhole'], 'drops its ICMP' if bh else 'answers'))
    if bh:
        # Silence in front of the last hop: a size-dependent drop, flagged; the bisection still finds the link.
        if not r['blackhole']:
            why.append('black hole not flagged')
        if hops[2]['mtu'] != truth[2]:
            why.append('last hop mtu %d, link says %d' % (hops[2]['mtu'], truth[2]))
    else:
        if r['blackhole']:
            why.append('black hole flagged on a path that answers')
        # The DGRAM lane gets no next-hop MTU (see SPEC), the RAW lane does: both must be exact.
        for i, h in enumerate(hops):
            if h['mtu'] != truth[i]:
                why.append('hop %d mtu %d, link says %d' % (i + 1, h['mtu'], truth[i]))
        # The narrowed hop is attributed to the router in front of the smaller link.
        for i, who in ((1, r1), (2, r2)):
            if truth[i] < truth[i - 1]:
                if not hops[i]['narrowed'] or hops[i]['narrowed_by'] != who:
                    why.append('hop %d: narrowed by %s, expected %s' % (i + 1, hops[i]['narrowed_by'], who))
        if tp[1] != truth[2]:
            why.append('tracepath pmtu %s, link says %d' % (tp[1], truth[2]))
    if not bh and tp[0] != [r1, r2, srv]:  # tracepath cannot pass the black hole at all
        why.append('tracepath hops %s' % tp[0])
    return why


def inner(exe):
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run'], check=True)
    os.makedirs('/run/netns', exist_ok=True)
    bad = 0
    total = 0
    only = os.environ.get('HOPS_ORACLE_ONLY')  # a scenario name, to run just that one
    for name, fam, c, m1, m2, bh in SCENARIOS:
        if only and name != only:
            continue
        dest = ADDR[fam][2]
        for kind in ('dgram', 'raw'):
            topology(c, m1, m2, bh)
            warm(dest)
            if name.endswith('-forged-route-pmtu'):
                forge_ptb(fam, dest)
            p = sh('ip', 'netns', 'exec', 'c', exe, '--hops', dest, 'vc', kind, str(TIMEOUT_MS), str(RETRIES), check=False)
            total += 1
            if only:
                sys.stderr.write(p.stderr)
            if p.returncode != 0:
                bad += 1
                sys.stderr.write('%s/%s: walk exited %d: %s\n' % (name, kind, p.returncode, p.stderr[-500:]))
                continue
            r = json.loads(p.stdout)
            topology(c, m1, m2, bh)
            warm(dest)
            tp = tracepath(dest)
            why = judge_one(name, fam, c, m1, m2, bh, kind, r, tp)
            if why:
                bad += 1
                sys.stderr.write('%s/%s: %s\n  %s\n' % (name, kind, '; '.join(why), json.dumps(r)[:700]))
            else:
                sys.stderr.write('%s/%s: ok (mtu %d, tracepath %s)\n' % (name, kind, r['mtu'], tp[1]))
    # A deadline that expires mid-walk: the black-hole path, probes that would wait a minute each, 255
    # retries, and a 1.5 s budget. The walk must end by itself, say so, and not claim to have arrived.
    if not only:
        topology(1500, 1500, 1300, True)
        warm(ADDR['v4'][2])
        t0 = time.time()
        p = sh('ip', 'netns', 'exec', 'c', exe, '--hops', ADDR['v4'][2], 'vc', 'dgram', '60000', '255', '1500', check=False)
        took = time.time() - t0
        total += 1
        try:
            r = json.loads(p.stdout)
        except ValueError:
            r = None
        if p.returncode != 0 or not isinstance(r, dict) or not r['timed_out'] or r['reached'] or took > 20:
            bad += 1
            sys.stderr.write('deadline: expected a timed-out walk in under 20 s, got rc=%d after %.1f s: %s\n' % (
                p.returncode, took, (p.stdout or p.stderr)[:400]))
        else:
            sys.stderr.write('deadline: ok (timed out after %.1f s, %d hops)\n' % (took, len(r['hops'])))
    for n in ('c', 'r1', 'r2', 's'):
        sh('ip', 'netns', 'del', n, check=False)
    sys.stderr.write('%d walks; %d disagreed with the links\n' % (total, bad))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'judge':
        exe = os.path.abspath(sys.argv[2])
        p = subprocess.run(['unshare', '-rmn', sys.executable, os.path.abspath(__file__), 'inner', exe])
        sys.exit(p.returncode)
    if len(sys.argv) == 3 and sys.argv[1] == 'inner':
        inner(sys.argv[2])
    sys.exit(2)
