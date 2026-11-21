#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for src/testdata/geneve_oracle.zig: `geneve [vni]` combined with other primitives.

Builds a small Ethernet savefile (Geneve datagrams over IPv4 and IPv6 carrying an Ethernet frame or a bare
IPv4 / IPv6 packet, with and without options, VNIs 5 and 7, and frames that are not Geneve: version 1, another UDP
port, a fragment, plain TCP) and asks `tcpdump -n -tt -r` (libpcap, black box) which frames each expression selects.
`filter.compile` + `run` must select the same.

    python3 -I modules/rawsock/tools/gen_geneve_oracle.py OUTDIR      # from the repository root

Needs tcpdump (libpcap 1.10.x). No privileges. Frame i is stamped at second 1000 + i.

Not in the table: expressions in which a primitive after `geneve` can be reached on a frame that never ran it
(`geneve or tcp`, `not geneve and ip`): libpcap leaves its scratch slots uninitialised there (the kernel refuses
the program), `filter.compile` reads zeros.
"""
import os, struct, subprocess, sys

D = sys.argv[1].rstrip('/') + '/'
os.makedirs(D, exist_ok=True)

SRC = bytes.fromhex('001122334455')
DST = bytes.fromhex('ffffffffffff')


def eth(ety, payload):
    return DST + SRC + struct.pack('>H', ety) + payload


def ip4(proto, src, dst, l4):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, bytes(src), bytes(dst))
    return h + l4


def ip6(nh, src, dst, l4):
    return struct.pack('>IHBB16s16s', 0x60000000, len(l4), nh, 64, src, dst) + l4


def tcp(sp, dp):
    return struct.pack('>HHIIBBHHH', sp, dp, 0, 0, 0x50, 0x02, 1024, 0, 0)


def udp(sp, dp):
    return struct.pack('>HHHH', sp, dp, 8, 0)


def label(lab, s, ttl=64):
    return struct.pack('>I', (lab << 12) | (s << 8) | ttl)


def pppoe(session, ppp, payload):
    body = struct.pack('>H', ppp) + payload
    return struct.pack('>BBHH', 0x11, 0, session, len(body)) + body


A1 = (192, 0, 2, 1)
A2 = (192, 0, 2, 2)
I1 = (10, 1, 0, 1)
I2 = (10, 1, 0, 2)
V1 = bytes.fromhex('20010db8000000000000000000000001')
V2 = bytes.fromhex('20010db8000000000000000000000002')
IV1 = bytes.fromhex('fd000000000000000000000000000001')
IV2 = bytes.fromhex('fd000000000000000000000000000002')
IN_SRC = bytes.fromhex('020000000001')
IN_DST = bytes.fromhex('030000000002')


def ieth(ety, payload, dst=IN_DST, src=IN_SRC):
    return dst + src + struct.pack('>H', ety) + payload


def gnv(vni, proto, inner, optwords=0, ver=0):
    return struct.pack('>BBH', (ver << 6) | optwords, 0, proto) + struct.pack('>I', vni << 8) + bytes(4 * optwords) + inner


def outer4(udp_payload, dport=6081, frag=False):
    u = struct.pack('>HHHH', 40000, dport, 8 + len(udp_payload), 0) + udp_payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0x2000 if frag else 0, 64, 17, 0, bytes(A1), bytes(A2))
    return eth(0x0800, h + u)


def outer6(udp_payload, dport=6081):
    u = struct.pack('>HHHH', 40000, dport, 8 + len(udp_payload), 0) + udp_payload
    return eth(0x86dd, ip6(17, V1, V2, u))


T80 = ip4(6, I1, I2, tcp(1234, 80))
U53 = ip4(17, I2, I1, udp(53, 4000))
T6 = ip6(6, IV1, IV2, tcp(1234, 443))
U6 = ip6(17, IV2, IV1, udp(5000, 53))
ARP = struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, IN_SRC, bytes(I1), bytes(6), bytes(I2))

frames = [
    outer4(gnv(5, 0x6558, ieth(0x0800, T80))),                         # 0 IPv4 outer, VNI 5, Ethernet inner, IPv4 TCP 80
    outer4(gnv(7, 0x6558, ieth(0x0800, U53))),                         # 1 VNI 7, inner IPv4 UDP src 53
    outer4(gnv(5, 0x6558, ieth(0x86dd, U6))),                          # 2 VNI 5, inner IPv6 UDP 53
    outer4(gnv(7, 0x6558, ieth(0x86dd, T6))),                          # 3 VNI 7, inner IPv6 TCP 443
    outer4(gnv(5, 0x0800, T80)),                                       # 4 bare IPv4 inner (protocol 0x0800)
    outer4(gnv(5, 0x86dd, U6)),                                        # 5 bare IPv6 inner
    outer4(gnv(5, 0x6558, ieth(0x0800, T80), optwords=2)),             # 6 two option words
    outer4(gnv(7, 0x0800, T80, optwords=1)),                           # 7 bare IPv4 with an option word
    outer6(gnv(5, 0x6558, ieth(0x0800, T80))),                         # 8 IPv6 outer, Ethernet inner IPv4 TCP 80
    outer6(gnv(7, 0x0800, U53)),                                       # 9 IPv6 outer, bare IPv4 UDP
    outer6(gnv(7, 0x6558, ieth(0x86dd, U6), optwords=3)),              # 10 IPv6 outer, options, inner IPv6 UDP 53
    outer4(gnv(5, 0x6558, ieth(0x0806, ARP))),                         # 11 inner ARP
    outer4(gnv(5, 0x6558, ieth(0x0800, T80, dst=bytes.fromhex('ffffffffffff')))),  # 12 inner broadcast MAC
    outer4(gnv(5, 0x6558, ieth(0x0800, T80), ver=1)),                  # 13 Geneve version 1
    outer4(gnv(5, 0x6558, ieth(0x0800, T80)), dport=6082),             # 14 another UDP port
    outer4(gnv(5, 0x6558, ieth(0x0800, T80)), frag=True),              # 15 outer fragment
    eth(0x0800, ip4(6, A1, A2, tcp(40000, 6081))),                     # 16 outer TCP port 6081
    eth(0x0800, ip4(17, A1, A2, udp(53, 4000))),                       # 17 plain UDP
    eth(0x86dd, ip6(6, V1, V2, tcp(1, 80))),                           # 18 plain IPv6 TCP
    outer4(gnv(16777215, 0x6558, ieth(0x0800, T80))),                  # 19 VNI 16777215
    outer4(gnv(5, 0x6558, ieth(0x0800, T80, src=bytes.fromhex('010000000009')))),  # 20 inner source MAC with the multicast bit
]

EXPRESSIONS = [
    'geneve', 'geneve 5', 'geneve 7', 'geneve 0', 'geneve 16777215', 'geneve 6',
    'geneve and ip', 'geneve and ip6', 'geneve 5 and ip', 'geneve 7 and ip6', 'geneve and tcp', 'geneve and udp',
    'geneve and tcp port 80', 'geneve and udp port 53', 'geneve 5 and tcp dst port 80', 'geneve and src port 53',
    'geneve and ip src host 10.1.0.1', 'geneve and ip dst host 10.1.0.1', 'geneve and ip proto 6', 'geneve and ip6 host fd00::1',
    'geneve and ip6 and tcp', 'geneve and ip6 and udp', 'geneve and not ip', 'geneve and (ip or ip6)', 'geneve and ip or ip6',
    'geneve and ether proto 0x800', 'geneve and ether proto \\ip6', 'geneve and arp', 'geneve and rarp',
    'geneve and ether src 02:00:00:00:00:01', 'geneve and ether dst 03:00:00:00:00:02', 'geneve and ether host 02:00:00:00:00:01',
    'geneve and ether host 00:11:22:33:44:55', 'geneve and not ether host 02:00:00:00:00:01', 'geneve and multicast', 'geneve and broadcast',
    'geneve and ether[0] = 0xff', 'geneve and ether[6:2] = 0x0200',
    'geneve and ip[8] = 64', 'geneve and tcp[13] & 2 != 0', 'geneve and less 100', 'geneve and greater 80', 'geneve and len > 90',
    'geneve and net 10.1.0.0/16', 'geneve and host 10.1.0.2', 'geneve and src net 10.1.0.0/24', 'geneve and icmp', 'geneve and portrange 50-60',
    'geneve and ip and tcp', 'geneve and ip and tcp[13] & 2 != 0', 'geneve and tcp and not ip6', 'geneve and not tcp',
    'ip and geneve', 'ip6 and geneve', 'udp and geneve', 'udp port 6081 and geneve', 'udp port 53 or geneve', 'tcp or geneve',
    'ip src host 192.0.2.1 and geneve and ip src host 10.1.0.1', 'not geneve', 'ether proto 0x800 and geneve 5 and tcp',
]

# libpcap accepts these; filter.compile refuses them (UnsupportedExpression): a second `geneve`, and `geneve` together with a
# primitive that shifts the offsets by its own rule.
NOT_BUILT = ['geneve and geneve', 'geneve and vlan', 'vlan and geneve', 'geneve and mpls', 'mpls and geneve', 'geneve and pppoes', 'pppoes and geneve']

hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
data = hdr
for i, f in enumerate(frames):
    data += struct.pack('<IIII', 1000 + i, 0, len(f), len(f)) + f
open(D + 'geneve.pcap', 'wb').write(data)


def zig_hex(name, b):
    h = b.hex()
    lines = [h[i:i + 100] for i in range(0, len(h), 100)]
    t = 'pub const %s =\n' % name
    for j, l in enumerate(lines):
        t += '    "%s"%s\n' % (l, ' ++' if j < len(lines) - 1 else ';')
    return t


rows = []
refused = []
for e in NOT_BUILT:
    r = subprocess.run(['tcpdump', '-n', '-tt', '-r', D + 'geneve.pcap', e], capture_output=True, text=True)
    assert r.returncode == 0, e
for e in EXPRESSIONS:
    r = subprocess.run(['tcpdump', '-n', '-tt', '-r', D + 'geneve.pcap', e], capture_output=True, text=True)
    if r.returncode != 0:
        refused.append(e)
        continue
    idx = sorted(int(float(l.split()[0])) - 1000 for l in r.stdout.splitlines() if l and l[0].isdigit())
    rows.append((e, idx))

with open(D + 'geneve_oracle.zig', 'w') as z:
    z.write('// SPDX-License-Identifier: MIT\n// Generated by tools/gen_geneve_oracle.py (tcpdump -r, libpcap 1.10.6). Do not edit.\n\n')
    z.write('pub const Row = struct { []const u8, []const usize };\n\n')
    z.write(zig_hex('corpus', data))
    z.write('\npub const oracle = [_]Row{\n')
    for e, idx in rows:
        z.write('    .{ "%s", &.{ %s } },\n' % (e.replace('\\', '\\\\'), ', '.join(map(str, idx))))
    z.write('};\n\n/// Refused by libpcap: `filter.compile` refuses them too.\npub const refused = [_][]const u8{\n')
    for e in refused:
        z.write('    "%s",\n' % e)
    z.write('};\n\n/// Accepted by libpcap, refused here.\npub const not_built = [_][]const u8{\n')
    for e in NOT_BUILT:
        z.write('    "%s",\n' % e)
    z.write('};\n')
print('frames', len(frames), 'rows', len(rows), 'refused', refused)
