#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for src/testdata/mpls_oracle.zig: `mpls` and `pppoes` combined with other primitives.

Builds a small Ethernet savefile (MPLS label stacks over IPv4 and IPv6, PPPoE sessions with
IPv4, IPv6 and LCP, a PPPoE discovery frame, plain IP) and asks `tcpdump -n -tt -r` (libpcap, black
box) which frames each expression selects. `filter.compile` + `run` must select the same.

    python3 -I modules/rawsock/tools/gen_mpls_oracle.py OUTDIR      # from the repository root

Needs tcpdump (libpcap 1.10.x). No privileges. Frame i is stamped at second 1000 + i.

Not in the table: `ip and mpls` (libpcap's optimiser sees it can never match and refuses it with
"expression rejects all packets"; filter.compile, which has no optimiser, builds the program that
never matches). A second `mpls` is the next label of the stack (the label before it must not be the
bottom one), as libpcap reads it; the offsets after it move by 4 per label.
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


A1 = (10, 0, 0, 1)
A2 = (10, 0, 0, 2)
V1 = bytes.fromhex('20010db8000000000000000000000001')
V2 = bytes.fromhex('20010db8000000000000000000000002')

frames = [
    eth(0x8847, label(5, 1) + ip4(6, A1, A2, tcp(1234, 80))),                      # 0 MPLS 1 label, IPv4 TCP 80
    eth(0x8847, label(100, 1) + ip6(17, V1, V2, udp(5000, 53))),                    # 1 MPLS, IPv6 UDP 53
    eth(0x8847, label(7, 0) + label(9, 1) + ip4(6, A1, A2, tcp(1, 80))),            # 2 two labels (bottom bit clear on the first)
    eth(0x8847, label(5, 1) + ip4(17, A2, A1, udp(53, 4000))),                      # 3 MPLS, IPv4 UDP src 53
    eth(0x8864, pppoe(7, 0x0021, ip4(6, A1, A2, tcp(1234, 80)))),                   # 4 PPPoE session 7, IPv4 TCP 80
    eth(0x8864, pppoe(9, 0x0057, ip6(6, V1, V2, tcp(1234, 443)))),                  # 5 PPPoE session 9, IPv6 TCP 443
    eth(0x8864, pppoe(7, 0xc021, b'\x01\x01\x00\x04')),                             # 6 PPPoE session 7, LCP
    eth(0x8863, struct.pack('>BBHH', 0x11, 0x09, 0, 0)),                            # 7 PPPoE discovery
    eth(0x0800, ip4(6, A1, A2, tcp(1234, 80))),                                     # 8 plain IPv4 TCP
    eth(0x8848, label(5, 1) + ip4(6, A1, A2, tcp(1234, 80))),                       # 9 MPLS multicast ethertype
    eth(0x8864, pppoe(7, 0x0281, label(5, 1) + ip4(6, A1, A2, tcp(1, 80)))),        # 10 PPPoE session, PPP MPLS
    eth(0x8864, pppoe(7, 0x0021, ip4(17, A2, A1, udp(53, 4000)))),                  # 11 PPPoE session 7, IPv4 UDP src 53
    eth(0x0806, struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, SRC, bytes(A1), bytes(6), bytes(A2))),  # 12 ARP
    eth(0x8847, label(100, 1) + ip6(6, V2, V1, tcp(80, 9))),                        # 13 MPLS label 100, IPv6 TCP src 80
    eth(0x8847, label(7, 0) + label(8, 0) + label(9, 1) + ip4(6, A1, A2, tcp(1, 80))),  # 14 three labels, IPv4 TCP 80
    eth(0x8847, label(5, 0) + label(6, 1) + ip6(17, V1, V2, udp(5000, 53))),         # 15 two labels, IPv6 UDP 53
    eth(0x8847, label(7, 0) + label(9, 1) + ip4(17, A2, A1, udp(53, 4000))),         # 16 two labels, IPv4 UDP src 53
    eth(0x8864, pppoe(7, 0x0281, label(7, 0) + label(9, 1) + ip4(6, A1, A2, tcp(1, 80)))),   # 17 PPPoE session, PPP MPLS, two labels, IPv4 TCP 80
    eth(0x8864, pppoe(9, 0x0281, label(5, 1) + ip6(17, V1, V2, udp(5000, 53)))),             # 18 PPPoE session 9, PPP MPLS, one label, IPv6 UDP 53
]

EXPRESSIONS = [
    'mpls', 'mpls 5', 'mpls 100', 'mpls 7', 'pppoes', 'pppoes 7', 'pppoes 9', 'pppoed',
    'mpls and ip', 'mpls and ip6', 'mpls 5 and ip', 'mpls 100 and ip6', 'mpls and tcp', 'mpls and udp',
    'mpls and udp port 53', 'mpls and tcp port 80', 'mpls 5 and tcp dst port 80', 'mpls and src port 53',
    'mpls and ip src host 10.0.0.1', 'mpls and ip dst host 10.0.0.1', 'mpls and ip proto 6', 'mpls and ip6 host 2001:db8::1',
    'mpls and not ip', 'mpls and (ip or ip6)', 'mpls and ip or ip6', 'mpls or ip', 'ip or mpls',
    'mpls and ether src 00:11:22:33:44:55', 'mpls and ether proto 0x800', 'mpls and net 10.0.0.0/8', 'mpls and host 10.0.0.2',
    'mpls and icmp', 'mpls and ip[8] = 64', 'mpls and tcp[13] & 2 != 0', 'mpls and less 100', 'mpls and portrange 50-60',
    'not mpls and ip', 'mpls and ip6 and tcp',
    'mpls and mpls', 'mpls 7 and mpls 9', 'mpls 5 and mpls 9', 'mpls 7 and mpls', 'mpls and mpls 9', 'mpls and mpls and ip',
    'mpls 7 and mpls 9 and ip', 'mpls and mpls and ip6', 'mpls and mpls and mpls', 'mpls 7 and mpls 8 and mpls 9',
    'mpls 7 and mpls 8 and mpls 9 and ip', 'mpls and mpls and tcp', 'mpls and mpls and udp', 'mpls and mpls and tcp port 80',
    'mpls and mpls and udp src port 53', 'mpls and mpls and ip src host 10.0.0.1', 'mpls and mpls and ip6 host 2001:db8::1',
    'mpls 5 or mpls 100', 'mpls or mpls', 'mpls 7 and mpls 9 or ip', 'not (mpls and mpls)', 'mpls and mpls and not ip',
    'mpls and mpls and ip[8] = 64', 'mpls and mpls and tcp[13] & 2 != 0', 'mpls and mpls and host 10.0.0.2',
    'mpls and mpls and mpls and ip', 'mpls and mpls and arp', 'mpls and mpls and vlan', 'mpls and mpls and pppoes',
    'mpls and mpls and ether src 00:11:22:33:44:55', 'mpls and mpls and net 10.0.0.0/8',
    'pppoes and mpls and mpls', 'mpls and mpls and mpls 9',
    'pppoes and mpls 5', 'pppoes 7 and mpls 5', 'pppoes and mpls 7 and mpls 9', 'pppoes and mpls and ip', 'pppoes and mpls and ip6',
    'pppoes and mpls and mpls and ip', 'pppoes and mpls 5 and ip6', 'pppoes and mpls and tcp', 'pppoes and mpls and udp port 53',
    'pppoes and mpls and not ip', 'pppoes and mpls and tcp port 80', 'pppoes and mpls and ip src host 10.0.0.1',
    'pppoes and ip', 'pppoes and ip6', 'pppoes 7 and ip', 'pppoes 9 and ip6', 'pppoes and tcp', 'pppoes and udp',
    'pppoes 7 and tcp port 80', 'pppoes and tcp port 443', 'pppoes and udp src port 53', 'pppoes and ip src host 10.0.0.1',
    'pppoes and ip6 host 2001:db8::1', 'pppoes and ip proto 6', 'pppoes and not ip', 'pppoes and (ip or ip6)', 'pppoes or ip',
    'ip or pppoes', 'pppoes and arp', 'pppoes and mpls', 'pppoes and pppoes', 'pppoes and ether src 00:11:22:33:44:55',
    'pppoes and host 10.0.0.2', 'pppoes and ip[8] = 64', 'pppoes and tcp[13] & 2 != 0', 'pppoes and icmp', 'pppoes and net 10',
    'pppoes and multicast', 'not pppoes and tcp', 'pppoes and ip6 and tcp', 'pppoes and portrange 50-60', 'pppoes and greater 80',
]

hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
data = hdr
for i, f in enumerate(frames):
    data += struct.pack('<IIII', 1000 + i, 0, len(f), len(f)) + f
open(D + 'mpls.pcap', 'wb').write(data)


def zig_hex(name, b):
    h = b.hex()
    lines = [h[i:i + 100] for i in range(0, len(h), 100)]
    t = 'pub const %s =\n' % name
    for j, l in enumerate(lines):
        t += '    "%s"%s\n' % (l, ' ++' if j < len(lines) - 1 else ';')
    return t


rows = []
refused = []
for e in EXPRESSIONS:
    r = subprocess.run(['tcpdump', '-n', '-tt', '-r', D + 'mpls.pcap', e], capture_output=True, text=True)
    if r.returncode != 0:
        refused.append(e)
        continue
    idx = sorted(int(float(l.split()[0])) - 1000 for l in r.stdout.splitlines() if l and l[0].isdigit())
    rows.append((e, idx))

with open(D + 'mpls_oracle.zig', 'w') as z:
    z.write('// SPDX-License-Identifier: MIT\n// Generated by tools/gen_mpls_oracle.py (tcpdump -r, libpcap 1.10.6). Do not edit.\n\n')
    z.write('pub const Row = struct { []const u8, []const usize };\n\n')
    z.write(zig_hex('corpus', data))
    z.write('\npub const oracle = [_]Row{\n')
    for e, idx in rows:
        z.write('    .{ "%s", &.{ %s } },\n' % (e, ', '.join(map(str, idx))))
    z.write('};\n\n/// Refused by libpcap: `filter.compile` refuses them too.\npub const refused = [_][]const u8{\n')
    for e in refused:
        z.write('    "%s",\n' % e)
    z.write('};\n')
print('frames', len(frames), 'rows', len(rows), 'refused', refused)
