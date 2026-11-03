#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for the filter oracle in src/filter.zig (`corpus_pcap` and `oracle`).

Keeps the first 20 frames of the corpus already in filter.zig, appends the ten
frames built below, then asks `tcpdump -n -tt -r` (libpcap, black box) which
frames each expression in EXPRESSIONS selects, and prints the Zig for the new
`corpus_pcap` and `oracle` to the directory given as argv[1] (corpus.zig,
oracle.zig, dump.txt = `tcpdump -d` of each expression). Frame i is stamped at
second 1000 + i. An expression tcpdump refuses is reported on stderr and left
out (the refusals are tested separately in filter.zig).

    python3 -I tools/gen_filter_oracle.py OUTDIR      # from modules/rawsock/..

Run from the repository root; needs tcpdump (libpcap 1.10.x). No privileges.
"""
import re, struct, subprocess, sys, os

D = sys.argv[1].rstrip('/') + '/'
os.makedirs(D, exist_ok=True)
FILTER = 'modules/rawsock/src/filter.zig'
EXPRESSIONS = [
    'ip',
    'ip6',
    'arp',
    'icmp',
    'tcp',
    'udp',
    'sctp',
    'port 53',
    'udp port 53',
    'tcp dst port 80',
    'tcp src port 80',
    'udp src port 53',
    'src port 53',
    'dst port 80',
    'ip src host 10.0.0.1',
    'ip dst host 10.0.0.1',
    'ip host 10.0.0.1',
    'ip net 10.0.0.0/8',
    'ip src net 10.200.0.0/16',
    'ip dst net 192.0.2.0/24',
    'ether host 00:11:22:33:44:55',
    'ether src 00:11:22:33:44:55',
    'ether dst ff:ff:ff:ff:ff:ff',
    'ether proto 0x86dd',
    'ether proto 34997',
    'ip proto 132',
    'not ip',
    'arp or icmp',
    'tcp and not port 80',
    '(udp or tcp) and ip6',
    '!tcp && !udp',
    'ip and not ip src net 10.0.0.0/8 or arp',
    'not (ip or ip6 or arp)',
    'sctp port 53',
    'udp and ip6 and dst port 53',
    'ip6 host 2001:db8::1',
    'ip6 src host 2001:db8::2',
    'ip6 dst host 2001:db8::2',
    'ip6 dst net 2001:db8::/32',
    'ip6 net 2001:db8:1::/48',
    'ip6 src net 2001:db8:ffff::/48',
    'ip6 host ff02::1',
    'ip6 net ::/0',
    'host 10.0.0.1',
    'src host 10.0.0.1',
    'dst host 10.0.0.9',
    'net 10.0.0.0/8',
    'src net 192.0.2.0/24',
    'host 2001:db8::1',
    'ip6 proto 17',
    'arp host 10.0.0.9',
    'arp src host 10.0.0.1',
    'arp dst host 10.0.0.9',
    'rarp',
    'rarp host 10.1.1.1',
    'portrange 20-30',
    'tcp portrange 20-30',
    'udp src portrange 5000-5400',
    'dst portrange 80-20',
    'tcp dst portrange 22-22',
    'less 60',
    'less 42',
    'greater 100',
    'greater 64',
    'len <= 60',
    'len > 100',
    'len = 42',
    'len >= 200',
    'len != 62',
    'ip[6:2] & 0x1fff = 0',
    'ip[6:2] & 0x1fff != 0',
    'ip[8] <= 64',
    'ip[8] < 2',
    'ip[8] > 1',
    'ip[9] = 6',
    'ip[0] & 0xf > 5',
    'tcp[13] & 2 != 0',
    'tcp[13] = 0x12',
    'tcp[0:2] = 22',
    'udp[0:2] = 53',
    'udp[2:2] >= 2500',
    'icmp[0] = 8',
    'icmp[0] != 8',
    'ether[0] & 1 = 1',
    'ether[12:2] = 0x0806',
    'ether[0:4] = 0xffffffff',
    'ip6[6] = 17',
    'ip6[6:1] = 6',
    'arp[6:2] = 1',
    'arp[6:2] = 3',
    'rarp[6:2] = 3',
    'broadcast',
    'multicast',
    'ether broadcast',
    'ether multicast',
    'ip proto 6',
    'not host 10.0.0.1 and tcp',
    'ip[6:2]&0x1fff=0',
    'tcp[13]&2!=0',
    '(tcp[13] & 2 != 0) or udp portrange 25-53']
src = open(FILTER).read()
m = re.search(r'const corpus_pcap = hex\((.*?)\n\);', src, re.S)
old_hex = ''.join(re.findall(r'"([0-9a-f]+)"', m.group(1)))
full = bytes.fromhex(old_hex)
n_old = 20
pos = 24
for _ in range(n_old):  # keep the first 20 records, whatever follows them now
    pos += 16 + struct.unpack_from('<I', full, pos + 8)[0]
old = full[:pos]


def mac(s):
    return bytes.fromhex(s.replace(':', ''))


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def ip6(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


def eth(dst, src, ty, body):
    return mac(dst) + mac(src) + struct.pack('>H', ty) + body


def v4(src_, dst_, proto, l4, ttl=64, frag=0, pad=0):
    total = 20 + len(l4) + pad
    return struct.pack('>BBHHHBBH', 0x45, 0, total, 1, frag, ttl, proto, 0) + ip4(src_) + ip4(dst_) + l4 + bytes(pad)


def v6(src_, dst_, nh, l4, pad=0):
    return struct.pack('>IHBB', 0x60000000, len(l4) + pad, nh, 64) + ip6(src_) + ip6(dst_) + l4 + bytes(pad)


def tcp(sp, dp, flags):
    return struct.pack('>HHIIBBHHH', sp, dp, 0, 0, 0x50, flags, 1000, 0, 0)


def udp(sp, dp, n=8):
    return struct.pack('>HHHH', sp, dp, n, 0)


def arp(op, sha, spa, tha, tpa):
    return struct.pack('>HHBBH', 1, 0x0800, 6, 4, op) + mac(sha) + ip4(spa) + mac(tha) + ip4(tpa)


A = '00:11:22:33:44:55'
B = '02:00:00:00:09:02'
new = [
    eth('ff:ff:ff:ff:ff:ff', A, 0x0806, arp(1, A, '10.0.0.1', '00:00:00:00:00:00', '10.0.0.9')),  # 20 arp who-has
    eth(B, A, 0x8035, arp(3, A, '192.0.2.5', B, '10.1.1.1')),  # 21 rarp
    eth('33:33:00:00:00:01', A, 0x86dd, v6('2001:db8:1::5', 'ff02::1', 17, udp(5353, 5353))),  # 22 v6 udp multicast
    eth(B, A, 0x0800, v4('10.0.0.1', '10.0.0.2', 6, tcp(1000, 22, 0x02), pad=10)),  # 23 SYN 64B
    eth(B, A, 0x0800, v4('10.0.0.2', '10.0.0.1', 6, tcp(22, 1000, 0x12), pad=146)),  # 24 SYN-ACK 200B
    eth('01:00:5e:00:00:fb', A, 0x0800, v4('192.0.2.9', '224.0.0.251', 17, udp(25, 2500, 80), pad=72)),  # 25 udp mcast
    eth(B, A, 0x0800, v4('10.0.0.1', '10.0.0.2', 1, struct.pack('>BBHHH', 8, 0, 0, 1, 1) + bytes(8))),  # 26 echo req
    eth(B, A, 0x0800, v4('10.0.0.2', '10.0.0.1', 1, struct.pack('>BBHHH', 0, 0, 0, 1, 1) + bytes(8), ttl=1)),  # 27 echo reply
    eth(B, A, 0x86dd, v6('2001:db8:ffff::7', '2001:db8::2', 6, tcp(25, 80, 0x10))),  # 28 v6 tcp, other prefix
    eth(B, A, 0x0800, v4('10.0.0.1', '10.0.0.2', 17, udp(53, 5000), frag=0x2000 | 0, pad=0)),  # 29 udp, MF fragment 0 offset
]
data = old
for i, f in enumerate(new):
    ts = 1000 + n_old + i
    data += struct.pack('<IIII', ts, 0, len(f), len(f)) + f
open(D + 'corpus.pcap', 'wb').write(data)
total = n_old + len(new)

exprs = EXPRESSIONS
out = []
for e in exprs:
    r = subprocess.run(['tcpdump', '-n', '-tt', '-r', D + 'corpus.pcap', e], capture_output=True, text=True)
    if r.returncode != 0:
        print('FAIL', e, r.stderr.strip(), file=sys.stderr)
        continue
    idx = sorted(int(float(l.split()[0])) - 1000 for l in r.stdout.splitlines() if l and l[0].isdigit())
    out.append((e, idx))
    # also dump the BPF text for the record
    d = subprocess.run(['tcpdump', '-d', '-n', e], capture_output=True, text=True).stdout
    open(D + 'dump.txt', 'a').write('== ' + e + '\n' + d)
with open(D + 'oracle.zig', 'w') as f:
    for e, idx in out:
        f.write('    .{ "%s", &.{ %s } },\n' % (e, ', '.join(map(str, idx))))
h = data.hex()
with open(D + 'corpus.zig', 'w') as f:
    lines = [h[i:i + 100] for i in range(0, len(h), 100)]
    f.write('const corpus_pcap = hex(\n')
    for j, l in enumerate(lines):
        f.write('    "%s"%s\n' % (l, ' ++' if j < len(lines) - 1 else ','))
    f.write(');\n')
print('frames', total, 'exprs', len(out))
