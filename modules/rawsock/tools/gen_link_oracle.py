#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for src/testdata/link_oracle.zig and src/testdata/vlan_live.zig.

Black box: only `tcpdump` 4.99.x / libpcap 1.10.6 is run, no libpcap source is read.

  link_oracle.zig  the 34-frame corpus of src/filter.zig as DLT_NULL (0), DLT_LOOP (108) and
                   DLT_LINUX_SLL2 (276) savefiles, and for each link which frame numbers
                   `tcpdump -y DLT -n -tt -r FILE EXPR` selects (record i is stamped at second
                   1000 + i, as in gen_filter_oracle.py), plus the expressions libpcap refuses.
                   NULL words are little-endian: the file a little-endian host captured.
  vlan_live.zig    for each expression `tcpdump -i lo -dd EXPR`: the program libpcap emits for a
                   LIVE Ethernet socket (the ancillary vlan form, `ldx M[1]`). `lo` is an
                   Ethernet device, so this needs CAP_NET_RAW in a throwaway namespace:

    unshare -rn python3 -I modules/rawsock/tools/gen_link_oracle.py OUTDIR      # from the repository root

Needs tcpdump and ip. Frames the link cannot carry (an EtherType other than IPv4/IPv6 on NULL and
LOOP, a runt) are left out of that link's file.
"""
import re, struct, subprocess, sys, os

D = sys.argv[1].rstrip('/') + '/'
os.makedirs(D, exist_ok=True)
FILTER = 'modules/rawsock/src/filter.zig'

LINK_EXPRS = [
    'ip', 'ip6', 'tcp port 80', 'udp port 53', 'host 10.0.0.1', 'src host 10.0.0.1', 'dst host 10.0.0.9', 'net 10',
    'ip[8] = 64', 'tcp[13] & 2 != 0', 'ip6 net 2001:db8::/32', 'icmp', 'icmp6', 'proto 6', 'proto 17', 'portrange 20-30',
    'less 60', 'greater 100', 'len > 60', 'tcp or udp and port 53', 'ip6 host 2001:db8::1', 'ip and host 10.0.0.1 or ip6',
    'ip proto 6', 'ip6 proto 17', 'ip6 proto \\tcp', 'ether proto 0x800', 'ether proto 0x86dd', 'ether proto \\ip', 'not ip',
    'tcp[tcpflags] & tcp-syn != 0', 'icmp[icmptype] = icmp-echo', 'udp portrange 5000-5400', 'ip[6:2] & 0x1fff = 0',
    'ip6[6] = 17', 'ip6 or ip', 'ether[0] & 1 = 1', 'sctp', 'tcp dst port 80 or 443',
    'net 10.0.0.0 mask 255.0.255.0', 'ip6 dst net 2001:db8::/32', 'not (tcp or udp)',
]
# SLL2 carries ARP: libpcap answers these there and refuses them on NULL / LOOP.
LOOP_EXTRA = ['ether[0:4] = 2']  # network-order word: the same bytes on every host (NULL's are host-order)
SLL2_EXTRA = ['ether[0:2] = 0x800', 'arp', 'rarp', 'arp host 10.0.0.9', 'arp src host 10.0.0.1', 'host 10.0.0.9', 'net 10.0.0.0/8', 'ether proto 0x806',
              'ether proto \\arp', 'arp[6:2] = 1', 'arp or icmp']
REFUSED = ['ether host 00:11:22:33:44:55', 'multicast', 'broadcast', 'vlan', 'vlan 5', 'ether src 00:11:22:33:44:55']
REFUSED_NULL = ['arp', 'rarp', 'arp host 10.0.0.9', 'ether proto 0x806', 'arp[6:2] = 1']

LIVE_EXPRS = [
    'inbound', 'outbound', 'ifindex 1', 'ifindex 2', 'inbound and tcp', 'ip and outbound', 'not outbound', 'mpls', 'mpls 5', 'mpls 6', 'pppoes', 'pppoes 7', 'pppoes 8', 'pppoed', 'vlan and inbound', 'outbound and vlan 5', 'ifindex 1 and (tcp or udp)',
    'vlan', 'vlan 5', 'vlan 6', 'vlan 0', 'vlan 4095', 'not vlan', 'vlan or ip6', 'vlan and ip', 'ip and vlan 5', 'vlan 5 and tcp port 80',
    'vlan and vlan 7 and udp', 'vlan 7 and vlan 5 and udp', 'vlan and ether host 00:11:22:33:44:55', 'vlan and multicast',
    'vlan and tcp[13] & 2 != 0', 'vlan and greater 100', 'vlan and ip host 10.0.0.1', 'vlan and arp', 'vlan and ip6 host 2001:db8::1',
    'vlan and vlan', 'vlan and ip[8] = 64', 'vlan and host 10.0.0.1', 'vlan and net 10', '(vlan 5 or vlan 6) and ip',
    'vlan and portrange 20-30', 'vlan and ip proto 6', 'ip and vlan and tcp', 'vlan and not tcp', 'not vlan and ip', 'vlan or ip',
    'vlan and ether proto 0x800', 'vlan and ether[12:2] = 0x800', 'vlan and arp host 10.0.0.1', 'vlan and less 60', 'vlan and icmp',
    'vlan 5 and vlan 7', 'vlan and udp port 53', 'tcp and vlan 5', 'ip6 and vlan and udp', 'vlan and (tcp or udp) and port 53',
    'vlan and tcp dst port 80 or 443', 'vlan and len > 100', 'vlan and ip src net 10.0.0.0/8',
]

src = open(FILTER).read()
m = re.search(r'const corpus_pcap = hex\((.*?)\n\);', src, re.S)
data = bytes.fromhex(''.join(re.findall(r'"([0-9a-f]+)"', m.group(1))))
frames = []
pos = 24
while pos < len(data):
    ts, tu, cl, ol = struct.unpack_from('<IIII', data, pos)
    frames.append((ts, data[pos + 16:pos + 16 + cl]))
    pos += 16 + cl


def wrap(dlt, conv):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, dlt)
    for ts, f in frames:
        b = conv(f)
        if b is None:
            continue
        out += struct.pack('<IIII', ts, 0, len(b), len(b)) + b
    return out


def null_conv(order):
    n = [0]

    def conv(f):
        if len(f) < 14:
            return None
        ety = struct.unpack('>H', f[12:14])[0]
        if ety == 0x86dd:  # a savefile holds the capturing OS's AF_INET6: 24 (NetBSD, OpenBSD, BSD/OS), 28 (FreeBSD), 30 (macOS)
            fam = (24, 28, 30)[n[0] % 3]
            n[0] += 1
        else:
            fam = {0x0800: 2}.get(ety)
        if fam is None:
            return None
        return struct.pack(order + 'I', fam) + f[14:]
    return conv


def sll2_conv(f):
    if len(f) < 14:
        return None
    ety = struct.unpack('>H', f[12:14])[0]
    return struct.pack('>HHIHBB', ety, 0, 1, 1, 0, 6) + f[6:12] + b'\0\0' + f[14:]


def zig_hex(name, b):
    h = b.hex()
    lines = [h[i:i + 100] for i in range(0, len(h), 100)]
    t = 'pub const %s =\n' % name
    for j, l in enumerate(lines):
        t += '    "%s"%s\n' % (l, ' ++' if j < len(lines) - 1 else ';')
    return t


def esc(e):
    return e.replace('\\', '\\\\')


def verdicts(path, e):
    r = subprocess.run(['tcpdump', '-Z', 'root', '-n', '-tt', '-r', path, e], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return sorted(int(float(l.split()[0])) - 1000 for l in r.stdout.splitlines() if l and l[0].isdigit())


out = '// SPDX-License-Identifier: MIT\n// Generated by tools/gen_link_oracle.py (tcpdump -y DLT -r, libpcap 1.10.6). Do not edit.\n\n'
out += 'pub const Row = struct { []const u8, []const usize };\n\n'
for name, dlt, conv, extra in (('null', 0, null_conv('<'), []), ('loop', 108, null_conv('>'), LOOP_EXTRA), ('sll2', 276, sll2_conv, SLL2_EXTRA)):
    path = D + 'corpus_%s.pcap' % name
    open(path, 'wb').write(wrap(dlt, conv))
    out += zig_hex('corpus_' + name, open(path, 'rb').read()) + '\n'
    out += 'pub const oracle_%s = [_]Row{\n' % name
    for e in LINK_EXPRS + extra:
        v = verdicts(path, e)
        if v is None:
            print('REFUSED', name, e, file=sys.stderr)
            continue
        out += '    .{ "%s", &.{ %s } },\n' % (esc(e), ', '.join(map(str, v)))
    out += '};\n\n'
    refused = [e for e in REFUSED + (REFUSED_NULL if name != 'sll2' else []) if verdicts(path, e) is None]
    out += 'pub const refused_%s = [_][]const u8{ %s };\n\n' % (name, ', '.join('"%s"' % esc(e) for e in refused))
open(D + 'link_oracle.zig', 'w').write(out)

# the live vlan programs
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
live = '// SPDX-License-Identifier: MIT\n// Generated by tools/gen_link_oracle.py: `tcpdump -i lo -dd EXPR` (libpcap 1.10.6, live Ethernet, ancillary vlan). Do not edit.\n\n'
live += 'pub const Row = struct { []const u8, []const u8 };\n\npub const rows = [_]Row{\n'
for e in LIVE_EXPRS:
    r = subprocess.run(['tcpdump', '-i', 'lo', '-dd', e], capture_output=True, text=True)
    if r.returncode != 0:
        print('REFUSED live', e, r.stderr.strip()[-80:], file=sys.stderr)
        continue
    b = b''
    for l in r.stdout.splitlines():
        mm = re.match(r'\{ (0x[0-9a-f]+), (\d+), (\d+), (0x[0-9a-f]+) \}', l.strip())
        if mm:
            b += struct.pack('<HBBI', int(mm.group(1), 16), int(mm.group(2)), int(mm.group(3)), int(mm.group(4), 16))
    live += '    .{ "%s", "%s" },\n' % (esc(e), b.hex())
live += '};\n'
open(D + 'vlan_live.zig', 'w').write(live)
print('links done; live rows', live.count('\n    .{'))
