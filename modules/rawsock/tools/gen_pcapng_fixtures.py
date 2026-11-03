#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for the pcapng fixtures in src/pcapng.zig.

Takes three frames of the corpus in src/filter.zig (frames 0, 16 and 1: an ARP
request, a 13-byte runt that needs padding, a UDP datagram), writes them as a
nanosecond and a microsecond classic pcap file, asks Wireshark's `editcap -F
pcapng` (black box) to convert both, encodes the same capture a second time
with the layout this module's writer emits, and prints what `tcpdump -n --nano
-tt -r` (libpcap) and `capinfos` read from the writer's files. Writes
OUTDIR/fixtures.zig (the six `const NAME = hex(...)` blocks the tests quote:
pcap_ns, pcap_us, editcap_ns, editcap_us, ours_ns, ours_us).

    python3 -I modules/rawsock/tools/gen_pcapng_fixtures.py OUTDIR   # from the repo root

Needs editcap, capinfos (wireshark-common) and tcpdump. No privileges.
"""
import os, re, struct, subprocess, sys

D = sys.argv[1].rstrip('/') + '/'
os.makedirs(D, exist_ok=True)
src = open('modules/rawsock/src/filter.zig').read()
m = re.search(r'const corpus_pcap = hex\((.*?)\n\);', src, re.S)
corpus = bytes.fromhex(''.join(re.findall(r'"([0-9a-f]+)"', m.group(1))))
recs = []
pos = 24
while pos < len(corpus):
    ts, tu, cl, ol = struct.unpack_from('<IIII', corpus, pos)
    recs.append((ol, corpus[pos + 16:pos + 16 + cl]))
    pos += 16 + cl
pick = [recs[0], recs[16], recs[1]]


def classic(magic, frac):
    out = struct.pack('<IHHiIII', magic, 2, 4, 0, 0, 262144, 1)
    for i, (ol, d) in enumerate(pick):
        out += struct.pack('<IIII', 1700000000 + i, frac(i), len(d), ol) + d
    return out


files = {
    'pcap_ns': classic(0xa1b23c4d, lambda i: 123456789 - i * 1000),
    'pcap_us': classic(0xa1b2c3d4, lambda i: 123456 - i),
}
for name, key in (('ns', 'pcap_ns'), ('us', 'pcap_us')):
    open(D + name + '.pcap', 'wb').write(files[key])
    subprocess.run(['editcap', '-F', 'pcapng', D + name + '.pcap', D + name + '.pcapng'], check=True)
    files['editcap_' + name] = open(D + name + '.pcapng', 'rb').read()


def pad(b):
    return b + bytes(-len(b) % 4)


def ours(nano):
    out = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    out += struct.pack('<IIHHIHHBBBBHHI', 1, 32, 1, 0, 262144, 9, 1, 9 if nano else 6, 0, 0, 0, 0, 0, 32)
    for i, (ol, d) in enumerate(pick):
        sec = 1700000000 + i
        frac = (123456789 - i * 1000) if nano else (123456 - i)
        ticks = sec * (10**9 if nano else 10**6) + frac
        total = 32 + len(pad(d))
        out += struct.pack('<IIIIIII', 6, total, 0, ticks >> 32, ticks & 0xffffffff, len(d), ol) + pad(d) + struct.pack('<I', total)
    return out


files['ours_ns'] = ours(True)
files['ours_us'] = ours(False)
for k in ('ours_ns', 'ours_us'):
    open(D + k + '.pcapng', 'wb').write(files[k])
    print(k)
    print(subprocess.run(['tcpdump', '-n', '--nano', '-tt', '-r', D + k + '.pcapng'], capture_output=True, text=True).stdout)
    print(subprocess.run(['capinfos', '-T', '-c', '-a', '-e', D + k + '.pcapng'], capture_output=True, text=True).stdout)

with open(D + 'fixtures.zig', 'w') as f:
    for name in ('pcap_ns', 'pcap_us', 'editcap_ns', 'editcap_us', 'ours_ns', 'ours_us'):
        h = files[name].hex()
        parts = [h[i:i + 96] for i in range(0, len(h), 96)]
        f.write('const %s = hex(\n' % name)
        for j, p in enumerate(parts):
            f.write('    "%s"%s\n' % (p, ' ++' if j < len(parts) - 1 else ','))
        f.write(');\n\n')
