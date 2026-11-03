#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for src/testdata/run_diff.zig: random kernel-valid classic-BPF
programs and the value libpcap's interpreter (`pcap_offline_filter`) returns
for each over a few frames, which `filter.run` must reproduce exactly.

    python3 -I modules/rawsock/tools/gen_run_diff.py OUTDIR   # from the repo root

Builds tools/run_diff.c with `cc` against the system libpcap.so.0.8 (override
with LIBPCAP), writes OUTDIR/run_diff.zig. Seeded, so it reproduces.

What it avoids, on purpose: a register shift count of 32 or more (undefined in
libpcap's C `A <<= X`; the kernel masks it, so `run` masks it and
`src/filter.zig` pins that against the KERNEL, not libpcap), and scratch reads
before writes (the kernel refuses such a program; every store is in the
program's first instructions). Jump targets land on block boundaries so an
X-shift's `ldx #n` is never skipped.
"""
import os, random, struct, subprocess, sys

OUT = sys.argv[1].rstrip('/') + '/'
os.makedirs(OUT, exist_ok=True)
LIBPCAP = os.environ.get('LIBPCAP', '/usr/lib/x86_64-linux-gnu/libpcap.so.0.8')
R = random.Random(20261103)

ALU = {'add': 0x04, 'sub': 0x14, 'mul': 0x24, 'div': 0x34, 'or': 0x44, 'and': 0x54, 'lsh': 0x64, 'rsh': 0x74, 'neg': 0x84, 'mod': 0x94, 'xor': 0xa4}
X = 0x08


def insn(code, k=0, jt=0, jf=0):
    return struct.pack('<HBBI', code, jt, jf, k & 0xffffffff)


def blocks_for_program():
    """A list of blocks; a block is a list of instructions, or ('jump', code, k, kind)."""
    n_stores = R.randint(0, 3)
    slots = [R.randrange(16) for _ in range(n_stores)]
    blocks = []
    for s in slots:
        blocks.append([insn(R.choice([0x02, 0x03]), s)])  # st / stx
    for _ in range(R.randint(2, 14)):
        c = R.randrange(100)
        if c < 18:
            size = R.choice([0x20, 0x28, 0x30])
            blocks.append([insn(size, R.choice([R.randrange(0, 40), R.randrange(0, 120), 0xfff00000, 0xfffff000]))])
        elif c < 28:
            size = R.choice([0x40, 0x48, 0x50])
            blocks.append([insn(0x01, R.choice([0, 3, 7, 50, 100, 0x7ffffff0])), insn(size, R.choice([0, 1, 2, 14, 30, 2]))])
        elif c < 34:
            blocks.append([insn(R.choice([0x00, 0x01]), R.choice([0, 1, 2, 5, 0x7fffffff, 0xffffffff, R.getrandbits(32)]))])
        elif c < 38:
            blocks.append([insn(R.choice([0x80, 0x81]))])
        elif c < 42:
            blocks.append([insn(0xb1, R.randrange(0, 40))])
        elif c < 60:
            op = R.choice(['add', 'sub', 'mul', 'or', 'and', 'xor'])
            if R.random() < 0.5:
                blocks.append([insn(ALU[op], R.choice([0, 1, 3, 255, 0xffffffff, R.getrandbits(32)]))])
            else:
                blocks.append([insn(0x01, R.choice([0, 1, 7, 0xffffffff, R.getrandbits(32)])), insn(ALU[op] | X)])
        elif c < 64:
            sh = R.choice(['lsh', 'rsh'])
            if R.random() < 0.5:
                blocks.append([insn(ALU[sh], R.randrange(0, 32))])
            else:
                blocks.append([insn(0x01, R.randrange(0, 32)), insn(ALU[sh] | X)])
        elif c < 70:
            op = R.choice(['div', 'mod'])
            if R.random() < 0.5:
                blocks.append([insn(ALU[op], R.choice([1, 2, 3, 7, 0xffffffff]))])
            else:
                blocks.append([insn(0x01, R.choice([0, 1, 5, 0xffffffff])), insn(ALU[op] | X)])
        elif c < 72:
            blocks.append([insn(ALU['neg'])])
        elif c < 76:
            blocks.append([insn(R.choice([0x07, 0x87]))])
        elif c < 80 and slots:
            blocks.append([insn(R.choice([0x60, 0x61]), R.choice(slots))])
        else:
            jc = R.choice([0x15, 0x25, 0x35, 0x45])
            if R.random() < 0.3:
                blocks.append(('jump', jc | X, 0))
            else:
                blocks.append(('jump', jc, R.choice([0, 1, 5, 0x10, 0x45, 0xffffffff, R.getrandbits(32)])))
    return blocks


def assemble(blocks):
    # Layout: instruction index of each block start, then a final ret block.
    starts = []
    at = 0
    for b in blocks:
        starts.append(at)
        at += 1 if isinstance(b, tuple) else len(b)
    ret_at = at
    out = []
    for bi, b in enumerate(blocks):
        if isinstance(b, tuple):
            _, code, k = b
            here = starts[bi]
            targets = [s for s in starts[bi + 1:]] + [ret_at, ret_at + 1]
            t, f = R.choice(targets), R.choice(targets)
            if R.random() < 0.15:
                out.append(insn(0x05, t - here - 1))  # ja
            else:
                out.append(insn(code, k, t - here - 1, f - here - 1))
        else:
            out.extend(b)
    out.append(insn(R.choice([0x16, 0x06]), R.choice([0, 1, 65535, 262144])))  # ret A / ret k
    out.append(insn(0x06, 0))
    return b''.join(out)


def frames():
    lens = [60, 14, 3, 100, 0 + 2, 64]
    return [bytes(R.getrandbits(8) for _ in range(n)) for n in lens]


fr = frames()
progs = [assemble(blocks_for_program()) for _ in range(160)]
open(OUT + 'progs.txt', 'w').write('\n'.join(p.hex() for p in progs) + '\n')
open(OUT + 'frames.txt', 'w').write('\n'.join(f.hex() for f in fr) + '\n')
exe = OUT + 'run_diff'
subprocess.run(['cc', '-O1', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'run_diff.c'), LIBPCAP, '-o', exe], check=True)
res = subprocess.run([exe, OUT + 'progs.txt', OUT + 'frames.txt'], capture_output=True, text=True, check=True).stdout.splitlines()
assert len(res) == len(progs)
with open(OUT + 'run_diff.zig', 'w') as z:
    z.write('// SPDX-License-Identifier: MIT\n// Generated by tools/gen_run_diff.py: random kernel-valid classic-BPF programs and what\n// libpcap 1.10.6 `pcap_offline_filter` returned for each over `frames`. Do not edit.\n\n')
    z.write('pub const frames = [_][]const u8{\n' + ''.join('    "%s",\n' % f.hex() for f in fr) + '};\n\n')
    z.write('pub const Case = struct { prog: []const u8, libpcap_valid: bool, verdicts: [%d]u32 };\n\n' % len(fr))
    z.write('pub const cases = [_]Case{\n')
    for p, r in zip(progs, res):
        f = r.split()
        z.write('    .{ .prog = "%s", .libpcap_valid = %s, .verdicts = .{ %s } },\n' % (p.hex(), 'true' if f[0] == '1' else 'false', ', '.join(f[1:])))
    z.write('};\n')
print(len(progs), 'programs;', sum(1 for r in res if r.split()[0] == '1'), 'valid for libpcap')
