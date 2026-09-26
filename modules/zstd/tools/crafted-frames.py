#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""crafted-frames -- the recipe for the frames `decoder_test.zig`'s test
"frames no encoder writes ..." builds itself, and for the verdicts it pins.

    python3 crafted-frames.py DIR     # writes DIR/<name>.zst, prints each
                                      # frame's length and FNV-1a
    for f in DIR/*.zst; do for m in 0 1 2; do zdec "$f" - $m; done; done

Every frame is valid by the format but no encoder writes it: 4 Huffman
streams of exactly 6 literals (X1, and X2 through a treeless block after
one whose literals chose X2), an RLE table of the largest literal-length
(35) or match-length (52) code, and 0x7EFF / 0x7F00 / 0x7F01 sequences. The
test's Zig builder must give the same bytes (it checks the FNV-1a printed
here); `zdec` gives libzstd's `OK <size> <fnv1a64>` the test expects.
"""
import os
import sys

def fnv(b):
    h=0xcbf29ce484222325
    for x in b: h=((h^x)*0x100000001b3)&0xFFFFFFFFFFFFFFFF
    return h
def lit(n, seed):  # the literals: an LCG's top bytes
    s=seed; out=bytearray()
    for _ in range(n):
        s=(s*6364136223846793005+1442695040888963407)&0xFFFFFFFFFFFFFFFF
        out.append(s>>56)
    return bytes(out)
def le(v,n): return v.to_bytes(n,'little')
def frame(content_size, block):
    # a 128 KB window, 4-byte content size, one last compressed block
    return b'\x28\xb5\x2f\xfd' + bytes([0x80, 0x38]) + le(content_size,4) + le(1|(2<<1)|(len(block)<<3),3) + block
def raw_lits(l):
    return le(0|(3<<2)|(len(l)<<4),3) + l
def rle_seqs(nbseq_bytes, ll, of, ml, bits):
    return nbseq_bytes + bytes([0x54, ll, of, ml]) + bits
out_dir = sys.argv[1]
frames={}
# 4 streams, 6 literals: symbols 0/1, both 1 bit (weights: header 0x80, 0x10)
streams=[0x05,0x06,0x07,0x01]  # [0,1] [1,0] [1,1] []
huf=bytes([0x80,0x10]) + le(1,2)*3 + bytes(streams)
lits=le(2|(1<<2)|(6<<4)|(len(huf)<<14),3) + huf
frames['huf4x_6']=frame(6, lits + b'\x00')
# RLE LL code 35: 65536 + 7 literals, then a 3-byte match at offset 1
l=lit(65543, 1)
frames['rle_ll35']=frame(65546, raw_lits(l) + rle_seqs(b'\x01', 35, 0, 0, le(7|(1<<16),3)))
# RLE ML code 52: 1 literal, a match of 65539 + 5
frames['rle_ml52']=frame(65545, le(1<<3,1) + b'\x5a' + rle_seqs(b'\x01', 1, 0, 52, le(5|(1<<16),3)))
# nbSeq around 0x7F00: every sequence 1 literal + 3 at offset 1, no bits
for n, hdr in [(0x7EFF, b'\xfe\xff'), (0x7F00, b'\xff\x00\x00'), (0x7F01, b'\xff\x01\x00')]:
    frames['nbseq_%04x'%n]=frame(4*n, raw_lits(lit(n, 2)) + rle_seqs(hdr, 1, 0, 0, b'\x01'))
for k,f in frames.items():
    open(os.path.join(out_dir, k+'.zst'),'wb').write(f)
    print(k, len(f), '0x%016x'%fnv(f))
# X2 for 4 streams of 6 literals: a first block whose literals pick the
# double-symbol decoder (64 000 of symbols 0/1, 1 bit each), then a treeless
# block (type 3) of 6 literals in 4 streams that reuses its table
def stream_bytes(syms):
    k=len(syms); v=1<<k
    for i,s in enumerate(syms): v|=s<<(k-1-i)
    return le(v,(k+8)//8)
def huf4(syms):
    seg=(len(syms)+3)//4
    parts=[stream_bytes(syms[i*seg:(i+1)*seg]) for i in range(4)]
    return b''.join(le(len(p),2) for p in parts[:3]) + b''.join(parts)
N=64000
bits=[b>>7 for b in lit(N,3)]
body=bytes([0x80,0x10]) + huf4(bits)
h1=le(2|(3<<2)|(N<<4)|(len(body)<<22),5)
blk1=h1+body+b'\x00'
body2=huf4([0,1,1,0,1,1])
blk2=le(3|(1<<2)|(6<<4)|(len(body2)<<14),3)+body2+b'\x00'
f=b'\x28\xb5\x2f\xfd'+bytes([0x80,0x38])+le(N+6,4)+le(0|(2<<1)|(len(blk1)<<3),3)+blk1+le(1|(2<<1)|(len(blk2)<<3),3)+blk2
open(os.path.join(out_dir, 'huf4x2_6.zst'),'wb').write(f)
print('huf4x2_6', len(f), '0x%016x'%fnv(f))
