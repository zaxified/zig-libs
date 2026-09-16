#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Corpus generator for the dns differential. Writes hex, one packet per line."""
import random, struct, sys
random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
N = int(sys.argv[1])
TYPES = [1,2,5,6,12,15,16,28,33,41,257,99,65535,0]
out = []

def rname(depth=None, maxlab=None):
    labs = []
    d = depth if depth is not None else random.randint(0,4)
    for _ in range(d):
        n = random.choice([1,2,3,7,random.randint(1,63)]) if maxlab is None else maxlab
        labs.append(bytes([n]) + bytes(random.choice([ord('a'),ord('.'),0,0xff,ord('A')]) for _ in range(n)))
    return b"".join(labs) + b"\x00"

def rdata_for(t, base):
    if t == 1:  return bytes(random.getrandbits(8) for _ in range(random.choice([4,4,4,3,5])))
    if t == 28: return bytes(random.getrandbits(8) for _ in range(random.choice([16,16,4,17])))
    if t in (2,5,12): return rname()
    if t == 15: return struct.pack("!H", random.getrandbits(16)) + rname()
    if t == 16:
        b=b""
        for _ in range(random.randint(0,4)):
            n=random.randint(0,20); b += bytes([random.choice([n, n+random.randint(0,5)])]) + bytes(n)
        return b
    if t == 6:  return rname()+rname()+bytes(20)
    if t == 33: return struct.pack("!HHH", *[random.getrandbits(16) for _ in range(3)]) + rname()
    if t == 257:
        tag = bytes(random.randint(0,6))
        return bytes([random.getrandbits(8), max(0, min(255, len(tag)+random.choice([0,0,1,-1])))]) + tag + b"val"
    if t == 41: return bytes(random.randint(0,8))
    return bytes(random.randint(0,10))

for _ in range(N):
    qd = random.choice([0,1,1,1,2])
    an = random.choice([0,1,1,2,3])
    ns_ = random.choice([0,0,1])
    ar = random.choice([0,0,1])
    body = b""
    for _ in range(qd):
        body += rname() + struct.pack("!HH", random.choice(TYPES), random.choice([1,1,1,3,255]))
    for _ in range(an+ns_+ar):
        t = random.choice(TYPES)
        # 40 % of owners are a compression pointer into the packet we have so far
        if body and random.random() < 0.4:
            off = random.randint(0, min(len(body)+11, 0x3fff))
            owner = bytes([0xc0 | (off>>8), off & 0xff])
        else:
            owner = rname()
        rd = rdata_for(t, body)
        rdlen = len(rd) + random.choice([0,0,0,0,0,0,0,0,1,-1])
        if rdlen < 0: rdlen = 0
        body += owner + struct.pack("!HHIH", t, random.choice([1,1,1,3]), random.getrandbits(32), rdlen) + rd
    hdr = struct.pack("!HHHHHH", random.getrandbits(16), random.getrandbits(16), qd, an, ns_, ar)
    pkt = hdr + body
    if random.random() < 0.15:   # truncate somewhere
        pkt = pkt[:random.randint(0, len(pkt))]
    if random.random() < 0.15:   # flip some bytes
        pkt = bytearray(pkt)
        for _ in range(random.randint(1,4)):
            if pkt: pkt[random.randrange(len(pkt))] = random.getrandbits(8)
        pkt = bytes(pkt)
    out.append(pkt.hex())

for _ in range(N//4):
    out.append(bytes(random.getrandbits(8) for _ in range(random.randint(0,600))).hex())

print("\n".join(out))
