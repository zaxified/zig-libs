#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Recipe for the hand-derived Secure Authentication vectors pinned by the first
# test in src/secure_auth.zig ("SA: key change, challenge, reply and aggressive
# mode match hand-derived vectors"). Independent of this module: Python hmac /
# hashlib for every MAC and the `cryptography` package for RFC 3394 AES key wrap,
# over the IEEE 1815-2012 g120 byte layouts. Prints each fragment as hex.
#
# Run: python3 -I modules/dnp3/tools/sa_outstation_kat.py   (needs `cryptography`)
import hmac, hashlib
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
H=bytes.fromhex
def mac(k,m): return hmac.new(k,m,hashlib.sha256).digest()[:16]
def obj(v,body): return bytes([120,v,0x5B,1])+len(body).to_bytes(2,'little')+body
U=bytes(range(0x00,0x10)); Kc=bytes(range(0x40,0x50)); Km=bytes(range(0x60,0x70))
iin=H('8000')
st1=H('01000000'+'0100'+'01'+'02'+'04'+'0400'+'01020304')
print('status1', (H('C083')+iin+obj(5,st1)).hex())
# SAv5 key wrap: key length (u16 LE) || control || monitoring || the g120v5
# body that opened the window (st1) || zero padding to a multiple of 8.
plain=(16).to_bytes(2,'little')+Kc+Km+st1
plain+=bytes(-len(plain)%8)
wrapped=aes_key_wrap(U,plain)
kc=H('01000000'+'0100')+wrapped
print('keychange_req', (H('C120')+obj(6,kc)).hex())
st2=H('02000000'+'0100'+'01'+'01'+'04'+'0400'+'05060708')+mac(Km,kc)
print('status2', (H('C183')+iin+obj(5,st2)).hex())
crob=H('0C011701000301640000006400000000')
req=H('C305')+crob
ch=H('C383')+iin+obj(1,H('01000000'+'0100'+'04'+'01'+'090A0B0C'))
print('challenge', ch.hex())
rep=H('C320')+obj(2,H('01000000'+'0100')+mac(Kc,ch+req))
print('reply', rep.hex())
agg_pre=H('C405')+obj(3,H('02000000'+'0100'))+crob
agg=agg_pre+obj(9,mac(Kc,ch+agg_pre))
print('aggressive', agg.hex())
