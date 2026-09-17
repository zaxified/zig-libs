#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recompute RFC 8613 Appendix C from scratch with a THIRD-PARTY crypto stack
(python `cryptography`: HKDF-SHA-256 + AESCCM tag_length=8), independent of
the `oscore` Zig module, and compare against `kat_vectors.zig`'s committed
values field by field. This is a recipe for the committed data, not a wire
driver: it reads the vectors as text and recomputes each field, so a KAT is
something this repo can re-derive rather than merely re-read.

Covers: the §3.2.1 `info` CBOR array, the Sender/Recipient Key and Common IV
HKDF derivation, the §5.2 nonce XOR, the §5.4 aad_array / Enc_structure AAD,
and the §8 AES-CCM-16-64-128 seal (ciphertext||tag).

Needs: Python 3 with `cryptography` (`python3 -c "import cryptography"`) —
Apache-2.0 OR BSD-3-Clause, verified at its dist-info METADATA
(`License-Expression: Apache-2.0 OR BSD-3-Clause`). Not copyleft.
Produces: one `agreements: <n>   mismatches: <n>` line on stdout, plus any
per-field MISMATCH lines; exit 0 iff there are no mismatches.

Usage (see `tools/README.md` for the measured result of the last run):
    python3 modules/oscore/tools/independent_oracle.py modules/oscore/src/kat_vectors.zig
"""
import re, sys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

H = bytes.fromhex

# ── minimal CBOR encoder, written from RFC 7049's own major-type table ──
def head(major, arg):
    mt = major << 5
    if arg < 24:   return bytes([mt | arg])
    if arg <= 0xFF: return bytes([mt | 24, arg])
    if arg <= 0xFFFF: return bytes([mt | 25]) + arg.to_bytes(2, "big")
    if arg <= 0xFFFFFFFF: return bytes([mt | 26]) + arg.to_bytes(4, "big")
    return bytes([mt | 27]) + arg.to_bytes(8, "big")

def bstr(b):  return head(2, len(b)) + b
def tstr(s):  return head(3, len(s)) + s.encode()
def arr(n):   return head(4, n)
def uint(v):  return head(0, v)
CBOR_NULL = bytes([0xF6])

ALG = 10  # AES-CCM-16-64-128

def info(id_, id_ctx, label, L):
    return (arr(5) + bstr(id_) +
            (bstr(id_ctx) if id_ctx is not None else CBOR_NULL) +
            uint(ALG) + tstr(label) + uint(L))

def hkdf(secret, salt, inf, L):
    prk = hmac.HMAC(salt if salt else b"\x00"*32, SHA256())
    prk.update(secret); prk = prk.finalize()
    return HKDFExpand(algorithm=SHA256(), length=L, info=inf).derive(prk)

def nonce(common_iv, id_piv, piv):
    assert len(id_piv) <= 7, "ID_PIV wider than nonce_len-6"
    blk = bytes([len(id_piv)]) + b"\x00"*(7-len(id_piv)) + id_piv + piv.to_bytes(5, "big")
    assert len(blk) == 13
    return bytes(a ^ b for a, b in zip(blk, common_iv))

def aad_array(req_kid, req_piv, opts=b""):
    return arr(5) + uint(1) + arr(1) + uint(ALG) + bstr(req_kid) + bstr(req_piv) + bstr(opts)

def full_aad(req_kid, req_piv, opts=b""):
    return arr(3) + tstr("Encrypt0") + bstr(b"") + bstr(aad_array(req_kid, req_piv, opts))

# ── parse kat_vectors.zig ────────────────────────────────────────────────
src = re.sub(r"//.*", "", open(sys.argv[1], encoding="utf-8").read())
def blocks(after):
    seg = src.split(after, 1)[1].split("};", 1)[0]
    return [b for b in seg.split(".{")[1:]]
def fields(b):
    d = {}
    for m in re.finditer(r'\.(\w+)\s*=\s*(?:"([^"]*)"|(\d+)|(null)|(true|false))', b):
        k = m.group(1)
        d[k] = m.group(2) if m.group(2) is not None else (
               int(m.group(3)) if m.group(3) is not None else (
               None if m.group(4) else m.group(5) == "true"))
    return d

ok = bad = 0
def chk(name, got, want):
    global ok, bad
    if got == want: ok += 1
    else:
        bad += 1
        print(f"  MISMATCH {name}\n    got  {got.hex() if isinstance(got,bytes) else got}"
              f"\n    want {want.hex() if isinstance(want,bytes) else want}")

print("== C.1-C.3 key derivation (info / Sender Key / Recipient Key / Common IV / nonces) ==")
for b in blocks("key_derivation_vectors = [_]KeyDerivationVector{"):
    f = fields(b)
    if "master_secret" not in f: continue
    ms, msalt = H(f["master_secret"]), H(f["master_salt"])
    idc = H(f["id_context"]) if f["id_context"] else None
    sid, rid = H(f["sender_id"]), H(f["recipient_id"])
    print(f"- {f['label']}")
    chk("info_sender_key",    info(sid, idc, "Key", 16), H(f["info_sender_key"]))
    chk("info_recipient_key", info(rid, idc, "Key", 16), H(f["info_recipient_key"]))
    chk("info_common_iv",     info(b"",  idc, "IV", 13), H(f["info_common_iv"]))
    sk = hkdf(ms, msalt, info(sid, idc, "Key", 16), 16)
    rk = hkdf(ms, msalt, info(rid, idc, "Key", 16), 16)
    civ = hkdf(ms, msalt, info(b"", idc, "IV", 13), 13)
    chk("sender_key", sk, H(f["sender_key"]))
    chk("recipient_key", rk, H(f["recipient_key"]))
    chk("common_iv", civ, H(f["common_iv"]))
    chk("sender_nonce_piv0",    nonce(civ, sid, 0), H(f["sender_nonce_piv0"]))
    chk("recipient_nonce_piv0", nonce(civ, rid, 0), H(f["recipient_nonce_piv0"]))

print("== C.4-C.8 protected messages (nonce / aad_array / AAD / AEAD ciphertext||tag) ==")
for b in blocks("message_vectors = [_]MessageVector{"):
    f = fields(b)
    if "sender_key" not in f: continue
    print(f"- {f['label']}")
    civ = H(f["common_iv"])
    n = nonce(civ, H(f["nonce_id"]), f["nonce_piv"])
    chk("nonce", n, H(f["nonce"]))
    chk("aad_array", aad_array(H(f["request_kid"]), H(f["request_piv"])), H(f["aad_array"]))
    aad = full_aad(H(f["request_kid"]), H(f["request_piv"]))
    chk("aad", aad, H(f["aad"]))
    ct = AESCCM(H(f["sender_key"]), tag_length=8).encrypt(n, H(f["plaintext"]), aad)
    chk("ciphertext||tag", ct, H(f["ciphertext"]))
    pt = AESCCM(H(f["sender_key"]), tag_length=8).decrypt(n, H(f["ciphertext"]), aad)
    chk("decrypt->plaintext", pt, H(f["plaintext"]))

print(f"\nagreements: {ok}   mismatches: {bad}")
sys.exit(1 if bad else 0)
