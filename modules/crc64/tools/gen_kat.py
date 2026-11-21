# Recipe for the frozen values in src/root.zig: liblzma's CRC-64 as a black box.
# Python's `lzma` has no crc64 function, so the value is read back out of an .xz
# stream made with CHECK_CRC64: the 8 check bytes sit right before the index.
#   python3 -I modules/crc64/tools/gen_kat.py
import lzma
import struct


def data(n):
    x = 12345
    out = bytearray()
    for _ in range(n):
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append(x >> 24)
    return bytes(out)


def crc64(d):
    z = lzma.compress(d, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    index = (struct.unpack("<I", z[-8:-4])[0] + 1) * 4
    return struct.unpack("<Q", z[-12 - index - 8 : -12 - index])[0]


print(hex(crc64(b"123456789")))
for n in (1, 15, 16, 17, 63, 64, 65, 1000, 65536, 100003):
    print(n, hex(crc64(data(n))))
