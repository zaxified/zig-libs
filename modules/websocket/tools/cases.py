# SPDX-License-Identifier: MIT
# Shared adversarial/valid case table for the websocket external-anchor capture.
# Each case: (name, client_to_server_frame_bytes_UNMASKED_TEMPLATE)
# Frames are built here unmasked; the raw client masks them before sending.
import struct

def hdr(fin, opcode, plen, force=None):
    b0 = (0x80 if fin else 0) | opcode
    if force == 16:
        return bytes([b0, 126]) + struct.pack('!H', plen)
    if force == 64:
        return bytes([b0, 127]) + struct.pack('!Q', plen)
    if plen <= 125:
        return bytes([b0, plen])
    if plen <= 0xFFFF:
        return bytes([b0, 126]) + struct.pack('!H', plen)
    return bytes([b0, 127]) + struct.pack('!Q', plen)

def frame(fin, opcode, payload, force=None):
    return hdr(fin, opcode, len(payload), force) + payload

def close_body(code, reason=b''):
    return struct.pack('!H', code) + reason

CASES = []
def C(name, data): CASES.append((name, data))

# ---- valid ----
C("valid_text_hello",            frame(True, 0x1, b"Hello"))
C("valid_binary_256",            frame(True, 0x2, bytes(range(256))*1 if False else bytes(i & 0xff for i in range(256))))
C("valid_ping_hello",            frame(True, 0x9, b"Hello"))
C("valid_pong_hello",            frame(True, 0xA, b"Hello"))
C("valid_text_125",              frame(True, 0x1, b"a"*125))
C("valid_text_126_16bit",        frame(True, 0x1, b"a"*126))
C("valid_text_65535_16bit",      frame(True, 0x1, b"a"*65535))
C("valid_text_65536_64bit",      frame(True, 0x1, b"a"*65536))
C("valid_text_empty",            frame(True, 0x1, b""))
C("valid_ctrl_125",              frame(True, 0x9, b"a"*125))
C("valid_close_1000",            frame(True, 0x8, close_body(1000)))
C("valid_close_1000_reason",     frame(True, 0x8, close_body(1000, b"bye")))
C("valid_close_empty",           frame(True, 0x8, b""))
C("valid_close_1001",            frame(True, 0x8, close_body(1001)))
C("valid_close_1003",            frame(True, 0x8, close_body(1003)))
C("valid_close_1007",            frame(True, 0x8, close_body(1007)))
C("valid_close_1011",            frame(True, 0x8, close_body(1011)))
C("valid_close_3000",            frame(True, 0x8, close_body(3000)))
C("valid_close_4999",            frame(True, 0x8, close_body(4999)))
C("valid_utf8_2byte",            frame(True, 0x1, b"\xc3\xa9"))
C("valid_utf8_4byte",            frame(True, 0x1, b"\xf0\x9f\x92\xa9"))

# ---- adversarial: header ----
C("rsv1_set",                    bytes([0xC1, 0x05]) + b"Hello")
C("rsv2_set",                    bytes([0xA1, 0x05]) + b"Hello")
C("rsv3_set",                    bytes([0x91, 0x05]) + b"Hello")
C("opcode_0x3_reserved",         frame(True, 0x3, b"Hello"))
C("opcode_0x7_reserved",         frame(True, 0x7, b"Hello"))
C("opcode_0xB_reserved",         frame(True, 0xB, b""))
C("opcode_0xF_reserved",         frame(True, 0xF, b""))
C("fragmented_ping",             frame(False, 0x9, b"x"))
C("fragmented_close",            frame(False, 0x8, close_body(1000)))
C("control_payload_126",         hdr(True, 0x9, 126, force=16) + b"a"*126)
C("nonminimal_len16",            hdr(True, 0x1, 5, force=16) + b"Hello")
C("nonminimal_len16_zero",       hdr(True, 0x1, 0, force=16))
C("nonminimal_len64",            hdr(True, 0x1, 5, force=64) + b"Hello")
C("nonminimal_len64_at_65535",   hdr(True, 0x1, 65535, force=64) + b"a"*65535)
C("len64_msb_set",               bytes([0x81, 127]) + struct.pack('!Q', 1 << 63) )
C("orphan_continuation",         frame(True, 0x0, b"orphan"))
C("bad_utf8_text",               frame(True, 0x1, b"\xff\xfe"))
C("bad_utf8_overlong",           frame(True, 0x1, b"\xc0\xaf"))
C("bad_utf8_surrogate",          frame(True, 0x1, b"\xed\xa0\x80"))
C("bad_utf8_truncated",          frame(True, 0x1, b"\xe2\x82"))

# ---- adversarial: close codes (the F5 §7.9 class) ----
for code in [0, 999, 1004, 1005, 1006, 1012, 1013, 1014, 1015, 1016, 1100, 2000, 2999, 5000, 65535]:
    C("close_code_%d" % code, frame(True, 0x8, close_body(code)))
C("close_body_1byte",            frame(True, 0x8, b"\x03"))
C("close_reason_bad_utf8",       frame(True, 0x8, close_body(1000, b"\xff\xfe")))
