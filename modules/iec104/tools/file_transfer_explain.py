#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Needs python `c104` 2.2.1 (a lib60870-C binding), used as a black box decoder.
"""Checks the envelope of the file-transfer ASDUs pinned in src/file.zig
("wire bytes of the file ASDUs"): c104.explain_bytes must name the type id,
the cause (file transfer 13, request 5), the common address and the information
object address. c104 does not decode the file elements, so the element octets
stay anchored to the standard's layouts in SPEC "File transfer", not to this oracle.

    python3 file_transfer_explain.py
"""
import sys

import c104

FRAMES = [  # (ASDU hex, type name, cause)
    ("78010d00010000000002010504030" "0", "F_FR_NA_1", "FILE_TRANSFER"),
    ("79010d0001000000000100021000008" "0", "F_SR_NA_1", "FILE_TRANSFER"),
    ("7a010d000100000000010002" "06", "F_SC_NA_1", "FILE_TRANSFER"),
    ("7b010d000100000000010002" "03ab", "F_LS_NA_1", "FILE_TRANSFER"),
    ("7c010d000100000000010002" "24", "F_AF_NA_1", "FILE_TRANSFER"),
    ("7d010d000100000000010002" "03" "78797a", "F_SG_NA_1", "FILE_TRANSFER"),
    ("7e0105000100000000010002" "0000" "20" "00000000150b1a", "F_DR_TA_1", "REQUEST"),
]

bad = 0
for h, name, cause in FRAMES:
    asdu = bytes.fromhex(h)
    apdu = bytes([0x68, 4 + len(asdu), 0, 0, 0, 0]) + asdu
    text = c104.explain_bytes(apdu)
    ok = name in text and cause in text and "CA 1" in text and "1st IOA 0" in text
    print(("OK   " if ok else "FAIL ") + text)
    bad += not ok
sys.exit(1 if bad else 0)
