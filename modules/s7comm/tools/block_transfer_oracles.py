#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Needs: rawshark (Wireshark, used as a black box; its source is not read) and
# python-snap7 3.1.0 (MIT). Not part of `zig build`.
"""Two checks of the block-transfer layouts in src/blocktransfer.zig.

1. Wireshark's s7comm dissector decodes the frames pinned in the module's
   tests (same hex) into the expected fields: file name, block type, number,
   destination, upload id, load/MC7 lengths, status.
2. python-snap7 3.1.0 builds its own start-upload / request-download frames;
   the script prints them next to ours and states where they differ. python-snap7
   speaks a simplified shape, so it cannot interoperate with the module's
   block transfer (see SPEC "Block upload and download").

    python3 block_transfer_oracles.py   # plain python3: python-snap7 lives in the user site
"""
import struct
import subprocess
import sys

H = bytes.fromhex


def pdu(rosctr, params, data=b"", ref=1):
    h = struct.pack(">BBHHHH", 0x32, rosctr, 0, ref, len(params), len(data))
    if rosctr in (2, 3):
        h += b"\x00\x00"
    return h + params + data


def tpkt(p):
    return struct.pack(">BBH", 3, 0, 7 + len(p)) + b"\x02\xf0\x80" + p


def pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    seq = 1000
    for f in frames:
        tcp = struct.pack(">HHIIBBHHH", 50000, 102, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + f
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, b"\n\0\0\1", b"\n\0\0\2")
        pk = b"\0" * 12 + b"\x08\x00" + ip + tcp
        out += struct.pack("<IIII", 1, 0, len(pk), len(pk)) + pk
        seq += len(f)
    return out


def dissect(frame, fields):
    cmd = ["rawshark", "-s", "-r", "-", "-d", "encap:EN10MB", "-n", "-o", "tcp.check_checksum:FALSE"]
    for f in fields:
        cmd += ["-F", f]
    r = subprocess.run(cmd, input=pcap([frame]), capture_output=True)
    if r.stderr.strip():
        raise SystemExit("rawshark: " + r.stderr.decode())
    last = [l for l in r.stdout.decode().split("\n") if l.startswith("1 ")][-1]
    vals = {}
    for tok in last.split()[1:-1]:
        i, _, v = tok.partition("=")
        vals[fields[int(i)]] = v.strip('"')
    return vals


F = "s7comm.param.blockcontrol.filename s7comm.data.blockcontrol.block_type s7comm.data.blockcontrol.block_number " \
    "s7comm.data.blockcontrol.dest_filesys s7comm.data.blockcontrol.uploadid s7comm.data.blockcontrol.loadmem_len " \
    "s7comm.data.blockcontrol.mc7code_len s7comm.param.blockcontrol.upl_lenstring s7comm.param.func " \
    "s7comm.param.pistart.servicename".split()

# (name, rosctr, parameters hex as pinned in src/blocktransfer.zig, expected fields)
CASES = [
    ("start upload", 1, "1d000000" "00000000" "09" "5f30413030303031" "41",
     {"s7comm.param.blockcontrol.filename": "_0A00001A", "s7comm.data.blockcontrol.block_type": "0A",
      "s7comm.data.blockcontrol.block_number": "00001", "s7comm.data.blockcontrol.dest_filesys": "A"}),
    ("start upload reply", 3, "1d000100" "00000001" "07" "30303030323334",
     {"s7comm.param.blockcontrol.upl_lenstring": "0000234", "s7comm.data.blockcontrol.uploadid": "0x00000001"}),
    ("request download", 1, "1a010000" "00000000" "09" "5f3041303030303150" "0d" "31" "303030323430" "303030313030",
     {"s7comm.param.blockcontrol.filename": "_0A00001P", "s7comm.data.blockcontrol.loadmem_len": "000240",
      "s7comm.data.blockcontrol.mc7code_len": "000100", "s7comm.data.blockcontrol.dest_filesys": "P"}),
    ("download block job", 1, "1b000000" "00000001" "09" "5f3043303030313250",
     {"s7comm.param.blockcontrol.filename": "_0C00012P", "s7comm.data.blockcontrol.block_number": "00012"}),
    ("insert", 1, "28000000" "000000fd" "000a" "0100" "3043303030313250" "05" "5f494e5345",
     {"s7comm.param.pistart.servicename": "_INSE"}),
]

ok = True
for name, rosctr, params, want in CASES:
    got = dissect(tpkt(pdu(rosctr, H(params))), F)
    bad = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
    print(("OK   " if not bad else "FAIL ") + name, bad if bad else "")
    ok &= not bad

# python-snap7's builders against ours (for the record, not an assertion).
try:
    from snap7.s7protocol import S7Protocol
    p = S7Protocol()
    theirs = {
        "start upload (DB1)": p.build_start_upload_request(0x41, 1)[10:].hex(),
        "request download (DB1, 240 B)": p.build_download_request(0x41, 1, bytes(240))[10:].hex(),
    }
    ours = {
        "start upload (DB1)": "1d000000" "00000000" "09" "5f30413030303031" "41",
        "request download (DB1, 240 B)": "1a010000" "00000000" "09" "5f3041303030303150" "0d" "31" "303030323430" "303030313030",
    }
    for k in theirs:
        print(f"python-snap7 {k}:\n  theirs {theirs[k]}\n  ours   {ours[k]}")
except Exception as e:  # python-snap7 absent: the dissector half still stands
    print("python-snap7 comparison skipped:", e)
sys.exit(0 if ok else 1)
