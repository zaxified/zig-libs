#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dissect raw protocol bytes with Wireshark's dissectors, headless.

An *anchoring* tool, not a test dependency. Modules in this repo that encode a
wire format need an oracle that can fail independently of whoever wrote the
encoder; Wireshark's dissector library is exactly that — a mature, third-party
reading of the same specification. This script feeds bytes to it and prints
what it made of them.

The intended workflow is capture-and-freeze: run this once, read the field
values back, and commit them into a Zig test as literals with the command that
produced them in a comment. Nothing in the default test gate may invoke this —
the gate stays offline and dependency-free.

Requires `text2pcap` and `sharkd` on PATH (Debian/Ubuntu: `wireshark-common`).
Note that `sharkd` ships with the GUI package, so it is usually present even
where the `tshark` CLI is not.

Usage:
    scripts/dissect.py --frame llc <<< '831b0100 0f010000 ...'
    printf '%s' "$hex" | scripts/dissect.py --frame llc --fields
    scripts/dissect.py --frame eth --json < frame.hex

Input is hex on stdin or as a positional argument; whitespace, newlines,
`0x` prefixes and `:`/`-` separators are all ignored, so a Zig array literal
or a hexdump column can be pasted in directly.

Framings (`--frame`):
    raw   input is already a complete link-layer frame (default encap 1)
    eth   same as `raw`, spelled for readability
    llc   input is a bare OSI PDU; wrap it in 802.3 + LLC (DSAP/SSAP 0xfe,
          control 0x03) with an IS-IS multicast destination, which is how
          IS-IS, ESIS and friends actually appear on the wire
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ISIS_ALL_L1 = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x14])
DEFAULT_SRC = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01])


def parse_hex(text: str) -> bytes:
    """Accept hexdumps, Zig `0x..,` array literals, or bare hex."""
    cleaned = re.sub(r"0x|[\s,:;\-_]|//.*", "", text)
    if len(cleaned) % 2:
        sys.exit("error: odd number of hex digits (%d)" % len(cleaned))
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        sys.exit("error: not hex: %s" % exc)


def wrap_llc(pdu: bytes, dst: bytes, src: bytes) -> bytes:
    """802.3 length-framed Ethernet + LLC UI, the OSI-over-LAN encapsulation."""
    llc = bytes([0xFE, 0xFE, 0x03]) + pdu
    return dst + src + len(llc).to_bytes(2, "big") + llc


def flatten(nodes, depth=0, out=None):
    """Walk sharkd's proto tree into (depth, filter_name, label) triples."""
    if out is None:
        out = []
    for node in nodes or ():
        out.append((depth, node.get("f", ""), node.get("l", "")))
        flatten(node.get("n"), depth + 1, out)
    return out


def dissect(frame: bytes, encap: int):
    for tool in ("text2pcap", "sharkd"):
        if not shutil.which(tool):
            sys.exit(
                "error: %s not found on PATH — install wireshark-common" % tool
            )

    tmpdir = tempfile.mkdtemp(prefix="dissect-")
    hexfile = os.path.join(tmpdir, "in.txt")
    pcapfile = os.path.join(tmpdir, "in.pcap")
    try:
        with open(hexfile, "w") as fh:
            for off in range(0, len(frame), 16):
                chunk = frame[off : off + 16]
                fh.write("%06x  %s\n" % (off, " ".join("%02x" % b for b in chunk)))

        subprocess.run(
            ["text2pcap", "-q", "-l", str(encap), hexfile, pcapfile],
            check=True,
        )

        script = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "load",
                    "params": {"file": pcapfile},
                }
            )
            + "\n"
            + json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "frame",
                    "params": {"frame": 1, "proto": True},
                }
            )
            + "\n"
        )
        proc = subprocess.run(
            ["sharkd", "-"], input=script, capture_output=True, text=True
        )

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            msg = json.loads(line)
            if msg.get("id") == 2:
                if "error" in msg:
                    sys.exit("error: sharkd: %s" % msg["error"])
                return msg["result"]
        sys.exit(
            "error: sharkd returned no dissection\n--- stderr ---\n%s"
            % proc.stderr[:2000]
        )
    finally:
        for path in (hexfile, pcapfile):
            if os.path.exists(path):
                os.remove(path)
        os.rmdir(tmpdir)


def main():
    ap = argparse.ArgumentParser(
        description="Dissect raw bytes with Wireshark's dissectors (headless).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:", 1)[1],
    )
    ap.add_argument("hex", nargs="?", help="hex bytes; omit to read stdin")
    ap.add_argument(
        "--frame",
        choices=("raw", "eth", "llc"),
        default="raw",
        help="how to frame the input before handing it to Wireshark",
    )
    ap.add_argument(
        "--encap",
        type=int,
        default=1,
        help="text2pcap link type for --frame raw/eth (default 1, Ethernet)",
    )
    ap.add_argument("--dst", default=None, help="destination MAC for --frame llc")
    ap.add_argument(
        "--json", action="store_true", help="print sharkd's raw JSON result"
    )
    ap.add_argument(
        "--fields",
        action="store_true",
        help="print `filter.name = label` pairs, the form easiest to assert on",
    )
    args = ap.parse_args()

    raw = args.hex if args.hex is not None else sys.stdin.read()
    if not raw.strip():
        sys.exit("error: no input bytes")
    pdu = parse_hex(raw)

    if args.frame == "llc":
        dst = parse_hex(args.dst) if args.dst else ISIS_ALL_L1
        if len(dst) != 6:
            sys.exit("error: --dst must be 6 bytes")
        frame = wrap_llc(pdu, dst, DEFAULT_SRC)
    else:
        frame = pdu

    result = dissect(frame, args.encap)

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    rows = flatten(result.get("tree"))
    if args.fields:
        for _, name, label in rows:
            if name:
                print("%s = %s" % (name, label))
    else:
        for depth, _, label in rows:
            print("%s%s" % ("  " * depth, label))


if __name__ == "__main__":
    main()
