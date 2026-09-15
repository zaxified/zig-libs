#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Privileged IPv4 fragment-reassembly capture tool for `ethfrag`'s kernel oracle.

`modules/ethfrag/src/kernel_oracle.zig` replays frozen, hand-built IPv4/IPv6
fragment captures against this module's own `Reassembler` as a black-box
RFC-policy oracle (see that file's module doc comment for the full recipe and
rationale). That doc comment used to say "`capture.py` is not part of this
repository -- a throwaway harness, not shipped code": this file is that
harness, now checked in per `CONVENTIONS.md` Sec.9 ("an instrument that needs a
FOREIGN TOOLCHAIN lives in `modules/<name>/tools/`, never in `src/`" -- this
needs a Python interpreter and `CAP_NET_RAW`, neither of which `test-ethfrag`
may require).

It builds real IPv4 fragments BY HAND (`socket.SOCK_RAW` + `IP_HDRINCL`,
manual header packing, manual Internet checksum -- `scapy` is not installed
and may not be installed) and fires them at a plain `SOCK_DGRAM` UDP listener
on the loopback interface in the SAME network namespace, so the only judge of
"was this reassembled" is the real Linux kernel's own `ip_defrag` /
`ip_local_deliver` path. Needs `CAP_NET_RAW` to create the raw socket, which a
normal process does not have; the cheap way to get it without `sudo` is an
unprivileged user namespace with its own net namespace:

    unshare --user --map-root-user --net -- sh -c '
        ip link set lo up
        python3 modules/ethfrag/tools/capture.py --verify
    '

Two entry points:

  * `--verify` (default): runs every scenario in `SCENARIOS`, compares the
    live kernel's verdict against the `expect` recorded on that scenario, and
    exits non-zero on any mismatch (or on `PermissionError` -- see "skip
    shape" below). This is the gate: it must FAIL on a corrupted expectation
    or a corrupted packet-builder, and PASS on the real ones.
  * `--print` <scenario>: runs one scenario and prints its raw fragment bytes
    (hex, in send order) plus the delivered datagram (hex) or "TIMEOUT", in
    the same shape as `kernel_oracle.zig`'s `Capture` struct literal, so a
    new scenario's frozen bytes can be captured once and pasted into that
    file (exactly how the original 12 were produced, per that file's doc
    comment).

Mutation flags for demonstrating the RED side of RED->GREEN (see
`A1/ethfrag.md`, "Dispozice 2026-09-15 (F13 unshare)"):

  * `--corrupt-offset SCENARIO` shifts the named scenario's first fragment's
    declared IPv4 fragment offset by +8 bytes (still a legal multiple of the
    8-byte granularity, so the packet is well-formed -- just misaligned). The
    reassembly queue then has a gap it never fills, so the delivered-datagram
    outcome flips to TIMEOUT -- proving this tool's verdict is actually
    driven by what real bytes reach the kernel, not a canned answer. (A
    corrupted IPv4 HEADER CHECKSUM was tried first and does NOT reproduce
    here: loopback traffic carries `CHECKSUM_UNNECESSARY` in this kernel, so
    `ip_rcv` never verifies it -- measured, not assumed, and worth recording
    since it is the opposite of what the obvious mutation would suggest.)
  * `--corrupt-expect SCENARIO` runs the real, uncorrupted packets but
    compares against a deliberately wrong `expect` (flips DELIVERED to
    dropped, or fuzzes one byte of the expected payload) -- proving `--verify`
    actually reads its own answer key instead of unconditionally exiting 0.

Skip shape (unprivileged run, i.e. this file invoked WITHOUT `unshare`):
opening the raw sender socket raises `PermissionError` (`EPERM`) before a
single byte is sent. `--verify` treats that as an honest, loudly-reported
skip -- one line per scenario naming the OSError, plus a final "N run / M
skipped (no CAP_NET_RAW)" summary -- never a silent pass. Compare that count
to the same command run under `unshare` (0 skipped) for the before/after
number the fix record cites.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

LISTEN_ADDR = "127.0.0.1"
LISTEN_PORT = 52345
SRC_PORT = 51778


def ip4_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_checksum4(src: str, dst: str, udp_bytes: bytes) -> int:
    pseudo = (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack("!BBH", 0, socket.IPPROTO_UDP, len(udp_bytes))
    )
    return ip4_checksum(pseudo + udp_bytes)


def build_udp_datagram(payload: bytes) -> bytes:
    """8-byte UDP header (checksum filled in below) + payload, addressed
    loopback->loopback on the fixed src/dst ports above."""
    length = 8 + len(payload)
    header = struct.pack("!HHHH", SRC_PORT, LISTEN_PORT, length, 0)
    csum = udp_checksum4(LISTEN_ADDR, LISTEN_ADDR, header + payload)
    header = struct.pack("!HHHH", SRC_PORT, LISTEN_PORT, length, csum)
    return header + payload


def build_ipv4_fragment(ident: int, offset_bytes: int, more: bool, payload: bytes, *, corrupt_offset: bool = False) -> bytes:
    """One raw IPv4 fragment carrying `payload` at byte offset `offset_bytes`
    (must be a multiple of 8 -- IPv4's fragment-offset granularity).
    `corrupt_offset` advertises `offset_bytes + 8` instead, on purpose --
    see `--corrupt-offset` in this file's module doc comment."""
    assert offset_bytes % 8 == 0, "IPv4 fragment offsets are 8-byte units"
    wire_offset = offset_bytes + 8 if corrupt_offset else offset_bytes
    ihl = 5
    total_len = ihl * 4 + len(payload)
    flags_frag = ((1 if more else 0) << 13) | (wire_offset // 8)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,
        total_len,
        ident,
        flags_frag,
        64,
        socket.IPPROTO_UDP,
        0,
        socket.inet_aton(LISTEN_ADDR),
        socket.inet_aton(LISTEN_ADDR),
    )
    csum = ip4_checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


class Scenario:
    def __init__(self, name: str, fragments: list[tuple[int, bytes, bool]], expect_delivered: bool, expect_payload: bytes | None):
        self.name = name
        self.fragments = fragments  # (offset_bytes, payload_slice, more) in SEND order
        self.expect_delivered = expect_delivered
        self.expect_payload = expect_payload  # full UDP datagram bytes, when expect_delivered


def _zero_length_duplicate_scenario() -> Scenario:
    """The shape F13 named as highest-value: a FINAL (`more=false`) fragment
    of LENGTH ZERO, sent twice, byte-for-byte identical (same offset, same
    empty content) -- the exact-duplicate-tolerance question `ethfrag`'s
    kernel oracle already asks for non-empty fragments (the `duplicate`
    scenario in `kernel_oracle.zig`), now asked for the shape `ethfrag`'s F1
    fix specifically carves out (A21 in `A1/ethfrag.md`'s attack table: two
    `more=false` zero-length fragments at the same offset).

    MEASURED (this file, under `unshare`, reproduced across 3 fresh IPv4
    idents): unlike a non-empty duplicate, the real kernel never completes
    reassembly here AT ALL -- not even once, duplicate or not. A single,
    non-duplicated zero-length closing fragment already times out; sending
    it twice changes nothing. `ip_defrag` appears to treat a fragment with
    no payload bytes as contributing nothing towards completion, silently,
    rather than rejecting the packet outright. That is a DIFFERENT verdict
    shape than the `duplicate` scenario's kernel-tolerates-it divergence.

    Fragment order matters for what this exercises on the `ethfrag` side of
    the replay in `kernel_oracle.zig` (not for the kernel, whose reassembly
    is offset-keyed, not sequence-keyed -- reordering these three fragments
    changed nothing about the kernel's verdict, reconfirmed by capture): the
    two zero-length closers are sent BEFORE the real data, so `ethfrag`'s own
    `Reassembler` -- which after the F1 fix rejects the second zero-length
    closer as `OverlappingFragment` before `total_len` is ever satisfied by
    real bytes -- actually exercises F1's rule 2, instead of racing to an
    unrelated completion on the first closer alone.
    """
    payload = bytes(range(0x40, 0x48))
    dgram = build_udp_datagram(payload)  # 16 bytes
    assert len(dgram) == 16
    tail_offset = len(dgram)
    fragments = [
        (tail_offset, b"", False),
        (tail_offset, b"", False),  # exact duplicate of the fragment above
        (0, dgram, True),
    ]
    return Scenario("zero_length_final_duplicate", fragments, expect_delivered=False, expect_payload=None)


def _plain_two_fragment_scenario() -> Scenario:
    """Small scenario used by `--corrupt-offset`'s demonstration: nothing
    adversarial about the shape itself, just two in-order fragments, so a
    corrupted first fragment has an unambiguous effect (no second copy of
    the same bytes for the kernel to fall back on)."""
    payload = bytes(range(0x10, 0x18))
    dgram = build_udp_datagram(payload)
    half = len(dgram) // 2
    fragments = [
        (0, dgram[:half], True),
        (half, dgram[half:], False),
    ]
    # A real SOCK_DGRAM listener strips the UDP header before recvfrom()
    # returns -- only the application payload reaches the caller, unlike
    # `kernel_oracle.zig`'s frozen replay, which compares raw IP-fragment
    # payload bytes (UDP header included) at the `ethfrag.Reassembler` level.
    return Scenario("plain_two_fragment", fragments, expect_delivered=True, expect_payload=payload)


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        _zero_length_duplicate_scenario(),
        _plain_two_fragment_scenario(),
    )
}


def run_scenario(scenario: Scenario, *, ident: int, corrupt_offset_on: int | None = None) -> tuple[bool, bytes | None, Exception | None]:
    """Sends `scenario.fragments` as real IPv4 fragments and listens for a
    reassembled UDP datagram. Returns (delivered, bytes_or_None, skip_exc).
    `skip_exc` is set (and the other two are meaningless) when the raw
    sender socket could not be opened -- the honest permission-skip shape."""
    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError as exc:
        return (False, None, exc)

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((LISTEN_ADDR, LISTEN_PORT))
    listener.settimeout(1.5)

    try:
        for i, (offset, chunk, more) in enumerate(scenario.fragments):
            pkt = build_ipv4_fragment(ident, offset, more, chunk, corrupt_offset=(i == corrupt_offset_on))
            sender.sendto(pkt, (LISTEN_ADDR, 0))
        try:
            data, _addr = listener.recvfrom(4096)
            return (True, data, None)
        except socket.timeout:
            return (False, None, None)
    finally:
        sender.close()
        listener.close()


def _fresh_ident() -> int:
    # 16-bit IPv4 identification; low bits of the wall clock is enough
    # uniqueness for one capture run (the methodology note in
    # kernel_oracle.zig explains why reuse across scenarios is the trap).
    return int(time.time() * 1000) & 0xFFFF


def cmd_print(name: str) -> int:
    scenario = SCENARIOS[name]
    ident = _fresh_ident()
    delivered, data, skip = run_scenario(scenario, ident=ident)
    if skip is not None:
        print(f"SKIP {name}: {skip!r} (no CAP_NET_RAW -- run under unshare --user --map-root-user --net)", file=sys.stderr)
        return 1
    for offset, chunk, more in scenario.fragments:
        pkt = build_ipv4_fragment(ident, offset, more, chunk)
        print(pkt.hex())
    if delivered:
        print(f"DELIVERED {data.hex()}")
    else:
        print("TIMEOUT")
    return 0


def cmd_verify(*, corrupt_offset: str | None, corrupt_expect: str | None) -> int:
    ran = 0
    skipped = 0
    failed = []
    for name, scenario in SCENARIOS.items():
        ident = _fresh_ident()
        break_at = 0 if name == corrupt_offset else None
        delivered, data, skip = run_scenario(scenario, ident=ident, corrupt_offset_on=break_at)
        if skip is not None:
            skipped += 1
            print(f"SKIP {name}: {skip!r} (no CAP_NET_RAW)")
            continue
        ran += 1

        expect_delivered = scenario.expect_delivered
        expect_payload = scenario.expect_payload
        if name == corrupt_expect:
            expect_delivered = not expect_delivered
            if expect_payload is not None:
                expect_payload = bytes([expect_payload[0] ^ 0xFF]) + expect_payload[1:]

        if delivered != expect_delivered:
            failed.append(f"{name}: expected delivered={expect_delivered}, got delivered={delivered}")
            continue
        if expect_delivered and data != expect_payload:
            failed.append(f"{name}: payload mismatch, expected {expect_payload!r} got {data!r}")
            continue
        print(f"OK   {name}: delivered={delivered}" + (f" ({len(data)} bytes, byte-exact)" if delivered else ""))

    print(f"-- {ran} run, {skipped} skipped (no CAP_NET_RAW), {len(failed)} failed --")
    for line in failed:
        print("FAIL", line, file=sys.stderr)
    if skipped:
        return 1
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print", dest="print_scenario", metavar="SCENARIO", choices=sorted(SCENARIOS))
    parser.add_argument("--verify", action="store_true", help="run every scenario and check it against its recorded expectation (default if no other mode given)")
    parser.add_argument("--corrupt-offset", metavar="SCENARIO", choices=sorted(SCENARIOS), help="RED demo: shift one fragment's declared IPv4 offset by +8 bytes so the kernel never fills the gap")
    parser.add_argument("--corrupt-expect", metavar="SCENARIO", choices=sorted(SCENARIOS), help="RED demo: compare the real capture against a deliberately wrong expectation")
    args = parser.parse_args(argv)

    if args.print_scenario:
        return cmd_print(args.print_scenario)
    return cmd_verify(corrupt_offset=args.corrupt_offset, corrupt_expect=args.corrupt_expect)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
