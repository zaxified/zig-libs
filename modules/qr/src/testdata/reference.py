# SPDX-License-Identifier: MIT
#
# Reference driver for the qr module's external-oracle golden vectors.
#
# Uses `segno` (github.com/heuer/segno; pure-Python, ISO/IEC 18004 model 2
# encoder) purely as a black-box oracle: this file was written without
# reading segno's implementation beyond the one function named below, whose
# defect made that unavoidable, and only its public `segno.make(...)` API and
# its documented `mode`/`version`/`error`/`mask` parameters otherwise. No
# segno source was ported or studied as a design reference (CONVENTIONS.md 5
# — a black-box compatibility oracle needs no NOTICE entry).
#
# What this targets: `SPEC.md`'s "Verification" section used to claim
# hundreds of matrices were compared against an independent encoder, and the
# module never actually did that -- the claim was prose with no test behind
# it. This script is what makes the claim real. It forces the SAME version,
# error-correction level and mask on both segno and our own encoder, so both
# implementations answer the identical question ("what does symbol
# (content, version, ecc, mask) look like") and their matrices can be
# compared module-for-module: any disagreement is a real defect, not a
# difference in mode/version/mask selection heuristics.
#
# Deliberately covers what the module's 29 self-consistency tests
# structurally cannot: our own round trip is blind to the module-placement
# (zigzag `Walk`) order and to the transcribed error-correction block
# structure table, because a decode that undoes the SAME wrong order or the
# SAME mistranscribed table as the encode that produced it still reports
# success. Only an independently-authored encoder that places modules and
# interleaves blocks by its own logic can catch that class.
#
# ── a real defect in the oracle itself, found and worked around ───────────
#
# `segno.encoder.write_padding_bits` computes the bit-padding-to-byte-boundary
# amount as `8 - (length % 8)` unconditionally. ISO/IEC 18004:2015 7.4.10:
# "If the bit stream length is such that it does not end at a codeword
# boundary, padding bits ... shall be added ... to extend it to the codeword
# boundary" -- i.e. when the stream is ALREADY byte-aligned after the
# terminator, zero bits should be added. segno's formula instead adds a full
# spurious 8-bit zero byte in exactly that case (confirmed in isolation:
# calling it on an already-16-bit-aligned buffer grows it to 24 bits, not
# 16). This is silent almost everywhere -- it only bites when mode-indicator
# + count-field + data bits + terminator lands exactly on a byte boundary --
# which is how it surfaced: the very first version of this script sized
# content to nearly fill capacity, and a version-5-quartile case at exactly
# that boundary disagreed with our own encoder in dozens of bytes spread
# through the whole matrix. Hand-tracing both implementations' pre-mask,
# pre-interleave data codewords (see the module CHANGELOG's 2026-08-18 entry
# for the byte-level comparison) pinned it to this one extra byte shifting
# everything after it -- and confirmed our OWN encoder was the one matching
# ISO 7.4.10, not segno. `pyzbar`/`zbar` decoded both the segno-buggy matrix
# and our own matrix for that case to the correct message anyway, because a
# lenient decoder never validates padding content -- which is exactly why a
# byte-identical golden comparison, not a decode round-trip, is what catches
# this class of bug at all.
#
# `_fixed_write_padding_bits` below is the one-line ISO-conformant version,
# monkeypatched over segno's own at import time so every case in this file
# reflects segno's real encoding logic rather than this one bug in it. This
# is generation-time tooling, not a copy of segno shipped in the repo (this
# file is not part of the `qr` module's public surface, only of how its
# golden vectors are reproduced) -- CONVENTIONS.md 5's "black-box oracle"
# framing still holds: nothing of segno's own encoding logic was read or
# reused, only this one already-public, already-diagnosed bug was routed
# around so the oracle answers the question it claims to answer.
#
# Usage (from this directory, in a venv with `pip install segno`):
#   python3 reference.py dump          -> prints one `Entry` literal per
#                                          case, ready to paste into
#                                          golden_matrices.zig
#   python3 reference.py selftest      -> sanity check, no output
#
# Captured with segno 1.6.6 (`pip show segno`) on Python 3.
# Regenerate the same way after changing CASES below -- the count canary in
# `golden_test.zig` fails loudly if the two tables drift apart.

import sys
import segno
from segno import encoder as _segno_encoder, consts as _segno_consts


def _fixed_write_padding_bits(buff, version, length):
    """ISO/IEC 18004:2015 7.4.10, correctly: pad to the next byte boundary
    only when not already on one. See the module docstring above."""
    if version not in (_segno_consts.VERSION_M1, _segno_consts.VERSION_M3):
        rem = length % 8
        if rem != 0:
            buff.extend([0] * (8 - rem))


_segno_encoder.write_padding_bits = _fixed_write_padding_bits


def numeric_content(n):
    return ("1234567890" * ((n // 10) + 1))[:n]


ALNUM_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def alnum_content(n):
    return (ALNUM_CHARSET * ((n // len(ALNUM_CHARSET)) + 1))[:n]


BYTE_TEXT = (
    "Hello, world! Zig-libs QR external oracle -- byte-mode payload with "
    "punctuation and digits: 0123456789. The quick brown fox jumps over "
    "the lazy dog."
)


def byte_content(n):
    return (BYTE_TEXT * ((n // len(BYTE_TEXT)) + 1))[:n]


def max_fit(version, ecc_char, mode, content_fn, seed_len):
    """Largest length <= seed_len that segno accepts at this (version, ecc,
    mode) without raising -- i.e. as much real (non-padding) content as the
    symbol holds, so the golden vector exercises data rather than mostly the
    fixed 0xEC/0x11 pad sequence."""
    length = seed_len
    while length > 0:
        content = content_fn(length)
        try:
            segno.make(
                content,
                error=ecc_char,
                version=version,
                mode=mode,
                mask=0,
                boost_error=False,
            )
            return length
        except Exception:
            length -= 1
    raise RuntimeError("no fitting length for %r/%r/%r" % (version, ecc_char, mode))


# ── case tables ──────────────────────────────────────────────────────────
#
# "spread": a version across the whole 1-40 range x every ECC level, mask
# forced to 0, numeric mode. Exercises the block-structure table broadly --
# a wrong entry changes the interleave and the matrix stops matching -- and
# includes version 32, the one documented exception to the alignment-centre
# spacing rule (SPEC.md "Design & invariants"), so the oracle also covers
# the special case rather than only the derived versions either side of it.
SPREAD_VERSIONS = [1, 2, 5, 7, 10, 14, 20, 27, 32, 40]

# "masks": one version/level held fixed, every one of the 8 mask patterns
# forced in turn. A masking-formula bug (e.g. two patterns' conditions
# swapped) does not change what our own decoder reads back -- unmask always
# undoes whatever mask encode applied -- so only an oracle that computes the
# mask pattern independently catches it.
MASK_VERSION = 5
MASK_ECC = "q"

# "modes": one version/level held fixed, all three implemented modes in
# turn, mask forced to 0. Exercises the mode-indicator and count-field bits
# the spread/mask sets (numeric only) do not.
MODE_VERSION = 3
MODE_ECC = "m"


def build_cases():
    cases = []
    for v in SPREAD_VERSIONS:
        # As many digits as fit at ECC H (the tightest level), reused at
        # L/M/Q too (more padding, still a real symbol) so all four levels
        # of a version share one input and only the ECC parameter changes.
        length = max_fit(v, "h", "numeric", numeric_content, 1200)
        content = numeric_content(length)
        for ecc in ("l", "m", "q", "h"):
            cases.append(
                {
                    "name": "spread_v%d_%s" % (v, ecc),
                    "version": v,
                    "ecc": ecc,
                    "mode": "numeric",
                    "mask": 0,
                    "content": content,
                }
            )
    mask_length = max_fit(MASK_VERSION, MASK_ECC, "numeric", numeric_content, 150)
    mask_content = numeric_content(mask_length)
    for mask in range(8):
        cases.append(
            {
                "name": "mask_v%d_%s_m%d" % (MASK_VERSION, MASK_ECC, mask),
                "version": MASK_VERSION,
                "ecc": MASK_ECC,
                "mode": "numeric",
                "mask": mask,
                "content": mask_content,
            }
        )
    mode_seed_lens = {"numeric": 150, "alphanumeric": 90, "byte": 60}
    mode_builders = {
        "numeric": numeric_content,
        "alphanumeric": alnum_content,
        "byte": byte_content,
    }
    for mode, seed in mode_seed_lens.items():
        length = max_fit(MODE_VERSION, MODE_ECC, mode, mode_builders[mode], seed)
        cases.append(
            {
                "name": "mode_v%d_%s_%s" % (MODE_VERSION, MODE_ECC, mode),
                "version": MODE_VERSION,
                "ecc": MODE_ECC,
                "mode": mode,
                "mask": 0,
                "content": mode_builders[mode](length),
            }
        )
    return cases


CASES = build_cases()


def make(case):
    # boost_error=False is load-bearing: segno's default silently raises the
    # ECC level when the chosen version has spare capacity at the requested
    # level (confirmed empirically -- error='l', version=1, 17 numeric digits
    # comes back as error='H' with boost_error's default of True). Forcing it
    # off is what makes "ecc" in the case table the level actually encoded,
    # matching what our own encoder is told to use.
    return segno.make(
        case["content"],
        error=case["ecc"],
        version=case["version"],
        mode=case["mode"],
        mask=case["mask"],
        boost_error=False,
    )


def pack_rows(qr):
    """Row-major, MSB-first bit packing: row 0's modules first (module 0 in
    the top bit of byte 0), then row 1, etc. Each row starts a fresh byte
    boundary so the packing is independent of the symbol's side length --
    this is a description of the module grid, not of qr's or our internal
    storage layout, so it stays meaningful even if either changes."""
    out = bytearray()
    for row in qr.matrix:
        b = 0
        n = 0
        for module in row:
            b = (b << 1) | (1 if module else 0)
            n += 1
            if n == 8:
                out.append(b)
                b = 0
                n = 0
        if n:
            out.append(b << (8 - n))
    return bytes(out)


def zig_bytes_literal(data):
    return "&.{ " + ", ".join("0x%02x" % b for b in data) + " }"


def zig_string_literal(s):
    out = []
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= code < 0x7F:
            out.append(ch)
        else:
            out.append("\\x%02x" % code)
    return '"' + "".join(out) + '"'


def dump():
    for case in CASES:
        qr = make(case)
        rows = pack_rows(qr)
        size = len(qr.matrix)
        print("    .{")
        print('        .name = "%s",' % case["name"])
        print("        .version = %d," % case["version"])
        print('        .ecc = .%s,' % {
            "l": "low", "m": "medium", "q": "quartile", "h": "high",
        }[case["ecc"]])
        print('        .mode = .%s,' % case["mode"])
        print("        .mask = %d," % case["mask"])
        print("        .size = %d," % size)
        print("        .content = %s," % zig_string_literal(case["content"]))
        print("        .bits = %s," % zig_bytes_literal(rows))
        print("    },")


ECC_NAME = {"l": "L", "m": "M", "q": "Q", "h": "H"}


def selftest():
    for case in CASES:
        qr = make(case)
        assert qr.version == case["version"], (case["name"], qr.version)
        assert qr.mask == case["mask"], (case["name"], qr.mask)
        assert qr.error == ECC_NAME[case["ecc"]], (case["name"], qr.error)
    print("selftest OK:", len(CASES), "cases")


def main(argv):
    op = argv[1] if len(argv) > 1 else "dump"
    if op == "selftest":
        selftest()
    elif op == "dump":
        dump()
    else:
        raise SystemExit("unknown op " + op)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
