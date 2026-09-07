#!/usr/bin/env python3
"""Candidate corpus seeds, harvested from a module's own tests.

The fuzz burn-down's expensive half is not the draw fix -- that is one line --
it is finding real frames for the corpus. Every module already has them: the
value tests beside the harness quote the frames the decoder is supposed to
accept and the truncations it is supposed to refuse, and those are exactly the
seeds a corpus wants. This prints them, deduplicated and with the line they came
from, in the `seed("...")` form `testkit.fuzz.seedHex` takes.

    ./scripts/fuzz-seed-candidates.py modules/iec61850/src/cotp.zig

It is a HARVESTER, not a generator. Its output is a shortlist to read, choose
from and comment; a corpus pasted from it unread is a corpus nobody chose, and
the burn-down has already measured what those are worth (`bacnet/service`
scored 19 of 19 "accepted" because `WhoIs.decode("")` is legal).

⚠ Frames longer than the harness's buffer are printed with a warning: a seed
longer than the buffer is not a large seed, it is the empty one -- `Smith.slice`
falls back to the range minimum. See `modules/testkit/src/fuzz.zig`.
"""
import re
import sys
from pathlib import Path

BYTE_ARRAY = re.compile(r"(?:&|=\s*)\[_\]u8\{([^{}]*)\}|:\s*\[\d+\]u8\s*=\s*\.?\{([^{}]*)\}")
HEX_CALL = re.compile(r'hex\.bytes\(\s*\d+\s*,\s*"([0-9a-fA-F]+)"')
NUM = re.compile(r"0[xX]([0-9a-fA-F]{1,2})\b|\b(\d{1,3})\b")


def literals(src: str):
    """(line, hex, provenance) for every byte-string literal in the file."""
    out = []
    for m in BYTE_ARRAY.finditer(src):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if "..." in body or "**" in body:
            continue
        vals = []
        ok = True
        for tok in (t.strip() for t in body.split(",") if t.strip()):
            n = NUM.fullmatch(tok)
            if not n:
                ok = False
                break
            v = int(n.group(1), 16) if n.group(1) else int(n.group(2))
            if v > 255:
                ok = False
                break
            vals.append(v)
        if ok and vals:
            out.append((src[:m.start()].count("\n") + 1,
                        "".join(f"{v:02X}" for v in vals), "byte array"))
    for m in HEX_CALL.finditer(src):
        out.append((src[:m.start()].count("\n") + 1,
                    m.group(1).upper(), "hex.bytes"))
    return out


def buffer_sizes(src: str):
    """The buffer each fuzz target draws into, so an over-long seed is named."""
    sizes = {}
    for m in re.finditer(r"fn (fuzz\w+)\(", src):
        tail = src[m.end():m.end() + 1200]
        b = re.search(r"var \w+: \[(\d+)\]u8", tail)
        if b:
            sizes[m.group(1)] = int(b.group(1))
    return sizes


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    p = Path(sys.argv[1])
    src = p.read_text(errors="replace")
    sizes = buffer_sizes(src)
    smallest = min(sizes.values()) if sizes else None

    seen = {}
    for line, hx, prov in literals(src):
        seen.setdefault(hx, (line, prov))
    if not seen:
        print(f"{p}: no byte literals found — the seeds have to come from the "
              f"module's encoder or from a capture")
        return 1

    print(f"# {p} — {len(seen)} distinct byte literals")
    if sizes:
        print(f"# fuzz buffers: " +
              ", ".join(f"{k}=[{v}]u8" for k, v in sorted(sizes.items())))
    print()
    for hx, (line, prov) in sorted(seen.items(), key=lambda kv: kv[1][0]):
        n = len(hx) // 2
        warn = ""
        if smallest is not None and n > smallest:
            warn = f"  ⚠ {n} octets > the [{smallest}]u8 buffer: this seed reads back EMPTY"
        print(f'    seed("{hx}"), // :{line} {prov}, {n} octets{warn}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
