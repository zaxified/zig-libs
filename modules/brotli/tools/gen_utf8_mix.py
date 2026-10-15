#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/testdata/utf8-mix`: made-up words in several scripts whose
UTF-8 lead bytes span 0xC3..0xDC (Latin-1 supplement, Greek, Cyrillic,
Armenian, Hebrew, Arabic, Syriac), in sentences. google/brotli compresses such
text with the UTF8 literal context mode from quality 5 up, and in that mode a
lead byte two positions back (`p2`) selects the context — the bytes
0xD0..0xDF were classed wrongly by this module's table until 2026-10-15, and
no committed input had them (`interop_corpus.zig`, `ref_streams`).

Deterministic: a fixed seed; the words are random letters, not text from any
source.

    python3 modules/brotli/tools/gen_utf8_mix.py > modules/brotli/src/testdata/utf8-mix
"""
import random
import sys

SCRIPTS = [
    (0x00E0, 0x00FE),  # Latin-1 letters (lead 0xC3)
    (0x03B1, 0x03C9),  # Greek (0xCE, 0xCF)
    (0x0430, 0x044F),  # Cyrillic (0xD0, 0xD1)
    (0x0561, 0x0586),  # Armenian (0xD5, 0xD6)
    (0x05D0, 0x05EA),  # Hebrew (0xD7)
    (0x0627, 0x064A),  # Arabic (0xD8, 0xD9)
    (0x0710, 0x072F),  # Syriac (0xDC)
]


def main() -> None:
    rng = random.Random(0x6272)
    vocab = []
    for lo, hi in SCRIPTS:
        for _ in range(60):
            n = rng.randint(2, 9)
            vocab.append("".join(chr(rng.randint(lo, hi)) for _ in range(n)))
    # Zipf-like word frequencies, so the text repeats as text does.
    weights = [1.0 / (i + 1) for i in range(len(vocab))]
    rng.shuffle(vocab)
    out = []
    size = 0
    while size < 40000:
        words = rng.choices(vocab, weights, k=rng.randint(4, 14))
        s = " ".join(words).capitalize() + rng.choice([". ", ", ", "! ", "? ", ".\n"])
        out.append(s)
        size += len(s.encode())
    sys.stdout.buffer.write("".join(out).encode())


if __name__ == "__main__":
    main()
