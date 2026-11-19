#!/usr/bin/env bash
# Regenerate modules/zstd/src/testdata/superblock_goldens.zig: libzstd
# v1.5.7's one-shot ZSTD_compress2 (tools/zref.c) with targetCBlockSize on
# inputs made of text (matches), noise of 64 high byte values (compressible
# literals, no match) and random bytes. With 1024-byte blocks
# (maxBlockSize=1024) the noise blocks go through ZSTD_compressSuperBlock
# with no sequence at all, which no other golden reaches (each such row's
# frame is checked here to hold a compressed block whose sequences section
# says 0); with whole 128 KiB blocks the mixes are cut into several
# sub-blocks, and a random tail is left raw. Rows without targetCBlockSize
# reach HUF_compress's sampling of literals suspected incompressible ("-")
# and the block splitter (splitAfterSequences=1). src/emut2_test.zig makes
# the same inputs and compares the frame's length and SHA-256.
#
# The layout string names 1024 bytes per letter: T text
# ("the quick brown fox jumps over the lazy dog; "[(7 * i + (i >> 3)) % 44]
# at the input offset i), N noise (0x80 | (x & 63)), R random (x & 255),
# W words (words[x & 7] followed by a space, the next word started where the
# last ended: many short matches, so compressed sequence tables), x
# stepping xorshift32 from 2463534242, one generator for the whole input,
# one step per N or R byte and per W word. A count before a letter repeats
# it ("8T" = "TTTTTTTT"; "4(TN)" = "TNTNTNTN").
#
# Needs: git, a C compiler, python3. The libzstd checkout goes to $ZSTD_REF
# (default .zig-cache/zstd-ref under the repository root), as for
# gen-goldens.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mod=$(dirname "$here")
root=$(cd "$mod/../.." && pwd)
R=${ZSTD_REF:-$root/.zig-cache/zstd-ref}
pin=f8745da6ff1ad1e7bab384bd1f9d742439278e99 # tag v1.5.7

if [ ! -d "$R/lib" ]; then
    git clone --quiet --depth 1 --branch v1.5.7 https://github.com/facebook/zstd.git "$R"
fi
got=$(git -C "$R" rev-parse HEAD)
if [ "$got" != "$pin" ]; then
    echo "libzstd checkout at $got, expected v1.5.7 ($pin)" >&2
    exit 1
fi
# shellcheck disable=SC2086
cc -O2 -DZSTD_DISABLE_ASM -I "$R/lib" -I "$R/lib/common" -o "$R/zref-sb" "$here/zref.c" \
    $R/lib/common/*.c $R/lib/compress/*.c $R/lib/decompress/*.c

work="$R/superblock"
mkdir -p "$work"
python3 -I - "$R/zref-sb" "$work" "$mod/src/testdata/superblock_goldens.zig" "$pin" <<'PY'
import hashlib, subprocess, sys
zref, work, out, pin = sys.argv[1:5]
text = b"the quick brown fox jumps over the lazy dog; "

def expand(layout):
    """"4(TN)2R" -> "TNTNTNTNRR"."""
    out, i = "", 0
    while i < len(layout):
        n = 0
        while layout[i].isdigit():
            n, i = n * 10 + int(layout[i]), i + 1
        if layout[i] == "(":
            j = layout.index(")", i)
            unit, i = layout[i + 1:j], j + 1
        else:
            unit, i = layout[i], i + 1
        out += unit * (n or 1)
    return out

words = [b"zero", b"one", b"two", b"three", b"four", b"five", b"six", b"seven"]

def make(layout):
    b = bytearray()
    x = 2463534242
    pending = b""
    def step():
        nonlocal x
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
    for kind in expand(layout):
        for _ in range(1024):
            i = len(b)
            if kind == 'T':
                b.append(text[(7 * i + (i >> 3)) % 44])
            elif kind == 'W':
                if not pending:
                    step()
                    pending = words[x & 7] + b" "
                b.append(pending[0])
                pending = pending[1:]
            else:
                step()
                b.append(0x80 | (x & 63) if kind == 'N' else x & 255)
    return bytes(b)

def literal_only_blocks(f):
    """Compressed blocks of frame `f` whose sequences section holds 0."""
    fhd = f[4]
    single = (fhd >> 5) & 1
    at = 5 + (1 - single) + [0, 1, 2, 4][fhd & 3] + [single, 2, 4, 8][fhd >> 6]
    n = 0
    while True:
        h = int.from_bytes(f[at:at + 3], 'little')
        kind, size = (h >> 1) & 3, h >> 3
        body = at + 3
        if kind == 2:
            b0 = f[body]
            lt, sf = b0 & 3, (b0 >> 2) & 3
            if lt in (0, 1):
                # RFC 8878 3.1.1.3.1.1: Size_Format 0/2 one byte (5 bits),
                # 1 two bytes (12 bits), 3 three bytes (20 bits)
                hs = {0: 1, 2: 1, 1: 2, 3: 3}[sf]
                v = int.from_bytes(f[body:body + hs], 'little')
                regen = v >> 3 if hs == 1 else v >> 4
                payload = regen if lt == 0 else 1
            else:
                hs = {0: 3, 1: 3, 2: 4, 3: 5}[sf]
                v = int.from_bytes(f[body:body + hs], 'little')
                payload = {3: (v >> 14) & 0x3FF, 4: (v >> 18) & 0x3FFF, 5: (v >> 22) & 0x3FFFF}[hs]
            if f[body + hs + payload] == 0:
                n += 1
        at = body + (1 if kind == 1 else size)
        if h & 1:
            return n

small = "targetCBlockSize=1340,maxBlockSize=1024"
whole = "targetCBlockSize=1340"
runs = [  # layout, params, levels, must hold a block without sequences
    ("TTNTT", small, (1, 3, 7), True),
    ("NTNTN", small, (1, 3, 7), True),
    ("16(TN)", whole, (1, 3, 7, 19), False),
    ("12(TN)4R", whole, (1, 3, 7, 19), False),
    ("8(TNN)", whole, (1, 7), False),
    ("24T8R", whole, (1, 7), False),
    ("128(TN)", whole, (1, 7), False),
    # compressed sequence tables, a block without sequences, then a block
    # that may repeat the tables (it must not: the dummy statistics reset
    # the repeat modes)
    ("WWNWW", small, (1, 3, 7), True),
    ("WWWNWWNW", small, (1, 7), True),
    # a literal run above 0xFFFF inside a superblock (a long length)
    ("66R8W", whole, (1, 7), False),
    # sequence tables built over 2 KiB blocks, then a block without sequences
    ("4W2N4W", "targetCBlockSize=1340,maxBlockSize=2048", (1, 7), True),
    # a raw tail of more than 8 KiB (a 3-byte block size)
    ("16T12R", whole, (1, 7), False),
    # no superblock: HUF_compress's sampling of the first and last 4 KiB
    # of literals suspected incompressible (no sequence), from 40 KiB up
    ("4R32N4R", "-", (1,), False),
    ("4R44N", "-", (1,), False),
    # no superblock: the block splitter (ZSTD_c_splitAfterSequences) over
    # a literal run above 0xFFFF, repcodes across partitions, many mixes
    ("66R8W", "splitAfterSequences=1", (1, 7), False),
    ("16(TN)", "splitAfterSequences=1", (1, 7), False),
    ("8(WNR)", "splitAfterSequences=1", (1, 7, 19), False),
    ("64(WR)", "splitAfterSequences=1", (1, 19), False),
]
rows = []
for layout, params, levels, need_lit_only in runs:
    src = make(layout)
    name = layout.replace("(", "_").replace(")", "_")
    open(f"{work}/{name}", "wb").write(src)
    for level in levels:
        dst = f"{work}/{name}.{level}.zst"
        subprocess.run([zref, str(level), "0", f"{work}/{name}", dst, "0", "0", "0", params], check=True)
        f = open(dst, "rb").read()
        lo = literal_only_blocks(f)
        assert lo > 0 or not need_lit_only, (layout, level, "no compressed block without sequences")
        rows.append(f'    .{{ .layout = "{layout}", .level = {level}, .params = "{params}", .len = {len(f)}, .literal_only_blocks = {lo}, .sha256 = "{hashlib.sha256(f).hexdigest()}" }},')
with open(out, "w") as o:
    o.write(f'''// SPDX-License-Identifier: MIT
//! GENERATED by modules/zstd/tools/gen-superblock-goldens.sh -- do not edit.
//! libzstd v1.5.7 ({pin}), `zref` (one-shot ZSTD_compress2, content size in
//! the header, no checksum) with `params` on the input `layout` names; the
//! frame's length, its compressed blocks without sequences, its SHA-256.

pub const Golden = struct {{ layout: []const u8, level: i32, params: []const u8, len: usize, literal_only_blocks: usize, sha256: *const [64]u8 }};

pub const rows = [_]Golden{{
''')
    o.write('\n'.join(rows) + '\n};\n')
print(f"wrote {out} ({len(rows)} rows)")
PY
