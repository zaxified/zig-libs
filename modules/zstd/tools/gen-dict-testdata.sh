#!/usr/bin/env bash
# Regenerate modules/zstd/src/testdata/dict_kats.zig from libzstd v1.5.7:
# a raw-content dictionary, two small zstd-format dictionaries (different
# dictionary IDs, trained by ZDICT_trainFromBuffer on unrelated corpora so
# the mismatch and multi-dictionary tests are meaningful), one of them
# truncated inside its entropy tables (dictionary_corrupted), and a few
# frames ZSTD_compress_usingDict emits with them at a couple of levels.
#
# Needs: git, make, a C compiler, zig. Writes only dict_kats.zig; the
# libzstd checkout and everything else goes to a disposable directory
# ($ZSTD_REF, default .zig-cache/zstd-ref under the repository root, same
# as gen-goldens.sh).
#
# This is a one-off fixture, not a growing table like the main goldens: it
# exists so decoder_dict_test.zig can exercise real libzstd dictionary
# frames without needing this module's own compressor to support
# dictionaries yet (Z4). Keep it small; do not add more cases here without
# a reason -- extend goldens.zig-style tables instead if broad coverage is
# ever wanted.
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
make -C "$R/lib" -j"$(nproc)" libzstd.a >/dev/null

# gendict: trains a zstd-format dictionary from one sample per file in a
# directory (ZDICT_trainFromBuffer). zcdict: compresses one file with one
# dictionary (ZSTD_compress_usingDict). Neither ships in the repo (a few
# lines each, foreign-toolchain, CONVENTIONS.md §9); write them here.
cat >"$R/gendict.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#define ZDICT_STATIC_LINKING_ONLY
#include "zdict.h"
int main(int argc, char** argv) {
    if (argc != 4) { fprintf(stderr, "usage: gendict <samples-dir> <out-dict> <cap>\n"); return 2; }
    DIR* d = opendir(argv[1]);
    struct dirent* ent; char** names = NULL; int n = 0, capN = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (n == capN) { capN = capN ? capN * 2 : 64; names = realloc(names, capN * sizeof(char*)); }
        char path[4096]; snprintf(path, sizeof(path), "%s/%s", argv[1], ent->d_name);
        names[n++] = strdup(path);
    }
    closedir(d);
    char* buf = NULL; size_t bufCap = 0, bufLen = 0;
    size_t* sizes = malloc(n * sizeof(size_t));
    for (int i = 0; i < n; i++) {
        FILE* f = fopen(names[i], "rb"); fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        if (bufLen + sz > bufCap) { bufCap = (bufLen + sz) * 2 + 4096; buf = realloc(buf, bufCap); }
        if (sz && fread(buf + bufLen, 1, sz, f) != (size_t)sz) return 4;
        fclose(f); sizes[i] = (size_t)sz; bufLen += sz;
    }
    size_t cap = (size_t)atol(argv[3]);
    void* dictBuf = malloc(cap);
    size_t r = ZDICT_trainFromBuffer(dictBuf, cap, buf, sizes, (unsigned)n);
    if (ZDICT_isError(r)) { fprintf(stderr, "%s\n", ZDICT_getErrorName(r)); return 5; }
    FILE* of = fopen(argv[2], "wb"); fwrite(dictBuf, 1, r, of); fclose(of);
    return 0;
}
EOF
cat >"$R/zcdict.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "zstd.h"
static char* readFile(const char* path, size_t* n) {
    FILE* f = fopen(path, "rb"); fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = malloc(sz ? (size_t)sz : 1);
    if (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) exit(4);
    fclose(f); *n = (size_t)sz; return buf;
}
int main(int argc, char** argv) {
    if (argc != 5) { fprintf(stderr, "usage: zcdict <level> <in> <dict> <out.zst>\n"); return 2; }
    size_t srcSize, dictSize;
    char* src = readFile(argv[2], &srcSize);
    char* dict = readFile(argv[3], &dictSize);
    size_t const cap = ZSTD_compressBound(srcSize);
    char* dst = malloc(cap);
    ZSTD_CCtx* cctx = ZSTD_createCCtx();
    size_t const r = ZSTD_compress_usingDict(cctx, dst, cap, src, srcSize, dict, dictSize, atoi(argv[1]));
    if (ZSTD_isError(r)) { fprintf(stderr, "%s\n", ZSTD_getErrorName(r)); return 1; }
    FILE* of = fopen(argv[4], "wb"); fwrite(dst, 1, r, of); fclose(of);
    return 0;
}
EOF
cc -O2 -I "$R/lib" -o "$R/gendict" "$R/gendict.c" "$R/lib/libzstd.a"
cc -O2 -I "$R/lib" -o "$R/zcdict" "$R/zcdict.c" "$R/lib/libzstd.a"

work="$R/dict-fixtures"
rm -rf "$work"
mkdir -p "$work/samples1" "$work/samples2"
python3 - "$work" <<'PYEOF'
import random, sys
work = sys.argv[1]
words1 = ['alpha','beta','gamma','delta','epsilon','zeta','eta','theta']
words2 = ['red','green','blue','yellow','purple','orange','black','white']
random.seed(1)
for i in range(60):
    n = random.randint(10, 40)
    doc = ' '.join(random.choice(words1) for _ in range(n))
    open(f'{work}/samples1/s{i:03d}.txt', 'w').write(
        '{"event":"%s","fields":[%s]}\n' % (random.choice(words1), ', '.join('"%s"' % w for w in doc.split())))
random.seed(3)
for i in range(60):
    n = random.randint(10, 40)
    doc = ' '.join(random.choice(words2) for _ in range(n))
    open(f'{work}/samples2/s{i:03d}.txt', 'w').write(
        '{"kind":"%s","tags":[%s]}\n' % (random.choice(words2), ', '.join('"%s"' % w for w in doc.split())))
random.seed(5)
doc = ' '.join(random.choice(words1) for _ in range(30))
open(f'{work}/in1.txt', 'w').write('{"event":"beta","fields":[%s]}\n' % ', '.join('"%s"' % w for w in doc.split()))
open(f'{work}/in2.txt', 'wb').write(b'unrelated content not in the dictionary at all 12345')
open(f'{work}/raw.bin', 'wb').write(b'the quick brown fox jumps over the lazy dog repeatedly for testing dict content ')
PYEOF

"$R/gendict" "$work/samples1" "$work/full.bin" 512
"$R/gendict" "$work/samples2" "$work/full2.bin" 512
head -c 40 "$work/full.bin" >"$work/full_corrupt.bin"

"$R/zcdict" 3 "$work/in1.txt" "$work/full.bin" "$work/frame_full_l3.zst"
"$R/zcdict" 19 "$work/in1.txt" "$work/full.bin" "$work/frame_full_l19.zst"
"$R/zcdict" 3 "$work/in1.txt" "$work/raw.bin" "$work/frame_raw_l3.zst"
"$R/zcdict" 5 "$work/in2.txt" "$work/raw.bin" "$work/frame_raw_l5.zst"

out="$mod/src/testdata/dict_kats.zig"
python3 - "$work" "$out" "$pin" <<'PYEOF'
import json, sys
work, out, pin = sys.argv[1], sys.argv[2], sys.argv[3]

def zig_bytes(data):
    return '&.{' + ','.join('0x%02x' % b for b in data) + '}'

def rd(name):
    with open(f'{work}/{name}', 'rb') as f:
        return f.read()

lines = []
lines.append('// SPDX-License-Identifier: MIT')
lines.append(f'// Generated for Z2c (2026-09-24) by tools/gen-dict-testdata.sh from libzstd')
lines.append(f'// 1.5.7 ({pin}): a raw-content dictionary,')
lines.append('// a zstd-format one trained by ZDICT_trainFromBuffer (two, with different')
lines.append('// dictionary IDs, for the mismatch and multi-dictionary cases), and frames')
lines.append('// ZSTD_compress_usingDict emits with each. full_dict_corrupt is full_dict')
lines.append('// truncated inside its entropy tables (dictionary_corrupted).')
lines.append('')
lines.append('pub const raw_dict: []const u8 = %s;' % zig_bytes(rd('raw.bin')))
lines.append('pub const full_dict: []const u8 = %s;' % zig_bytes(rd('full.bin')))
lines.append('pub const full_dict2: []const u8 = %s;' % zig_bytes(rd('full2.bin')))
lines.append('pub const full_dict_corrupt: []const u8 = %s;' % zig_bytes(rd('full_corrupt.bin')))
lines.append('')
with open(f'{work}/in1.txt') as f:
    in1 = f.read()
with open(f'{work}/in2.txt') as f:
    in2 = f.read()
lines.append('pub const in1_content = %s;' % json.dumps(in1))
lines.append('pub const in2_content = %s;' % json.dumps(in2))
lines.append('')
lines.append('/// ZSTD_compress_usingDict(in1_content, full_dict, level=3).')
lines.append('pub const frame_full_l3: []const u8 = %s;' % zig_bytes(rd('frame_full_l3.zst')))
lines.append('/// Same content and dictionary, level 19.')
lines.append('pub const frame_full_l19: []const u8 = %s;' % zig_bytes(rd('frame_full_l19.zst')))
lines.append('/// ZSTD_compress_usingDict(in1_content, raw_dict, level=3).')
lines.append('pub const frame_raw_l3: []const u8 = %s;' % zig_bytes(rd('frame_raw_l3.zst')))
lines.append('/// ZSTD_compress_usingDict(in2_content, raw_dict, level=5).')
lines.append('pub const frame_raw_l5: []const u8 = %s;' % zig_bytes(rd('frame_raw_l5.zst')))
lines.append('')
with open(out, 'w') as f:
    f.write('\n'.join(lines) + '\n')
print(f"wrote {out}")
PYEOF

zig fmt "$mod/src/testdata/dict_kats.zig"
