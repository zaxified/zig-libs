#!/usr/bin/env bash
# Regenerate modules/zstd/src/testdata/entropy_kats.zig: libzstd 1.5.7's
# entropy-table builders on fixed counts (`zentropy.c`), which
# `src/entropy_kat_test.zig` pins against fse.zig and huf.zig.
#
# The counts were chosen (encoder mutation audit, 2026-11-19) to reach what
# the byte-parity goldens never do: every branch of FSE_normalizeM2, zero
# runs of 24 and more in FSE_writeNCount, the least room FSE_writeNCount and
# HUF_writeCTable accept, and histograms where HUF_optimalTableLog's
# optimal-depth search stops on a size that grew before a smaller one. The
# reason for each request is the text after its tab.
#
# Needs: git, a C compiler, python3. Writes only the KAT file; the checkout
# goes to $ZSTD_REF (default .zig-cache/zstd-ref under the repository root),
# as for gen-goldens.sh.
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
cc -O2 -DZSTD_DISABLE_ASM -I "$R/lib" -I "$R/lib/common" -o "$R/zentropy" "$here/zentropy.c" \
    $R/lib/common/*.c $R/lib/compress/*.c $R/lib/decompress/*.c

req="$R/entropy-req.txt"
cat > "$req" <<'EOF'
norm 6 0 28 1 3 425 2 3 384 0 1 534 380 1 2 3 2 1 1 553 562 0 3 2 3 6 3 1 3 0 493 584	m2-lowthr, m2-general
norm 8 0 52 498 0 1 302 1 763 729 1 2 3 453 241 892 2 0 2 3 108 100 949 0 3 1 3 2 1 2 0 3 0 1 2 1 3 2 3 0 0 667 3 0 3 1 36 2 2 0 3 1 1 1 410 2	m2-lowone
norm 6 0 28 1 1184 3 2 1 3 1126 3 3 188 2 2 1 96 2 430 3 3 1 2 0 1 3 3 3 978 3 1 1	m2-relow, m2-relow-assign
norm 5 0 28 1 0 1 1 1 0 1 0 1 1 1 1 1 1 0 1 1 1 1 1 0 1 0 1 1 1 0 1 1	m2-total0
norm 5 0 21 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1	m2-alldist (only all-1 counts reach it)
norm 6 0 43 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1	m2-alldist at table log 6
norm 7 0 52 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 30	a run of 24 zeros
norm 7 0 52 100 5 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 40 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1	a run of 25 zeros
norm 8 1 52 3000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 900 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 40	low-probability counts, runs of 25 zeros
norm 8 0 52 7 0 40 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9 0 0 1	a run of 46 zeros
norm 7 0 35 60 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 1	a run of 29 zeros
norm 6 0 31 50 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 0 0 2 0 0 1	a run of 23 zeros
norm 9 1 52 1 8 15 22 6 13 20 4 11 18 2 9 16 23 7 14 21 5 12 19 3 10 17 1 8 15 22 6 13 20 4 11 18 2 9 16 23 7 14 21 5 12 19 3 10 17 1 8 15 22 6 13 20	every symbol, low-probability ones
norm 8 0 35 0 13 26 39 12 0 38 11 24 37 0 23 36 9 22 0 8 21 34 7 0 33 6 19 32 0 18 31 4 17 0 3 16 29 2 1	short zero runs
norm 6 0 28 500 0 0 200 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 1	two symbols near the low threshold
huf 11 1 47 16 64 0 512 1 128 0 0 0 256 128 1 32 4 4 512 16 0 0 512 32 4 64 256 1 2 256 128 0 2048 0 0 0 512 64 2 0 1024 256 1 0 0 0 128 0 1024 0 8	optimal depth: the size grows by more than 1, then shrinks
huf 11 1 38 32 1 1024 2048 256 0 8 128 128 0 64 2 8 8 2 2048 256 8 64 0 0 256 16 0 1 128 1024 128 512 512 8 0 512 1024 32 1024 1024 0 1	optimal depth: the size grows by more than 1, then shrinks
huf 11 1 40 0 512 8 2048 4 16 16 2 32 1024 256 2 0 2048 16 512 2048 128 2 512 128 128 4 64 32 512 1 32 1024 2 512 0 2 256 2048 2 4 0 64 2 8	optimal depth: the size grows by more than 1, then shrinks
huf 11 0 47 16 64 0 512 1 128 0 0 0 256 128 1 32 4 4 512 16 0 0 512 32 4 64 256 1 2 256 128 0 2048 0 0 0 512 64 2 0 1024 256 1 0 0 0 128 0 1024 0 8	the same counts without the depth search
huf 11 0 38 32 1 1024 2048 256 0 8 128 128 0 64 2 8 8 2 2048 256 8 64 0 0 256 16 0 1 128 1024 128 512 512 8 0 512 1024 32 1024 1024 0 1	the same counts without the depth search
huf 11 0 40 0 512 8 2048 4 16 16 2 32 1024 256 2 0 2048 16 512 2048 128 2 512 128 128 4 64 32 512 1 32 1024 2 512 0 2 256 2048 2 4 0 64 2 8	the same counts without the depth search
huf 11 0 3 8 4 2 2	every weight distinct: raw weights
huf 11 0 4 16 8 4 2 2	two equal weights among distinct ones
huf 11 1 255 1 38 75 112 149 186 223 9 46 83 120 157 194 231 17 54 91 128 165 202 239 25 62 99 136 173 210 247 33 70 107 144 181 218 4 41 78 115 152 189 226 12 49 86 123 160 197 234 20 57 94 131 168 205 242 28 65 102 139 176 213 250 36 73 110 147 184 221 7 44 81 118 155 192 229 15 52 89 126 163 200 237 23 60 97 134 171 208 245 31 68 105 142 179 216 2 39 76 113 150 187 224 10 47 84 121 158 195 232 18 55 92 129 166 203 240 26 63 100 137 174 211 248 34 71 108 145 182 219 5 42 79 116 153 190 227 13 50 87 124 161 198 235 21 58 95 132 169 206 243 29 66 103 140 177 214 251 37 74 111 148 185 222 8 45 82 119 156 193 230 16 53 90 127 164 201 238 24 61 98 135 172 209 246 32 69 106 143 180 217 3 40 77 114 151 188 225 11 48 85 122 159 196 233 19 56 93 130 167 204 241 27 64 101 138 175 212 249 35 72 109 146 183 220 6 43 80 117 154 191 228 14 51 88 125 162 199 236 22 59 96 133 170 207 244 30 67 104 141 178 215 1 38 75 112 149	a full alphabet
huf 6 0 9 1 1 1 1 1 1 1 1 1 300	a log capped below the tree height
EOF
cut -f1 "$req" | "$R/zentropy" > "$R/entropy-ans.txt"

python3 - "$req" "$R/entropy-ans.txt" "$mod/src/testdata/entropy_kats.zig" "$pin" <<'PY'
import sys
req = [l.rstrip('\n').split('\t') for l in open(sys.argv[1])]
ans = [l.split() for l in open(sys.argv[2])]
assert len(req) == len(ans), (len(req), len(ans))
norm, huf = [], []
def esc(h):
    return "".join("\\x" + h[k:k + 2] for k in range(0, len(h), 2))
for (r, why), a in zip(req, ans):
    p = r.split()
    ms = int(p[3])
    counts = ', '.join(p[4:])
    assert len(p[4:]) == ms + 1
    if p[0] == 'norm':
        assert a[0] == 'norm' and a[1] != 'err', r
        i = a.index('nc')
        assert a[i + 3] == 'full', r
        norm.append(f'    .{{ .why = "{why}", .table_log = {p[1]}, .low_prob = {"true" if p[2] == "1" else "false"}, .counts = &.{{ {counts} }}, .norm_log = {a[1]}, .norm = &.{{ {", ".join(a[2:i])} }}, .least = {a[i + 1]}, .header = "{esc(a[i + 2])}", .full = "{esc(a[i + 4])}" }},')
    else:
        assert a[0] == 'huf' and a[2] != 'err', r
        i = a.index('wt')
        assert a[i + 3] == 'full', r
        huf.append(f'    .{{ .why = "{why}", .max_log = {p[1]}, .depth = {"true" if p[2] == "1" else "false"}, .counts = &.{{ {counts} }}, .opt_log = {a[1]}, .built_log = {a[2]}, .least = {a[i + 1]}, .header = "{esc(a[i + 2])}", .full = "{esc(a[i + 4])}" }},')
with open(sys.argv[3], 'w') as o:
    o.write(f'''// SPDX-License-Identifier: MIT
//! GENERATED by modules/zstd/tools/gen-entropy-kats.sh -- do not edit.
//! libzstd v1.5.7 ({sys.argv[4]}), `zentropy` on fixed counts:
//! FSE_normalizeCount at `table_log` (useLowProbCount `low_prob`) gives
//! `norm` at `norm_log`; FSE_writeNCount of it fails below `least` bytes
//! of room and writes `header` there, `full` with ample room.
//! HUF_optimalTableLog (with the optimal-depth search when `depth`) gives
//! `opt_log`; HUF_buildCTable at it `built_log`; HUF_writeCTable fails
//! below `least`, writes `header` there and `full` with ample room.

pub const NormKat = struct {{ why: []const u8, table_log: u32, low_prob: bool, counts: []const u32, norm_log: u32, norm: []const i16, least: usize, header: []const u8, full: []const u8 }};
pub const HufKat = struct {{ why: []const u8, max_log: u32, depth: bool, counts: []const u32, opt_log: u32, built_log: u32, least: usize, header: []const u8, full: []const u8 }};

pub const norm_kats = [_]NormKat{{
''')
    o.write('\n'.join(norm) + '\n};\n\npub const huf_kats = [_]HufKat{\n' + '\n'.join(huf) + '\n};\n')
PY
echo "wrote $mod/src/testdata/entropy_kats.zig"
