#!/usr/bin/env bash
# Builds the liblzma 5.8.1 black-box driver `lzref` (tools/c_oracle/lzref.c) and
# the bench driver from the pinned XZ Utils clone. Needs: git (first run only)
# and cc. Run from the repository root.
#
#   modules/lzma/tools/build-oracle.sh        # -> .zig-cache/lzma-oracle/{lzref,lzbench}
#
# The clone is gitignored scratch under .zig-cache/survey/lzma/xz (override with
# LZMA_SRC=<dir>). The project's own build system is never run: the library
# sources are compiled directly with the macros its CMake would define.
set -euo pipefail
src="${LZMA_SRC:-.zig-cache/survey/lzma/xz}"
tag=v5.8.1
pin=a522a226545730551f7e7c2685fab27cf567746c
if [ ! -d "$src" ]; then
    mkdir -p "$(dirname "$src")"
    git clone --depth 1 --branch "$tag" https://github.com/tukaani-project/xz.git "$src"
fi
head=$(git -C "$src" rev-parse HEAD)
if [ "$head" != "$pin" ]; then echo "warning: $src is at $head, not the pinned $pin" >&2; fi
out=.zig-cache/lzma-oracle
mkdir -p "$out"
L="$src/src/liblzma"
files=$(ls "$L"/common/*.c | grep -v -e stream_encoder_mt -e stream_decoder_mt -e outqueue \
    -e hardware_cputhreads -e hardware_physmem -e string_conversion -e file_info -e lzip_decoder)
files="$files $L/check/check.c $L/check/crc32_fast.c $L/check/crc64_fast.c $L/check/sha256.c"
files="$files $L/lz/lz_encoder.c $L/lz/lz_encoder_mf.c $L/lz/lz_decoder.c"
files="$files $L/lzma/lzma_encoder.c $L/lzma/lzma_encoder_presets.c $L/lzma/lzma_encoder_optimum_fast.c"
files="$files $L/lzma/lzma_encoder_optimum_normal.c $L/lzma/lzma_decoder.c $L/lzma/lzma2_encoder.c"
files="$files $L/lzma/lzma2_decoder.c $L/lzma/fastpos_table.c $L/rangecoder/price_table.c"
defs="-DHAVE_ENCODERS -DHAVE_DECODERS -DHAVE_ENCODER_LZMA1 -DHAVE_ENCODER_LZMA2 -DHAVE_DECODER_LZMA1
 -DHAVE_DECODER_LZMA2 -DHAVE_CHECK_CRC32 -DHAVE_CHECK_CRC64 -DHAVE_CHECK_SHA256 -DHAVE_MF_HC3 -DHAVE_MF_HC4
 -DHAVE_MF_BT2 -DHAVE_MF_BT3 -DHAVE_MF_BT4 -DTUKLIB_SYMBOL_PREFIX=lzma_ -DNDEBUG -DHAVE_STDBOOL_H -DHAVE_STDINT_H -DHAVE_INTTYPES_H -DHAVE__BOOL"
inc="-I$L/api -I$L/common -I$L/check -I$L/lz -I$L/lzma -I$L/rangecoder -I$L/simple -I$L/delta -I$src/src/common"
for drv in lzref lzbench; do
    cc -O2 -w $defs $inc -o "$out/$drv" "modules/lzma/tools/c_oracle/$drv.c" $files -lpthread
done
echo "$out/lzref"
