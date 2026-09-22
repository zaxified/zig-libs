/* SPDX-License-Identifier: MIT */
/* zref -- differential oracle: compress a file with libzstd exactly the way
 * modules/zstd does (one-shot ZSTD_compress2, content size in the header).
 *
 *   zref <level> <checksum 0|1> <in> <out>
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zref zref.c "$R/lib/libzstd.a"
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#include <stdio.h>
#include <stdlib.h>
#include "zstd.h"

int main(int argc, char** argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: zref <level> <checksum 0|1> <in> <out>\n");
        return 2;
    }
    int const level = atoi(argv[1]);
    int const checksum = atoi(argv[2]);

    FILE* f = fopen(argv[3], "rb");
    if (!f) { perror(argv[3]); return 3; }
    fseek(f, 0, SEEK_END);
    long const n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* const src = malloc(n ? (size_t)n : 1);
    if (n && fread(src, 1, (size_t)n, f) != (size_t)n) { perror("read"); return 4; }
    fclose(f);

    size_t const cap = ZSTD_compressBound((size_t)n);
    char* const dst = malloc(cap);
    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, checksum);
    size_t const r = ZSTD_compress2(cctx, dst, cap, src, (size_t)n);
    if (ZSTD_isError(r)) { fprintf(stderr, "%s\n", ZSTD_getErrorName(r)); return 5; }

    f = fopen(argv[4], "wb");
    if (!f) { perror(argv[4]); return 6; }
    fwrite(dst, 1, r, f);
    fclose(f);
    ZSTD_freeCCtx(cctx);
    free(src);
    free(dst);
    return 0;
}
