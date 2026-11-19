/* SPDX-License-Identifier: MIT */
/* zroom -- libzstd 1.5.7 at every destination capacity, the reference for
 * src/room_sweep_test.zig: the bound checks of the block, buffer-less and
 * sequence-level APIs, whose least room one-shot frames never reach.
 *
 *   zroom block      <level> <kind> <len> <maxcap>
 *   zroom bufferless <level> <kind> <len> <split 0|1> <maxcap>
 *   zroom seq        <level> <checksum 0|1> <shape l|a> <k> <maxcap>
 *
 * For every capacity 0..<maxcap> one line on stdout:
 *   "<cap> ok <hex>"            the bytes the call wrote
 *   "<cap> err <name>"          a libzstd error (dstSize_tooSmall, or
 *                               "code <n> <message>" for any other)
 *   "<cap> below-header"        seq only, below ZSTD_FRAMEHEADERSIZE_MAX
 *                               (18): libzstd is not called there, see
 *                               below; the module answers DstSizeTooSmall
 *
 * block       ZSTD_compressBegin(level), then ZSTD_compressBlock of the input
 *             into <cap> bytes (0 written: not compressible).
 * bufferless  ZSTD_compressBegin(level); with <split> 1 the first half of
 *             the input through ZSTD_compressContinue into ample room
 *             (hex of it first, then a space), then ZSTD_compressEnd of the
 *             rest into <cap> bytes.
 * seq         ZSTD_compressSequences with explicit block delimiters at
 *             <level>, the checksum as given. Shape l: <k> bytes of the text
 *             kind as one literal run; shape a: "abcd" repeated, 4 * k + 4
 *             bytes, k matches of 4 at offset 4 after one run of 4 literals.
 *
 * Inputs are made here, not read: <kind> z (zeros), t (text: byte
 * "the quick brown fox jumps over the lazy dog; "[(7 * i + (i >> 3)) % 44]),
 * r (xorshift32 from 2463534242 + len, the low byte of each step). The test
 * makes the same bytes.
 *
 * Build against the pinned libzstd checkout (gen-goldens.sh does):
 *   cc -O2 -DZSTD_DISABLE_ASM -I "$R/lib" -I "$R/lib/common" -o zroom zroom.c \
 *      $R/lib/common/*.c $R/lib/compress/*.c $R/lib/decompress/*.c
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#define ZSTD_DISABLE_DEPRECATE_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"
#include "zstd_errors.h"

static const char text[] = "the quick brown fox jumps over the lazy dog; ";

static void make(unsigned char* buf, size_t len, char kind)
{
    unsigned x = 2463534242u + (unsigned)len;
    for (size_t i = 0; i < len; i++) {
        switch (kind) {
        case 'z': buf[i] = 0; break;
        case 't': buf[i] = (unsigned char)text[(7 * i + (i >> 3)) % 44]; break;
        case 'r':
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            buf[i] = (unsigned char)x;
            break;
        default: fprintf(stderr, "kind %c?\n", kind); exit(2);
        }
    }
}

static void hex(const unsigned char* p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

/* 1 when r is an error (the line is finished) */
static int err(size_t cap, size_t r)
{
    if (!ZSTD_isError(r)) return 0;
    if (ZSTD_getErrorCode(r) == ZSTD_error_dstSize_tooSmall) printf("%zu err dstSize_tooSmall\n", cap);
    else printf("%zu err code %d %s\n", cap, (int)ZSTD_getErrorCode(r), ZSTD_getErrorName(r));
    return 1;
}

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: see the head of zroom.c\n"); return 2; }
    const char* mode = argv[1];
    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    if (!strcmp(mode, "block") && argc == 6) {
        int const level = atoi(argv[2]);
        size_t const len = strtoull(argv[4], 0, 10), maxcap = strtoull(argv[5], 0, 10);
        unsigned char* const src = malloc(len + 1);
        unsigned char* const dst = malloc(maxcap + 1);
        make(src, len, argv[3][0]);
        for (size_t cap = 0; cap <= maxcap; cap++) {
            if (err(cap, ZSTD_compressBegin(cctx, level))) continue;
            size_t const r = ZSTD_compressBlock(cctx, dst, cap, src, len);
            if (err(cap, r)) continue;
            printf("%zu ok ", cap); hex(dst, r); printf("\n");
        }
        return 0;
    }
    if (!strcmp(mode, "bufferless") && argc == 7) {
        int const level = atoi(argv[2]);
        size_t const len = strtoull(argv[4], 0, 10), maxcap = strtoull(argv[6], 0, 10);
        int const split = atoi(argv[5]);
        size_t const half = split ? len / 2 : 0;
        size_t const big = ZSTD_compressBound(len) + 64;
        unsigned char* const src = malloc(len + 1);
        unsigned char* const head = malloc(big);
        unsigned char* const dst = malloc(maxcap + 1);
        make(src, len, argv[3][0]);
        for (size_t cap = 0; cap <= maxcap; cap++) {
            size_t h = 0;
            if (err(cap, ZSTD_compressBegin(cctx, level))) continue;
            if (split) {
                h = ZSTD_compressContinue(cctx, head, big, src, half);
                if (err(cap, h)) continue;
            }
            size_t const r = ZSTD_compressEnd(cctx, dst, cap, src + half, len - half);
            if (err(cap, r)) continue;
            printf("%zu ok ", cap); hex(head, h); printf(" "); hex(dst, r); printf("\n");
        }
        return 0;
    }
    if (!strcmp(mode, "seq") && argc == 7) {
        int const level = atoi(argv[2]), ck = atoi(argv[3]);
        char const shape = argv[4][0];
        size_t const k = strtoull(argv[5], 0, 10), maxcap = strtoull(argv[6], 0, 10);
        size_t const len = shape == 'l' ? k : 4 * k + 4;
        unsigned char* const src = malloc(len + 1);
        unsigned char* const dst = malloc(maxcap + 1);
        ZSTD_Sequence* const seqs = calloc(k + 2, sizeof(ZSTD_Sequence));
        size_t ns;
        if (shape == 'l') {
            make(src, len, 't');
            seqs[0].litLength = (unsigned)len;
            ns = 1;
        } else {
            for (size_t i = 0; i < len; i++) src[i] = (unsigned char)"abcd"[i % 4];
            for (size_t i = 0; i < k; i++) {
                seqs[i].offset = 4;
                seqs[i].litLength = i == 0 ? 4 : 0;
                seqs[i].matchLength = 4;
            }
            seqs[k].litLength = k == 0 ? 4 : 0;
            ns = k + 1;
        }
        for (size_t cap = 0; cap <= maxcap; cap++) {
            /* Below the largest frame header, ZSTD_compressSequences does
             * not check ZSTD_writeFrameHeader's error and goes on at a wild
             * position: not called (the module refuses the room). */
            if (cap < ZSTD_FRAMEHEADERSIZE_MAX) { printf("%zu below-header\n", cap); continue; }
            ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, ck);
            ZSTD_CCtx_setParameter(cctx, ZSTD_c_blockDelimiters, ZSTD_sf_explicitBlockDelimiters);
            size_t const r = ZSTD_compressSequences(cctx, dst, cap, seqs, ns, src, len);
            if (err(cap, r)) continue;
            printf("%zu ok ", cap); hex(dst, r); printf("\n");
        }
        return 0;
    }
    fprintf(stderr, "usage: see the head of zroom.c\n");
    return 2;
}
