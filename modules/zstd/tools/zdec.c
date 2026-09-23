/* SPDX-License-Identifier: MIT */
/* zdec -- differential oracle for the decoder: decompress a file with
 * libzstd the way modules/zstd does.
 *
 *   zdec <in> <out|-> [mode [reps]]
 *
 * mode 0 (default): one-shot ZSTD_decompressDCtx into a buffer of
 *   ZSTD_decompressBound(src) bytes -- the counterpart of
 *   `Decompressor.decompress` with the same capacity.
 * mode 1: streaming ZSTD_decompressStream with ZSTD_d_windowLogMax 31, fed
 *   the whole input at once, output drained through a 128 KB buffer; this
 *   is the reference for which malformed frames are refused (the one-shot
 *   decoder does not bound raw and RLE blocks by the block maximum).
 *   With the whole frame in the input and room for its content, libzstd
 *   takes its single-pass shortcut, i.e. the one-shot decoder.
 * mode 2: streaming as mode 1, but the input fed one byte per call and the
 *   output drained through a 997-byte buffer: no shortcut, every block
 *   through ZSTD_decompressContinue -- the plan `DecompressStream` tests
 *   repeat call for call.
 *
 * Prints "OK <size> <fnv1a64 of the output>" and writes the output
 * (unless <out> is "-"), or
 * prints "ERR <ZSTD_ErrorCode>" and exits 1. With reps > 0 (mode 0 only)
 * it decodes that many times and prints the best time in ns as well.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zdec zdec.c "$R/lib/libzstd.a"
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "zstd.h"
#include "zstd_errors.h"

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static unsigned long long fnv1a64(const char* p, size_t n)
{
    unsigned long long h = 0xcbf29ce484222325ull;
    size_t i;
    for (i = 0; i < n; i++) { h ^= (unsigned char)p[i]; h *= 0x100000001b3ull; }
    return h;
}

static int fail(size_t r)
{
    printf("ERR %d\n", (int)ZSTD_getErrorCode(r));
    return 1;
}

int main(int argc, char** argv)
{
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: zdec <in> <out|-> [mode [reps]]\n");
        return 2;
    }
    int const mode = argc >= 4 ? atoi(argv[3]) : 0;
    int const reps = argc == 5 ? atoi(argv[4]) : 0;

    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 3; }
    fseek(f, 0, SEEK_END);
    long const n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* const src = malloc(n ? (size_t)n : 1);
    if (n && fread(src, 1, (size_t)n, f) != (size_t)n) { perror("read"); return 4; }
    fclose(f);

    char* out = NULL;
    size_t outSize = 0;
    ZSTD_DCtx* const dctx = ZSTD_createDCtx();
    if (mode == 0) {
        unsigned long long const bound = ZSTD_decompressBound(src, (size_t)n);
        if (bound == ZSTD_CONTENTSIZE_ERROR) { printf("ERR bound\n"); return 1; }
        size_t const cap = bound > (1ull << 32) ? (size_t)(1ull << 32) : (size_t)bound;
        out = malloc(cap ? cap : 1);
        unsigned long long best = ~0ull;
        int i;
        for (i = 0; i < (reps > 0 ? reps : 1); i++) {
            unsigned long long const t0 = now_ns();
            size_t const r = ZSTD_decompressDCtx(dctx, out, cap, src, (size_t)n);
            unsigned long long const t = now_ns() - t0;
            if (ZSTD_isError(r)) return fail(r);
            outSize = r;
            if (t < best) best = t;
        }
        if (reps > 0) printf("NS %llu\n", best);
    } else {
        size_t const ochunk = mode == 2 ? 997 : (1 << 17);
        ZSTD_DCtx_setParameter(dctx, ZSTD_d_windowLogMax, 31);
        size_t cap = 1 << 20;
        out = malloc(cap);
        char buf[1 << 17];
        ZSTD_inBuffer in = { src, mode == 2 ? (n > 0 ? 1 : 0) : (size_t)n, 0 };
        size_t r = 1;
        for (;;) {
            ZSTD_outBuffer o = { buf, ochunk, 0 };
            r = ZSTD_decompressStream(dctx, &o, &in);
            if (ZSTD_isError(r)) return fail(r);
            if (outSize + o.pos > cap) {
                while (outSize + o.pos > cap) cap *= 2;
                out = realloc(out, cap);
            }
            memcpy(out + outSize, buf, o.pos);
            outSize += o.pos;
            if (mode == 2 && in.pos == in.size && in.size < (size_t)n) { in.size++; continue; }
            if (in.pos == in.size && o.pos < o.size) break;
        }
        /* input ended inside a frame */
        if (r != 0) { printf("ERR truncated\n"); return 1; }
    }

    printf("OK %zu %016llx\n", outSize, fnv1a64(out, outSize));
    if (strcmp(argv[2], "-") != 0) {
        f = fopen(argv[2], "wb");
        if (!f) { perror(argv[2]); return 6; }
        fwrite(out, 1, outSize, f);
        fclose(f);
    }
    ZSTD_freeDCtx(dctx);
    free(src);
    free(out);
    return 0;
}
