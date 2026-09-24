/* SPDX-License-Identifier: MIT */
/* zdec -- differential oracle for the decoder: decompress a file with
 * libzstd the way modules/zstd does.
 *
 *   zdec <in> <out|-> [mode [reps [dict-spec ...]]]
 *
 * mode 0 (default): one-shot ZSTD_decompressDCtx into a buffer of
 *   ZSTD_decompressBound(src) bytes -- the counterpart of
 *   `Decompressor.decompress` with the same capacity. With a "legacy"
 *   dict-spec (see below), calls ZSTD_decompress_usingDict instead.
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
 * dict-spec (0 or more, mode 0/1/2 alike -- "legacy" is mode 0 only):
 *   auto:PATH     ZSTD_createDDict_advanced(dlm_byRef, dct_auto)   + refDDict
 *   raw:PATH      ZSTD_createDDict_advanced(dlm_byRef, dct_rawContent) + refDDict
 *   full:PATH     ZSTD_createDDict_advanced(dlm_byRef, dct_fullDict) + refDDict
 *   prefix:PATH   ZSTD_DCtx_refPrefix(dctx, ...) (raw content, one frame)
 *   legacy:PATH   ZSTD_decompress_usingDict(dctx, ..., buf, size) -- mode 0
 *                 only, exclusive with every other dict-spec.
 * More than one auto/raw/full/prefix spec sets ZSTD_d_refMultipleDDicts
 * before the refDDict calls (libzstd requires the parameter set first).
 *
 * Prints "OK <size> <fnv1a64 of the output>" and writes the output
 * (unless <out> is "-"), or
 * prints "ERR <ZSTD_ErrorCode>" and exits 1. With reps > 0 (mode 0 only,
 * no dict-specs) it decodes that many times and prints the best time in ns
 * as well.
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

static char* readFile(const char* path, size_t* sizeOut)
{
    FILE* f = fopen(path, "rb");
    long n;
    char* buf;
    if (!f) { perror(path); exit(3); }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(n ? (size_t)n : 1);
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("read"); exit(4); }
    fclose(f);
    *sizeOut = (size_t)n;
    return buf;
}

#define MAX_DICTS 16

int main(int argc, char** argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: zdec <in> <out|-> [mode [reps [dict-spec ...]]]\n");
        return 2;
    }
    int const mode = argc >= 4 ? atoi(argv[3]) : 0;
    int const reps = argc >= 5 ? atoi(argv[4]) : 0;

    /* parse dict-specs */
    const char* legacyPath = NULL;
    ZSTD_DDict* ddicts[MAX_DICTS];
    int nDDict = 0;
    const char* prefixPath = NULL;
    ZSTD_customMem const cmem = { NULL, NULL, NULL };

    {
        int i;
        for (i = 5; i < argc; i++) {
            const char* spec = argv[i];
            const char* colon = strchr(spec, ':');
            if (!colon) { fprintf(stderr, "bad dict-spec %s (want TYPE:PATH)\n", spec); return 2; }
            size_t typeLen = (size_t)(colon - spec);
            const char* path = colon + 1;
            size_t dsize;
            char* dbuf;
            if (strncmp(spec, "legacy", typeLen) == 0 && typeLen == 6) {
                legacyPath = path;
                continue;
            }
            if (strncmp(spec, "prefix", typeLen) == 0 && typeLen == 6) {
                prefixPath = path;
                continue;
            }
            dbuf = readFile(path, &dsize);
            {
                ZSTD_dictContentType_e ct;
                if (typeLen == 4 && strncmp(spec, "auto", 4) == 0) ct = ZSTD_dct_auto;
                else if (typeLen == 3 && strncmp(spec, "raw", 3) == 0) ct = ZSTD_dct_rawContent;
                else if (typeLen == 4 && strncmp(spec, "full", 4) == 0) ct = ZSTD_dct_fullDict;
                else { fprintf(stderr, "bad dict-spec type in %s\n", spec); return 2; }
                if (nDDict >= MAX_DICTS) { fprintf(stderr, "too many dicts\n"); return 2; }
                ddicts[nDDict] = ZSTD_createDDict_advanced(dbuf, dsize, ZSTD_dlm_byRef, ct, cmem);
                if (!ddicts[nDDict]) {
                    /* ZSTD_createDDict_advanced returns NULL with no error
                     * code of its own; the only realistic cause (a `full`
                     * dict too short or missing the magic number, or a
                     * malformed entropy section) is dictionary_corrupted. */
                    printf("ERR %d\n", (int)ZSTD_error_dictionary_corrupted);
                    return 1;
                }
                nDDict++;
            }
        }
    }
    if (legacyPath && (nDDict > 0 || prefixPath)) {
        fprintf(stderr, "legacy: is exclusive with every other dict-spec\n");
        return 2;
    }
    if (legacyPath && mode != 0) {
        fprintf(stderr, "legacy: is mode 0 only\n");
        return 2;
    }

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

    size_t legacySize = 0;
    char* legacyBuf = NULL;
    if (legacyPath) legacyBuf = readFile(legacyPath, &legacySize);

    if (nDDict > 1) {
        ZSTD_DCtx_setParameter(dctx, ZSTD_d_refMultipleDDicts, ZSTD_rmd_refMultipleDDicts);
    }
    {
        int i;
        for (i = 0; i < nDDict; i++) {
            size_t const r = ZSTD_DCtx_refDDict(dctx, ddicts[i]);
            if (ZSTD_isError(r)) return fail(r);
        }
    }
    if (prefixPath) {
        size_t psize;
        char* pbuf = readFile(prefixPath, &psize);
        size_t const r = ZSTD_DCtx_refPrefix(dctx, pbuf, psize);
        if (ZSTD_isError(r)) return fail(r);
    }

    if (mode == 0) {
        unsigned long long const bound = ZSTD_decompressBound(src, (size_t)n);
        if (bound == ZSTD_CONTENTSIZE_ERROR) {
            /* ZSTD_decompressBound has no error code of its own; recover
             * the real one the same way it failed internally. */
            size_t const probe = ZSTD_findFrameCompressedSize(src, (size_t)n);
            if (ZSTD_isError(probe)) return fail(probe);
            printf("ERR bound\n");
            return 1;
        }
        size_t const cap = bound > (1ull << 32) ? (size_t)(1ull << 32) : (size_t)bound;
        out = malloc(cap ? cap : 1);
        unsigned long long best = ~0ull;
        int i;
        for (i = 0; i < (reps > 0 ? reps : 1); i++) {
            unsigned long long const t0 = now_ns();
            size_t r;
            if (legacyPath) {
                r = ZSTD_decompress_usingDict(dctx, out, cap, src, (size_t)n, legacyBuf, legacySize);
            } else {
                r = ZSTD_decompressDCtx(dctx, out, cap, src, (size_t)n);
            }
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
        /* input ended inside a frame: same class libzstd uses for any
         * other "not enough input" case (srcSize_wrong), so print it the
         * same way `fail()` would rather than a placeholder string. */
        if (r != 0) { printf("ERR %d\n", (int)ZSTD_error_srcSize_wrong); return 1; }
    }

    printf("OK %zu %016llx\n", outSize, fnv1a64(out, outSize));
    if (strcmp(argv[2], "-") != 0) {
        f = fopen(argv[2], "wb");
        if (!f) { perror(argv[2]); return 6; }
        fwrite(out, 1, outSize, f);
        fclose(f);
    }
    ZSTD_freeDCtx(dctx);
    {
        int i;
        for (i = 0; i < nDDict; i++) ZSTD_freeDDict(ddicts[i]);
    }
    free(src);
    free(out);
    return 0;
}
