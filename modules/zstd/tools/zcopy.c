/* SPDX-License-Identifier: MIT */
/* zcopy -- libzstd's buffer-less compression (ZSTD_compressBegin*,
 * ZSTD_compressContinue, ZSTD_compressEnd) and ZSTD_copyCCtx, the reference
 * for `Compressor.begin` / `compressContinue` / `compressEnd` / `copyFrom`.
 *
 *   zcopy <input> <dict|-> <mode> <level> <pledged|-> <copy pledged|-> \
 *         <chunks> <flags> <out prefix> [<capacity>|- [<cparams>]]
 *
 * <mode>  L  ZSTD_compressBegin_usingDict (ZSTD_compressBegin without a
 *            dictionary); <pledged> is ignored (unknown)
 *         A  ZSTD_compressBegin_advanced with ZSTD_getCParams(level,
 *            pledged or 0, dict size) and the frame parameters of <flags>
 *         C  ZSTD_compressBegin_usingCDict_advanced, the CDict made by
 *            ZSTD_createCDict(dict, level), frame parameters of <flags>
 *         c  ZSTD_compressBegin_usingCDict (no frame parameters, unknown size)
 * <flags> bit 0 checksum, bit 1 no dictionary ID, bit 2 no content size
 *         (A and C only)
 * <cparams> (A only) "wlog,clog,hlog,slog,minmatch,tlen,strategy" in place
 *         of ZSTD_getCParams' -- e.g. a 2^27 window over small tables, which
 *         switches long-distance matching on without a gigabyte of tables
 *
 * One context ("src") is begun as <mode> says. A second one ("dst") is then
 * made its copy with <copy pledged> (ZSTD_copyCCtx; "-" is
 * ZSTD_CONTENTSIZE_UNKNOWN) and compresses the input, cut into <chunks>
 * equal pieces of one buffer (ZSTD_compressContinue for all but the last,
 * ZSTD_compressEnd for the last): <out>.copy1. The same dst is made a copy
 * again and compresses the input again: <out>.copy2 (a reused copy). Then src
 * itself compresses it: <out>.orig. Every call gets the room left of a
 * buffer of <capacity> bytes (default ZSTD_compressBound + 18); a call that
 * fails prints "<frame> error <name>" and that frame's file is not written.
 * With <copy pledged> "none", no copy is made (only <out>.orig).
 *
 * Build against the pinned libzstd checkout (as gen-goldens.sh builds zref):
 *   cc -O2 -DZSTD_DISABLE_ASM -I "$R/lib" -I "$R/lib/common" -o zcopy zcopy.c \
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

static char* slurp(const char* path, size_t* n)
{
    FILE* f = fopen(path, "rb");
    char* buf;
    long len;
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(len > 0 ? (size_t)len : 1);
    if (len > 0 && fread(buf, 1, (size_t)len, f) != (size_t)len) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)len;
    return buf;
}

static void spill(const char* prefix, const char* ext, const char* p, size_t n)
{
    char path[4096];
    FILE* f;
    snprintf(path, sizeof path, "%s.%s", prefix, ext);
    f = fopen(path, "wb");
    if (!f || fwrite(p, 1, n, f) != n) { perror(path); exit(2); }
    fclose(f);
}

static void check(size_t r, const char* what)
{
    if (ZSTD_isError(r)) {
        fprintf(stderr, "%s: %s\n", what, ZSTD_getErrorName(r));
        exit(2);
    }
}

/* The input in `chunks` pieces through `c`; 0 and a message on error. */
static size_t run(ZSTD_CCtx* c, const char* name, char* dst, size_t cap, const char* src, size_t n, unsigned chunks)
{
    size_t op = 0, ip = 0;
    unsigned i;
    for (i = 0; i < chunks; i++) {
        size_t const piece = i + 1 == chunks ? n - ip : n / chunks;
        size_t const r = i + 1 == chunks ? ZSTD_compressEnd(c, dst + op, cap - op, src + ip, piece)
                                         : ZSTD_compressContinue(c, dst + op, cap - op, src + ip, piece);
        if (ZSTD_isError(r)) {
            printf("%s error %s\n", name, ZSTD_getErrorName(r));
            return 0;
        }
        op += r;
        ip += piece;
    }
    return op;
}

int main(int argc, char** argv)
{
    size_t n, dict_len = 0, cap, out_len;
    char *src, *dict = NULL, *dst;
    char mode;
    int level;
    unsigned long long pledged, copy_pledged = ZSTD_CONTENTSIZE_UNKNOWN;
    unsigned chunks, flags;
    int copy;
    ZSTD_CCtx *s, *d;
    ZSTD_CDict* cdict = NULL;
    ZSTD_frameParameters fp;
    if (argc < 10) {
        fprintf(stderr, "usage: zcopy <input> <dict|-> <L|A|C|c> <level> <pledged|-> <copy pledged|-|none> <chunks> <flags> <out prefix> [<capacity>|- [<cparams>]]\n");
        return 2;
    }
    src = slurp(argv[1], &n);
    if (strcmp(argv[2], "-") != 0) dict = slurp(argv[2], &dict_len);
    mode = argv[3][0];
    level = atoi(argv[4]);
    pledged = strcmp(argv[5], "-") == 0 ? ZSTD_CONTENTSIZE_UNKNOWN : strtoull(argv[5], NULL, 10);
    copy = strcmp(argv[6], "none") != 0;
    if (copy && strcmp(argv[6], "-") != 0) copy_pledged = strtoull(argv[6], NULL, 10);
    chunks = (unsigned)atoi(argv[7]);
    if (chunks == 0) chunks = 1;
    flags = (unsigned)atoi(argv[8]);
    cap = argc > 10 && strcmp(argv[10], "-") != 0 ? strtoull(argv[10], NULL, 10) : ZSTD_compressBound(n) + 18;
    dst = malloc(cap ? cap : 1);
    fp.contentSizeFlag = !(flags & 4);
    fp.checksumFlag = flags & 1;
    fp.noDictIDFlag = (flags >> 1) & 1;

    s = ZSTD_createCCtx();
    d = ZSTD_createCCtx();
    if (mode == 'C' || mode == 'c') cdict = ZSTD_createCDict(dict, dict_len, level);
    switch (mode) {
    case 'L':
        check(ZSTD_compressBegin_usingDict(s, dict, dict_len, level), "begin");
        break;
    case 'A': {
        ZSTD_parameters p;
        p.cParams = ZSTD_getCParams(level, pledged == ZSTD_CONTENTSIZE_UNKNOWN ? 0 : pledged, dict_len);
        if (argc > 11) {
            unsigned v[7];
            if (sscanf(argv[11], "%u,%u,%u,%u,%u,%u,%u", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]) != 7) {
                fprintf(stderr, "bad cparams\n");
                return 2;
            }
            p.cParams.windowLog = v[0];
            p.cParams.chainLog = v[1];
            p.cParams.hashLog = v[2];
            p.cParams.searchLog = v[3];
            p.cParams.minMatch = v[4];
            p.cParams.targetLength = v[5];
            p.cParams.strategy = (ZSTD_strategy)v[6];
        }
        p.fParams = fp;
        check(ZSTD_compressBegin_advanced(s, dict, dict_len, p, pledged), "begin");
        break;
    }
    case 'C':
        check(ZSTD_compressBegin_usingCDict_advanced(s, cdict, fp, pledged), "begin");
        break;
    case 'c':
        check(ZSTD_compressBegin_usingCDict(s, cdict), "begin");
        break;
    default:
        fprintf(stderr, "bad mode\n");
        return 2;
    }
    if (copy) {
        int k;
        for (k = 1; k <= 2; k++) {
            char name[8];
            size_t r = ZSTD_copyCCtx(d, s, copy_pledged);
            snprintf(name, sizeof name, "copy%d", k);
            if (ZSTD_isError(r)) {
                printf("%s error %s\n", name, ZSTD_getErrorName(r));
                continue;
            }
            out_len = run(d, name, dst, cap, src, n, chunks);
            if (out_len) spill(argv[9], name, dst, out_len);
        }
    }
    out_len = run(s, "orig", dst, cap, src, n, chunks);
    if (out_len) spill(argv[9], "orig", dst, out_len);
    /* a copy of a context no longer in the init stage */
    if (copy) {
        size_t const r = ZSTD_copyCCtx(d, s, copy_pledged);
        printf("copy-after %s\n", ZSTD_isError(r) ? ZSTD_getErrorName(r) : "ok");
    }
    ZSTD_freeCDict(cdict);
    ZSTD_freeCCtx(s);
    ZSTD_freeCCtx(d);
    free(dst);
    free(dict);
    free(src);
    return 0;
}
