/* SPDX-License-Identifier: MIT */
/* zfinal -- differential oracle for FINISHED dictionaries: libzstd's public
 * trainers and finalizer, and COVER_selectDict (the optimizers' scorer).
 *
 *   zfinal finalize   <samples> <out> <cap> <coff> <clen> <nbfin> <level> <dictID>
 *   zfinal addentropy <samples> <out> <cap> <coff> <clen>
 *   zfinal cover      <samples> <out> <cap> <k> <d> <level> <dictID>
 *   zfinal fastcover  <samples> <out> <cap> <k> <d> <f> <accel> <level> <dictID>
 *   zfinal optcover   <samples> <out> <cap> <k> <d> <steps> <split> <level> <dictID>
 *   zfinal optfast    <samples> <out> <cap> <k> <d> <steps> <split> <f> <accel> <level> <dictID>
 *   zfinal default    <samples> <out> <cap>
 *   zfinal select     <samples> <out> <cap> <boff> <clen> <nbfin> <nbtrain> <split> <level> <dictID> <shrink> <maxreg>
 *
 * <samples> is a sample set as `ztrain.c` reads it (u32 LE count, u32 LE
 * sizes, the samples). `coff`/`clen`: the content is those bytes of the
 * samples (finalize: in place; addentropy: copied to the end of a zeroed
 * <cap>-byte buffer). `boff`: select's <cap>-byte buffer is a copy of the
 * samples from there, the content its last <clen> bytes; `nbtrain` is the
 * training share (offsets over all samples). The dictionary goes to <out>;
 * stdout gets `OK <size> <header size> <a> <b>` -- a, b: the optimizers'
 * chosen k and d, select's total compressed size and 0, else 0 0 -- or
 * `ERR <ZSTD_ErrorCode>` (select: `ERR 1000` for a failed selection). The
 * header size is ZDICT_getDictHeaderSize of the output (its error code
 * negated when it is not a dictionary).
 *
 * Single-threaded throughout (nbThreads 0): with threads, the optimizers
 * break ties by completion order.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   make -C "$R/lib" libzstd.a
 *   cc -O2 -I "$R/lib" -I "$R/lib/dictBuilder" -o zfinal zfinal.c "$R/lib/libzstd.a" -lpthread
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZDICT_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"
#include "zstd_errors.h"
#include "zdict.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cover.h: the scorer the optimizers call for each candidate */
typedef struct {
    unsigned char* dictContent;
    size_t dictSize;
    size_t totalCompressedSize;
} COVER_dictSelection_t;
COVER_dictSelection_t COVER_selectDict(unsigned char* customDictContent, size_t dictBufferCapacity,
        size_t dictContentSize, const unsigned char* samplesBuffer, const size_t* samplesSizes, unsigned nbFinalizeSamples,
        size_t nbCheckSamples, size_t nbSamples, ZDICT_cover_params_t params, size_t* offsets, size_t totalCompressedSize);
unsigned COVER_dictSelectionIsError(COVER_dictSelection_t selection);
void COVER_dictSelectionFree(COVER_dictSelection_t selection);

static unsigned char* readAll(char const* path, size_t* size)
{
    FILE* f = fopen(path, "rb");
    unsigned char* buf;
    long n;
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 4 || n > (1L << 30)) { fprintf(stderr, "bad sample file size\n"); exit(2); }
    buf = (unsigned char*)malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "read failed\n"); exit(2); }
    fclose(f);
    *size = (size_t)n;
    return buf;
}

static unsigned readLE32(unsigned char const* p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned)p[3] << 24);
}

static int emit(char const* out, unsigned char const* dict, size_t r, unsigned long long a, unsigned long long b)
{
    FILE* f;
    long long hdr;
    if (ZDICT_isError(r)) {
        printf("ERR %d\n", (int)ZSTD_getErrorCode(r));
        return 0;
    }
    f = fopen(out, "wb");
    if (!f || fwrite(dict, 1, r, f) != r || fclose(f) != 0) { perror(out); return 2; }
    {
        size_t const h = ZDICT_getDictHeaderSize(dict, r);
        hdr = ZDICT_isError(h) ? -(long long)ZSTD_getErrorCode(h) : (long long)h;
    }
    printf("OK %zu %lld %llu %llu\n", r, hdr, a, b);
    return 0;
}

#define ARG(i) strtoull(argv[i], NULL, 10)

int main(int argc, char** argv)
{
    size_t fileSize, total = 0, cap, *sizes;
    unsigned char *file, *samples, *dict;
    unsigned nbSamples, i;
    char const* op;
    if (argc < 5) { fprintf(stderr, "usage: see the header of zfinal.c\n"); return 2; }
    op = argv[1];
    file = readAll(argv[2], &fileSize);
    cap = (size_t)ARG(4);
    nbSamples = readLE32(file);
    if (4 + 4 * (size_t)nbSamples > fileSize) { fprintf(stderr, "bad sample count\n"); return 2; }
    sizes = (size_t*)malloc(sizeof(size_t) * (nbSamples + 1));
    for (i = 0; i < nbSamples; i++) { sizes[i] = readLE32(file + 4 + 4 * i); total += sizes[i]; }
    if (4 + 4 * (size_t)nbSamples + total > fileSize) { fprintf(stderr, "sizes exceed the file\n"); return 2; }
    samples = file + 4 + 4 * (size_t)nbSamples;
    dict = (unsigned char*)calloc(cap ? cap : 1, 1);

    if (!strcmp(op, "finalize") && argc == 10) {
        ZDICT_params_t zp;
        size_t coff = ARG(5), clen = ARG(6);
        memset(&zp, 0, sizeof(zp));
        zp.compressionLevel = atoi(argv[8]);
        zp.dictID = (unsigned)ARG(9);
        if (coff + clen > total) { fprintf(stderr, "content past the samples\n"); return 2; }
        return emit(argv[3], dict, ZDICT_finalizeDictionary(dict, cap, samples + coff, clen, samples, sizes, (unsigned)ARG(7), zp), 0, 0);
    }
    if (!strcmp(op, "addentropy") && argc == 7) {
        size_t coff = ARG(5), clen = ARG(6);
        if (coff + clen > total || clen > cap) { fprintf(stderr, "content past the samples\n"); return 2; }
        memcpy(dict + cap - clen, samples + coff, clen);
        return emit(argv[3], dict, ZDICT_addEntropyTablesFromBuffer(dict, clen, cap, samples, sizes, nbSamples), 0, 0);
    }
    if (!strcmp(op, "cover") && argc == 9) {
        ZDICT_cover_params_t p;
        memset(&p, 0, sizeof(p));
        p.k = (unsigned)ARG(5); p.d = (unsigned)ARG(6);
        p.zParams.compressionLevel = atoi(argv[7]); p.zParams.dictID = (unsigned)ARG(8);
        return emit(argv[3], dict, ZDICT_trainFromBuffer_cover(dict, cap, samples, sizes, nbSamples, p), 0, 0);
    }
    if (!strcmp(op, "fastcover") && argc == 11) {
        ZDICT_fastCover_params_t p;
        memset(&p, 0, sizeof(p));
        p.k = (unsigned)ARG(5); p.d = (unsigned)ARG(6); p.f = (unsigned)ARG(7); p.accel = (unsigned)ARG(8);
        p.zParams.compressionLevel = atoi(argv[9]); p.zParams.dictID = (unsigned)ARG(10);
        return emit(argv[3], dict, ZDICT_trainFromBuffer_fastCover(dict, cap, samples, sizes, nbSamples, p), 0, 0);
    }
    if (!strcmp(op, "optcover") && argc == 11) {
        ZDICT_cover_params_t p;
        size_t r;
        memset(&p, 0, sizeof(p));
        p.k = (unsigned)ARG(5); p.d = (unsigned)ARG(6); p.steps = (unsigned)ARG(7); p.splitPoint = strtod(argv[8], NULL);
        p.zParams.compressionLevel = atoi(argv[9]); p.zParams.dictID = (unsigned)ARG(10);
        r = ZDICT_optimizeTrainFromBuffer_cover(dict, cap, samples, sizes, nbSamples, &p);
        return emit(argv[3], dict, r, p.k, p.d);
    }
    if (!strcmp(op, "optfast") && argc == 13) {
        ZDICT_fastCover_params_t p;
        size_t r;
        memset(&p, 0, sizeof(p));
        p.k = (unsigned)ARG(5); p.d = (unsigned)ARG(6); p.steps = (unsigned)ARG(7); p.splitPoint = strtod(argv[8], NULL);
        p.f = (unsigned)ARG(9); p.accel = (unsigned)ARG(10);
        p.zParams.compressionLevel = atoi(argv[11]); p.zParams.dictID = (unsigned)ARG(12);
        r = ZDICT_optimizeTrainFromBuffer_fastCover(dict, cap, samples, sizes, nbSamples, &p);
        return emit(argv[3], dict, r, p.k, p.d);
    }
    if (!strcmp(op, "default") && argc == 5) {
        return emit(argv[3], dict, ZDICT_trainFromBuffer(dict, cap, samples, sizes, nbSamples), 0, 0);
    }
    if (!strcmp(op, "select") && argc == 14) {
        ZDICT_cover_params_t p;
        COVER_dictSelection_t s;
        size_t boff = ARG(5), clen = ARG(6), *offsets;
        unsigned char* buf;
        int rc;
        if (boff + cap > total || clen > cap) { fprintf(stderr, "buffer past the samples\n"); return 2; }
        buf = (unsigned char*)malloc(cap);
        memcpy(buf, samples + boff, cap);
        offsets = (size_t*)malloc(sizeof(size_t) * (nbSamples + 1));
        offsets[0] = 0;
        for (i = 0; i < nbSamples; i++) offsets[i + 1] = offsets[i] + sizes[i];
        memset(&p, 0, sizeof(p));
        p.splitPoint = strtod(argv[9], NULL);
        p.zParams.compressionLevel = atoi(argv[10]); p.zParams.dictID = (unsigned)ARG(11);
        p.shrinkDict = (unsigned)ARG(12); p.shrinkDictMaxRegression = (unsigned)ARG(13);
        s = COVER_selectDict(buf + cap - clen, cap, clen, samples, sizes, (unsigned)ARG(7), (size_t)ARG(8), nbSamples, p, offsets, 0);
        if (COVER_dictSelectionIsError(s)) { printf("ERR 1000\n"); return 0; } /* no selection */
        rc = emit(argv[3], s.dictContent, s.dictSize, s.totalCompressedSize, 0);
        COVER_dictSelectionFree(s);
        return rc;
    }
    (void)argc;
    fprintf(stderr, "bad arguments for %s\n", op);
    return 2;
}
