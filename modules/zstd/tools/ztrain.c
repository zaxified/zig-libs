/* SPDX-License-Identifier: MIT */
/* ztrain -- differential oracle for dictionary training (content selection):
 * the dictionary CONTENT libzstd's cover and fastCover trainers pick, before
 * ZDICT_finalizeDictionary prepends the header and the entropy tables.
 *
 *   ztrain <cover|fastcover> <samples> <out> <capacity> <k> <d> [f accel [splitPoint]]
 *
 * <samples> is a sample set as `src/dict_builder.zig` tests write it: u32 LE
 * sample count, that many u32 LE sample sizes, then the samples back to back.
 * The content (`dict + tail .. dict + capacity`) goes to <out>; stdout gets
 * `OK <content size> <small corpus warning 0|1>` or `ERR <ZSTD_ErrorCode>`.
 *
 * The public trainers finalize the content, and finalization may drop the
 * content's head to make room for the header, so the content is not
 * recoverable from their output. This program therefore includes the
 * trainers' sources and calls their internal steps in the order
 * ZDICT_trainFromBuffer_cover / _fastCover do -- parameter checks, context,
 * `*_buildDictionary` -- and stops before finalization. With a splitPoint
 * below 1 the context is built on the training share of the samples, as
 * ZDICT_optimizeTrainFromBuffer_* builds it for each (k, d) it tries
 * (single-threaded: libzstd's pool breaks ties by completion order).
 * f and accel of 0 take libzstd's defaults (20, 1); cover ignores them.
 *
 * Build against the pinned libzstd checkout (see README.md), from sources,
 * once per trainer (cover.h has no include guard, so a build includes the
 * one it drives and links the other):
 *   L="$R/lib/common/*.c $R/lib/compress/*.c $R/lib/dictBuilder/zdict.c $R/lib/dictBuilder/divsufsort.c"
 *   cc -O2 -I "$R/lib" -I "$R/lib/dictBuilder" -o ztrain-cover ztrain.c \
 *      $L "$R/lib/dictBuilder/fastcover.c"
 *   cc -O2 -DZTRAIN_FASTCOVER -I "$R/lib" -I "$R/lib/dictBuilder" -o ztrain-fastcover ztrain.c \
 *      $L "$R/lib/dictBuilder/cover.c"
 * The first argument must name the trainer the build includes.
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
/* cover.h has no include guard, so one build includes one trainer: */
#ifdef ZTRAIN_FASTCOVER
#  include "fastcover.c"
#else
#  include "cover.c"
#endif

#include <stdio.h>
#include <stdlib.h>

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

static int report(size_t r)
{
    printf("ERR %d\n", (int)ZSTD_getErrorCode(r));
    return 0;
}

static int emit(char const* out, unsigned char const* content, size_t n, int small)
{
    FILE* f = fopen(out, "wb");
    if (!f || fwrite(content, 1, n, f) != n || fclose(f) != 0) { perror(out); return 2; }
    printf("OK %zu %d\n", n, small);
    return 0;
}

static int smallCorpus(size_t maxDictSize, size_t nbDmers)
{
    /* COVER_warnOnSmallCorpus's condition */
    return (double)nbDmers / (double)maxDictSize < 10;
}

int main(int argc, char** argv)
{
    size_t fileSize, capacity, *sizes, total = 0;
    unsigned char *file, *dict;
    unsigned nbSamples, i, f = 0, accel = 0;
    double splitPoint = 1.0;
    int cover;
    ZDICT_cover_params_t p;
    if (argc < 7) {
        fprintf(stderr, "usage: ztrain <cover|fastcover> <samples> <out> <capacity> <k> <d> [f accel [splitPoint]]\n");
        return 2;
    }
    cover = strcmp(argv[1], "cover") == 0;
    file = readAll(argv[2], &fileSize);
    capacity = (size_t)strtoull(argv[4], NULL, 10);
    memset(&p, 0, sizeof(p));
    p.k = (unsigned)strtoul(argv[5], NULL, 10);
    p.d = (unsigned)strtoul(argv[6], NULL, 10);
    if (argc > 8) { f = (unsigned)strtoul(argv[7], NULL, 10); accel = (unsigned)strtoul(argv[8], NULL, 10); }
    if (argc > 9) splitPoint = strtod(argv[9], NULL);
    nbSamples = MEM_readLE32(file);
    if (4 + 4 * (size_t)nbSamples > fileSize) { fprintf(stderr, "bad sample count\n"); return 2; }
    sizes = (size_t*)malloc(sizeof(size_t) * (nbSamples + 1));
    for (i = 0; i < nbSamples; i++) { sizes[i] = MEM_readLE32(file + 4 + 4 * i); total += sizes[i]; }
    if (4 + 4 * (size_t)nbSamples + total > fileSize) { fprintf(stderr, "sizes exceed the file\n"); return 2; }
    {
        unsigned char const* samples = file + 4 + 4 * (size_t)nbSamples;
        dict = (unsigned char*)malloc(capacity ? capacity : 1);
        p.splitPoint = splitPoint;
#ifndef ZTRAIN_FASTCOVER
        if (!cover) { fprintf(stderr, "this build drives cover\n"); return 2; }
        {
            /* ZDICT_trainFromBuffer_cover up to its finalization */
            COVER_ctx_t ctx;
            COVER_map_t activeDmers;
            size_t tail, r;
            if (!COVER_checkParameters(p, capacity)) return report(ERROR(parameter_outOfBound));
            if (nbSamples == 0) return report(ERROR(srcSize_wrong));
            if (capacity < ZDICT_DICTSIZE_MIN) return report(ERROR(dstSize_tooSmall));
            r = COVER_ctx_init(&ctx, samples, sizes, nbSamples, p.d, p.splitPoint);
            if (ZSTD_isError(r)) return report(r);
            if (!COVER_map_init(&activeDmers, p.k - p.d + 1)) return report(ERROR(memory_allocation));
            tail = COVER_buildDictionary(&ctx, ctx.freqs, &activeDmers, dict, capacity, p);
            return emit(argv[3], dict + tail, capacity - tail, smallCorpus(capacity, ctx.suffixSize));
        }
#else
        if (cover) { fprintf(stderr, "this build drives fastcover\n"); return 2; }
        {
            /* ZDICT_trainFromBuffer_fastCover up to its finalization */
            FASTCOVER_ctx_t ctx;
            FASTCOVER_accel_t accelParams;
            U16* segmentFreqs;
            size_t tail, r;
            f = f == 0 ? DEFAULT_F : f;
            accel = accel == 0 ? DEFAULT_ACCEL : accel;
            if (!FASTCOVER_checkParameters(p, capacity, f, accel)) return report(ERROR(parameter_outOfBound));
            if (nbSamples == 0) return report(ERROR(srcSize_wrong));
            if (capacity < ZDICT_DICTSIZE_MIN) return report(ERROR(dstSize_tooSmall));
            accelParams = FASTCOVER_defaultAccelParameters[accel];
            r = FASTCOVER_ctx_init(&ctx, samples, sizes, nbSamples, p.d, p.splitPoint, f, accelParams);
            if (ZSTD_isError(r)) return report(r);
            segmentFreqs = (U16*)calloc(((U64)1 << f), sizeof(U16));
            if (!segmentFreqs) return report(ERROR(memory_allocation));
            tail = FASTCOVER_buildDictionary(&ctx, ctx.freqs, dict, capacity, p, segmentFreqs);
            return emit(argv[3], dict + tail, capacity - tail, smallCorpus(capacity, ctx.nbDmers));
        }
#endif
    }
}
