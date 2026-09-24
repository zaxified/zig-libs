/* SPDX-License-Identifier: MIT */
/* zref -- differential oracle: compress a file with libzstd exactly the way
 * modules/zstd does (one-shot ZSTD_compress2, content size in the header).
 *
 *   zref <level> <checksum 0|1> <in> <out> [strategy [ldm 0|1 [window_log [params]]]]
 *
 * With a strategy (1 = fast ... 9 = btultra2) it is forced through
 * ZSTD_c_strategy on top of the level, which reaches strategy/size pairs no
 * level maps to; the module's counterpart is `frame.Options.strategy`.
 * Strategy 0 leaves the level's own. With ldm 1, long-distance matching is
 * switched on by hand (ZSTD_c_enableLongDistanceMatching), which reaches it
 * far below the 64 MB where level 22 switches it on; the counterpart is
 * `zstd.Advanced.long_distance_matching = .enable`. A nonzero window log is set through ZSTD_c_windowLog
 * (`zstd.Advanced.window_log`). `params` is a comma-separated list of
 * advanced parameters by libzstd's names, `name=value` (`windowLog=12,
 * useRowMatchFinder=1`; switches 0 auto, 1 enable, 2 disable), the module's
 * `zstd.Advanced`; "-" for none.
 *
 * Compiled with -DZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY=1 against the
 * library sources (gen-goldens.sh does), it is the reference for
 * `frame.Options.overflow_correct_frequently`.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zref zref.c "$R/lib/libzstd.a"
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

/* The advanced parameters by libzstd's own names, as `name=value` tokens
 * (the module's `zstd.Advanced`; `srcSizeHint` is `StreamOptions`). */
static struct { char const* name; ZSTD_cParameter p; } const params[] = {
    { "windowLog", ZSTD_c_windowLog },
    { "hashLog", ZSTD_c_hashLog },
    { "chainLog", ZSTD_c_chainLog },
    { "searchLog", ZSTD_c_searchLog },
    { "minMatch", ZSTD_c_minMatch },
    { "targetLength", ZSTD_c_targetLength },
    { "strategy", ZSTD_c_strategy },
    { "contentSizeFlag", ZSTD_c_contentSizeFlag },
    { "format", ZSTD_c_format },
    { "literalCompressionMode", ZSTD_c_literalCompressionMode },
    { "useRowMatchFinder", ZSTD_c_useRowMatchFinder },
    { "splitAfterSequences", ZSTD_c_splitAfterSequences },
    { "blockSplitterLevel", ZSTD_c_blockSplitterLevel },
    { "maxBlockSize", ZSTD_c_maxBlockSize },
    { "enableLongDistanceMatching", ZSTD_c_enableLongDistanceMatching },
    { "ldmHashLog", ZSTD_c_ldmHashLog },
    { "ldmMinMatch", ZSTD_c_ldmMinMatch },
    { "ldmBucketSizeLog", ZSTD_c_ldmBucketSizeLog },
    { "ldmHashRateLog", ZSTD_c_ldmHashRateLog },
    { "targetCBlockSize", ZSTD_c_targetCBlockSize },
    { "srcSizeHint", ZSTD_c_srcSizeHint },
};

/* Set one `name=value` token; 0 when it is not one, -1 on error. */
static int setParam(ZSTD_CCtx* cctx, char const* tok)
{
    char const* const eq = strchr(tok, '=');
    if (!eq) return 0;
    for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        if (strlen(params[i].name) == (size_t)(eq - tok) && !strncmp(tok, params[i].name, (size_t)(eq - tok))) {
            size_t const r = ZSTD_CCtx_setParameter(cctx, params[i].p, atoi(eq + 1));
            if (ZSTD_isError(r)) { fprintf(stderr, "%s: %s\n", tok, ZSTD_getErrorName(r)); return -1; }
            return 1;
        }
    }
    fprintf(stderr, "unknown parameter %s\n", tok);
    return -1;
}

int main(int argc, char** argv)
{
    if (argc < 5 || argc > 9) {
        fprintf(stderr, "usage: zref <level> <checksum 0|1> <in> <out> [strategy [ldm 0|1 [window_log [params]]]]\n");
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
    if (argc >= 6 && atoi(argv[5]) != 0) ZSTD_CCtx_setParameter(cctx, ZSTD_c_strategy, atoi(argv[5]));
    /* 1 = ZSTD_ps_enable, which zstd.h declares only for static linking */
    if (argc >= 7 && atoi(argv[6]) != 0) ZSTD_CCtx_setParameter(cctx, ZSTD_c_enableLongDistanceMatching, 1);
    if (argc >= 8 && atoi(argv[7]) != 0) ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, atoi(argv[7]));
    if (argc == 9 && strcmp(argv[8], "-")) {
        char* const list = strdup(argv[8]);
        for (char* tok = strtok(list, ","); tok; tok = strtok(NULL, ","))
            if (setParam(cctx, tok) != 1) return 7;
        free(list);
    }
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
