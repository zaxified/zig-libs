/* SPDX-License-Identifier: MIT */
/* zstream -- differential oracle for modules/zstd streaming: compress a file
 * with libzstd's ZSTD_compressStream2 following a call schedule, exactly as
 * `stream_test.zig` drives `zstd.Stream`.
 *
 *   zstream <level> <checksum 0|1> <in> <out> <schedule>
 *
 * The schedule is a comma-separated list of tokens, applied in order:
 *   pN   pledge N bytes (ZSTD_CCtx_setPledgedSrcSize), before any call
 *   wN   window log N (ZSTD_c_windowLog), before any call
 *   oN   later calls get an output buffer of N bytes (default: 1 << 24)
 *   cN   ZSTD_e_continue with the next N input bytes ("c*": all the rest)
 *   fN   ZSTD_e_flush, likewise
 *   eN   ZSTD_e_end, likewise; ends the schedule
 *   l    long-distance matching switched on by hand
 *        (ZSTD_c_enableLongDistanceMatching; the module's
 *        `Advanced.long_distance_matching = .enable`)
 *   x    index overflow corrected whenever it safely can: only accepted by a
 *        build with -DZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY=1 (the
 *        module's `Stream.overflow_correct_frequently`)
 *   name=value  an advanced parameter by libzstd's name (`hashLog=12`,
 *        `srcSizeHint=5000`; switches 0 auto, 1 enable, 2 disable), before
 *        any call: the module's `StreamOptions.advanced` / `src_size_hint`
 * Each c/f/e call is repeated with a fresh output buffer until its input is
 * consumed (continue) or it returns 0 (flush, end); every output buffer's
 * contents are appended to <out>.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zstream zstream.c "$R/lib/libzstd.a"
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
    if (argc != 6) {
        fprintf(stderr, "usage: zstream <level> <checksum 0|1> <in> <out> <schedule>\n");
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

    FILE* const out = fopen(argv[4], "wb");
    if (!out) { perror(argv[4]); return 6; }

    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, checksum);

    size_t ocap = (size_t)1 << 24;
    char* obuf = malloc(ocap);
    size_t fed = 0;
    char* const sched = strdup(argv[5]);
    for (char* tok = strtok(sched, ","); tok; tok = strtok(NULL, ",")) {
        {   /* before the one-letter tokens: a name may start with any of them */
            int const r = setParam(cctx, tok);
            if (r < 0) return 7;
            if (r > 0) continue;
        }
        char const op = tok[0];
        if (op == 'x') {
#if !defined(ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY) || !ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY
            fprintf(stderr, "x needs a build with ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY\n");
            return 7;
#endif
            continue;
        }
        if (op == 'l') { ZSTD_CCtx_setParameter(cctx, ZSTD_c_enableLongDistanceMatching, 1); continue; }
        size_t const num = tok[1] == '*' ? (size_t)n - fed : (size_t)strtoull(tok + 1, NULL, 10);
        if (op == 'p') { ZSTD_CCtx_setPledgedSrcSize(cctx, num); continue; }
        if (op == 'w') { ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, (int)num); continue; }
        if (op == 'o') { ocap = num; free(obuf); obuf = malloc(ocap ? ocap : 1); continue; }
        ZSTD_EndDirective const dir = op == 'c' ? ZSTD_e_continue : op == 'f' ? ZSTD_e_flush : ZSTD_e_end;
        if (op != 'c' && op != 'f' && op != 'e') { fprintf(stderr, "bad token %s\n", tok); return 7; }
        if (num > (size_t)n - fed) { fprintf(stderr, "token %s runs past the input\n", tok); return 7; }
        ZSTD_inBuffer in = { src + fed, num, 0 };
        for (;;) {
            ZSTD_outBuffer o = { obuf, ocap, 0 };
            size_t const r = ZSTD_compressStream2(cctx, &o, &in, dir);
            if (ZSTD_isError(r)) { fprintf(stderr, "%s\n", ZSTD_getErrorName(r)); return 5; }
            fwrite(obuf, 1, o.pos, out);
            if (dir == ZSTD_e_continue ? in.pos == in.size : r == 0) break;
        }
        fed += num;
        if (op == 'e') break;
    }
    fclose(out);
    ZSTD_freeCCtx(cctx);
    free(sched);
    free(obuf);
    free(src);
    return 0;
}
