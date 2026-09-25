/* SPDX-License-Identifier: MIT */
/* zref -- differential oracle: compress a file with libzstd exactly the way
 * modules/zstd does (one-shot ZSTD_compress2, content size in the header).
 *
 *   zref <level> <checksum 0|1> <in> <out> [strategy [ldm 0|1 [window_log [params [dict]]]]]
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
 * `dict` is `<mode>:<content type>:<file>` ("-" for none): a dictionary used
 * the way <mode> names -- the module's counterpart in brackets --
 *   load        ZSTD_CCtx_loadDictionary_advanced (by copy) + ZSTD_compress2
 *               [Options.dictionary = .raw]
 *   loadadj     the same, with the input placed right after the dictionary
 *               in one buffer (the copy libzstd keeps is not adjacent)
 *   cdict       ZSTD_createCDict(level) + ZSTD_CCtx_refCDict + ZSTD_compress2
 *               [CDict.init + .cdict]
 *   cdictadv    ZSTD_createCDict_advanced2 with the level and `params`
 *               + ZSTD_CCtx_refCDict + ZSTD_compress2 [CDict.initAdvanced]
 *   cdictref    the same by reference (ZSTD_dlm_byRef) [CDict.initReference]
 *   cdictrefadj the same, with the input placed right after the dictionary
 *               in one buffer (the CDict's window continues into it)
 *   prefix      ZSTD_CCtx_refPrefix_advanced + ZSTD_compress2 [.prefix]
 *   prefixadj   the same, with the input placed right after the prefix in
 *               one buffer (contiguous in memory)
 *   usingdict   ZSTD_compress_usingDict(level), no other parameter
 *               [Compressor.compressUsingDict]
 *   usingcdict  ZSTD_createCDict(level) + ZSTD_compress_usingCDict_advanced,
 *               frame parameters from `checksum` and `params`'
 *               contentSizeFlag / dictIDFlag [Compressor.compressUsingCDict]
 * and the content type 0 auto, 1 raw content, 2 full (ZSTD_dictContentType_e;
 * cdict, usingdict and usingcdict take only 0). The frame is decoded back
 * with the dictionary (libzstd's decoder) and must give the input: exit 8
 * otherwise.
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
#define ZSTD_DISABLE_DEPRECATE_WARNINGS
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
    { "dictIDFlag", ZSTD_c_dictIDFlag },
    { "forceAttachDict", ZSTD_c_forceAttachDict },
    { "deterministicRefPrefix", ZSTD_c_deterministicRefPrefix },
    { "forceMaxWindow", ZSTD_c_forceMaxWindow },
    { "enableDedicatedDictSearch", ZSTD_c_enableDedicatedDictSearch },
    /* multithreading: needs a library built with ZSTD_MULTITHREAD */
    { "nbWorkers", ZSTD_c_nbWorkers },
    { "jobSize", ZSTD_c_jobSize },
    { "overlapLog", ZSTD_c_overlapLog },
};

/* Set one `name=value` token on `cctx` (or on `cparams` when given); 0 when
 * it is not one, -1 on error. */
static int setParam(ZSTD_CCtx* cctx, ZSTD_CCtx_params* cparams, char const* tok)
{
    char const* const eq = strchr(tok, '=');
    if (!eq) return 0;
    for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        if (strlen(params[i].name) == (size_t)(eq - tok) && !strncmp(tok, params[i].name, (size_t)(eq - tok))) {
            size_t const r = cparams ? ZSTD_CCtxParams_setParameter(cparams, params[i].p, atoi(eq + 1))
                                     : ZSTD_CCtx_setParameter(cctx, params[i].p, atoi(eq + 1));
            if (ZSTD_isError(r)) { fprintf(stderr, "%s: %s\n", tok, ZSTD_getErrorName(r)); return -1; }
            return 1;
        }
    }
    fprintf(stderr, "unknown parameter %s\n", tok);
    return -1;
}

/* The whole of `path` after `pad` bytes of room, in a new buffer. */
static char* readFile(char const* path, size_t pad, size_t* size)
{
    FILE* const f = fopen(path, "rb");
    if (!f) { perror(path); exit(3); }
    fseek(f, 0, SEEK_END);
    long const n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* const buf = malloc(pad + (size_t)n + 1);
    if (n && fread(buf + pad, 1, (size_t)n, f) != (size_t)n) { perror("read"); exit(4); }
    fclose(f);
    *size = (size_t)n;
    return buf;
}

/* Apply the `params` argument (comma-separated `name=value`, "-" for none)
 * to `cctx`, or to `cparams`. */
static int setParams(ZSTD_CCtx* cctx, ZSTD_CCtx_params* cparams, char const* list)
{
    if (!strcmp(list, "-")) return 0;
    char* const copy = strdup(list);
    for (char* tok = strtok(copy, ","); tok; tok = strtok(NULL, ","))
        if (setParam(cctx, cparams, tok) != 1) return -1;
    free(copy);
    return 0;
}

/* The value of `name=` in the `params` list, or `dflt`. */
static int paramValue(char const* list, char const* name, int dflt)
{
    size_t const len = strlen(name);
    for (char const* p = list; p && *p; p = strchr(p, ',') ? strchr(p, ',') + 1 : NULL)
        if (!strncmp(p, name, len) && p[len] == '=') return atoi(p + len + 1);
    return dflt;
}

int main(int argc, char** argv)
{
    if (argc < 5 || argc > 10) {
        fprintf(stderr, "usage: zref <level> <checksum 0|1> <in> <out> [strategy [ldm 0|1 [window_log [params [dict]]]]]\n");
        return 2;
    }
    int const level = atoi(argv[1]);
    int const checksum = atoi(argv[2]);
    char const* const plist = argc >= 9 ? argv[8] : "-";

    /* the dictionary, if any: mode:type:file */
    char mode[16] = "";
    int ctype = 0;
    size_t dsize = 0;
    char* dict = NULL;
    if (argc == 10 && strcmp(argv[9], "-")) {
        char const* const c1 = strchr(argv[9], ':');
        char const* const c2 = c1 ? strchr(c1 + 1, ':') : NULL;
        if (!c2 || (size_t)(c1 - argv[9]) >= sizeof(mode)) { fprintf(stderr, "bad dict %s\n", argv[9]); return 2; }
        memcpy(mode, argv[9], (size_t)(c1 - argv[9]));
        ctype = atoi(c1 + 1);
        dict = readFile(c2 + 1, 0, &dsize);
    }
    int const adjacent = !strcmp(mode, "prefixadj") || !strcmp(mode, "loadadj") || !strcmp(mode, "cdictrefadj");
    int const byref = !strcmp(mode, "cdictref") || !strcmp(mode, "cdictrefadj");

    /* the input, right after a copy of the prefix when they must be adjacent */
    size_t sz;
    char* const buf = readFile(argv[3], adjacent ? dsize : 0, &sz);
    if (adjacent) memcpy(buf, dict, dsize);
    char* const src = adjacent ? buf + dsize : buf;
    long const n = (long)sz;

    size_t const cap = ZSTD_compressBound((size_t)n);
    char* const dst = malloc(cap);
    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, checksum);
    if (argc >= 6 && atoi(argv[5]) != 0) ZSTD_CCtx_setParameter(cctx, ZSTD_c_strategy, atoi(argv[5]));
    /* 1 = ZSTD_ps_enable, which zstd.h declares only for static linking */
    if (argc >= 7 && atoi(argv[6]) != 0) ZSTD_CCtx_setParameter(cctx, ZSTD_c_enableLongDistanceMatching, 1);
    if (argc >= 8 && atoi(argv[7]) != 0) ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, atoi(argv[7]));
    if (setParams(cctx, NULL, plist)) return 7;
    ZSTD_CDict* cdict = NULL;
    size_t r;
    if (!dict) {
        r = ZSTD_compress2(cctx, dst, cap, src, (size_t)n);
    } else if (!strcmp(mode, "load") || !strcmp(mode, "loadadj")) {
        if (ZSTD_isError(ZSTD_CCtx_loadDictionary_advanced(cctx, adjacent ? buf : dict, dsize, ZSTD_dlm_byCopy, (ZSTD_dictContentType_e)ctype))) return 7;
        r = ZSTD_compress2(cctx, dst, cap, src, (size_t)n);
    } else if (!strcmp(mode, "cdict") || !strcmp(mode, "usingcdict")) {
        cdict = ZSTD_createCDict(dict, dsize, level);
        if (!cdict) { fprintf(stderr, "ZSTD_createCDict failed\n"); return 5; }
        if (!strcmp(mode, "cdict")) {
            ZSTD_CCtx_refCDict(cctx, cdict);
            r = ZSTD_compress2(cctx, dst, cap, src, (size_t)n);
        } else {
            ZSTD_frameParameters const fp = { paramValue(plist, "contentSizeFlag", 1), checksum, !paramValue(plist, "dictIDFlag", 1) };
            ZSTD_CCtx* const fresh = ZSTD_createCCtx();
            r = ZSTD_compress_usingCDict_advanced(fresh, dst, cap, src, (size_t)n, cdict, fp);
            ZSTD_freeCCtx(fresh);
        }
    } else if (!strcmp(mode, "cdictadv") || byref) {
        ZSTD_CCtx_params* const cp = ZSTD_createCCtxParams();
        ZSTD_CCtxParams_init(cp, level);
        if (setParams(NULL, cp, plist)) return 7;
        cdict = ZSTD_createCDict_advanced2(adjacent ? buf : dict, dsize, byref ? ZSTD_dlm_byRef : ZSTD_dlm_byCopy, (ZSTD_dictContentType_e)ctype, cp, ZSTD_defaultCMem);
        ZSTD_freeCCtxParams(cp);
        if (!cdict) { fprintf(stderr, "ZSTD_createCDict_advanced2 failed\n"); return 5; }
        ZSTD_CCtx_refCDict(cctx, cdict);
        r = ZSTD_compress2(cctx, dst, cap, src, (size_t)n);
    } else if (!strcmp(mode, "prefix") || adjacent) {
        ZSTD_CCtx_refPrefix_advanced(cctx, adjacent ? buf : dict, dsize, (ZSTD_dictContentType_e)ctype);
        r = ZSTD_compress2(cctx, dst, cap, src, (size_t)n);
    } else if (!strcmp(mode, "usingdict")) {
        ZSTD_CCtx* const fresh = ZSTD_createCCtx();
        r = ZSTD_compress_usingDict(fresh, dst, cap, src, (size_t)n, dict, dsize, level);
        ZSTD_freeCCtx(fresh);
    } else {
        fprintf(stderr, "unknown dict mode %s\n", mode);
        return 2;
    }
    if (ZSTD_isError(r)) { fprintf(stderr, "%s\n", ZSTD_getErrorName(r)); return 5; }

    if (dict) { /* decode it back with the dictionary */
        ZSTD_DCtx* const dctx = ZSTD_createDCtx();
        ZSTD_DCtx_setParameter(dctx, ZSTD_d_windowLogMax, 31);
        if (paramValue(plist, "format", 0)) ZSTD_DCtx_setParameter(dctx, ZSTD_d_format, ZSTD_f_zstd1_magicless);
        if (!strcmp(mode, "prefix") || !strcmp(mode, "prefixadj"))
            ZSTD_DCtx_refPrefix_advanced(dctx, dict, dsize, (ZSTD_dictContentType_e)ctype);
        else
            ZSTD_DCtx_loadDictionary_advanced(dctx, dict, dsize, ZSTD_dlm_byRef, (ZSTD_dictContentType_e)ctype);
        char* const back = malloc((size_t)n + 1);
        size_t const d = ZSTD_decompressDCtx(dctx, back, (size_t)n + 1, dst, r);
        if (ZSTD_isError(d) || d != (size_t)n || memcmp(back, src, (size_t)n)) {
            fprintf(stderr, "decode with the dictionary failed: %s\n", ZSTD_isError(d) ? ZSTD_getErrorName(d) : "mismatch");
            return 8;
        }
        free(back);
        ZSTD_freeDCtx(dctx);
    }

    FILE* f = fopen(argv[4], "wb");
    if (!f) { perror(argv[4]); return 6; }
    fwrite(dst, 1, r, f);
    fclose(f);
    ZSTD_freeCCtx(cctx);
    ZSTD_freeCDict(cdict);
    free(buf);
    free(dict);
    free(dst);
    return 0;
}
