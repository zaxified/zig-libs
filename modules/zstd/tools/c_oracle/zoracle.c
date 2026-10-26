/* SPDX-License-Identifier: MIT */
/* zoracle -- the live libzstd peer of `zig build interop-zstd`
 * (modules/zstd/tools/interop.zig). One process, linked with libzstd 1.5.7
 * built from the pinned checkout's sources (interop.zig builds it with
 * `zig cc`), answering requests on stdin with replies on stdout until EOF,
 * so a run asks it thousands of questions without a process per question.
 *
 * Wire format, little-endian; a "blob" is u32 length + bytes:
 *
 *   'C' compress  i32 level, u8 checksum, blob params, u8 dict mode
 *                 (0 none, 1 ZSTD_CCtx_loadDictionary, 2 ZSTD_CCtx_refPrefix),
 *                 blob dict, blob src                 -> ZSTD_compress2
 *   'S' stream    i32 level, u8 checksum, blob params, u8 dict mode, blob dict,
 *                 u32 output buffer size, u64 pledged size (all ones: none),
 *                 u32 steps, each u8 directive (0 continue, 1 flush, 2 end)
 *                 + u32 input bytes, blob src          -> ZSTD_compressStream2
 *   'D' decode    u8 mode (0 one-shot into ZSTD_decompressBound bytes,
 *                 1 streaming fed whole, 2 streaming fed one byte per call
 *                 into 997-byte output buffers), u8 magicless, u8 dict mode
 *                 (0 none, 1 ZSTD_DCtx_loadDictionary, 2 ZSTD_DCtx_refPrefix),
 *                 blob dict, blob src
 *   'T' train     u32 capacity, u32 n, n × u32 sizes, blob samples
 *                                                     -> ZDICT_trainFromBuffer
 *   'V' version                                       -> ZSTD_versionString
 *
 * Reply: u8 0 + blob output, or u8 1 + u32 ZSTD_ErrorCode (ZDICT errors are
 * ZSTD error codes too). `params` is the `name=value,...` list zref.c reads,
 * by libzstd's parameter names, applied with ZSTD_CCtx_setParameter after the
 * level; a refused parameter is the reply (its error code).
 *
 * The stream loop is zstream.c's, call for call: a `continue` step repeats
 * until its input is consumed, a `flush`/`end` step until the call returns 0.
 * Mode 2 of 'D' is zdec.c's mode 2; a frame that ends short of its content
 * replies srcSize_wrong, as `DecompressStream` reports it.
 *
 * A foreign-toolchain instrument (CONVENTIONS.md §2, §9): no module build
 * compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#define ZDICT_STATIC_LINKING_ONLY
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"
#include "zstd_errors.h"
#include "zdict.h"

static void die(const char* what)
{
    fprintf(stderr, "zoracle: %s\n", what);
    exit(2);
}

static void rd(void* p, size_t n)
{
    if (n && fread(p, 1, n, stdin) != n) {
        if (feof(stdin)) exit(0);
        die("short read");
    }
}
static uint8_t rd8(void) { uint8_t v; rd(&v, 1); return v; }
static uint32_t rd32(void)
{
    uint8_t b[4];
    rd(b, 4);
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static uint64_t rd64(void)
{
    uint64_t lo = rd32();
    return lo | (uint64_t)rd32() << 32;
}

typedef struct { uint8_t* p; size_t n; } Blob;
static Blob rdblob(void)
{
    Blob b;
    b.n = rd32();
    b.p = malloc(b.n + 1); /* +1: a malloc(0) may return NULL */
    if (!b.p) die("out of memory");
    rd(b.p, b.n);
    return b;
}

static void wr(const void* p, size_t n)
{
    if (n && fwrite(p, 1, n, stdout) != n) die("short write");
}
static void wr32(uint32_t v)
{
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    wr(b, 4);
}
static void replyOk(const void* p, size_t n)
{
    uint8_t z = 0;
    wr(&z, 1);
    wr32((uint32_t)n);
    wr(p, n);
    fflush(stdout);
}
static void replyErr(size_t r)
{
    uint8_t one = 1;
    wr(&one, 1);
    wr32((uint32_t)ZSTD_getErrorCode(r));
    fflush(stdout);
}

/* zref.c's table: every advanced parameter `zstd.Advanced` carries. */
static const struct { const char* name; ZSTD_cParameter p; } params[] = {
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
    { "nbWorkers", ZSTD_c_nbWorkers },
    { "jobSize", ZSTD_c_jobSize },
    { "overlapLog", ZSTD_c_overlapLog },
    { "rsyncable", ZSTD_c_rsyncable },
};

/* Sets the level, checksum and `name=value,...`; 0 or libzstd's error. */
static size_t setup(ZSTD_CCtx* cctx, int level, int checksum, Blob plist, int* magicless)
{
    size_t r;
    *magicless = 0;
    ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
    if (ZSTD_isError(r = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level))) return r;
    if (ZSTD_isError(r = ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, checksum))) return r;
    plist.p[plist.n] = 0;
    char* save = NULL;
    for (char* tok = strtok_r((char*)plist.p, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char* eq = strchr(tok, '=');
        if (!eq) die("bad parameter token");
        *eq = 0;
        int const v = atoi(eq + 1);
        size_t i;
        for (i = 0; i < sizeof params / sizeof params[0]; i++)
            if (!strcmp(params[i].name, tok)) break;
        if (i == sizeof params / sizeof params[0]) die("unknown parameter");
        if (params[i].p == ZSTD_c_format && v) *magicless = 1;
        if (ZSTD_isError(r = ZSTD_CCtx_setParameter(cctx, params[i].p, v))) return r;
    }
    return 0;
}

static size_t setDict(ZSTD_CCtx* cctx, int mode, Blob d)
{
    if (mode == 1) return ZSTD_CCtx_loadDictionary(cctx, d.p, d.n);
    if (mode == 2) return ZSTD_CCtx_refPrefix(cctx, d.p, d.n);
    return 0;
}

static void opCompress(ZSTD_CCtx* cctx)
{
    int const level = (int)rd32();
    int const checksum = rd8();
    Blob plist = rdblob();
    int const dmode = rd8();
    Blob dict = rdblob();
    Blob src = rdblob();
    int magicless;
    size_t r = setup(cctx, level, checksum, plist, &magicless);
    if (!ZSTD_isError(r)) r = setDict(cctx, dmode, dict);
    if (ZSTD_isError(r)) {
        replyErr(r);
    } else {
        size_t const cap = ZSTD_compressBound(src.n);
        void* dst = malloc(cap + 1);
        if (!dst) die("out of memory");
        r = ZSTD_compress2(cctx, dst, cap, src.p, src.n);
        if (ZSTD_isError(r)) replyErr(r); else replyOk(dst, r);
        free(dst);
    }
    free(plist.p);
    free(dict.p);
    free(src.p);
}

static void opStream(ZSTD_CCtx* cctx)
{
    int const level = (int)rd32();
    int const checksum = rd8();
    Blob plist = rdblob();
    int const dmode = rd8();
    Blob dict = rdblob();
    uint32_t const ocap = rd32();
    uint64_t const pledged = rd64();
    uint32_t const nsteps = rd32();
    uint8_t* dirs = malloc(nsteps + 1);
    uint32_t* lens = malloc(4 * (size_t)nsteps + 4);
    if (!dirs || !lens) die("out of memory");
    for (uint32_t i = 0; i < nsteps; i++) {
        dirs[i] = rd8();
        lens[i] = rd32();
    }
    Blob src = rdblob();
    int magicless;
    size_t r = setup(cctx, level, checksum, plist, &magicless);
    if (!ZSTD_isError(r) && pledged != UINT64_MAX) r = ZSTD_CCtx_setPledgedSrcSize(cctx, pledged);
    if (!ZSTD_isError(r)) r = setDict(cctx, dmode, dict);
    size_t outcap = 1 << 20, outn = 0, fed = 0;
    uint8_t* out = malloc(outcap);
    uint8_t* obuf = malloc(ocap + 1);
    if (!out || !obuf) die("out of memory");
    for (uint32_t i = 0; i < nsteps && !ZSTD_isError(r); i++) {
        ZSTD_EndDirective const dir = dirs[i] == 0 ? ZSTD_e_continue : dirs[i] == 1 ? ZSTD_e_flush : ZSTD_e_end;
        ZSTD_inBuffer in = { src.p + fed, lens[i], 0 };
        for (;;) {
            ZSTD_outBuffer o = { obuf, ocap, 0 };
            r = ZSTD_compressStream2(cctx, &o, &in, dir);
            if (ZSTD_isError(r)) break;
            if (outn + o.pos > outcap) {
                while (outn + o.pos > outcap) outcap *= 2;
                out = realloc(out, outcap);
                if (!out) die("out of memory");
            }
            memcpy(out + outn, obuf, o.pos);
            outn += o.pos;
            if (dir == ZSTD_e_continue ? in.pos == in.size : r == 0) break;
        }
        fed += lens[i];
    }
    if (ZSTD_isError(r)) replyErr(r); else replyOk(out, outn);
    free(out);
    free(obuf);
    free(dirs);
    free(lens);
    free(plist.p);
    free(dict.p);
    free(src.p);
}

/* A fresh context per frame, as zdec.c has one: a reused ZSTD_DCtx keeps
 * the stream buffers an earlier, larger frame sized, and a damaged block
 * that overruns this frame's own buffer then fails later and with another
 * code (corruption_detected instead of dstSize_tooSmall) -- the verdict
 * would depend on the requests before it. */
static void opDecode(void)
{
    ZSTD_DCtx* const dctx = ZSTD_createDCtx();
    if (!dctx) die("out of memory");
    int const mode = rd8();
    int const magicless = rd8();
    int const dmode = rd8();
    Blob dict = rdblob();
    Blob src = rdblob();
    size_t r = ZSTD_DCtx_setParameter(dctx, ZSTD_d_format, magicless ? ZSTD_f_zstd1_magicless : ZSTD_f_zstd1);
    if (!ZSTD_isError(r) && mode != 0) r = ZSTD_DCtx_setParameter(dctx, ZSTD_d_windowLogMax, 31);
    if (!ZSTD_isError(r) && dmode == 1) r = ZSTD_DCtx_loadDictionary(dctx, dict.p, dict.n);
    if (!ZSTD_isError(r) && dmode == 2) r = ZSTD_DCtx_refPrefix(dctx, dict.p, dict.n);
    if (ZSTD_isError(r)) {
        replyErr(r);
    } else if (mode == 0) {
        /* zdec.c mode 0: the capacity `Decompressor` gets from the same query */
        unsigned long long const bound = ZSTD_decompressBound(src.p, src.n);
        if (bound == ZSTD_CONTENTSIZE_ERROR) {
            uint8_t one = 1;
            wr(&one, 1);
            wr32(ZSTD_error_srcSize_wrong);
            fflush(stdout);
        } else if (bound > (1u << 30)) {
            uint8_t one = 1;
            wr(&one, 1);
            wr32(ZSTD_error_memory_allocation);
            fflush(stdout);
        } else {
            void* dst = malloc((size_t)bound + 1);
            if (!dst) die("out of memory");
            r = ZSTD_decompressDCtx(dctx, dst, (size_t)bound, src.p, src.n);
            if (ZSTD_isError(r)) replyErr(r); else replyOk(dst, r);
            free(dst);
        }
    } else {
        size_t const ochunk = mode == 1 ? (size_t)1 << 17 : 997;
        uint8_t* obuf = malloc(ochunk);
        size_t outcap = 1 << 16, outn = 0;
        uint8_t* out = malloc(outcap);
        if (!obuf || !out) die("out of memory");
        size_t size = mode == 1 ? src.n : (src.n < 1 ? src.n : 1);
        ZSTD_inBuffer in = { src.p, size, 0 };
        r = 1;
        for (;;) {
            ZSTD_outBuffer o = { obuf, ochunk, 0 };
            r = ZSTD_decompressStream(dctx, &o, &in);
            if (ZSTD_isError(r)) break;
            if (outn + o.pos > outcap) {
                while (outn + o.pos > outcap) outcap *= 2;
                out = realloc(out, outcap);
                if (!out) die("out of memory");
            }
            memcpy(out + outn, obuf, o.pos);
            outn += o.pos;
            if (outn > (1u << 30)) { r = (size_t)-ZSTD_error_memory_allocation; break; }
            if (mode == 2 && in.pos == in.size && size < src.n) {
                size++;
                in.size = size;
                continue;
            }
            if (in.pos == in.size && o.pos < o.size) break;
        }
        if (ZSTD_isError(r)) replyErr(r);
        else if (r != 0) replyErr((size_t)-ZSTD_error_srcSize_wrong);
        else replyOk(out, outn);
        free(obuf);
        free(out);
    }
    free(dict.p);
    free(src.p);
    ZSTD_freeDCtx(dctx);
}

static void opTrain(void)
{
    uint32_t const cap = rd32();
    uint32_t const n = rd32();
    size_t* sizes = malloc(sizeof(size_t) * ((size_t)n + 1));
    if (!sizes) die("out of memory");
    for (uint32_t i = 0; i < n; i++) sizes[i] = rd32();
    Blob samples = rdblob();
    void* dict = malloc((size_t)cap + 1);
    if (!dict) die("out of memory");
    size_t const r = ZDICT_trainFromBuffer(dict, cap, samples.p, sizes, n);
    if (ZDICT_isError(r)) replyErr(r); else replyOk(dict, r);
    free(dict);
    free(sizes);
    free(samples.p);
}

int main(void)
{
    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    if (!cctx) die("out of memory");
    for (;;) {
        int const op = getchar();
        if (op == EOF) return 0;
        switch (op) {
        case 'C': opCompress(cctx); break;
        case 'S': opStream(cctx); break;
        case 'D': opDecode(); break;
        case 'T': opTrain(); break;
        case 'V': replyOk(ZSTD_versionString(), strlen(ZSTD_versionString())); break;
        default: die("unknown request");
        }
    }
}
