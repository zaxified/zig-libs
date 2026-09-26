/* SPDX-License-Identifier: MIT */
/* zseq -- differential oracle for the sequence-level API of modules/zstd:
 * runs libzstd 1.5.7's ZSTD_generateSequences, ZSTD_mergeBlockDelimiters,
 * ZSTD_compressSequences, ZSTD_compressSequencesAndLiterals, and
 * ZSTD_compress2 / ZSTD_compressStream2 with a registered example sequence
 * producer, the way the module's tests do.
 *
 *   zseq <cmd> <level> <checksum 0|1> <in> <out> <params> <seqs> <capacity> [dict]
 *
 * cmd:
 *   gen          ZSTD_generateSequences into a zeroed buffer of <capacity>
 *                sequences (0: ZSTD_sequenceBound); <out> gets them
 *   merge        ZSTD_mergeBlockDelimiters over <seqs>; <out> gets the rest
 *   cseq         ZSTD_compressSequences(<seqs>, <in>) into <capacity> bytes
 *   clit         ZSTD_compressSequencesAndLiterals(<seqs>, literals of <in>
 *                as the sequences walk it, decompressedSize = size of <in>)
 *   prod:M       register the example producer in mode M, ZSTD_compress2
 *   sprod:M:C    the same through ZSTD_compressStream2, C bytes per
 *                ZSTD_e_continue call, then ZSTD_e_end
 * <params> is zref's comma-separated `name=value` list ("-" for none) with
 * the sequence parameters added (blockDelimiters, validateSequences,
 * repcodeResolution, enableSeqProducerFallback). <seqs> is a file of
 * sequences, 16 bytes each (offset, litLength, matchLength, rep as
 * little-endian u32), or "-". <capacity> 0 is the default: compressBound of
 * the input plus 4 bytes per sequence plus 32. [dict] is `mode:type:file`
 * with mode load, cdict or prefix (zref's meanings).
 *
 * Output: <out> on success; on a libzstd error, `ERR <name>` on stdout and
 * exit 5. The module's counterpart of the example producer is in
 * src/seq_test.zig; the two must stay identical.
 *
 * Build against the pinned libzstd checkout as zref is (multithreaded, for
 * nbWorkers; see gen-goldens.sh):
 *   cc -O2 -DZSTD_MULTITHREAD -DZSTD_DISABLE_ASM -pthread -I "$R/lib" -I "$R/lib/common"
 *       -o zseq zseq.c <the .c files of lib/common, lib/compress, lib/decompress>
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#define ZSTD_DISABLE_DEPRECATE_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

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
    { "nbWorkers", ZSTD_c_nbWorkers },
    { "blockDelimiters", ZSTD_c_blockDelimiters },
    { "validateSequences", ZSTD_c_validateSequences },
    { "repcodeResolution", ZSTD_c_repcodeResolution },
    { "enableSeqProducerFallback", ZSTD_c_enableSeqProducerFallback },
};

static int setParams(ZSTD_CCtx* cctx, char const* list)
{
    if (!strcmp(list, "-")) return 0;
    char* const copy = strdup(list);
    for (char* tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        char const* const eq = strchr(tok, '=');
        size_t i = 0;
        for (; eq && i < sizeof(params) / sizeof(params[0]); i++)
            if (strlen(params[i].name) == (size_t)(eq - tok) && !strncmp(tok, params[i].name, (size_t)(eq - tok))) break;
        if (!eq || i == sizeof(params) / sizeof(params[0])) { fprintf(stderr, "unknown parameter %s\n", tok); return -1; }
        size_t const r = ZSTD_CCtx_setParameter(cctx, params[i].p, atoi(eq + 1));
        if (ZSTD_isError(r)) { printf("ERR %s\n", ZSTD_getErrorName(r)); exit(5); }
    }
    free(copy);
    return 0;
}

static char* readFile(char const* path, size_t* size)
{
    FILE* const f = fopen(path, "rb");
    if (!f) { perror(path); exit(3); }
    fseek(f, 0, SEEK_END);
    long const n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* const buf = malloc((size_t)n + 1);
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("read"); exit(4); }
    fclose(f);
    *size = (size_t)n;
    return buf;
}

static uint32_t rd32(unsigned char const* p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void wr32(unsigned char* p, uint32_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24); }

static ZSTD_Sequence* readSeqs(char const* path, size_t* n)
{
    if (!strcmp(path, "-")) { *n = 0; return calloc(1, sizeof(ZSTD_Sequence)); }
    size_t sz;
    unsigned char* const raw = (unsigned char*)readFile(path, &sz);
    *n = sz / 16;
    ZSTD_Sequence* const s = calloc(*n + 1, sizeof(ZSTD_Sequence));
    for (size_t i = 0; i < *n; i++) {
        s[i].offset = rd32(raw + 16 * i);
        s[i].litLength = rd32(raw + 16 * i + 4);
        s[i].matchLength = rd32(raw + 16 * i + 8);
        s[i].rep = rd32(raw + 16 * i + 12);
    }
    free(raw);
    return s;
}

static void writeSeqs(char const* path, ZSTD_Sequence const* s, size_t n)
{
    FILE* const f = fopen(path, "wb");
    if (!f) { perror(path); exit(6); }
    for (size_t i = 0; i < n; i++) {
        unsigned char b[16];
        wr32(b, s[i].offset);
        wr32(b + 4, s[i].litLength);
        wr32(b + 8, s[i].matchLength);
        wr32(b + 12, s[i].rep);
        fwrite(b, 1, 16, f);
    }
    fclose(f);
}

/* The example producer: greedy matching within the block over a 4096-entry
 * hash of 4 bytes. Mode bits:
 *   0-3  fail every P-th call (P = mode & 15; 0 never)
 *   4    leave the trailing delimiter out (libzstd appends it)
 *   5    return 0 sequences
 *   6    return one more than the capacity
 *   7    last literals one byte too many (sum above the block)
 *   8    accept matches of 3 bytes (else 4)
 *   9    last literals one byte short (sum below the block)
 *   10   the first match's offset 2^20 too large
 *   11   matches cut to 3 bytes
 * The module's `ExampleProducer` (src/seq_test.zig) is the same function. */
typedef struct { unsigned mode; unsigned calls; } Producer;

static size_t produce(void* state, ZSTD_Sequence* out, size_t cap, void const* srcv, size_t n,
                      void const* dict, size_t dictSize, int level, size_t windowSize)
{
    Producer* const p = (Producer*)state;
    unsigned char const* const src = (unsigned char const*)srcv;
    (void)dict; (void)dictSize; (void)level; (void)windowSize;
    unsigned const period = p->mode & 15;
    p->calls++;
    if (period && p->calls % period == 0) return ZSTD_SEQUENCE_PRODUCER_ERROR;
    if (p->mode & 32) return 0;
    if (p->mode & 64) return cap + 1;
    static uint32_t table[4096];
    for (size_t i = 0; i < 4096; i++) table[i] = 0xFFFFFFFFu;
    size_t const mm = (p->mode & 256) ? 3 : 4;
    size_t i = 0, anchor = 0, ns = 0;
    while (i + 4 <= n) {
        uint32_t const h = (rd32(src + i) * 2654435761u) >> 20;
        uint32_t const cand = table[h];
        table[h] = (uint32_t)i;
        if (cand != 0xFFFFFFFFu) {
            size_t len = 0;
            while (i + len < n && src[cand + len] == src[i + len]) len++;
            if ((p->mode & 2048) && len > 3) len = 3;
            if (len >= mm) {
                out[ns].offset = (unsigned)(i - cand);
                if (ns == 0 && (p->mode & 1024)) out[ns].offset += 1u << 20;
                out[ns].litLength = (unsigned)(i - anchor);
                out[ns].matchLength = (unsigned)len;
                out[ns].rep = 0;
                ns++;
                i += len;
                anchor = i;
                continue;
            }
        }
        i++;
    }
    if (!(p->mode & 16)) {
        out[ns].offset = 0;
        out[ns].litLength = (unsigned)(n - anchor);
        if (p->mode & 128) out[ns].litLength++;
        if ((p->mode & 512) && out[ns].litLength) out[ns].litLength--;
        out[ns].matchLength = 0;
        out[ns].rep = 0;
        ns++;
    }
    return ns;
}

static void fail(size_t r)
{
    printf("ERR %s\n", ZSTD_getErrorName(r));
    exit(5);
}

int main(int argc, char** argv)
{
    if (argc < 9 || argc > 10) {
        fprintf(stderr, "usage: zseq <cmd> <level> <checksum> <in> <out> <params> <seqs> <capacity> [dict]\n");
        return 2;
    }
    char const* const cmd = argv[1];
    int const level = atoi(argv[2]);
    size_t n;
    char* const src = readFile(argv[4], &n);
    size_t nseq;
    ZSTD_Sequence* const seqs = readSeqs(argv[7], &nseq);
    size_t const capArg = (size_t)strtoull(argv[8], NULL, 10);

    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, atoi(argv[3]));
    if (setParams(cctx, argv[6])) return 7;

    char* dict = NULL;
    ZSTD_CDict* cdict = NULL;
    if (argc == 10 && strcmp(argv[9], "-")) {
        char const* const c1 = strchr(argv[9], ':');
        char const* const c2 = c1 ? strchr(c1 + 1, ':') : NULL;
        if (!c2) { fprintf(stderr, "bad dict %s\n", argv[9]); return 2; }
        size_t dsize;
        dict = readFile(c2 + 1, &dsize);
        int const ctype = atoi(c1 + 1);
        size_t r = 0;
        if (!strncmp(argv[9], "load:", 5)) {
            r = ZSTD_CCtx_loadDictionary_advanced(cctx, dict, dsize, ZSTD_dlm_byCopy, (ZSTD_dictContentType_e)ctype);
        } else if (!strncmp(argv[9], "cdict:", 6)) {
            cdict = ZSTD_createCDict(dict, dsize, level);
            if (!cdict) { fprintf(stderr, "ZSTD_createCDict failed\n"); return 5; }
            r = ZSTD_CCtx_refCDict(cctx, cdict);
        } else if (!strncmp(argv[9], "prefix:", 7)) {
            r = ZSTD_CCtx_refPrefix_advanced(cctx, dict, dsize, (ZSTD_dictContentType_e)ctype);
        } else { fprintf(stderr, "bad dict mode %s\n", argv[9]); return 2; }
        if (ZSTD_isError(r)) fail(r);
    }

    if (!strcmp(cmd, "gen")) {
        size_t const cap = capArg ? capArg : ZSTD_sequenceBound(n);
        ZSTD_Sequence* const out = calloc(cap + 1, sizeof(ZSTD_Sequence));
        size_t const r = ZSTD_generateSequences(cctx, out, cap, src, n);
        if (ZSTD_isError(r)) fail(r);
        writeSeqs(argv[5], out, r);
        return 0;
    }
    if (!strcmp(cmd, "merge")) {
        size_t const r = ZSTD_mergeBlockDelimiters(seqs, nseq);
        writeSeqs(argv[5], seqs, r);
        return 0;
    }

    size_t const cap = capArg ? capArg : ZSTD_compressBound(n) + 4 * nseq + 32;
    char* const dst = malloc(cap + 1);
    size_t r;
    Producer prod = { 0, 0 };
    if (!strcmp(cmd, "cseq")) {
        r = ZSTD_compressSequences(cctx, dst, cap, seqs, nseq, src, n);
    } else if (!strcmp(cmd, "clit")) {
        /* the literals as the sequences walk the input (clamped to its end) */
        char* const lits = malloc(n + 1);
        size_t pos = 0, nl = 0;
        for (size_t i = 0; i < nseq; i++) {
            size_t ll = seqs[i].litLength;
            if (pos > n) pos = n;
            if (ll > n - pos) ll = n - pos;
            memcpy(lits + nl, src + pos, ll);
            nl += ll;
            pos += (size_t)seqs[i].litLength + seqs[i].matchLength;
        }
        r = ZSTD_compressSequencesAndLiterals(cctx, dst, cap, seqs, nseq, lits, nl, nl + 8, n);
    } else if (!strncmp(cmd, "prod:", 5) || !strncmp(cmd, "sprod:", 6)) {
        char const* const m = strchr(cmd, ':') + 1;
        prod.mode = (unsigned)atoi(m);
        ZSTD_registerSequenceProducer(cctx, &prod, produce);
        if (cmd[0] == 'p') {
            r = ZSTD_compress2(cctx, dst, cap, src, n);
        } else {
            char const* const c = strchr(m, ':');
            size_t const chunk = c ? (size_t)atoi(c + 1) : n;
            ZSTD_outBuffer out = { dst, cap, 0 };
            size_t in = 0;
            r = 0;
            while (!ZSTD_isError(r)) {
                size_t const take = chunk && n - in > chunk ? chunk : n - in;
                ZSTD_inBuffer ib = { src + in, take, 0 };
                ZSTD_EndDirective const end = in + take == n ? ZSTD_e_end : ZSTD_e_continue;
                r = ZSTD_compressStream2(cctx, &out, &ib, end);
                in += ib.pos;
                if (end == ZSTD_e_end && r == 0) break;
            }
            if (!ZSTD_isError(r)) r = out.pos;
        }
    } else {
        fprintf(stderr, "unknown command %s\n", cmd);
        return 2;
    }
    if (ZSTD_isError(r)) fail(r);
    FILE* const f = fopen(argv[5], "wb");
    if (!f) { perror(argv[5]); return 6; }
    fwrite(dst, 1, r, f);
    fclose(f);
    ZSTD_freeCCtx(cctx);
    ZSTD_freeCDict(cdict);
    free(dict);
    free(dst);
    free(seqs);
    free(src);
    return 0;
}
