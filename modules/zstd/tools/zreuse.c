/* SPDX-License-Identifier: MIT */
/* zreuse -- does libzstd give a reused compression context the bytes of a
 * fresh one? The module's golden tests run every frame through one reused
 * context against goldens made on fresh contexts; that is only sound while
 * the answer is yes (SPEC.md, *Contexts*). Re-run it when the pinned libzstd
 * changes.
 *
 *   zreuse <input> <seed> <frames> <mode 0 one-shot | 1 stream | 2 mixed>
 *          [<min level> <max level>]
 *
 * Each frame is a random slice of <input> (0 .. ~1 MB) at a random level,
 * with or without checksum, half of the frames with random explicit
 * parameters (window, strategy, search log, minimum match, row match finder,
 * LDM), compressed once on a context reused across all frames and once on a
 * fresh one -- by ZSTD_compress2, or by ZSTD_compressStream2 with random
 * chunks, flushes and 70 000-byte output buffers. Prints "DIFF ..." for a
 * frame that differs and "frames N diffs D" at the end.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zreuse zreuse.c "$R/lib/libzstd.a"
 * and, to exercise the index overflow correction on reused contexts, with
 * -DZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY=1 from the library's sources, as
 * gen-goldens.sh builds zref-ocf.
 * A build with -DDEBUGLEVEL=4 logs "reset indices : 0" for each frame that
 * continued its indexing -- the check that the reuse path was taken.
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zstd.h"

static unsigned long long state;

/* splitmix64 */
static unsigned long long rnd(void)
{
    unsigned long long z = (state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void check(size_t r)
{
    if (ZSTD_isError(r)) {
        fprintf(stderr, "error: %s\n", ZSTD_getErrorName(r));
        exit(2);
    }
}

/* One frame through ZSTD_compressStream2, cut by a schedule drawn from
 * `seed` (the same for both contexts). */
static size_t stream(ZSTD_CCtx* c, char* dst, size_t cap, const char* src, size_t n, unsigned long long seed)
{
    unsigned long long saved = state;
    size_t op = 0, ip = 0;
    state = seed;
    for (;;) {
        size_t const chunk = ip < n ? 1 + rnd() % (n - ip) : 0;
        int const last = ip + chunk >= n;
        ZSTD_EndDirective const dir = last ? ZSTD_e_end : (rnd() % 4 == 0 ? ZSTD_e_flush : ZSTD_e_continue);
        ZSTD_inBuffer in = { src + ip, chunk, 0 };
        for (;;) {
            ZSTD_outBuffer out = { dst + op, cap - op < 70000 ? cap - op : 70000, 0 };
            size_t const r = ZSTD_compressStream2(c, &out, &in, dir);
            check(r);
            op += out.pos;
            if (in.pos == in.size && (r == 0 || !last)) break;
        }
        ip += chunk;
        if (last) break;
    }
    state = saved;
    return op;
}

int main(int argc, char** argv)
{
    FILE* f;
    size_t n, cap;
    char *buf, *out[2];
    int frames, mode, lmin, lmax, diffs = 0, i, k;
    ZSTD_CCtx* reused;
    if (argc < 5) {
        fprintf(stderr, "usage: zreuse <input> <seed> <frames> <mode 0|1|2> [<min level> <max level>]\n");
        return 2;
    }
    f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(n);
    if (fread(buf, 1, n, f) != n) { perror("read"); return 2; }
    fclose(f);
    state = strtoull(argv[2], 0, 10);
    frames = atoi(argv[3]);
    mode = atoi(argv[4]);
    lmin = argc > 5 ? atoi(argv[5]) : -5;
    lmax = argc > 6 ? atoi(argv[6]) : 19;
    reused = ZSTD_createCCtx();
    cap = ZSTD_compressBound(n) + 1000;
    out[0] = malloc(cap);
    out[1] = malloc(cap);
    for (i = 0; i < frames; i++) {
        int const level = lmin + (int)(rnd() % (unsigned)(lmax - lmin + 1));
        size_t len = rnd() % 4 == 0 ? rnd() % 2000 : ((size_t)1 << (rnd() % 21)) + rnd() % 100000;
        size_t off, sizes[2];
        int ck, st, adv, wl, strat, row, sl, mm, ldm;
        unsigned long long seed;
        ZSTD_CCtx* cs[2];
        if (len > n) len = n;
        off = rnd() % (n - len + 1);
        ck = rnd() % 2;
        st = mode == 2 ? (int)(rnd() % 2) : mode;
        seed = rnd();
        adv = rnd() % 2; wl = 10 + rnd() % 15; strat = 1 + rnd() % 9; row = rnd() % 3;
        sl = 1 + rnd() % 8; mm = 3 + rnd() % 5; ldm = rnd() % 4 == 0;
        cs[0] = reused;
        cs[1] = ZSTD_createCCtx();
        for (k = 0; k < 2; k++) {
            ZSTD_CCtx* const c = cs[k];
            check(ZSTD_CCtx_reset(c, ZSTD_reset_session_and_parameters));
            check(ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level));
            check(ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, ck));
            if (adv) {
                check(ZSTD_CCtx_setParameter(c, ZSTD_c_windowLog, wl));
                check(ZSTD_CCtx_setParameter(c, ZSTD_c_strategy, strat));
                check(ZSTD_CCtx_setParameter(c, ZSTD_c_useRowMatchFinder, row));
                check(ZSTD_CCtx_setParameter(c, ZSTD_c_searchLog, sl));
                check(ZSTD_CCtx_setParameter(c, ZSTD_c_minMatch, mm));
                check(ZSTD_CCtx_setParameter(c, ZSTD_c_enableLongDistanceMatching, ldm));
            }
            sizes[k] = st ? stream(c, out[k], cap, buf + off, len, seed) : ZSTD_compress2(c, out[k], cap, buf + off, len);
            check(sizes[k]);
        }
        ZSTD_freeCCtx(cs[1]);
        if (sizes[0] != sizes[1] || memcmp(out[0], out[1], sizes[0]) != 0) {
            diffs++;
            printf("DIFF frame %d level %d len %zu stream %d: %zu vs %zu\n", i, level, len, st, sizes[0], sizes[1]);
        }
    }
    printf("frames %d diffs %d\n", frames, diffs);
    ZSTD_freeCCtx(reused);
    return diffs != 0;
}
