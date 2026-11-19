/* SPDX-License-Identifier: MIT */
/* zentropy -- libzstd 1.5.7's entropy-table builders on given counts, the
 * reference for src/entropy_kat_test.zig (testdata/entropy_kats.zig): the
 * branches of FSE_normalizeCount (FSE_normalizeM2 among them) and
 * FSE_writeNCount, HUF_optimalTableLog with and without the optimal-depth
 * search, and HUF_writeCTable, which the byte-parity goldens never reach
 * with the distributions real inputs produce.
 *
 * One request per stdin line, one answer per line on stdout:
 *
 *   norm <tableLog> <useLowProb 0|1> <maxSymbol> <count0> .. <countMax>
 *     -> "norm <tableLogUsed> <n0> .. <nMax> nc <least> <hex> full <hex>"
 *        FSE_normalizeCount (total = sum of counts), then FSE_writeNCount
 *        into every capacity from 0 up: <least> is the first one it accepts,
 *        <hex> the bytes written there; then the bytes written with ample
 *        room (4096). "norm err" when normalizing fails.
 *   huf <maxTableLog> <depth 0|1> <maxSymbol> <count0> .. <countMax>
 *     -> "huf <optimalLog> <builtLog> wt <least> <hex> full <hex>"
 *        HUF_optimalTableLog (HUF_flags_optimalDepth when <depth> is 1),
 *        HUF_buildCTable_wksp at that log, then HUF_writeCTable_wksp into
 *        every capacity from 0 up, as for norm. With little room the
 *        weights go raw where ample room codes them with FSE: the FSE
 *        payload needs 8 bytes of slack (BIT_initCStream).
 *
 * Build against the pinned libzstd checkout (gen-entropy-kats.sh does):
 *   cc -O2 -DZSTD_DISABLE_ASM -I "$R/lib" -I "$R/lib/common" -o zentropy \
 *      zentropy.c $R/lib/common/*.c $R/lib/compress/*.c $R/lib/decompress/*.c
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define FSE_STATIC_LINKING_ONLY
#define HUF_STATIC_LINKING_ONLY
#include <stdio.h>
#include <string.h>
#include "fse.h"
#include "huf.h"

static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static int read_counts(unsigned *ms, unsigned *counts, size_t *total) {
    if (scanf("%u", ms) != 1 || *ms > 255) return 0;
    *total = 0;
    for (unsigned s = 0; s <= *ms; s++) {
        if (scanf("%u", &counts[s]) != 1) return 0;
        *total += counts[s];
    }
    return 1;
}

int main(void) {
    char cmd[16];
    static unsigned char buf[4096];
    while (scanf("%15s", cmd) == 1) {
        unsigned counts[256], ms, a, b;
        size_t total;
        if (scanf("%u %u", &a, &b) != 2 || !read_counts(&ms, counts, &total)) return 2;
        if (strcmp(cmd, "norm") == 0) {
            short norm[256];
            size_t tl = FSE_normalizeCount(norm, a, counts, total, ms, b);
            if (FSE_isError(tl)) { printf("norm err\n"); continue; }
            printf("norm %u", (unsigned)tl);
            for (unsigned s = 0; s <= ms; s++) printf(" %d", norm[s]);
            for (size_t cap = 0; cap <= sizeof buf; cap++) {
                memset(buf, 0xAA, sizeof buf);
                size_t n = FSE_writeNCount(buf, cap, norm, ms, (unsigned)tl);
                if (FSE_isError(n)) continue;
                printf(" nc %u ", (unsigned)cap);
                hex(buf, n);
                break;
            }
            {
                size_t n = FSE_writeNCount(buf, sizeof buf, norm, ms, (unsigned)tl);
                printf(" full ");
                hex(buf, n);
            }
            printf("\n");
        } else if (strcmp(cmd, "huf") == 0) {
            static U64 wksp[HUF_WORKSPACE_SIZE_U64];
            HUF_CREATE_STATIC_CTABLE(ct, HUF_SYMBOLVALUE_MAX);
            memset(ct, 0, sizeof ct);
            unsigned opt = HUF_optimalTableLog(a, total, ms, wksp, sizeof wksp, ct, counts, b ? HUF_flags_optimalDepth : 0);
            memset(ct, 0, sizeof ct);
            size_t built = HUF_buildCTable_wksp(ct, counts, ms, opt, wksp, sizeof wksp);
            if (HUF_isError(built)) { printf("huf %u err\n", opt); continue; }
            printf("huf %u %u", opt, (unsigned)built);
            for (size_t cap = 0; cap <= sizeof buf; cap++) {
                memset(buf, 0xAA, sizeof buf);
                size_t n = HUF_writeCTable_wksp(buf, cap, ct, ms, (unsigned)built, wksp, sizeof wksp);
                if (HUF_isError(n)) continue;
                printf(" wt %u ", (unsigned)cap);
                hex(buf, n);
                break;
            }
            {
                size_t n = HUF_writeCTable_wksp(buf, sizeof buf, ct, ms, (unsigned)built, wksp, sizeof wksp);
                printf(" full ");
                hex(buf, n);
            }
            printf("\n");
        } else {
            return 2;
        }
    }
    return 0;
}
