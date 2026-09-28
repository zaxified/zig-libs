/* SPDX-License-Identifier: MIT */
/* zparams -- differential oracle: libzstd's parameter queries
 * (ZSTD_adjustCParams, ZSTD_getCParams) over any list of arguments.
 *
 *   zparams < grid.txt > answers.txt
 *
 * Each input line is one query, each output line its answer
 * "windowLog chainLog hashLog searchLog minMatch targetLength strategy":
 *
 *   a <windowLog> <chainLog> <hashLog> <searchLog> <minMatch> <targetLength> <strategy> <srcSize> <dictSize>
 *       ZSTD_adjustCParams(cParams, srcSize, dictSize) -- the module's
 *       `zstd.adjustCParams(cp, src_size, dict_size)`
 *   g <level> <srcSize> <dictSize>
 *       ZSTD_getCParams(level, srcSize, dictSize) -- `zstd.getCParams`
 *
 * srcSize 0 is "unknown" to both, as ZSTD_CONTENTSIZE_UNKNOWN is. The values
 * are read as unsigned 64-bit numbers (the level as a signed int) and passed
 * as they are: a parameter above INT_MAX is what ZSTD_adjustCParams' clamp
 * sees as negative. `dump_corpus.zig` writes the grid the tests pin
 * (`corpus.cparamsSample`), `gen-goldens.sh` its digest.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zparams zparams.c "$R/lib/libzstd.a"
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#define ZSTD_STATIC_LINKING_ONLY
#include <stdio.h>
#include <stdlib.h>
#include "zstd.h"

int main(void)
{
    char line[512];
    while (fgets(line, sizeof line, stdin)) {
        ZSTD_compressionParameters cp;
        if (line[0] == 'a') {
            unsigned long long v[9];
            if (sscanf(line + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8]) != 9) {
                fprintf(stderr, "bad line: %s", line);
                return 2;
            }
            cp.windowLog = (unsigned)v[0];
            cp.chainLog = (unsigned)v[1];
            cp.hashLog = (unsigned)v[2];
            cp.searchLog = (unsigned)v[3];
            cp.minMatch = (unsigned)v[4];
            cp.targetLength = (unsigned)v[5];
            cp.strategy = (ZSTD_strategy)v[6];
            cp = ZSTD_adjustCParams(cp, v[7], (size_t)v[8]);
        } else if (line[0] == 'g') {
            int level;
            unsigned long long src, dict;
            if (sscanf(line + 1, "%d %llu %llu", &level, &src, &dict) != 3) {
                fprintf(stderr, "bad line: %s", line);
                return 2;
            }
            cp = ZSTD_getCParams(level, src, (size_t)dict);
        } else {
            fprintf(stderr, "bad line: %s", line);
            return 2;
        }
        printf("%u %u %u %u %u %u %u\n", cp.windowLog, cp.chainLog, cp.hashLog, cp.searchLog, cp.minMatch, cp.targetLength, (unsigned)cp.strategy);
    }
    return 0;
}
