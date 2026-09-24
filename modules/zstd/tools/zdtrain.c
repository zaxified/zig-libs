/* SPDX-License-Identifier: MIT */
/* zdtrain -- part of the golden recipe: train a zstd-format dictionary with
 * libzstd's ZDICT_trainFromBuffer (fastCover, d=8, 4 steps, one thread: the
 * result is deterministic) on sample files.
 *
 *   zdtrain <out> <capacity> <sample>...
 *
 * gen-goldens.sh trains the dictionaries `corpus.train_sets` names on the
 * samples dump_corpus.zig writes, and the golden tests embed the result
 * (the `.zdict` files in src/testdata), whose digest they pin.
 *
 * Build against the pinned libzstd checkout (see README.md):
 *   cc -O2 -I "$R/lib" -o zdtrain zdtrain.c "$R/lib/libzstd.a"
 *
 * This file is a foreign-toolchain instrument (CONVENTIONS.md §2, §9): no
 * module build compiles it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zdict.h"

int main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: zdtrain <out> <capacity> <sample>...\n");
        return 2;
    }
    size_t const cap = (size_t)atol(argv[2]);
    unsigned const nb = (unsigned)(argc - 3);
    size_t* const sizes = malloc(nb * sizeof(size_t));
    size_t total = 0, used = 0;
    char* samples = NULL;
    for (unsigned i = 0; i < nb; i++) {
        FILE* const f = fopen(argv[3 + i], "rb");
        if (!f) { perror(argv[3 + i]); return 3; }
        fseek(f, 0, SEEK_END);
        long const n = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (used + (size_t)n > total) {
            total = 2 * (used + (size_t)n);
            samples = realloc(samples, total);
        }
        if (n && fread(samples + used, 1, (size_t)n, f) != (size_t)n) { perror("read"); return 4; }
        fclose(f);
        sizes[i] = (size_t)n;
        used += (size_t)n;
    }
    char* const dict = malloc(cap);
    size_t const r = ZDICT_trainFromBuffer(dict, cap, samples, sizes, nb);
    if (ZDICT_isError(r)) { fprintf(stderr, "%s\n", ZDICT_getErrorName(r)); return 5; }
    FILE* const out = fopen(argv[1], "wb");
    if (!out) { perror(argv[1]); return 6; }
    fwrite(dict, 1, r, out);
    fclose(out);
    free(dict);
    free(samples);
    free(sizes);
    return 0;
}
