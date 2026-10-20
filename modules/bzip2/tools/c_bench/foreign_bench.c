// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-bzip2` (modules/bzip2/tools/bench.zig): times
// libbzip2 1.0.8 (compiled from the pinned clone together with this file) on
// the payloads the Zig program writes into the work directory (argv[1]).
//
//   foreign_bench <dir> enc<L>_<kind>   BZ2_bzBuffToBuffCompress, level L, into a
//                                       buffer allocated once; prints the compressed size
//   foreign_bench <dir> dec<L>_<kind>   BZ2_bzBuffToBuffDecompress of <kind>.<L>.ref.bz2 into a
//                                       buffer allocated once; prints the plain size
//   foreign_bench <dir> prep            writes <kind>.<L>.ref.bz2 for L in 1, 9
//
// Output for a workload: `name \t ns/op \t count`, the banner on stderr.
// Timing as the Zig side: double the batch until it takes over 100 ms, then
// the best of five batches.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bzlib.h"

static const char *kinds[] = { "text", "binary" };

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static unsigned char *slurp(const char *dir, const char *name, size_t *n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(*n + 1);
    if (fread(b, 1, *n, f) != *n) { fprintf(stderr, "short read %s\n", path); exit(1); }
    fclose(f);
    return b;
}

static void spit(const char *dir, const char *name, const void *p, size_t n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(p, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);
}

static unsigned compress_once(unsigned char *dst, size_t cap, unsigned char *src, size_t n, int level) {
    unsigned int out = (unsigned int)cap;
    int r = BZ2_bzBuffToBuffCompress((char *)dst, &out, (char *)src, (unsigned int)n, level, 0, 30);
    if (r != BZ_OK) { fprintf(stderr, "compress: %d\n", r); exit(1); }
    return out;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <dir> <workload>\n"); return 2; }
    const char *dir = argv[1], *w = argv[2];
    fprintf(stderr, "libbzip2 %s\n", BZ2_bzlibVersion());
    if (!strcmp(w, "prep")) {
        for (int k = 0; k < 2; k++) {
            char name[64];
            snprintf(name, sizeof name, "%s.bin", kinds[k]);
            size_t n;
            unsigned char *plain = slurp(dir, name, &n);
            size_t cap = n + n / 100 + 1024;
            unsigned char *dst = malloc(cap);
            for (int level = 1; level <= 9; level += 8) {
                unsigned c = compress_once(dst, cap, plain, n, level);
                snprintf(name, sizeof name, "%s.%d.ref.bz2", kinds[k], level);
                spit(dir, name, dst, c);
                printf("%s %d %u\n", kinds[k], level, c);
            }
        }
        return 0;
    }
    int dec = !strncmp(w, "dec", 3);
    if (!dec && strncmp(w, "enc", 3)) { fprintf(stderr, "bad workload %s\n", w); return 2; }
    int level = w[3] - '0';
    const char *kind = w + 5;
    char name[64];
    snprintf(name, sizeof name, "%s.bin", kind);
    size_t n;
    unsigned char *plain = slurp(dir, name, &n);
    size_t cap = n + n / 100 + 1024;
    unsigned char *buf = malloc(cap > n + 1 ? cap : n + 1);
    unsigned char *packed = NULL;
    size_t pn = 0;
    if (dec) {
        snprintf(name, sizeof name, "%s.%d.ref.bz2", kind, level);
        packed = slurp(dir, name, &pn);
    }
    volatile unsigned sink = 0;
#define OP() do { \
        if (dec) { \
            unsigned int out = (unsigned int)(n + 1); \
            int r = BZ2_bzBuffToBuffDecompress((char *)buf, &out, (char *)packed, (unsigned int)pn, 0, 0); \
            if (r != BZ_OK) { fprintf(stderr, "decompress: %d\n", r); return 1; } \
            count = out; \
        } else count = compress_once(buf, cap, plain, n, level); \
        sink += (unsigned)count; \
    } while (0)
    unsigned long count = 0;
    size_t reps = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < reps; i++) OP();
        if (now_ns() - t > 1e8) break;
        reps *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (size_t i = 0; i < reps; i++) OP();
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    printf("%s\t%.1f\t%lu\n", w, best / (double)reps, count);
    return 0;
}
