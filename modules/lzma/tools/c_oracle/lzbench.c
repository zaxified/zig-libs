// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-lzma` (modules/lzma/tools/bench.zig): times
// liblzma 5.8.1 (compiled from the pinned clone together with this file) on
// the payloads the Zig program writes into the work directory (argv[1]).
//
//   lzbench <dir> enc<P>_<kind>   lzma_stream_encoder, preset P, CRC-64, into a
//                                 buffer allocated once; prints the compressed size
//   lzbench <dir> dec<P>_<kind>   lzma_stream_decoder of <kind>.<P>.ref.xz into a
//                                 buffer allocated once; prints the plain size
//   lzbench <dir> prep            writes <kind>.<P>.ref.xz for P in 1, 6, 9
//
// Output for a workload: `name \t ns/op \t count`. Timing as the Zig side:
// double the batch until it takes over 100 ms, then the best of five batches.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "lzma.h"

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

static size_t compress_once(unsigned char *dst, size_t cap, unsigned char *src, size_t n, int preset) {
    lzma_options_lzma o;
    if (lzma_lzma_preset(&o, (uint32_t)preset)) { fprintf(stderr, "bad preset\n"); exit(1); }
    lzma_filter f[2] = { { .id = LZMA_FILTER_LZMA2, .options = &o }, { .id = LZMA_VLI_UNKNOWN } };
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_stream_encoder(&s, f, LZMA_CHECK_CRC64) != LZMA_OK) { fprintf(stderr, "init\n"); exit(1); }
    s.next_in = src;
    s.avail_in = n;
    s.next_out = dst;
    s.avail_out = cap;
    lzma_ret r = lzma_code(&s, LZMA_FINISH);
    if (r != LZMA_STREAM_END) { fprintf(stderr, "compress: %d\n", r); exit(1); }
    size_t out = cap - s.avail_out;
    lzma_end(&s);
    return out;
}

static size_t decompress_once(unsigned char *dst, size_t cap, unsigned char *src, size_t n) {
    lzma_stream s = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&s, UINT64_MAX, 0) != LZMA_OK) { fprintf(stderr, "init\n"); exit(1); }
    s.next_in = src;
    s.avail_in = n;
    s.next_out = dst;
    s.avail_out = cap;
    lzma_ret r = lzma_code(&s, LZMA_FINISH);
    if (r != LZMA_STREAM_END) { fprintf(stderr, "decompress: %d\n", r); exit(1); }
    size_t out = cap - s.avail_out;
    lzma_end(&s);
    return out;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: lzbench <dir> <workload>\n"); return 2; }
    const char *dir = argv[1], *w = argv[2];
    fprintf(stderr, "liblzma %s\n", lzma_version_string());
    static const int presets[] = { 1, 6, 9 };
    if (!strcmp(w, "prep")) {
        for (int k = 0; k < 2; k++) {
            char name[64];
            snprintf(name, sizeof name, "%s.bin", kinds[k]);
            size_t n;
            unsigned char *plain = slurp(dir, name, &n);
            size_t cap = n + n / 2 + 4096;
            unsigned char *dst = malloc(cap);
            for (int i = 0; i < 3; i++) {
                size_t c = compress_once(dst, cap, plain, n, presets[i]);
                snprintf(name, sizeof name, "%s.%d.ref.xz", kinds[k], presets[i]);
                spit(dir, name, dst, c);
                printf("%s %d %zu\n", kinds[k], presets[i], c);
            }
        }
        return 0;
    }
    int dec = !strncmp(w, "dec", 3);
    if (!dec && strncmp(w, "enc", 3)) { fprintf(stderr, "bad workload %s\n", w); return 2; }
    int preset = w[3] - '0';
    const char *kind = w + 5;
    char name[64];
    snprintf(name, sizeof name, "%s.bin", kind);
    size_t n;
    unsigned char *plain = slurp(dir, name, &n);
    size_t cap = n + n / 2 + 4096;
    unsigned char *buf = malloc(cap);
    unsigned char *packed = NULL;
    size_t pn = 0;
    if (dec) {
        snprintf(name, sizeof name, "%s.%d.ref.xz", kind, preset);
        packed = slurp(dir, name, &pn);
    }
    volatile size_t sink = 0;
    size_t count = 0;
#define OP() do { \
        if (dec) count = decompress_once(buf, cap, packed, pn); \
        else count = compress_once(buf, cap, plain, n, preset); \
        sink += count; \
    } while (0)
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
    printf("%s\t%.1f\t%zu\n", w, best / (double)reps, count);
    return 0;
}
