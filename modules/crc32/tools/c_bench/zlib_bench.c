// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-crc32` (modules/crc32/tools/bench.zig): times
// zlib's `crc32_z` (the system zlib, linked with -lz) over the buffers the Zig
// program writes into the directory given as the only argument. One line per
// workload: name, ns/op, the CRC (the result count the Zig side compares).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five batches.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static volatile unsigned long sink;

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: zlib_bench <work dir>\n"); return 2; }
    const char *names[] = { "crc_64", "crc_1k", "crc_64k", "crc_1m" };
    const size_t sizes[] = { 64, 1024, 65536, 1 << 20 };
    char path[4096];
    snprintf(path, sizeof path, "%s/data.bin", argv[1]);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    unsigned char *data = malloc(1 << 20);
    if (fread(data, 1, 1 << 20, f) != 1 << 20) { fprintf(stderr, "short data.bin\n"); return 1; }
    fclose(f);
    for (int w = 0; w < 4; w++) {
        size_t n = 1;
        for (;;) {
            double t = now_ns();
            for (size_t i = 0; i < n; i++) sink += crc32_z(0, data, sizes[w]);
            if (now_ns() - t > 1e8) break;
            n *= 2;
        }
        double best = 1e300;
        unsigned long crc = 0;
        for (int k = 0; k < 5; k++) {
            double t = now_ns();
            for (size_t i = 0; i < n; i++) crc = crc32_z(0, data, sizes[w]);
            double d = now_ns() - t;
            if (d < best) best = d;
        }
        printf("%s\t%.1f\t%lu\n", names[w], best / (double)n, crc);
    }
    return 0;
}
