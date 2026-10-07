// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-fastmem` (modules/fastmem/tools/bench.zig): times
// the libc `memset` this file is linked against (the program builds it twice,
// with musl-gcc -static and with zig cc against glibc) over the canvas the Zig
// program writes into the directory given as the only argument. One line per
// workload: name, ns/op, FNV-1a of the canvas after one memset (the equality
// check: every side must produce the same bytes). Timing matches the Zig side:
// double the batch until it takes over 100 ms, then keep the best of five.
//
// The call goes through a volatile function pointer so no compiler can turn it
// into inline stores or drop it; -fno-builtin keeps `memset` a real call.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PAT 0xA5
#define CANVAS ((1u << 20) + 256)
#define MISALIGN 5

static void *(*volatile memset_fn)(void *, int, size_t) = memset;

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static uint64_t fnv(const unsigned char *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ull;
    return h;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: memset_bench <work dir>\n"); return 2; }
    char path[4096];
    snprintf(path, sizeof path, "%s/canvas.bin", argv[1]);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    size_t total = CANVAS;
    unsigned char *pristine = malloc(total);
    unsigned char *canvas = aligned_alloc(64, (total + 63) & ~(size_t)63);
    if (fread(pristine, 1, total, f) != total) { fprintf(stderr, "short canvas\n"); return 1; }
    fclose(f);

    static const size_t sizes[] = {16, 256, 4096, 65536, 1u << 20};
    static const char *snames[] = {"16", "256", "4k", "64k", "1m"};
    for (int s = 0; s < 5; s++) {
        for (int mis = 0; mis < 2; mis++) {
            size_t off = mis ? MISALIGN : 0, len = sizes[s];
            // Equality fingerprint: one memset over a pristine canvas.
            memcpy(canvas, pristine, total);
            memset_fn(canvas + 64 + off, PAT, len);
            uint64_t h = fnv(canvas, total);
            unsigned char *p = canvas + 64 + off;
            size_t n = 1;
            for (;;) {
                double t = now_ns();
                for (size_t i = 0; i < n; i++) memset_fn(p, PAT, len);
                if (now_ns() - t > 1e8) break;
                n *= 2;
            }
            double best = 1e300;
            for (int k = 0; k < 5; k++) {
                double t = now_ns();
                for (size_t i = 0; i < n; i++) memset_fn(p, PAT, len);
                double d = now_ns() - t;
                if (d < best) best = d;
            }
            printf("set_%s_%s\t%.2f\t%llu\n", snames[s], mis ? "u" : "a", best / (double)n, (unsigned long long)h);
        }
    }
    return 0;
}
