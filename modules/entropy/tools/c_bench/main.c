// SPDX-License-Identifier: MIT

// C side of `zig build bench-entropy` (modules/entropy/tools/bench.zig): times
// glibc's `arc4random_buf` (2.36+; 2.41+ takes the vDSO getrandom) and the bare
// `getrandom(2)` syscall wrapper on the same three buffer sizes, with the Go
// side's timing (double the batch until it takes over 100 ms, best of five).
// Usage: cbench arc4random | getrandom. One line per workload: name, ns/op, length.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int use_getrandom;
static unsigned char sink;

static void draw(unsigned char *buf, size_t len) {
    if (use_getrandom) {
        size_t got = 0;
        while (got < len) {
            ssize_t n = getrandom(buf + got, len - got, 0);
            if (n < 0) { perror("getrandom"); exit(1); }
            got += (size_t)n;
        }
    } else {
        arc4random_buf(buf, len);
    }
    sink ^= buf[0];
    __asm__ volatile("" : : "r"(buf) : "memory");
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    use_getrandom = strcmp(argv[1], "getrandom") == 0;
    const char *names[] = {"fill_32", "fill_4k", "fill_1m"};
    size_t sizes[] = {32, 4096, 1 << 20};
    for (int w = 0; w < 3; w++) {
        unsigned char *buf = malloc(sizes[w]);
        long n = 1;
        for (;;) {
            double t = now_ns();
            for (long i = 0; i < n; i++) draw(buf, sizes[w]);
            if (now_ns() - t > 100e6) break;
            n *= 2;
        }
        double best = 1e300;
        for (int k = 0; k < 5; k++) {
            double t = now_ns();
            for (long i = 0; i < n; i++) draw(buf, sizes[w]);
            double d = now_ns() - t;
            if (d < best) best = d;
        }
        printf("%s\t%.1f\t%zu\n", names[w], best / (double)n, sizes[w]);
        free(buf);
    }
    return sink == 255 ? 3 : 0;
}
