// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-ripemd160` (modules/ripemd160/tools/bench.zig):
// times OpenSSL libcrypto's one-shot RIPEMD160() over the messages the Zig
// program writes into the directory given as the only argument, and writes
// each digest to <name>.digest for the Zig side to compare (the interop
// check). One line per workload: name, ns/op, the number of bytes hashed.
// libcrypto's headers are not needed: the one prototype is declared here
// (OpenSSL's public API, unchanged since 0.9.x; in OpenSSL 3 the function is
// still exported by libcrypto.so.3 although the algorithm is "legacy").
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned char *RIPEMD160(const unsigned char *d, size_t n, unsigned char *md);

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static unsigned char *slurp(const char *dir, const char *name, size_t want) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    unsigned char *b = malloc(want);
    if (fread(b, 1, want, f) != want) { fprintf(stderr, "short %s\n", path); exit(1); }
    fclose(f);
    return b;
}

static volatile unsigned char sink;

static void bench(const char *dir, const char *name, const char *file, size_t len) {
    unsigned char *msg = slurp(dir, file, len);
    unsigned char md[20];
    RIPEMD160(msg, len, md);
    char path[4096];
    snprintf(path, sizeof path, "%s/%s.digest", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(md, 1, 20, f) != 20) { perror(path); exit(1); }
    fclose(f);
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) { RIPEMD160(msg, len, md); sink ^= md[0]; }
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) { RIPEMD160(msg, len, md); sink ^= md[0]; }
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    printf("%s\t%.1f\t%zu\n", name, best / (double)n, len);
    free(msg);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: openssl_bench <work dir>\n"); return 2; }
    bench(argv[1], "hash_64", "msg64.bin", 64);
    bench(argv[1], "hash_64k", "msg64k.bin", 65536);
    bench(argv[1], "hash_1m", "msg1m.bin", 1 << 20);
    return 0;
}
