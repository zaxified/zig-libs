// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-sealedbox` (modules/sealedbox/tools/bench.zig):
// times libsodium's crypto_box_seal / crypto_box_seal_open over the key pair
// and messages the Zig program writes into the directory given as the only
// argument, and seals one 64-byte message for the Zig side to open (the
// interop check). One line per workload: name, ns/op, the output length.
// libsodium's headers are not installed on every host, so the five
// prototypes are declared here (libsodium's public API, unchanged since 1.0).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int sodium_init(void);
const char *sodium_version_string(void);
int crypto_box_seal(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *pk);
int crypto_box_seal_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *pk, const unsigned char *sk);

#define OVERHEAD 48

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

static volatile int sink;

static void bench(const char *name, int open, const unsigned char *pk, const unsigned char *sk, const unsigned char *msg, size_t len) {
    unsigned char *sealed = malloc(len + OVERHEAD), *out = malloc(len + OVERHEAD);
    if (crypto_box_seal(sealed, msg, len, pk) != 0) { fprintf(stderr, "seal failed\n"); exit(1); }
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++)
            sink += open ? crypto_box_seal_open(out, sealed, len + OVERHEAD, pk, sk) : crypto_box_seal(out, msg, len, pk);
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++)
            if ((open ? crypto_box_seal_open(out, sealed, len + OVERHEAD, pk, sk) : crypto_box_seal(out, msg, len, pk)) != 0) { fprintf(stderr, "%s failed\n", name); exit(1); }
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    printf("%s\t%.1f\t%zu\n", name, best / (double)n, open ? len : len + OVERHEAD);
    free(sealed);
    free(out);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: sodium_bench <work dir>\n"); return 2; }
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    fprintf(stderr, "libsodium %s\n", sodium_version_string());
    unsigned char *pk = slurp(argv[1], "pk.bin", 32), *sk = slurp(argv[1], "sk.bin", 32);
    unsigned char *m64 = slurp(argv[1], "msg64.bin", 64), *m64k = slurp(argv[1], "msg64k.bin", 65536);
    // The interop check: a box sealed here, opened by the Zig side.
    unsigned char sealed[64 + OVERHEAD];
    if (crypto_box_seal(sealed, m64, 64, pk) != 0) return 1;
    char path[4096];
    snprintf(path, sizeof path, "%s/sodium_sealed64.bin", argv[1]);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(sealed, 1, sizeof sealed, f) != sizeof sealed) { perror(path); return 1; }
    fclose(f);
    bench("seal_64", 0, pk, sk, m64, 64);
    bench("seal_64k", 0, pk, sk, m64k, 65536);
    bench("open_64", 1, pk, sk, m64, 64);
    bench("open_64k", 1, pk, sk, m64k, 65536);
    return 0;
}
