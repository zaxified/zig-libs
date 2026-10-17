// SPDX-License-Identifier: MIT
//
// libsodium side of `zig build bench-b64ct` (modules/b64ct/tools/bench.zig):
// times sodium_bin2base64 / sodium_base642bin from libsodium 1.0.22's
// codecs.c (compiled with the shim headers, tools/sodium_shim/) over the
// inputs the Zig program writes into the directory given as argv[1], and
// writes each output to <name>.out for the Zig side to compare first.
// One line per workload: name, ns/op, output length. Timing matches the Zig
// side: double the batch until it takes over 50 ms, then keep the best of
// argv[2] rounds.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char *sodium_bin2base64(char *const b64, const size_t b64_maxlen,
                        const unsigned char *const bin, const size_t bin_len,
                        const int variant);
int sodium_base642bin(unsigned char *const bin, const size_t bin_maxlen,
                      const char *const b64, const size_t b64_len,
                      const char *const ignore, size_t *const bin_len,
                      const char **const b64_end, const int variant);

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static unsigned char *slurp(const char *dir, const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(*len + 1);
    if (fread(b, 1, *len, f) != *len) { fprintf(stderr, "short %s\n", path); exit(1); }
    fclose(f);
    return b;
}

static void spill(const char *dir, const char *name, const void *b, size_t n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s.out", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(b, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);
}

static volatile unsigned char sink;
static int rounds = 5;

enum op { ENC, DEC, DEC_IGN };

static void bench(const char *dir, const char *name, const char *file, enum op op) {
    size_t len;
    unsigned char *in = slurp(dir, file, &len);
    size_t cap = len * 2 + 16;
    unsigned char *out = malloc(cap);
    size_t n_out = 0;
#define RUN()                                                                       \
    do {                                                                            \
        if (op == ENC) {                                                            \
            sodium_bin2base64((char *)out, cap, in, len, 1);                        \
            n_out = (len + 2) / 3 * 4;                                              \
        } else if (sodium_base642bin(out, cap, (const char *)in, len,               \
                                     op == DEC_IGN ? "\n" : NULL, &n_out, NULL, 1)) { \
            fprintf(stderr, "%s: decode failed\n", name);                           \
            exit(1);                                                                \
        }                                                                           \
        sink ^= out[0];                                                             \
    } while (0)
    RUN();
    spill(dir, name, out, n_out);
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) RUN();
        if (now_ns() - t > 5e7) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < rounds; k++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) RUN();
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    printf("%s\t%.2f\t%zu\n", name, best / (double)n, n_out);
    free(in);
    free(out);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: sodium_bench <work dir> <rounds>\n"); return 2; }
    rounds = atoi(argv[2]);
    bench(argv[1], "enc_32", "bin32", ENC);
    bench(argv[1], "enc_1k", "bin1k", ENC);
    bench(argv[1], "enc_64k", "bin64k", ENC);
    bench(argv[1], "dec_32", "b64_32", DEC);
    bench(argv[1], "dec_1k", "b64_1k", DEC);
    bench(argv[1], "dec_64k", "b64_64k", DEC);
    bench(argv[1], "dec_pem_4k", "pem_4k", DEC_IGN);
    return 0;
}
