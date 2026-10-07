// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-hqc` (modules/hqc/tools/bench.zig): times the HQC
// v5.0.0 authors' crypto_kem_keypair / crypto_kem_enc / crypto_kem_dec. Built
// by the Zig program with `zig cc` straight from the reference's sources (one
// build per parameter set and lane); the reference's build system is never run.
//
// usage: hqc_bench <outdir> <seed_hex_96> <tag>
//
// First it seeds the reference PRNG with the 48-byte seed (the same flow as
// the reference's own KAT harness and as oracle_hqc.c: prng_init, keypair,
// enc, dec) and writes pk/sk/ct/ss to <outdir>/<tag>.{pk,sk,ct,ss} for the Zig
// side to compare byte for byte. Then one line per workload: name, ns/op,
// output length. Timing matches the Zig side: double the batch until it takes
// over 100 ms, then keep the best of five. Not copied from the reference.
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"
#include "symmetric.h"

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss2[CRYPTO_BYTES];
static unsigned char pk2[CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
static unsigned char ct2[CRYPTO_CIPHERTEXTBYTES];
static volatile int sink;

static int op(int which) {
    switch (which) {
    case 0: return crypto_kem_keypair(pk2, sk2);
    case 1: return crypto_kem_enc(ct2, ss2, pk);
    default: return crypto_kem_dec(ss2, ct, sk);
    }
}

static void bench(const char *name, int which, size_t outlen) {
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) sink += op(which);
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++)
            if (op(which) != 0) { fprintf(stderr, "%s failed\n", name); exit(1); }
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    printf("%s\t%.1f\t%zu\n", name, best / (double)n, outlen);
}

static void dump(const char *dir, const char *tag, const char *ext, const unsigned char *b, size_t n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s.%s", dir, tag, ext);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(b, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);
}

int main(int argc, char **argv) {
    unsigned char seed[48];
    if (argc != 4 || strlen(argv[2]) != 96) { fprintf(stderr, "usage: hqc_bench outdir seed96hex tag\n"); return 2; }
    for (int i = 0; i < 48; i++) { unsigned x; sscanf(argv[2] + 2 * i, "%2x", &x); seed[i] = (unsigned char)x; }

    prng_init(seed, NULL, 48, 0);
    if (crypto_kem_keypair(pk, sk) != 0 || crypto_kem_enc(ct, ss, pk) != 0) { fprintf(stderr, "kem failed\n"); return 1; }
    if (crypto_kem_dec(ss2, ct, sk) != 0 || memcmp(ss, ss2, CRYPTO_BYTES) != 0) { fprintf(stderr, "dec disagrees with enc\n"); return 1; }
    dump(argv[1], argv[3], "pk", pk, sizeof pk);
    dump(argv[1], argv[3], "sk", sk, sizeof sk);
    dump(argv[1], argv[3], "ct", ct, sizeof ct);
    dump(argv[1], argv[3], "ss", ss, sizeof ss);
    fprintf(stderr, "%s", CRYPTO_ALGNAME);

    bench("keygen", 0, sizeof pk);
    bench("encaps", 1, sizeof ct);
    bench("decaps", 2, sizeof ss);
    return 0;
}
