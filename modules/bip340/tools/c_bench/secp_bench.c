// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-bip340` (modules/bip340/tools/bench.zig): times
// libsecp256k1 v0.8.0's BIP340 `schnorrsig` + `extrakeys` over the key, message
// and aux randomness the Zig program writes into the directory given as the only
// argument. It is compiled together with libsecp256k1's own sources (never via
// its build system; see bench.zig), so it includes the library's public headers.
//
// Interop files: this side writes pk.c.bin (x-only public key) and sig.c.bin
// (its signature over msg.bin); it reads sig.zig.bin (the Zig module's
// signature over the same message) and exits non-zero unless libsecp256k1
// verifies it. One line per workload: name, ns/op, ops per call.
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static void slurp(const char *dir, const char *name, unsigned char *b, size_t want) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    if (fread(b, 1, want, f) != want) { fprintf(stderr, "short %s\n", path); exit(1); }
    fclose(f);
}

static void spit(const char *dir, const char *name, const unsigned char *b, size_t len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(b, 1, len, f) != len) { perror(path); exit(1); }
    fclose(f);
}

static secp256k1_context *ctx;
static unsigned char sk[32], msg[32], aux[32], sig[64];
static secp256k1_keypair kp;
static secp256k1_xonly_pubkey xpk;
static volatile int sink;

static int op_keypair(void) {
    secp256k1_keypair k;
    secp256k1_xonly_pubkey x;
    if (!secp256k1_keypair_create(ctx, &k, sk)) return 1;
    if (!secp256k1_keypair_xonly_pub(ctx, &x, NULL, &k)) return 1;
    return 0;
}
static int op_sign(void) {
    return !secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, aux);
}
static int op_verify(void) {
    return !secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &xpk);
}

static void bench(const char *name, int (*op)(void)) {
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) sink += op();
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++)
            if (op() != 0) { fprintf(stderr, "%s failed\n", name); exit(1); }
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    printf("%s\t%.1f\t1\n", name, best / (double)n);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: secp_bench <work dir>\n"); return 2; }
    fprintf(stderr, "libsecp256k1 v0.8.0 (compiled from source, zig cc -O3)\n");
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) return 1;
    slurp(argv[1], "sk.bin", sk, 32);
    slurp(argv[1], "msg.bin", msg, 32);
    slurp(argv[1], "aux.bin", aux, 32);
    if (!secp256k1_keypair_create(ctx, &kp, sk)) { fprintf(stderr, "bad secret key\n"); return 1; }
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 1;
    unsigned char pk[32];
    secp256k1_xonly_pubkey_serialize(ctx, pk, &xpk);
    spit(argv[1], "pk.c.bin", pk, 32);

    // Interop: our signature, over the same message, must verify here.
    unsigned char zsig[64];
    slurp(argv[1], "sig.zig.bin", zsig, 64);
    if (!secp256k1_schnorrsig_verify(ctx, zsig, msg, 32, &xpk)) {
        fprintf(stderr, "INTEROP FAILED: libsecp256k1 rejects the Zig module's signature\n");
        return 1;
    }
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, aux)) return 1;
    spit(argv[1], "sig.c.bin", sig, 64);

    bench("keypair", op_keypair);
    bench("sign", op_sign);
    bench("verify", op_verify);
    return 0;
}
