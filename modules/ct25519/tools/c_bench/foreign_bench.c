// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-ct25519` (modules/ct25519/tools/bench.zig): times
// libsodium (the reference) and, for X25519, OpenSSL over the scalars and
// points the Zig program writes into the directory given as the first
// argument, for the one workload named by the second:
//   sodium.x25519       crypto_scalarmult (shared secret, variable base)
//   sodium.x25519_pub   crypto_scalarmult_base
//   sodium.ed_base      crypto_scalarmult_ed25519_base_noclamp (s*B, encoded)
//   sodium.rist_base    crypto_scalarmult_ristretto255_base (s*B, encoded)
//   ossl.x25519         EVP_PKEY_derive on a context with the peer set once
//   ossl.x25519_pub     EVP_PKEY_new_raw_private_key + get_raw_public_key
//                       (+ free) -- OpenSSL's only route from a raw scalar
// Prints one line: name, ns/op, user-mode cycles/op (0 without a counter),
// bytes produced per op. The run named `interop` writes every workload's
// output to `<impl>.<workload>.bin` for the Zig side to compare.
//
// Neither library's headers are installed on every host, so the prototypes
// used are declared here (public, stable APIs). Timing matches the Zig side:
// double the batch until it takes over 100 ms, then keep the best of five.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int sodium_init(void);
const char *sodium_version_string(void);
int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);
int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
int crypto_scalarmult_ed25519_base_noclamp(unsigned char *q, const unsigned char *n);
int crypto_scalarmult_ristretto255_base(unsigned char *q, const unsigned char *n);

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, void *e, const unsigned char *priv, size_t len);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, void *e, const unsigned char *pub, size_t len);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len);
void EVP_PKEY_free(EVP_PKEY *pkey);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *e);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
const char *OpenSSL_version(int t);
#define NID_X25519 1034

// ---- shared harness (same in every module's c_bench) ----
static const char *dir;
static int cyc_fd = -1;
static volatile size_t sink;
static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}
static void cycles_open(void) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    cyc_fd = (int)syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
}
static unsigned long long cycles_read(void) {
    unsigned long long v = 0;
    if (cyc_fd < 0 || read(cyc_fd, &v, sizeof v) != sizeof v) return 0;
    return v;
}
static unsigned char *slurp(const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short %s\n", path); exit(1); }
    fclose(f);
    if (len) *len = (size_t)n;
    return b;
}
static void spit(const char *name, const void *b, size_t n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(b, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);
}
static void bench(const char *name, size_t (*f)(void)) {
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) sink += f();
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300, bestc = 1e300;
    size_t count = 0;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        unsigned long long c0 = cycles_read();
        for (size_t i = 0; i < n; i++) count = f();
        double c = (double)(cycles_read() - c0);
        double d = now_ns() - t;
        if (d < best) best = d;
        if (c < bestc) bestc = c;
    }
    printf("%s\t%.1f\t%.1f\t%zu\n", name, best / (double)n, cyc_fd < 0 ? 0.0 : bestc / (double)n, count);
}
// ---- end shared harness ----

static unsigned char sk[32], peer[32], s[32], out[32];
static EVP_PKEY_CTX *dctx;

static size_t sodium_x25519(void) {
    if (crypto_scalarmult(out, sk, peer) != 0) { fprintf(stderr, "scalarmult failed\n"); exit(1); }
    return 32;
}
static size_t sodium_x25519_pub(void) {
    crypto_scalarmult_base(out, sk);
    return 32;
}
static size_t sodium_ed_base(void) {
    if (crypto_scalarmult_ed25519_base_noclamp(out, s) != 0) { fprintf(stderr, "ed base failed\n"); exit(1); }
    return 32;
}
static size_t sodium_rist_base(void) {
    if (crypto_scalarmult_ristretto255_base(out, s) != 0) { fprintf(stderr, "ristretto base failed\n"); exit(1); }
    return 32;
}
static size_t ossl_x25519(void) {
    size_t l = 32;
    if (EVP_PKEY_derive(dctx, out, &l) != 1) { fprintf(stderr, "derive failed\n"); exit(1); }
    return l;
}
static size_t ossl_x25519_pub(void) {
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(NID_X25519, NULL, sk, 32);
    size_t l = 32;
    if (!k || EVP_PKEY_get_raw_public_key(k, out, &l) != 1) { fprintf(stderr, "pub failed\n"); exit(1); }
    EVP_PKEY_free(k);
    return l;
}

static const struct { const char *name; size_t (*f)(void); } ops[] = {
    {"sodium.x25519", sodium_x25519}, {"sodium.x25519_pub", sodium_x25519_pub},
    {"sodium.ed_base", sodium_ed_base}, {"sodium.rist_base", sodium_rist_base},
    {"ossl.x25519", ossl_x25519}, {"ossl.x25519_pub", ossl_x25519_pub},
};

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: ct25519_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    if (sodium_init() < 0) return 1;
    memcpy(sk, slurp("sk.bin", NULL), 32);
    memcpy(peer, slurp("peer.bin", NULL), 32);
    memcpy(s, slurp("scalar.bin", NULL), 32);
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(NID_X25519, NULL, sk, 32);
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(NID_X25519, NULL, peer, 32);
    dctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) != 1 || EVP_PKEY_derive_set_peer(dctx, pub) != 1) { fprintf(stderr, "derive setup failed\n"); return 1; }
    cycles_open();
    int interop = strcmp(w, "interop") == 0;
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        if (interop) {
            char f[64];
            ops[i].f();
            snprintf(f, sizeof f, "%s.bin", ops[i].name);
            spit(f, out, 32);
        } else if (strcmp(w, ops[i].name) == 0) {
            fprintf(stderr, "%s\n", strncmp(w, "ossl", 4) == 0 ? OpenSSL_version(0) : sodium_version_string());
            bench(w, ops[i].f);
            return 0;
        }
    }
    if (interop) return 0;
    fprintf(stderr, "unknown workload %s\n", w);
    return 2;
}
