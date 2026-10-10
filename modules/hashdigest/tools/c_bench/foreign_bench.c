// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-hashdigest` (modules/hashdigest/tools/bench.zig):
// times a one-shot digest + lowercase hex encoding -- what `hashdigest.hex`
// does -- in OpenSSL (EVP, the digest fetched and the EVP_MD_CTX allocated
// once; `ossl.<algo>_<size>`) and, for BLAKE2b-256, libsodium
// (`crypto_generichash` with a 32-byte output; `sodium.blake2b256_<size>`),
// over `msg<size>.bin` from the directory given as the first argument.
// Prints one line: name, ns/op, user-mode cycles/op (0 without a counter),
// hex characters per op. The run named `interop` writes `<algo>.hex` of
// msg65536.bin for every algorithm for the Zig side to compare.
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

typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
EVP_MD *EVP_MD_fetch(void *ctx, const char *algorithm, const char *properties);
EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type, const void *params);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
const char *OpenSSL_version(int t);
int sodium_init(void);
const char *sodium_version_string(void);
int crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen);

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

static const struct { const char *ours, *ossl; } algos[] = {
    {"sha256", "SHA256"}, {"sha224", "SHA224"}, {"sha384", "SHA384"}, {"sha512", "SHA512"},
    {"sha512_256", "SHA512-256"}, {"sha3_256", "SHA3-256"}, {"sha3_512", "SHA3-512"},
};
static EVP_MD *md;
static EVP_MD_CTX *mctx;
static unsigned char *msg, raw[64];
static char hex[129];
static size_t len;

static size_t tohex(unsigned n) {
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        hex[2 * i] = d[raw[i] >> 4];
        hex[2 * i + 1] = d[raw[i] & 15];
    }
    return 2 * (size_t)n;
}
static size_t ossl_digest(void) {
    unsigned n = 0;
    if (EVP_DigestInit_ex2(mctx, md, NULL) != 1 || EVP_DigestUpdate(mctx, msg, len) != 1 || EVP_DigestFinal_ex(mctx, raw, &n) != 1) { fprintf(stderr, "digest failed\n"); exit(1); }
    return tohex(n);
}
static size_t sodium_b2b(void) {
    crypto_generichash(raw, 32, msg, len, NULL, 0);
    return tohex(32);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: hashdigest_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    if (sodium_init() < 0) return 1;
    mctx = EVP_MD_CTX_new();
    if (strcmp(w, "interop") == 0) {
        msg = slurp("msg65536.bin", &len);
        for (size_t i = 0; i < sizeof algos / sizeof algos[0]; i++) {
            char f[64];
            md = EVP_MD_fetch(NULL, algos[i].ossl, NULL);
            if (!md) { fprintf(stderr, "no %s\n", algos[i].ossl); return 1; }
            size_t n = ossl_digest();
            snprintf(f, sizeof f, "%s.hex", algos[i].ours);
            spit(f, hex, n);
        }
        spit("blake2b256.hex", hex, sodium_b2b());
        return 0;
    }
    char impl[16], algo[32];
    if (sscanf(w, "%15[a-z].%31[a-z0-9_]", impl, algo) != 2) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    char *us = strrchr(algo, '_');
    if (!us) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    *us = 0;
    char f[64];
    snprintf(f, sizeof f, "msg%s.bin", us + 1);
    msg = slurp(f, &len);
    cycles_open();
    if (strcmp(impl, "sodium") == 0 && strcmp(algo, "blake2b256") == 0) {
        fprintf(stderr, "libsodium %s\n", sodium_version_string());
        bench(w, sodium_b2b);
        return 0;
    }
    for (size_t i = 0; i < sizeof algos / sizeof algos[0]; i++)
        if (strcmp(impl, "ossl") == 0 && strcmp(algo, algos[i].ours) == 0) {
            md = EVP_MD_fetch(NULL, algos[i].ossl, NULL);
            fprintf(stderr, "%s\n", OpenSSL_version(0));
            bench(w, ossl_digest);
            return 0;
        }
    fprintf(stderr, "unknown workload %s\n", w);
    return 2;
}
