// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-aesgcm` (modules/aesgcm/tools/bench.zig): times
// OpenSSL's EVP AES-GCM over the key, nonce, associated data and messages the
// Zig program writes into the directory given as the first argument, for the
// one workload named by the second argument. Prints one line: name, ns/op,
// user-mode cycles/op (0 without a cycle counter), bytes produced per op.
// The run named `interop` instead writes `ossl_ct.bin` (AES-256-GCM of
// msg16384.bin, ciphertext || tag) for the Zig side to compare byte for byte.
//
// OpenSSL's headers are not installed on every host, so the few EVP
// prototypes used are declared here (the public EVP API, stable since 1.1).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. The context keeps the key schedule (set once);
// each operation sets the nonce, feeds the AD and the message, and takes or
// checks the tag -- the same work as the Zig side's `Context.encrypt/decrypt`.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);
const char *OpenSSL_version(int t);
#define CTRL_GET_TAG 0x10
#define CTRL_SET_TAG 0x11

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

static EVP_CIPHER_CTX *ectx, *dctx;
static unsigned char nonce[12], ad[13], tag[16], *msg, *out, *ct;
static size_t len;

static size_t enc(void) {
    int l = 0, l2 = 0;
    if (EVP_EncryptInit_ex(ectx, NULL, NULL, NULL, nonce) != 1 ||
        EVP_EncryptUpdate(ectx, NULL, &l, ad, sizeof ad) != 1 ||
        EVP_EncryptUpdate(ectx, out, &l, msg, (int)len) != 1 ||
        EVP_EncryptFinal_ex(ectx, out + l, &l2) != 1 ||
        EVP_CIPHER_CTX_ctrl(ectx, CTRL_GET_TAG, 16, tag) != 1) { fprintf(stderr, "encrypt failed\n"); exit(1); }
    return (size_t)(l + l2) + 16;
}
static size_t dec(void) {
    int l = 0, l2 = 0;
    if (EVP_DecryptInit_ex(dctx, NULL, NULL, NULL, nonce) != 1 ||
        EVP_CIPHER_CTX_ctrl(dctx, CTRL_SET_TAG, 16, tag) != 1 ||
        EVP_DecryptUpdate(dctx, NULL, &l, ad, sizeof ad) != 1 ||
        EVP_DecryptUpdate(dctx, out, &l, ct, (int)len) != 1 ||
        EVP_DecryptFinal_ex(dctx, out + l, &l2) != 1) { fprintf(stderr, "decrypt failed (tag)\n"); exit(1); }
    return (size_t)(l + l2);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: openssl_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    unsigned char *k = slurp("key32.bin", NULL), *nn = slurp("nonce.bin", NULL), *aa = slurp("ad.bin", NULL);
    memcpy(nonce, nn, 12);
    memcpy(ad, aa, 13);
    int bits = 0, decrypt = 0;
    if (strcmp(w, "interop") == 0) {
        bits = 256;
        len = 16384;
    } else if (sscanf(w, "aes%d_enc_%zu", &bits, &len) == 2) {
        decrypt = 0;
    } else if (sscanf(w, "aes%d_dec_%zu", &bits, &len) == 2) {
        decrypt = 1;
    } else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    const EVP_CIPHER *cipher = bits == 128 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    char mname[64];
    snprintf(mname, sizeof mname, "msg%zu.bin", len);
    msg = slurp(mname, NULL);
    out = malloc(len + 16);
    ct = malloc(len + 16);
    ectx = EVP_CIPHER_CTX_new();
    dctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ectx, cipher, NULL, k, NULL) != 1 || EVP_DecryptInit_ex(dctx, cipher, NULL, k, NULL) != 1) {
        fprintf(stderr, "init failed\n");
        return 1;
    }
    cycles_open();
    enc();
    memcpy(ct, out, len);
    if (strcmp(w, "interop") == 0) {
        memcpy(out + len, tag, 16);
        spit("ossl_ct.bin", out, len + 16);
        return 0;
    }
    bench(w, decrypt ? dec : enc);
    return 0;
}
