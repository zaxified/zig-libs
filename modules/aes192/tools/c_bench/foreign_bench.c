// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-aes192` (modules/aes192/tools/bench.zig): times
// OpenSSL's EVP AES-192 over the key, IV and message the Zig program writes
// into the directory given as the first argument, for the one workload named
// by the second argument. Prints one line: name, ns/op, user-mode cycles/op
// (0 without a cycle counter), bytes produced per op. The run named `interop`
// instead writes `ossl_ecb.bin`, `ossl_cbc.bin` and `ossl_ctr.bin` (each the
// 16 KiB message under the 24-byte key) for the Zig side to compare byte for
// byte.
//
// OpenSSL's headers are not installed on every host, so the few EVP
// prototypes used are declared here (the public EVP API, stable since 1.1).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. Workloads:
//   ecb_enc_16384, ecb_dec_16384 -- independent blocks (aesni_ecb_encrypt's
//       8-wide pipeline against the module's encryptWide/decryptWide);
//   cbc_enc_16384 -- chained blocks, latency-bound (IV set per op);
//   ctr_16384 -- counter mode (IV set per op);
//   key_enc, key_dec -- a fresh key schedule per op (EVP_*Init_ex with the
//       key on a context that already holds the cipher).
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
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
const char *OpenSSL_version(int t);

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

#define LEN 16384
static EVP_CIPHER_CTX *ctx;
static unsigned char *key, *iv, *msg, *out;

static void die(const char *what) {
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}
static size_t ecb_enc(void) {
    int l = 0;
    if (EVP_EncryptUpdate(ctx, out, &l, msg, LEN) != 1) die("ecb encrypt");
    return (size_t)l;
}
static size_t ecb_dec(void) {
    int l = 0;
    if (EVP_DecryptUpdate(ctx, out, &l, msg, LEN) != 1) die("ecb decrypt");
    return (size_t)l;
}
static size_t ivenc(void) {
    int l = 0;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1 || EVP_EncryptUpdate(ctx, out, &l, msg, LEN) != 1) die("encrypt");
    return (size_t)l;
}
static size_t key_enc(void) {
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL) != 1) die("key setup");
    return 0;
}
static size_t key_dec(void) {
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL) != 1) die("key setup");
    return 0;
}

static void init(const EVP_CIPHER *c, int decrypt) {
    ctx = EVP_CIPHER_CTX_new();
    int ok = decrypt ? EVP_DecryptInit_ex(ctx, c, NULL, key, iv) : EVP_EncryptInit_ex(ctx, c, NULL, key, iv);
    if (ok != 1 || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) die("init");
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    key = slurp("key24.bin", NULL);
    iv = slurp("iv.bin", NULL);
    msg = slurp("msg16384.bin", NULL);
    out = malloc(LEN + 16);
    if (strcmp(w, "interop") == 0) {
        init(EVP_aes_192_ecb(), 0);
        ecb_enc();
        spit("ossl_ecb.bin", out, LEN);
        init(EVP_aes_192_cbc(), 0);
        ivenc();
        spit("ossl_cbc.bin", out, LEN);
        init(EVP_aes_192_ctr(), 0);
        ivenc();
        spit("ossl_ctr.bin", out, LEN);
        return 0;
    }
    size_t (*f)(void);
    if (strcmp(w, "ecb_enc_16384") == 0) init(EVP_aes_192_ecb(), 0), f = ecb_enc;
    else if (strcmp(w, "ecb_dec_16384") == 0) init(EVP_aes_192_ecb(), 1), f = ecb_dec;
    else if (strcmp(w, "cbc_enc_16384") == 0) init(EVP_aes_192_cbc(), 0), f = ivenc;
    else if (strcmp(w, "ctr_16384") == 0) init(EVP_aes_192_ctr(), 0), f = ivenc;
    else if (strcmp(w, "key_enc") == 0) init(EVP_aes_192_ecb(), 0), f = key_enc;
    else if (strcmp(w, "key_dec") == 0) init(EVP_aes_192_ecb(), 1), f = key_dec;
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    cycles_open();
    bench(w, f);
    return 0;
}
