// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-aescbc` (modules/aescbc/tools/bench.zig): times
// OpenSSL's EVP AES-256-CBC over the key, IV and messages the Zig program
// writes into the directory given as the first argument, for the one workload
// named by the second. Prints one line: name, ns/op, user-mode cycles/op (0
// without a cycle counter), bytes produced per op. The run named `interop`
// instead writes `ossl_cbc.bin` (the 16 KiB message) and `ossl_pkcs7.bin`
// (the 1008-byte message, padded by EVP) for the Zig side to compare.
//
// OpenSSL's headers are not installed on every host, so the few EVP
// prototypes used are declared here (the public EVP API, stable since 1.1).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. Workloads (key schedule set up once unless
// named): enc_N / dec_N -- an N-byte message, IV set per op (EVP_*Init_ex
// with only the IV); oneshot_dec_1024 -- key AND IV per op; pkcs7_dec_1024 --
// EVP's default PKCS#7 padding on, Update + Final; stream_enc_1008 -- the
// same, encrypting; cts_enc_1000 / cts_dec_1000 -- AES-256-CBC-CTS, CS3,
// key AND IV per op (as the module's one-shot encryptCts/decryptCts). `interop` also writes ossl_cts_<CSn>_<len>.bin.
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
const EVP_CIPHER *EVP_aes_256_cbc(void);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
const char *OpenSSL_version(int t);
// CBC-CTS is a provider cipher (OpenSSL 3): fetched by name, mode set by param.
typedef struct ossl_param_st {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_end(void);
EVP_CIPHER *EVP_CIPHER_fetch(void *libctx, const char *algorithm, const char *properties);
int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv,
                       int enc, const OSSL_PARAM params[]);
int EVP_CipherUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);

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
static unsigned char *key, *iv, *msg, *ct, *pad, *out;
static int n;

static void die(const char *what) {
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}
static size_t enc(void) {
    int l = 0;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1 || EVP_EncryptUpdate(ctx, out, &l, msg, n) != 1) die("encrypt");
    return (size_t)l;
}
static size_t dec(void) {
    int l = 0;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1 || EVP_DecryptUpdate(ctx, out, &l, ct, n) != 1) die("decrypt");
    return (size_t)l;
}
static size_t oneshot_dec(void) {
    int l = 0;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 || EVP_DecryptUpdate(ctx, out, &l, ct, n) != 1) die("decrypt");
    return (size_t)l;
}
static size_t pkcs7_dec(void) {
    int l = 0, f = 0;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1 || EVP_DecryptUpdate(ctx, out, &l, pad, 1024) != 1 ||
        EVP_DecryptFinal_ex(ctx, out + l, &f) != 1)
        die("pkcs7 decrypt");
    return (size_t)(l + f);
}

static EVP_CIPHER *cts;
static unsigned char *cts_ct;
static void cts_init(const char *mode, int enc) {
    if (!cts) cts = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", NULL);
    if (!cts) die("fetch AES-256-CBC-CTS");
    ctx = EVP_CIPHER_CTX_new();
    OSSL_PARAM p[2] = {OSSL_PARAM_construct_utf8_string("cts_mode", (char *)mode, 0), OSSL_PARAM_construct_end()};
    if (EVP_CipherInit_ex2(ctx, cts, key, iv, enc, p) != 1) die("cts init");
}
static size_t cts_once(const unsigned char *in) {
    int l = 0;
    if (EVP_CipherInit_ex2(ctx, NULL, key, iv, -1, NULL) != 1 || EVP_CipherUpdate(ctx, out, &l, in, n) != 1) die("cts");
    return (size_t)l;
}
static size_t cts_enc(void) { return cts_once(msg); }
static size_t cts_dec(void) { return cts_once(cts_ct); }
static size_t stream_enc(void) {
    int l = 0, f = 0;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) != 1 || EVP_EncryptUpdate(ctx, out, &l, msg, 1008) != 1 ||
        EVP_EncryptFinal_ex(ctx, out + l, &f) != 1)
        die("stream encrypt");
    return (size_t)(l + f);
}

static void init(int decrypt, int padding) {
    ctx = EVP_CIPHER_CTX_new();
    int ok = decrypt ? EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)
                     : EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (ok != 1 || EVP_CIPHER_CTX_set_padding(ctx, padding) != 1) die("init");
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    key = slurp("key32.bin", NULL);
    iv = slurp("iv.bin", NULL);
    msg = slurp("msg16384.bin", NULL);
    ct = slurp("ct16384.bin", NULL);
    pad = slurp("pad1024.bin", NULL);
    cts_ct = slurp("cts1000.bin", NULL);
    out = malloc(LEN + 32);
    if (strcmp(w, "interop") == 0) {
        init(0, 0);
        n = LEN;
        enc();
        spit("ossl_cbc.bin", out, LEN);
        int l = 0, f = 0;
        init(0, 1);
        if (EVP_EncryptUpdate(ctx, out, &l, msg, 1008) != 1 || EVP_EncryptFinal_ex(ctx, out + l, &f) != 1) die("pkcs7 encrypt");
        spit("ossl_pkcs7.bin", out, (size_t)(l + f));
        static const int lens[] = {16, 17, 31, 32, 47, 48, 1000, 1024};
        static const char *modes[] = {"CS1", "CS2", "CS3"};
        for (int m = 0; m < 3; m++)
            for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
                char name[64];
                cts_init(modes[m], 1);
                n = lens[i];
                l = (int)cts_enc();
                snprintf(name, sizeof name, "ossl_cts_%s_%d.bin", modes[m], lens[i]);
                spit(name, out, (size_t)l);
            }
        return 0;
    }
    size_t (*fn)(void);
    if (strcmp(w, "enc_16384") == 0) init(0, 0), n = LEN, fn = enc;
    else if (strcmp(w, "dec_16384") == 0) init(1, 0), n = LEN, fn = dec;
    else if (strcmp(w, "enc_64") == 0) init(0, 0), n = 64, fn = enc;
    else if (strcmp(w, "dec_64") == 0) init(1, 0), n = 64, fn = dec;
    else if (strcmp(w, "oneshot_dec_1024") == 0) init(1, 0), n = 1024, fn = oneshot_dec;
    else if (strcmp(w, "pkcs7_dec_1024") == 0) init(1, 1), fn = pkcs7_dec;
    else if (strcmp(w, "stream_enc_1008") == 0) init(0, 1), fn = stream_enc;
    else if (strcmp(w, "cts_enc_1000") == 0) cts_init("CS3", 1), n = 1000, fn = cts_enc;
    else if (strcmp(w, "cts_dec_1000") == 0) cts_init("CS3", 0), n = 1000, fn = cts_dec;
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    cycles_open();
    bench(w, fn);
    return 0;
}
