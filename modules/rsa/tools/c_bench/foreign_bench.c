// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-rsa` (modules/rsa/tools/bench.zig): times
// OpenSSL's RSA (EVP; CRT, blinding on, its default) for the one workload
// named by the second argument, over the inputs in the directory given as the
// first:
//   ossl.sign_<bits>    SHA256(msg) + EVP_PKEY_sign, PKCS#1 v1.5 / SHA-256
//   ossl.verify_<bits>  SHA256(msg) + EVP_PKEY_verify of one signature
//   ossl.dec_<bits>     EVP_PKEY_decrypt, OAEP / SHA-256 / MGF1-SHA-256, of
//                       the ciphertext the Zig side encrypted (`ct_<bits>.bin`)
// with contexts initialised once, <bits> = 2048, 3072 or 4096. Prints one
// line: name, ns/op, user-mode cycles/op (0 without a counter), bytes per op.
// Two non-timing modes: `keygen` writes `sk_<bits>.der` (PKCS#1
// RSAPrivateKey) and `pk_<bits>.der` (SubjectPublicKeyInfo) for all three
// sizes; `interop` writes OpenSSL's signature `sig_<bits>.bin` over msg.bin
// and checks that it decrypts each `ct_<bits>.bin` to msg.bin.
//
// OpenSSL's headers are not installed on every host, so the prototypes used
// are declared here (public, stable 3.x API). Timing matches the Zig side:
// double the batch until it takes over 100 ms, then keep the best of five.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_st EVP_MD;
EVP_PKEY *EVP_PKEY_Q_keygen(void *libctx, const char *propq, const char *type, ...);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *e);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);
int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
const EVP_MD *EVP_sha256(void);
int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);
int i2d_PUBKEY(const EVP_PKEY *a, unsigned char **pp);
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
const char *OpenSSL_version(int t);
void CRYPTO_free(void *p, const char *file, int line); // OPENSSL_free is a macro over it
#define RSA_PKCS1_PADDING 1
#define RSA_PKCS1_OAEP_PADDING 4

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

static EVP_PKEY_CTX *sctx, *vctx, *dctx;
static unsigned char *msg, sig[512], out[512], *ct;
static size_t msg_len, sig_len, ct_len;

static void put(const char *fmt, int bits, unsigned char *der, int len) {
    char f[64];
    snprintf(f, sizeof f, fmt, bits);
    if (len <= 0) { fprintf(stderr, "i2d failed\n"); exit(1); }
    spit(f, der, (size_t)len);
}
static size_t op_sign(void) {
    unsigned char md[32];
    size_t l = sizeof out;
    SHA256(msg, msg_len, md);
    if (EVP_PKEY_sign(sctx, out, &l, md, 32) != 1) { fprintf(stderr, "sign failed\n"); exit(1); }
    return l;
}
static size_t op_verify(void) {
    unsigned char md[32];
    SHA256(msg, msg_len, md);
    if (EVP_PKEY_verify(vctx, sig, sig_len, md, 32) != 1) { fprintf(stderr, "verify failed\n"); exit(1); }
    return 1;
}
static size_t op_dec(void) {
    size_t l = sizeof out;
    if (EVP_PKEY_decrypt(dctx, out, &l, ct, ct_len) != 1) { fprintf(stderr, "decrypt failed\n"); exit(1); }
    return l;
}

static EVP_PKEY *load(int bits) {
    char f[64];
    size_t n;
    snprintf(f, sizeof f, "sk_%d.der", bits);
    const unsigned char *p = slurp(f, &n);
    EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &p, (long)n);
    if (!k) { fprintf(stderr, "cannot load %s\n", f); exit(1); }
    return k;
}
static void setup(EVP_PKEY *k, int bits) {
    char f[64];
    sctx = EVP_PKEY_CTX_new(k, NULL);
    vctx = EVP_PKEY_CTX_new(k, NULL);
    dctx = EVP_PKEY_CTX_new(k, NULL);
    if (EVP_PKEY_sign_init(sctx) != 1 || EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) != 1 || EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256()) != 1 ||
        EVP_PKEY_verify_init(vctx) != 1 || EVP_PKEY_CTX_set_rsa_padding(vctx, RSA_PKCS1_PADDING) != 1 || EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) != 1 ||
        EVP_PKEY_decrypt_init(dctx) != 1 || EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_PKCS1_OAEP_PADDING) != 1 || EVP_PKEY_CTX_set_rsa_oaep_md(dctx, EVP_sha256()) != 1) {
        fprintf(stderr, "ctx setup failed\n");
        exit(1);
    }
    snprintf(f, sizeof f, "ct_%d.bin", bits);
    ct = slurp(f, &ct_len);
    unsigned char md[32];
    SHA256(msg, msg_len, md);
    sig_len = sizeof sig;
    if (EVP_PKEY_sign(sctx, sig, &sig_len, md, 32) != 1) { fprintf(stderr, "sign failed\n"); exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: rsa_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    static const int sizes[] = {2048, 3072, 4096};
    if (strcmp(w, "keygen") == 0) {
        for (int i = 0; i < 3; i++) {
            EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)sizes[i]);
            if (!k) { fprintf(stderr, "keygen failed\n"); return 1; }
            unsigned char *der = NULL;
            int n = i2d_PrivateKey(k, &der);
            put("sk_%d.der", sizes[i], der, n);
            CRYPTO_free(der, __FILE__, __LINE__);
            der = NULL;
            n = i2d_PUBKEY(k, &der);
            put("pk_%d.der", sizes[i], der, n);
            CRYPTO_free(der, __FILE__, __LINE__);
        }
        return 0;
    }
    msg = slurp("msg.bin", &msg_len);
    if (strcmp(w, "interop") == 0) {
        for (int i = 0; i < 3; i++) {
            setup(load(sizes[i]), sizes[i]);
            char f[64];
            snprintf(f, sizeof f, "sig_%d.bin", sizes[i]);
            spit(f, sig, sig_len);
            size_t l = op_dec();
            if (l != msg_len || memcmp(out, msg, l) != 0) { fprintf(stderr, "OpenSSL decrypts our OAEP ciphertext (%d) to something else\n", sizes[i]); return 1; }
        }
        return 0;
    }
    char op[16];
    int bits;
    if (sscanf(w, "ossl.%15[a-z]_%d", op, &bits) != 2) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    setup(load(bits), bits);
    cycles_open();
    if (strcmp(op, "sign") == 0) bench(w, op_sign);
    else if (strcmp(op, "verify") == 0) bench(w, op_verify);
    else if (strcmp(op, "dec") == 0) bench(w, op_dec);
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    return 0;
}
