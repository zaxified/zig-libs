// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-p256` (modules/p256/tools/bench.zig): times
// OpenSSL's P-256 (EVP, the x86-64 nistz256 assembly) for the one workload
// named by the second argument, over the inputs the Zig program writes into
// the directory given as the first:
//   ossl.sign    SHA256(msg) + EVP_PKEY_sign (random nonce) on a context
//                initialised once; count = 64 (r||s; OpenSSL emits DER of it)
//   ossl.verify  SHA256(msg) + EVP_PKEY_verify of one DER signature
//   ossl.ecdh    EVP_PKEY_derive, the peer (the Zig side's public key,
//                imported once) set once; 32-byte shared x
//   ossl.keygen  EVP_PKEY_keygen on a P-256 context initialised once (+ free)
// Prints one line: name, ns/op, user-mode cycles/op (0 without a counter),
// bytes per op. The run named `interop` checks that OpenSSL verifies the Zig
// side's signature (`ours_sig.der` over msg.bin by `ours_pub.bin`) and writes
// its own public key and DER signature over msg.bin (`ossl_pub.bin`,
// `ossl_sig.der`) for the Zig side to verify.
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
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(void *libctx, const char *name, const char *propquery);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
void EVP_PKEY_free(EVP_PKEY *pkey);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t max_buf_sz, size_t *out_sz);
EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
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

// X.509 SubjectPublicKeyInfo prefix of an uncompressed P-256 point.
static const unsigned char spki_prefix[26] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

static EVP_PKEY_CTX *sctx, *vctx, *dctx, *gctx;
static unsigned char *msg, sig[80], out[80];
static size_t msg_len, sig_len;

static EVP_PKEY *import_pub(const unsigned char *pt) {
    unsigned char spki[91];
    memcpy(spki, spki_prefix, 26);
    memcpy(spki + 26, pt, 65);
    const unsigned char *p = spki;
    EVP_PKEY *k = d2i_PUBKEY(NULL, &p, sizeof spki);
    if (!k) { fprintf(stderr, "d2i_PUBKEY failed\n"); exit(1); }
    return k;
}

static size_t op_sign(void) {
    unsigned char md[32];
    size_t l = sizeof out;
    SHA256(msg, msg_len, md);
    if (EVP_PKEY_sign(sctx, out, &l, md, 32) != 1) { fprintf(stderr, "sign failed\n"); exit(1); }
    return 64;
}
static size_t op_verify(void) {
    unsigned char md[32];
    SHA256(msg, msg_len, md);
    if (EVP_PKEY_verify(vctx, sig, sig_len, md, 32) != 1) { fprintf(stderr, "verify failed\n"); exit(1); }
    return 1;
}
static size_t op_ecdh(void) {
    size_t l = sizeof out;
    if (EVP_PKEY_derive(dctx, out, &l) != 1) { fprintf(stderr, "derive failed\n"); exit(1); }
    return l;
}
static size_t op_keygen(void) {
    EVP_PKEY *k = NULL;
    if (EVP_PKEY_keygen(gctx, &k) != 1) { fprintf(stderr, "keygen failed\n"); exit(1); }
    EVP_PKEY_free(k);
    return 65;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p256_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    msg = slurp("msg.bin", &msg_len);
    gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!gctx || EVP_PKEY_keygen_init(gctx) != 1 || EVP_PKEY_CTX_set_group_name(gctx, "P-256") != 1) { fprintf(stderr, "keygen setup failed\n"); return 1; }
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen(gctx, &key) != 1) return 1;
    sctx = EVP_PKEY_CTX_new(key, NULL);
    vctx = EVP_PKEY_CTX_new(key, NULL);
    dctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY *peer = import_pub(slurp("ours_pub.bin", NULL));
    if (EVP_PKEY_sign_init(sctx) != 1 || EVP_PKEY_verify_init(vctx) != 1 || EVP_PKEY_derive_init(dctx) != 1 || EVP_PKEY_derive_set_peer(dctx, peer) != 1) { fprintf(stderr, "ctx setup failed\n"); return 1; }
    unsigned char md[32];
    SHA256(msg, msg_len, md);
    sig_len = sizeof sig;
    if (EVP_PKEY_sign(sctx, sig, &sig_len, md, 32) != 1) return 1;
    cycles_open();
    if (strcmp(w, "interop") == 0) {
        size_t der_len;
        unsigned char *der = slurp("ours_sig.der", &der_len);
        EVP_PKEY_CTX *ov = EVP_PKEY_CTX_new(peer, NULL);
        if (EVP_PKEY_verify_init(ov) != 1 || EVP_PKEY_verify(ov, der, der_len, md, 32) != 1) { fprintf(stderr, "OpenSSL rejects our signature\n"); return 1; }
        unsigned char pub[65];
        size_t pl = 0;
        if (EVP_PKEY_get_octet_string_param(key, "encoded-pub-key", pub, sizeof pub, &pl) != 1 || pl != 65) { fprintf(stderr, "pub export failed\n"); return 1; }
        spit("ossl_pub.bin", pub, 65);
        spit("ossl_sig.der", sig, sig_len);
        return 0;
    }
    static const struct { const char *name; size_t (*f)(void); } ops[] = {
        {"ossl.sign", op_sign}, {"ossl.verify", op_verify}, {"ossl.ecdh", op_ecdh}, {"ossl.keygen", op_keygen},
    };
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
        if (strcmp(w, ops[i].name) == 0) { bench(w, ops[i].f); return 0; }
    fprintf(stderr, "unknown workload %s\n", w);
    return 2;
}
