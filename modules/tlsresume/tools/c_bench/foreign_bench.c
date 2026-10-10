// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-tlsresume` (modules/tlsresume/tools/bench.zig):
// the same computations as `tlsresume`, written against OpenSSL 3's public
// EVP API, over the inputs the Zig program writes into the directory given as
// the first argument, for the one workload named by the second argument:
//   seal_<N>   ticket seal: AES-256-GCM of an N-byte session state under the
//              STEK, AAD = the 1-byte key id, blob = id || nonce || ct || tag
//   open_<N>   the inverse, on the blob the Zig side sealed (tag checked)
//   binder     the RFC 8446 resumption PSK chain per resumed handshake:
//              PSK = Expand-Label(rms, "resumption", nonce), early secret =
//              Extract(0^32, PSK), binder key = Expand-Label(early,
//              "res binder", Hash("")), finished key = Expand-Label(binder
//              key, "finished", ""), binder = HMAC(finished key, transcript
//              hash). HKDF is composed from HMAC-SHA256 (EVP_MAC) exactly as
//              RFC 5869 defines it; OpenSSL has no TLS 1.3 resumption call to
//              use instead.
// Prints one line: name, ns/op, user-mode cycles/op (0 without a cycle
// counter), output bytes per op. The run named `interop` writes
// `ossl_seal_<N>.bin` and `ossl_binder.bin` for the Zig side to compare.
//
// OpenSSL's headers are not installed on every host, so the few prototypes
// used are declared here (public API, stable since 3.0). Timing matches the
// Zig side: double the batch until it takes over 100 ms, keep the best of
// five. Each call (re-)keys the cipher / MAC: the Zig side expands its key
// schedule per call too.
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
typedef struct evp_mac_st EVP_MAC;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;
typedef struct { const char *key; unsigned data_type; void *data; size_t data_size; size_t return_size; } OSSL_PARAM;
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);
EVP_MAC *EVP_MAC_fetch(void *libctx, const char *algorithm, const char *properties);
EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac);
int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
int EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize);
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_end(void);
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

static unsigned char key[32], nonce[12], rms[32], th[32], empty_hash[32], *pt, *blob, *out;
static size_t len;
static EVP_CIPHER_CTX *ectx, *dctx;
static EVP_MAC_CTX *mctx;
static OSSL_PARAM sha256_param[2];

static void die(const char *what) { fprintf(stderr, "%s failed\n", what); exit(1); }

static size_t seal(void) {
    int l = 0, l2 = 0;
    unsigned char id = 1;
    out[0] = id;
    memcpy(out + 1, nonce, 12);
    if (EVP_EncryptInit_ex(ectx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ectx, NULL, &l, &id, 1) != 1 ||
        EVP_EncryptUpdate(ectx, out + 13, &l, pt, (int)len) != 1 ||
        EVP_EncryptFinal_ex(ectx, out + 13 + l, &l2) != 1 ||
        EVP_CIPHER_CTX_ctrl(ectx, CTRL_GET_TAG, 16, out + 13 + len) != 1) die("seal");
    return len + 29;
}
static size_t open_(void) {
    int l = 0, l2 = 0;
    if (EVP_DecryptInit_ex(dctx, NULL, NULL, key, blob + 1) != 1 ||
        EVP_CIPHER_CTX_ctrl(dctx, CTRL_SET_TAG, 16, blob + 13 + len) != 1 ||
        EVP_DecryptUpdate(dctx, NULL, &l, blob, 1) != 1 ||
        EVP_DecryptUpdate(dctx, out, &l, blob + 13, (int)len) != 1 ||
        EVP_DecryptFinal_ex(dctx, out + l, &l2) != 1) die("open (tag)");
    return len;
}

static void hmac(const unsigned char *k, size_t klen, const unsigned char *d, size_t dlen, unsigned char *mac) {
    size_t n = 32;
    if (EVP_MAC_init(mctx, k, klen, sha256_param) != 1 || EVP_MAC_update(mctx, d, dlen) != 1 || EVP_MAC_final(mctx, mac, &n, 32) != 1) die("hmac");
}
// HKDF-Expand-Label for output <= 32 bytes: T(1) = HMAC(secret, HkdfLabel || 0x01).
static void expand_label(const unsigned char *secret, const char *label, const unsigned char *ctx, size_t ctx_len, size_t olen, unsigned char *o) {
    unsigned char buf[128], mac[32];
    size_t n = 0, ll = strlen(label);
    buf[n++] = (unsigned char)(olen >> 8);
    buf[n++] = (unsigned char)olen;
    buf[n++] = (unsigned char)(6 + ll);
    memcpy(buf + n, "tls13 ", 6); n += 6;
    memcpy(buf + n, label, ll); n += ll;
    buf[n++] = (unsigned char)ctx_len;
    memcpy(buf + n, ctx, ctx_len); n += ctx_len;
    buf[n++] = 1;
    hmac(secret, 32, buf, n, mac);
    memcpy(o, mac, olen);
}
static unsigned char binder_out[32];
static size_t binder(void) {
    unsigned char psk[32], early[32], bkey[32], fkey[32];
    static const unsigned char tnonce[2] = {0, 0}, zero[32] = {0};
    expand_label(rms, "resumption", tnonce, 2, 32, psk);
    hmac(zero, 32, psk, 32, early);
    expand_label(early, "res binder", empty_hash, 32, 32, bkey);
    expand_label(bkey, "finished", NULL, 0, 32, fkey);
    hmac(fkey, 32, th, 32, binder_out);
    return 32;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    size_t n;
    unsigned char *t;
    t = slurp("key32.bin", &n); memcpy(key, t, 32);
    t = slurp("nonce12.bin", &n); memcpy(nonce, t, 12);
    t = slurp("rms32.bin", &n); memcpy(rms, t, 32);
    t = slurp("th32.bin", &n); memcpy(th, t, 32);
    t = slurp("empty_hash32.bin", &n); memcpy(empty_hash, t, 32);
    ectx = EVP_CIPHER_CTX_new();
    dctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 || EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("cipher init");
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    mctx = EVP_MAC_CTX_new(mac);
    sha256_param[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    sha256_param[1] = OSSL_PARAM_construct_end();
    cycles_open();
    if (strcmp(w, "interop") == 0) {
        static const size_t lens[] = {128, 512};
        for (int i = 0; i < 2; i++) {
            char nm[64];
            len = lens[i];
            snprintf(nm, sizeof nm, "pt%zu.bin", len);
            pt = slurp(nm, NULL);
            out = malloc(len + 64);
            seal();
            snprintf(nm, sizeof nm, "ossl_seal_%zu.bin", len);
            spit(nm, out, len + 29);
        }
        binder();
        spit("ossl_binder.bin", binder_out, 32);
        return 0;
    }
    if (strcmp(w, "binder") == 0) { bench(w, binder); return 0; }
    int isopen = 0;
    if (sscanf(w, "seal_%zu", &len) == 1) isopen = 0;
    else if (sscanf(w, "open_%zu", &len) == 1) isopen = 1;
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    char nm[64];
    snprintf(nm, sizeof nm, "pt%zu.bin", len);
    pt = slurp(nm, NULL);
    snprintf(nm, sizeof nm, "blob%zu.bin", len);
    blob = slurp(nm, NULL);
    out = malloc(len + 64);
    bench(w, isopen ? open_ : seal);
    return 0;
}
