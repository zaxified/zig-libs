// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-slhdsa` (modules/slhdsa/tools/bench.zig): times
// OpenSSL 3.5's SLH-DSA (EVP_PKEY "SLH-DSA-<set>", one-shot EVP_DigestSign /
// EVP_DigestVerify with a NULL digest = the pure FIPS 205 sign/verify with an
// empty context string) over the key and message the Zig program writes into
// the directory given as the first argument, for the one workload named by the
// second argument, `<set>/<op>`, with <set> like `sha2_128s` and <op> one of
//   sign     deterministic signature of msg.bin (sk_<set>.bin imported once)
//   verify   verification of the signature the Zig side made (sig_<set>.bin)
//   keygen   EVP_PKEY_generate of a fresh key pair
// Prints one line: name, ns/op, user-mode cycles/op (0 without a cycle
// counter), output bytes per op (signature / 1 / public key). The run named
// `interop/<set>` instead writes `ossl_sig_<set>.bin` and checks that OpenSSL
// accepts the Zig side's signature (exit 1 if not).
//
// OpenSSL's headers are not installed on every host, so the few EVP/OSSL_PARAM
// prototypes used are declared here (public API, OpenSSL 3.5). The per-call
// EVP_MD_CTX create/init/free is inside the timed loop: that is what a caller
// of the one-shot API pays (a few microseconds against signing in
// milliseconds). Timing matches the Zig side: double the batch until it takes
// over 100 ms, then keep the best of five.
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
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct { const char *key; unsigned data_type; void *data; size_t data_size; size_t return_size; } OSSL_PARAM;
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(void *libctx, const char *name, const char *propq);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[]);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
void EVP_PKEY_free(EVP_PKEY *k);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *c);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *c);
int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const char *mdname, void *libctx, const char *props, EVP_PKEY *pkey, const OSSL_PARAM params[]);
int EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const char *mdname, void *libctx, const char *props, EVP_PKEY *pkey, const OSSL_PARAM params[]);
int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
OSSL_PARAM OSSL_PARAM_construct_end(void);
const char *OpenSSL_version(int t);
#define SEL_KEYPAIR 0x87 /* EVP_PKEY_KEYPAIR */

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

static EVP_PKEY *pkey;
static EVP_PKEY_CTX *gen_ctx;
static unsigned char *msg, *sig, *ours_sig;
static size_t msg_len, sig_len, ours_len;
static char ossl_name[64];
static int det = 1;

static void die(const char *what) { fprintf(stderr, "%s failed\n", what); exit(1); }

static size_t sign_op(void) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    OSSL_PARAM p[2] = {OSSL_PARAM_construct_int("deterministic", &det), OSSL_PARAM_construct_end()};
    size_t n = sig_len;
    if (!c || EVP_DigestSignInit_ex(c, NULL, NULL, NULL, NULL, pkey, p) != 1) die("DigestSignInit");
    if (EVP_DigestSign(c, sig, &n, msg, msg_len) != 1) die("DigestSign");
    EVP_MD_CTX_free(c);
    return n;
}
static size_t verify_op(void) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c || EVP_DigestVerifyInit_ex(c, NULL, NULL, NULL, NULL, pkey, NULL) != 1) die("DigestVerifyInit");
    if (EVP_DigestVerify(c, ours_sig, ours_len, msg, msg_len) != 1) die("DigestVerify (signature rejected)");
    EVP_MD_CTX_free(c);
    return 1;
}
static size_t keygen_op(void) {
    EVP_PKEY *k = NULL;
    if (EVP_PKEY_generate(gen_ctx, &k) != 1) die("EVP_PKEY_generate");
    EVP_PKEY_free(k);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    char set[32], op[16], path[96];
    int interop = 0;
    if (strncmp(argv[2], "interop/", 8) == 0) { interop = 1; strcpy(op, "sign"); snprintf(set, sizeof set, "%s", argv[2] + 8); }
    else if (sscanf(argv[2], "%31[^/]/%15s", set, op) != 2) { fprintf(stderr, "bad workload %s\n", argv[2]); return 2; }
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    // sha2_128s -> SLH-DSA-SHA2-128s
    {
        char up[32];
        size_t i = 0;
        for (; set[i] && set[i] != '_'; i++) up[i] = (char)(set[i] - 32);
        up[i] = 0;
        snprintf(ossl_name, sizeof ossl_name, "SLH-DSA-%s-%s", up, set + i + 1);
    }
    cycles_open();
    if (strcmp(op, "keygen") == 0) {
        gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, ossl_name, NULL);
        if (!gen_ctx || EVP_PKEY_keygen_init(gen_ctx) != 1) die("keygen init");
        bench(argv[2], keygen_op);
        return 0;
    }
    size_t sk_len;
    snprintf(path, sizeof path, "sk_%s.bin", set);
    unsigned char *sk = slurp(path, &sk_len);
    msg = slurp("msg.bin", &msg_len);
    snprintf(path, sizeof path, "sig_%s.bin", set);
    ours_sig = slurp(path, &ours_len);
    sig_len = ours_len;
    sig = malloc(sig_len + 64);
    EVP_PKEY_CTX *ic = EVP_PKEY_CTX_new_from_name(NULL, ossl_name, NULL);
    OSSL_PARAM kp[2] = {OSSL_PARAM_construct_octet_string("priv", sk, sk_len), OSSL_PARAM_construct_end()};
    if (!ic || EVP_PKEY_fromdata_init(ic) != 1 || EVP_PKEY_fromdata(ic, &pkey, SEL_KEYPAIR, kp) != 1) die("key import");
    if (interop) {
        if (verify_op() != 1) return 1;
        size_t n = sign_op();
        char out[96];
        snprintf(out, sizeof out, "ossl_sig_%s.bin", set);
        spit(out, sig, n);
        return 0;
    }
    if (strcmp(op, "sign") == 0) bench(argv[2], sign_op);
    else if (strcmp(op, "verify") == 0) bench(argv[2], verify_op);
    else { fprintf(stderr, "unknown op %s\n", op); return 2; }
    return 0;
}
