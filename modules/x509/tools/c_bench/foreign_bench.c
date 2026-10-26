// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-x509` (modules/x509/tools/bench.zig): OpenSSL's
// X509_verify_cert as the fastest-in-the-field side. Reads the chains the Go
// side wrote into the directory given as the first argument
// (`<kind>_{leaf,inter,root}.der`, `now.txt`) and times the one workload
// named by the second argument. Prints one line: name, ns/op, user-mode
// cycles/op (0 without a cycle counter), certificates in the verified chain.
// The run named `check` instead verifies every chain with the right host
// (must pass) and a wrong one (must fail), and exits non-zero otherwise.
//
// Workload `verify_<kind>`, the shape of the other two sides: d2i_X509 of
// leaf and intermediate, a fresh untrusted stack and X509_STORE_CTX, and
// X509_verify_cert against an X509_STORE holding the root, parsed once (as
// Go's root pool), with the verification time, the host
// (X509_VERIFY_PARAM_set1_host) and the sslserver purpose set.
//
// OpenSSL's headers are not installed on every host, so the few prototypes
// used are declared here (public API, stable since 1.1/3.0).
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
typedef struct stack_st OPENSSL_STACK;
X509 *d2i_X509(X509 **a, const unsigned char **in, long len);
void X509_free(X509 *x);
X509_STORE *X509_STORE_new(void);
int X509_STORE_add_cert(X509_STORE *s, X509 *x);
X509_STORE_CTX *X509_STORE_CTX_new(void);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *s, X509 *target, OPENSSL_STACK *untrusted);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(const X509_STORE_CTX *ctx);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *p, time_t t);
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *p, const char *name, size_t namelen);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_verify_cert(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx);
const char *X509_verify_cert_error_string(long n);
OPENSSL_STACK *X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx);
OPENSSL_STACK *OPENSSL_sk_new_null(void);
int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
int OPENSSL_sk_num(const OPENSSL_STACK *st);
void OPENSSL_sk_free(OPENSSL_STACK *st);
const char *OpenSSL_version(int t);
#define X509_PURPOSE_SSL_SERVER 2

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

static const char *kinds[] = { "ecdsa256", "rsa2048", "mixed" };
#define NKINDS (sizeof kinds / sizeof kinds[0])
static const char *host = "bench.example.test";

static unsigned char *leaf, *inter;
static size_t leaf_len, inter_len;
static X509_STORE *store;
static time_t now;
static const char *want_host;
static int last_error;

static void die(const char *what) {
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}

// One verification; returns the chain length, 0 when it does not verify.
static size_t verify(void) {
    const unsigned char *p = leaf;
    X509 *l = d2i_X509(NULL, &p, (long)leaf_len);
    p = inter;
    X509 *i = d2i_X509(NULL, &p, (long)inter_len);
    if (!l || !i) die("d2i_X509");
    OPENSSL_STACK *untrusted = OPENSSL_sk_new_null();
    if (!untrusted || !OPENSSL_sk_push(untrusted, i)) die("sk_push");
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx || X509_STORE_CTX_init(ctx, store, l, untrusted) != 1) die("X509_STORE_CTX_init");
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(param, now);
    if (X509_VERIFY_PARAM_set1_host(param, want_host, 0) != 1) die("set1_host");
    if (X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER) != 1) die("set_purpose");
    size_t n = 0;
    if (X509_verify_cert(ctx) == 1) n = (size_t)OPENSSL_sk_num(X509_STORE_CTX_get0_chain(ctx));
    else last_error = X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);
    OPENSSL_sk_free(untrusted);
    X509_free(i);
    X509_free(l);
    return n;
}

static size_t verify_timed(void) {
    size_t n = verify();
    if (n != 3) die("X509_verify_cert");
    return n;
}

static void load(const char *kind) {
    char name[64];
    snprintf(name, sizeof name, "%s_leaf.der", kind);
    leaf = slurp(name, &leaf_len);
    snprintf(name, sizeof name, "%s_inter.der", kind);
    inter = slurp(name, &inter_len);
    size_t root_len;
    snprintf(name, sizeof name, "%s_root.der", kind);
    unsigned char *root_der = slurp(name, &root_len);
    const unsigned char *p = root_der;
    X509 *root = d2i_X509(NULL, &p, (long)root_len);
    store = X509_STORE_new();
    if (!root || !store || X509_STORE_add_cert(store, root) != 1) die("root store");
    X509_free(root);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    char *now_txt = (char *)slurp("now.txt", NULL);
    now = (time_t)strtoll(now_txt, NULL, 10);
    if (strcmp(w, "check") == 0) {
        for (size_t k = 0; k < NKINDS; k++) {
            load(kinds[k]);
            want_host = host;
            if (verify() != 3) { fprintf(stderr, "%s: OpenSSL refuses the chain: %s\n", kinds[k], X509_verify_cert_error_string(last_error)); return 1; }
            want_host = "other.example.test";
            if (verify() != 0) { fprintf(stderr, "%s: OpenSSL accepts a wrong host\n", kinds[k]); return 1; }
        }
        return 0;
    }
    if (strncmp(w, "verify_", 7) != 0) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    size_t k = 0;
    while (k < NKINDS && strcmp(kinds[k], w + 7) != 0) k++;
    if (k == NKINDS) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    load(kinds[k]);
    want_host = host;
    cycles_open();
    bench(w, verify_timed);
    return 0;
}
