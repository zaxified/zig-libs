// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-montint` (modules/montint/tools/bench.zig): times
// OpenSSL's BN Montgomery arithmetic over the modulus and operands the Zig
// program writes (big-endian) into the directory given as the first argument,
// for the one workload named by the second argument:
//   mul_<bits>   BN_mod_mul_montgomery(a, b)  -- operands already in the
//                Montgomery domain, as in the Zig side's `montMul`
//   exp_<bits>   BN_mod_exp_mont_consttime(a, e, m) -- full-width secret exponent
//   pub_<bits>   BN_mod_exp_mont(a, 65537, m) -- the RSA-verify shape
// Prints one line: name, ns/op, user-mode cycles/op (0 without a cycle
// counter), result bytes per op. The run named `interop` instead writes
// `ossl_<op>_<bits>.bin` for every op and size for the Zig side to compare.
//
// OpenSSL's headers are not installed on every host, so the few BN
// prototypes used are declared here (the public BN API, stable since 1.1).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. The BN_MONT_CTX is built once (the Zig side's
// modulus object is built once too); the BN_CTX is reused.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
BIGNUM *BN_new(void);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
BN_CTX *BN_CTX_new(void);
BN_MONT_CTX *BN_MONT_CTX_new(void);
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_MONT_CTX *mont, BN_CTX *ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
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

static BIGNUM *m, *a, *b, *e, *e65537, *r;
static BN_CTX *bctx;
static BN_MONT_CTX *mont;
static size_t nbytes;
static int op; // 0 mul, 1 exp, 2 pub

static size_t run_op(void) {
    int ok;
    if (op == 0) ok = BN_mod_mul_montgomery(r, a, b, mont, bctx);
    else if (op == 1) ok = BN_mod_exp_mont_consttime(r, a, e, m, bctx, mont);
    else ok = BN_mod_exp_mont(r, a, e65537, m, bctx, mont);
    if (!ok) { fprintf(stderr, "BN operation failed\n"); exit(1); }
    return nbytes;
}

static BIGNUM *load(const char *name, size_t want) {
    size_t n;
    unsigned char *buf = slurp(name, &n);
    if (n != want) { fprintf(stderr, "%s: %zu bytes, want %zu\n", name, n, want); exit(1); }
    return BN_bin2bn(buf, (int)n, NULL);
}

static void setup(int bits) {
    char nm[64];
    nbytes = (size_t)bits / 8;
    snprintf(nm, sizeof nm, "m%d.bin", bits);
    m = load(nm, nbytes);
    snprintf(nm, sizeof nm, "a%d.bin", bits);
    a = load(nm, nbytes);
    snprintf(nm, sizeof nm, "b%d.bin", bits);
    b = load(nm, nbytes);
    snprintf(nm, sizeof nm, "e%d.bin", bits);
    e = load(nm, nbytes);
    unsigned char p[3] = {1, 0, 1};
    e65537 = BN_bin2bn(p, 3, NULL);
    r = BN_new();
    bctx = BN_CTX_new();
    mont = BN_MONT_CTX_new();
    if (!BN_MONT_CTX_set(mont, m, bctx)) { fprintf(stderr, "BN_MONT_CTX_set failed\n"); exit(1); }
}

static const int sizes[] = {1024, 1536, 2048, 3072, 4096};

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    cycles_open();
    if (strcmp(w, "interop") == 0) {
        static const char *ops[] = {"mul", "exp", "pub"};
        for (unsigned s = 0; s < sizeof sizes / sizeof *sizes; s++) {
            setup(sizes[s]);
            unsigned char *out = malloc(nbytes);
            for (op = 0; op < 3; op++) {
                run_op();
                if (BN_bn2binpad(r, out, (int)nbytes) != (int)nbytes) { fprintf(stderr, "bn2bin\n"); return 1; }
                char nm[64];
                snprintf(nm, sizeof nm, "ossl_%s_%d.bin", ops[op], sizes[s]);
                spit(nm, out, nbytes);
            }
        }
        return 0;
    }
    int bits;
    if (sscanf(w, "mul_%d", &bits) == 1) op = 0;
    else if (sscanf(w, "exp_%d", &bits) == 1) op = 1;
    else if (sscanf(w, "pub_%d", &bits) == 1) op = 2;
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    setup(bits);
    bench(w, run_op);
    return 0;
}
