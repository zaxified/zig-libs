// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-sha2` (modules/sha2/tools/bench.zig): times
// OpenSSL's one-shot digests and HMAC over the key and message the Zig
// program writes into the directory given as the first argument, for the one
// workload named by the second argument. Prints one line: name, ns/op,
// user-mode cycles/op (0 without a cycle counter), bytes produced per op. The
// run named `interop` instead writes `ossl_<workload>.bin` (the digest or MAC)
// for every workload for the Zig side to compare byte for byte.
//
// OpenSSL's headers are not installed on every host, so the few prototypes
// used are declared here (public API, stable since 1.1/3.0).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. Workload names (the Zig side builds the same):
//   <alg>_<N> -- EVP_Digest() of the first N bytes of msg.bin, the EVP_MD
//       looked up once; alg is sha224, sha256, sha384, sha512, sha512t256;
//   hmac_<alg>_256 -- the one-shot HMAC() of the first 256 bytes under the
//       first 32 / 48 / 64 bytes of key64.bin (the digest's length), the key
//       passed afresh on every op.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct evp_md_st EVP_MD;
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sha512_256(void);
int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, void *impl);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
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

static const struct { const char *name; const EVP_MD *(*md)(void); size_t dlen; } algs[] = {
    { "sha224", EVP_sha224, 28 },     { "sha256", EVP_sha256, 32 }, { "sha384", EVP_sha384, 48 },
    { "sha512", EVP_sha512, 64 },     { "sha512t256", EVP_sha512_256, 32 },
};
#define NALGS (sizeof algs / sizeof algs[0])

static unsigned char *key, *msg, out[64];
static const EVP_MD *md;
static size_t mlen, dlen;
static int hmac_mode;

static void die(const char *what) {
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}
static size_t digest(void) {
    unsigned int l = 0;
    if (EVP_Digest(msg, mlen, out, &l, md, NULL) != 1) die("EVP_Digest");
    return (size_t)l;
}
static size_t mac(void) {
    unsigned int l = 0;
    if (!HMAC(md, key, (int)dlen, msg, mlen, out, &l)) die("HMAC");
    return (size_t)l;
}

// Select workload `w` ("sha256_64", "hmac_sha384_256"): sets md, mlen, dlen,
// hmac_mode. Returns the function to time, or NULL for an unknown name.
static size_t (*select_work(const char *w))(void) {
    hmac_mode = strncmp(w, "hmac_", 5) == 0;
    const char *rest = hmac_mode ? w + 5 : w;
    const char *us = strrchr(rest, '_');
    if (!us) return NULL;
    char *end;
    mlen = strtoul(us + 1, &end, 10);
    if (*end != 0 || end == us + 1) return NULL;
    for (size_t i = 0; i < NALGS; i++) {
        if (strlen(algs[i].name) == (size_t)(us - rest) && strncmp(algs[i].name, rest, (size_t)(us - rest)) == 0) {
            md = algs[i].md();
            dlen = algs[i].dlen;
            return hmac_mode ? mac : digest;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    key = slurp("key64.bin", NULL);
    msg = slurp("msg.bin", NULL);
    if (strcmp(w, "interop") == 0) {
        static const size_t sizes[] = { 64, 256, 1024, 16384, 1048576 };
        char name[64], file[80];
        // The workloads of bench.zig's table, in any order.
        for (int h = 0; h < 2; h++) {
            for (size_t i = 0; i < NALGS; i++) {
                size_t n_sizes = h ? 1 : sizeof sizes / sizeof sizes[0];
                for (size_t j = 0; j < n_sizes; j++) {
                    size_t n = h ? 256 : sizes[j];
                    // Only the workloads bench.zig lists: sha256/384/512 at every
                    // size, sha224 and sha512t256 at 1024, HMAC for sha256/384/512.
                    int main3 = i == 1 || i == 2 || i == 3;
                    if (h ? !main3 : (!main3 && n != 1024)) continue;
                    snprintf(name, sizeof name, "%s%s_%zu", h ? "hmac_" : "", algs[i].name, n);
                    size_t (*f)(void) = select_work(name);
                    if (!f) die("select");
                    size_t l = f();
                    snprintf(file, sizeof file, "ossl_%s.bin", name);
                    spit(file, out, l);
                }
            }
        }
        return 0;
    }
    size_t (*f)(void) = select_work(w);
    if (!f) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    cycles_open();
    bench(w, f);
    return 0;
}
