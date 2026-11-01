// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-mlkem` (modules/mlkem/tools/bench.zig): OpenSSL
// 3.5's libcrypto ML-KEM, through its public EVP APIs only, doing the work
// `mlkem` does on the same inputs.
//
// Usage: foreign_bench <work dir> <workload>   name \t ns/op \t cycles/op \t count
//        foreign_bench <work dir> interop      check against the files the Zig side wrote
//        foreign_bench <work dir> interop2     second half of the check
//
// Workloads (n = 512 | 768 | 1024), count = the size of the operation's output:
//   keygen_<n>    EVP_PKEY_generate (a cached keygen context) + the encoded
//                 encapsulation key ("pub"); count = ek octets
//   encaps_<n>    EVP_PKEY_fromdata of the ek octets (the FIPS 203 modulus check
//                 is OpenSSL's) + EVP_PKEY_encapsulate; count = ciphertext octets
//   decaps_<n>    EVP_PKEY_decapsulate with an already loaded key; count = 32
//   ek_parse_<n>  EVP_PKEY_fromdata alone; count = ek octets
//
// OpenSSL's headers are not installed on every host, so the prototypes used are
// declared here (public API; constants checked against the OpenSSL 3.5 headers).
// Timing matches the Zig side: double the batch until it takes over 100 ms, keep
// the best of five.
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
typedef struct {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_end(void);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(void *libctx, const char *name, const char *propq);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(void *libctx, EVP_PKEY *pkey, const char *propq);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[]);
void EVP_PKEY_free(EVP_PKEY *pkey);
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t max_buf_sz, size_t *out_sz);
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *wrappedkey, size_t *wrappedkeylen, unsigned char *genkey, size_t *genkeylen);
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *unwrapped, size_t *unwrappedlen, const unsigned char *wrapped, size_t wrappedlen);
const char *OpenSSL_version(int t);
unsigned long ERR_get_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
#define EVP_PKEY_PUBLIC_KEY 0x86  /* EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY */
#define EVP_PKEY_KEYPAIR 0x87

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

static void die(const char *what) {
    char e[256] = "";
    unsigned long code = ERR_get_error();
    if (code) ERR_error_string_n(code, e, sizeof e);
    fprintf(stderr, "%s failed %s\n", what, e);
    exit(1);
}
#define CHK(x) do { if (!(x)) die(#x); } while (0)

static void spit(const char *name, const void *b, size_t n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    if (fwrite(b, 1, n, f) != n) { fprintf(stderr, "short write %s\n", path); exit(1); }
    fclose(f);
}

// ---- ML-KEM ----
typedef struct {
    const char *name, *alg;
    size_t ek, dk, ct;
    EVP_PKEY_CTX *kg, *imp;
} kemp;
static kemp sets[3] = {
    {"512", "ML-KEM-512", 800, 1632, 768, NULL, NULL},
    {"768", "ML-KEM-768", 1184, 2400, 1088, NULL, NULL},
    {"1024", "ML-KEM-1024", 1568, 3168, 1568, NULL, NULL},
};
static kemp *find_set(const char *n) {
    for (int i = 0; i < 3; i++) if (!strcmp(sets[i].name, n)) return &sets[i];
    return NULL;
}
enum { max_ek = 1568, max_dk = 3168, max_ct = 1568 };

static EVP_PKEY *gen(kemp *k) {
    if (!k->kg) {
        CHK(k->kg = EVP_PKEY_CTX_new_from_name(NULL, k->alg, NULL));
        CHK(EVP_PKEY_keygen_init(k->kg) == 1);
    }
    EVP_PKEY *p = NULL;
    CHK(EVP_PKEY_generate(k->kg, &p) == 1);
    return p;
}
static void get_octets(const EVP_PKEY *p, const char *param, unsigned char *buf, size_t cap, size_t want) {
    size_t n = 0;
    CHK(EVP_PKEY_get_octet_string_param(p, param, buf, cap, &n) == 1);
    if (n != want) { fprintf(stderr, "%s is %zu octets, expected %zu\n", param, n, want); exit(1); }
}
// An ek from its wire octets (OpenSSL checks it on import) or a dk (selection KEYPAIR).
static EVP_PKEY *import(kemp *k, const char *param, int selection, const unsigned char *b, size_t len) {
    if (!k->imp) {
        CHK(k->imp = EVP_PKEY_CTX_new_from_name(NULL, k->alg, NULL));
        CHK(EVP_PKEY_fromdata_init(k->imp) == 1);
    }
    OSSL_PARAM prm[2];
    prm[0] = OSSL_PARAM_construct_octet_string(param, (void *)b, len);
    prm[1] = OSSL_PARAM_construct_end();
    EVP_PKEY *p = NULL;
    CHK(EVP_PKEY_fromdata(k->imp, &p, selection, prm) == 1);
    return p;
}
static size_t encaps(kemp *k, EVP_PKEY *pub, unsigned char *ct, unsigned char *ss) {
    EVP_PKEY_CTX *c;
    CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL));
    CHK(EVP_PKEY_encapsulate_init(c, NULL) == 1);
    size_t cl = k->ct, sl = 32;
    CHK(EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl) == 1 && cl == k->ct && sl == 32);
    EVP_PKEY_CTX_free(c);
    return cl;
}
static void decaps(EVP_PKEY *priv, const unsigned char *ct, size_t ctlen, unsigned char *ss) {
    EVP_PKEY_CTX *c;
    CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL));
    CHK(EVP_PKEY_decapsulate_init(c, NULL) == 1);
    size_t sl = 32;
    CHK(EVP_PKEY_decapsulate(c, ss, &sl, ct, ctlen) == 1 && sl == 32);
    EVP_PKEY_CTX_free(c);
}

static kemp *cur;
static EVP_PKEY *cur_key;
static unsigned char cur_ek[max_ek], cur_ct[max_ct], cur_ss[32], tmp_ct[max_ct], tmp_ek[max_ek];
static size_t keygen_once(void) {
    EVP_PKEY *p = gen(cur);
    get_octets(p, "pub", tmp_ek, sizeof tmp_ek, cur->ek);
    EVP_PKEY_free(p);
    return cur->ek;
}
static size_t encaps_once(void) {
    EVP_PKEY *p = import(cur, "pub", EVP_PKEY_PUBLIC_KEY, cur_ek, cur->ek);
    size_t n = encaps(cur, p, tmp_ct, cur_ss);
    EVP_PKEY_free(p);
    return n;
}
static size_t decaps_once(void) {
    decaps(cur_key, cur_ct, cur->ct, cur_ss);
    return 32;
}
static size_t parse_once(void) {
    EVP_PKEY *p = import(cur, "pub", EVP_PKEY_PUBLIC_KEY, cur_ek, cur->ek);
    EVP_PKEY_free(p);
    return cur->ek;
}

static void interop(void) {
    for (int i = 0; i < 3; i++) {
        kemp *k = &sets[i];
        char nm[128];
        size_t n;
        snprintf(nm, sizeof nm, "zin_mlkem%s.ek", k->name);
        unsigned char *zek = slurp(nm, &n);
        if (n != k->ek) { fprintf(stderr, "%s: bad ek length\n", nm); exit(1); }
        snprintf(nm, sizeof nm, "zin_mlkem%s.dk", k->name);
        unsigned char *zdk = slurp(nm, &n);
        if (n != k->dk) { fprintf(stderr, "%s: bad dk length\n", nm); exit(1); }
        snprintf(nm, sizeof nm, "zin_mlkem%s.ct", k->name);
        unsigned char *zct = slurp(nm, &n);
        size_t zctn = n;
        snprintf(nm, sizeof nm, "zin_mlkem%s.ss", k->name);
        unsigned char *zss = slurp(nm, &n);
        // Our key pair, loaded here: our ciphertext must decapsulate to our secret.
        EVP_PKEY *dk = import(k, "priv", EVP_PKEY_KEYPAIR, zdk, k->dk);
        unsigned char ss[32];
        decaps(dk, zct, zctn, ss);
        if (memcmp(ss, zss, 32)) { fprintf(stderr, "%s: OpenSSL decapsulates our ciphertext to another secret\n", k->name); exit(1); }
        EVP_PKEY_free(dk);
        // Encapsulate to our ek.
        EVP_PKEY *ek = import(k, "pub", EVP_PKEY_PUBLIC_KEY, zek, k->ek);
        unsigned char ct[max_ct];
        encaps(k, ek, ct, ss);
        EVP_PKEY_free(ek);
        snprintf(nm, sizeof nm, "ossl_mlkem%s.ct", k->name);
        spit(nm, ct, k->ct);
        snprintf(nm, sizeof nm, "ossl_mlkem%s.ss", k->name);
        spit(nm, ss, 32);
        // A key pair of its own.
        EVP_PKEY *own = gen(k);
        unsigned char b[max_dk];
        get_octets(own, "pub", b, sizeof b, k->ek);
        snprintf(nm, sizeof nm, "ossl_mlkem%s.ek", k->name);
        spit(nm, b, k->ek);
        get_octets(own, "priv", b, sizeof b, k->dk);
        snprintf(nm, sizeof nm, "ossl_mlkem%s.dk", k->name);
        spit(nm, b, k->dk);
        EVP_PKEY_free(own);
    }
}

static void interop2(void) {
    for (int i = 0; i < 3; i++) {
        kemp *k = &sets[i];
        char nm[128];
        size_t n, n2, n3;
        snprintf(nm, sizeof nm, "ossl_mlkem%s.dk", k->name);
        unsigned char *dkb = slurp(nm, &n);
        snprintf(nm, sizeof nm, "zig_mlkem%s.ct", k->name);
        unsigned char *ct = slurp(nm, &n2);
        snprintf(nm, sizeof nm, "zig_mlkem%s.ss", k->name);
        unsigned char *theirs = slurp(nm, &n3);
        if (n != k->dk || n2 != k->ct || n3 != 32) { fprintf(stderr, "%s: bad lengths\n", k->name); exit(1); }
        EVP_PKEY *dk = import(k, "priv", EVP_PKEY_KEYPAIR, dkb, n);
        unsigned char ss[32];
        decaps(dk, ct, n2, ss);
        if (memcmp(ss, theirs, 32)) { fprintf(stderr, "%s: the shared secrets differ (OpenSSL decapsulating our ciphertext)\n", k->name); exit(1); }
        EVP_PKEY_free(dk);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <work dir> <workload>\n", argv[0]); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    cycles_open();
    fprintf(stderr, "%s (libcrypto, public EVP APIs)\n", OpenSSL_version(0));
    if (!strcmp(w, "interop")) { interop(); return 0; }
    if (!strcmp(w, "interop2")) { interop2(); return 0; }
    const char *us = strrchr(w, '_');
    if (!us) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    cur = find_set(us + 1);
    if (!cur) { fprintf(stderr, "unknown parameter set in %s\n", w); return 2; }
    // A key pair of this set, an ek, and a ciphertext for it.
    cur_key = gen(cur);
    get_octets(cur_key, "pub", cur_ek, sizeof cur_ek, cur->ek);
    EVP_PKEY *pub = import(cur, "pub", EVP_PKEY_PUBLIC_KEY, cur_ek, cur->ek);
    encaps(cur, pub, cur_ct, cur_ss);
    EVP_PKEY_free(pub);
    if (!strncmp(w, "keygen_", 7)) bench(w, keygen_once);
    else if (!strncmp(w, "encaps_", 7)) bench(w, encaps_once);
    else if (!strncmp(w, "decaps_", 7)) bench(w, decaps_once);
    else if (!strncmp(w, "ek_parse_", 9)) bench(w, parse_once);
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    return 0;
}
