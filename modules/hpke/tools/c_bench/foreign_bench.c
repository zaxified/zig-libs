// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-hpke` (modules/hpke/tools/bench.zig): OpenSSL
// 3.5's libcrypto OSSL_HPKE API (RFC 9180, base mode), the fastest serious
// candidate in the field, doing the work `hpke` does on the same keys, info and
// messages. libssl is not involved.
//
// Usage: foreign_bench <work dir> <workload>   name \t ns/op \t cycles/op \t count
//        foreign_bench <work dir> interop      check against the files the Zig side wrote
//
// Workloads: <suite>_<op>, suite = x25519, p256, p384, p521 (each with the
// RFC-paired HKDF and AES-128-GCM) or x25519cc (X25519, HKDF-SHA256,
// ChaCha20Poly1305); op = keygen, setupS, setupR, seal64, open64, seal16k,
// open16k, export. OpenSSL 3.5.5 has no HPKE for the draft-ietf-hpke-pq KEMs
// (ML-KEM, X-Wing, the P-256/P-384 hybrids): those rows have no figure here.
//
//   keygen    OSSL_HPKE_keygen (random IKM drawn inside, DeriveKeyPair)
//   setupS    OSSL_HPKE_CTX_new + OSSL_HPKE_encap (ephemeral key, encap,
//             key schedule), context freed
//   setupR    OSSL_HPKE_CTX_new + OSSL_HPKE_decap, context freed
//   seal64, seal16k   OSSL_HPKE_seal on an established sender context
//   open64, open16k   OSSL_HPKE_open on an established receiver context; the
//             sequence number is rewound to 0 for each call
//             (OSSL_HPKE_CTX_set_seq), as the Zig side does
//   export    OSSL_HPKE_export (32 B)
//
// The recipient's private key is an EVP_PKEY built from the Zig side's raw
// secret key (raw X25519 key; SEC1 ECPrivateKey DER for the curves), outside the
// timed regions. OpenSSL's headers are not installed on every host, so the
// prototypes used are declared here (public API of OpenSSL 3.5's
// openssl/hpke.h). Timing matches the Zig side: double the batch until it takes
// over 100 ms, keep the best of five.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;
typedef struct {
    uint16_t kem_id;
    uint16_t kdf_id;
    uint16_t aead_id;
} OSSL_HPKE_SUITE;
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite, int role, void *libctx, const char *propq);
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);
int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);
int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx, unsigned char *enc, size_t *enclen, const unsigned char *pub, size_t publen, const unsigned char *info, size_t infolen);
int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx, const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv, const unsigned char *info, size_t infolen);
int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx, unsigned char *ct, size_t *ctlen, const unsigned char *aad, size_t aadlen, const unsigned char *pt, size_t ptlen);
int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx, unsigned char *pt, size_t *ptlen, const unsigned char *aad, size_t aadlen, const unsigned char *ct, size_t ctlen);
int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx, unsigned char *secret, size_t secretlen, const unsigned char *label, size_t labellen);
int OSSL_HPKE_keygen(OSSL_HPKE_SUITE suite, unsigned char *pub, size_t *publen, EVP_PKEY **priv, const unsigned char *ikm, size_t ikmlen, void *libctx, const char *propq);
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t max_buf_sz, size_t *out_sz);
void EVP_PKEY_free(EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length);
EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(void *libctx, const char *keytype, const char *propq, const unsigned char *priv, size_t len);
const char *OpenSSL_version(int t);
unsigned long ERR_get_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
#define EVP_PKEY_EC 408
#define OSSL_HPKE_MODE_BASE 0
#define OSSL_HPKE_ROLE_SENDER 0
#define OSSL_HPKE_ROLE_RECEIVER 1

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

typedef struct {
    const char *name;
    uint16_t kem, kdf, aead;
    size_t nsk, npk; // npk = Nenc too (DHKEM: the encapsulated key is the ephemeral public key)
    const unsigned char *oid; // EC curve OID body, NULL for X25519
    size_t oidlen;
} suite;
static const unsigned char oid_p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
static const unsigned char oid_p384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};
static const unsigned char oid_p521[] = {0x2b, 0x81, 0x04, 0x00, 0x23};
// RFC 9180 section 7 identifiers.
static const suite suites[] = {
    {"x25519", 0x20, 1, 1, 32, 32, NULL, 0},
    {"p256", 0x10, 1, 1, 32, 65, oid_p256, sizeof oid_p256},
    {"p384", 0x11, 2, 1, 48, 97, oid_p384, sizeof oid_p384},
    {"p521", 0x12, 3, 1, 66, 133, oid_p521, sizeof oid_p521},
    {"x25519cc", 0x20, 1, 3, 32, 32, NULL, 0},
};
enum { nsuites = sizeof suites / sizeof suites[0], max_enc = 140, tag = 16 };
static const unsigned char info[] = "bench info";
#define INFO_LEN (sizeof info - 1)
static const unsigned char aad[] = "interop-aad";
#define AAD_LEN (sizeof aad - 1)
static const unsigned char exporter_cx[] = "interop-export";
#define CX_LEN (sizeof exporter_cx - 1)

// Plaintexts: the same bytes as on the Zig and Go sides.
static unsigned char pt_short[64], pt_long[16384];
static void fill_plain(void) {
    for (size_t i = 0; i < sizeof pt_short; i++) pt_short[i] = (unsigned char)(i * 7 + 1);
    for (size_t i = 0; i < sizeof pt_long; i++) pt_long[i] = (unsigned char)(i * 31 + 5);
}

static OSSL_HPKE_SUITE su(const suite *s) {
    OSSL_HPKE_SUITE r = {s->kem, s->kdf, s->aead};
    return r;
}
static OSSL_HPKE_CTX *new_ctx(const suite *s, int role) {
    OSSL_HPKE_CTX *c;
    CHK(c = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, su(s), role, NULL, NULL));
    return c;
}

// The recipient key pair of the suite, from <name>.sk / <name>.pk.
static EVP_PKEY *cur_priv;
static unsigned char cur_pk[max_enc];
static const suite *cur_s;
static void load_keys(const suite *s) {
    size_t n, npk;
    char fn[64];
    snprintf(fn, sizeof fn, "%s.sk", s->name);
    unsigned char *sk = slurp(fn, &n);
    snprintf(fn, sizeof fn, "%s.pk", s->name);
    unsigned char *pk = slurp(fn, &npk);
    if (n != s->nsk || npk != s->npk) { fprintf(stderr, "%s: key sizes %zu/%zu\n", s->name, n, npk); exit(1); }
    memcpy(cur_pk, pk, npk);
    if (!s->oid) {
        CHK(cur_priv = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, sk, n));
    } else {
        // SEC1 ECPrivateKey (RFC 5915): version 1, the scalar, [0] the curve's OID.
        unsigned char der[160];
        size_t o = 0;
        der[o++] = 0x30;
        der[o++] = (unsigned char)(3 + 2 + n + 4 + s->oidlen);
        der[o++] = 0x02; der[o++] = 0x01; der[o++] = 0x01;
        der[o++] = 0x04; der[o++] = (unsigned char)n;
        memcpy(der + o, sk, n); o += n;
        der[o++] = 0xa0; der[o++] = (unsigned char)(2 + s->oidlen);
        der[o++] = 0x06; der[o++] = (unsigned char)s->oidlen;
        memcpy(der + o, s->oid, s->oidlen); o += s->oidlen;
        const unsigned char *p = der;
        CHK(cur_priv = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)o));
    }
    // The public key OpenSSL derives must be the one the Zig side wrote.
    unsigned char got[max_enc];
    size_t gn = 0;
    CHK(EVP_PKEY_get_octet_string_param(cur_priv, "pub", got, sizeof got, &gn) == 1);
    if (gn != npk || memcmp(got, pk, npk)) { fprintf(stderr, "%s: the public key derived here differs from the Zig side's\n", s->name); exit(1); }
    cur_s = s;
}

// ---- workloads ----
static OSSL_HPKE_CTX *snd, *rcv; // established contexts
static unsigned char enc_buf[max_enc], ct_short[64 + tag], ct_long[16384 + tag];
static unsigned char out_short[64], out_long[16384], seal_short[64 + tag], seal_long[16384 + tag];
static unsigned char exp_out[32];
static size_t enc_len;

static size_t keygen_once(void) {
    unsigned char pub[max_enc];
    size_t n = sizeof pub;
    EVP_PKEY *k = NULL;
    CHK(OSSL_HPKE_keygen(su(cur_s), pub, &n, &k, NULL, 0, NULL, NULL) == 1);
    EVP_PKEY_free(k);
    return n;
}
static size_t setup_s_once(void) {
    unsigned char enc[max_enc];
    size_t n = sizeof enc;
    OSSL_HPKE_CTX *c = new_ctx(cur_s, OSSL_HPKE_ROLE_SENDER);
    CHK(OSSL_HPKE_encap(c, enc, &n, cur_pk, cur_s->npk, info, INFO_LEN) == 1);
    OSSL_HPKE_CTX_free(c);
    return n;
}
static size_t setup_r_once(void) {
    OSSL_HPKE_CTX *c = new_ctx(cur_s, OSSL_HPKE_ROLE_RECEIVER);
    CHK(OSSL_HPKE_decap(c, enc_buf, enc_len, cur_priv, info, INFO_LEN) == 1);
    OSSL_HPKE_CTX_free(c);
    return 1;
}
static size_t seal64_once(void) {
    size_t n = sizeof seal_short;
    CHK(OSSL_HPKE_seal(snd, seal_short, &n, NULL, 0, pt_short, sizeof pt_short) == 1);
    return n;
}
static size_t seal16k_once(void) {
    size_t n = sizeof seal_long;
    CHK(OSSL_HPKE_seal(snd, seal_long, &n, NULL, 0, pt_long, sizeof pt_long) == 1);
    return n;
}
static size_t open64_once(void) {
    size_t n = sizeof out_short;
    CHK(OSSL_HPKE_CTX_set_seq(rcv, 0) == 1);
    CHK(OSSL_HPKE_open(rcv, out_short, &n, NULL, 0, ct_short, sizeof ct_short) == 1);
    return n;
}
static size_t open16k_once(void) {
    size_t n = sizeof out_long;
    CHK(OSSL_HPKE_CTX_set_seq(rcv, 0) == 1);
    CHK(OSSL_HPKE_open(rcv, out_long, &n, NULL, 0, ct_long, sizeof ct_long) == 1);
    return n;
}
static size_t export_once(void) {
    CHK(OSSL_HPKE_export(snd, exp_out, sizeof exp_out, exporter_cx, CX_LEN) == 1);
    return sizeof exp_out;
}

static const suite *find_suite(const char *n, size_t len) {
    for (int i = 0; i < nsuites; i++)
        if (strlen(suites[i].name) == len && !strncmp(suites[i].name, n, len)) return &suites[i];
    return NULL;
}

// ---- interop ----
static void same(const suite *s, const char *what, const unsigned char *a, const unsigned char *b, size_t n) {
    if (memcmp(a, b, n)) { fprintf(stderr, "%s: %s differs\n", s->name, what); exit(1); }
}
static unsigned char *slurpf(const char *fmt, const char *name, size_t *n) {
    char f[128];
    snprintf(f, sizeof f, fmt, name);
    return slurp(f, n);
}
static void interop(void) {
    for (int i = 0; i < nsuites; i++) {
        const suite *s = &suites[i];
        load_keys(s);
        // Zig sealed, OpenSSL opens.
        size_t n_enc, n0, n1, n_exp;
        unsigned char *enc = slurpf("zig_%s.enc", s->name, &n_enc);
        unsigned char *ct0 = slurpf("zig_%s.ct0", s->name, &n0);
        unsigned char *ct1 = slurpf("zig_%s.ct1", s->name, &n1);
        unsigned char *exp = slurpf("zig_%s.exp", s->name, &n_exp);
        if (n_enc != s->npk || n0 != sizeof pt_short + tag || n1 != sizeof pt_long + tag || n_exp != 32) {
            fprintf(stderr, "%s: the Zig side's files have unexpected sizes\n", s->name);
            exit(1);
        }
        OSSL_HPKE_CTX *r = new_ctx(s, OSSL_HPKE_ROLE_RECEIVER);
        CHK(OSSL_HPKE_decap(r, enc, n_enc, cur_priv, info, INFO_LEN) == 1);
        size_t n = sizeof out_short;
        if (OSSL_HPKE_open(r, out_short, &n, aad, AAD_LEN, ct0, n0) != 1) { fprintf(stderr, "%s: OpenSSL cannot open the Zig side's message 0\n", s->name); exit(1); }
        if (n != sizeof pt_short) { fprintf(stderr, "%s: message 0 opened to %zu bytes\n", s->name, n); exit(1); }
        same(s, "message 0 (Zig sealed)", out_short, pt_short, sizeof pt_short);
        n = sizeof out_long;
        if (OSSL_HPKE_open(r, out_long, &n, aad, AAD_LEN, ct1, n1) != 1) { fprintf(stderr, "%s: OpenSSL cannot open the Zig side's message 1\n", s->name); exit(1); }
        if (n != sizeof pt_long) { fprintf(stderr, "%s: message 1 opened to %zu bytes\n", s->name, n); exit(1); }
        same(s, "message 1 (Zig sealed)", out_long, pt_long, sizeof pt_long);
        unsigned char e[32];
        CHK(OSSL_HPKE_export(r, e, sizeof e, exporter_cx, CX_LEN) == 1);
        same(s, "export (Zig sealed)", e, exp, 32);
        OSSL_HPKE_CTX_free(r);
        // OpenSSL seals, Zig opens.
        char nm[64];
        OSSL_HPKE_CTX *c = new_ctx(s, OSSL_HPKE_ROLE_SENDER);
        unsigned char enc2[max_enc];
        size_t en = sizeof enc2;
        CHK(OSSL_HPKE_encap(c, enc2, &en, cur_pk, s->npk, info, INFO_LEN) == 1);
        snprintf(nm, sizeof nm, "ossl_%s.enc", s->name); spit(nm, enc2, en);
        size_t cn = sizeof seal_short;
        CHK(OSSL_HPKE_seal(c, seal_short, &cn, aad, AAD_LEN, pt_short, sizeof pt_short) == 1);
        snprintf(nm, sizeof nm, "ossl_%s.ct0", s->name); spit(nm, seal_short, cn);
        cn = sizeof seal_long;
        CHK(OSSL_HPKE_seal(c, seal_long, &cn, aad, AAD_LEN, pt_long, sizeof pt_long) == 1);
        snprintf(nm, sizeof nm, "ossl_%s.ct1", s->name); spit(nm, seal_long, cn);
        CHK(OSSL_HPKE_export(c, e, sizeof e, exporter_cx, CX_LEN) == 1);
        snprintf(nm, sizeof nm, "ossl_%s.exp", s->name); spit(nm, e, 32);
        OSSL_HPKE_CTX_free(c);
        EVP_PKEY_free(cur_priv);
        cur_priv = NULL;
    }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <work dir> <workload>\n", argv[0]); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    cycles_open();
    fill_plain();
    fprintf(stderr, "%s (libcrypto, OSSL_HPKE)\n", OpenSSL_version(0));
    if (!strcmp(w, "interop")) { interop(); return 0; }
    const char *us = strrchr(w, '_');
    const suite *s = us ? find_suite(w, (size_t)(us - w)) : NULL;
    if (!s) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    const char *op = us + 1;
    load_keys(s);
    // A sender context (for seal / export) and the first message a receiver opens.
    snd = new_ctx(s, OSSL_HPKE_ROLE_SENDER);
    enc_len = sizeof enc_buf;
    CHK(OSSL_HPKE_encap(snd, enc_buf, &enc_len, cur_pk, s->npk, info, INFO_LEN) == 1);
    if (!strcmp(op, "keygen")) bench(w, keygen_once);
    else if (!strcmp(op, "setupS")) bench(w, setup_s_once);
    else if (!strcmp(op, "setupR")) bench(w, setup_r_once);
    else if (!strcmp(op, "seal64")) bench(w, seal64_once);
    else if (!strcmp(op, "seal16k")) bench(w, seal16k_once);
    else if (!strcmp(op, "export")) bench(w, export_once);
    else if (!strcmp(op, "open64") || !strcmp(op, "open16k")) {
        // The ciphertext comes from a fresh sender at seq 0 (OpenSSL lets only a
        // receiver's sequence number be set), opened by a receiver whose seq is
        // rewound for each call.
        int is_short = op[4] == '6';
        OSSL_HPKE_CTX *s2 = new_ctx(s, OSSL_HPKE_ROLE_SENDER);
        unsigned char enc2[max_enc];
        size_t en = sizeof enc2, n;
        CHK(OSSL_HPKE_encap(s2, enc2, &en, cur_pk, s->npk, info, INFO_LEN) == 1);
        if (is_short) {
            n = sizeof ct_short;
            CHK(OSSL_HPKE_seal(s2, ct_short, &n, NULL, 0, pt_short, sizeof pt_short) == 1);
        } else {
            n = sizeof ct_long;
            CHK(OSSL_HPKE_seal(s2, ct_long, &n, NULL, 0, pt_long, sizeof pt_long) == 1);
        }
        rcv = new_ctx(s, OSSL_HPKE_ROLE_RECEIVER);
        CHK(OSSL_HPKE_decap(rcv, enc2, en, cur_priv, info, INFO_LEN) == 1);
        bench(w, is_short ? open64_once : open16k_once);
    } else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    return 0;
}
