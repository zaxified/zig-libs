// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-tls13` (modules/tls13/tools/bench.zig): OpenSSL
// 3.5's libcrypto, through its public EVP APIs only, doing the work `tls13`
// does -- the RFC 8446 key schedule, the key-exchange groups of a TLS 1.3
// handshake and the CertificateVerify signatures -- on the same inputs.
// libssl is not involved; what a TLS stack calls (EVP_KDF "HKDF",
// EVP_PKEY keygen / derive / encapsulate / decapsulate, EVP_DigestSign /
// EVP_DigestVerify) is timed directly.
//
// Usage: foreign_bench <work dir> <workload>   name \t ns/op \t cycles/op \t count
//        foreign_bench <work dir> interop      check against the files the Zig side wrote
//        foreign_bench <work dir> interop2     second half of the key-exchange check
//
// Workloads (count is always 1):
//   ks256, ks384      one full-handshake key schedule: early, handshake, master
//                     secrets, the two handshake and the two application traffic
//                     secrets, the exporter master secret and one 32-octet
//                     TLS-Exporter output (13 EVP_KDF "HKDF" derive calls, a fresh
//                     EVP_KDF_CTX per call, plus the exporter's context hash)
//   gen_<g>           the client's key generation and the encoding of its share
//   srv_<g>           the server: parse the client's share, generate / encapsulate,
//                     encode its share, derive the shared secret
//   cli_<g>           the client: parse the server's share, derive / decapsulate
//   sign_<s>, verify_<s>   a CertificateVerify signature over the RFC 8446
//                     4.4.3 signed content (a fresh EVP_MD_CTX per call, as libssl)
// <g> is secp256r1, ... as in bench.zig (ffdhe2048 / ffdhe3072 / ffdhe4096: an OpenSSL "DH" key
// of the RFC 7919 named group, shares through EVP_PKEY_get1/set1_encoded_public_key and the
// padded derive, as libssl does in TLS 1.3); hybrids are composed from their parts in
// the draft's layout (X25519MLKEM768: ML-KEM first; SecP256r1MLKEM768 and
// SecP384r1MLKEM1024: the ECDH element first), shared secret = the parts' secrets
// concatenated in the same order.
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
typedef struct evp_md_st EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_kdf_st EVP_KDF;
typedef struct evp_kdf_ctx_st EVP_KDF_CTX;
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct ossl_param_bld_st OSSL_PARAM_BLD;
typedef struct {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
} OSSL_PARAM;
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
OSSL_PARAM OSSL_PARAM_construct_end(void);
OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn);
OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld);
void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld);
void OSSL_PARAM_free(OSSL_PARAM *p);
BIGNUM *BN_new(void);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
BN_CTX *BN_CTX_new(void);
const BIGNUM *BN_value_one(void);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(void *libctx, const char *name, const char *propq);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(void *libctx, EVP_PKEY *pkey, const char *propq);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[]);
void EVP_PKEY_free(EVP_PKEY *pkey);
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t max_buf_sz, size_t *out_sz);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad);
int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey, const unsigned char *pub, size_t publen);
size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub);
void CRYPTO_free(void *ptr, const char *file, int line);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *wrappedkey, size_t *wrappedkeylen, unsigned char *genkey, size_t *genkeylen);
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *unwrapped, size_t *unwrappedlen, const unsigned char *wrapped, size_t wrappedlen);
int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length);
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
EVP_PKEY *EVP_PKEY_new_raw_private_key_ex(void *libctx, const char *keytype, const char *propq, const unsigned char *priv, size_t len);
EVP_MD *EVP_MD_fetch(void *ctx, const char *algorithm, const char *properties);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type, const OSSL_PARAM params[]);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, void *e, EVP_PKEY *pkey);
int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, void *e, EVP_PKEY *pkey);
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode);
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
EVP_KDF *EVP_KDF_fetch(void *libctx, const char *algorithm, const char *properties);
EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf);
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);
int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
const char *OpenSSL_version(int t);
unsigned long ERR_get_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
#define EVP_PKEY_EC 408
#define EVP_PKEY_KEY_PARAMETERS 0x84 /* OSSL_KEYMGMT_SELECT_ALL_PARAMETERS */
#define EVP_PKEY_PUBLIC_KEY 0x86  /* EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY */
#define EVP_PKEY_KEYPAIR 0x87
#define RSA_PKCS1_PSS_PADDING 6
#define RSA_PSS_SALTLEN_DIGEST (-1)
#define KDF_EXTRACT_ONLY 1
#define KDF_EXPAND_ONLY 2

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
static unsigned char *slurpf(const char *fmt, const char *a, const char *b, size_t *len) {
    char n[256];
    snprintf(n, sizeof n, fmt, a, b);
    return slurp(n, len);
}

// ---- key schedule (RFC 8446 section 7.1) over EVP_KDF "HKDF" ----
static EVP_KDF *kdf13;
static EVP_MD *md256, *md384;
static EVP_MD_CTX *hctx;
typedef struct {
    const char *dg;
    size_t L;
    EVP_MD *md;
    unsigned char empty[48];
    unsigned char dhe[48], th_hs[48], th_ap[48];
} ksp;
static ksp ks[2];
static const unsigned char ks_ctx[16] = "bench-exporter-c";
static const char ks_label[] = "EXPERIMENTAL bench";
static void ks_init(void) {
    CHK(kdf13 = EVP_KDF_fetch(NULL, "HKDF", NULL));
    CHK(md256 = EVP_MD_fetch(NULL, "SHA256", NULL));
    CHK(md384 = EVP_MD_fetch(NULL, "SHA384", NULL));
    CHK(hctx = EVP_MD_CTX_new());
    for (int i = 0; i < 2; i++) {
        ksp *k = &ks[i];
        k->dg = i ? "SHA384" : "SHA256";
        k->L = i ? 48 : 32;
        k->md = i ? md384 : md256;
        unsigned int n;
        CHK(EVP_DigestInit_ex2(hctx, k->md, NULL) && EVP_DigestFinal_ex(hctx, k->empty, &n));
        for (size_t j = 0; j < k->L; j++) {
            k->dhe[j] = (unsigned char)(j * 3 + 1);
            k->th_hs[j] = (unsigned char)(0x40 + j);
            k->th_ap[j] = (unsigned char)(0x80 + j);
        }
    }
}
// A fresh EVP_KDF_CTX per call, as libssl's tls13_hkdf_expand / tls13_generate_secret do.
static void derive1(unsigned char *out, size_t n, const OSSL_PARAM *p) {
    EVP_KDF_CTX *c;
    CHK(c = EVP_KDF_CTX_new(kdf13));
    CHK(EVP_KDF_derive(c, out, n, p) > 0);
    EVP_KDF_CTX_free(c);
}
static void extract(const ksp *k, unsigned char *out, const unsigned char *salt, const unsigned char *ikm) {
    int mode = KDF_EXTRACT_ONLY;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)k->dg, 0),
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_octet_string("key", (void *)ikm, k->L),
        OSSL_PARAM_construct_octet_string("salt", (void *)salt, k->L),
        OSSL_PARAM_construct_end(),
    };
    derive1(out, k->L, p);
}
// HKDF-Expand-Label (RFC 8446 7.1): the HkdfLabel is built here, EVP_KDF "HKDF" expands.
static void expand(const ksp *k, unsigned char *out, size_t outlen, const unsigned char *secret, const char *label, const unsigned char *data) {
    int mode = KDF_EXPAND_ONLY;
    unsigned char info[2 + 1 + 6 + 255 + 1 + 48];
    size_t ll = strlen(label), n = 0;
    info[n++] = (unsigned char)(outlen >> 8);
    info[n++] = (unsigned char)outlen;
    info[n++] = (unsigned char)(6 + ll);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ll); n += ll;
    info[n++] = (unsigned char)k->L;
    memcpy(info + n, data, k->L); n += k->L;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)k->dg, 0),
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_octet_string("key", (void *)secret, k->L),
        OSSL_PARAM_construct_octet_string("info", info, n),
        OSSL_PARAM_construct_end(),
    };
    derive1(out, outlen, p);
}
// out: early, hs, hs_c, hs_s, ms, ap_c, ap_s, exp (L each), then 32 exported.
static void ks_run(const ksp *k, unsigned char *out) {
    size_t L = k->L;
    unsigned char zeros[48] = {0}, derived[48], dm[48], ch[48];
    unsigned char *early = out, *hs = out + L, *hs_c = out + 2 * L, *hs_s = out + 3 * L, *ms = out + 4 * L;
    unsigned char *ap_c = out + 5 * L, *ap_s = out + 6 * L, *exp = out + 7 * L, *exported = out + 8 * L;
    extract(k, early, zeros, zeros);
    expand(k, derived, L, early, "derived", k->empty);
    extract(k, hs, derived, k->dhe);
    expand(k, hs_c, L, hs, "c hs traffic", k->th_hs);
    expand(k, hs_s, L, hs, "s hs traffic", k->th_hs);
    expand(k, derived, L, hs, "derived", k->empty);
    extract(k, ms, derived, zeros);
    expand(k, ap_c, L, ms, "c ap traffic", k->th_ap);
    expand(k, ap_s, L, ms, "s ap traffic", k->th_ap);
    expand(k, exp, L, ms, "exp master", k->th_ap);
    expand(k, dm, L, exp, ks_label, k->empty);
    unsigned int n;
    CHK(EVP_DigestInit_ex2(hctx, k->md, NULL) && EVP_DigestUpdate(hctx, ks_ctx, sizeof ks_ctx) && EVP_DigestFinal_ex(hctx, ch, &n));
    expand(k, exported, 32, dm, "exporter", ch);
}
static unsigned char ks_out[8 * 48 + 32];
static const ksp *ks_cur;
static size_t ks_once(void) {
    ks_run(ks_cur, ks_out);
    return 1;
}

// ---- key exchange ----
typedef struct {
    const char *alg, *grp;
    size_t cpub, spub, ss;
    int kem;
    EVP_PKEY_CTX *kg, *imp;
    int dh; // an RFC 7919 FFDHE group ("DH" key): shares are len(p) octets, the secret is padded
} part;
static part P_X25519 = {"X25519", NULL, 32, 32, 32, 0};
static part P_P256 = {"EC", "P-256", 65, 65, 32, 0};
static part P_P384 = {"EC", "P-384", 97, 97, 48, 0};
static part P_K768 = {"ML-KEM-768", NULL, 1184, 1088, 32, 1};
static part P_K1024 = {"ML-KEM-1024", NULL, 1568, 1568, 32, 1};
static part P_DH2048 = {"DH", "ffdhe2048", 256, 256, 256, 0, NULL, NULL, 1};
static part P_DH3072 = {"DH", "ffdhe3072", 384, 384, 384, 0, NULL, NULL, 1};
static part P_DH4096 = {"DH", "ffdhe4096", 512, 512, 512, 0, NULL, NULL, 1};
typedef struct {
    const char *name;
    int n;
    part *p[2];
} group;
static group groups[] = {
    {"x25519", 1, {&P_X25519}},
    {"secp256r1", 1, {&P_P256}},
    {"secp384r1", 1, {&P_P384}},
    {"x25519mlkem768", 2, {&P_K768, &P_X25519}},
    {"secp256r1mlkem768", 2, {&P_P256, &P_K768}},
    {"secp384r1mlkem1024", 2, {&P_P384, &P_K1024}},
    {"mlkem1024", 1, {&P_K1024}},
    {"ffdhe2048", 1, {&P_DH2048}},
    {"ffdhe3072", 1, {&P_DH3072}},
    {"ffdhe4096", 1, {&P_DH4096}},
};
enum { ngroups = sizeof groups / sizeof groups[0], max_share = 1700, max_ss = 512 };
static size_t g_cpub(const group *g) { size_t n = 0; for (int i = 0; i < g->n; i++) n += g->p[i]->cpub; return n; }
static size_t g_spub(const group *g) { size_t n = 0; for (int i = 0; i < g->n; i++) n += g->p[i]->spub; return n; }
static size_t g_ss(const group *g) { size_t n = 0; for (int i = 0; i < g->n; i++) n += g->p[i]->ss; return n; }

static EVP_PKEY *part_gen(part *p) {
    if (!p->kg) {
        CHK(p->kg = EVP_PKEY_CTX_new_from_name(NULL, p->alg, NULL));
        CHK(EVP_PKEY_keygen_init(p->kg) == 1);
        if (p->grp) CHK(EVP_PKEY_CTX_set_group_name(p->kg, p->grp) == 1);
    }
    EVP_PKEY *k = NULL;
    CHK(EVP_PKEY_generate(p->kg, &k) == 1);
    return k;
}
static void part_pub(EVP_PKEY *k, unsigned char *buf, size_t want, int dh) {
    size_t n = 0;
    if (dh) {
        unsigned char *e = NULL;
        CHK((n = EVP_PKEY_get1_encoded_public_key(k, &e)) > 0);
        if (n != want) { fprintf(stderr, "public key is %zu octets, expected %zu\n", n, want); exit(1); }
        memcpy(buf, e, n);
        CRYPTO_free(e, "foreign_bench.c", __LINE__);
        return;
    }
    CHK(EVP_PKEY_get_octet_string_param(k, "pub", buf, want + 8, &n) == 1);
    if (n != want) { fprintf(stderr, "public key is %zu octets, expected %zu\n", n, want); exit(1); }
}
// A peer's public key from its wire octets (the point is checked on import).
static EVP_PKEY *part_import(part *p, const unsigned char *pub, size_t len) {
    if (!p->imp) {
        CHK(p->imp = EVP_PKEY_CTX_new_from_name(NULL, p->alg, NULL));
        CHK(EVP_PKEY_fromdata_init(p->imp) == 1);
    }
    char grp[16] = "";
    if (p->grp) strcpy(grp, p->grp);
    OSSL_PARAM prm[3];
    int n = 0;
    if (p->dh) {
        // The named group's parameters, then the peer value (checked at derive), as libssl does.
        EVP_PKEY *k = NULL;
        prm[n++] = OSSL_PARAM_construct_utf8_string("group", grp, 0);
        prm[n++] = OSSL_PARAM_construct_end();
        CHK(EVP_PKEY_fromdata(p->imp, &k, EVP_PKEY_KEY_PARAMETERS, prm) == 1);
        CHK(EVP_PKEY_set1_encoded_public_key(k, pub, len) == 1);
        return k;
    }
    if (p->grp) prm[n++] = OSSL_PARAM_construct_utf8_string("group", grp, 0);
    prm[n++] = OSSL_PARAM_construct_octet_string("pub", (void *)pub, len);
    prm[n++] = OSSL_PARAM_construct_end();
    EVP_PKEY *k = NULL;
    CHK(EVP_PKEY_fromdata(p->imp, &k, EVP_PKEY_PUBLIC_KEY, prm) == 1);
    return k;
}
static void ecdh(EVP_PKEY *local, EVP_PKEY *peer, unsigned char *out, size_t want, int dh) {
    EVP_PKEY_CTX *c;
    CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, local, NULL));
    CHK(EVP_PKEY_derive_init(c) == 1);
    if (dh) CHK(EVP_PKEY_CTX_set_dh_pad(c, 1) > 0); // RFC 8446 section 7.4.1: leading zeros kept
    CHK(EVP_PKEY_derive_set_peer(c, peer) == 1);
    size_t n = want;
    CHK(EVP_PKEY_derive(c, out, &n) == 1 && n == want);
    EVP_PKEY_CTX_free(c);
}
static void part_server(part *p, const unsigned char *cpub, unsigned char *spub, unsigned char *ss) {
    EVP_PKEY *peer = part_import(p, cpub, p->cpub);
    if (p->kem) {
        EVP_PKEY_CTX *c;
        CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL));
        CHK(EVP_PKEY_encapsulate_init(c, NULL) == 1);
        size_t wl = p->spub, sl = p->ss;
        CHK(EVP_PKEY_encapsulate(c, spub, &wl, ss, &sl) == 1 && wl == p->spub && sl == p->ss);
        EVP_PKEY_CTX_free(c);
    } else {
        EVP_PKEY *k = part_gen(p);
        part_pub(k, spub, p->spub, p->dh);
        ecdh(k, peer, ss, p->ss, p->dh);
        EVP_PKEY_free(k);
    }
    EVP_PKEY_free(peer);
}
static void part_client(part *p, EVP_PKEY *local, const unsigned char *spub, unsigned char *ss) {
    if (p->kem) {
        EVP_PKEY_CTX *c;
        CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, local, NULL));
        CHK(EVP_PKEY_decapsulate_init(c, NULL) == 1);
        size_t n = p->ss;
        CHK(EVP_PKEY_decapsulate(c, ss, &n, spub, p->spub) == 1 && n == p->ss);
        EVP_PKEY_CTX_free(c);
    } else {
        EVP_PKEY *peer = part_import(p, spub, p->spub);
        ecdh(local, peer, ss, p->ss, p->dh);
        EVP_PKEY_free(peer);
    }
}
static void group_server(const group *g, const unsigned char *cshare, unsigned char *sshare, unsigned char *ss) {
    size_t co = 0, so = 0, xo = 0;
    for (int i = 0; i < g->n; i++) {
        part *p = g->p[i];
        part_server(p, cshare + co, sshare + so, ss + xo);
        co += p->cpub; so += p->spub; xo += p->ss;
    }
}
static void group_client(const group *g, EVP_PKEY **keys, const unsigned char *sshare, unsigned char *ss) {
    size_t so = 0, xo = 0;
    for (int i = 0; i < g->n; i++) {
        part *p = g->p[i];
        part_client(p, keys[i], sshare + so, ss + xo);
        so += p->spub; xo += p->ss;
    }
}
static void group_gen(const group *g, EVP_PKEY **keys, unsigned char *cshare) {
    size_t co = 0;
    for (int i = 0; i < g->n; i++) {
        keys[i] = part_gen(g->p[i]);
        part_pub(keys[i], cshare + co, g->p[i]->cpub, g->p[i]->dh);
        co += g->p[i]->cpub;
    }
}
static const group *cur_g;
static EVP_PKEY *cur_keys[2];
static unsigned char cur_cshare[max_share], cur_sshare[max_share], cur_ss[max_ss];
static size_t gen_once(void) {
    EVP_PKEY *k[2];
    group_gen(cur_g, k, cur_cshare);
    for (int i = 0; i < cur_g->n; i++) EVP_PKEY_free(k[i]);
    return 1;
}
static size_t srv_once(void) {
    group_server(cur_g, cur_cshare, cur_sshare, cur_ss);
    return 1;
}
static size_t cli_once(void) {
    group_client(cur_g, cur_keys, cur_sshare, cur_ss);
    return 1;
}
static const group *find_group(const char *n) {
    for (int i = 0; i < ngroups; i++) if (!strcmp(groups[i].name, n)) return &groups[i];
    return NULL;
}

// ---- CertificateVerify ----
enum { nsch = 4 };
static const char *sch_name[nsch] = {"ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha256", "ed25519"};
static const char *sch_md[nsch] = {"SHA256", "SHA384", "SHA256", NULL};
static const size_t sch_th[nsch] = {32, 48, 32, 32};
static const unsigned char sch_thbyte[nsch] = {0x11, 0x22, 0x11, 0x11};
static EVP_PKEY *sch_key[nsch];
static EVP_MD *sch_mdp[nsch];
static unsigned char sch_content[nsch][200];
static size_t sch_clen[nsch];
static void load_keys(void) {
    size_t n;
    const unsigned char *p;
    unsigned char *b;
    b = slurp("ec256.der", &n); p = b;
    CHK(sch_key[0] = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)n));
    b = slurp("ec384.der", &n); p = b;
    CHK(sch_key[1] = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)n));
    b = slurp("ed25519.seed", &n);
    CHK(n == 32 && (sch_key[3] = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, b, 32)));
    // RSA: n, e, d, p, q (big-endian octets); the CRT values are derived here.
    const char *nm[5] = {"rsa_n.bin", "rsa_e.bin", "rsa_d.bin", "rsa_p.bin", "rsa_q.bin"};
    BIGNUM *v[5];
    for (int i = 0; i < 5; i++) { b = slurp(nm[i], &n); CHK(v[i] = BN_bin2bn(b, (int)n, NULL)); }
    BN_CTX *bc = BN_CTX_new();
    BIGNUM *pm1 = BN_new(), *qm1 = BN_new(), *dp = BN_new(), *dq = BN_new(), *qinv = BN_new();
    CHK(BN_sub(pm1, v[3], BN_value_one()) && BN_sub(qm1, v[4], BN_value_one()));
    CHK(BN_div(NULL, dp, v[2], pm1, bc) && BN_div(NULL, dq, v[2], qm1, bc) && BN_mod_inverse(qinv, v[4], v[3], bc));
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    CHK(OSSL_PARAM_BLD_push_BN(bld, "n", v[0]) && OSSL_PARAM_BLD_push_BN(bld, "e", v[1]) && OSSL_PARAM_BLD_push_BN(bld, "d", v[2]));
    CHK(OSSL_PARAM_BLD_push_BN(bld, "rsa-factor1", v[3]) && OSSL_PARAM_BLD_push_BN(bld, "rsa-factor2", v[4]));
    CHK(OSSL_PARAM_BLD_push_BN(bld, "rsa-exponent1", dp) && OSSL_PARAM_BLD_push_BN(bld, "rsa-exponent2", dq) && OSSL_PARAM_BLD_push_BN(bld, "rsa-coefficient1", qinv));
    OSSL_PARAM *prm;
    CHK(prm = OSSL_PARAM_BLD_to_param(bld));
    EVP_PKEY_CTX *c;
    CHK(c = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL));
    CHK(EVP_PKEY_fromdata_init(c) == 1 && EVP_PKEY_fromdata(c, &sch_key[2], EVP_PKEY_KEYPAIR, prm) == 1);
    for (int i = 0; i < nsch; i++) {
        if (sch_md[i]) CHK(sch_mdp[i] = EVP_MD_fetch(NULL, sch_md[i], NULL));
        // 64 x 0x20 || context string || 0x00 || transcript hash (RFC 8446 4.4.3)
        unsigned char *c2 = sch_content[i];
        memset(c2, 0x20, 64);
        const char *cs = "TLS 1.3, server CertificateVerify";
        memcpy(c2 + 64, cs, strlen(cs));
        c2[64 + strlen(cs)] = 0;
        memset(c2 + 65 + strlen(cs), sch_thbyte[i], sch_th[i]);
        sch_clen[i] = 65 + strlen(cs) + sch_th[i];
    }
}
static void pss(int i, EVP_PKEY_CTX *pc) {
    if (i != 2) return;
    CHK(EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) > 0);
    CHK(EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) > 0);
    CHK(EVP_PKEY_CTX_set_rsa_mgf1_md(pc, sch_mdp[i]) > 0);
}
static size_t sig_sign(int i, unsigned char *sig, size_t cap) {
    EVP_MD_CTX *m;
    EVP_PKEY_CTX *pc = NULL;
    CHK(m = EVP_MD_CTX_new());
    CHK(EVP_DigestSignInit(m, &pc, sch_mdp[i], NULL, sch_key[i]) == 1);
    pss(i, pc);
    size_t n = cap;
    CHK(EVP_DigestSign(m, sig, &n, sch_content[i], sch_clen[i]) == 1);
    EVP_MD_CTX_free(m);
    return n;
}
static int sig_verify(int i, const unsigned char *sig, size_t n) {
    EVP_MD_CTX *m;
    EVP_PKEY_CTX *pc = NULL;
    CHK(m = EVP_MD_CTX_new());
    CHK(EVP_DigestVerifyInit(m, &pc, sch_mdp[i], NULL, sch_key[i]) == 1);
    pss(i, pc);
    int r = EVP_DigestVerify(m, sig, n, sch_content[i], sch_clen[i]);
    EVP_MD_CTX_free(m);
    return r == 1;
}
static int cur_s;
static unsigned char cur_sig[512];
static size_t cur_siglen;
static size_t sign_once(void) {
    return sig_sign(cur_s, cur_sig, sizeof cur_sig) ? 1 : 0;
}
static size_t verify_once(void) {
    if (!sig_verify(cur_s, cur_sig, cur_siglen)) die("verify");
    return 1;
}
static int find_sch(const char *n) {
    for (int i = 0; i < nsch; i++) if (!strcmp(sch_name[i], n)) return i;
    return -1;
}

// ---- interop ----
static void interop(void) {
    // Key schedule: identical secrets for the fixed inputs.
    for (int i = 0; i < 2; i++) {
        size_t n;
        char name[32];
        snprintf(name, sizeof name, "zig_ks%d.bin", i ? 384 : 256);
        unsigned char *theirs = slurp(name, &n);
        unsigned char mine[8 * 48 + 32];
        ks_run(&ks[i], mine);
        if (n != 8 * ks[i].L + 32) { fprintf(stderr, "key schedule %s: the Zig side wrote %zu octets\n", i ? "SHA-384" : "SHA-256", n); exit(1); }
        static const char *const secret_name[9] = {"early", "handshake", "client hs traffic", "server hs traffic", "master", "client ap traffic", "server ap traffic", "exporter master", "exported"};
        int bad = 0;
        for (int s = 0; s < 9; s++) {
            size_t off = (size_t)s * ks[i].L, len = s == 8 ? 32 : ks[i].L;
            if (memcmp(theirs + off, mine + off, len)) {
                fprintf(stderr, "key schedule %s: %s differs (ours %02x%02x%02x%02x.., OpenSSL %02x%02x%02x%02x..)\n", i ? "SHA-384" : "SHA-256", secret_name[s], theirs[off], theirs[off + 1], theirs[off + 2], theirs[off + 3], mine[off], mine[off + 1], mine[off + 2], mine[off + 3]);
                bad = 1;
            }
        }
        if (bad) exit(1);
    }
    // Key exchange, half one: serve the Zig client's share, publish a client share of our own.
    for (int gi = 0; gi < ngroups; gi++) {
        const group *g = &groups[gi];
        size_t n;
        unsigned char *cs = slurpf("zig_%s%s.cshare", g->name, "", &n);
        if (n != g_cpub(g)) { fprintf(stderr, "%s: client share is %zu octets\n", g->name, n); exit(1); }
        unsigned char ss[max_ss], sshare[max_share];
        group_server(g, cs, sshare, ss);
        char nm[128];
        snprintf(nm, sizeof nm, "ossl_%s.sshare", g->name); spit(nm, sshare, g_spub(g));
        snprintf(nm, sizeof nm, "ossl_%s.sss", g->name); spit(nm, ss, g_ss(g));
        EVP_PKEY *keys[2];
        unsigned char cshare[max_share];
        group_gen(g, keys, cshare);
        snprintf(nm, sizeof nm, "ossl_%s.cshare", g->name); spit(nm, cshare, g_cpub(g));
        for (int i = 0; i < g->n; i++) {
            unsigned char der[16384], *p = der;
            int dl = i2d_PrivateKey(keys[i], &p);
            CHK(dl > 0);
            snprintf(nm, sizeof nm, "ossl_%s.cpriv%d", g->name, i); spit(nm, der, (size_t)dl);
        }
    }
    // Signatures: verify the Zig side's, publish ours.
    load_keys();
    for (int i = 0; i < nsch; i++) {
        size_t n;
        unsigned char *sg = slurpf("zig_sig_%s%s.sig", sch_name[i], "", &n);
        if (!sig_verify(i, sg, n)) { fprintf(stderr, "%s: OpenSSL does not verify our signature\n", sch_name[i]); exit(1); }
        unsigned char mine[512];
        size_t ml = sig_sign(i, mine, sizeof mine);
        char nm[128];
        snprintf(nm, sizeof nm, "ossl_sig_%s.sig", sch_name[i]); spit(nm, mine, ml);
    }
}
static void interop2(void) {
    for (int gi = 0; gi < ngroups; gi++) {
        const group *g = &groups[gi];
        EVP_PKEY *keys[2];
        for (int i = 0; i < g->n; i++) {
            size_t n;
            char nm[128];
            snprintf(nm, sizeof nm, "ossl_%s.cpriv%d", g->name, i);
            unsigned char *b = slurp(nm, &n);
            const unsigned char *p = b;
            CHK(keys[i] = d2i_AutoPrivateKey(NULL, &p, (long)n));
        }
        size_t n1, n2;
        unsigned char *sshare = slurpf("zig_%s%s.sshare", g->name, "", &n1);
        unsigned char *theirs = slurpf("zig_%s%s.sss", g->name, "", &n2);
        if (n1 != g_spub(g) || n2 != g_ss(g)) { fprintf(stderr, "%s: bad server share or secret length\n", g->name); exit(1); }
        unsigned char ss[max_ss];
        group_client(g, keys, sshare, ss);
        if (memcmp(ss, theirs, n2)) { fprintf(stderr, "%s: the shared secrets differ (OpenSSL client, Zig server)\n", g->name); exit(1); }
    }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <work dir> <workload>\n", argv[0]); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    cycles_open();
    fprintf(stderr, "%s (libcrypto, public EVP APIs)\n", OpenSSL_version(0));
    ks_init();
    if (!strcmp(w, "interop")) { interop(); return 0; }
    if (!strcmp(w, "interop2")) { interop2(); return 0; }
    if (!strcmp(w, "ks256") || !strcmp(w, "ks384")) {
        ks_cur = &ks[w[2] == '3' && w[3] == '8' ? 1 : 0];
        bench(w, ks_once);
        return 0;
    }
    if (!strncmp(w, "gen_", 4) || !strncmp(w, "srv_", 4) || !strncmp(w, "cli_", 4)) {
        cur_g = find_group(w + 4);
        if (!cur_g) { fprintf(stderr, "unknown group in %s\n", w); return 2; }
        if (w[0] == 'g') { bench(w, gen_once); return 0; }
        // a client share to serve, and (for cli_) the server's answer to a client key kept here
        group_gen(cur_g, cur_keys, cur_cshare);
        if (w[0] == 's') { bench(w, srv_once); return 0; }
        group_server(cur_g, cur_cshare, cur_sshare, cur_ss);
        bench(w, cli_once);
        return 0;
    }
    if (!strncmp(w, "sign_", 5) || !strncmp(w, "verify_", 7)) {
        cur_s = find_sch(w + (w[0] == 's' ? 5 : 7));
        if (cur_s < 0) { fprintf(stderr, "unknown scheme in %s\n", w); return 2; }
        load_keys();
        cur_siglen = sig_sign(cur_s, cur_sig, sizeof cur_sig);
        bench(w, w[0] == 's' ? sign_once : verify_once);
        return 0;
    }
    fprintf(stderr, "unknown workload %s\n", w);
    return 2;
}
