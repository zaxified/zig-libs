// SPDX-License-Identifier: MIT
//
// C side of `zig build interop-tls13` (modules/tls13/tools/interop.zig): the
// live oracle. A line-oriented request/reply server over stdin/stdout on top of
// OpenSSL 3.5's libcrypto (public EVP APIs only, no libssl, no headers: the
// prototypes used are declared below). One request per line, tokens separated
// by single spaces, binary fields in lowercase hex ("-" is the empty string);
// one reply per request, "OK <tokens>" or "ERR" (the operation was refused).
// A broken request or an OpenSSL failure on an input that must work is fatal
// (stderr + exit 1), so a disagreement is never a silent one.
//
//   VERSION                              OK <OpenSSL version string>
//   SEED <hex8>                          OK    make every random draw OpenSSL takes
//                                              (keygen, encapsulation, ECDSA nonces,
//                                              PSS salts, blinding) a pure function of
//                                              the seed, so a frozen transcript is
//                                              reproducible (RAND_set_rand_method)
//   KS <256|384> ...                     the RFC 8446 section 7 key schedule, see ks_cmd
//   KEMS <group> <peer share>            OpenSSL as SERVER: OK <server share> <secret>
//   KEMC_GEN <group>                     OpenSSL as CLIENT: OK <id> <client share>
//   KEMC_FIN <id> <server share>         OK <secret>
//   DHP <ffdhe group>                    OK <p>   the group's prime, big-endian, len(p) octets
//                                              (for the malformed-share rows; ours is not exported)
//   KEY <id> ec|ed|mldsa44|mldsa65|mldsa87 <DER or seed>   |  KEY <id> rsa <n e d p q>
//   SIGN <id> <scheme hex> s|c <hash>    OK <signature>   over the RFC 8446 4.4.3 content
//   VERIFY <id> <scheme hex> s|c <hash> <sig>   OK 1|0
//
// The key schedule is computed twice, once with EVP_KDF "HKDF" and the
// HkdfLabel built here, once with EVP_KDF "TLS13-KDF" (libssl's own), and the
// reply says whether the two agree. TLS13-KDF's EXTRACT_ONLY mode is NOT
// HKDF-Extract: when a salt is given it first runs Derive-Secret(salt,
// "derived", "") over it (that is libssl's tls13_generate_secret), so the early
// secret needs NO salt (an all-zero salt gets "derived" applied to it, which is
// what bench.zig's "wrong early secret" was) and the handshake and master
// secrets take the PREVIOUS SECRET as the salt.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
typedef struct {
    int (*seed)(const void *buf, int num);
    int (*bytes)(unsigned char *buf, int num);
    void (*cleanup)(void);
    int (*add)(const void *buf, int num, double randomness);
    int (*pseudorand)(unsigned char *buf, int num);
    int (*status)(void);
} RAND_METHOD;
int RAND_set_rand_method(const RAND_METHOD *meth);
OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf, size_t bsize);
OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
OSSL_PARAM OSSL_PARAM_construct_end(void);
OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn);
OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld);
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
int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name, BIGNUM **bn);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_num_bits(const BIGNUM *a);
void CRYPTO_free(void *ptr, const char *file, int line);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *wrappedkey, size_t *wrappedkeylen, unsigned char *genkey, size_t *genkeylen);
int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *unwrapped, size_t *unwrappedlen, const unsigned char *wrapped, size_t wrappedlen);
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length);
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
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *md, unsigned int *md_len);
const char *OpenSSL_version(int t);
unsigned long ERR_get_error(void);
void ERR_clear_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
#define EVP_PKEY_EC 408
#define EVP_PKEY_KEY_PARAMETERS 0x84 /* OSSL_KEYMGMT_SELECT_ALL_PARAMETERS */
#define EVP_PKEY_PUBLIC_KEY 0x86 /* EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY */
#define EVP_PKEY_KEYPAIR 0x87
#define RSA_PKCS1_PSS_PADDING 6
#define RSA_PSS_SALTLEN_DIGEST (-1)
#define KDF_EXTRACT_ONLY 1
#define KDF_EXPAND_ONLY 2

static void die(const char *what) {
    char e[256] = "";
    unsigned long code = ERR_get_error();
    if (code) ERR_error_string_n(code, e, sizeof e);
    fprintf(stderr, "oracle: %s failed %s\n", what, e);
    exit(1);
}
#define CHK(x) do { if (!(x)) die(#x); } while (0)

// ---- deterministic randomness (splitmix64; a test oracle, not a CSPRNG) ----
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static int rng_bytes(unsigned char *buf, int num) {
    for (int i = 0; i < num; i += 8) {
        rng_state += 0x9e3779b97f4a7c15ULL;
        uint64_t z = rng_state;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        z ^= z >> 31;
        int m = num - i < 8 ? num - i : 8;
        for (int j = 0; j < m; j++) buf[i + j] = (unsigned char)(z >> (8 * j));
    }
    return 1;
}
static int rng_seed(const void *b, int n) { (void)b; (void)n; return 1; }
static void rng_cleanup(void) {}
static int rng_add(const void *b, int n, double r) { (void)b; (void)n; (void)r; return 1; }
static int rng_status(void) { return 1; }
static const RAND_METHOD rng_method = {rng_seed, rng_bytes, rng_cleanup, rng_add, rng_bytes, rng_status};

// ---- hex and tokens ----
static unsigned char *unhex(const char *s, size_t *len) {
    size_t n = strcmp(s, "-") ? strlen(s) : 0;
    if (n & 1) { fprintf(stderr, "oracle: odd hex length\n"); exit(1); }
    unsigned char *b = malloc(n / 2 + 1);
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) { fprintf(stderr, "oracle: bad hex\n"); exit(1); }
        b[i] = (unsigned char)v;
    }
    *len = n / 2;
    return b;
}
static void puthex(const unsigned char *b, size_t n) {
    putchar(' ');
    if (!n) { putchar('-'); return; }
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}
static char *tok[96];
static int ntok;
static void split(char *line) {
    ntok = 0;
    for (char *s = strtok(line, " \r\n"); s && ntok < 96; s = strtok(NULL, " \r\n")) tok[ntok++] = s;
}
static void need(int n) {
    if (ntok != n) { fprintf(stderr, "oracle: %s takes %d tokens, got %d\n", tok[0], n, ntok); exit(1); }
}

// ---- key schedule (RFC 8446 section 7.1) ----
static EVP_KDF *kdf_hkdf, *kdf_tls13;
static EVP_MD *md256, *md384;
static EVP_MD_CTX *hctx;
typedef struct {
    const char *dg;
    size_t L;
    EVP_MD *md;
    unsigned char empty[48];
} hk;
static hk hks[2];
static int impl; // 0: EVP_KDF "HKDF" + HkdfLabel built here; 1: EVP_KDF "TLS13-KDF"
static int impl_err;
static const char tls13_prefix[] = "tls13 ";

static void ks_init(void) {
    CHK(kdf_hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL));
    CHK(kdf_tls13 = EVP_KDF_fetch(NULL, "TLS13-KDF", NULL));
    CHK(md256 = EVP_MD_fetch(NULL, "SHA256", NULL));
    CHK(md384 = EVP_MD_fetch(NULL, "SHA384", NULL));
    CHK(hctx = EVP_MD_CTX_new());
    for (int i = 0; i < 2; i++) {
        hk *k = &hks[i];
        k->dg = i ? "SHA384" : "SHA256";
        k->L = i ? 48 : 32;
        k->md = i ? md384 : md256;
        unsigned int n;
        CHK(EVP_DigestInit_ex2(hctx, k->md, NULL) && EVP_DigestFinal_ex(hctx, k->empty, &n));
    }
}
static void dgst(const hk *k, unsigned char *out, const unsigned char *d, size_t n) {
    unsigned int o;
    CHK(EVP_DigestInit_ex2(hctx, k->md, NULL) && EVP_DigestUpdate(hctx, d, n) && EVP_DigestFinal_ex(hctx, out, &o));
}
// A fresh EVP_KDF_CTX per call. A refusal by the TLS13-KDF is recorded, not fatal:
// the reply reports it; a refusal by HKDF is a bug of this program.
static void derive1(unsigned char *out, size_t n, const OSSL_PARAM *p) {
    EVP_KDF_CTX *c;
    CHK(c = EVP_KDF_CTX_new(impl ? kdf_tls13 : kdf_hkdf));
    if (EVP_KDF_derive(c, out, n, p) <= 0) {
        if (!impl) die("EVP_KDF_derive(HKDF)");
        impl_err = 1;
        memset(out, 0, n);
        ERR_clear_error();
    }
    EVP_KDF_CTX_free(c);
}
// HKDF-Expand-Label(secret, label, data, outlen), hash of k.
static void expand(const hk *k, unsigned char *out, size_t outlen, const unsigned char *secret, const char *label, const unsigned char *data, size_t dlen) {
    int mode = KDF_EXPAND_ONLY;
    size_t ll = strlen(label);
    if (impl) {
        char pfx[8];
        memcpy(pfx, tls13_prefix, 6);
        OSSL_PARAM p[] = {
            OSSL_PARAM_construct_utf8_string("digest", (char *)k->dg, 0),
            OSSL_PARAM_construct_int("mode", &mode),
            OSSL_PARAM_construct_octet_string("key", (void *)secret, k->L),
            OSSL_PARAM_construct_octet_string("prefix", pfx, 6),
            OSSL_PARAM_construct_octet_string("label", (void *)label, ll),
            OSSL_PARAM_construct_octet_string("data", (void *)data, dlen),
            OSSL_PARAM_construct_end(),
        };
        derive1(out, outlen, p);
        return;
    }
    unsigned char info[2 + 1 + 6 + 255 + 1 + 255];
    size_t n = 0;
    info[n++] = (unsigned char)(outlen >> 8);
    info[n++] = (unsigned char)outlen;
    info[n++] = (unsigned char)(6 + ll);
    memcpy(info + n, tls13_prefix, 6); n += 6;
    memcpy(info + n, label, ll); n += ll;
    info[n++] = (unsigned char)dlen;
    memcpy(info + n, data, dlen); n += dlen;
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)k->dg, 0),
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_octet_string("key", (void *)secret, k->L),
        OSSL_PARAM_construct_octet_string("info", info, n),
        OSSL_PARAM_construct_end(),
    };
    derive1(out, outlen, p);
}
// The RFC 8446 section 7.1 extract step: HKDF-Extract(Derive-Secret(prev, "derived", "") or 0^L,
// ikm or 0^L). prev == NULL: no earlier secret (the early secret).
static void gen_secret(const hk *k, unsigned char *out, const unsigned char *prev, const unsigned char *ikm, size_t ikm_len) {
    int mode = KDF_EXTRACT_ONLY;
    if (impl) {
        char pfx[8];
        memcpy(pfx, tls13_prefix, 6);
        OSSL_PARAM p[9];
        int n = 0;
        p[n++] = OSSL_PARAM_construct_utf8_string("digest", (char *)k->dg, 0);
        p[n++] = OSSL_PARAM_construct_int("mode", &mode);
        p[n++] = OSSL_PARAM_construct_octet_string("prefix", pfx, 6);
        if (prev) {
            // The salt is the PREVIOUS SECRET: the KDF first derives Derive-Secret(salt, label, "")
            // from it, and the label is the caller's to name (libssl passes "derived").
            p[n++] = OSSL_PARAM_construct_octet_string("salt", (void *)prev, k->L);
            p[n++] = OSSL_PARAM_construct_octet_string("label", (void *)"derived", 7);
        }
        if (ikm) p[n++] = OSSL_PARAM_construct_octet_string("key", (void *)ikm, ikm_len);
        p[n++] = OSSL_PARAM_construct_end();
        derive1(out, k->L, p);
        return;
    }
    unsigned char zeros[96] = {0}, salt[48];
    if (prev) expand(k, salt, k->L, prev, "derived", k->empty, k->L);
    else memcpy(salt, zeros, k->L);
    if (!ikm) { ikm = zeros; ikm_len = k->L; }
    OSSL_PARAM p[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)k->dg, 0),
        OSSL_PARAM_construct_int("mode", &mode),
        OSSL_PARAM_construct_octet_string("key", (void *)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string("salt", salt, k->L),
        OSSL_PARAM_construct_end(),
    };
    derive1(out, k->L, p);
}

enum { nfields = 29 };
typedef struct {
    unsigned char b[nfields][128];
    size_t n[nfields];
} ksout;
typedef struct {
    const hk *k;
    int haspsk, hasdhe;
    unsigned char *psk, *dhe, *th[4], *nonce, *xl, *xc;
    size_t psk_len, dhe_len, nonce_len, xl_len, xc_len, exp_len, key_len;
} ksin;

static void ks_run(const ksin *in, ksout *o) {
    const hk *k = in->k;
    size_t L = k->L;
    unsigned char early[48], hs[48], ms[48], c_hs[48], s_hs[48], c_ap[48], s_ap[48], exp[48], res[48], ext[48], fk[48], dm[48], ch[48];
    unsigned char label[257];
    unsigned int n;
    int f = 0;
#define OUT(len) (o->n[f] = (len), o->b[f])
    impl_err = 0;
    gen_secret(k, early, NULL, in->haspsk ? in->psk : NULL, in->psk_len);
    memcpy(OUT(L), early, L); f++;
    expand(k, ext, L, early, "ext binder", k->empty, L);
    memcpy(OUT(L), ext, L); f++;
    expand(k, OUT(L), L, early, "res binder", k->empty, L); f++;
    expand(k, fk, L, ext, "finished", (const unsigned char *)"", 0);
    CHK(HMAC(k->md, fk, (int)L, in->th[0], L, OUT(L), &n)); f++;
    expand(k, OUT(L), L, early, "c e traffic", in->th[0], L); f++;
    expand(k, OUT(L), L, early, "e exp master", in->th[0], L); f++;
    gen_secret(k, hs, early, in->hasdhe ? in->dhe : NULL, in->dhe_len);
    memcpy(OUT(L), hs, L); f++;
    expand(k, c_hs, L, hs, "c hs traffic", in->th[1], L);
    memcpy(OUT(L), c_hs, L); f++;
    expand(k, s_hs, L, hs, "s hs traffic", in->th[1], L);
    memcpy(OUT(L), s_hs, L); f++;
    gen_secret(k, ms, hs, NULL, 0);
    memcpy(OUT(L), ms, L); f++;
    expand(k, c_ap, L, ms, "c ap traffic", in->th[2], L);
    memcpy(OUT(L), c_ap, L); f++;
    expand(k, s_ap, L, ms, "s ap traffic", in->th[2], L);
    memcpy(OUT(L), s_ap, L); f++;
    expand(k, exp, L, ms, "exp master", in->th[2], L);
    memcpy(OUT(L), exp, L); f++;
    expand(k, res, L, ms, "res master", in->th[3], L);
    memcpy(OUT(L), res, L); f++;
    expand(k, OUT(L), L, res, "resumption", in->nonce, in->nonce_len); f++;
    unsigned char fc[48], fs[48];
    expand(k, fc, L, c_hs, "finished", (const unsigned char *)"", 0);
    memcpy(OUT(L), fc, L); f++;
    expand(k, fs, L, s_hs, "finished", (const unsigned char *)"", 0);
    memcpy(OUT(L), fs, L); f++;
    CHK(HMAC(k->md, fs, (int)L, in->th[2], L, OUT(L), &n)); f++;
    const unsigned char *traffic[4] = {c_hs, s_hs, c_ap, s_ap};
    for (int t = 0; t < 4; t++) {
        expand(k, OUT(in->key_len), in->key_len, traffic[t], "key", (const unsigned char *)"", 0); f++;
        expand(k, OUT(12), 12, traffic[t], "iv", (const unsigned char *)"", 0); f++;
    }
    expand(k, OUT(L), L, c_ap, "traffic upd", (const unsigned char *)"", 0); f++;
    expand(k, OUT(L), L, s_ap, "traffic upd", (const unsigned char *)"", 0); f++;
    memcpy(label, in->xl, in->xl_len);
    label[in->xl_len] = 0;
    expand(k, dm, L, exp, (const char *)label, k->empty, L);
    dgst(k, ch, in->xc, in->xc_len);
    expand(k, OUT(in->exp_len), in->exp_len, dm, "exporter", ch, L); f++;
    if (f != nfields) { fprintf(stderr, "oracle: %d key-schedule fields\n", f); exit(1); }
#undef OUT
}
// KS <256|384> <haspsk> <psk> <hasdhe> <dhe> <th_ch> <th_sh> <th_sf> <th_cf> <nonce> <exporter label> <exporter context> <exporter length> <aead key length>
// reply: OK <29 fields> <tls13kdf=ok|differs|refused>
static void ks_cmd(void) {
    need(15);
    ksin in;
    memset(&in, 0, sizeof in);
    in.k = &hks[!strcmp(tok[1], "384")];
    in.haspsk = atoi(tok[2]);
    in.psk = unhex(tok[3], &in.psk_len);
    in.hasdhe = atoi(tok[4]);
    in.dhe = unhex(tok[5], &in.dhe_len);
    for (int i = 0; i < 4; i++) {
        size_t n;
        in.th[i] = unhex(tok[6 + i], &n);
        if (n != in.k->L) { fprintf(stderr, "oracle: transcript hash of %zu octets\n", n); exit(1); }
    }
    in.nonce = unhex(tok[10], &in.nonce_len);
    in.xl = unhex(tok[11], &in.xl_len);
    in.xc = unhex(tok[12], &in.xc_len);
    in.exp_len = (size_t)atoi(tok[13]);
    in.key_len = (size_t)atoi(tok[14]);
    if (in.xl_len > 200 || in.exp_len > 120 || in.key_len > 120 || in.nonce_len > 200) { fprintf(stderr, "oracle: KS bounds\n"); exit(1); }
    static ksout a, b;
    impl = 0;
    ks_run(&in, &a);
    impl = 1;
    ks_run(&in, &b);
    char verdict[256] = "ok";
    if (impl_err) strcpy(verdict, "refused");
    else for (int i = 0; i < nfields; i++)
        if (a.n[i] != b.n[i] || memcmp(a.b[i], b.b[i], a.n[i])) {
            size_t l = strlen(verdict);
            snprintf(verdict + (l == 2 && !strcmp(verdict, "ok") ? 0 : l), sizeof verdict - (l == 2 && !strcmp(verdict, "ok") ? 0 : l), "%s%d", l == 2 && !strcmp(verdict, "ok") ? "differs:" : ",", i);
        }
    printf("OK");
    for (int i = 0; i < nfields; i++) puthex(a.b[i], a.n[i]);
    printf(" tls13kdf=%s\n", verdict);
}

// ---- key exchange ----
typedef struct {
    const char *name, *alg, *grp;
    int kem;
    size_t dh_len; // FFDHE ("DH" keys): len(p) in octets, 0 for every other group
} group;
static const group groups[] = {
    {"x25519", "X25519", NULL, 0},
    {"secp256r1", "EC", "P-256", 0},
    {"secp384r1", "EC", "P-384", 0},
    {"secp521r1", "EC", "P-521", 0},
    {"x25519mlkem768", "X25519MLKEM768", NULL, 1},
    {"secp256r1mlkem768", "SecP256r1MLKEM768", NULL, 1},
    {"secp384r1mlkem1024", "SecP384r1MLKEM1024", NULL, 1},
    {"mlkem1024", "ML-KEM-1024", NULL, 1},
    {"mlkem512", "ML-KEM-512", NULL, 1},
    {"mlkem768", "ML-KEM-768", NULL, 1},
    // RFC 7919 named groups as OpenSSL "DH" keys, the way libssl uses them in TLS 1.3: the
    // share is EVP_PKEY_get1_encoded_public_key / set1_encoded_public_key, the secret is
    // derived with the padded output (EVP_PKEY_CTX_set_dh_pad), as ssl_derive does.
    {"ffdhe2048", "DH", "ffdhe2048", 0, 256},
    {"ffdhe3072", "DH", "ffdhe3072", 0, 384},
    {"ffdhe4096", "DH", "ffdhe4096", 0, 512},
    {"ffdhe6144", "DH", "ffdhe6144", 0, 768},
    {"ffdhe8192", "DH", "ffdhe8192", 0, 1024},
};
static const group *find_group(const char *n) {
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++) if (!strcmp(groups[i].name, n)) return &groups[i];
    fprintf(stderr, "oracle: unknown group %s\n", n);
    exit(1);
}
enum { max_buf = 8192 };
static EVP_PKEY *kem_gen(const group *g) {
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;
    CHK(c = EVP_PKEY_CTX_new_from_name(NULL, g->alg, NULL));
    CHK(EVP_PKEY_keygen_init(c) == 1);
    if (g->grp) CHK(EVP_PKEY_CTX_set_group_name(c, g->grp) == 1);
    CHK(EVP_PKEY_generate(c, &k) == 1);
    EVP_PKEY_CTX_free(c);
    return k;
}
static size_t kem_pub(EVP_PKEY *k, unsigned char *buf, const group *g) {
    size_t n = 0;
    if (g->dh_len) {
        unsigned char *p = NULL;
        CHK((n = EVP_PKEY_get1_encoded_public_key(k, &p)) > 0 && n <= max_buf);
        memcpy(buf, p, n);
        CRYPTO_free(p, "oracle.c", __LINE__);
        return n;
    }
    // The hybrid keys expose their wire form as "encoded-pub-key" (the others also as "pub").
    if (EVP_PKEY_get_octet_string_param(k, "encoded-pub-key", buf, max_buf, &n) != 1) {
        ERR_clear_error();
        CHK(EVP_PKEY_get_octet_string_param(k, "pub", buf, max_buf, &n) == 1);
    }
    return n;
}
// The peer's public key from its wire octets; NULL when OpenSSL refuses it.
static EVP_PKEY *kem_import(const group *g, const unsigned char *pub, size_t len) {
    EVP_PKEY_CTX *c;
    EVP_PKEY *k = NULL;
    if (g->dh_len) {
        // The group parameters by name, then the peer value through libssl's own call; either
        // step may refuse a malformed value (the verdict is then "refused", as in libssl).
        char name[16];
        OSSL_PARAM p[2];
        strcpy(name, g->grp);
        p[0] = OSSL_PARAM_construct_utf8_string("group", name, 0);
        p[1] = OSSL_PARAM_construct_end();
        CHK(c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL));
        CHK(EVP_PKEY_fromdata_init(c) == 1 && EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEY_PARAMETERS, p) == 1);
        EVP_PKEY_CTX_free(c);
        if (EVP_PKEY_set1_encoded_public_key(k, pub, len) != 1) { EVP_PKEY_free(k); return NULL; }
        return k;
    }
    char grp[16] = "";
    OSSL_PARAM prm[3];
    int n = 0;
    CHK(c = EVP_PKEY_CTX_new_from_name(NULL, g->alg, NULL));
    CHK(EVP_PKEY_fromdata_init(c) == 1);
    if (g->grp) { strcpy(grp, g->grp); prm[n++] = OSSL_PARAM_construct_utf8_string("group", grp, 0); }
    prm[n++] = OSSL_PARAM_construct_octet_string("pub", (void *)pub, len);
    prm[n++] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, prm) != 1) k = NULL;
    EVP_PKEY_CTX_free(c);
    return k;
}
static int ecdh(EVP_PKEY *local, EVP_PKEY *peer, unsigned char *out, size_t *n, const group *g) {
    EVP_PKEY_CTX *c;
    int ok;
    CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, local, NULL));
    CHK(EVP_PKEY_derive_init(c) == 1);
    if (g->dh_len) CHK(EVP_PKEY_CTX_set_dh_pad(c, 1) > 0); // RFC 8446 section 7.4.1: leading zeros kept
    ok = EVP_PKEY_derive_set_peer(c, peer) == 1;
    if (ok) { *n = max_buf; ok = EVP_PKEY_derive(c, out, n) == 1; }
    EVP_PKEY_CTX_free(c);
    return ok;
}
static void kems_cmd(void) {
    need(3);
    const group *g = find_group(tok[1]);
    size_t pl, sl = max_buf, ssl = max_buf;
    unsigned char *peer = unhex(tok[2], &pl);
    static unsigned char sshare[max_buf], ss[max_buf];
    EVP_PKEY *pk = kem_import(g, peer, pl);
    int ok = 0;
    if (pk) {
        if (g->kem) {
            EVP_PKEY_CTX *c;
            CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL));
            CHK(EVP_PKEY_encapsulate_init(c, NULL) == 1);
            ok = EVP_PKEY_encapsulate(c, sshare, &sl, ss, &ssl) == 1;
            EVP_PKEY_CTX_free(c);
        } else {
            EVP_PKEY *k = kem_gen(g);
            sl = kem_pub(k, sshare, g);
            ok = ecdh(k, pk, ss, &ssl, g);
            EVP_PKEY_free(k);
        }
        EVP_PKEY_free(pk);
    }
    ERR_clear_error();
    if (!ok) { printf("ERR\n"); return; }
    printf("OK");
    puthex(sshare, sl);
    puthex(ss, ssl);
    printf("\n");
}
// DHP <ffdhe group>: OK <p>
static void dhp_cmd(void) {
    need(2);
    const group *g = find_group(tok[1]);
    static unsigned char pbuf[max_buf];
    if (!g->dh_len) { fprintf(stderr, "oracle: DHP of a non-FFDHE group %s\n", g->name); exit(1); }
    EVP_PKEY *k = kem_gen(g);
    BIGNUM *p = NULL;
    CHK(EVP_PKEY_get_bn_param(k, "p", &p) == 1);
    CHK((size_t)BN_num_bits(p) == 8 * g->dh_len);
    CHK(BN_bn2binpad(p, pbuf, (int)g->dh_len) == (int)g->dh_len);
    EVP_PKEY_free(k);
    printf("OK");
    puthex(pbuf, g->dh_len);
    printf("\n");
}
enum { max_ckeys = 4096 };
static EVP_PKEY *ckeys[max_ckeys];
static const group *ckey_group[max_ckeys];
static int nckeys;
static void kemc_gen_cmd(void) {
    need(2);
    const group *g = find_group(tok[1]);
    static unsigned char cshare[max_buf];
    if (nckeys == max_ckeys) { fprintf(stderr, "oracle: too many client keys\n"); exit(1); }
    EVP_PKEY *k = kem_gen(g);
    size_t n = kem_pub(k, cshare, g);
    ckeys[nckeys] = k;
    ckey_group[nckeys] = g;
    printf("OK %d", nckeys++);
    puthex(cshare, n);
    printf("\n");
}
static void kemc_fin_cmd(void) {
    need(3);
    int id = atoi(tok[1]);
    if (id < 0 || id >= nckeys) { fprintf(stderr, "oracle: bad client key id\n"); exit(1); }
    const group *g = ckey_group[id];
    size_t pl, ssl = max_buf;
    unsigned char *peer = unhex(tok[2], &pl);
    static unsigned char ss[max_buf];
    int ok = 0;
    if (g->kem) {
        EVP_PKEY_CTX *c;
        CHK(c = EVP_PKEY_CTX_new_from_pkey(NULL, ckeys[id], NULL));
        CHK(EVP_PKEY_decapsulate_init(c, NULL) == 1);
        ok = EVP_PKEY_decapsulate(c, ss, &ssl, peer, pl) == 1;
        EVP_PKEY_CTX_free(c);
    } else {
        EVP_PKEY *pk = kem_import(g, peer, pl);
        if (pk) { ok = ecdh(ckeys[id], pk, ss, &ssl, g); EVP_PKEY_free(pk); }
    }
    ERR_clear_error();
    if (!ok) { printf("ERR\n"); return; }
    printf("OK");
    puthex(ss, ssl);
    printf("\n");
}

// ---- CertificateVerify ----
enum { max_keys = 32 };
static EVP_PKEY *keys[max_keys];
static EVP_MD *fetched[3];
static EVP_MD *md_by_name(const char *n) {
    int i = !strcmp(n, "SHA256") ? 0 : !strcmp(n, "SHA384") ? 1 : 2;
    if (!fetched[i]) CHK(fetched[i] = EVP_MD_fetch(NULL, n, NULL));
    return fetched[i];
}
static void key_cmd(void) {
    if (ntok < 4) { fprintf(stderr, "oracle: KEY needs a kind\n"); exit(1); }
    int id = atoi(tok[1]);
    if (id < 0 || id >= max_keys) { fprintf(stderr, "oracle: bad key id\n"); exit(1); }
    size_t n;
    unsigned char *b = unhex(tok[3], &n);
    const char *kind = tok[2];
    if (!strcmp(kind, "ec")) {
        const unsigned char *p = b;
        CHK(keys[id] = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)n));
    } else if (!strcmp(kind, "ed")) {
        CHK(n == 32 && (keys[id] = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, b, 32)));
    } else if (!strncmp(kind, "mldsa", 5)) {
        char alg[16];
        snprintf(alg, sizeof alg, "ML-DSA-%s", kind + 5);
        EVP_PKEY_CTX *c;
        OSSL_PARAM prm[2];
        prm[0] = OSSL_PARAM_construct_octet_string("seed", b, n);
        prm[1] = OSSL_PARAM_construct_end();
        CHK(c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL));
        CHK(EVP_PKEY_fromdata_init(c) == 1 && EVP_PKEY_fromdata(c, &keys[id], EVP_PKEY_KEYPAIR, prm) == 1);
        EVP_PKEY_CTX_free(c);
    } else if (!strcmp(kind, "rsa")) {
        need(8);
        BIGNUM *v[5];
        for (int i = 0; i < 5; i++) { size_t m; unsigned char *x = unhex(tok[3 + i], &m); CHK(v[i] = BN_bin2bn(x, (int)m, NULL)); }
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
        CHK(EVP_PKEY_fromdata_init(c) == 1 && EVP_PKEY_fromdata(c, &keys[id], EVP_PKEY_KEYPAIR, prm) == 1);
        EVP_PKEY_CTX_free(c);
    } else {
        fprintf(stderr, "oracle: unknown key kind %s\n", kind);
        exit(1);
    }
    printf("OK\n");
}
// The signed content of RFC 8446 section 4.4.3, built here: 64 x 0x20, the context string,
// 0x00, the transcript hash.
static size_t content(unsigned char *out, int server, const unsigned char *th, size_t thl) {
    const char *cs = server ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify";
    size_t n = 0;
    memset(out, 0x20, 64); n = 64;
    memcpy(out + n, cs, strlen(cs)); n += strlen(cs);
    out[n++] = 0;
    memcpy(out + n, th, thl); n += thl;
    return n;
}
static const char *scheme_md(unsigned s) {
    switch (s) {
    case 0x0403: case 0x0804: return "SHA256";
    case 0x0503: case 0x0805: return "SHA384";
    case 0x0603: case 0x0806: return "SHA512";
    default: return NULL; // Ed25519, ML-DSA: no digest argument
    }
}
static void pss(unsigned s, EVP_PKEY_CTX *pc, const EVP_MD *md) {
    if (s < 0x0804 || s > 0x0806) return;
    CHK(EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) > 0);
    CHK(EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) > 0);
    CHK(EVP_PKEY_CTX_set_rsa_mgf1_md(pc, md) > 0);
}
// SIGN <id> <scheme hex> s|c <hash>; VERIFY <id> <scheme hex> s|c <hash> <sig>
static void sig_cmd(int verify) {
    need(verify ? 6 : 5);
    int id = atoi(tok[1]);
    if (id < 0 || id >= max_keys || !keys[id]) { fprintf(stderr, "oracle: no key %d\n", id); exit(1); }
    unsigned s = (unsigned)strtoul(tok[2], NULL, 16);
    size_t thl, sl;
    unsigned char *th = unhex(tok[4], &thl);
    unsigned char msg[64 + 40 + 1 + 128];
    if (thl > 128) { fprintf(stderr, "oracle: transcript hash too long\n"); exit(1); }
    size_t ml = content(msg, tok[3][0] == 's', th, thl);
    const char *mdn = scheme_md(s);
    const EVP_MD *md = mdn ? md_by_name(mdn) : NULL;
    EVP_MD_CTX *m;
    EVP_PKEY_CTX *pc = NULL;
    CHK(m = EVP_MD_CTX_new());
    if (verify) {
        unsigned char *sig = unhex(tok[5], &sl);
        CHK(EVP_DigestVerifyInit(m, &pc, md, NULL, keys[id]) == 1);
        pss(s, pc, md);
        int r = EVP_DigestVerify(m, sig, sl, msg, ml);
        ERR_clear_error();
        printf("OK %d\n", r == 1);
    } else {
        static unsigned char sig[max_buf];
        sl = max_buf;
        CHK(EVP_DigestSignInit(m, &pc, md, NULL, keys[id]) == 1);
        pss(s, pc, md);
        CHK(EVP_DigestSign(m, sig, &sl, msg, ml) == 1);
        printf("OK");
        puthex(sig, sl);
        printf("\n");
    }
    EVP_MD_CTX_free(m);
}

int main(void) {
    static char line[1 << 17];
    ks_init();
    while (fgets(line, sizeof line, stdin)) {
        split(line);
        if (!ntok) continue;
        const char *c = tok[0];
        if (!strcmp(c, "VERSION")) printf("OK %s\n", OpenSSL_version(0));
        else if (!strcmp(c, "SEED")) {
            need(2);
            rng_state = strtoull(tok[1], NULL, 16);
            CHK(RAND_set_rand_method(&rng_method) == 1);
            printf("OK\n");
        }
        else if (!strcmp(c, "KS")) ks_cmd();
        else if (!strcmp(c, "KEMS")) kems_cmd();
        else if (!strcmp(c, "KEMC_GEN")) kemc_gen_cmd();
        else if (!strcmp(c, "KEMC_FIN")) kemc_fin_cmd();
        else if (!strcmp(c, "DHP")) dhp_cmd();
        else if (!strcmp(c, "KEY")) key_cmd();
        else if (!strcmp(c, "SIGN")) sig_cmd(0);
        else if (!strcmp(c, "VERIFY")) sig_cmd(1);
        else { fprintf(stderr, "oracle: unknown request %s\n", c); return 2; }
        fflush(stdout);
    }
    return 0;
}
