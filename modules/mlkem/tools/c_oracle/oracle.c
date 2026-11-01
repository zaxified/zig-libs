// SPDX-License-Identifier: MIT
//
// C side of `zig build interop-mlkem` (modules/mlkem/tools/interop.zig): the
// live oracle. A line-oriented request/reply server over stdin/stdout on top of
// OpenSSL 3.5's libcrypto ML-KEM (public EVP APIs only, no headers: the
// prototypes used are declared below). One request per line, tokens separated
// by single spaces, binary fields in lowercase hex; one reply per request,
// "OK <tokens>" or "ERR" (OpenSSL refused the input). An OpenSSL failure on an
// input that must work is fatal (stderr + exit 1), so a disagreement is never
// a silent one. <n> is the parameter set: 512 | 768 | 1024.
//
//   VERSION                       OK <OpenSSL version string>
//   KEYGEN <n> <seed d||z>        OK <ek> <dk>   key from the 64-octet seed
//                                                (OSSL_PKEY_PARAM_ML_KEM_SEED)
//   IMPEK <n> <ek>                OK | ERR       import an encapsulation key (the
//                                                FIPS 203 modulus check is OpenSSL's)
//   IMPDK <n> <dk>                OK | ERR       import a decapsulation key (expanded form)
//   ENCAPS <n> <ek> <m>           OK <ct> <ss>   deterministic encapsulation with
//                                                m = OSSL_KEM_PARAM_IKME; ERR when the
//                                                ek is refused
//   DECAPS <n> <dk> <ct>          OK <ss>        ERR when the dk is refused
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
void ERR_clear_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
#define EVP_PKEY_PUBLIC_KEY 0x86
#define EVP_PKEY_KEYPAIR 0x87

static void die(const char *what) {
    char e[256] = "";
    unsigned long code = ERR_get_error();
    if (code) ERR_error_string_n(code, e, sizeof e);
    fprintf(stderr, "oracle: %s failed %s\n", what, e);
    exit(1);
}
#define CHK(x) do { if (!(x)) die(#x); } while (0)

typedef struct {
    const char *name, *alg;
    size_t ek, dk, ct;
} kemp;
static const kemp sets[3] = {
    {"512", "ML-KEM-512", 800, 1632, 768},
    {"768", "ML-KEM-768", 1184, 2400, 1088},
    {"1024", "ML-KEM-1024", 1568, 3168, 1568},
};
enum { max_dk = 3168, max_ct = 1568 };

static const kemp *find_set(const char *n) {
    for (int i = 0; i < 3; i++) if (!strcmp(sets[i].name, n)) return &sets[i];
    fprintf(stderr, "oracle: unknown set %s\n", n);
    exit(1);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    fprintf(stderr, "oracle: bad hex digit\n");
    exit(1);
}
static size_t unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) { fprintf(stderr, "oracle: bad hex field length %zu\n", n); exit(1); }
    for (size_t i = 0; i < n / 2; i++) out[i] = (unsigned char)(hexval(s[2 * i]) << 4 | hexval(s[2 * i + 1]));
    return n / 2;
}
static void puthex(const unsigned char *b, size_t n) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { putchar(d[b[i] >> 4]); putchar(d[b[i] & 15]); }
}

// Import with a fresh context (the contexts are cheap; a refused import must not
// poison the next one). NULL when OpenSSL refuses.
static EVP_PKEY *import(const kemp *k, const char *param, int selection, const unsigned char *b, size_t len) {
    EVP_PKEY_CTX *c;
    CHK(c = EVP_PKEY_CTX_new_from_name(NULL, k->alg, NULL));
    CHK(EVP_PKEY_fromdata_init(c) == 1);
    OSSL_PARAM prm[2];
    prm[0] = OSSL_PARAM_construct_octet_string(param, (void *)b, len);
    prm[1] = OSSL_PARAM_construct_end();
    EVP_PKEY *p = NULL;
    int ok = EVP_PKEY_fromdata(c, &p, selection, prm);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok == 1 ? p : NULL;
}

static char *tok(char **sp) {
    char *t = strsep(sp, " ");
    if (!t || !*t) { fprintf(stderr, "oracle: missing token\n"); exit(1); }
    return t;
}

int main(void) {
    static unsigned char a[2 * max_dk], b[2 * max_dk], c[max_ct];
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        char *sp = line;
        char *cmd = tok(&sp);
        if (!strcmp(cmd, "VERSION")) {
            printf("OK %s\n", OpenSSL_version(0));
        } else if (!strcmp(cmd, "KEYGEN")) {
            const kemp *k = find_set(tok(&sp));
            size_t n = unhex(tok(&sp), a, 64);
            if (n != 64) { fprintf(stderr, "oracle: seed must be 64 octets\n"); return 1; }
            EVP_PKEY *p = import(k, "seed", EVP_PKEY_KEYPAIR, a, 64);
            if (!p) die("keygen from seed");
            size_t m = 0;
            CHK(EVP_PKEY_get_octet_string_param(p, "pub", a, sizeof a, &m) == 1 && m == k->ek);
            CHK(EVP_PKEY_get_octet_string_param(p, "priv", b, sizeof b, &m) == 1 && m == k->dk);
            printf("OK ");
            puthex(a, k->ek);
            putchar(' ');
            puthex(b, k->dk);
            putchar('\n');
            EVP_PKEY_free(p);
        } else if (!strcmp(cmd, "IMPEK") || !strcmp(cmd, "IMPDK")) {
            const kemp *k = find_set(tok(&sp));
            int pub = cmd[3] == 'E';
            size_t n = unhex(tok(&sp), a, sizeof a);
            EVP_PKEY *p = import(k, pub ? "pub" : "priv", pub ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, a, n);
            printf(p ? "OK\n" : "ERR\n");
            if (p) EVP_PKEY_free(p);
        } else if (!strcmp(cmd, "ENCAPS")) {
            const kemp *k = find_set(tok(&sp));
            size_t n = unhex(tok(&sp), a, sizeof a);
            unsigned char m[32];
            if (unhex(tok(&sp), m, sizeof m) != 32) { fprintf(stderr, "oracle: m must be 32 octets\n"); return 1; }
            EVP_PKEY *p = import(k, "pub", EVP_PKEY_PUBLIC_KEY, a, n);
            if (!p) { printf("ERR\n"); fflush(stdout); continue; }
            EVP_PKEY_CTX *x;
            CHK(x = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL));
            OSSL_PARAM prm[2];
            prm[0] = OSSL_PARAM_construct_octet_string("ikme", m, 32);
            prm[1] = OSSL_PARAM_construct_end();
            CHK(EVP_PKEY_encapsulate_init(x, prm) == 1);
            unsigned char ss[32];
            size_t cl = k->ct, sl = 32;
            CHK(EVP_PKEY_encapsulate(x, c, &cl, ss, &sl) == 1 && cl == k->ct && sl == 32);
            printf("OK ");
            puthex(c, cl);
            putchar(' ');
            puthex(ss, 32);
            putchar('\n');
            EVP_PKEY_CTX_free(x);
            EVP_PKEY_free(p);
        } else if (!strcmp(cmd, "DECAPS")) {
            const kemp *k = find_set(tok(&sp));
            size_t n = unhex(tok(&sp), a, sizeof a);
            size_t cn = unhex(tok(&sp), c, sizeof c);
            EVP_PKEY *p = import(k, "priv", EVP_PKEY_KEYPAIR, a, n);
            if (!p) { printf("ERR\n"); fflush(stdout); continue; }
            EVP_PKEY_CTX *x;
            CHK(x = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL));
            CHK(EVP_PKEY_decapsulate_init(x, NULL) == 1);
            unsigned char ss[32];
            size_t sl = 32;
            CHK(EVP_PKEY_decapsulate(x, ss, &sl, c, cn) == 1 && sl == 32);
            printf("OK ");
            puthex(ss, 32);
            putchar('\n');
            EVP_PKEY_CTX_free(x);
            EVP_PKEY_free(p);
        } else {
            fprintf(stderr, "oracle: unknown command %s\n", cmd);
            return 1;
        }
        fflush(stdout);
    }
    return 0;
}
