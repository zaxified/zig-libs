// SPDX-License-Identifier: MIT
//
// C side of `zig build interop-sha2` (modules/sha2/tools/interop.zig): answers
// a stream of cases with the system OpenSSL 3 (`libcrypto.so.3`, linked by
// path). Usage: openssl_oracle <cases file> <results file>; `--version` prints
// OpenSSL_version(0) and exits.
//
// Cases file, little-endian, until EOF -- one record per case:
//   op u8, alg u8, then
//   op 0 (digest):  len u32, msg[len]                         -> digest bytes
//   op 1 (HMAC):    keylen u32, msglen u32, key, msg          -> mac bytes
//   op 2 (HKDF):    saltlen u32, ikmlen u32, infolen u32, outlen u32,
//                   salt, ikm, info                           -> outlen bytes
// alg indexes `names` below (the EVP digest names). The results file is the
// answers concatenated, no framing: the Zig side knows every length. Any
// OpenSSL failure aborts with exit 1 -- the oracle never guesses.
//
// OpenSSL's headers are not installed on every host, so the few prototypes
// used are declared here (the public EVP/HMAC/HKDF API, stable across 3.x).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct evp_md_st EVP_MD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
const EVP_MD *EVP_get_digestbyname(const char *name);
int EVP_MD_get_size(const EVP_MD *md);
int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, void *impl);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, void *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX *ctx, const unsigned char *salt, int saltlen);
int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX *ctx, const unsigned char *key, int keylen);
int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *ctx, const unsigned char *info, int infolen);
int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *ctx, int mode);
const char *OpenSSL_version(int t);

#define EVP_PKEY_HKDF 1036
#define HKDF_MODE_EXTRACT_AND_EXPAND 0

static const char *names[] = {"SHA224", "SHA256", "SHA384", "SHA512", "SHA512-224", "SHA512-256"};
#define N_NAMES (sizeof names / sizeof names[0])

static void die(const char *what) {
    fprintf(stderr, "openssl_oracle: %s failed\n", what);
    exit(1);
}
static void need(FILE *f, void *b, size_t n) {
    if (n && fread(b, 1, n, f) != n) die("short cases file");
}
static uint32_t u32(FILE *f) {
    unsigned char b[4];
    need(f, b, 4);
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
// Never NULL, even for length 0: HMAC()/HKDF treat NULL as "no key at all".
static unsigned char *grab(FILE *f, uint32_t n) {
    unsigned char *b = malloc(n ? n : 1);
    if (!b) die("malloc");
    need(f, b, n);
    return b;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts(OpenSSL_version(0));
        return 0;
    }
    if (argc != 3) { fprintf(stderr, "usage: openssl_oracle <cases> <results>\n"); return 2; }
    FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wb");
    if (!in || !out) die("open");
    const EVP_MD *md[N_NAMES];
    for (size_t i = 0; i < N_NAMES; i++)
        if (!(md[i] = EVP_get_digestbyname(names[i]))) die(names[i]);
    for (;;) {
        int op = fgetc(in);
        if (op == EOF) break;
        int alg = fgetc(in);
        if (alg < 0 || (size_t)alg >= N_NAMES) die("bad alg");
        unsigned char res[64];
        unsigned int rl = 0;
        if (op == 0) {
            uint32_t n = u32(in);
            unsigned char *m = grab(in, n);
            if (EVP_Digest(m, n, res, &rl, md[alg], NULL) != 1) die("EVP_Digest");
            fwrite(res, 1, rl, out);
            free(m);
        } else if (op == 1) {
            uint32_t kl = u32(in), ml = u32(in);
            unsigned char *k = grab(in, kl), *m = grab(in, ml);
            if (!HMAC(md[alg], k, (int)kl, m, ml, res, &rl)) die("HMAC");
            fwrite(res, 1, rl, out);
            free(k);
            free(m);
        } else if (op == 2) {
            uint32_t sl = u32(in), il = u32(in), nl = u32(in), ol = u32(in);
            unsigned char *s = grab(in, sl), *k = grab(in, il), *info = grab(in, nl), *o = malloc(ol ? ol : 1);
            size_t olen = ol;
            EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
            if (!c || EVP_PKEY_derive_init(c) != 1 || EVP_PKEY_CTX_set_hkdf_mode(c, HKDF_MODE_EXTRACT_AND_EXPAND) != 1 ||
                EVP_PKEY_CTX_set_hkdf_md(c, md[alg]) != 1 || EVP_PKEY_CTX_set1_hkdf_salt(c, s, (int)sl) != 1 ||
                EVP_PKEY_CTX_set1_hkdf_key(c, k, (int)il) != 1 || EVP_PKEY_CTX_add1_hkdf_info(c, info, (int)nl) != 1 ||
                EVP_PKEY_derive(c, o, &olen) != 1 || olen != ol)
                die("HKDF");
            fwrite(o, 1, ol, out);
            EVP_PKEY_CTX_free(c);
            free(s); free(k); free(info); free(o);
        } else {
            die("bad op");
        }
    }
    if (fclose(out) != 0) die("write results");
    return 0;
}
