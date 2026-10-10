// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-wireguard` (modules/wireguard/tools/bench.zig).
// Neither the in-kernel WireGuard (needs root and a tunnel) nor wireguard-go
// (not installed) can be timed op for op here, so the reference is a
// PER-PRIMITIVE COMPOSITION of the same work in OpenSSL and libsodium:
//   comp.seal_<n>    transport data message (WireGuard whitepaper 5.4.6):
//                    16-byte header (type 4, receiver index, LE64 counter),
//                    plaintext zero-padded to 16, OpenSSL EVP
//                    ChaCha20-Poly1305 under nonce 0^4 || LE64(counter),
//                    counter incremented per op
//   comp.open_<n>    header parse + the same AEAD open of one sealed message
//   comp.handshake   the X25519 work of one full handshake (initiation +
//                    response, both sides): 2 x crypto_scalarmult_base
//                    (the ephemerals) + 8 x crypto_scalarmult (es, ss on
//                    each side; ee, se on each side), libsodium. The BLAKE2s
//                    chain, HMACs, AEADs and TAI64N of the handshake are NOT
//                    in it, so this is a LOWER BOUND on the reference's time
//                    and the ratio against it is pessimistic for us.
// over the inputs in the directory given as the first argument. Prints one
// line: name, ns/op, user-mode cycles/op (0 without a counter), bytes per
// op. The run named `interop` writes `comp_sealed_1420.bin`, the message for
// counter 0 of msg1420.bin, for the Zig side to compare byte for byte.
//
// Neither library's headers are installed on every host, so the prototypes
// used are declared here (public, stable APIs). Timing matches the Zig side:
// double the batch until it takes over 100 ms, then keep the best of five.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int sodium_init(void);
const char *sodium_version_string(void);
int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);
int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
const EVP_CIPHER *EVP_chacha20_poly1305(void);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *c, const EVP_CIPHER *t, void *e, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *c, unsigned char *out, int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *c, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);
const char *OpenSSL_version(int t);
#define CTRL_GET_TAG 0x10
#define CTRL_SET_TAG 0x11

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

static EVP_CIPHER_CTX *ectx, *dctx;
static unsigned char key[32], *msg, *sealed, *plain, padded[1440];
static size_t len, plen, sealed_len;
static uint32_t receiver;
static uint64_t counter;
static unsigned char s_i[32], s_r[32], e_i[32], e_r[32], S_i[32], S_r[32], E_i[32], E_r[32], dh[32];

static void put_le(unsigned char *p, uint64_t v, int n) {
    for (int i = 0; i < n; i++) p[i] = (unsigned char)(v >> (8 * i));
}
static size_t op_seal(void) {
    unsigned char nonce[12] = {0};
    int l = 0, l2 = 0;
    put_le(sealed, 4, 4);
    put_le(sealed + 4, receiver, 4);
    put_le(sealed + 8, counter, 8);
    put_le(nonce + 4, counter, 8);
    counter++;
    memcpy(padded, msg, len);
    memset(padded + len, 0, plen - len);
    if (EVP_EncryptInit_ex(ectx, NULL, NULL, NULL, nonce) != 1 ||
        EVP_EncryptUpdate(ectx, sealed + 16, &l, padded, (int)plen) != 1 ||
        EVP_EncryptFinal_ex(ectx, sealed + 16 + l, &l2) != 1 ||
        EVP_CIPHER_CTX_ctrl(ectx, CTRL_GET_TAG, 16, sealed + 16 + plen) != 1) { fprintf(stderr, "seal failed\n"); exit(1); }
    return 16 + plen + 16;
}
static size_t op_open(void) {
    unsigned char nonce[12] = {0};
    int l = 0, l2 = 0;
    uint32_t type = (uint32_t)sealed[0] | (uint32_t)sealed[1] << 8 | (uint32_t)sealed[2] << 16 | (uint32_t)sealed[3] << 24;
    if (type != 4) exit(1);
    memcpy(nonce + 4, sealed + 8, 8);
    size_t clen = sealed_len - 32;
    if (EVP_DecryptInit_ex(dctx, NULL, NULL, NULL, nonce) != 1 ||
        EVP_CIPHER_CTX_ctrl(dctx, CTRL_SET_TAG, 16, sealed + 16 + clen) != 1 ||
        EVP_DecryptUpdate(dctx, plain, &l, sealed + 16, (int)clen) != 1 ||
        EVP_DecryptFinal_ex(dctx, plain + l, &l2) != 1) { fprintf(stderr, "open failed (tag)\n"); exit(1); }
    return clen;
}
static size_t op_handshake(void) {
    int bad = 0;
    bad |= crypto_scalarmult_base(E_i, e_i);    // initiator ephemeral
    bad |= crypto_scalarmult(dh, e_i, S_r);     // initiator es
    bad |= crypto_scalarmult(dh, s_i, S_r);     // initiator ss
    bad |= crypto_scalarmult(dh, s_r, E_i);     // responder es
    bad |= crypto_scalarmult(dh, s_r, S_i);     // responder ss
    bad |= crypto_scalarmult_base(E_r, e_r);    // responder ephemeral
    bad |= crypto_scalarmult(dh, e_r, E_i);     // responder ee
    bad |= crypto_scalarmult(dh, e_r, S_i);     // responder se
    bad |= crypto_scalarmult(dh, e_i, E_r);     // initiator ee
    bad |= crypto_scalarmult(dh, s_i, E_r);     // initiator se
    if (bad) { fprintf(stderr, "scalarmult failed\n"); exit(1); }
    e_i[0] ^= dh[0] & 0xf8; // fresh ephemerals per op, as the Zig side generates them
    e_r[0] ^= dh[1] & 0xf8;
    return 2;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: wireguard_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    if (sodium_init() < 0) return 1;
    memcpy(key, slurp("key.bin", NULL), 32);
    unsigned char *ri = slurp("receiver.bin", NULL);
    receiver = (uint32_t)ri[0] | (uint32_t)ri[1] << 8 | (uint32_t)ri[2] << 16 | (uint32_t)ri[3] << 24;
    ectx = EVP_CIPHER_CTX_new();
    dctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ectx, EVP_chacha20_poly1305(), NULL, key, NULL) != 1 || EVP_DecryptInit_ex(dctx, EVP_chacha20_poly1305(), NULL, key, NULL) != 1) { fprintf(stderr, "init failed\n"); return 1; }
    char op[16];
    if (strcmp(w, "interop") == 0) {
        len = 1420;
    } else if (strcmp(w, "comp.handshake") == 0) {
        fprintf(stderr, "libsodium %s (X25519 only)\n", sodium_version_string());
        memcpy(s_i, slurp("s_i.bin", NULL), 32);
        memcpy(s_r, slurp("s_r.bin", NULL), 32);
        memcpy(e_i, s_i, 32);
        e_i[1] ^= 1;
        memcpy(e_r, s_r, 32);
        e_r[1] ^= 1;
        crypto_scalarmult_base(S_i, s_i);
        crypto_scalarmult_base(S_r, s_r);
        cycles_open();
        bench(w, op_handshake);
        return 0;
    } else if (sscanf(w, "comp.%15[a-z]_%zu", op, &len) != 2) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    fprintf(stderr, "%s (ChaCha20-Poly1305)\n", OpenSSL_version(0));
    char f[64];
    snprintf(f, sizeof f, "msg%zu.bin", len);
    msg = slurp(f, NULL);
    plen = (len + 15) / 16 * 16;
    sealed = malloc(32 + plen);
    plain = malloc(plen);
    sealed_len = op_seal();
    if (strcmp(w, "interop") == 0) {
        spit("comp_sealed_1420.bin", sealed, sealed_len);
        return 0;
    }
    cycles_open();
    if (strcmp(op, "seal") == 0) bench(w, op_seal);
    else if (strcmp(op, "open") == 0) bench(w, op_open);
    else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    return 0;
}
