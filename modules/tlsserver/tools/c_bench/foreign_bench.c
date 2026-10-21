// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-tlsserver` (modules/tlsserver/tools/bench.zig):
// an OpenSSL 3 libssl TLS 1.3 server doing the same server-side work as
// `tlsserver.Server`, in memory, for the one workload named by the second
// argument, over the certificates and keys the Zig program writes into the
// directory given as the first argument.
//
// How only the server is timed. Both sides REPLAY a recorded session: an
// OpenSSL client and server first run the handshake through memory BIOs, the
// client's octets are kept, and each timed op is a fresh server fed exactly
// those octets. That replays because randomness is made deterministic: a
// RAND_METHOD (public, deprecated-in-3.0 API, still honoured by
// RAND_bytes_ex / RAND_priv_bytes_ex outside the FIPS module) draws from one
// of two SplitMix64 streams — the client's or the server's, switched around
// each call — and the server's stream is reset to its seed before every
// replayed connection. The first replay is checked against the recording
// octet for octet; a mismatch (randomness OpenSSL took elsewhere) fails the
// run. The Zig side does the same with `Config.random` and tlsclient.
//
// Workloads (all TLS_AES_256_GCM_SHA384, the server's choice forced; one
// NewSessionTicket where tickets are on, SSL_CTX_set_num_tickets(1), no
// server session cache — stateless tickets as `StekTicketer`):
//   hs_p256        full handshake, ECDSA P-256 (ecdsa_secp256r1_sha256), X25519
//   hs_p256_mlkem  the same over X25519MLKEM768
//   hs_rsa2048     full handshake, RSA-2048 (rsa_pss_rsae_sha256), X25519
//   resumed        a ticket resumed (psk_dhe_ke, X25519), one new ticket issued
//   send_16k       one 16384-octet application data record sealed (the
//                  output goes to a null BIO: a socket would take it as is)
//   recv_16k       one such record opened and its plaintext read
// The bulk rows run on a replayed connection that is replaced (replayed
// again, timed) every `pool` records: the server's sequence numbers start over
// with the same keys, so `recv_16k`'s pool of client records, sealed once,
// opens again. The replay costs about 1 % of a bulk op; the Zig side pays the
// same.
//
// Prints one line: name, ns/op, user-mode cycles/op (0 without a cycle
// counter), the count (1 per handshake, 16384 per bulk record). Mode
// `interop` runs every workload's recording and checks (negotiated suite,
// group, resumption, replay identical to the recording) without timing.
//
// OpenSSL's headers are not installed on every host, so the few prototypes
// used are declared here (public API, stable since 3.0; constants checked
// against the OpenSSL 3.5 headers). Timing matches the Zig side: double the
// batch until it takes over 100 ms, keep the best of five.
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_session_st SSL_SESSION;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
typedef struct rand_meth_st {
    int (*seed)(const void *buf, int num);
    int (*bytes)(unsigned char *buf, int num);
    void (*cleanup)(void);
    int (*add)(const void *buf, int num, double randomness);
    int (*pseudorand)(unsigned char *buf, int num);
    int (*status)(void);
} RAND_METHOD;
const SSL_METHOD *TLS_server_method(void);
const SSL_METHOD *TLS_client_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *m);
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);
int SSL_CTX_set_num_tickets(SSL_CTX *ctx, size_t n);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d);
int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx, const unsigned char *d, long len);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *cb);
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *s);
void SSL_set_shutdown(SSL *s, int mode);
long SSL_ctrl(SSL *s, int cmd, long larg, void *parg);
void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
void SSL_set_accept_state(SSL *s);
void SSL_set_connect_state(SSL *s);
int SSL_do_handshake(SSL *s);
int SSL_get_error(const SSL *s, int ret);
int SSL_read(SSL *s, void *buf, int num);
int SSL_write(SSL *s, const void *buf, int num);
SSL_SESSION *SSL_get1_session(SSL *s);
int SSL_set_session(SSL *s, SSL_SESSION *sess);
int SSL_session_reused(const SSL *s);
const SSL_CIPHER *SSL_get_current_cipher(const SSL *s);
const char *SSL_CIPHER_get_name(const SSL_CIPHER *c);
const char *SSL_group_to_name(SSL *s, int id);
BIO *BIO_new(const BIO_METHOD *t);
BIO *BIO_new_mem_buf(const void *buf, int len);
const BIO_METHOD *BIO_s_mem(void);
const BIO_METHOD *BIO_s_null(void);
int BIO_read(BIO *b, void *data, int dlen);
int BIO_write(BIO *b, const void *data, int dlen);
size_t BIO_ctrl_pending(BIO *b);
int RAND_set_rand_method(const RAND_METHOD *meth);
const char *OpenSSL_version(int t);
unsigned long ERR_get_error(void);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
#define SSL_CTRL_SET_MIN_PROTO_VERSION 123
#define SSL_CTRL_SET_MAX_PROTO_VERSION 124
#define SSL_CTRL_SET_SESS_CACHE_MODE 44
#define SSL_CTRL_SET_GROUPS_LIST 92
#define SSL_CTRL_SET_SIGALGS_LIST 98
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_CTRL_GET_NEGOTIATED_GROUP 134
#define SSL_SESS_CACHE_OFF 0
#define SSL_SENT_SHUTDOWN 1
#define SSL_RECEIVED_SHUTDOWN 2
#define SSL_VERIFY_NONE 0
#define SSL_ERROR_WANT_READ 2
#define TLS1_3_VERSION 0x0304
#define EVP_PKEY_EC 408
#define EVP_PKEY_RSA 6

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

// ---- deterministic randomness: a client and a server stream ----
static unsigned long long streams[2];
static int who; // 0 = client, 1 = server
enum { server_seed = 0x5e17, client_seed = 0xc11e };
static unsigned long long splitmix(unsigned long long *s) {
    unsigned long long z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
static int rand_bytes(unsigned char *buf, int num) {
    for (int i = 0; i < num; i += 8) {
        unsigned long long v = splitmix(&streams[who]);
        for (int j = 0; j < 8 && i + j < num; j++) buf[i + j] = (unsigned char)(v >> (8 * j));
    }
    return 1;
}
static int rand_seed(const void *b, int n) { (void)b; (void)n; return 1; }
static int rand_add(const void *b, int n, double r) { (void)b; (void)n; (void)r; return 1; }
static int rand_status(void) { return 1; }
static const RAND_METHOD det_rand = { rand_seed, rand_bytes, NULL, rand_add, rand_bytes, rand_status };

// ---- the case ----
enum { pool = 2048, rec = 16384 };
static SSL_CTX *sctx, *cctx;
static int tickets, want_resumed;
static const char *want_group;
static unsigned char *hs_in;   // the client's octets of the replayed handshake
static size_t hs_in_len;
static unsigned char *hs_out;  // the server's, as recorded
static size_t hs_out_len;
static unsigned char *recs;    // `pool` client records (recv_16k)
static size_t recs_len;
static unsigned char *plain, *rbuf;

static void drain(BIO *b, unsigned char **out, size_t *len) {
    size_t n = BIO_ctrl_pending(b);
    *out = realloc(*out, *len + n + 1);
    if (n && BIO_read(b, *out + *len, (int)n) != (int)n) die("BIO_read");
    *len += n;
}
static int step(SSL *s, int as) {
    who = as;
    int r = SSL_do_handshake(s);
    if (r == 1) return 1;
    if (SSL_get_error(s, r) != SSL_ERROR_WANT_READ) die("SSL_do_handshake");
    return 0;
}

static SSL_CTX *ctx_new(int server, const char *cert, const char *key, int key_type, const char *sigalg) {
    SSL_CTX *c = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!c) die("SSL_CTX_new");
    SSL_CTX_ctrl(c, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, NULL);
    SSL_CTX_ctrl(c, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, NULL);
    if (SSL_CTX_ctrl(c, SSL_CTRL_SET_GROUPS_LIST, 0, (void *)want_group) != 1) die("groups");
    if (!server) { SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL); return c; }
    if (SSL_CTX_set_ciphersuites(c, "TLS_AES_256_GCM_SHA384") != 1) die("ciphersuites");
    if (SSL_CTX_ctrl(c, SSL_CTRL_SET_SIGALGS_LIST, 0, (void *)sigalg) != 1) die("sigalgs");
    SSL_CTX_ctrl(c, SSL_CTRL_SET_SESS_CACHE_MODE, SSL_SESS_CACHE_OFF, NULL);
    SSL_CTX_set_num_tickets(c, tickets ? 1 : 0);
    size_t n;
    unsigned char *d = slurp(cert, &n);
    if (SSL_CTX_use_certificate_ASN1(c, (int)n, d) != 1) die("certificate");
    d = slurp(key, &n);
    if (SSL_CTX_use_PrivateKey_ASN1(key_type, c, d, (long)n) != 1) die("private key");
    if (SSL_CTX_check_private_key(c) != 1) die("key/certificate");
    return c;
}

// One recorded connection: client ↔ server through memory BIOs. Returns the
// client (still connected) and keeps its handshake octets; `sess` resumes.
static SSL *record_session(SSL_SESSION *sess, SSL **server_out) {
    streams[1] = server_seed;
    who = 1;
    SSL *s = SSL_new(sctx);
    who = 0;
    SSL *c = SSL_new(cctx);
    if (!s || !c) die("SSL_new");
    BIO *c2s = BIO_new(BIO_s_mem()), *s2c = BIO_new(BIO_s_mem());
    BIO *s_in = BIO_new(BIO_s_mem()), *c_in = BIO_new(BIO_s_mem());
    SSL_set_bio(c, c_in, c2s);
    SSL_set_bio(s, s_in, s2c);
    SSL_ctrl(c, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)"localhost");
    if (sess && SSL_set_session(c, sess) != 1) die("SSL_set_session");
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    free(hs_in); hs_in = NULL; hs_in_len = 0;
    free(hs_out); hs_out = NULL; hs_out_len = 0;
    int cdone = 0, sdone = 0;
    while (!cdone || !sdone) {
        if (!cdone) cdone = step(c, 0);
        size_t from = hs_in_len;
        drain(c2s, &hs_in, &hs_in_len);
        if (hs_in_len > from) BIO_write(s_in, hs_in + from, (int)(hs_in_len - from));
        if (!sdone) sdone = step(s, 1);
        from = hs_out_len;
        drain(s2c, &hs_out, &hs_out_len);
        if (hs_out_len > from) BIO_write(c_in, hs_out + from, (int)(hs_out_len - from));
    }
    // The client takes the ticket (if any) on its first read.
    char b[1];
    who = 0;
    if (SSL_read(c, b, 1) > 0) die("unexpected application data");
    const char *suite = SSL_CIPHER_get_name(SSL_get_current_cipher(s));
    const char *group = SSL_group_to_name(s, (int)SSL_ctrl(s, SSL_CTRL_GET_NEGOTIATED_GROUP, 0, NULL));
    if (strcmp(suite, "TLS_AES_256_GCM_SHA384") != 0) { fprintf(stderr, "suite %s\n", suite); exit(1); }
    if (!group || strcasecmp(group, want_group) != 0) { fprintf(stderr, "group %s, not %s\n", group ? group : "?", want_group); exit(1); }
    if (SSL_session_reused(s) != (sess != NULL)) { fprintf(stderr, "resumed %d\n", SSL_session_reused(s)); exit(1); }
    *server_out = s;
    return c;
}

// A fresh server fed the recorded handshake; output to `out` (a null BIO
// when timed).
static SSL *replay(BIO *out) {
    streams[1] = server_seed;
    who = 1;
    SSL *s = SSL_new(sctx);
    if (!s) die("SSL_new");
    SSL_set_bio(s, BIO_new_mem_buf(hs_in, (int)hs_in_len), out);
    SSL_set_accept_state(s);
    if (SSL_do_handshake(s) != 1) die("replayed handshake");
    return s;
}

static size_t op_handshake(void) {
    SSL *s = replay(BIO_new(BIO_s_null()));
    SSL_free(s);
    return 1;
}

static SSL *bulk;
static size_t bulk_left;
static void bulk_renew(void) {
    if (bulk) SSL_free(bulk);
    bulk = replay(BIO_new(BIO_s_null()));
    bulk_left = pool;
}
static size_t op_send(void) {
    if (bulk_left == 0) bulk_renew();
    bulk_left--;
    if (SSL_write(bulk, plain, rec) != rec) die("SSL_write");
    return rec;
}
static size_t op_recv(void) {
    if (bulk_left == 0) {
        bulk_renew();
        // Read-only, no copy: the record buffer is OpenSSL's own.
        SSL_set_bio(bulk, BIO_new_mem_buf(recs, (int)recs_len), BIO_new(BIO_s_null()));
    }
    bulk_left--;
    int got = 0;
    while (got < rec) {
        int r = SSL_read(bulk, rbuf + got, rec - got);
        if (r <= 0) die("SSL_read");
        got += r;
    }
    return rec;
}

static int setup(const char *w) {
    want_group = "X25519";
    const char *cert = "p256_cert.der", *key = "p256_key.der", *sigalg = "ecdsa_secp256r1_sha256";
    int key_type = EVP_PKEY_EC;
    tickets = 0;
    want_resumed = 0;
    if (strcmp(w, "hs_p256_mlkem") == 0) want_group = "X25519MLKEM768";
    else if (strcmp(w, "hs_rsa2048") == 0) {
        cert = "rsa2048_cert.der", key = "rsa2048_key.der", sigalg = "rsa_pss_rsae_sha256";
        key_type = EVP_PKEY_RSA;
    } else if (strcmp(w, "resumed") == 0) tickets = 1, want_resumed = 1;
    else if (strcmp(w, "hs_p256") != 0 && strcmp(w, "send_16k") != 0 && strcmp(w, "recv_16k") != 0) return 0;
    // Each context is built under its own stream (the server's ticket keys
    // come from it).
    streams[0] = client_seed;
    streams[1] = server_seed;
    who = 1;
    if (sctx) { /* one case per process */ }
    sctx = ctx_new(1, cert, key, key_type, sigalg);
    who = 0;
    cctx = ctx_new(0, NULL, NULL, 0, NULL);
    SSL *s, *c = record_session(NULL, &s);
    if (want_resumed) {
        SSL_SESSION *sess = SSL_get1_session(c);
        if (!sess) die("no ticket");
        // Freed without a shutdown, the client's session would be marked
        // not resumable (ssl_clear_bad_session).
        SSL_set_shutdown(c, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(c); SSL_free(s);
        c = record_session(sess, &s);
    }
    if (strcmp(w, "recv_16k") == 0) {
        // The pool, sealed by the recorded client right after its handshake.
        BIO *c2s = BIO_new(BIO_s_mem());
        SSL_set_bio(c, BIO_new(BIO_s_mem()), c2s);
        who = 0;
        for (int i = 0; i < pool; i++) if (SSL_write(c, plain, rec) != rec) die("client SSL_write");
        recs_len = 0;
        drain(c2s, &recs, &recs_len);
        if (recs_len != (size_t)pool * (rec + 5 + 1 + 16)) { fprintf(stderr, "pool %zu octets\n", recs_len); exit(1); }
    }
    SSL_free(c);
    SSL_free(s);
    // The replay must give the recorded server octets back.
    BIO *out = BIO_new(BIO_s_mem());
    SSL *r = replay(out);
    unsigned char *got = NULL;
    size_t got_len = 0;
    drain(out, &got, &got_len);
    if (got_len != hs_out_len || memcmp(got, hs_out, got_len) != 0) {
        fprintf(stderr, "%s: the replayed server is not the recorded one (%zu vs %zu octets) -- randomness taken past RAND_METHOD?\n", w, got_len, hs_out_len);
        exit(1);
    }
    if (SSL_session_reused(r) != want_resumed) die("replayed resumption");
    if (strcmp(w, "recv_16k") == 0) {
        SSL_set_bio(r, BIO_new_mem_buf(recs, (int)recs_len), BIO_new(BIO_s_null()));
        for (int i = 0; i < pool; i++) {
            int got_n = 0;
            while (got_n < rec) {
                int k = SSL_read(r, rbuf + got_n, rec - got_n);
                if (k <= 0) die("replayed pool");
                got_n += k;
            }
            if (memcmp(rbuf, plain, rec) != 0) die("pool plaintext");
        }
    }
    SSL_free(r);
    free(got);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "%s libssl\n", OpenSSL_version(0));
    if (RAND_set_rand_method(&det_rand) != 1) die("RAND_set_rand_method");
    plain = malloc(rec);
    rbuf = malloc(rec);
    for (int i = 0; i < rec; i++) plain[i] = (unsigned char)(i * 7 + 1);
    cycles_open();
    if (strcmp(w, "interop") == 0) {
        static const char *all[] = {"hs_p256", "hs_p256_mlkem", "hs_rsa2048", "resumed", "recv_16k"};
        for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
            if (!setup(all[i])) return 2;
            fprintf(stderr, "%s: recorded %zu client / %zu server octets, replay identical\n", all[i], hs_in_len, hs_out_len);
        }
        return 0;
    }
    if (!setup(w)) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    if (strncmp(w, "hs_", 3) == 0 || strcmp(w, "resumed") == 0) bench(w, op_handshake);
    else if (strcmp(w, "send_16k") == 0) bench(w, op_send);
    else bench(w, op_recv);
    return 0;
}
