/* SPDX-License-Identifier: MIT */
// A real third-party DTLS peer for `tools/interop.zig` — wolfSSL in either
// role, speaking DTLS 1.3 (and, in the `12-*` modes, DTLS 1.2) on loopback.
//
// THIS FILE IS NOT PART OF THE `dtls` MODULE. It lives beside the program that
// compiles it, outside `src/`, because a zig-libs module is standalone Zig with
// no external dependency; it used to sit in `src/testdata/` only because the
// test `@embedFile`d it and a module may not embed a file outside its own
// package root. `tools/interop.zig` now reads it from this path at run time.
//
//   cc -o wolfssl_peer wolfssl_peer.c -lwolfssl
//   ./wolfssl_peer server <port>      # prints READY, then accepts + echoes
//   ./wolfssl_peer server-hrr <port>  # same, but with the DEFAULT cookie
//                                     # exchange (HelloRetryRequest) left on
//   ./wolfssl_peer client <port>      # connects, sends, expects the echo
//   ./wolfssl_peer version            # prints the runtime wolfSSL version
//   ./wolfssl_peer server-cert <port> [mtu]
//                                     # PSK-LESS certificate server: X25519
//                                     # (EC)DHE + an ECDSA P-256 chain read
//                                     # from ./server-cert.der +
//                                     # ./server-key.der (written by the Zig
//                                     # test from ITS OWN fixtures, so both
//                                     # sides trust exactly one blob). An
//                                     # optional MTU makes wolfSSL fragment
//                                     # its Certificate across datagrams.
//   ./wolfssl_peer server-cert-hrr <port>
//                                     # ...with the cookie exchange left ON:
//                                     # a HelloRetryRequest carrying a cookie
//                                     # in CERTIFICATE mode.
//   ./wolfssl_peer server-cert-p256 <port>
//                                     # ...restricted to secp256r1, so the
//                                     # client's x25519 key_share is unusable
//                                     # and wolfSSL answers with a
//                                     # HelloRetryRequest naming secp256r1
//                                     # (RFC 8446 §4.1.4's (EC)DHE half). No
//                                     # cookie, so the retry's ONLY content
//                                     # is the group change.
//   ./wolfssl_peer server-cert-p256-hrr <port>
//                                     # ...both at once: cookie + group
//                                     # change in one HelloRetryRequest.
//   ./wolfssl_peer server-cert-mlkem <port>
//                                     # ...restricted to X25519MLKEM768
//                                     # (0x11EC), the PQ hybrid: a client
//                                     # offering the 1216-byte hybrid share
//                                     # completes directly; one offering
//                                     # x25519 gets a HelloRetryRequest
//                                     # naming the hybrid. Needs a wolfSSL
//                                     # built with ML-KEM (Debian's 5.9.1
//                                     # is); otherwise exits before READY.
//   ./wolfssl_peer server-cert-mutual <port>
//                                     # ...and REQUIRES a client certificate,
//                                     # verified against ./anchor-cert.der.
//                                     # A handshake that completes here is a
//                                     # third party accepting OUR client
//                                     # certificate + CertificateVerify.
//   ./wolfssl_peer client-cert <port> # PSK-less certificate CLIENT: verifies
//                                     # the chain OUR server presents against
//                                     # ./anchor-cert.der, then sends +
//                                     # expects an echo.
//   ./wolfssl_peer client-cert-mlkem <port>
//                                     # ...offering the X25519MLKEM768 hybrid
//                                     # share, so OUR server's encapsulation
//                                     # path is exercised by foreign code.
//   ./wolfssl_peer server-alpn <port> # PSK server that accepts ONLY "coap"
//                                     # over ALPN (RFC 7301) and prints
//                                     # `ALPN <name>` once connected.
//   ./wolfssl_peer client-alpn <port> # PSK client offering "h3,coap" and
//                                     # exiting non-zero unless the server's
//                                     # answer is "coap".
//   ./wolfssl_peer server-ku-ours <port>
//                                     # PSK server that, after the echo, reads
//                                     # one more message and echoes it: our
//                                     # side sends a KeyUpdate in between and
//                                     # wolfSSL must accept and answer it.
//   ./wolfssl_peer 12-server-<what> <port> [mtu]
//   ./wolfssl_peer 12-client-<what> <port> [mtu]
//                                     # DTLS 1.2 (RFC 6347) through
//                                     # `wolfDTLSv1_2_*_method`; <what> is
//                                     # psk (ECDHE-PSK-CHACHA20-POLY1305),
//                                     # ecdsa, ecdsa-aes256, ecdsa-chacha,
//                                     # ecdsa-p256 (secp256r1 only),
//                                     # ecdsa-mutual (client certificates
//                                     # required / presented) or rsa. See
//                                     # `run12` below.
//   ./wolfssl_peer server-ku-theirs <port>
//                                     # ...and here wolfSSL itself starts a
//                                     # KeyUpdate (`wolfSSL_update_keys`) after
//                                     # the echo and sends a message under the
//                                     # new keys; our side must accept it.
//   ./wolfssl_peer client-ku-theirs <port>
//                                     # PSK CLIENT that, after the echo, starts
//                                     # a KeyUpdate, sends a message under its
//                                     # new keys and expects it echoed back.
//   ./wolfssl_peer server-cert-alpn <port>
//   ./wolfssl_peer server-cert-ku-ours <port>
//   ./wolfssl_peer server-cert-ku-theirs <port>
//                                     # `server-cert` with the ALPN / KeyUpdate
//                                     # switches of the PSK modes above.
//
// Deliberate configuration, each item chosen to match what this module
// implements — a mismatch here would make the test prove nothing:
//
//   * `wolfSSL_CTX_no_dhe_psk` — psk_ke, no (EC)DHE. This module's `.psk`
//     mode is PSK-only; wolfSSL defaults to psk_dhe_ke.
//   * `wolfSSL_disable_hrr_cookie` — only in the plain `server` mode, and
//     only to keep one test focused on the no-retry path. `server-hrr`
//     leaves the default cookie exchange on, which is what a stock DTLS 1.3
//     server does.
//   * `TLS13-AES128-GCM-SHA256` — the intersection of what both sides do.
//     This module also has ChaCha20-Poly1305; CCM is unwired (std nonce
//     width), which is why the CoAP-profile default suite is not used here.
//
// The PSK and identity below are fixtures duplicated in `tools/interop.zig`;
// they are test material, never a default for anything.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

static const unsigned char kPsk[16] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};
static const char kIdentity[] = "zig-libs-dtls";
static const char kSuite[] = "TLS13-AES128-GCM-SHA256";

// The SHA-384 variant of the PSK cases: a 48-byte PSK (the length of a SHA-384
// output) under TLS13-AES256-GCM-SHA384. Selected by the `*-aes256` modes
// through `g_suite` / `g_psk`; every other mode keeps the defaults. Duplicated
// in `tools/interop.zig`.
static const unsigned char kPsk384[48] = {
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
};
static const char kSuite384[] = "TLS13-AES256-GCM-SHA384";
static const char *g_suite = kSuite;
static const unsigned char *g_psk = kPsk;
static unsigned int g_psk_len = sizeof(kPsk);

// Set by `main` for the cases that need them; every other mode leaves them off.
static const char *g_alpn = NULL;        // ALPN list offered (client) / accepted (server)
static const char *g_alpn_expect = NULL; // client: the name the server must answer
static int g_keyupdate = 0;              // 1: our side initiates, 2: wolfSSL initiates

// Applies the ALPN switch to a fresh session. wolfSSL takes a comma-separated
// list and, with FAILED_ON_MISMATCH, aborts the handshake instead of silently
// carrying on without a protocol.
static int apply_alpn(WOLFSSL *ssl) {
    if (!g_alpn) return 0;
    if (wolfSSL_UseALPN(ssl, (char *)g_alpn, (unsigned int)strlen(g_alpn),
                        WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "UseALPN failed\n");
        return 1;
    }
    return 0;
}

// Prints the negotiated protocol (`ALPN <name>` or `ALPN none`) and, when the
// mode names an expected answer, returns non-zero if it is not that.
static int report_alpn(WOLFSSL *ssl) {
    if (!g_alpn) return 0;
    char *proto = NULL;
    unsigned short size = 0;
    if (wolfSSL_ALPN_GetProtocol(ssl, &proto, &size) == WOLFSSL_SUCCESS) {
        printf("ALPN %.*s\n", (int)size, proto);
    } else {
        printf("ALPN none\n");
        proto = NULL;
    }
    fflush(stdout);
    if (g_alpn_expect && (!proto || strlen(g_alpn_expect) != size ||
                          memcmp(proto, g_alpn_expect, size) != 0)) {
        fprintf(stderr, "ALPN answer is not \"%s\"\n", g_alpn_expect);
        return 1;
    }
    return 0;
}

// The client side of mode 2: wolfSSL starts a KeyUpdate, sends a message under
// its new keys and must get exactly that message echoed back.
static int client_keyupdate_round(WOLFSSL *ssl) {
    if (wolfSSL_update_keys(ssl) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "update_keys failed\n");
        return 1;
    }
    const char *note = "wolfssl after its keyupdate";
    int len = (int)strlen(note);
    if (wolfSSL_write(ssl, note, len) != len) {
        fprintf(stderr, "write after update_keys failed\n");
        return 1;
    }
    printf("KEYUPDATE sent\n");
    fflush(stdout);
    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n != len || memcmp(msg, note, (size_t)len) != 0) {
        int err = n < 0 ? wolfSSL_get_error(ssl, n) : 0;
        char buf[80];
        fprintf(stderr, "echo after keyupdate is not the message (read %d, error %d %s)\n", n, err,
                err ? wolfSSL_ERR_error_string((unsigned long)err, buf) : "");
        return 1;
    }
    printf("ECHO %.*s\n", n, msg);
    fflush(stdout);
    return 0;
}

// The KeyUpdate round (RFC 9147 section 8), after the first echo. Mode 2 has
// wolfSSL start the update and then speak under the new keys; both modes then
// read the other side's next message and echo it, which is what makes the
// peer process (and answer) a KeyUpdate our side sent in between.
static int keyupdate_round(WOLFSSL *ssl) {
    if (g_keyupdate == 2) {
        if (wolfSSL_update_keys(ssl) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "update_keys failed\n");
            return 1;
        }
        const char *note = "wolfssl after its keyupdate";
        int len = (int)strlen(note);
        if (wolfSSL_write(ssl, note, len) != len) {
            fprintf(stderr, "write after update_keys failed\n");
            return 1;
        }
        printf("KEYUPDATE sent\n");
        fflush(stdout);
    }
    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n <= 0) { fprintf(stderr, "read after keyupdate failed\n"); return 1; }
    msg[n] = '\0';
    printf("RECV %s\n", msg);
    fflush(stdout);
    if (wolfSSL_write(ssl, msg, n) != n) { fprintf(stderr, "echo after keyupdate failed\n"); return 1; }
    return 0;
}

static unsigned int psk_server_cb(WOLFSSL *ssl, const char *identity,
                                  unsigned char *key, unsigned int key_max_len,
                                  const char **ciphername) {
    (void)ssl;
    if (strcmp(identity, kIdentity) != 0) return 0;
    if (key_max_len < g_psk_len) return 0;
    memcpy(key, g_psk, g_psk_len);
    *ciphername = g_suite;
    return (unsigned int)g_psk_len;
}

static unsigned int psk_client_cb(WOLFSSL *ssl, const char *hint,
                                  char *identity, unsigned int id_max_len,
                                  unsigned char *key, unsigned int key_max_len,
                                  const char **ciphername) {
    (void)ssl;
    (void)hint;
    if (id_max_len < sizeof(kIdentity)) return 0;
    memcpy(identity, kIdentity, sizeof(kIdentity));
    if (key_max_len < g_psk_len) return 0;
    memcpy(key, g_psk, g_psk_len);
    *ciphername = g_suite;
    return (unsigned int)g_psk_len;
}

// `hrr_cookie` selects between the two server postures that matter here:
//   0 — cookie exchange disabled, the shape most DTLS test harnesses use;
//   1 — DEFAULT wolfSSL, which answers the first ClientHello with a
//       HelloRetryRequest carrying a cookie (return-routability without
//       server state). A client that cannot do the retry cannot talk to a
//       stock server at all, so this mode is the one that proves it.
static int run_server(int port, int hrr_cookie) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, psk_server_cb);
    wolfSSL_CTX_no_dhe_psk(ctx);
    if (wolfSSL_CTX_set_cipher_list(ctx, g_suite) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }
    printf("READY\n");
    fflush(stdout);

    // Learn the peer address from the first datagram without consuming it.
    char probe[1];
    struct sockaddr_in peer = {0};
    socklen_t peer_len = sizeof(peer);
    if (recvfrom(fd, probe, sizeof(probe), MSG_PEEK, (struct sockaddr *)&peer,
                 &peer_len) < 0) {
        perror("recvfrom peek");
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&peer, peer_len) != 0) {
        perror("connect");
        return 1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    if (!hrr_cookie) wolfSSL_disable_hrr_cookie(ssl);
    if (apply_alpn(ssl)) return 1;
    int rc = wolfSSL_accept(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char buf[80];
        fprintf(stderr, "accept failed: %d (%s)\n", err,
                wolfSSL_ERR_error_string((unsigned long)err, buf));
        return 1;
    }
    printf("HANDSHAKE %s\n", wolfSSL_get_cipher(ssl));
    fflush(stdout);
    if (report_alpn(ssl)) return 1;

    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
    msg[n] = '\0';
    printf("RECV %s\n", msg);
    fflush(stdout);
    if (wolfSSL_write(ssl, msg, n) != n) { fprintf(stderr, "write failed\n"); return 1; }
    if (g_keyupdate && keyupdate_round(ssl)) return 1;

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}

// Loads a DER file written by the Zig test into `ctx`'s trusted-CA store.
// The anchor is the SAME blob the Zig side verifies against, so "wolfSSL
// accepted our certificate" cannot degrade into "wolfSSL trusted something
// else".
static int load_anchor(WOLFSSL_CTX *ctx) {
    unsigned char der[4096];
    FILE *f = fopen("anchor-cert.der", "rb");
    if (!f) { fprintf(stderr, "anchor-cert.der missing\n"); return 0; }
    size_t n = fread(der, 1, sizeof(der), f);
    fclose(f);
    if (n == 0 || n == sizeof(der)) { fprintf(stderr, "anchor-cert.der unreadable\n"); return 0; }
    if (wolfSSL_CTX_load_verify_buffer(ctx, der, (long)n, WOLFSSL_FILETYPE_ASN1)
        != WOLFSSL_SUCCESS) {
        fprintf(stderr, "load_verify_buffer failed\n");
        return 0;
    }
    return 1;
}

// PSK-less certificate server (RFC 8446's ordinary certificate handshake,
// carried by DTLS 1.3): (EC)DHE for the keys, an ECDSA P-256 leaf for the
// identity. Every knob below exists because some Zig-side behaviour can only
// be proven by a third party choosing it:
//
//   * `group` — the single NamedGroup this server will accept a share in.
//     WOLFSSL_ECC_X25519 matches what a fresh Zig ClientHello offers, so the
//     handshake proceeds directly. WOLFSSL_ECC_SECP256R1 does NOT, so
//     wolfSSL answers with a HelloRetryRequest naming secp256r1 — RFC 8446
//     §4.1.4's (EC)DHE half, which is unreachable in any self-interop test
//     because this module's own server never asks for a group change.
//   * `hrr_cookie` — leaves wolfSSL's DEFAULT cookie exchange on, so the
//     retry also carries a cookie. Combined with `group` above, one
//     HelloRetryRequest can carry both changes at once.
//   * `verify_peer` — WOLFSSL_VERIFY_PEER | FAIL_IF_NO_PEER_CERT plus the
//     anchor as a trusted CA: wolfSSL sends a CertificateRequest and REFUSES
//     the handshake unless our client's certificate and CertificateVerify
//     check out. Until this existed, our client certificate had only ever
//     been validated by our own server.
//   * `mtu`, when non-zero — forces wolfSSL to split its
//     Certificate/CertificateVerify flight into several datagrams, so the
//     Zig side must genuinely reassemble to get anywhere.
struct cert_server_opts {
    int mtu;
    int hrr_cookie;
    int group;      // WOLFSSL_ECC_*
    int verify_peer;
};

static int run_cert_server(int port, struct cert_server_opts o) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }
    if (wolfSSL_CTX_use_certificate_file(ctx, "server-cert.der",
                                         WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "use_certificate_file failed\n");
        return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "server-key.der",
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "use_PrivateKey_file failed\n");
        return 1;
    }
    if (wolfSSL_CTX_set_cipher_list(ctx, kSuite) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed\n");
        return 1;
    }
    int groups[] = {o.group};
    if (wolfSSL_CTX_set_groups(ctx, groups, 1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_groups failed\n");
        return 1;
    }
    if (o.verify_peer) {
        if (!load_anchor(ctx)) return 1;
        wolfSSL_CTX_set_verify(
            ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }
    printf("READY\n");
    fflush(stdout);

    char probe[1];
    struct sockaddr_in peer = {0};
    socklen_t peer_len = sizeof(peer);
    if (recvfrom(fd, probe, sizeof(probe), MSG_PEEK, (struct sockaddr *)&peer,
                 &peer_len) < 0) {
        perror("recvfrom peek");
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&peer, peer_len) != 0) {
        perror("connect");
        return 1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    if (!o.hrr_cookie) wolfSSL_disable_hrr_cookie(ssl);
    if (apply_alpn(ssl)) return 1;
    if (o.mtu > 0 && wolfSSL_dtls_set_mtu(ssl, (unsigned short)o.mtu) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_set_mtu(%d) failed\n", o.mtu);
        return 1;
    }
    int rc = wolfSSL_accept(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char buf[80];
        fprintf(stderr, "accept failed: %d (%s)\n", err,
                wolfSSL_ERR_error_string((unsigned long)err, buf));
        return 1;
    }
    printf("HANDSHAKE %s\n", wolfSSL_get_cipher(ssl));
    fflush(stdout);
    if (report_alpn(ssl)) return 1;

    // With `verify_peer` the handshake above cannot have succeeded without a
    // client certificate that chained to the anchor, but say so explicitly:
    // a silent "no peer cert" would otherwise be indistinguishable from a
    // verified one in the Zig test's eyes.
    if (o.verify_peer) {
        WOLFSSL_X509 *peer_cert = wolfSSL_get_peer_certificate(ssl);
        if (!peer_cert) { fprintf(stderr, "no peer certificate\n"); return 1; }
        char *subject = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_subject_name(peer_cert), NULL, 0);
        printf("PEERCERT %s\n", subject ? subject : "?");
        fflush(stdout);
        wolfSSL_X509_free(peer_cert);
    }

    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
    msg[n] = '\0';
    printf("RECV %s\n", msg);
    fflush(stdout);
    if (wolfSSL_write(ssl, msg, n) != n) { fprintf(stderr, "write failed\n"); return 1; }
    if (g_keyupdate && keyupdate_round(ssl)) return 1;

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}

// PSK-less certificate CLIENT — the direction our server had never been
// tested in: a third party verifying the chain WE present. `VERIFY_PEER`
// with the anchor as the only trusted CA means the handshake fails unless
// our Certificate + CertificateVerify actually check out; wolfSSL's default
// (no domain-name check unless asked) is left alone, since the fixture leaf
// carries a CN, not a SAN matching a loopback address.
//
// `group` — the single NamedGroup this client offers its key_share in.
// WOLFSSL_ECC_X25519 is the classical baseline; WOLFSSL_X25519MLKEM768
// makes wolfSSL offer the 1216-byte PQ-hybrid share, so OUR server's
// encapsulation path (ciphertext-form answer, concatenated shared secret)
// is proven by a third party's key schedule agreeing with ours.
static int run_cert_client(int port, int group) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }
    if (wolfSSL_CTX_set_cipher_list(ctx, kSuite) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed\n");
        return 1;
    }
    int groups[] = {group};
    if (wolfSSL_CTX_set_groups(ctx, groups, 1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_groups failed\n");
        return 1;
    }
    if (!load_anchor(ctx)) return 1;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    // Two knobs, both needed before the hybrid share actually appears in
    // ClientHello1 (found live — with either missing, wolfSSL sends an
    // EMPTY client_shares list and bets on a group-naming HRR, which our
    // server deliberately never sends; see `clientHelloShare`'s documented
    // limit):
    //   * `UseKeyShare` — `set_groups` alone only fills `supported_groups`;
    //     wolfSSL does not GENERATE a PQ-hybrid share unless told to.
    //   * a raised MTU — wolfSSL builds ML-KEM with `WOLFSSL_DTLS_CH_FRAG`,
    //     whose client half EMPTIES the key share whenever ClientHello1
    //     would exceed the MTU rather than fragment it (an initial-flight
    //     amplification precaution). The 1216-byte share puts the hello
    //     over the default; on loopback a 4 KB datagram is fine.
    if (wolfSSL_UseKeyShare(ssl, (word16)group) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "UseKeyShare failed\n");
        return 1;
    }
    if (wolfSSL_dtls_set_mtu(ssl, 4096) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_set_mtu failed\n");
        return 1;
    }
    int rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char buf[80];
        fprintf(stderr, "connect failed: %d (%s)\n", err,
                wolfSSL_ERR_error_string((unsigned long)err, buf));
        return 1;
    }
    // The verify result is the point of this mode, so it is asserted rather
    // than assumed: X509_V_OK means the chain we presented chained to the
    // anchor and its CertificateVerify signature checked out.
    long verify = wolfSSL_get_verify_result(ssl);
    if (verify != WOLFSSL_X509_V_OK) {
        fprintf(stderr, "peer chain not verified: %ld\n", verify);
        return 1;
    }
    WOLFSSL_X509 *peer_cert = wolfSSL_get_peer_certificate(ssl);
    if (!peer_cert) { fprintf(stderr, "no peer certificate\n"); return 1; }
    char *subject =
        wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(peer_cert), NULL, 0);
    printf("PEERCERT %s\n", subject ? subject : "?");
    fflush(stdout);
    wolfSSL_X509_free(peer_cert);

    const char *hello = "hello from wolfssl cert client";
    if (wolfSSL_write(ssl, hello, (int)strlen(hello)) <= 0) {
        fprintf(stderr, "write failed\n");
        return 1;
    }
    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
    msg[n] = '\0';
    printf("ECHO %s\n", msg);
    fflush(stdout);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}

static int run_client(int port) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }
    wolfSSL_CTX_set_psk_client_tls13_callback(ctx, psk_client_cb);
    wolfSSL_CTX_no_dhe_psk(ctx);
    if (wolfSSL_CTX_set_cipher_list(ctx, g_suite) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    if (apply_alpn(ssl)) return 1;
    int rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char buf[80];
        fprintf(stderr, "connect failed: %d (%s)\n", err,
                wolfSSL_ERR_error_string((unsigned long)err, buf));
        return 1;
    }
    printf("HANDSHAKE %s\n", wolfSSL_get_cipher(ssl));
    fflush(stdout);
    if (report_alpn(ssl)) return 1;

    const char *hello = "hello from wolfssl client";
    if (wolfSSL_write(ssl, hello, (int)strlen(hello)) <= 0) {
        fprintf(stderr, "write failed\n");
        return 1;
    }
    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
    msg[n] = '\0';
    printf("ECHO %s\n", msg);
    fflush(stdout);
    if (g_keyupdate == 2 && client_keyupdate_round(ssl)) return 1;

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}

// ── DTLS 1.2 (RFC 6347), `wolfDTLSv1_2_*_method` ─────────────────────────
//
// One runner for every 1.2 mode, configured by `struct opts12`:
//
//   * `psk` — ECDHE-PSK (RFC 5489) with the same fixture PSK/identity as the
//     1.3 modes, through wolfSSL's 1.2 PSK callbacks. Plain (static) PSK is
//     NOT available: Debian's wolfSSL 5.9.1 is built without
//     `WOLFSSL_STATIC_PSK`, so `PSK-AES128-GCM-SHA256` does not exist there.
//   * `cert` / `key` — the identity this side presents (server: always in a
//     certificate mode; client: only when `client_cert`). DER files written
//     by the Zig program from the repo's own fixtures.
//   * `anchor` — the trusted CA for verifying the other side; a client in a
//     certificate mode always verifies (VERIFY_PEER, verify result asserted),
//     a server only with `verify_peer` (VERIFY_PEER | FAIL_IF_NO_PEER_CERT).
//   * `group` / `group_name` — when set, the only ECDHE curve this side
//     accepts.
//   * `mtu` — when non-zero, wolfSSL fragments what it sends to fit it.
//
// The cookie exchange (HelloVerifyRequest) is wolfSSL's DTLS 1.2 server
// default and is left on, so every server mode here runs it.
struct opts12 {
    int server;
    int psk;
    const char *suite;
    const char *cert;
    const char *key;
    const char *anchor;
    int verify_peer;
    int client_cert;
    int group;
    const char *group_name;
    int mtu;
};

static unsigned int psk12_server_cb(WOLFSSL *ssl, const char *identity,
                                    unsigned char *key, unsigned int key_max_len) {
    (void)ssl;
    if (strcmp(identity, kIdentity) != 0) return 0;
    if (key_max_len < sizeof(kPsk)) return 0;
    memcpy(key, kPsk, sizeof(kPsk));
    return (unsigned int)sizeof(kPsk);
}

static unsigned int psk12_client_cb(WOLFSSL *ssl, const char *hint, char *identity,
                                    unsigned int id_max_len, unsigned char *key,
                                    unsigned int key_max_len) {
    (void)ssl;
    printf("HINT %s\n", hint ? hint : "");
    fflush(stdout);
    if (id_max_len < sizeof(kIdentity)) return 0;
    memcpy(identity, kIdentity, sizeof(kIdentity));
    if (key_max_len < sizeof(kPsk)) return 0;
    memcpy(key, kPsk, sizeof(kPsk));
    return (unsigned int)sizeof(kPsk);
}

static int load_anchor_file(WOLFSSL_CTX *ctx, const char *path) {
    unsigned char der[4096];
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "%s missing\n", path); return 0; }
    size_t n = fread(der, 1, sizeof(der), f);
    fclose(f);
    if (n == 0 || n == sizeof(der)) { fprintf(stderr, "%s unreadable\n", path); return 0; }
    if (wolfSSL_CTX_load_verify_buffer(ctx, der, (long)n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "load_verify_buffer(%s) failed\n", path);
        return 0;
    }
    return 1;
}

static int run12(int port, struct opts12 o) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(o.server ? wolfDTLSv1_2_server_method()
                                                : wolfDTLSv1_2_client_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }
    if (wolfSSL_CTX_set_cipher_list(ctx, o.suite) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list(%s) failed\n", o.suite);
        return 1;
    }
    if (o.psk) {
        if (o.server) {
            wolfSSL_CTX_set_psk_server_callback(ctx, psk12_server_cb);
            if (wolfSSL_CTX_use_psk_identity_hint(ctx, "wolfssl-hint") != WOLFSSL_SUCCESS) {
                fprintf(stderr, "use_psk_identity_hint failed\n");
                return 1;
            }
        } else {
            wolfSSL_CTX_set_psk_client_callback(ctx, psk12_client_cb);
        }
    }
    if (o.cert && (o.server || o.client_cert)) {
        if (wolfSSL_CTX_use_certificate_file(ctx, o.cert, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "use_certificate_file(%s) failed\n", o.cert);
            return 1;
        }
        if (wolfSSL_CTX_use_PrivateKey_file(ctx, o.key, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "use_PrivateKey_file(%s) failed\n", o.key);
            return 1;
        }
    }
    int verify = !o.psk && (!o.server || o.verify_peer);
    if (verify) {
        if (!load_anchor_file(ctx, o.anchor)) return 1;
        wolfSSL_CTX_set_verify(ctx,
                               o.server ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT
                                        : WOLFSSL_VERIFY_PEER,
                               NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    if (o.group) {
        // `set_groups` is the TLS 1.3 key-share knob; a 1.2 server picks its
        // ECDHE curve from the client's supported_groups minus the curves
        // `set1_curves_list` leaves out, so that is the one that restricts
        // it (found live: with `set_groups` alone it still chose X25519).
        if (wolfSSL_CTX_set1_curves_list(ctx, o.group_name) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "set1_curves_list(%s) failed\n", o.group_name);
            return 1;
        }
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (o.server) {
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
        printf("READY\n");
        fflush(stdout);
        char probe[1];
        struct sockaddr_in peer = {0};
        socklen_t peer_len = sizeof(peer);
        if (recvfrom(fd, probe, sizeof(probe), MSG_PEEK, (struct sockaddr *)&peer, &peer_len) < 0) {
            perror("recvfrom peek");
            return 1;
        }
        if (connect(fd, (struct sockaddr *)&peer, peer_len) != 0) { perror("connect"); return 1; }
    } else if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    if (o.mtu > 0 && wolfSSL_dtls_set_mtu(ssl, (unsigned short)o.mtu) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_set_mtu(%d) failed\n", o.mtu);
        return 1;
    }
    int rc = o.server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, rc);
        char buf[80];
        fprintf(stderr, "%s failed: %d (%s)\n", o.server ? "accept" : "connect", err,
                wolfSSL_ERR_error_string((unsigned long)err, buf));
        return 1;
    }
    printf("HANDSHAKE %s %s\n", wolfSSL_get_version(ssl), wolfSSL_get_cipher(ssl));
    fflush(stdout);
    if (verify) {
        if (!o.server) {
            long vr = wolfSSL_get_verify_result(ssl);
            if (vr != WOLFSSL_X509_V_OK) { fprintf(stderr, "peer chain not verified: %ld\n", vr); return 1; }
        }
        WOLFSSL_X509 *peer_cert = wolfSSL_get_peer_certificate(ssl);
        if (!peer_cert) { fprintf(stderr, "no peer certificate\n"); return 1; }
        char *subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(peer_cert), NULL, 0);
        printf("PEERCERT %s\n", subject ? subject : "?");
        fflush(stdout);
        wolfSSL_X509_free(peer_cert);
    }

    char msg[256];
    if (o.server) {
        int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
        if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
        msg[n] = '\0';
        printf("RECV %s\n", msg);
        fflush(stdout);
        if (wolfSSL_write(ssl, msg, n) != n) { fprintf(stderr, "write failed\n"); return 1; }
    } else {
        const char *hello = "hello from wolfssl 1.2 client";
        if (wolfSSL_write(ssl, hello, (int)strlen(hello)) <= 0) { fprintf(stderr, "write failed\n"); return 1; }
        int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
        if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
        msg[n] = '\0';
        printf("ECHO %s\n", msg);
        fflush(stdout);
        if (strcmp(msg, hello) != 0) { fprintf(stderr, "echo differs\n"); return 1; }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}

// The 1.2 mode table: `12-<role>-<what>`. Returns -1 for a name that is not
// a 1.2 mode.
static int run12_mode(const char *mode, int port, int mtu) {
    struct opts12 o = {0};
    o.mtu = mtu;
    o.anchor = "anchor-cert.der";
    o.cert = "server-cert.der";
    o.key = "server-key.der";
    o.suite = "ECDHE-ECDSA-AES128-GCM-SHA256";
    if (strncmp(mode, "12-server-", 10) == 0) {
        o.server = 1;
        mode += 10;
    } else if (strncmp(mode, "12-client-", 10) == 0) {
        mode += 10;
    } else {
        return -1;
    }
    if (strcmp(mode, "psk") == 0) {
        o.psk = 1;
        o.suite = "ECDHE-PSK-CHACHA20-POLY1305";
    } else if (strcmp(mode, "ecdsa") == 0) {
    } else if (strcmp(mode, "ecdsa-aes256") == 0) {
        o.suite = "ECDHE-ECDSA-AES256-GCM-SHA384";
    } else if (strcmp(mode, "ecdsa-chacha") == 0) {
        o.suite = "ECDHE-ECDSA-CHACHA20-POLY1305";
    } else if (strcmp(mode, "ecdsa-p256") == 0) {
        o.group = WOLFSSL_ECC_SECP256R1;
        o.group_name = "P-256";
    } else if (strcmp(mode, "ecdsa-mutual") == 0) {
        // Server: requires and verifies OUR client certificate. Client:
        // presents the fixture client certificate to OUR server.
        o.verify_peer = 1;
        o.client_cert = 1;
        if (!o.server) {
            o.cert = "client-cert.der";
            o.key = "client-key.der";
        }
    } else if (strcmp(mode, "rsa") == 0) {
        o.suite = "ECDHE-RSA-AES128-GCM-SHA256";
        o.cert = "rsa12-cert.der";
        o.key = "rsa12-key.der";
        o.anchor = "rsa12-cert.der";
    } else {
        return -1;
    }
    return run12(port, o);
}

int main(int argc, char **argv) {
    // `version` prints the RUNTIME library version and exits. The recorder
    // stamps the committed transcript with whatever this prints, so the header
    // names the wolfSSL that actually produced the bytes -- not a constant in
    // the Zig side that a package upgrade would leave behind.
    if (argc == 2 && strcmp(argv[1], "version") == 0) {
        printf("%s\n", wolfSSL_lib_version());
        return 0;
    }
    if (argc != 3 && argc != 4) {
        fprintf(stderr,
                "usage: %s server|server-hrr|server-cert|server-cert-hrr|"
                "server-cert-p256|server-cert-p256-hrr|server-cert-mlkem|"
                "server-cert-mutual|client|client-cert|client-cert-mlkem|"
                "server-alpn|client-alpn|server-ku-ours|server-ku-theirs|"
                "client-ku-theirs|server-cert-alpn|server-cert-ku-ours|"
                "server-cert-ku-theirs|"
                "server-aes256|server-aes256-hrr|client-aes256|"
                "12-{server,client}-{psk,ecdsa,ecdsa-aes256,ecdsa-chacha,"
                "ecdsa-p256,ecdsa-mutual,rsa} <port> [mtu] | version\n",
                argv[0]);
        return 2;
    }
    wolfSSL_Init();
    int port = atoi(argv[2]);
    int mtu = (argc == 4) ? atoi(argv[3]) : 0;
    struct cert_server_opts cert = {
        .mtu = mtu,
        .hrr_cookie = 0,
        .group = WOLFSSL_ECC_X25519,
        .verify_peer = 0,
    };
    int rc = run12_mode(argv[1], port, mtu);
    if (rc != -1) {
        // a DTLS 1.2 mode, already run
    } else if (strcmp(argv[1], "server") == 0) {
        rc = run_server(port, 0);
    } else if (strcmp(argv[1], "server-hrr") == 0) {
        rc = run_server(port, 1);
    } else if (strcmp(argv[1], "server-cert") == 0) {
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-cert-hrr") == 0) {
        cert.hrr_cookie = 1;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-cert-p256") == 0) {
        cert.group = WOLFSSL_ECC_SECP256R1;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-cert-p256-hrr") == 0) {
        cert.group = WOLFSSL_ECC_SECP256R1;
        cert.hrr_cookie = 1;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-cert-mlkem") == 0) {
        // The X25519MLKEM768 PQ hybrid (0x11EC), guarded because wolfSSL
        // builds it opt-in — Debian's 5.9.1 has it. A build without it
        // exits before READY, which the Zig harness reports as a loud skip.
#ifdef WOLFSSL_HAVE_MLKEM
        cert.group = WOLFSSL_X25519MLKEM768;
        rc = run_cert_server(port, cert);
#else
        fprintf(stderr, "no ML-KEM in this wolfSSL build\n");
        rc = 2;
#endif
    } else if (strcmp(argv[1], "server-cert-mutual") == 0) {
        cert.verify_peer = 1;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-aes256") == 0 ||
               strcmp(argv[1], "server-aes256-hrr") == 0 ||
               strcmp(argv[1], "client-aes256") == 0) {
        g_suite = kSuite384;
        g_psk = kPsk384;
        g_psk_len = sizeof(kPsk384);
        if (strcmp(argv[1], "client-aes256") == 0) {
            rc = run_client(port);
        } else {
            rc = run_server(port, strcmp(argv[1], "server-aes256-hrr") == 0);
        }
    } else if (strcmp(argv[1], "server-alpn") == 0) {
        g_alpn = "coap";
        rc = run_server(port, 0);
    } else if (strcmp(argv[1], "client-alpn") == 0) {
        g_alpn = "h3,coap";
        g_alpn_expect = "coap";
        rc = run_client(port);
    } else if (strcmp(argv[1], "server-ku-ours") == 0) {
        g_keyupdate = 1;
        rc = run_server(port, 0);
    } else if (strcmp(argv[1], "server-ku-theirs") == 0) {
        g_keyupdate = 2;
        rc = run_server(port, 0);
    } else if (strcmp(argv[1], "client-ku-theirs") == 0) {
        g_keyupdate = 2;
        rc = run_client(port);
    } else if (strcmp(argv[1], "server-cert-alpn") == 0) {
        g_alpn = "coap";
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-cert-ku-ours") == 0) {
        g_keyupdate = 1;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "server-cert-ku-theirs") == 0) {
        g_keyupdate = 2;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "client-cert") == 0) {
        rc = run_cert_client(port, WOLFSSL_ECC_X25519);
    } else if (strcmp(argv[1], "client-cert-mlkem") == 0) {
#ifdef WOLFSSL_HAVE_MLKEM
        rc = run_cert_client(port, WOLFSSL_X25519MLKEM768);
#else
        fprintf(stderr, "no ML-KEM in this wolfSSL build\n");
        rc = 2;
#endif
    } else {
        rc = run_client(port);
    }
    wolfSSL_Cleanup();
    return rc;
}
