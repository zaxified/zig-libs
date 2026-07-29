// A real third-party DTLS 1.3 peer for `wolfssl_interop.zig` — wolfSSL in
// either role, speaking PSK-only DTLS 1.3 on loopback.
//
//   cc -o wolfssl_peer wolfssl_peer.c -lwolfssl
//   ./wolfssl_peer server <port>      # prints READY, then accepts + echoes
//   ./wolfssl_peer server-hrr <port>  # same, but with the DEFAULT cookie
//                                     # exchange (HelloRetryRequest) left on
//   ./wolfssl_peer client <port>      # connects, sends, expects the echo
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
// The PSK and identity below are fixtures duplicated in wolfssl_interop.zig;
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

static unsigned int psk_server_cb(WOLFSSL *ssl, const char *identity,
                                  unsigned char *key, unsigned int key_max_len,
                                  const char **ciphername) {
    (void)ssl;
    if (strcmp(identity, kIdentity) != 0) return 0;
    if (key_max_len < sizeof(kPsk)) return 0;
    memcpy(key, kPsk, sizeof(kPsk));
    *ciphername = kSuite;
    return (unsigned int)sizeof(kPsk);
}

static unsigned int psk_client_cb(WOLFSSL *ssl, const char *hint,
                                  char *identity, unsigned int id_max_len,
                                  unsigned char *key, unsigned int key_max_len,
                                  const char **ciphername) {
    (void)ssl;
    (void)hint;
    if (id_max_len < sizeof(kIdentity)) return 0;
    memcpy(identity, kIdentity, sizeof(kIdentity));
    if (key_max_len < sizeof(kPsk)) return 0;
    memcpy(key, kPsk, sizeof(kPsk));
    *ciphername = kSuite;
    return (unsigned int)sizeof(kPsk);
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
    if (wolfSSL_CTX_set_cipher_list(ctx, kSuite) != WOLFSSL_SUCCESS) {
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

    char msg[256];
    int n = wolfSSL_read(ssl, msg, sizeof(msg) - 1);
    if (n <= 0) { fprintf(stderr, "read failed\n"); return 1; }
    msg[n] = '\0';
    printf("RECV %s\n", msg);
    fflush(stdout);
    if (wolfSSL_write(ssl, msg, n) != n) { fprintf(stderr, "write failed\n"); return 1; }

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
static int run_cert_client(int port) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (!ctx) { fprintf(stderr, "CTX_new failed\n"); return 1; }
    if (wolfSSL_CTX_set_cipher_list(ctx, kSuite) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed\n");
        return 1;
    }
    int groups[] = {WOLFSSL_ECC_X25519};
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
    if (wolfSSL_CTX_set_cipher_list(ctx, kSuite) != WOLFSSL_SUCCESS) {
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

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr,
                "usage: %s server|server-hrr|server-cert|server-cert-hrr|"
                "server-cert-p256|server-cert-p256-hrr|server-cert-mutual|"
                "client|client-cert <port> [mtu]\n",
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
    int rc;
    if (strcmp(argv[1], "server") == 0) {
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
    } else if (strcmp(argv[1], "server-cert-mutual") == 0) {
        cert.verify_peer = 1;
        rc = run_cert_server(port, cert);
    } else if (strcmp(argv[1], "client-cert") == 0) {
        rc = run_cert_client(port);
    } else {
        rc = run_client(port);
    }
    wolfSSL_Cleanup();
    return rc;
}
