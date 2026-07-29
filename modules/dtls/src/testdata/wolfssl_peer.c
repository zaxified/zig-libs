// A real third-party DTLS 1.3 peer for `wolfssl_interop.zig` — wolfSSL in
// either role, speaking PSK-only DTLS 1.3 on loopback.
//
//   cc -o wolfssl_peer wolfssl_peer.c -lwolfssl
//   ./wolfssl_peer server <port>     # prints READY, then accepts + echoes
//   ./wolfssl_peer client <port>     # connects, sends, expects the echo
//
// Deliberate configuration, each item chosen to match what this module
// implements — a mismatch here would make the test prove nothing:
//
//   * `wolfSSL_CTX_no_dhe_psk` — psk_ke, no (EC)DHE. This module's `.psk`
//     mode is PSK-only; wolfSSL defaults to psk_dhe_ke.
//   * `wolfSSL_disable_hrr_cookie` — this module deliberately does NOT
//     implement the HelloRetryRequest cookie round trip (it detects an HRR
//     and returns a typed error). wolfSSL's DTLS server does a cookie
//     exchange by default, so it has to be told not to. This is a real
//     limitation of ours, recorded in SPEC.md, not a harness convenience.
//   * `TLS13-AES128-GCM-SHA256` — the intersection of what both sides do.
//     This module also has ChaCha20-Poly1305; CCM is unwired (std nonce
//     width), which is why the CoAP-profile default suite is not used here.
//
// The PSK and identity below are fixtures duplicated in wolfssl_interop.zig;
// they are test material, never a default for anything.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
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

static int run_server(int port) {
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
    wolfSSL_disable_hrr_cookie(ssl);  // our client rejects HelloRetryRequest
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
    if (argc != 3) {
        fprintf(stderr, "usage: %s server|client <port>\n", argv[0]);
        return 2;
    }
    wolfSSL_Init();
    int port = atoi(argv[2]);
    int rc = strcmp(argv[1], "server") == 0 ? run_server(port) : run_client(port);
    wolfSSL_Cleanup();
    return rc;
}
