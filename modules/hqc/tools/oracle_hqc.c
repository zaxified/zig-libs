/* SPDX-License-Identifier: MIT
 *
 * HQC differential oracle: seed the reference PRNG with a caller-supplied
 * 48-byte seed (hex on argv[1], or the NIST KAT default when absent) and dump
 * pk/sk/ct/ss as hex.  Mirrors exactly what the reference's own
 * tests/kats/test_kat.c does:
 *   prng_init(seed,NULL,48,0); crypto_kem_keypair; crypto_kem_enc; crypto_kem_dec
 * so that with the KAT seed for count=N it reproduces .rsp line-for-line.
 *
 * WHY THIS EXISTS. It is the only way to ask the C reference a question the
 * published KATs do not answer. The nine official vectors fix nine seeds; a
 * disagreement that only shows up on a tenth input is invisible to them, and
 * this module's own tests cannot find it either, because they replay the same
 * nine. Compiled against the reference's static library by `oracle.sh`, this
 * turns the reference into a black box we can query with any seed.
 *
 * WHAT IT NEEDS. The reference headers (api.h, symmetric.h) and its built
 * library — `oracle.sh` supplies both. This file is ours; nothing here is
 * copied from the reference, whose licence (public domain) is recorded in the
 * module's NOTICE.
 *
 * WHAT IT PRODUCES. One `label = UPPERCASE-HEX` line per field, field names
 * identical to the .rsp files, so output and .rsp can be compared directly.
 *
 * usage: oracle_<lane>_hqc-<v> [seed_hex_96chars | --kat N]
 *   --kat N  derive the KAT seed for count=N exactly as PQCgenKAT_kem does
 *            (entropy_input = 0x00..0x2f, then N+1 draws of 48 bytes).
 */
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "symmetric.h"

static void put(const char *label, const unsigned char *a, size_t n) {
    printf("%s = ", label);
    for (size_t i = 0; i < n; i++) printf("%02X", a[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    unsigned char seed[48];
    static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    static unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    static unsigned char ss[CRYPTO_BYTES], ss2[CRYPTO_BYTES];
    int katno = -1;

    if (argc >= 3 && strcmp(argv[1], "--kat") == 0) {
        katno = atoi(argv[2]);
    } else if (argc >= 2) {
        if (strlen(argv[1]) != 96) { fprintf(stderr, "seed must be 96 hex chars\n"); return 2; }
        for (int i = 0; i < 48; i++) { unsigned x; sscanf(argv[1] + 2*i, "%2x", &x); seed[i] = (unsigned char)x; }
    } else {
        katno = 0;
    }

    if (katno >= 0) {
        unsigned char entropy_input[48];
        for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)i;
        prng_init(entropy_input, NULL, 48, 0);
        for (int i = 0; i <= katno; i++) prng_get_bytes(seed, 48);
    }

    printf("# %s  (%s)\n", CRYPTO_ALGNAME, katno >= 0 ? "NIST KAT seed" : "user seed");
    if (katno >= 0) printf("count = %d\n", katno);
    put("seed", seed, 48);

    prng_init(seed, NULL, 48, 0);
    if (crypto_kem_keypair(pk, sk) != 0) { fprintf(stderr, "keypair failed\n"); return 1; }
    put("pk", pk, CRYPTO_PUBLICKEYBYTES);
    put("sk", sk, CRYPTO_SECRETKEYBYTES);
    if (crypto_kem_enc(ct, ss, pk) != 0) { fprintf(stderr, "enc failed\n"); return 1; }
    put("ct", ct, CRYPTO_CIPHERTEXTBYTES);
    put("ss", ss, CRYPTO_BYTES);
    if (crypto_kem_dec(ss2, ct, sk) != 0) { fprintf(stderr, "dec failed\n"); return 1; }
    if (memcmp(ss, ss2, CRYPTO_BYTES) != 0) { fprintf(stderr, "ss mismatch enc vs dec\n"); return 1; }
    printf("# dec agrees with enc\n");
    return 0;
}
