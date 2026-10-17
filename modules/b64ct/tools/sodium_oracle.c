// SPDX-License-Identifier: MIT
//
// libsodium side of `zig build interop-b64ct` (modules/b64ct/tools/interop.zig):
// a black box over libsodium's public base64 API. Reads one case per line
// from argv[1], writes one verdict per line to argv[2].
//
//   case:     <op> <variant> <ignore hex | -> <input hex | ->
//             op E = sodium_bin2base64, D = sodium_base642bin with
//             b64_end NULL (whole input), P = with b64_end (prefix);
//             variant = libsodium's constant (1, 3, 5, 7); ignore "-" = NULL
//   verdict:  ok <output hex | -> <consumed>   or   err
//
// Built from libsodium's own `src/libsodium/sodium/codecs.c` (the recipe and
// pinned hash are in interop.zig / tools/README.md) and the shim headers in
// tools/sodium_shim/; the prototypes below are its public API (sodium/utils.h).
// SODIUM_CODECS_VERSION names the release the codecs.c came from.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *sodium_bin2base64(char *const b64, const size_t b64_maxlen,
                        const unsigned char *const bin, const size_t bin_len,
                        const int variant);
int sodium_base642bin(unsigned char *const bin, const size_t bin_maxlen,
                      const char *const b64, const size_t b64_len,
                      const char *const ignore, size_t *const bin_len,
                      const char **const b64_end, const int variant);
size_t sodium_base64_encoded_len(const size_t bin_len, const int variant);

static size_t unhex(const char *h, unsigned char *out) {
    if (strcmp(h, "-") == 0) return 0;
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

static void puthex(FILE *f, const unsigned char *b, size_t n) {
    if (n == 0) { fputc('-', f); return; }
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
}

static char line[1 << 16];
static unsigned char input[1 << 15];
static unsigned char out[1 << 15];
static char ignore_buf[256];

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", SODIUM_CODECS_VERSION);
        return 0;
    }
    if (argc != 3) { fprintf(stderr, "usage: sodium_oracle <cases> <verdicts>\n"); return 2; }
    FILE *in = fopen(argv[1], "r");
    FILE *o = fopen(argv[2], "w");
    if (!in || !o) { perror("open"); return 1; }
    while (fgets(line, sizeof line, in)) {
        char op[4], ig_hex[600], in_hex[sizeof line];
        int variant;
        if (sscanf(line, "%3s %d %599s %s", op, &variant, ig_hex, in_hex) != 4) {
            fprintf(stderr, "bad case: %s", line);
            return 1;
        }
        size_t n = unhex(in_hex, input);
        const char *ignore = NULL;
        if (strcmp(ig_hex, "-") != 0) {
            size_t k = unhex(ig_hex, (unsigned char *)ignore_buf);
            ignore_buf[k] = 0;
            ignore = ignore_buf;
        }
        if (op[0] == 'E') {
            size_t len = sodium_base64_encoded_len(n, variant); // includes the NUL
            sodium_bin2base64((char *)out, len, input, n, variant);
            fputs("ok ", o);
            puthex(o, out, len - 1);
            fputs(" 0\n", o);
        } else {
            size_t bin_len = 0;
            const char *end = NULL;
            int rc = sodium_base642bin(out, sizeof out, (const char *)input, n, ignore,
                                       &bin_len, op[0] == 'P' ? &end : NULL, variant);
            if (rc != 0) {
                fputs("err\n", o);
            } else {
                fputs("ok ", o);
                puthex(o, out, bin_len);
                fprintf(o, " %zu\n", op[0] == 'P' ? (size_t)(end - (const char *)input) : n);
            }
        }
    }
    fclose(o);
    return 0;
}
