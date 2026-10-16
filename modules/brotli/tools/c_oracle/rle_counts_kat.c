// SPDX-License-Identifier: MIT
//
// The recipe of the `optimizeCountsForRle` known answers in `src/encoder.zig`:
// google/brotli's own `BrotliOptimizeHuffmanCountsForRle` (an internal
// symbol, so built from its source, not the system library) over histograms
// from the same generator as the test. Writes the smoothed counts of case
// `n`, little-endian u32, to stdout; the test pins their SHA-256.
//
//   SRC=<brotli-1.2.0 checkout>
//   cc -O2 -I$SRC/c/include -I$SRC/c $SRC/c/enc/entropy_encode.c \
//      tools/c_oracle/rle_counts_kat.c -o /tmp/rle_kat
//   for n in 0 1 2 3 4; do /tmp/rle_kat $n | sha256sum; done
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "enc/entropy_encode.h"

static uint64_t state;

static uint32_t next(void) {
    state = state * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(state >> 33);
}

/* Case 4: a histogram found by a search where a run's count meets the
   streak bound exactly (`>=` against `>`). Keep in step with
   `rle_kat_case4` in src/encoder.zig. */
static const uint32_t case4[256] = {
    4, 2, 4, 3, 3, 2, 4, 3, 2, 3, 4, 2, 0, 1, 0, 0, 4, 1, 0, 0, 1, 0, 3, 3, 58, 58, 58, 58, 58,
    58, 58, 3, 4, 4, 4, 2, 3, 2, 4, 0, 3, 4, 1, 269, 270, 0, 0, 55, 59, 57, 53, 42, 40, 39, 40,
    41, 42, 2, 2, 1, 2, 2, 2, 2, 3, 1, 2, 1, 3, 0, 1, 2, 1, 1, 4, 2, 5, 0, 0, 0, 0, 0, 0, 1, 3,
    3, 1, 3, 1, 3, 3, 2, 3, 3, 1, 24, 22, 24, 22, 24, 23, 22, 3, 1, 1, 2, 2, 2, 1, 1, 3, 2, 2,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 6, 2, 2, 2, 3, 7, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 2, 2, 0, 1, 1, 2, 1, 2, 2, 2, 1, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 88, 87, 88, 89, 87,
    87, 87, 88, 88, 87, 89, 89, 331, 329, 331, 331, 330, 331, 327, 330, 329, 329, 3, 3, 2, 1, 0,
    2, 0, 0, 2, 1, 3, 20, 18, 21, 18, 19, 20, 21, 2, 2, 2, 2, 2, 3, 370, 368, 370, 370, 366,
    368, 371, 277, 277, 278, 277, 276, 278, 277, 276, 278, 1, 3, 2, 2, 3, 3, 3, 2, 1, 0, 1, 3,
    1, 3, 4, 2, 0, 2, 5, 7, 1, 2, 0, 0, 0, 0,
};

/* Keep in step with `rleKatCase` in src/encoder.zig. */
static size_t make_case(int n, uint32_t *counts) {
    state = 0x9e3779b97f4a7c15ull * (uint64_t)(n + 1);
    size_t len = n == 1 ? 704 : 256;
    for (size_t i = 0; i < len; i++) {
        uint32_t r = next();
        switch (n) {
        case 0: /* font-like: many small counts, some zeros */
            counts[i] = r % 7 == 0 ? 0 : (r >> 7) % (1 + (uint32_t)(i * 37 % 50));
            break;
        case 1: /* small counts between runs of zeros, trailing zeros */
            counts[i] = i % 24 < 8 || i >= 690 ? 0 : 1 + r % 3;
            break;
        case 4:
            counts[i] = case4[i];
            break;
        case 2: /* smooth, falling */
            counts[i] = 1000 / (1 + (uint32_t)i / 8) + r % 5;
            break;
        default: /* plateaus with noise and isolated zeros */
            counts[i] = r % 11 == 0 ? 0 : 40 * (1 + (uint32_t)(i / 32)) + r % 9;
            break;
        }
    }
    return len;
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    uint32_t counts[704];
    uint8_t good[704];
    size_t len = make_case(atoi(argv[1]), counts);
    BrotliOptimizeHuffmanCountsForRle(len, counts, good);
    for (size_t i = 0; i < len; i++) {
        uint8_t b[4] = { (uint8_t)counts[i], (uint8_t)(counts[i] >> 8),
                         (uint8_t)(counts[i] >> 16), (uint8_t)(counts[i] >> 24) };
        fwrite(b, 1, 4, stdout);
    }
    return 0;
}
