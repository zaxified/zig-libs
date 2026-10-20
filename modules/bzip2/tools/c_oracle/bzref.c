/* SPDX-License-Identifier: MIT
 *
 * Black-box driver around libbzip2 1.0.8 (built from the pinned clone, see
 * README.md), for the differential tests and the benchmark.
 *
 *   bzref c LEVEL WORKFACTOR CHUNK in out.bz2   compress (CHUNK 0 = one BZ_RUN call)
 *   bzref d in.bz2 out                          decompress (all streams)
 *   bzref t in.bz2                              decompress, print "<STATUS> <bytes>"
 *   bzref bench-c LEVEL ROUNDS in.bin               best-of-ROUNDS compress, "ns <n> <bytes>"
 *   bzref bench-d ROUNDS in.bz2                     best-of-ROUNDS decompress
 *
 * Exit status 0 on success; on a libbzip2 error the status name goes to
 * stderr and the exit status is 2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bzlib.h"

static unsigned char *slurp(FILE *f, size_t *n) {
    size_t cap = 1 << 20, len = 0;
    unsigned char *b = malloc(cap);
    for (;;) {
        size_t r = fread(b + len, 1, cap - len, f);
        len += r;
        if (len < cap) break;
        cap *= 2;
        b = realloc(b, cap);
    }
    *n = len;
    return b;
}

static const char *name(int r) {
    switch (r) {
    case BZ_OK: return "BZ_OK";
    case BZ_STREAM_END: return "BZ_STREAM_END";
    case BZ_SEQUENCE_ERROR: return "BZ_SEQUENCE_ERROR";
    case BZ_PARAM_ERROR: return "BZ_PARAM_ERROR";
    case BZ_MEM_ERROR: return "BZ_MEM_ERROR";
    case BZ_DATA_ERROR: return "BZ_DATA_ERROR";
    case BZ_DATA_ERROR_MAGIC: return "BZ_DATA_ERROR_MAGIC";
    case BZ_UNEXPECTED_EOF: return "BZ_UNEXPECTED_EOF";
    default: return "BZ_OTHER";
    }
}

/* Fed the way the bzip2 CLI and Python's BZ2Compressor do: every input byte
 * through BZ_RUN calls (CHUNK bytes each, 0 = all at once), then BZ_FINISH
 * with no input left. (BZ2_bzBuffToBuffCompress passes everything with
 * BZ_FINISH, which closes a block that fills exactly at the end of the input
 * differently.) */
static unsigned char *compress(const unsigned char *in, size_t n, int level, int wf, size_t chunk, size_t *outn) {
    bz_stream s;
    memset(&s, 0, sizeof s);
    if (BZ2_bzCompressInit(&s, level, 0, wf) != BZ_OK) exit(3);
    size_t cap = n + n / 100 + (1 << 20), len = 0;
    unsigned char *out = malloc(cap);
    size_t pos = 0;
    int r;
    while (pos < n) {
        size_t take = chunk ? (n - pos < chunk ? n - pos : chunk) : n - pos;
        s.next_in = (char *)in + pos;
        s.avail_in = (unsigned)take;
        pos += take;
        while (s.avail_in > 0) {
            if (cap - len < (1 << 16)) { cap *= 2; out = realloc(out, cap); }
            s.next_out = (char *)out + len;
            s.avail_out = (unsigned)(cap - len);
            r = BZ2_bzCompress(&s, BZ_RUN);
            len = cap - s.avail_out;
            if (r != BZ_RUN_OK) { fprintf(stderr, "%s\n", name(r)); exit(2); }
        }
    }
    s.next_in = NULL;
    s.avail_in = 0;
    do {
        if (cap - len < (1 << 16)) { cap *= 2; out = realloc(out, cap); }
        s.next_out = (char *)out + len;
        s.avail_out = (unsigned)(cap - len);
        r = BZ2_bzCompress(&s, BZ_FINISH);
        len = cap - s.avail_out;
        if (r != BZ_FINISH_OK && r != BZ_STREAM_END) { fprintf(stderr, "%s\n", name(r)); exit(2); }
    } while (r != BZ_STREAM_END);
    BZ2_bzCompressEnd(&s);
    *outn = len;
    return out;
}

/* All streams; returns status of the last call. */
static int decompress(const unsigned char *in, size_t n, unsigned char **outp, size_t *outn) {
    size_t cap = n * 4 + 4096, len = 0;
    unsigned char *out = malloc(cap);
    size_t pos = 0;
    int r = BZ_OK;
    while (pos < n || r == BZ_OK) {
        bz_stream s;
        memset(&s, 0, sizeof s);
        if (BZ2_bzDecompressInit(&s, 0, 0) != BZ_OK) exit(3);
        s.next_in = (char *)in + pos;
        s.avail_in = (unsigned)(n - pos);
        for (;;) {
            if (cap - len < 65536) { cap *= 2; out = realloc(out, cap); }
            s.next_out = (char *)out + len;
            s.avail_out = (unsigned)(cap - len);
            r = BZ2_bzDecompress(&s);
            len = cap - s.avail_out;
            if (r != BZ_OK) break;
            if (s.avail_in == 0 && s.avail_out > 0) { r = BZ_UNEXPECTED_EOF; break; }
        }
        pos = n - s.avail_in;
        BZ2_bzDecompressEnd(&s);
        if (r != BZ_STREAM_END) break;
        if (pos >= n) break;
    }
    *outp = out;
    *outn = len;
    return r;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t n, outn;
    if (!strcmp(argv[1], "c") && argc == 7) {
        FILE *f = fopen(argv[5], "rb");
        if (!f) return 1;
        unsigned char *in = slurp(f, &n);
        unsigned char *out = compress(in, n, atoi(argv[2]), atoi(argv[3]), (size_t)atol(argv[4]), &outn);
        FILE *o = fopen(argv[6], "wb");
        fwrite(out, 1, outn, o);
        fclose(o);
        return 0;
    }
    if (!strcmp(argv[1], "t") && argc == 3) {
        FILE *f = fopen(argv[2], "rb");
        if (!f) return 1;
        unsigned char *in = slurp(f, &n), *out;
        int r = decompress(in, n, &out, &outn);
        printf("%s %zu\n", name(r), outn);
        return 0;
    }
    if (!strcmp(argv[1], "d") && argc == 4) {
        FILE *f = fopen(argv[2], "rb");
        if (!f) return 1;
        unsigned char *in = slurp(f, &n), *out;
        int r = decompress(in, n, &out, &outn);
        if (r != BZ_STREAM_END) { fprintf(stderr, "%s\n", name(r)); return 2; }
        FILE *o = fopen(argv[3], "wb");
        fwrite(out, 1, outn, o);
        fclose(o);
        return 0;
    }
    if (!strcmp(argv[1], "bench-c") && argc == 5) {
        FILE *f = fopen(argv[4], "rb");
        unsigned char *in = slurp(f, &n);
        double best = 1e30;
        for (int i = 0; i < atoi(argv[3]); i++) {
            double t0 = now();
            unsigned char *out = compress(in, n, atoi(argv[2]), 30, 0, &outn);
            double t = now() - t0;
            free(out);
            if (t < best) best = t;
        }
        printf("%.0f %zu\n", best, outn);
        return 0;
    }
    if (!strcmp(argv[1], "bench-d") && argc == 4) {
        FILE *f = fopen(argv[3], "rb");
        unsigned char *in = slurp(f, &n), *out;
        double best = 1e30;
        for (int i = 0; i < atoi(argv[2]); i++) {
            double t0 = now();
            int r = decompress(in, n, &out, &outn);
            double t = now() - t0;
            if (r != BZ_STREAM_END) { fprintf(stderr, "%s\n", name(r)); return 2; }
            free(out);
            if (t < best) best = t;
        }
        printf("%.0f %zu\n", best, outn);
        return 0;
    }
    return 1;
}
