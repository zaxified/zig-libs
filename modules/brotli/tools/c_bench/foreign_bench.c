// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-brotli` (modules/brotli/tools/bench.zig): times
// google/brotli's one-shot API (libbrotlienc / libbrotlidec) over the payloads
// the Zig program writes into the directory given as the first argument, for
// the one workload named by the second argument:
//   c<Q>_<payload>   BrotliEncoderCompress at quality Q, lgwin 22, generic mode
//   d_<payload>      BrotliDecoderDecompress of <payload>.ref.br (the stream
//                    this program wrote with quality 9 in `prep` mode)
//   prep             writes <payload>.ref.br and prints every quality's size
// Prints one line: name, ns/op, user-mode cycles/op (0 without a counter),
// and the number of UNCOMPRESSED bytes the operation covers (the count that
// must agree with the Zig side). Compressed sizes are reported by `prep`.
#define _GNU_SOURCE
#include <brotli/decode.h>
#include <brotli/encode.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

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

static unsigned char *in, *enc_buf, *dec_buf, *ref_br;
static size_t in_len, ref_len;
static int quality;

static size_t comp(void) {
    size_t n = BrotliEncoderMaxCompressedSize(in_len);
    if (!BrotliEncoderCompress(quality, 22, BROTLI_MODE_GENERIC, in_len, in, &n, enc_buf)) {
        fprintf(stderr, "BrotliEncoderCompress failed\n");
        exit(1);
    }
    sink += n;
    return in_len;
}
static size_t decomp(void) {
    size_t n = in_len;
    if (BrotliDecoderDecompress(ref_len, ref_br, &n, dec_buf) != BROTLI_DECODER_RESULT_SUCCESS || n != in_len) {
        fprintf(stderr, "BrotliDecoderDecompress failed\n");
        exit(1);
    }
    return n;
}

static const char *payloads[] = {"json", "html", "text"};

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "google/brotli encoder %08x decoder %08x\n", BrotliEncoderVersion(), BrotliDecoderVersion());
    if (strcmp(w, "prep") == 0) {
        for (int p = 0; p < 3; p++) {
            char name[64];
            snprintf(name, sizeof name, "%s.bin", payloads[p]);
            in = slurp(name, &in_len);
            enc_buf = malloc(BrotliEncoderMaxCompressedSize(in_len));
            printf("%s: %zu bytes\n", payloads[p], in_len);
            for (int q = 0; q <= 11; q++) {
                size_t n = BrotliEncoderMaxCompressedSize(in_len);
                BrotliEncoderCompress(q, 22, BROTLI_MODE_GENERIC, in_len, in, &n, enc_buf);
                printf("  q%-2d %zu\n", q, n);
                if (q == 9) {
                    snprintf(name, sizeof name, "%s.ref.br", payloads[p]);
                    spit(name, enc_buf, n);
                }
            }
        }
        return 0;
    }
    char pay[32];
    int q = 0;
    int decompress = 0;
    if (sscanf(w, "c%d_%31s", &q, pay) == 2) {
        quality = q;
    } else if (sscanf(w, "d_%31s", pay) == 1) {
        decompress = 1;
    } else { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    char name[64];
    snprintf(name, sizeof name, "%s.bin", pay);
    in = slurp(name, &in_len);
    enc_buf = malloc(BrotliEncoderMaxCompressedSize(in_len));
    dec_buf = malloc(in_len + 1);
    if (decompress) {
        snprintf(name, sizeof name, "%s.ref.br", pay);
        ref_br = slurp(name, &ref_len);
    }
    cycles_open();
    bench(w, decompress ? decomp : comp);
    return 0;
}
