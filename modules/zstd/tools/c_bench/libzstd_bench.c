// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-zstd` (modules/zstd/tools/bench.zig): times
// libzstd's one-shot compression and decompression on reused contexts
// (ZSTD_compressCCtx / ZSTD_decompressDCtx) over the workloads listed in
// <work dir>/workloads.tsv (name, c|d, level, input path). One line per
// workload: name, ns/op, the output size (a compressed size must equal the
// Zig side's byte for byte: the module emits libzstd's frames), user-mode
// cycles/op (0 without a cycle counter). The system
// libzstd is linked by path; its headers are not installed everywhere, so the
// prototypes are declared here (libzstd's stable API). Timing matches the
// Zig side: double the batch until it takes over 100 ms, best of five.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

typedef struct ZSTD_CCtx_s ZSTD_CCtx;
typedef struct ZSTD_DCtx_s ZSTD_DCtx;
ZSTD_CCtx *ZSTD_createCCtx(void);
ZSTD_DCtx *ZSTD_createDCtx(void);
size_t ZSTD_compressCCtx(ZSTD_CCtx *, void *, size_t, const void *, size_t, int);
size_t ZSTD_decompressDCtx(ZSTD_DCtx *, void *, size_t, const void *, size_t);
size_t ZSTD_compressBound(size_t);
unsigned ZSTD_isError(size_t);
const char *ZSTD_versionString(void);

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

// This thread's user-mode cycles, as the Zig side counts them; -1 = none.
static int cycles_open(void) {
#ifdef __linux__
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    return (int)syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
#else
    return -1;
#endif
}

static unsigned long long cycles_read(int fd) {
    unsigned long long v = 0;
#ifdef __linux__
    if (fd >= 0 && read(fd, &v, sizeof v) != sizeof v) v = 0;
#endif
    return v;
}

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(*len);
    if (fread(b, 1, *len, f) != *len) { fprintf(stderr, "short read %s\n", path); exit(1); }
    fclose(f);
    return b;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: libzstd_bench <work dir>\n"); return 2; }
    fprintf(stderr, "libzstd %s\n", ZSTD_versionString());
    char path[4096];
    snprintf(path, sizeof path, "%s/workloads.tsv", argv[1]);
    FILE *list = fopen(path, "r");
    if (!list) { perror(path); return 1; }
    int cyc = cycles_open();
    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    char name[256], mode[8], file[4096];
    int level;
    while (fscanf(list, "%255s\t%7s\t%d\t%4095s\n", name, mode, &level, file) == 4) {
        size_t len;
        unsigned char *src = slurp(file, &len);
        size_t cap = ZSTD_compressBound(len);
        unsigned char *frame = malloc(cap), *out = malloc(cap > len ? cap : len);
        size_t flen = ZSTD_compressCCtx(cctx, frame, cap, src, len, level);
        if (ZSTD_isError(flen)) { fprintf(stderr, "compress failed\n"); return 1; }
        int dec = mode[0] == 'd';
        size_t n = 1, result = 0;
        for (;;) {
            double t = now_ns();
            for (size_t i = 0; i < n; i++)
                result = dec ? ZSTD_decompressDCtx(dctx, out, len, frame, flen) : ZSTD_compressCCtx(cctx, out, cap, src, len, level);
            if (now_ns() - t > 1e8) break;
            n *= 2;
        }
        double best = 1e300;
        unsigned long long best_cyc = ~0ULL;
        for (int k = 0; k < 5; k++) {
            double t = now_ns();
            unsigned long long c0 = cycles_read(cyc);
            for (size_t i = 0; i < n; i++)
                result = dec ? ZSTD_decompressDCtx(dctx, out, len, frame, flen) : ZSTD_compressCCtx(cctx, out, cap, src, len, level);
            unsigned long long c = cycles_read(cyc) - c0;
            double d = now_ns() - t;
            if (d < best) best = d;
            if (c < best_cyc) best_cyc = c;
        }
        if (ZSTD_isError(result)) { fprintf(stderr, "%s failed\n", name); return 1; }
        printf("%s\t%.1f\t%zu\t%.1f\n", name, best / (double)n, result, cyc >= 0 ? (double)best_cyc / (double)n : 0.0);
        fflush(stdout);
        free(src);
        free(frame);
        free(out);
    }
    return 0;
}
