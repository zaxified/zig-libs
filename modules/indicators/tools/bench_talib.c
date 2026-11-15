/* SPDX-License-Identifier: MIT
 *
 * C side of the indicators comparative benchmark (`tools/bench.zig`): times
 * TA-Lib 0.8.3's batch API (`TA_<F>`) and streaming API (`TA_<F>_Open/_Update`)
 * over the same seeded random-walk OHLCV bars the Zig side generates.
 *
 *   bench_talib <dir> <row>.<n>     time one row over the first n bars
 *   bench_talib <dir> --sum <row>.<n>   print `row.n \t <sum of finite outputs>` (cross-check)
 *   bench_talib <dir> --list        print the row names
 *
 * <dir>/ohlcv.bin: five arrays (open, high, low, close, volume) of N f64 each, N = size/40.
 * Output of a timed run: `name \t ns/op \t cycles/op \t count` (benchkit's foreign
 * protocol); count = outNBElement of the batch call (streams: updates that produced a
 * value). Timing as the Zig side: double the batch until it takes over 100 ms, best
 * of five. One thread, preallocated output buffers, no allocation in the timed batch
 * (TA-Lib's own internal mallocs, e.g. STOCH's temp buffer, stay in: they are its cost).
 */
#define _GNU_SOURCE
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif
#include <ta_libc.h>

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

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

static double *IO, *IH, *IL, *IC, *IV, *OA, *OB, *OC, *OD;
static int *OI;
static size_t N;

#define UNP(...) __VA_ARGS__
/* ROW(name, TA function, (inputs,), (params,), (outputs)) */
#define ROW(nm, FN, INS, ARGS, OUTS) \
    static int w_##nm(int n) { \
        int b = 0, c = 0; \
        TA_RetCode r = FN(0, n - 1, UNP INS UNP ARGS & b, &c, UNP OUTS); \
        if (r != TA_SUCCESS) { fprintf(stderr, #nm ": rc %d\n", (int)r); exit(1); } \
        return c; \
    }
#include "bench_rows.h"
#undef ROW

/* streams: Open over the first SEED bars (TA-Lib refuses an empty history), then updates for the rest;
 * the count is the updates that gave a value */
#define SEED 100
static int s_ema(int n) {
    TA_EMA_Stream *s; double o;
    if (TA_EMA_Open(&s, IC, SEED, 30, &o) != TA_SUCCESS) { fprintf(stderr, "ema open\n"); exit(1); }
    int c = 0;
    for (int i = SEED; i < n; i++) if (TA_EMA_Update(s, IC[i], &o) == TA_SUCCESS && !isnan(o)) c++;
    TA_EMA_Close(s);
    return c;
}
static int s_rsi(int n) {
    TA_RSI_Stream *s; double o;
    if (TA_RSI_Open(&s, IC, SEED, 14, &o) != TA_SUCCESS) { fprintf(stderr, "rsi open\n"); exit(1); }
    int c = 0;
    for (int i = SEED; i < n; i++) if (TA_RSI_Update(s, IC[i], &o) == TA_SUCCESS && !isnan(o)) c++;
    TA_RSI_Close(s);
    return c;
}
static int s_atr(int n) {
    TA_ATR_Stream *s; double o;
    if (TA_ATR_Open(&s, IH, IL, IC, SEED, 14, &o) != TA_SUCCESS) { fprintf(stderr, "atr open\n"); exit(1); }
    int c = 0;
    for (int i = SEED; i < n; i++) if (TA_ATR_Update(s, IH[i], IL[i], IC[i], &o) == TA_SUCCESS && !isnan(o)) c++;
    TA_ATR_Close(s);
    return c;
}

typedef struct { const char *name; int (*f)(int); } Row;
static const Row rows[] = {
#define ROW(nm, FN, INS, ARGS, OUTS) { #nm, w_##nm },
#include "bench_rows.h"
#undef ROW
    { "s_ema", s_ema }, { "s_rsi", s_rsi }, { "s_atr", s_atr },
};
#define NROWS (sizeof rows / sizeof rows[0])

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: bench_talib <dir> <row>.<n> | --sum <row>.<n> | --list\n"); return 2; }
    if (!strcmp(argv[2], "--list")) {
        for (size_t i = 0; i < NROWS; i++) printf("%s\n", rows[i].name);
        return 0;
    }
    if (TA_Initialize() != TA_SUCCESS) { fprintf(stderr, "TA_Initialize failed\n"); return 2; }
    int sum_mode = !strcmp(argv[2], "--sum");
    const char *want = sum_mode ? argv[3] : argv[2];
    char name[256];
    snprintf(name, sizeof name, "%s", want);
    char *dot = strchr(name, '.');
    if (!dot) { fprintf(stderr, "workload must be row.n\n"); return 2; }
    *dot = 0;
    int n = atoi(dot + 1);
    const Row *row = NULL;
    for (size_t i = 0; i < NROWS; i++) if (!strcmp(rows[i].name, name)) row = &rows[i];
    if (!row) { fprintf(stderr, "unknown row %s\n", name); return 2; }

    char path[4096];
    snprintf(path, sizeof path, "%s/ohlcv.bin", argv[1]);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    N = (size_t)sz / 40;
    double *all = malloc((size_t)sz);
    if (fread(all, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);
    if ((size_t)n > N) { fprintf(stderr, "n > bars\n"); return 2; }
    IO = all; IH = all + N; IL = all + 2 * N; IC = all + 3 * N; IV = all + 4 * N;
    OA = malloc(N * sizeof(double)); OB = malloc(N * sizeof(double)); OC = malloc(N * sizeof(double)); OD = malloc(N * sizeof(double));
    OI = malloc(N * sizeof(int));
    memset(OA, 0, N * 8); memset(OB, 0, N * 8); memset(OC, 0, N * 8); memset(OD, 0, N * 8); memset(OI, 0, N * 4);

    if (sum_mode) {
        int c = row->f(n);
        double s = 0;
        for (int i = 0; i < c; i++) {
            if (isfinite(OA[i])) s += OA[i];
            if (isfinite(OB[i])) s += OB[i];
            if (isfinite(OC[i])) s += OC[i];
            if (isfinite(OD[i])) s += OD[i];
            s += OI[i];
        }
        printf("%s\t%.17g\t%d\n", want, s, c);
        return 0;
    }

    fprintf(stderr, "TA-Lib 0.8.3 (our compile: -O2 -ffp-contract=off -fno-math-errno, generic x86-64 + its own fma clones)\n");
    int cyc = cycles_open();
    int result = 0;
    size_t reps = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < reps; i++) result = row->f(n);
        if (now_ns() - t > 1e8) break;
        reps *= 2;
    }
    double best = 1e300;
    unsigned long long best_cyc = ~0ULL;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        unsigned long long c0 = cycles_read(cyc);
        for (size_t i = 0; i < reps; i++) result = row->f(n);
        unsigned long long c = cycles_read(cyc) - c0;
        double e = now_ns() - t;
        if (e < best) best = e;
        if (c < best_cyc) best_cyc = c;
    }
    printf("%s\t%.3f\t%.3f\t%d\n", want, best / (double)reps, cyc >= 0 ? (double)best_cyc / (double)reps : 0.0, result);
    return 0;
}
