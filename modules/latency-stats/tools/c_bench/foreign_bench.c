// SPDX-License-Identifier: MIT
//
// HdrHistogram_c 0.11.10 side of `zig build bench-latency-stats`
// (modules/latency-stats/tools/bench.zig). The library (hdr_histogram.c, public
// domain CC0 / BSD-2-Clause) is NOT vendored: bench.zig compiles it from the
// pinned release tarball unpacked at HDRHISTOGRAM_C_DIR (see tools/README.md).
//
//   foreign_bench <work dir> <workload>     name \t ns/op \t count
//   workloads: record record_corrected percentiles merge merge_empty mean_stddev
//
// Work done per op (the same on every side; see bench.zig):
//   record            hdr_reset, then hdr_record_value for each of the 100000 values
//   record_corrected  hdr_reset, then hdr_record_corrected_value(v, 1 ms) for each
//   percentiles       1000 x hdr_value_at_percentile on a populated histogram (sum)
//   merge             hdr_reset(dst), one sample (1) into dst, hdr_add(dst, src)
//   merge_empty       hdr_reset(dst), hdr_add(dst, src) into an EMPTY dst (the Rust
//                     crate turns that into a memcpy; the others add)
//   mean_stddev       hdr_mean + hdr_stddev (floor each, sum)
// Config: lowest 1, highest 3.6e12, 3 significant figures.
#define _POSIX_C_SOURCE 200809L
#include <hdr/hdr_histogram.h>
#include <hdr/hdr_histogram_log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HIGHEST 3600000000000LL
#define INTERVAL 1000000LL

static int64_t* vals;
static size_t nvals;
static struct hdr_histogram *h, *src;

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static uint64_t op_record(void) {
    hdr_reset(h);
    for (size_t i = 0; i < nvals; i++) hdr_record_value(h, vals[i]);
    return (uint64_t)h->total_count;
}
static uint64_t op_corrected(void) {
    hdr_reset(h);
    for (size_t i = 0; i < nvals; i++) hdr_record_corrected_value(h, vals[i], INTERVAL);
    return (uint64_t)h->total_count;
}
static uint64_t op_percentiles(void) {
    uint64_t sum = 0;
    for (int j = 0; j < 1000; j++) sum += (uint64_t)hdr_value_at_percentile(src, (100.0 * j + 0.7) / 1000.0);
    return sum;
}
static uint64_t op_merge(void) {
    hdr_reset(h);
    hdr_record_value(h, 1);
    hdr_add(h, src);
    return (uint64_t)h->total_count;
}
static uint64_t op_merge_empty(void) {
    hdr_reset(h);
    hdr_add(h, src);
    return (uint64_t)h->total_count;
}
static uint64_t op_moments(void) {
    return (uint64_t)hdr_mean(src) + (uint64_t)hdr_stddev(src);
}

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    char path[4096];
    snprintf(path, sizeof path, "%s/values.bin", argv[1]);
    FILE* f = fopen(path, "rb");
    if (!f) return 3;
    fseek(f, 0, SEEK_END);
    nvals = (size_t)ftell(f) / 8;
    fseek(f, 0, SEEK_SET);
    uint64_t* raw = malloc(nvals * 8);
    if (fread(raw, 8, nvals, f) != nvals) return 3;
    fclose(f);
    vals = (int64_t*)raw;
    if (hdr_init(1, HIGHEST, 3, &h) || hdr_init(1, HIGHEST, 3, &src)) return 4;
    for (size_t i = 0; i < nvals; i++) hdr_record_value(src, vals[i]);

    const char* name = argv[2];
    if (!strcmp(name, "interop")) {
        // ours.b64 (our encodeCompressed, base64) must decode here to exactly
        // `src`; our decoder reads c.b64, what this library encodes from `src`.
        snprintf(path, sizeof path, "%s/ours.b64", argv[1]);
        f = fopen(path, "rb");
        if (!f) return 3;
        char* text = malloc(1 << 22);
        size_t tl = fread(text, 1, 1 << 22, f);
        fclose(f);
        struct hdr_histogram* d = NULL;
        if (hdr_log_decode(&d, text, tl) != 0) { fprintf(stderr, "HdrHistogram_c refused our compressed histogram\n"); return 1; }
        if (d->counts_len != src->counts_len || d->total_count != src->total_count ||
            memcmp(d->counts, src->counts, (size_t)d->counts_len * 8) != 0 ||
            hdr_min(d) != hdr_min(src) || hdr_max(d) != hdr_max(src)) {
            fprintf(stderr, "HdrHistogram_c decoded our histogram to something else\n");
            return 1;
        }
        char* enc = NULL;
        if (hdr_log_encode(src, &enc) != 0) return 4;
        snprintf(path, sizeof path, "%s/c.b64", argv[1]);
        f = fopen(path, "wb");
        fwrite(enc, 1, strlen(enc), f);
        fclose(f);
        fprintf(stderr, "HdrHistogram_c 0.11.10 interop ok\n");
        return 0;
    }

    uint64_t (*op)(void) = 0;
    if (!strcmp(name, "record")) op = op_record;
    else if (!strcmp(name, "record_corrected")) op = op_corrected;
    else if (!strcmp(name, "percentiles")) op = op_percentiles;
    else if (!strcmp(name, "merge")) op = op_merge;
    else if (!strcmp(name, "merge_empty")) op = op_merge_empty;
    else if (!strcmp(name, "mean_stddev")) op = op_moments;
    else return 5;

    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) { volatile uint64_t c = op(); (void)c; }
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300;
    uint64_t count = 0;
    for (int r = 0; r < 5; r++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) count = op();
        double d = (now_ns() - t) / (double)n;
        if (d < best) best = d;
    }
    fprintf(stderr, "HdrHistogram_c 0.11.10 (hdr_histogram.c, cc -O3 -march=native)\n");
    printf("%s\t%.3f\t%llu\n", name, best, (unsigned long long)count);
    return 0;
}
