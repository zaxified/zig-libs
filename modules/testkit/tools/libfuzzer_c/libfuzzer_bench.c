// SPDX-License-Identifier: MIT
//
// The fastest-candidate side of `bench-testkit`: LLVM libFuzzer driving the
// same trivial property as `tools/bench.zig` -- the input (libFuzzer's own,
// at most 160 bytes) mapped to hex digits and decoded. libFuzzer runs inputs
// back to back in one process, so the cost per input is timed from inside
// the callback: one op = 10 000 consecutive inputs, everything libFuzzer
// does between two calls (mutation, coverage feedback, corpus upkeep)
// included -- that is the driver's cost per input.
//
// The property itself is kept out of libFuzzer's instrumentation
// (`NOCOV`: not inlined, no coverage): instrumented, its per-byte compare
// tracing was 37 % of the profile and the input cost 1.5-1.7 us instead of
// 0.58 (measured 2026-10-27) -- a cost of how the property is written, not of
// the driver. Without that feedback libFuzzer's inputs stay shorter (about
// 25 bytes on average against the driver's 56; printed on stderr), which
// only flatters it: this is libFuzzer at its cheapest.
//
// Built by `tools/bench.zig` with `clang -fsanitize=fuzzer-no-link` against
// clang's `libclang_rt.fuzzer_no_main` (own `main`, `LLVMFuzzerRunDriver`):
// with libFuzzer's `main` the work-directory argument would be taken for a
// corpus directory and written into.
//
// Usage: `libfuzzer_bench <work dir> <hex|alloc>`. Prints
// `name \t ns/op \t count` (wall time) and a banner on stderr, then exits
// from the callback. Timing as `testkit.bench.timeIt`: double the batch
// until it takes over 100 ms, then the best of five.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*cb)(const uint8_t *data, size_t size));

#define CASES 10000
#define MAX_LEN 160

#define NOCOV __attribute__((noinline, no_sanitize("coverage")))

static const char digits[] = "0123456789abcdef";
static const char *name;
static int alloc_mode;

NOCOV static int nibble(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

NOCOV static long hex_into(uint8_t *out, size_t out_len, const uint8_t *s, size_t n) {
    if (n % 2 != 0 || out_len < n / 2) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = nibble(s[2 * i]), lo = nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return (long)(n / 2);
}

NOCOV static void property(const uint8_t *data, size_t size) {
    uint8_t s[MAX_LEN];
    size_t n = size < MAX_LEN ? size : MAX_LEN;
    for (size_t i = 0; i < n; i++) s[i] = (uint8_t)digits[data[i] & 15];
    if (!alloc_mode) {
        uint8_t out[MAX_LEN / 2];
        if (hex_into(out, sizeof out, s, n & ~(size_t)1) < 0) abort();
        __asm__ volatile("" : : "r"(out) : "memory");
        return;
    }
    uint8_t *a = malloc(n / 2 + 1);
    uint8_t *c = malloc(n ? n : 1);
    if (!a || !c) abort();
    memcpy(c, s, n);
    if (hex_into(a, n / 2 + 1, c, n & ~(size_t)1) < 0) abort();
    __asm__ volatile("" : : "r"(a) : "memory");
    free(c);
    free(a);
}

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

// The `timeIt` state machine, advanced one input at a time.
static uint64_t calls, ops = 1, t0, best = UINT64_MAX, total_len, total_n;
static int measuring, rounds;

static int callback(const uint8_t *data, size_t size) {
    if (t0 == 0) t0 = now_ns();
    total_len += size;
    total_n++;
    property(data, size);
    if (++calls < ops * CASES) return 0;
    uint64_t t = now_ns(), elapsed = t - t0;
    if (!measuring) {
        if (elapsed > 100000000u) measuring = 1;
        else ops *= 2;
    } else {
        if (elapsed < best) best = elapsed;
        if (++rounds == 5) {
            printf("%s\t%.1f\t%d\n", name, (double)best / (double)ops, CASES);
            fflush(stdout);
            fprintf(stderr, "libFuzzer input length: %.1f bytes on average\n", (double)total_len / (double)total_n);
            _exit(0);
        }
    }
    calls = 0;
    t0 = now_ns();
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[2], "hex") != 0 && strcmp(argv[2], "alloc") != 0)) {
        fprintf(stderr, "usage: libfuzzer_bench <work dir> <hex|alloc>\n");
        return 2;
    }
    name = argv[2];
    alloc_mode = strcmp(name, "alloc") == 0;
    fprintf(stderr, "libFuzzer (LLVM %d, clang runtime), in-process, %d inputs per op\n", __clang_major__, CASES);
    // No corpus directory, a fixed seed, full length from the start (the
    // driver's lengths are not ramped either), quiet.
    char *fargv[] = {
        argv[0], "-max_len=160", "-len_control=0", "-seed=1", "-verbosity=0", "-print_final_stats=0", NULL,
    };
    int fargc = 6;
    char **fp = fargv;
    return LLVMFuzzerRunDriver(&fargc, &fp, callback);
}
