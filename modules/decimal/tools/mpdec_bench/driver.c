// SPDX-License-Identifier: MIT
//
// Reference side of `zig build bench-decimal` (modules/decimal/tools/bench.zig):
// libmpdec 4.0.1 (BSD-2, the C engine of Python's `decimal`), linked statically.
//
//   mpdec_bench <dir> <workload>   one line on stdout: name \t ns \t count
//   mpdec_bench <dir> check        writes sample_mpd_<w>.txt (the first 1000
//                                  canonical results of every workload) and prints
//                                  `count \t <w> \t <hash>` per workload
//
// <dir> holds the inputs the Zig side wrote: money.txt, rate.txt, big28.txt,
// big200.txt (one decimal string per line). Timing matches the Zig side: double
// the batch until it takes over 100 ms, keep the best of five, ns per op (one
// op = the whole workload). Results are consumed in place (a volatile sink of
// the low coefficient word), never stored; operands are parsed before the clock
// starts; one result mpd_t is reused (no allocation inside the loops, except
// the string workloads, where libmpdec's `mpd_to_sci_size` mallocs).
//
// The count is computed UNTIMED, after the timing: the sum over all results of
// FNV-1a-64 of the canonical text of the result (plain notation, trailing
// fractional zeros and a dangling dot stripped, "-0" -> "0"), identical in
// bench.zig and rust_bench/src/main.rs.
//
// Contexts: prec 38, round-half-even for parse / div / quantize-to-2 / sqrt;
// quantize-to-12 after a multiplication uses round-half-up (= away from zero
// in libmpdec); big add / mul run at prec 2P+8 (exact, as BigDecimal is exact).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mpdecimal.h"

enum Kind {
    PARSE_MONEY, ADDSUB_CHAIN, MUL12, MUL2, DIVROUND12, TOSTR_MONEY, TOSTR_Q12,
    ADD28, MUL28, DIV28, SQRT28, ADD200, MUL200, DIV200, SQRT200, NKINDS
};

typedef struct { const char *name; int kind; size_t n; } W;

#define N_DEC 100000
#define CHAIN_LEN 100
static const W works[] = {
    { "parse_money", PARSE_MONEY, N_DEC }, { "addsub_chain", ADDSUB_CHAIN, N_DEC },
    { "mul12", MUL12, N_DEC }, { "mul2", MUL2, N_DEC }, { "divround12", DIVROUND12, N_DEC },
    { "tostr_money", TOSTR_MONEY, N_DEC }, { "tostr_q12", TOSTR_Q12, N_DEC },
    { "add28", ADD28, 2000 }, { "mul28", MUL28, 2000 }, { "div28", DIV28, 2000 }, { "sqrt28", SQRT28, 2000 },
    { "add200", ADD200, 500 }, { "mul200", MUL200, 500 }, { "div200", DIV200, 500 }, { "sqrt200", SQRT200, 500 },
};
#define NW (sizeof works / sizeof works[0])

static volatile uint64_t g_sink;

// ── inputs ───────────────────────────────────────────────────────────────────

static char **money_s, **rate_s;
static mpd_t **money, **rate, **quo, **big[2]; // big[0] = 28 digits, big[1] = 200
static size_t n_money, n_rate, n_big[2];
static mpd_context_t ctx_he, ctx_hu, ctx_x28, ctx_x200, ctx_p28, ctx_p200;
static mpd_t *q12, *q2, *res, *res2, *acc;

static char *read_all(const char *dir, const char *file, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, file);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "short read %s\n", path); exit(2); }
    buf[sz] = 0;
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

// Split into NUL-terminated lines (in place).
static char **lines_of(char *buf, size_t len, size_t *n) {
    size_t cnt = 0;
    for (size_t i = 0; i < len; i++) if (buf[i] == '\n') cnt++;
    char **v = malloc((cnt + 1) * sizeof *v);
    size_t k = 0;
    char *p = buf;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n') { buf[i] = 0; v[k++] = p; p = buf + i + 1; }
    *n = k;
    return v;
}

static mpd_t **parse_exact(char **s, size_t n) {
    mpd_t **v = malloc(n * sizeof *v);
    for (size_t i = 0; i < n; i++) {
        uint32_t st = 0;
        v[i] = mpd_qnew_size(24);
        mpd_qset_string_exact(v[i], s[i], &st);
        if (st) { fprintf(stderr, "operand %s: status %u\n", s[i], st); exit(2); }
    }
    return v;
}

static void setup(const char *dir) {
    mpd_init(&ctx_he, 38);
    ctx_he.round = MPD_ROUND_HALF_EVEN;
    ctx_hu = ctx_he;
    ctx_hu.round = MPD_ROUND_HALF_UP;
    mpd_init(&ctx_x28, 2 * 28 + 8); ctx_x28.round = MPD_ROUND_HALF_EVEN;
    mpd_init(&ctx_x200, 2 * 200 + 8); ctx_x200.round = MPD_ROUND_HALF_EVEN;
    mpd_init(&ctx_p28, 28); ctx_p28.round = MPD_ROUND_HALF_EVEN;
    mpd_init(&ctx_p200, 200); ctx_p200.round = MPD_ROUND_HALF_EVEN;
    uint32_t st = 0;
    q12 = mpd_qnew(); mpd_qset_string_exact(q12, "1E-12", &st);
    q2 = mpd_qnew(); mpd_qset_string_exact(q2, "1E-2", &st);
    res = mpd_qnew_size(64);
    res2 = mpd_qnew_size(64);
    acc = mpd_qnew_size(8);

    size_t len;
    char *b = read_all(dir, "money.txt", &len);
    money_s = lines_of(b, len, &n_money);
    b = read_all(dir, "rate.txt", &len);
    rate_s = lines_of(b, len, &n_rate);
    money = parse_exact(money_s, n_money);
    rate = parse_exact(rate_s, n_rate);
    b = read_all(dir, "big28.txt", &len);
    char **s28 = lines_of(b, len, &n_big[0]);
    big[0] = parse_exact(s28, n_big[0]);
    b = read_all(dir, "big200.txt", &len);
    char **s200 = lines_of(b, len, &n_big[1]);
    big[1] = parse_exact(s200, n_big[1]);

    // The quotients tostr_q12 formats: money[i] / money[i+1] at 12 places.
    quo = malloc(n_money * sizeof *quo);
    for (size_t i = 0; i < n_money; i++) {
        quo[i] = mpd_qnew_size(4);
        mpd_qdiv(res, money[i], money[(i + 1) % n_money], &ctx_he, &st);
        mpd_qquantize(quo[i], res, q12, &ctx_he, &st);
    }
}

// ── the operations; each returns the mpd_t holding result `i` ────────────────

#define NEXT(a, i, n) ((a)[((i) + 1) % (n)])

static inline __attribute__((always_inline)) mpd_t *op(int kind, size_t i) {
    uint32_t st = 0;
    switch (kind) {
    case PARSE_MONEY:
        mpd_qset_string(res, money_s[i], &ctx_he, &st);
        return res;
    case ADDSUB_CHAIN: // result i = the end of chain i (CHAIN_LEN steps)
        mpd_qset_i64(acc, 0, &ctx_he, &st);
        for (size_t j = 0; j < CHAIN_LEN; j++) {
            if (j & 1) mpd_qsub(acc, acc, money[i * CHAIN_LEN + j], &ctx_he, &st);
            else mpd_qadd(acc, acc, money[i * CHAIN_LEN + j], &ctx_he, &st);
        }
        return acc;
    case MUL12:
        mpd_qmul(res, rate[i], NEXT(rate, i, n_rate), &ctx_he, &st);
        mpd_qquantize(res2, res, q12, &ctx_hu, &st);
        return res2;
    case MUL2:
        mpd_qmul(res, money[i], rate[i], &ctx_he, &st);
        mpd_qquantize(res2, res, q2, &ctx_he, &st);
        return res2;
    case DIVROUND12:
        mpd_qdiv(res, money[i], NEXT(money, i, n_money), &ctx_he, &st);
        mpd_qquantize(res2, res, q12, &ctx_he, &st);
        return res2;
    case ADD28: mpd_qadd(res, big[0][i], NEXT(big[0], i, n_big[0]), &ctx_x28, &st); return res;
    case MUL28: mpd_qmul(res, big[0][i], NEXT(big[0], i, n_big[0]), &ctx_x28, &st); return res;
    case DIV28: mpd_qdiv(res, big[0][i], NEXT(big[0], i, n_big[0]), &ctx_p28, &st); return res;
    case SQRT28: mpd_qsqrt(res, big[0][i], &ctx_p28, &st); return res;
    case ADD200: mpd_qadd(res, big[1][i], NEXT(big[1], i, n_big[1]), &ctx_x200, &st); return res;
    case MUL200: mpd_qmul(res, big[1][i], NEXT(big[1], i, n_big[1]), &ctx_x200, &st); return res;
    case DIV200: mpd_qdiv(res, big[1][i], NEXT(big[1], i, n_big[1]), &ctx_p200, &st); return res;
    case SQRT200: mpd_qsqrt(res, big[1][i], &ctx_p200, &st); return res;
    }
    return res;
}

static inline uint64_t mix(const mpd_t *r) {
    return (uint64_t)r->data[0] ^ (uint64_t)r->exp ^ ((uint64_t)r->len << 40);
}

#define LOOP(K, N) case K: for (size_t i = 0; i < (N); i++) s += mix(op(K, i)); break;

static uint64_t run(const W *w) {
    uint64_t s = 0;
    switch (w->kind) {
    LOOP(PARSE_MONEY, w->n)
    LOOP(ADDSUB_CHAIN, w->n / CHAIN_LEN)
    LOOP(MUL12, w->n)
    LOOP(MUL2, w->n)
    LOOP(DIVROUND12, w->n)
    LOOP(ADD28, w->n) LOOP(MUL28, w->n) LOOP(DIV28, w->n) LOOP(SQRT28, w->n)
    LOOP(ADD200, w->n) LOOP(MUL200, w->n) LOOP(DIV200, w->n) LOOP(SQRT200, w->n)
    case TOSTR_MONEY:
        for (size_t i = 0; i < w->n; i++) {
            char *str = NULL;
            mpd_ssize_t l = mpd_to_sci_size(&str, money[i], 0);
            s += (uint64_t)l + (uint8_t)str[l - 1];
            mpd_free(str);
        }
        break;
    case TOSTR_Q12:
        for (size_t i = 0; i < w->n; i++) {
            char *str = NULL;
            mpd_ssize_t l = mpd_to_sci_size(&str, quo[i], 0);
            s += (uint64_t)l + (uint8_t)str[l - 1];
            mpd_free(str);
        }
        break;
    }
    return s;
}

// ── the untimed check: canonical text, hash, sample ──────────────────────────

static uint64_t fnv1a(const char *s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
    return h;
}

// Strip in place: trailing fractional zeros and a dangling dot; "-0" -> "0".
static size_t canon(char *s, size_t len) {
    if (memchr(s, '.', len)) {
        while (len > 0 && s[len - 1] == '0') len--;
        if (len > 0 && s[len - 1] == '.') len--;
    }
    if (len == 2 && s[0] == '-' && s[1] == '0') { s[0] = '0'; len = 1; }
    return len;
}

static uint64_t check(const W *w, FILE *sample) {
    uint64_t sum = 0;
    size_t nres = w->kind == ADDSUB_CHAIN ? w->n / CHAIN_LEN : w->n;
    uint32_t st = 0;
    for (size_t i = 0; i < nres; i++) {
        const mpd_t *r;
        switch (w->kind) {
        case TOSTR_MONEY: r = money[i]; break;
        case TOSTR_Q12: r = quo[i]; break;
        default: r = op(w->kind, i); break;
        }
        char *str = mpd_qformat(r, "f", &ctx_he, &st); // fixed notation, never an exponent
        if (!str) { fprintf(stderr, "format failed\n"); exit(2); }
        size_t l = canon(str, strlen(str));
        sum += fnv1a(str, l);
        if (sample && i < 1000) { fwrite(str, 1, l, sample); fputc('\n', sample); }
        mpd_free(str);
    }
    return sum;
}

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static double time_it(const W *w) {
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) g_sink += run(w);
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300;
    for (int r = 0; r < 5; r++) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) g_sink += run(w);
        double d = (now_ns() - t) / (double)n;
        if (d < best) best = d;
    }
    return best;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: mpdec_bench <dir> <workload|check>\n"); return 2; }
    setup(argv[1]);
    fprintf(stderr, "libmpdec %s (BSD-2, built -O2 -g from source), mpdec_bench driver\n", mpd_version());
    if (strcmp(argv[2], "check") == 0) {
        for (size_t k = 0; k < NW; k++) {
            char path[4096];
            snprintf(path, sizeof path, "%s/sample_mpd_%s.txt", argv[1], works[k].name);
            FILE *f = fopen(path, "wb");
            if (!f) { fprintf(stderr, "cannot write %s\n", path); return 2; }
            uint64_t h = check(&works[k], f);
            fclose(f);
            printf("count\t%s\t%llu\n", works[k].name, (unsigned long long)h);
        }
        return 0;
    }
    for (size_t k = 0; k < NW; k++) {
        if (strcmp(argv[2], works[k].name) != 0) continue;
        double ns = time_it(&works[k]);
        uint64_t h = check(&works[k], NULL);
        printf("%s\t%.3f\t%llu\n", works[k].name, ns, (unsigned long long)h);
        return 0;
    }
    fprintf(stderr, "unknown workload %s\n", argv[2]);
    return 2;
}
