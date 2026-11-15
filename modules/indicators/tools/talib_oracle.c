/* SPDX-License-Identifier: MIT
 *
 * C side of the indicators live oracle (`tools/interop.zig`): drives TA-Lib
 * 0.8.3's batch API (TA_<F> and the float-input TA_S_<F>) over records written
 * by the Zig side and writes back what TA-Lib answered. Built by interop.zig
 * with `zig cc -I<ta-lib include> talib_oracle.c <libta-lib.a> -lm`; it needs
 * only the static archive and headers, no TA-Lib build system.
 *
 *   talib_oracle --version
 *   talib_oracle <cases.bin> <results.bin>
 *
 * cases.bin   u32 count, then per record (little endian, packed):
 *               u8 func, u8 is_f32, u8 unstable_kind (0 bars, 1 auto4, 2 auto8), u8 0,
 *               u32 unstable_bars, u32 n, i32 ip[6], f64 dp[2],
 *               then NIN arrays of n values (f64, or f32 when is_f32)
 * results.bin per record: i32 ret, i32 lookback, i32 outBegIdx, i32 outNBElement,
 *               then NOUT arrays of outNBElement f64 each
 *
 * func ids: the order of the `F_*` enum below (the Zig side has the same table);
 * ip/dp carry the parameters in the order of the TA-Lib prototype (ints in ip,
 * doubles in dp, MA types as their TA_MAType number).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ta_libc.h>

enum { F_SMA, F_EMA, F_WMA, F_MA, F_MACD, F_MACDEXT, F_MACDFIX, F_RSI, F_BBANDS, F_TRANGE,
       F_ATR, F_NATR, F_STOCH, F_STOCHF, F_MAX, F_MIN, F_SUM, F_COUNT };

static int nin(int f) {
    return (f == F_TRANGE || f == F_ATR || f == F_NATR || f == F_STOCH || f == F_STOCHF) ? 3 : 1;
}
static int nout(int f) {
    switch (f) {
    case F_MACD: case F_MACDEXT: case F_MACDFIX: case F_BBANDS: return 3;
    case F_STOCH: case F_STOCHF: return 2;
    default: return 1;
    }
}

static int rd(FILE *fp, void *p, size_t n) { return fread(p, 1, n, fp) == n; }

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        printf("TA-Lib %s\n", TA_GetVersionString());
        return 0;
    }
    if (argc != 3) { fprintf(stderr, "usage: talib_oracle cases results\n"); return 2; }
    if (TA_Initialize() != TA_SUCCESS) { fprintf(stderr, "TA_Initialize failed\n"); return 2; }
    FILE *in = fopen(argv[1], "rb");
    FILE *out = fopen(argv[2], "wb");
    if (!in || !out) { fprintf(stderr, "cannot open files\n"); return 2; }
    uint32_t count;
    if (!rd(in, &count, 4)) return 2;
    for (uint32_t r = 0; r < count; r++) {
        uint8_t hdr[4];
        uint32_t ubars, n;
        int32_t ip[6];
        double dp[2];
        if (!rd(in, hdr, 4) || !rd(in, &ubars, 4) || !rd(in, &n, 4) || !rd(in, ip, sizeof ip) || !rd(in, dp, sizeof dp)) return 2;
        int f = hdr[0], is32 = hdr[1];
        if (f >= F_COUNT) return 2;
        int ni = nin(f), no = nout(f);
        size_t esz = is32 ? 4 : 8;
        void *ins[3] = {0, 0, 0};
        for (int i = 0; i < ni; i++) {
            ins[i] = malloc(n * esz + 8);
            if (!rd(in, ins[i], n * esz)) return 2;
        }
        double *outs[3];
        for (int i = 0; i < 3; i++) outs[i] = malloc(n * sizeof(double) + 8);
        unsigned int u = hdr[2] == 0 ? ubars : hdr[2] == 1 ? (unsigned)TA_UNSTABLE_AUTO_PREC_4 : (unsigned)TA_UNSTABLE_AUTO_PREC_8;
        TA_SetUnstablePeriod(TA_FUNC_UNST_ALL, u);

        const double *d0 = ins[0], *d1 = ins[1], *d2 = ins[2];
        const float *s0 = ins[0], *s1 = ins[1], *s2 = ins[2];
        int beg = 0, nb = 0, lb = -1, ret = 0, e = (int)n - 1;
#define R(a, b) ret = is32 ? (a) : (b); break
#define O1 &beg, &nb, outs[0]
#define O2 &beg, &nb, outs[0], outs[1]
#define O3 &beg, &nb, outs[0], outs[1], outs[2]
#define MT(i) ((TA_MAType)ip[i])
        switch (f) {
        case F_SMA: lb = TA_SMA_Lookback(ip[0]); R(TA_S_SMA(0, e, s0, ip[0], O1), TA_SMA(0, e, d0, ip[0], O1));
        case F_EMA: lb = TA_EMA_Lookback(ip[0]); R(TA_S_EMA(0, e, s0, ip[0], O1), TA_EMA(0, e, d0, ip[0], O1));
        case F_WMA: lb = TA_WMA_Lookback(ip[0]); R(TA_S_WMA(0, e, s0, ip[0], O1), TA_WMA(0, e, d0, ip[0], O1));
        case F_MA: lb = TA_MA_Lookback(ip[0], MT(1)); R(TA_S_MA(0, e, s0, ip[0], MT(1), O1), TA_MA(0, e, d0, ip[0], MT(1), O1));
        case F_MACD: lb = TA_MACD_Lookback(ip[0], ip[1], ip[2]);
            R(TA_S_MACD(0, e, s0, ip[0], ip[1], ip[2], O3), TA_MACD(0, e, d0, ip[0], ip[1], ip[2], O3));
        case F_MACDEXT: lb = TA_MACDEXT_Lookback(ip[0], MT(1), ip[2], MT(3), ip[4], MT(5));
            R(TA_S_MACDEXT(0, e, s0, ip[0], MT(1), ip[2], MT(3), ip[4], MT(5), O3), TA_MACDEXT(0, e, d0, ip[0], MT(1), ip[2], MT(3), ip[4], MT(5), O3));
        case F_MACDFIX: lb = TA_MACDFIX_Lookback(ip[0]); R(TA_S_MACDFIX(0, e, s0, ip[0], O3), TA_MACDFIX(0, e, d0, ip[0], O3));
        case F_RSI: lb = TA_RSI_Lookback(ip[0]); R(TA_S_RSI(0, e, s0, ip[0], O1), TA_RSI(0, e, d0, ip[0], O1));
        case F_BBANDS: lb = TA_BBANDS_Lookback(ip[0], dp[0], dp[1], MT(1));
            R(TA_S_BBANDS(0, e, s0, ip[0], dp[0], dp[1], MT(1), O3), TA_BBANDS(0, e, d0, ip[0], dp[0], dp[1], MT(1), O3));
        case F_TRANGE: lb = TA_TRANGE_Lookback(); R(TA_S_TRANGE(0, e, s0, s1, s2, O1), TA_TRANGE(0, e, d0, d1, d2, O1));
        case F_ATR: lb = TA_ATR_Lookback(ip[0]); R(TA_S_ATR(0, e, s0, s1, s2, ip[0], O1), TA_ATR(0, e, d0, d1, d2, ip[0], O1));
        case F_NATR: lb = TA_NATR_Lookback(ip[0]); R(TA_S_NATR(0, e, s0, s1, s2, ip[0], O1), TA_NATR(0, e, d0, d1, d2, ip[0], O1));
        case F_STOCH: lb = TA_STOCH_Lookback(ip[0], ip[1], MT(2), ip[3], MT(4));
            R(TA_S_STOCH(0, e, s0, s1, s2, ip[0], ip[1], MT(2), ip[3], MT(4), O2), TA_STOCH(0, e, d0, d1, d2, ip[0], ip[1], MT(2), ip[3], MT(4), O2));
        case F_STOCHF: lb = TA_STOCHF_Lookback(ip[0], ip[1], MT(2));
            R(TA_S_STOCHF(0, e, s0, s1, s2, ip[0], ip[1], MT(2), O2), TA_STOCHF(0, e, d0, d1, d2, ip[0], ip[1], MT(2), O2));
        case F_MAX: lb = TA_MAX_Lookback(ip[0]); R(TA_S_MAX(0, e, s0, ip[0], O1), TA_MAX(0, e, d0, ip[0], O1));
        case F_MIN: lb = TA_MIN_Lookback(ip[0]); R(TA_S_MIN(0, e, s0, ip[0], O1), TA_MIN(0, e, d0, ip[0], O1));
        case F_SUM: lb = TA_SUM_Lookback(ip[0]); R(TA_S_SUM(0, e, s0, ip[0], O1), TA_SUM(0, e, d0, ip[0], O1));
        default: break;
        }
        (void)d1; (void)d2; (void)s1; (void)s2;
        int32_t head[4] = { ret, lb, beg, nb };
        fwrite(head, 4, 4, out);
        if (ret == TA_SUCCESS) for (int i = 0; i < no; i++) fwrite(outs[i], 8, (size_t)nb, out);
        for (int i = 0; i < ni; i++) free(ins[i]);
        for (int i = 0; i < 3; i++) free(outs[i]);
    }
    fclose(out);
    fclose(in);
    TA_Shutdown();
    return 0;
}
