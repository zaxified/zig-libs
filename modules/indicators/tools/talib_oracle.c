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
 *               u32 unstable_bars, u32 n, i32 ip[6], f64 dp[8],
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
       F_ATR, F_NATR, F_STOCH, F_STOCHF, F_MAX, F_MIN, F_SUM,
       /* wave I3: overlap studies */
       F_DEMA, F_TEMA, F_T3, F_TRIMA, F_KAMA, F_MIDPOINT, F_MIDPRICE, F_SAR, F_SAREXT, F_MAVP,
       F_ACCBANDS, F_ALMA, F_CKSP, F_DONCHIAN, F_FRAMA, F_HMA, F_ICHIMOKU, F_KC, F_MCGD, F_RMA,
       F_SUPERTREND, F_SWAK_BUTTER, F_SWAK_GAUSS, F_VIDYA, F_VWMA, F_ZIGZAG, F_ZLEMA, F_COUNT };

static int nin(int f) {
    switch (f) {
    case F_TRANGE: case F_ATR: case F_NATR: case F_STOCH: case F_STOCHF:
    case F_ACCBANDS: case F_CKSP: case F_KC: case F_SUPERTREND: return 3;
    case F_MIDPRICE: case F_SAR: case F_SAREXT: case F_DONCHIAN: case F_FRAMA: case F_ICHIMOKU:
    case F_ZIGZAG: case F_MAVP: case F_VWMA: return 2;
    default: return 1;
    }
}
static int nout(int f) {
    switch (f) {
    case F_MACD: case F_MACDEXT: case F_MACDFIX: case F_BBANDS:
    case F_ACCBANDS: case F_DONCHIAN: case F_KC: case F_ZIGZAG: return 3;
    case F_ICHIMOKU: return 4;
    case F_STOCH: case F_STOCHF: case F_CKSP: case F_SUPERTREND: return 2;
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
        double dp[8];
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
        double *outs[4];
        for (int i = 0; i < 4; i++) outs[i] = malloc(n * sizeof(double) + 8);
        int *ib[2];
        for (int i = 0; i < 2; i++) ib[i] = malloc(n * sizeof(int) + 8);
        unsigned int u = hdr[2] == 0 ? ubars : hdr[2] == 1 ? (unsigned)TA_UNSTABLE_AUTO_PREC_4 : (unsigned)TA_UNSTABLE_AUTO_PREC_8;
        TA_SetUnstablePeriod(TA_FUNC_UNST_ALL, u);

        const double *d0 = ins[0], *d1 = ins[1], *d2 = ins[2];
        const float *s0 = ins[0], *s1 = ins[1], *s2 = ins[2];
        int beg = 0, nb = 0, lb = -1, ret = 0, e = (int)n - 1;
#define R(a, b) ret = is32 ? (a) : (b); break
#define O1 &beg, &nb, outs[0]
#define O2 &beg, &nb, outs[0], outs[1]
#define O3 &beg, &nb, outs[0], outs[1], outs[2]
#define O4 &beg, &nb, outs[0], outs[1], outs[2], outs[3]
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
        case F_DEMA: lb = TA_DEMA_Lookback(ip[0]); R(TA_S_DEMA(0, e, s0, ip[0], O1), TA_DEMA(0, e, d0, ip[0], O1));
        case F_TEMA: lb = TA_TEMA_Lookback(ip[0]); R(TA_S_TEMA(0, e, s0, ip[0], O1), TA_TEMA(0, e, d0, ip[0], O1));
        case F_T3: lb = TA_T3_Lookback(ip[0], dp[0]); R(TA_S_T3(0, e, s0, ip[0], dp[0], O1), TA_T3(0, e, d0, ip[0], dp[0], O1));
        case F_TRIMA: lb = TA_TRIMA_Lookback(ip[0]); R(TA_S_TRIMA(0, e, s0, ip[0], O1), TA_TRIMA(0, e, d0, ip[0], O1));
        case F_KAMA: lb = TA_KAMA_Lookback(ip[0]); R(TA_S_KAMA(0, e, s0, ip[0], O1), TA_KAMA(0, e, d0, ip[0], O1));
        case F_MIDPOINT: lb = TA_MIDPOINT_Lookback(ip[0]); R(TA_S_MIDPOINT(0, e, s0, ip[0], O1), TA_MIDPOINT(0, e, d0, ip[0], O1));
        case F_MIDPRICE: lb = TA_MIDPRICE_Lookback(ip[0]); R(TA_S_MIDPRICE(0, e, s0, s1, ip[0], O1), TA_MIDPRICE(0, e, d0, d1, ip[0], O1));
        case F_SAR: lb = TA_SAR_Lookback(dp[0], dp[1]); R(TA_S_SAR(0, e, s0, s1, dp[0], dp[1], O1), TA_SAR(0, e, d0, d1, dp[0], dp[1], O1));
        case F_SAREXT: lb = TA_SAREXT_Lookback(dp[0], dp[1], dp[2], dp[3], dp[4], dp[5], dp[6], dp[7]);
            R(TA_S_SAREXT(0, e, s0, s1, dp[0], dp[1], dp[2], dp[3], dp[4], dp[5], dp[6], dp[7], O1), TA_SAREXT(0, e, d0, d1, dp[0], dp[1], dp[2], dp[3], dp[4], dp[5], dp[6], dp[7], O1));
        case F_MAVP: lb = TA_MAVP_Lookback(ip[0], ip[1], MT(2));
            R(TA_S_MAVP(0, e, s0, s1, ip[0], ip[1], MT(2), O1), TA_MAVP(0, e, d0, d1, ip[0], ip[1], MT(2), O1));
        case F_ACCBANDS: lb = TA_ACCBANDS_Lookback(ip[0]); R(TA_S_ACCBANDS(0, e, s0, s1, s2, ip[0], O3), TA_ACCBANDS(0, e, d0, d1, d2, ip[0], O3));
        case F_ALMA: lb = TA_ALMA_Lookback(ip[0], dp[0], dp[1]); R(TA_S_ALMA(0, e, s0, ip[0], dp[0], dp[1], O1), TA_ALMA(0, e, d0, ip[0], dp[0], dp[1], O1));
        case F_CKSP: lb = TA_CKSP_Lookback(ip[0], dp[0], ip[1]); R(TA_S_CKSP(0, e, s0, s1, s2, ip[0], dp[0], ip[1], O2), TA_CKSP(0, e, d0, d1, d2, ip[0], dp[0], ip[1], O2));
        case F_DONCHIAN: lb = TA_DONCHIAN_Lookback(ip[0]); R(TA_S_DONCHIAN(0, e, s0, s1, ip[0], O3), TA_DONCHIAN(0, e, d0, d1, ip[0], O3));
        case F_FRAMA: lb = TA_FRAMA_Lookback(ip[0]); R(TA_S_FRAMA(0, e, s0, s1, ip[0], O1), TA_FRAMA(0, e, d0, d1, ip[0], O1));
        case F_HMA: lb = TA_HMA_Lookback(ip[0]); R(TA_S_HMA(0, e, s0, ip[0], O1), TA_HMA(0, e, d0, ip[0], O1));
        case F_ICHIMOKU: lb = TA_ICHIMOKU_Lookback(ip[0], ip[1], ip[2]); R(TA_S_ICHIMOKU(0, e, s0, s1, ip[0], ip[1], ip[2], O4), TA_ICHIMOKU(0, e, d0, d1, ip[0], ip[1], ip[2], O4));
        case F_KC: lb = TA_KC_Lookback(ip[0], ip[1], dp[0]); R(TA_S_KC(0, e, s0, s1, s2, ip[0], ip[1], dp[0], O3), TA_KC(0, e, d0, d1, d2, ip[0], ip[1], dp[0], O3));
        case F_MCGD: lb = TA_MCGD_Lookback(ip[0]); R(TA_S_MCGD(0, e, s0, ip[0], O1), TA_MCGD(0, e, d0, ip[0], O1));
        case F_RMA: lb = TA_RMA_Lookback(ip[0]); R(TA_S_RMA(0, e, s0, ip[0], O1), TA_RMA(0, e, d0, ip[0], O1));
        case F_SUPERTREND: lb = TA_SUPERTREND_Lookback(ip[0], dp[0]);
            R(TA_S_SUPERTREND(0, e, s0, s1, s2, ip[0], dp[0], O1, ib[0]), TA_SUPERTREND(0, e, d0, d1, d2, ip[0], dp[0], O1, ib[0]));
        case F_SWAK_BUTTER: lb = TA_SWAK_BUTTER_Lookback(ip[0]); R(TA_S_SWAK_BUTTER(0, e, s0, ip[0], O1), TA_SWAK_BUTTER(0, e, d0, ip[0], O1));
        case F_SWAK_GAUSS: lb = TA_SWAK_GAUSS_Lookback(ip[0]); R(TA_S_SWAK_GAUSS(0, e, s0, ip[0], O1), TA_SWAK_GAUSS(0, e, d0, ip[0], O1));
        case F_VIDYA: lb = TA_VIDYA_Lookback(ip[0], ip[1]); R(TA_S_VIDYA(0, e, s0, ip[0], ip[1], O1), TA_VIDYA(0, e, d0, ip[0], ip[1], O1));
        case F_VWMA: lb = TA_VWMA_Lookback(ip[0]); R(TA_S_VWMA(0, e, s0, s1, ip[0], O1), TA_VWMA(0, e, d0, d1, ip[0], O1));
        case F_ZIGZAG: lb = TA_ZIGZAG_Lookback(dp[0], ip[0]);
            R(TA_S_ZIGZAG(0, e, s0, s1, dp[0], ip[0], O1, ib[0], ib[1]), TA_ZIGZAG(0, e, d0, d1, dp[0], ip[0], O1, ib[0], ib[1]));
        case F_ZLEMA: lb = TA_ZLEMA_Lookback(ip[0]); R(TA_S_ZLEMA(0, e, s0, ip[0], O1), TA_ZLEMA(0, e, d0, ip[0], O1));
        default: break;
        }
        (void)d1; (void)d2; (void)s1; (void)s2;
        /* integer outputs travel as doubles: SUPERTREND trend, ZIGZAG trend and pivot index */
        if (ret == TA_SUCCESS && f == F_SUPERTREND) for (int i = 0; i < nb; i++) outs[1][i] = ib[0][i];
        if (ret == TA_SUCCESS && f == F_ZIGZAG) for (int i = 0; i < nb; i++) { outs[1][i] = ib[0][i]; outs[2][i] = ib[1][i]; }
        int32_t head[4] = { ret, lb, beg, nb };
        fwrite(head, 4, 4, out);
        if (ret == TA_SUCCESS) for (int i = 0; i < no; i++) fwrite(outs[i], 8, (size_t)nb, out);
        for (int i = 0; i < ni; i++) free(ins[i]);
        for (int i = 0; i < 4; i++) free(outs[i]);
        for (int i = 0; i < 2; i++) free(ib[i]);
    }
    fclose(out);
    fclose(in);
    TA_Shutdown();
    return 0;
}
