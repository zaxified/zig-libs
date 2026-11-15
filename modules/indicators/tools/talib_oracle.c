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
       F_SUPERTREND, F_SWAK_BUTTER, F_SWAK_GAUSS, F_VIDYA, F_VWMA, F_ZIGZAG, F_ZLEMA,
       /* volume / volatility / price transform / statistic / math operator waves */
       F_AD, F_ADOSC, F_CMF, F_EFI, F_EMV, F_KVO, F_MARKETFI, F_NVI, F_OBV, F_PVI, F_PVO, F_PVT, F_RVOL, F_VWAP,
       F_ADR, F_BBW, F_CVI, F_MASSI, F_PERCENTB, F_ROGERSSATCHELL, F_RVI, F_RVIR,
       F_AVGDEV, F_AVGPRICE, F_HA, F_MEDPRICE, F_TYPPRICE, F_WCLPRICE,
       F_BETA, F_CORREL, F_KURTOSIS, F_LINEARREG, F_LINEARREG_ANGLE, F_LINEARREG_INTERCEPT, F_LINEARREG_SLOPE,
       F_MEDIAN, F_PERCENTILE, F_PERCENTRANK, F_STDDEV, F_TSF, F_VAR,
       F_ADD, F_CUMSUM, F_DIV, F_MAXINDEX, F_MININDEX, F_MINMAX, F_MINMAXINDEX, F_MULT, F_SUB,
       F_COUNT };

static int nin(int f) {
    switch (f) {
    case F_TRANGE: case F_ATR: case F_NATR: case F_STOCH: case F_STOCHF:
    case F_ACCBANDS: case F_CKSP: case F_KC: case F_SUPERTREND: return 3;
    case F_MIDPRICE: case F_SAR: case F_SAREXT: case F_DONCHIAN: case F_FRAMA: case F_ICHIMOKU:
    case F_ZIGZAG: case F_MAVP: case F_VWMA: return 2;
    case F_AD: case F_ADOSC: case F_CMF: case F_KVO: case F_VWAP: return 4;
    case F_EMV: case F_MARKETFI: case F_TYPPRICE: case F_WCLPRICE: return 3;
    case F_EFI: case F_NVI: case F_OBV: case F_PVI: case F_PVT: return 2;
    case F_ADR: case F_CVI: case F_MASSI: case F_RVIR: case F_MEDPRICE: return 2;
    case F_ROGERSSATCHELL: case F_AVGPRICE: case F_HA: return 4;
    case F_BETA: case F_CORREL: case F_ADD: case F_SUB: case F_MULT: case F_DIV: return 2;
    default: return 1;
    }
}
static int nout(int f) {
    switch (f) {
    case F_MACD: case F_MACDEXT: case F_MACDFIX: case F_BBANDS:
    case F_ACCBANDS: case F_DONCHIAN: case F_KC: case F_ZIGZAG: return 3;
    case F_ICHIMOKU: return 4;
    case F_STOCH: case F_STOCHF: case F_CKSP: case F_SUPERTREND: case F_KVO: case F_MINMAX: case F_MINMAXINDEX: return 2;
    case F_HA: return 4;
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
        void *ins[5] = {0, 0, 0, 0, 0};
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

        const double *d0 = ins[0], *d1 = ins[1], *d2 = ins[2], *d3 = ins[3];
        const float *s0 = ins[0], *s1 = ins[1], *s2 = ins[2], *s3 = ins[3];
        int beg = 0, nb = 0, lb = -1, ret = 0, e = (int)n - 1;
#define R(a, b) ret = is32 ? (a) : (b); break
#define O1 &beg, &nb, outs[0]
#define O2 &beg, &nb, outs[0], outs[1]
#define O3 &beg, &nb, outs[0], outs[1], outs[2]
#define O4 &beg, &nb, outs[0], outs[1], outs[2], outs[3]
#define OI1 &beg, &nb, ib[0]
#define OI2 &beg, &nb, ib[0], ib[1]
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
        /* volume */
        case F_AD: lb = TA_AD_Lookback(); R(TA_S_AD(0, e, s0, s1, s2, s3, O1), TA_AD(0, e, d0, d1, d2, d3, O1));
        case F_ADOSC: lb = TA_ADOSC_Lookback(ip[0], ip[1]); R(TA_S_ADOSC(0, e, s0, s1, s2, s3, ip[0], ip[1], O1), TA_ADOSC(0, e, d0, d1, d2, d3, ip[0], ip[1], O1));
        case F_CMF: lb = TA_CMF_Lookback(ip[0]); R(TA_S_CMF(0, e, s0, s1, s2, s3, ip[0], O1), TA_CMF(0, e, d0, d1, d2, d3, ip[0], O1));
        case F_EFI: lb = TA_EFI_Lookback(ip[0]); R(TA_S_EFI(0, e, s0, s1, ip[0], O1), TA_EFI(0, e, d0, d1, ip[0], O1));
        case F_EMV: lb = TA_EMV_Lookback(ip[0], dp[0]); R(TA_S_EMV(0, e, s0, s1, s2, ip[0], dp[0], O1), TA_EMV(0, e, d0, d1, d2, ip[0], dp[0], O1));
        case F_KVO: lb = TA_KVO_Lookback(ip[0], ip[1], ip[2]);
            R(TA_S_KVO(0, e, s0, s1, s2, s3, ip[0], ip[1], ip[2], O2), TA_KVO(0, e, d0, d1, d2, d3, ip[0], ip[1], ip[2], O2));
        case F_MARKETFI: lb = TA_MARKETFI_Lookback(); R(TA_S_MARKETFI(0, e, s0, s1, s2, O1), TA_MARKETFI(0, e, d0, d1, d2, O1));
        case F_NVI: lb = TA_NVI_Lookback(); R(TA_S_NVI(0, e, s0, s1, O1), TA_NVI(0, e, d0, d1, O1));
        case F_OBV: lb = TA_OBV_Lookback(); R(TA_S_OBV(0, e, s0, s1, O1), TA_OBV(0, e, d0, d1, O1));
        case F_PVI: lb = TA_PVI_Lookback(); R(TA_S_PVI(0, e, s0, s1, O1), TA_PVI(0, e, d0, d1, O1));
        case F_PVO: lb = TA_PVO_Lookback(ip[0], ip[1], MT(2)); R(TA_S_PVO(0, e, s0, ip[0], ip[1], MT(2), O1), TA_PVO(0, e, d0, ip[0], ip[1], MT(2), O1));
        case F_PVT: lb = TA_PVT_Lookback(); R(TA_S_PVT(0, e, s0, s1, O1), TA_PVT(0, e, d0, d1, O1));
        case F_RVOL: lb = TA_RVOL_Lookback(ip[0]); R(TA_S_RVOL(0, e, s0, ip[0], O1), TA_RVOL(0, e, d0, ip[0], O1));
        case F_VWAP: lb = TA_VWAP_Lookback(); R(TA_S_VWAP(0, e, s0, s1, s2, s3, O1), TA_VWAP(0, e, d0, d1, d2, d3, O1));
        /* volatility */
        case F_ADR: lb = TA_ADR_Lookback(ip[0]); R(TA_S_ADR(0, e, s0, s1, ip[0], O1), TA_ADR(0, e, d0, d1, ip[0], O1));
        case F_BBW: lb = TA_BBW_Lookback(ip[0], dp[0], dp[1], MT(1)); R(TA_S_BBW(0, e, s0, ip[0], dp[0], dp[1], MT(1), O1), TA_BBW(0, e, d0, ip[0], dp[0], dp[1], MT(1), O1));
        case F_CVI: lb = TA_CVI_Lookback(ip[0], ip[1]); R(TA_S_CVI(0, e, s0, s1, ip[0], ip[1], O1), TA_CVI(0, e, d0, d1, ip[0], ip[1], O1));
        case F_MASSI: lb = TA_MASSI_Lookback(ip[0], ip[1]); R(TA_S_MASSI(0, e, s0, s1, ip[0], ip[1], O1), TA_MASSI(0, e, d0, d1, ip[0], ip[1], O1));
        case F_PERCENTB: lb = TA_PERCENTB_Lookback(ip[0], dp[0], dp[1], MT(1)); R(TA_S_PERCENTB(0, e, s0, ip[0], dp[0], dp[1], MT(1), O1), TA_PERCENTB(0, e, d0, ip[0], dp[0], dp[1], MT(1), O1));
        case F_ROGERSSATCHELL: lb = TA_ROGERSSATCHELL_Lookback(ip[0], dp[0]);
            R(TA_S_ROGERSSATCHELL(0, e, s0, s1, s2, s3, ip[0], dp[0], O1), TA_ROGERSSATCHELL(0, e, d0, d1, d2, d3, ip[0], dp[0], O1));
        case F_RVI: lb = TA_RVI_Lookback(ip[0], ip[1]); R(TA_S_RVI(0, e, s0, ip[0], ip[1], O1), TA_RVI(0, e, d0, ip[0], ip[1], O1));
        case F_RVIR: lb = TA_RVIR_Lookback(ip[0], ip[1]); R(TA_S_RVIR(0, e, s0, s1, ip[0], ip[1], O1), TA_RVIR(0, e, d0, d1, ip[0], ip[1], O1));
        /* price transform */
        case F_AVGDEV: lb = TA_AVGDEV_Lookback(ip[0]); R(TA_S_AVGDEV(0, e, s0, ip[0], O1), TA_AVGDEV(0, e, d0, ip[0], O1));
        case F_AVGPRICE: lb = TA_AVGPRICE_Lookback(); R(TA_S_AVGPRICE(0, e, s0, s1, s2, s3, O1), TA_AVGPRICE(0, e, d0, d1, d2, d3, O1));
        case F_HA: lb = TA_HA_Lookback(); R(TA_S_HA(0, e, s0, s1, s2, s3, O4), TA_HA(0, e, d0, d1, d2, d3, O4));
        case F_MEDPRICE: lb = TA_MEDPRICE_Lookback(); R(TA_S_MEDPRICE(0, e, s0, s1, O1), TA_MEDPRICE(0, e, d0, d1, O1));
        case F_TYPPRICE: lb = TA_TYPPRICE_Lookback(); R(TA_S_TYPPRICE(0, e, s0, s1, s2, O1), TA_TYPPRICE(0, e, d0, d1, d2, O1));
        case F_WCLPRICE: lb = TA_WCLPRICE_Lookback(); R(TA_S_WCLPRICE(0, e, s0, s1, s2, O1), TA_WCLPRICE(0, e, d0, d1, d2, O1));
        /* statistic */
        case F_BETA: lb = TA_BETA_Lookback(ip[0]); R(TA_S_BETA(0, e, s0, s1, ip[0], O1), TA_BETA(0, e, d0, d1, ip[0], O1));
        case F_CORREL: lb = TA_CORREL_Lookback(ip[0]); R(TA_S_CORREL(0, e, s0, s1, ip[0], O1), TA_CORREL(0, e, d0, d1, ip[0], O1));
        case F_KURTOSIS: lb = TA_KURTOSIS_Lookback(ip[0]); R(TA_S_KURTOSIS(0, e, s0, ip[0], O1), TA_KURTOSIS(0, e, d0, ip[0], O1));
        case F_LINEARREG: lb = TA_LINEARREG_Lookback(ip[0]); R(TA_S_LINEARREG(0, e, s0, ip[0], O1), TA_LINEARREG(0, e, d0, ip[0], O1));
        case F_LINEARREG_ANGLE: lb = TA_LINEARREG_ANGLE_Lookback(ip[0]); R(TA_S_LINEARREG_ANGLE(0, e, s0, ip[0], O1), TA_LINEARREG_ANGLE(0, e, d0, ip[0], O1));
        case F_LINEARREG_INTERCEPT: lb = TA_LINEARREG_INTERCEPT_Lookback(ip[0]); R(TA_S_LINEARREG_INTERCEPT(0, e, s0, ip[0], O1), TA_LINEARREG_INTERCEPT(0, e, d0, ip[0], O1));
        case F_LINEARREG_SLOPE: lb = TA_LINEARREG_SLOPE_Lookback(ip[0]); R(TA_S_LINEARREG_SLOPE(0, e, s0, ip[0], O1), TA_LINEARREG_SLOPE(0, e, d0, ip[0], O1));
        case F_MEDIAN: lb = TA_MEDIAN_Lookback(ip[0]); R(TA_S_MEDIAN(0, e, s0, ip[0], O1), TA_MEDIAN(0, e, d0, ip[0], O1));
        case F_PERCENTILE: lb = TA_PERCENTILE_Lookback(ip[0], dp[0]); R(TA_S_PERCENTILE(0, e, s0, ip[0], dp[0], O1), TA_PERCENTILE(0, e, d0, ip[0], dp[0], O1));
        case F_PERCENTRANK: lb = TA_PERCENTRANK_Lookback(ip[0]); R(TA_S_PERCENTRANK(0, e, s0, ip[0], O1), TA_PERCENTRANK(0, e, d0, ip[0], O1));
        case F_STDDEV: lb = TA_STDDEV_Lookback(ip[0], dp[0]); R(TA_S_STDDEV(0, e, s0, ip[0], dp[0], O1), TA_STDDEV(0, e, d0, ip[0], dp[0], O1));
        case F_TSF: lb = TA_TSF_Lookback(ip[0]); R(TA_S_TSF(0, e, s0, ip[0], O1), TA_TSF(0, e, d0, ip[0], O1));
        case F_VAR: lb = TA_VAR_Lookback(ip[0], dp[0]); R(TA_S_VAR(0, e, s0, ip[0], dp[0], O1), TA_VAR(0, e, d0, ip[0], dp[0], O1));
        /* math operators */
        case F_ADD: lb = TA_ADD_Lookback(); R(TA_S_ADD(0, e, s0, s1, O1), TA_ADD(0, e, d0, d1, O1));
        case F_SUB: lb = TA_SUB_Lookback(); R(TA_S_SUB(0, e, s0, s1, O1), TA_SUB(0, e, d0, d1, O1));
        case F_MULT: lb = TA_MULT_Lookback(); R(TA_S_MULT(0, e, s0, s1, O1), TA_MULT(0, e, d0, d1, O1));
        case F_DIV: lb = TA_DIV_Lookback(); R(TA_S_DIV(0, e, s0, s1, O1), TA_DIV(0, e, d0, d1, O1));
        case F_CUMSUM: lb = TA_CUMSUM_Lookback(); R(TA_S_CUMSUM(0, e, s0, O1), TA_CUMSUM(0, e, d0, O1));
        case F_MINMAX: lb = TA_MINMAX_Lookback(ip[0]); R(TA_S_MINMAX(0, e, s0, ip[0], O2), TA_MINMAX(0, e, d0, ip[0], O2));
        case F_MAXINDEX: lb = TA_MAXINDEX_Lookback(ip[0]); R(TA_S_MAXINDEX(0, e, s0, ip[0], OI1), TA_MAXINDEX(0, e, d0, ip[0], OI1));
        case F_MININDEX: lb = TA_MININDEX_Lookback(ip[0]); R(TA_S_MININDEX(0, e, s0, ip[0], OI1), TA_MININDEX(0, e, d0, ip[0], OI1));
        case F_MINMAXINDEX: lb = TA_MINMAXINDEX_Lookback(ip[0]);
            R(TA_S_MINMAXINDEX(0, e, s0, ip[0], OI2), TA_MINMAXINDEX(0, e, d0, ip[0], OI2));
        default: break;
        }
        (void)d1; (void)d2; (void)d3; (void)s1; (void)s2; (void)s3;
        /* integer outputs travel as doubles: SUPERTREND trend, ZIGZAG trend and pivot index */
        if (ret == TA_SUCCESS && f == F_SUPERTREND) for (int i = 0; i < nb; i++) outs[1][i] = ib[0][i];
        if (ret == TA_SUCCESS && f == F_ZIGZAG) for (int i = 0; i < nb; i++) { outs[1][i] = ib[0][i]; outs[2][i] = ib[1][i]; }
        if (ret == TA_SUCCESS && (f == F_MAXINDEX || f == F_MININDEX || f == F_MINMAXINDEX))
            for (int i = 0; i < no; i++) for (int j = 0; j < nb; j++) outs[i][j] = (double)ib[i][j];
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
