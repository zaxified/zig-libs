// SPDX-License-Identifier: MIT
//! The 61 TA-Lib 0.8.3 candlestick-pattern functions (`CDL*`), ported from
//! `ta_CDL*.c` (BSD-3, see NOTICE). Output is `[]i32` per TA-Lib: 0 for no
//! pattern, +100 bullish / -100 bearish, with +-80 (ENGULFING, HARAMI,
//! HARAMICROSS: weaker form) and +-200 (HIKKAKE, HIKKAKEMOD: confirmed) where
//! the C writes them; the first `lookback` slots hold 0.
//!
//! TA-Lib's candle settings (what "long", "short", "near", ... mean) are a
//! process-global table there; here every call takes them in its params:
//! `.{ .settings = .{ .body_long = .{ .range = .real_body, .avg_period = 5,
//! .factor = 1.2 } } }` (`CandleSettings.default` is TA-Lib's table). The seven
//! functions with a penetration parameter (ABANDONEDBABY, DARKCLOUDCOVER,
//! EVENINGDOJISTAR, EVENINGSTAR, MATHOLD, MORNINGDOJISTAR, MORNINGSTAR) also
//! have `.penetration` (TA-Lib's default and range 0 .. 3e37).
//!
//! Per pattern `x`: `cdlx(T, open, high, low, close, out, params) !lookback`,
//! `cdlxLookback(params)`, `CdlxStream(T)` (`bufLen`, `init(params, buf)`,
//! `update(o, h, l, c)`, `peek`, `value`, `clone`) and `CdlxParams`.
//! All patterns share one engine (`candles_core.zig`): the same arithmetic runs in
//! batch and streaming, bit for bit.

const core = @import("candles_core.zig");
const A = @import("candles_a.zig");
const B = @import("candles_b.zig");

pub const RangeType = core.RangeType;
pub const Setting = core.Setting;
pub const SetId = core.SetId;
pub const CandleSettings = core.CandleSettings;
pub const Bar = core.Bar;
/// The generic surface of one pattern description (`all` holds them); used by tests and tools.
pub const Op = core.Op;

/// Every pattern's lowercase name (without `cdl`), alphabetical (for tests and tools).
pub const names = [_][]const u8{
    "2crows",
    "3blackcrows",
    "3inside",
    "3linestrike",
    "3outside",
    "3starsinsouth",
    "3whitesoldiers",
    "abandonedbaby",
    "advanceblock",
    "belthold",
    "breakaway",
    "closingmarubozu",
    "concealbabyswall",
    "counterattack",
    "darkcloudcover",
    "doji",
    "dojistar",
    "dragonflydoji",
    "engulfing",
    "eveningdojistar",
    "eveningstar",
    "gapsidesidewhite",
    "gravestonedoji",
    "hammer",
    "hangingman",
    "harami",
    "haramicross",
    "highwave",
    "hikkake",
    "hikkakemod",
    "homingpigeon",
    "identical3crows",
    "inneck",
    "invertedhammer",
    "kicking",
    "kickingbylength",
    "ladderbottom",
    "longleggeddoji",
    "longline",
    "marubozu",
    "matchinglow",
    "mathold",
    "morningdojistar",
    "morningstar",
    "onneck",
    "piercing",
    "rickshawman",
    "risefall3methods",
    "separatinglines",
    "shootingstar",
    "shortline",
    "spinningtop",
    "stalledpattern",
    "sticksandwich",
    "takuri",
    "tasukigap",
    "thrusting",
    "tristar",
    "unique3river",
    "upsidegap2crows",
    "xsidegap3methods",
};

/// The pattern descriptions in the order of `names` (tests and tools run every pattern through `core.Op`).
pub const all = .{
    A.Cdl2crows,
    A.Cdl3blackcrows,
    A.Cdl3inside,
    A.Cdl3linestrike,
    A.Cdl3outside,
    A.Cdl3starsinsouth,
    A.Cdl3whitesoldiers,
    A.Cdlabandonedbaby,
    A.Cdladvanceblock,
    A.Cdlbelthold,
    A.Cdlbreakaway,
    A.Cdlclosingmarubozu,
    A.Cdlconcealbabyswall,
    A.Cdlcounterattack,
    A.Cdldarkcloudcover,
    A.Cdldoji,
    A.Cdldojistar,
    A.Cdldragonflydoji,
    A.Cdlengulfing,
    A.Cdleveningdojistar,
    A.Cdleveningstar,
    A.Cdlgapsidesidewhite,
    A.Cdlgravestonedoji,
    A.Cdlhammer,
    A.Cdlhangingman,
    A.Cdlharami,
    A.Cdlharamicross,
    A.Cdlhighwave,
    A.Cdlhikkake,
    A.Cdlhikkakemod,
    A.Cdlhomingpigeon,
    A.Cdlidentical3crows,
    A.Cdlinneck,
    A.Cdlinvertedhammer,
    A.Cdlkicking,
    A.Cdlkickingbylength,
    A.Cdlladderbottom,
    A.Cdllongleggeddoji,
    A.Cdllongline,
    B.Cdlmarubozu,
    B.Cdlmatchinglow,
    B.Cdlmathold,
    B.Cdlmorningdojistar,
    B.Cdlmorningstar,
    B.Cdlonneck,
    B.Cdlpiercing,
    B.Cdlrickshawman,
    B.Cdlrisefall3methods,
    B.Cdlseparatinglines,
    B.Cdlshootingstar,
    B.Cdlshortline,
    B.Cdlspinningtop,
    B.Cdlstalledpattern,
    B.Cdlsticksandwich,
    B.Cdltakuri,
    B.Cdltasukigap,
    B.Cdlthrusting,
    B.Cdltristar,
    B.Cdlunique3river,
    B.Cdlupsidegap2crows,
    B.Cdlxsidegap3methods,
};

// 2CROWS
pub const Cdl2crowsParams = core.Op(A.Cdl2crows).Params;
pub const cdl2crows = core.Op(A.Cdl2crows).run;
pub const cdl2crowsLookback = core.Op(A.Cdl2crows).lookback;
pub const Cdl2crowsStream = core.Op(A.Cdl2crows).Stream;

// 3BLACKCROWS
pub const Cdl3blackcrowsParams = core.Op(A.Cdl3blackcrows).Params;
pub const cdl3blackcrows = core.Op(A.Cdl3blackcrows).run;
pub const cdl3blackcrowsLookback = core.Op(A.Cdl3blackcrows).lookback;
pub const Cdl3blackcrowsStream = core.Op(A.Cdl3blackcrows).Stream;

// 3INSIDE
pub const Cdl3insideParams = core.Op(A.Cdl3inside).Params;
pub const cdl3inside = core.Op(A.Cdl3inside).run;
pub const cdl3insideLookback = core.Op(A.Cdl3inside).lookback;
pub const Cdl3insideStream = core.Op(A.Cdl3inside).Stream;

// 3LINESTRIKE
pub const Cdl3linestrikeParams = core.Op(A.Cdl3linestrike).Params;
pub const cdl3linestrike = core.Op(A.Cdl3linestrike).run;
pub const cdl3linestrikeLookback = core.Op(A.Cdl3linestrike).lookback;
pub const Cdl3linestrikeStream = core.Op(A.Cdl3linestrike).Stream;

// 3OUTSIDE
pub const Cdl3outsideParams = core.Op(A.Cdl3outside).Params;
pub const cdl3outside = core.Op(A.Cdl3outside).run;
pub const cdl3outsideLookback = core.Op(A.Cdl3outside).lookback;
pub const Cdl3outsideStream = core.Op(A.Cdl3outside).Stream;

// 3STARSINSOUTH
pub const Cdl3starsinsouthParams = core.Op(A.Cdl3starsinsouth).Params;
pub const cdl3starsinsouth = core.Op(A.Cdl3starsinsouth).run;
pub const cdl3starsinsouthLookback = core.Op(A.Cdl3starsinsouth).lookback;
pub const Cdl3starsinsouthStream = core.Op(A.Cdl3starsinsouth).Stream;

// 3WHITESOLDIERS
pub const Cdl3whitesoldiersParams = core.Op(A.Cdl3whitesoldiers).Params;
pub const cdl3whitesoldiers = core.Op(A.Cdl3whitesoldiers).run;
pub const cdl3whitesoldiersLookback = core.Op(A.Cdl3whitesoldiers).lookback;
pub const Cdl3whitesoldiersStream = core.Op(A.Cdl3whitesoldiers).Stream;

// ABANDONEDBABY
pub const CdlabandonedbabyParams = core.Op(A.Cdlabandonedbaby).Params;
pub const cdlabandonedbaby = core.Op(A.Cdlabandonedbaby).run;
pub const cdlabandonedbabyLookback = core.Op(A.Cdlabandonedbaby).lookback;
pub const CdlabandonedbabyStream = core.Op(A.Cdlabandonedbaby).Stream;

// ADVANCEBLOCK
pub const CdladvanceblockParams = core.Op(A.Cdladvanceblock).Params;
pub const cdladvanceblock = core.Op(A.Cdladvanceblock).run;
pub const cdladvanceblockLookback = core.Op(A.Cdladvanceblock).lookback;
pub const CdladvanceblockStream = core.Op(A.Cdladvanceblock).Stream;

// BELTHOLD
pub const CdlbeltholdParams = core.Op(A.Cdlbelthold).Params;
pub const cdlbelthold = core.Op(A.Cdlbelthold).run;
pub const cdlbeltholdLookback = core.Op(A.Cdlbelthold).lookback;
pub const CdlbeltholdStream = core.Op(A.Cdlbelthold).Stream;

// BREAKAWAY
pub const CdlbreakawayParams = core.Op(A.Cdlbreakaway).Params;
pub const cdlbreakaway = core.Op(A.Cdlbreakaway).run;
pub const cdlbreakawayLookback = core.Op(A.Cdlbreakaway).lookback;
pub const CdlbreakawayStream = core.Op(A.Cdlbreakaway).Stream;

// CLOSINGMARUBOZU
pub const CdlclosingmarubozuParams = core.Op(A.Cdlclosingmarubozu).Params;
pub const cdlclosingmarubozu = core.Op(A.Cdlclosingmarubozu).run;
pub const cdlclosingmarubozuLookback = core.Op(A.Cdlclosingmarubozu).lookback;
pub const CdlclosingmarubozuStream = core.Op(A.Cdlclosingmarubozu).Stream;

// CONCEALBABYSWALL
pub const CdlconcealbabyswallParams = core.Op(A.Cdlconcealbabyswall).Params;
pub const cdlconcealbabyswall = core.Op(A.Cdlconcealbabyswall).run;
pub const cdlconcealbabyswallLookback = core.Op(A.Cdlconcealbabyswall).lookback;
pub const CdlconcealbabyswallStream = core.Op(A.Cdlconcealbabyswall).Stream;

// COUNTERATTACK
pub const CdlcounterattackParams = core.Op(A.Cdlcounterattack).Params;
pub const cdlcounterattack = core.Op(A.Cdlcounterattack).run;
pub const cdlcounterattackLookback = core.Op(A.Cdlcounterattack).lookback;
pub const CdlcounterattackStream = core.Op(A.Cdlcounterattack).Stream;

// DARKCLOUDCOVER
pub const CdldarkcloudcoverParams = core.Op(A.Cdldarkcloudcover).Params;
pub const cdldarkcloudcover = core.Op(A.Cdldarkcloudcover).run;
pub const cdldarkcloudcoverLookback = core.Op(A.Cdldarkcloudcover).lookback;
pub const CdldarkcloudcoverStream = core.Op(A.Cdldarkcloudcover).Stream;

// DOJI
pub const CdldojiParams = core.Op(A.Cdldoji).Params;
pub const cdldoji = core.Op(A.Cdldoji).run;
pub const cdldojiLookback = core.Op(A.Cdldoji).lookback;
pub const CdldojiStream = core.Op(A.Cdldoji).Stream;

// DOJISTAR
pub const CdldojistarParams = core.Op(A.Cdldojistar).Params;
pub const cdldojistar = core.Op(A.Cdldojistar).run;
pub const cdldojistarLookback = core.Op(A.Cdldojistar).lookback;
pub const CdldojistarStream = core.Op(A.Cdldojistar).Stream;

// DRAGONFLYDOJI
pub const CdldragonflydojiParams = core.Op(A.Cdldragonflydoji).Params;
pub const cdldragonflydoji = core.Op(A.Cdldragonflydoji).run;
pub const cdldragonflydojiLookback = core.Op(A.Cdldragonflydoji).lookback;
pub const CdldragonflydojiStream = core.Op(A.Cdldragonflydoji).Stream;

// ENGULFING
pub const CdlengulfingParams = core.Op(A.Cdlengulfing).Params;
pub const cdlengulfing = core.Op(A.Cdlengulfing).run;
pub const cdlengulfingLookback = core.Op(A.Cdlengulfing).lookback;
pub const CdlengulfingStream = core.Op(A.Cdlengulfing).Stream;

// EVENINGDOJISTAR
pub const CdleveningdojistarParams = core.Op(A.Cdleveningdojistar).Params;
pub const cdleveningdojistar = core.Op(A.Cdleveningdojistar).run;
pub const cdleveningdojistarLookback = core.Op(A.Cdleveningdojistar).lookback;
pub const CdleveningdojistarStream = core.Op(A.Cdleveningdojistar).Stream;

// EVENINGSTAR
pub const CdleveningstarParams = core.Op(A.Cdleveningstar).Params;
pub const cdleveningstar = core.Op(A.Cdleveningstar).run;
pub const cdleveningstarLookback = core.Op(A.Cdleveningstar).lookback;
pub const CdleveningstarStream = core.Op(A.Cdleveningstar).Stream;

// GAPSIDESIDEWHITE
pub const CdlgapsidesidewhiteParams = core.Op(A.Cdlgapsidesidewhite).Params;
pub const cdlgapsidesidewhite = core.Op(A.Cdlgapsidesidewhite).run;
pub const cdlgapsidesidewhiteLookback = core.Op(A.Cdlgapsidesidewhite).lookback;
pub const CdlgapsidesidewhiteStream = core.Op(A.Cdlgapsidesidewhite).Stream;

// GRAVESTONEDOJI
pub const CdlgravestonedojiParams = core.Op(A.Cdlgravestonedoji).Params;
pub const cdlgravestonedoji = core.Op(A.Cdlgravestonedoji).run;
pub const cdlgravestonedojiLookback = core.Op(A.Cdlgravestonedoji).lookback;
pub const CdlgravestonedojiStream = core.Op(A.Cdlgravestonedoji).Stream;

// HAMMER
pub const CdlhammerParams = core.Op(A.Cdlhammer).Params;
pub const cdlhammer = core.Op(A.Cdlhammer).run;
pub const cdlhammerLookback = core.Op(A.Cdlhammer).lookback;
pub const CdlhammerStream = core.Op(A.Cdlhammer).Stream;

// HANGINGMAN
pub const CdlhangingmanParams = core.Op(A.Cdlhangingman).Params;
pub const cdlhangingman = core.Op(A.Cdlhangingman).run;
pub const cdlhangingmanLookback = core.Op(A.Cdlhangingman).lookback;
pub const CdlhangingmanStream = core.Op(A.Cdlhangingman).Stream;

// HARAMI
pub const CdlharamiParams = core.Op(A.Cdlharami).Params;
pub const cdlharami = core.Op(A.Cdlharami).run;
pub const cdlharamiLookback = core.Op(A.Cdlharami).lookback;
pub const CdlharamiStream = core.Op(A.Cdlharami).Stream;

// HARAMICROSS
pub const CdlharamicrossParams = core.Op(A.Cdlharamicross).Params;
pub const cdlharamicross = core.Op(A.Cdlharamicross).run;
pub const cdlharamicrossLookback = core.Op(A.Cdlharamicross).lookback;
pub const CdlharamicrossStream = core.Op(A.Cdlharamicross).Stream;

// HIGHWAVE
pub const CdlhighwaveParams = core.Op(A.Cdlhighwave).Params;
pub const cdlhighwave = core.Op(A.Cdlhighwave).run;
pub const cdlhighwaveLookback = core.Op(A.Cdlhighwave).lookback;
pub const CdlhighwaveStream = core.Op(A.Cdlhighwave).Stream;

// HIKKAKE
pub const CdlhikkakeParams = core.Op(A.Cdlhikkake).Params;
pub const cdlhikkake = core.Op(A.Cdlhikkake).run;
pub const cdlhikkakeLookback = core.Op(A.Cdlhikkake).lookback;
pub const CdlhikkakeStream = core.Op(A.Cdlhikkake).Stream;

// HIKKAKEMOD
pub const CdlhikkakemodParams = core.Op(A.Cdlhikkakemod).Params;
pub const cdlhikkakemod = core.Op(A.Cdlhikkakemod).run;
pub const cdlhikkakemodLookback = core.Op(A.Cdlhikkakemod).lookback;
pub const CdlhikkakemodStream = core.Op(A.Cdlhikkakemod).Stream;

// HOMINGPIGEON
pub const CdlhomingpigeonParams = core.Op(A.Cdlhomingpigeon).Params;
pub const cdlhomingpigeon = core.Op(A.Cdlhomingpigeon).run;
pub const cdlhomingpigeonLookback = core.Op(A.Cdlhomingpigeon).lookback;
pub const CdlhomingpigeonStream = core.Op(A.Cdlhomingpigeon).Stream;

// IDENTICAL3CROWS
pub const Cdlidentical3crowsParams = core.Op(A.Cdlidentical3crows).Params;
pub const cdlidentical3crows = core.Op(A.Cdlidentical3crows).run;
pub const cdlidentical3crowsLookback = core.Op(A.Cdlidentical3crows).lookback;
pub const Cdlidentical3crowsStream = core.Op(A.Cdlidentical3crows).Stream;

// INNECK
pub const CdlinneckParams = core.Op(A.Cdlinneck).Params;
pub const cdlinneck = core.Op(A.Cdlinneck).run;
pub const cdlinneckLookback = core.Op(A.Cdlinneck).lookback;
pub const CdlinneckStream = core.Op(A.Cdlinneck).Stream;

// INVERTEDHAMMER
pub const CdlinvertedhammerParams = core.Op(A.Cdlinvertedhammer).Params;
pub const cdlinvertedhammer = core.Op(A.Cdlinvertedhammer).run;
pub const cdlinvertedhammerLookback = core.Op(A.Cdlinvertedhammer).lookback;
pub const CdlinvertedhammerStream = core.Op(A.Cdlinvertedhammer).Stream;

// KICKING
pub const CdlkickingParams = core.Op(A.Cdlkicking).Params;
pub const cdlkicking = core.Op(A.Cdlkicking).run;
pub const cdlkickingLookback = core.Op(A.Cdlkicking).lookback;
pub const CdlkickingStream = core.Op(A.Cdlkicking).Stream;

// KICKINGBYLENGTH
pub const CdlkickingbylengthParams = core.Op(A.Cdlkickingbylength).Params;
pub const cdlkickingbylength = core.Op(A.Cdlkickingbylength).run;
pub const cdlkickingbylengthLookback = core.Op(A.Cdlkickingbylength).lookback;
pub const CdlkickingbylengthStream = core.Op(A.Cdlkickingbylength).Stream;

// LADDERBOTTOM
pub const CdlladderbottomParams = core.Op(A.Cdlladderbottom).Params;
pub const cdlladderbottom = core.Op(A.Cdlladderbottom).run;
pub const cdlladderbottomLookback = core.Op(A.Cdlladderbottom).lookback;
pub const CdlladderbottomStream = core.Op(A.Cdlladderbottom).Stream;

// LONGLEGGEDDOJI
pub const CdllongleggeddojiParams = core.Op(A.Cdllongleggeddoji).Params;
pub const cdllongleggeddoji = core.Op(A.Cdllongleggeddoji).run;
pub const cdllongleggeddojiLookback = core.Op(A.Cdllongleggeddoji).lookback;
pub const CdllongleggeddojiStream = core.Op(A.Cdllongleggeddoji).Stream;

// LONGLINE
pub const CdllonglineParams = core.Op(A.Cdllongline).Params;
pub const cdllongline = core.Op(A.Cdllongline).run;
pub const cdllonglineLookback = core.Op(A.Cdllongline).lookback;
pub const CdllonglineStream = core.Op(A.Cdllongline).Stream;

// MARUBOZU
pub const CdlmarubozuParams = core.Op(B.Cdlmarubozu).Params;
pub const cdlmarubozu = core.Op(B.Cdlmarubozu).run;
pub const cdlmarubozuLookback = core.Op(B.Cdlmarubozu).lookback;
pub const CdlmarubozuStream = core.Op(B.Cdlmarubozu).Stream;

// MATCHINGLOW
pub const CdlmatchinglowParams = core.Op(B.Cdlmatchinglow).Params;
pub const cdlmatchinglow = core.Op(B.Cdlmatchinglow).run;
pub const cdlmatchinglowLookback = core.Op(B.Cdlmatchinglow).lookback;
pub const CdlmatchinglowStream = core.Op(B.Cdlmatchinglow).Stream;

// MATHOLD
pub const CdlmatholdParams = core.Op(B.Cdlmathold).Params;
pub const cdlmathold = core.Op(B.Cdlmathold).run;
pub const cdlmatholdLookback = core.Op(B.Cdlmathold).lookback;
pub const CdlmatholdStream = core.Op(B.Cdlmathold).Stream;

// MORNINGDOJISTAR
pub const CdlmorningdojistarParams = core.Op(B.Cdlmorningdojistar).Params;
pub const cdlmorningdojistar = core.Op(B.Cdlmorningdojistar).run;
pub const cdlmorningdojistarLookback = core.Op(B.Cdlmorningdojistar).lookback;
pub const CdlmorningdojistarStream = core.Op(B.Cdlmorningdojistar).Stream;

// MORNINGSTAR
pub const CdlmorningstarParams = core.Op(B.Cdlmorningstar).Params;
pub const cdlmorningstar = core.Op(B.Cdlmorningstar).run;
pub const cdlmorningstarLookback = core.Op(B.Cdlmorningstar).lookback;
pub const CdlmorningstarStream = core.Op(B.Cdlmorningstar).Stream;

// ONNECK
pub const CdlonneckParams = core.Op(B.Cdlonneck).Params;
pub const cdlonneck = core.Op(B.Cdlonneck).run;
pub const cdlonneckLookback = core.Op(B.Cdlonneck).lookback;
pub const CdlonneckStream = core.Op(B.Cdlonneck).Stream;

// PIERCING
pub const CdlpiercingParams = core.Op(B.Cdlpiercing).Params;
pub const cdlpiercing = core.Op(B.Cdlpiercing).run;
pub const cdlpiercingLookback = core.Op(B.Cdlpiercing).lookback;
pub const CdlpiercingStream = core.Op(B.Cdlpiercing).Stream;

// RICKSHAWMAN
pub const CdlrickshawmanParams = core.Op(B.Cdlrickshawman).Params;
pub const cdlrickshawman = core.Op(B.Cdlrickshawman).run;
pub const cdlrickshawmanLookback = core.Op(B.Cdlrickshawman).lookback;
pub const CdlrickshawmanStream = core.Op(B.Cdlrickshawman).Stream;

// RISEFALL3METHODS
pub const Cdlrisefall3methodsParams = core.Op(B.Cdlrisefall3methods).Params;
pub const cdlrisefall3methods = core.Op(B.Cdlrisefall3methods).run;
pub const cdlrisefall3methodsLookback = core.Op(B.Cdlrisefall3methods).lookback;
pub const Cdlrisefall3methodsStream = core.Op(B.Cdlrisefall3methods).Stream;

// SEPARATINGLINES
pub const CdlseparatinglinesParams = core.Op(B.Cdlseparatinglines).Params;
pub const cdlseparatinglines = core.Op(B.Cdlseparatinglines).run;
pub const cdlseparatinglinesLookback = core.Op(B.Cdlseparatinglines).lookback;
pub const CdlseparatinglinesStream = core.Op(B.Cdlseparatinglines).Stream;

// SHOOTINGSTAR
pub const CdlshootingstarParams = core.Op(B.Cdlshootingstar).Params;
pub const cdlshootingstar = core.Op(B.Cdlshootingstar).run;
pub const cdlshootingstarLookback = core.Op(B.Cdlshootingstar).lookback;
pub const CdlshootingstarStream = core.Op(B.Cdlshootingstar).Stream;

// SHORTLINE
pub const CdlshortlineParams = core.Op(B.Cdlshortline).Params;
pub const cdlshortline = core.Op(B.Cdlshortline).run;
pub const cdlshortlineLookback = core.Op(B.Cdlshortline).lookback;
pub const CdlshortlineStream = core.Op(B.Cdlshortline).Stream;

// SPINNINGTOP
pub const CdlspinningtopParams = core.Op(B.Cdlspinningtop).Params;
pub const cdlspinningtop = core.Op(B.Cdlspinningtop).run;
pub const cdlspinningtopLookback = core.Op(B.Cdlspinningtop).lookback;
pub const CdlspinningtopStream = core.Op(B.Cdlspinningtop).Stream;

// STALLEDPATTERN
pub const CdlstalledpatternParams = core.Op(B.Cdlstalledpattern).Params;
pub const cdlstalledpattern = core.Op(B.Cdlstalledpattern).run;
pub const cdlstalledpatternLookback = core.Op(B.Cdlstalledpattern).lookback;
pub const CdlstalledpatternStream = core.Op(B.Cdlstalledpattern).Stream;

// STICKSANDWICH
pub const CdlsticksandwichParams = core.Op(B.Cdlsticksandwich).Params;
pub const cdlsticksandwich = core.Op(B.Cdlsticksandwich).run;
pub const cdlsticksandwichLookback = core.Op(B.Cdlsticksandwich).lookback;
pub const CdlsticksandwichStream = core.Op(B.Cdlsticksandwich).Stream;

// TAKURI
pub const CdltakuriParams = core.Op(B.Cdltakuri).Params;
pub const cdltakuri = core.Op(B.Cdltakuri).run;
pub const cdltakuriLookback = core.Op(B.Cdltakuri).lookback;
pub const CdltakuriStream = core.Op(B.Cdltakuri).Stream;

// TASUKIGAP
pub const CdltasukigapParams = core.Op(B.Cdltasukigap).Params;
pub const cdltasukigap = core.Op(B.Cdltasukigap).run;
pub const cdltasukigapLookback = core.Op(B.Cdltasukigap).lookback;
pub const CdltasukigapStream = core.Op(B.Cdltasukigap).Stream;

// THRUSTING
pub const CdlthrustingParams = core.Op(B.Cdlthrusting).Params;
pub const cdlthrusting = core.Op(B.Cdlthrusting).run;
pub const cdlthrustingLookback = core.Op(B.Cdlthrusting).lookback;
pub const CdlthrustingStream = core.Op(B.Cdlthrusting).Stream;

// TRISTAR
pub const CdltristarParams = core.Op(B.Cdltristar).Params;
pub const cdltristar = core.Op(B.Cdltristar).run;
pub const cdltristarLookback = core.Op(B.Cdltristar).lookback;
pub const CdltristarStream = core.Op(B.Cdltristar).Stream;

// UNIQUE3RIVER
pub const Cdlunique3riverParams = core.Op(B.Cdlunique3river).Params;
pub const cdlunique3river = core.Op(B.Cdlunique3river).run;
pub const cdlunique3riverLookback = core.Op(B.Cdlunique3river).lookback;
pub const Cdlunique3riverStream = core.Op(B.Cdlunique3river).Stream;

// UPSIDEGAP2CROWS
pub const Cdlupsidegap2crowsParams = core.Op(B.Cdlupsidegap2crows).Params;
pub const cdlupsidegap2crows = core.Op(B.Cdlupsidegap2crows).run;
pub const cdlupsidegap2crowsLookback = core.Op(B.Cdlupsidegap2crows).lookback;
pub const Cdlupsidegap2crowsStream = core.Op(B.Cdlupsidegap2crows).Stream;

// XSIDEGAP3METHODS
pub const Cdlxsidegap3methodsParams = core.Op(B.Cdlxsidegap3methods).Params;
pub const cdlxsidegap3methods = core.Op(B.Cdlxsidegap3methods).run;
pub const cdlxsidegap3methodsLookback = core.Op(B.Cdlxsidegap3methods).lookback;
pub const Cdlxsidegap3methodsStream = core.Op(B.Cdlxsidegap3methods).Stream;
