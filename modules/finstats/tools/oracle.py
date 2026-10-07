#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/testdata/oracle_vectors.zig`: reference values from foreign
implementations, over seeded synthetic inputs, replayed by
`src/oracle_test.zig`.

    V=~/.local/share/zig-libs/oracle-venvs/finstats
    python3 -m venv $V && $V/bin/pip install pyxirr scipy numpy pandas empyrical-reloaded
    $V/bin/python modules/finstats/tools/oracle.py | zig fmt --stdin > modules/finstats/src/testdata/oracle_vectors.zig

Every expected number comes from a library this module did not write, used as
a black box (none of their source is read or copied):

  - xirr / xirrPrecise  -- pyxirr `xirr` with `DayCount.ACT_365_25` (this
    module's day count), on the cash flows `opening` describes;
  - skewness / excessKurtosis -- `scipy.stats.skew` / `kurtosis` (population,
    `bias=True`, Fisher);
  - invNormCdf / normalPdf -- `scipy.stats.norm.ppf` / `pdf`;
  - gaussianVaR / gaussianCVaR -- `norm.ppf`, and the tail mean by numerical
    integration (`norm.expect(..., conditional=True)`), not the closed form;
  - quantile -- `numpy.quantile(method="linear")`;
  - riskMetrics ann_vol / downside / var95 / cvar95 / mdd -- empyrical-reloaded
    `annual_volatility`, `downside_risk`, `value_at_risk`,
    `conditional_value_at_risk`, `max_drawdown` (daily, 252 periods);
  - omegaRatio -- empyrical `omega_ratio(annualization=1)`;
  - betaAlpha beta / r2 -- `scipy.stats.linregress` slope and rvalue^2;
  - rollingMean / rollingVolatility -- pandas `rolling(w).mean()` / `.std()`;
  - correlationMatrix -- pandas `DataFrame.corr(min_periods=min_overlap)` over a
    wide frame (NaN where a key has no row on a date). The diagonal is NOT
    compared with pandas (this module defines it as 1 even for a constant or
    short series, pandas gives NaN there); the test asserts it is 1 itself;
  - drawdownEpisodes -- ffn `to_drawdown_series` + `drawdown_details`. ffn
    reports an episode's first underwater date (`Start`), its recovery date
    (`End`) and depth; it has no valley date and counts `Length` in rows. So the
    oracle takes: peak = the row before ffn's `Start`; recovery = ffn's `End`
    (open when ffn's last drawdown is below 0); depth = ffn's `drawdown` * 100;
    valley = the first row where ffn's own drawdown series equals that depth
    (a lookup in a foreign series, not a foreign answer). fall/recover days are
    calendar-day differences of those dates (plain date subtraction, SELF-grade
    arithmetic). Prices are rounded to a 0.25 grid so some recoveries land
    EXACTLY on the old peak (this module's `v >= peak` recovers on a tie);
  - riskMetrics ulcer -- ffn `to_ulcer_index` and quantstats `ulcer_index`,
    both given the series a caller of this module effectively has: the level
    starts at 1 BEFORE the first return (this module's peak is seeded with 1, so
    a first-day loss is a drawdown), i.e. a leading 0.0 return / a leading 1.0
    price. Two documented conventions are converted, in the open: this module
    is the sqrt of the MEAN of squared percent drawdowns over the n returns;
    ffn averages over the n+1 points (first drawdown is 0), so
    ours == ffn * sqrt((n+1)/n); quantstats divides by (points - 1) = n and
    reports a fraction, so ours == qs * 100. (Without the baseline point the
    foreign values differ from ours by ~5e-6 relative: ffn/qs measure drawdown
    from the FIRST return's level, the module from 1.);
  - tradeStats win_rate / payoff / profit_factor / kelly / tail_ratio --
    quantstats `win_rate`, `payoff_ratio`, `profit_factor`, `kelly_criterion`,
    `tail_ratio`, also over a series with 40 exact-zero returns (neither win nor
    loss);
  - benchmarkStats up/down capture -- empyrical `up_capture` / `down_capture`;
    treynor -- quantstats `treynor_ratio`, fed the way its numerator is defined:
    quantstats' numerator is the COMPOUNDED total return (`qs.stats.comp`),
    so that value is passed as `port_ann` (the module takes the numerator from
    the caller); the division by beta is what is compared;
  - riskMetrics sharpe / sortino / calmar -- PARTLY anchored. The module's
    numerator is CAGR over calendar days, level^(365.25/days) - 1 (NOT ffn's /
    quantstats' mean/std), which no library's sharpe computes. The oracle takes
    the numerator from ffn `calc_cagr` over a two-point price series
    [1, prod(1+r)] on the first and last row date (ffn's calendar-day CAGR), the
    denominators from empyrical `annual_volatility` / `downside_risk` /
    `max_drawdown`, and does the division (and `- rf`) itself. So CAGR and the
    denominators are foreign; the choice of numerator and the division stay SELF.

New inputs (the zero-return series, drawdown price series, correlation frame)
come from a SEPARATE generator seeded 20261007 and are emitted AFTER everything
else, so the values above are byte-identical to before.

The Cornish-Fisher pair is anchored on R PerformanceAnalytics by
tools/cf_oracle.R, over the series `--series-csv` prints (see that file).

Not here, because no foreign implementation was found to anchor them on:
twrDaily (Modified Dietz), brinsonAttribution.
"""
import datetime as dt
import sys

import empyrical as ep
import ffn
import numpy as np
import pandas as pd
import pyxirr
import quantstats as qs
from scipy import stats

rng = np.random.default_rng(20261006)
N = 250
WINDOW = 20


def series():
    t = rng.standard_t(4, N) * 0.008 + 0.0004
    crash = rng.normal(0.0006, 0.006, N)
    crash[rng.choice(N, 6, replace=False)] -= rng.uniform(0.03, 0.08, 6)  # negative skew
    calm = rng.normal(0.0002, 0.004, N)
    bench = rng.normal(0.0003, 0.009, N)
    port = 1.2 * bench + rng.normal(0.0001, 0.004, N)
    return {"fat_tails": t, "crashes": crash, "calm": calm, "bench": bench, "port": port}


def f(x):
    return repr(float(x))


def floats(xs):
    return "&.{" + ", ".join(f(x) for x in xs) + "}"


def zstr(xs):
    return "&.{" + ", ".join(f'"{x}"' for x in xs) + "}"


def opt(x):
    return "null" if x is None or (isinstance(x, float) and np.isnan(x)) else f(x)


def extra(o, S):
    """Everything added after the first anchors; emitted last (see docstring)."""
    g = np.random.default_rng(20261007)
    idx = pd.bdate_range("2020-01-01", periods=N)
    iso = [d.date().isoformat() for d in idx]
    names = list(S)
    o.append("")
    o.append(f"pub const dates = [_][]const u8{{ {', '.join(chr(34) + d + chr(34) for d in iso)} }};")

    # -- sharpe / sortino / calmar (ratios), ulcer ------------------------------
    o.append("pub const Ratios = struct { series: usize, rf: f64, cagr: f64, sharpe: f64, sortino: f64, calmar: f64,"
             " ulcer_ffn: f64, ulcer_qs_as_ours: f64 };")
    o.append("pub const ratios = [_]Ratios{")
    for k, name in enumerate(names):
        r = pd.Series(S[name], index=idx)
        level = float(np.prod(1 + S[name]))
        cagr = ffn.core.calc_cagr(pd.Series([1.0, level], index=[idx[0], idx[-1]]))
        vol, dsd, mdd = ep.annual_volatility(r), ep.downside_risk(r, required_return=0), ep.max_drawdown(r)
        bidx = pd.bdate_range("2019-12-31", periods=N + 1)  # baseline point: level 1, return 0
        r0 = pd.Series(np.concatenate([[0.0], S[name]]), index=bidx)
        u_ffn = ffn.core.to_ulcer_index((1 + r0).cumprod()) * np.sqrt((N + 1) / N)
        u_qs = qs.stats.ulcer_index(r0) * 100
        for rf in (0.0, 0.02):
            o.append(f"    .{{ .series = {k}, .rf = {f(rf)}, .cagr = {f(cagr)}, .sharpe = {f((cagr - rf) / vol)},"
                     f" .sortino = {f((cagr - rf) / dsd)}, .calmar = {f(cagr / abs(mdd))},"
                     f" .ulcer_ffn = {f(u_ffn)}, .ulcer_qs_as_ours = {f(u_qs)} }},")
    o.append("};")

    # -- trade statistics -------------------------------------------------------
    z = g.normal(0.0004, 0.006, N)
    z[g.choice(N, 40, replace=False)] = 0.0
    trade_in = [(n, S[n]) for n in names] + [("zeros", z)]
    o.append("")
    o.append("pub const Trade = struct { name: []const u8, values: []const f64, win_rate: f64, payoff: f64,"
             " profit_factor: f64, kelly: f64, tail_ratio: f64 };")
    o.append("pub const trades = [_]Trade{")
    for n, v in trade_in:
        r = pd.Series(v, index=idx)
        o.append(f'    .{{ .name = "{n}", .values = {floats(v)}, .win_rate = {f(qs.stats.win_rate(r))},'
                 f" .payoff = {f(qs.stats.payoff_ratio(r))}, .profit_factor = {f(qs.stats.profit_factor(r))},"
                 f" .kelly = {f(qs.stats.kelly_criterion(r))}, .tail_ratio = {f(qs.stats.tail_ratio(r))} }},")
    o.append("};")

    # -- benchmark capture / treynor --------------------------------------------
    o.append("")
    o.append("pub const Bench = struct { port: usize, rf: f64, port_ann: f64, treynor: f64, up: f64, down: f64 };")
    o.append("pub const bench = [_]Bench{")
    bn = pd.Series(S["bench"], index=idx)
    for pname in ("port", "crashes", "calm"):
        pt = pd.Series(S[pname], index=idx)
        for rf in (0.0, 0.02):
            o.append(f"    .{{ .port = {names.index(pname)}, .rf = {f(rf)}, .port_ann = {f(qs.stats.comp(pt))},"
                     f" .treynor = {f(qs.stats.treynor_ratio(pt, bn, periods=252, rf=rf))},"
                     f" .up = {f(ep.up_capture(pt, bn))}, .down = {f(ep.down_capture(pt, bn))} }},")
    o.append("};")

    # -- drawdown episodes ------------------------------------------------------
    def prices(mu, sd, n):
        p = 100 * np.cumprod(1 + g.normal(mu, sd, n))
        return np.round(p * 4) / 4

    cases = []
    p = prices(0.0002, 0.006, N)
    while ffn.core.to_drawdown_series(pd.Series(p, index=idx)).iloc[-1] == 0:
        p = prices(0.0002, 0.006, N)
    cases.append(("ends underwater", p))
    p = prices(0.0005, 0.005, N)
    while ffn.core.to_drawdown_series(pd.Series(p, index=idx)).iloc[-1] != 0:
        p = prices(0.0005, 0.005, N)
    cases.append(("ends at a high", p))
    cases.append(("crashes level", 100 * np.cumprod(1 + S["crashes"])))
    o.append("")
    o.append("pub const Ep = struct { peak: []const u8, trough: []const u8, recovery: ?[]const u8, depth_pct: f64,"
             " fall_days: i64, recover_days: ?i64 };")
    o.append("pub const DdCase = struct { label: []const u8, levels: []const f64, episodes: []const Ep };")
    o.append("pub const dd_cases = [_]DdCase{")
    for label, p in cases:
        ser = pd.Series(p, index=idx)
        ddn = ffn.core.to_drawdown_series(ser)
        det = ffn.core.drawdown_details(ddn)
        open_at_end = ddn.iloc[-1] < 0
        eps, ties = [], 0
        for k, row in enumerate(det.itertuples()):
            start, end, depth = pd.Timestamp(row.Start), pd.Timestamp(row.End), float(row.drawdown)
            peak = idx[idx.get_loc(start) - 1]
            is_open = open_at_end and k == len(det) - 1
            seg = ddn[start:end]
            valley = seg[seg == depth].index[0]
            if not is_open and ser[end] == ser[peak]:
                ties += 1
            rec = None if is_open else end
            eps.append((peak, valley, rec, depth * 100, (valley - peak).days, None if is_open else (end - valley).days))
        if label != "crashes level":
            assert ties > 0, label  # an exact-tie recovery is in the input
        assert (label == "ends underwater") == open_at_end or label == "crashes level"
        es = ", ".join(
            f'.{{ .peak = "{a.date()}", .trough = "{b.date()}", .recovery = {"null" if c is None else chr(34) + str(c.date()) + chr(34)},'
            f" .depth_pct = {f(d)}, .fall_days = {fd}, .recover_days = {'null' if rd is None else rd} }}"
            for a, b, c, d, fd, rd in eps
        )
        o.append(f'    .{{ .label = "{label}", .levels = {floats(p)}, .episodes = &.{{{es}}} }},')
    o.append("};")

    # -- correlation matrix -----------------------------------------------------
    MIN = 30
    sel = {
        "A": np.arange(N),
        "B": np.sort(g.choice(N, 200, replace=False)),
        "C": np.arange(0, 40),
        "D": np.arange(N - 30, N),
        "E": np.arange(N),
    }
    vals = {
        "A": S["port"],
        "B": 0.6 * S["bench"] + 0.4 * S["fat_tails"],
        "C": S["crashes"] + 0.5 * S["port"],
        "D": S["calm"] - 0.7 * S["port"],
        "E": np.full(N, 0.5),  # zero variance
    }
    wide = pd.DataFrame({k: pd.Series(vals[k][sel[k]], index=iso_i) for k, iso_i in
                         ((k, [iso[i] for i in sel[k]]) for k in sel)}).reindex(iso)
    cm = wide.corr(min_periods=MIN)
    keys = list(sel)
    o.append("")
    o.append("pub const CorrSeries = struct { key: []const u8, dates: []const []const u8, values: []const f64 };")
    o.append(f"pub const corr_min_overlap = {MIN};")
    o.append("pub const corr_series = [_]CorrSeries{")
    for k in keys:
        o.append(f'    .{{ .key = "{k}", .dates = {zstr([iso[i] for i in sel[k]])}, .values = {floats(vals[k][sel[k]])} }},')
    o.append("};")
    o.append("/// pandas DataFrame.corr(min_periods): null = NaN. Diagonal not compared.")
    rows = ", ".join("&[_]?f64{" + ", ".join(opt(cm.loc[a, b]) for b in keys) + "}" for a in keys)
    o.append(f"pub const corr_matrix = [_][]const ?f64{{ {rows} }};")


def main():
    S = series()
    o = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by modules/finstats/tools/oracle.py: reference values from pyxirr, scipy,",
        "// numpy, pandas and empyrical-reloaded over seeded inputs. Replayed by src/oracle_test.zig.",
        "// Do not edit by hand.",
        "",
        f"pub const window = {WINDOW};",
        "pub const Pair = struct { f64, f64 };",
        "pub const Gauss = struct { mean: f64, sd: f64, conf: f64, var_: f64, cvar: f64 };",
        "pub const Series = struct { name: []const u8, values: []const f64, skew: f64, kurt: f64, quantiles: []const Pair,"
        " ann_vol: f64, downside: f64, var95: f64, cvar95: f64, mdd: f64, omega: []const Pair, gauss: []const Gauss,"
        " roll_mean: []const f64, roll_std: []const f64 };",
        "",
        "pub const series = [_]Series{",
    ]
    for name, r in S.items():
        qs = [0.0, 0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99, 1.0]
        quant = ", ".join(f".{{ {q}, {f(np.quantile(r, q, method='linear'))} }}" for q in qs)
        om = ", ".join(f".{{ {t}, {f(ep.omega_ratio(r, required_return=t, annualization=1))} }}" for t in (0.0, 0.001, -0.002))
        g = []
        mu, sd = float(np.mean(r)), float(np.std(r, ddof=1))
        for c in (0.95, 0.99):
            q = stats.norm.ppf(1 - c, mu, sd)
            tail = stats.norm.expect(lambda x: x, loc=mu, scale=sd, ub=q, conditional=True)
            g.append(f".{{ .mean = {f(mu)}, .sd = {f(sd)}, .conf = {c}, .var_ = {f(-q)}, .cvar = {f(-tail)} }}")
        roll = pd.Series(r).rolling(WINDOW)
        o.append(
            f'    .{{ .name = "{name}", .values = {floats(r)}, .skew = {f(stats.skew(r, bias=True))},'
            f" .kurt = {f(stats.kurtosis(r, fisher=True, bias=True))}, .quantiles = &.{{{quant}}},"
            f" .ann_vol = {f(ep.annual_volatility(r))}, .downside = {f(ep.downside_risk(r, required_return=0))},"
            f" .var95 = {f(-ep.value_at_risk(r, cutoff=0.05))}, .cvar95 = {f(-ep.conditional_value_at_risk(r, cutoff=0.05))},"
            f" .mdd = {f(ep.max_drawdown(r))}, .omega = &.{{{om}}}, .gauss = &.{{{', '.join(g)}}},"
            f" .roll_mean = {floats(roll.mean().dropna())}, .roll_std = {floats(roll.std().dropna())} }},"
        )
    o.append("};")

    lr = stats.linregress(S["bench"], S["port"])
    o.append("")
    o.append(f"/// `port` regressed on `bench` (scipy.stats.linregress).")
    o.append(f"pub const beta = {f(lr.slope)};")
    o.append(f"pub const r2 = {f(lr.rvalue ** 2)};")

    ps = [1e-12, 1e-6, 0.001, 0.02, 0.02425, 0.05, 0.3, 0.5, 0.7, 0.95, 0.97575, 0.999, 1 - 1e-9]
    o.append("")
    o.append("/// p -> scipy.stats.norm.ppf(p)")
    o.append("pub const ppf = [_]Pair{" + ", ".join(f".{{ {p!r}, {f(stats.norm.ppf(p))} }}" for p in ps) + "};")
    zs = [-6.0, -2.5, -1.0, 0.0, 0.3, 1.6448536269514722, 4.0]
    o.append("/// z -> scipy.stats.norm.pdf(z)")
    o.append("pub const pdf = [_]Pair{" + ", ".join(f".{{ {z!r}, {f(stats.norm.pdf(z))} }}" for z in zs) + "};")

    # Cash-flow schedules: rows of (date, flow, value). `flow` is money put in
    # (+) or taken out (-); `value` the position after it.
    o.append("")
    o.append("pub const Row = struct { date: []const u8, flow: f64, value: f64 };")
    o.append("pub const Opening = enum { none, value_includes_flow };")
    o.append("pub const Schedule = struct { rows: []const Row, opening: Opening, xirr: f64 };")
    o.append("pub const schedules = [_]Schedule{")
    for k in range(10):
        start = dt.date(2019, 1, 1) + dt.timedelta(days=int(rng.integers(0, 900)))
        n = int(rng.integers(3, 14))
        days = sorted(rng.choice(np.arange(1, 365 * int(rng.integers(1, 6))), n - 1, replace=False))
        dates = [start] + [start + dt.timedelta(days=int(d)) for d in days]
        rate = float(rng.uniform(-0.35, 0.6))
        flows = [float(rng.uniform(1000, 50000))] + [float(rng.choice([0.0, rng.uniform(-3000, 8000)])) for _ in dates[1:]]
        # Values grow at `rate` between rows, noisily, plus the flow.
        values, v = [], 0.0
        for i, d in enumerate(dates):
            if i:
                v *= (1 + rate) ** ((d - dates[i - 1]).days / 365.25) * float(rng.uniform(0.97, 1.03))
            v += flows[i]
            values.append(v)
        opening = "none" if k % 3 else "value_includes_flow"
        if opening == "none":
            cf = [(d, -fl) for d, fl in zip(dates, flows) if abs(fl) > 1e-6]
        else:  # seed = -value[0] on day 0; row 0's flow is inside it
            cf = [(dates[0], -values[0])] + [(d, -fl) for d, fl in zip(dates[1:], flows[1:]) if abs(fl) > 1e-6]
        cf.append((dates[-1], values[-1]))
        x = pyxirr.xirr([c[0] for c in cf], [c[1] for c in cf], day_count=pyxirr.DayCount.ACT_365_25)
        rows = ", ".join(f'.{{ .date = "{d.isoformat()}", .flow = {f(fl)}, .value = {f(v)} }}' for d, fl, v in zip(dates, flows, values))
        o.append(f"    .{{ .rows = &.{{{rows}}}, .opening = .{opening}, .xirr = {f(x)} }},")
    o.append("};")
    extra(o, S)
    sys.stdout.write("\n".join(o) + "\n")


def dump_series():
    """`--series-csv`: the five seeded series (the RNG's first draws, so the
    same values `main` emits) as `name,value` lines, for tools/cf_oracle.R."""
    for name, r in series().items():
        for x in r:
            sys.stdout.write(f"{name},{float(x)!r}\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["--series-csv"]:
        dump_series()
    else:
        main()
