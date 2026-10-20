#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Frozen-vector generator for the decimal module's S2 operations.

Run (stdlib only, no network):

    python3 -I modules/decimal/tools/py_oracle.py > modules/decimal/src/testdata/s2_oracle.vec

Every expected value comes from Python's `decimal` module (the GDA reference
implementation, libmpdec) or, where `decimal` would round twice (powers), from
exact `fractions.Fraction` arithmetic cross-checked against `decimal` at huge
precision. The Zig tests (`src/s2_test.zig`) replay the file; Python is NOT
needed at test time. Seeded and deterministic: re-running reproduces the file
byte for byte on the same Python minor version (the header records it).

Line format: `op|arg|...|expected`, `#` lines are comments. Expected values
that are errors are `ERR:<name>`. Decimal results are plain strings parsed by
`Decimal.parse`; BigDecimal results are Python's `str(Decimal)` (GDA
to-scientific-string), compared by `toSci`, so the exponent is part of the check.
No negative zero is ever emitted (this module has none): a zero result loses
its sign here.
"""
import random
import sys
from decimal import (
    Context, Decimal, ROUND_05UP, ROUND_CEILING, ROUND_DOWN, ROUND_FLOOR,
    ROUND_HALF_DOWN, ROUND_HALF_EVEN, ROUND_HALF_UP, ROUND_UP,
    Inexact, Rounded, MAX_EMAX, MIN_EMIN, getcontext,
)
from fractions import Fraction

SEED = 20261020
# Operators such as unary minus / abs() round to the *thread* context (28 digits
# by default); every call below passes an explicit context, and this guards the rest.
getcontext().prec = 5000
MODES = {
    'half_even': ROUND_HALF_EVEN, 'half_up': ROUND_HALF_UP, 'half_down': ROUND_HALF_DOWN,
    'up': ROUND_UP, 'down': ROUND_DOWN, 'ceiling': ROUND_CEILING, 'floor': ROUND_FLOOR,
    'round_05up': ROUND_05UP,
}
MODE_NAMES = list(MODES)
I128_MIN, I128_MAX = -(1 << 127), (1 << 127) - 1
SF = 10 ** 12


def ctx(prec=3000, rounding=ROUND_HALF_EVEN):
    return Context(prec=prec, rounding=rounding, Emax=MAX_EMAX, Emin=MIN_EMIN, traps=[], flags=[])


def nz(d):
    """str() of a decimal with the sign of a zero dropped."""
    s = str(d)
    if d == 0 and s.startswith('-'):
        s = s[1:]
    return s


# ---- fixed-scale values (raw i128 at 1e-12) -------------------------------
def raw_str(raw):
    neg = raw < 0
    m = -raw if neg else raw
    ip, fp = divmod(m, SF)
    s = str(ip)
    if fp:
        s += '.' + str(fp).zfill(12).rstrip('0')
    return ('-' if neg else '') + s


def rnd_raw(rng):
    r = rng.random()
    if r < 0.08:
        return rng.choice([0, 1, -1, SF, -SF, SF // 2, 5 * SF // 10, 25 * SF // 10, 1005 * SF // 1000,
                           -25 * SF // 10, SF // 1000, 2 * SF, 3 * SF, -7 * SF, I128_MAX, I128_MIN,
                           I128_MAX - 1, I128_MIN + 1, 10 ** 26, -10 ** 26])
    bits = rng.choice([8, 16, 24, 40, 60, 80, 100, 127])
    v = rng.getrandbits(bits)
    k = rng.choice([0, 0, 1, 3, 6, 9, 10, 11, 12])
    v = (v // 10 ** k) * 10 ** k
    if rng.random() < 0.5:
        v = -v
    return max(I128_MIN, min(I128_MAX, v))


def small_raw(rng):
    """Values with few digits, so ties and exact quotients happen often."""
    ip = rng.randrange(0, 200)
    fd = rng.choice([0, 1, 2, 3, 4, 6])
    fp = rng.randrange(0, 10 ** fd) * 10 ** (12 - fd) if fd else 0
    v = ip * SF + fp
    return -v if rng.random() < 0.5 else v


def in_range(raw):
    return I128_MIN <= raw <= I128_MAX


def raw_of(d):
    """Exact raw of a Decimal that is a multiple of 1e-12 (else None)."""
    s = d.scaleb(12, context=ctx())
    if s != s.to_integral_value(context=ctx()):
        return None
    return int(s)


def res_dec(d):
    """Result string for a Decimal-typed op; ERR:Overflow past the i128 range."""
    r = raw_of(d)
    assert r is not None, d
    return 'ERR:Overflow' if not in_range(r) else raw_str(r)


# ---- arbitrary-precision values -------------------------------------------
def rnd_big(rng, small=False):
    r = rng.random()
    if r < 0.1:
        return rng.choice(['0', '0.0', '0.00', '0E+2', '0E-9', '1', '1.0', '1.00', '5', '0.5', '2.5', '-2.5',
                           '9.99', '99.5', '1E+3', '1E-7', '123456789E-4', '-0.001', '7E+1'])
    nd = rng.choice([1, 1, 2, 3, 4, 6, 10, 20, 40] if not small else [1, 2, 3, 4, 6])
    coeff = rng.randrange(0, 10 ** nd)
    if rng.random() < 0.3:
        coeff = int(str(coeff) + '0' * rng.randrange(1, 4))
    exp = rng.randrange(-12, 9) if small else rng.randrange(-30, 25)
    sign = 1 if (coeff == 0 or rng.random() < 0.5) else -1
    return str(Decimal((0 if sign > 0 else 1, tuple(int(c) for c in str(coeff)), exp)))


def pair_big(rng, small=False):
    a = rnd_big(rng, small)
    if rng.random() < 0.3:  # same value, different scale (comparetotal / min / max ties)
        d = Decimal(a)
        k = rng.randrange(1, 5)
        t = d.as_tuple()
        sign = t.sign
        digs = t.digits + (0,) * k
        b = str(Decimal((sign, digs, t.exponent - k)))
        if rng.random() < 0.3:
            b = str(Decimal(b).copy_negate()) if Decimal(b) != 0 else b
        return (a, b) if rng.random() < 0.5 else (b, a)
    return a, rnd_big(rng, small)


out = []


def emit(*fields):
    out.append('|'.join(str(f) for f in fields))


def gen():
    rng = random.Random(SEED)
    # ---- Decimal --------------------------------------------------------
    c = ctx(300)
    for _ in range(300):  # rem / divideInteger / remainderNear / mag
        a, b = (rnd_raw(rng), rnd_raw(rng)) if rng.random() < 0.5 else (small_raw(rng), small_raw(rng))
        A, B = Decimal(raw_str(a)), Decimal(raw_str(b))
        if b == 0:
            for op in ('d.rem', 'd.divint', 'd.remnear'):
                emit(op, raw_str(a), raw_str(b), 'ERR:DivisionByZero')
        else:
            emit('d.rem', raw_str(a), raw_str(b), res_dec(c.remainder(A, B)))
            q = c.divide_int(A, B)
            emit('d.divint', raw_str(a), raw_str(b), 'ERR:Overflow' if not in_range(int(q)) else int(q))
            emit('d.remnear', raw_str(a), raw_str(b), res_dec(c.remainder_near(A, B)))
        emit('d.maxmag', raw_str(a), raw_str(b), res_dec(c.max_mag(A, B)))
        emit('d.minmag', raw_str(a), raw_str(b), res_dec(c.min_mag(A, B)))
        emit('d.max', raw_str(a), raw_str(b), res_dec(c.max(A, B)))
        emit('d.min', raw_str(a), raw_str(b), res_dec(c.min(A, B)))
        emit('d.signum', raw_str(a), (a > 0) - (a < 0))
    for _ in range(40):  # equal magnitudes, opposite signs
        a = abs(small_raw(rng))
        A = Decimal(raw_str(a))
        emit('d.maxmag', raw_str(a), raw_str(-a), res_dec(c.max_mag(A, A.copy_negate())))
        emit('d.minmag', raw_str(-a), raw_str(a), res_dec(c.min_mag(A.copy_negate(), A)))

    for _ in range(500):  # roundToMultiple, all modes
        x = small_raw(rng) if rng.random() < 0.6 else rnd_raw(rng)
        m = small_raw(rng) if rng.random() < 0.7 else rnd_raw(rng)
        mode = rng.choice(MODE_NAMES)
        if m == 0:
            emit('d.mround', mode, raw_str(x), raw_str(m), 'ERR:DivisionByZero')
            continue
        X, M = Decimal(raw_str(x)), Decimal(raw_str(m)).copy_abs()
        cm = ctx(400)
        n = cm.divide(X, M).to_integral_value(rounding=MODES[mode], context=cm)
        emit('d.mround', mode, raw_str(x), raw_str(m), res_dec(cm.multiply(n, M)))

    def pow_exact(x_raw, n):
        f = Fraction(x_raw, SF) ** n
        v = f * SF
        num, den = v.numerator, v.denominator
        q, r = divmod(abs(num), den)
        if 2 * r > den or (2 * r == den and q % 2):
            q += 1
        return -q if num < 0 else q

    for _ in range(400):  # pow
        x = small_raw(rng) if rng.random() < 0.7 else rnd_raw(rng)
        if rng.random() < 0.4:
            x = rng.choice([1, -1, 2, -2, 3, 5, 10, 11, 15, 105, 1005, 11, 5, 25]) * SF // rng.choice([1, 1, 10, 100, 1000])
        n = rng.randrange(-60, 61) if rng.random() < 0.8 else rng.randrange(-300, 301)
        if x == 0 and n < 0:
            emit('d.pow', raw_str(x), n, 'ERR:DivisionByZero')
            continue
        if n == 0:
            emit('d.pow', raw_str(x), n, '1')
            continue
        r = pow_exact(x, n)
        if n > 0:  # second opinion: decimal at huge precision is exact here
            cp = ctx(20000)
            d = cp.power(Decimal(raw_str(x)), n)
            assert not cp.flags[Inexact]
            q = d.quantize(Decimal((0, (1,), -12)), rounding=ROUND_HALF_EVEN, context=ctx(20000))
            assert raw_of(q) == r, (x, n)
        emit('d.pow', raw_str(x), n, 'ERR:Overflow' if not in_range(r) else raw_str(r))

    cs = ctx(80)
    sq_cases = [rnd_raw(rng) for _ in range(200)] + [small_raw(rng) for _ in range(150)]
    sq_cases += [k * k * SF for k in range(0, 40)] + [k * SF for k in range(0, 40)]
    sq_cases += [I128_MAX, I128_MIN, 1, 2, 3, 625 * SF // 100, SF // 4, 1000000000000, 10 ** 24]
    for v in sq_cases:
        if v < 0:
            emit('d.sqrt', raw_str(v), 'ERR:NegativeOperand')
            continue
        s = cs.sqrt(Decimal(raw_str(v)))
        emit('d.sqrt', raw_str(v), res_dec(s.quantize(Decimal((0, (1,), -12)), rounding=ROUND_HALF_EVEN, context=ctx(80))))

    cq = ctx(80)
    for _ in range(900):  # rescale (all 8 modes) and toStringFixed
        x = small_raw(rng) if rng.random() < 0.5 else rnd_raw(rng)
        mode = rng.choice(MODE_NAMES)
        places = rng.randrange(-3, 16)
        q = Decimal(raw_str(x)).quantize(Decimal((0, (1,), -places)), rounding=MODES[mode], context=cq)
        if places <= 12:
            r = raw_of(q)
            emit('d.rescale', mode, raw_str(x), places, 'ERR:Overflow' if not in_range(r) else raw_str(r))
        if places >= 0:
            fs = format(q, 'f')
            emit('d.fixed', mode, raw_str(x), places, fs[1:] if (q == 0 and fs.startswith('-')) else fs)
    for mode in MODE_NAMES:  # ties at every place, both signs
        for t in ['0.5', '1.5', '2.5', '0.05', '0.15', '0.25', '1.005', '1.015', '0.001', '5.05', '10.5', '15.5']:
            for sgn in ('', '-'):
                d = Decimal(sgn + t)
                for places in (0, 1, 2, 3, 12):
                    q = d.quantize(Decimal((0, (1,), -places)), rounding=MODES[mode], context=cq)
                    r = raw_of(q)
                    emit('d.rescale', mode, sgn + t, places, raw_str(r))

    for _ in range(500):  # divRound at an explicit scale
        a = small_raw(rng) if rng.random() < 0.6 else rnd_raw(rng)
        b = small_raw(rng) if rng.random() < 0.6 else rnd_raw(rng)
        mode = rng.choice(MODE_NAMES)
        scale = rng.randrange(-3, 15)
        if b == 0:
            emit('d.divround', mode, raw_str(a), raw_str(b), scale, 'ERR:DivisionByZero')
            continue
        cd = ctx(400)
        qd = cd.divide(Decimal(raw_str(a)), Decimal(raw_str(b)))
        eff = min(scale, 12)
        q = qd.quantize(Decimal((0, (1,), -eff)), rounding=MODES[mode], context=cd)
        r = raw_of(q)
        emit('d.divround', mode, raw_str(a), raw_str(b), scale, 'ERR:Overflow' if not in_range(r) else raw_str(r))

    for _ in range(300):  # float bridge in the new mode too (exact binary value)
        mant = rng.randrange(1, 1 << 40)
        x = mant / (1 << rng.randrange(0, 40))
        if rng.random() < 0.5:
            x = round(x, rng.randrange(0, 6))
        x = -x if rng.random() < 0.5 else x
        mode = rng.choice(MODE_NAMES)
        places = rng.randrange(0, 13)
        q = Decimal(x).quantize(Decimal((0, (1,), -places)), rounding=MODES[mode], context=ctx(400))
        emit('d.fromfloat', mode, repr(x), places, raw_str(raw_of(q)))
        q = Decimal(repr(x)).quantize(Decimal((0, (1,), -places)), rounding=MODES[mode], context=ctx(400))
        emit('d.fromfloatshortest', mode, repr(x), places, raw_str(raw_of(q)))

    # ---- BigDecimal ------------------------------------------------------
    for _ in range(700):  # quantize / rescale, all modes
        x = rnd_big(rng)
        mode = rng.choice(MODE_NAMES)
        exp = rng.randrange(-25, 12)
        q = Decimal(x).quantize(Decimal((0, (1,), exp)), rounding=MODES[mode], context=ctx(5000))
        emit('b.quant', mode, x, exp, nz(q))
    for _ in range(500):  # div with an explicit scale
        a, b = pair_big(rng, small=True)
        mode = rng.choice(MODE_NAMES)
        scale = rng.randrange(-4, 26)
        if Decimal(b) == 0:
            emit('b.div', mode, a, b, scale, 'ERR:DivisionByZero')
            continue
        qd = ctx(3000).divide(Decimal(a), Decimal(b))
        q = qd.quantize(Decimal((0, (1,), -scale)), rounding=MODES[mode], context=ctx(3000))
        emit('b.div', mode, a, b, scale, nz(q))

    def flags_of(c):
        return int(bool(c.flags[Inexact])), int(bool(c.flags[Rounded]))

    for _ in range(900):  # roundToPrecision
        x = rnd_big(rng)
        mode = rng.choice(MODE_NAMES)
        prec = rng.choice([1, 1, 2, 3, 4, 5, 8, 12, 20, 50])
        cp = ctx(prec, MODES[mode])
        y = cp.plus(Decimal(x))
        emit('b.roundprec', mode, x, prec, nz(y), *flags_of(cp))
    for _ in range(900):  # divPrec
        a, b = pair_big(rng, small=True)
        mode = rng.choice(MODE_NAMES)
        prec = rng.choice([1, 2, 3, 5, 7, 12, 20, 34])
        if Decimal(b) == 0:
            emit('b.divprec', mode, a, b, prec, 'ERR:DivisionByZero', 0, 0)
            continue
        cp = ctx(prec, MODES[mode])
        y = cp.divide(Decimal(a), Decimal(b))
        emit('b.divprec', mode, a, b, prec, nz(y), *flags_of(cp))
    for a, b, prec in [('1', '3', 5), ('1', '4', 5), ('100', '10', 5), ('1000', '100', 2), ('2.40', '2', 5), ('2', '3', 1),
                       ('9.99', '1', 2), ('0', '5', 3), ('0', '0.5', 3), ('1', '7', 30), ('-1', '3', 4), ('1', '-3', 4), ('10', '3', 1)]:
        for mode in MODE_NAMES:
            cp = ctx(prec, MODES[mode])
            y = cp.divide(Decimal(a), Decimal(b))
            emit('b.divprec', mode, a, b, prec, nz(y), *flags_of(cp))

    c5 = ctx(500)
    for _ in range(400):
        a, b = pair_big(rng)
        if Decimal(b) == 0:
            emit('b.divint', a, b, 'ERR:DivisionByZero')
            emit('b.remnear', a, b, 'ERR:DivisionByZero')
        else:
            emit('b.divint', a, b, nz(c5.divide_int(Decimal(a), Decimal(b))))
            emit('b.remnear', a, b, nz(c5.remainder_near(Decimal(a), Decimal(b))))
    for _ in range(500):
        a, b = pair_big(rng)
        emit('b.cmptotal', a, b, int(Decimal(a).compare_total(Decimal(b))))
        emit('b.maxmag', a, b, nz(c5.max_mag(Decimal(a), Decimal(b))))
        emit('b.minmag', a, b, nz(c5.min_mag(Decimal(a), Decimal(b))))
    for _ in range(300):
        x = rnd_big(rng)
        emit('b.adjusted', x, Decimal(x).adjusted())
    for e in range(-12, 13):  # sci / eng at every exponent, several digit counts
        for coeff in ('0', '1', '12', '123', '1234', '12345', '100', '-7', '-123456'):
            x = str(Decimal((1 if coeff.startswith('-') else 0, tuple(int(ch) for ch in coeff.lstrip('-')), e)))
            emit('b.sci', x, nz(Decimal(x)))
            emit('b.eng', x, nz_eng(Decimal(x)))
    for _ in range(400):
        x = rnd_big(rng)
        emit('b.sci', x, nz(Decimal(x)))
        emit('b.eng', x, nz_eng(Decimal(x)))
    for _ in range(500):  # toStringFixed
        x = rnd_big(rng)
        mode = rng.choice(MODE_NAMES)
        places = rng.randrange(-3, 14)
        q = Decimal(x).quantize(Decimal((0, (1,), -places)), rounding=MODES[mode], context=ctx(5000))
        s = format(q, 'f')
        if q == 0 and s.startswith('-'):
            s = s[1:]
        emit('b.fixed', mode, x, places, s)

    gen_transcendental()


def gen_transcendental():
    """exp / ln / log10 / power, appended after every older case (own RNG, so the
    older lines stay byte-identical). Python's decimal is correctly rounded for
    these only under ROUND_HALF_EVEN (libmpdec rounds half-even whatever the
    context says), so the expected value for EVERY mode is the true value, taken
    at 250+ digits and rounded once in that mode; for half_even the direct
    Python call is also checked to agree. Flags: (inexact, rounded) as Python
    reports them for the rounded result."""
    rng = random.Random(SEED + 77)
    HI = 250

    def hi_ctx(prec):
        return ctx(max(HI, prec + 200))

    def tr_flags(c):
        return int(bool(c.flags[Inexact])), int(bool(c.flags[Rounded]))

    def oob(r, prec):
        """Result exponent outside i32 (this module's exponent type): typed Overflow."""
        return r.adjusted() >= 2 ** 31 - 2 or r.adjusted() - prec + 1 < -(2 ** 31)

    def one(op, fname, x, prec, mode, extra_args=()):
        """Expected 'value|inexact|rounded' for a unary transcendental op."""
        X = Decimal(x)
        direct = ctx(prec, ROUND_HALF_EVEN)
        py = getattr(direct, fname)(X)
        hi = getattr(hi_ctx(prec), fname)(X)
        cm = ctx(prec, MODES[mode])
        r = cm.plus(hi)
        fl = tr_flags(cm)
        assert not r.is_nan() and r.is_finite(), (fname, x, prec)
        if not (py == hi or fname == 'x'):
            pass
        if mode == 'half_even':
            assert str(py) == str(r) or py == r, (fname, x, prec, py, r)
            # exact-integer cases (log10 of 10^k) keep Python's own text and flags
            fl = tr_flags(direct)
            r = py
        # exp(0) / ln(1) are exact with flags clear in Python: plus() agrees.
        if oob(r, prec):
            return emit(op, mode, x, prec, 'ERR:Overflow', 0, 0)
        emit(op, mode, x, prec, nz(r), *fl)

    def rnd_arg(rng, positive):
        r = rng.random()
        if r < 0.2:
            pool = ['1', '2', '3', '10', '0.5', '0.1', '1.5', '7', '0.9', '1.1', '100', '0.01', '5', '1.0000001', '0.9999999',
                    '123456789', '2.718281828459045', '0.693147180559945', '1E+3', '1E-3', '9.99', '99.9']
            if not positive:
                pool += ['0', '0.00', '-1', '-0.5', '-10', '-100', '1E-30', '-1E-30', '1E-19', '-1E-19', '1E-18', '-1E-5', '-3', '-7.25']
            return rng.choice(pool)
        nd = rng.choice([1, 2, 3, 5, 8, 12, 20, 30])
        coeff = rng.randrange(1, 10 ** nd)
        adj = rng.randrange(-8, 4) if not positive else rng.randrange(-12, 12)
        e = adj - (len(str(coeff)) - 1)
        sign = 0 if (positive or rng.random() < 0.5) else 1
        return str(Decimal((sign, tuple(int(c) for c in str(coeff)), e)))

    precs = [1, 2, 5, 9, 9, 16, 16, 28, 28, 50]
    for _ in range(900):
        emit_prec = rng.choice(precs)
        one('b.exp', 'exp', rnd_arg(rng, False), emit_prec, rng.choice(MODE_NAMES))
    for x in ['0', '0.00', '0E+3', '1', '-1', '1E-30', '-1E-30', '1E-19', '-1E-19', '1E+3', '-1E+3', '1E+9', '-1E+9']:
        for mode in ('half_even', 'up', 'down', 'floor', 'ceiling'):
            one('b.exp', 'exp', x, 16, mode)
    for x, pr in [('1E+10', 9), ('-1E+10', 9), ('1E+11', 9), ('-5E+9', 5), ('5E+9', 5)]:
        emit('b.exp', 'half_even', x, pr, 'ERR:Overflow', 0, 0)  # result exponent beyond i32
    for x in ('3E+9', '-3E+9', '2E+9', '-2E+9'):  # huge but representable
        one('b.exp', 'exp', x, 9, 'half_even')
        one('b.exp', 'exp', x, 9, 'up')

    for _ in range(900):
        one('b.ln', 'ln', rnd_arg(rng, True), rng.choice(precs), rng.choice(MODE_NAMES))
    for _ in range(300):  # arguments close to 1: the result has few significant digits at fixed scale
        sc = rng.choice([8, 15, 25, 40])
        d = rng.randrange(1, 10 ** min(rng.choice([3, 6, 12]), sc - 1)) * (1 if rng.random() < 0.5 else -1)
        x = str(Decimal(1) + Decimal(d).scaleb(-sc, context=ctx(100)))
        one('b.ln', 'ln', x, rng.choice([5, 9, 16, 28]), rng.choice(MODE_NAMES))
    for x in ['1', '1.00', '1E+0', '1.000000000000000000000000000000']:
        for mode in ('half_even', 'up', 'floor'):
            one('b.ln', 'ln', x, 9, mode)
    for x in ['0', '0.00', '-1', '-1E-5', '-1E+5']:
        emit('b.ln', 'half_even', x, 9, 'ERR:NonPositiveOperand', 0, 0)
        emit('b.log10', 'half_even', x, 9, 'ERR:NonPositiveOperand', 0, 0)

    for _ in range(900):
        one('b.log10', 'log10', rnd_arg(rng, True), rng.choice(precs), rng.choice(MODE_NAMES))
    for k in list(range(-25, 26)) + [100, -100, 1000, -1000, 123456, 99999]:  # exact powers of ten
        for form in (0, 1):
            x = str(Decimal((0, (1,), k))) if form == 0 else ('1' + '0' * k if 0 <= k <= 6 else str(Decimal((0, (1,), k))))
            pr = rng.choice([1, 2, 5, 9, 16])
            one('b.log10', 'log10', x, pr, rng.choice(MODE_NAMES))
    for x in ['2', '20', '200', '0.2', '1.0001', '9.9999E+5']:
        for mode in MODE_NAMES:
            one('b.log10', 'log10', x, 7, mode)

    def power_case(base, ex, prec, mode):
        B, E = Decimal(base), Decimal(ex)
        cm = ctx(prec, MODES[mode])
        hc = hi_ctx(prec)
        if E == 0:
            if B == 0:
                return emit('b.power', mode, base, ex, prec, 'ERR:ZeroToZero', 0, 0)
            return emit('b.power', mode, base, ex, prec, '1', 0, 0)
        if B == 0:
            if E < 0:
                return emit('b.power', mode, base, ex, prec, 'ERR:DivisionByZero', 0, 0)
            return emit('b.power', mode, base, ex, prec, '0', 0, 0)
        is_int = E == E.to_integral_value(context=ctx(5000))
        if B < 0 and not is_int:
            return emit('b.power', mode, base, ex, prec, 'ERR:NegativeBase', 0, 0)
        if is_int and abs(E) <= 2000 and len(B.as_tuple().digits) * abs(int(E)) <= 20000:
            # exact power, one rounding (positive: plus(exact); negative: divide(1, exact))
            exact = ctx(60000).power(B, abs(int(E)))
            assert not ctx(60000).power(B, abs(int(E))) is None
            if E > 0:
                r = cm.plus(exact)
            else:
                r = cm.divide(Decimal(1), exact)
            if mode == 'half_even':
                d = ctx(prec).power(B, E)
                if str(d) != str(r):
                    sys.stderr.write('python power differs from exact-then-round: %s ** %s prec %d: %s vs %s\n' % (base, ex, prec, d, r))
            return emit('b.power', mode, base, ex, prec, nz(r), *tr_flags(cm))
        # real path: true value at high precision, rounded once; flags inexact+rounded
        if B.copy_abs() == 1 and is_int:  # +-1 to a huge integer: exactly +-1
            odd = int(E) % 2 != 0
            return emit('b.power', mode, base, ex, prec, '-1' if (B < 0 and odd) else '1', 0, 0)
        hi = hc.power(B, E)
        r = cm.plus(hi)
        if B.copy_abs() == 1 and not is_int:
            r = Decimal((0, (1,) + (0,) * (prec - 1), -(prec - 1)))
        if mode == 'half_even':
            d = ctx(prec).power(B, E)
            if str(d) != str(r):
                sys.stderr.write('python power differs from correctly rounded: %s ** %s prec %d: %s vs %s\n' % (base, ex, prec, d, r))
        if oob(r, prec):
            return emit('b.power', mode, base, ex, prec, 'ERR:Overflow', 0, 0)
        emit('b.power', mode, base, ex, prec, nz(r), 1, 1)

    exps_frac = ['0.5', '1.5', '-0.5', '2.5', '0.25', '-1.5', '0.1', '0.3333333333', '1.0000001', '-2.75', '0.75', '3.14159', '1E-5', '-1E-5', '0.0001', '12.5', '0.2']
    for _ in range(900):
        r = rng.random()
        base = rnd_arg(rng, True) if rng.random() < 0.9 else rng.choice(['1', '1.000', '10', '100', '0.1'])
        if r < 0.55:
            ex = rng.choice(exps_frac) if rng.random() < 0.5 else str(Decimal((rng.randrange(2), tuple(int(c) for c in str(rng.randrange(1, 10 ** rng.choice([1, 2, 3, 6, 10])))), -rng.randrange(1, 8))))
        elif r < 0.85:
            ex = str(rng.randrange(-30, 31)) if rng.random() < 0.8 else rng.choice(['2.0', '3.00', '1E+1', '-1E+1', '4E+0', '-2.0'])
            if rng.random() < 0.3:
                base = str(Decimal(base).copy_negate())
        else:
            ex = rng.choice(['0.5', '-0.5', '1.5', '0.25', '2.5', '-0.75'])
            base = rng.choice(['4', '9', '0.25', '6.25', '2.25', '100', '1E+10', '16', '0.04', '1.21', '1E-6', '8', '0.125', '1.44', '10000', '81', '256', '0.0625'])
        power_case(base, ex, rng.choice(precs), rng.choice(MODE_NAMES))
    # exact results of a fractional exponent: every mode, and a tie at the last digit
    for base, ex in [('4', '0.5'), ('6.25', '0.5'), ('2.25', '0.5'), ('0.25', '-0.5'), ('100', '1.5'), ('16', '0.25'),
                     ('32', '0.2'), ('8', '0.3333333333'), ('2.5', '2'), ('1.5625', '0.5'), ('0.0625', '0.5'), ('1', '0.5'), ('1.000', '2.5'),
                     ('1E+10', '0.5'), ('1E-10', '0.5'), ('12.25', '0.5'), ('110.25', '0.5'), ('1.0000001', '0.5'), ('100', '-1.5')]:
        for pr in (1, 2, 3, 5, 9):
            for mode in MODE_NAMES:
                power_case(base, ex, pr, mode)
    for base, ex in [('0', '0'), ('0', '0.00'), ('5', '0'), ('5', '0.0'), ('0', '3'), ('0', '0.5'), ('0.00', '2'), ('0', '-1'), ('0', '-0.5'),
                     ('-8', '0.5'), ('-8', '0.3333'), ('-2', '3'), ('-2', '-3'), ('-2', '4'), ('-1', '0.5'), ('-0.5', '2.0'), ('-1.5', '-3')]:
        power_case(base, ex, 9, 'half_even')
    # integer exponents past the exact path's budget fall back to exp(y ln x)
    for base, ex, pr in [('1.1', '1000000007', 9), ('1.0000001', '5E+8', 12), ('0.999', '-123456', 9), ('-1.01', '3000001', 9), ('-1.01', '3000000', 9),
                         ('2', '1000', 16), ('-1', '1000001', 5), ('1', '1000000007', 5), ('3', '-100000', 9)]:
        for mode in ('half_even', 'up', 'floor'):
            power_case(base, ex, pr, mode)
    # large precision
    for pr in (100, 200, 500, 1000, 2000):
        one('b.exp', 'exp', '1.5', pr, 'half_even')
        one('b.ln', 'ln', '7', pr, 'half_up')
        one('b.log10', 'log10', '3.25', pr, 'floor')
        power_case('2', '0.5', pr, 'half_even')
    emit('b.exp', 'half_even', '1', 2001, 'ERR:PrecisionTooLarge', 0, 0)
    emit('b.ln', 'half_even', '2', 2001, 'ERR:PrecisionTooLarge', 0, 0)
    emit('b.log10', 'half_even', '2', 2001, 'ERR:PrecisionTooLarge', 0, 0)
    emit('b.power', 'half_even', '2', '0.5', 2001, 'ERR:PrecisionTooLarge', 0, 0)
    emit('b.exp', 'half_even', '1', 0, 'ERR:InvalidPrecision', 0, 0)
    emit('b.ln', 'half_even', '2', 0, 'ERR:InvalidPrecision', 0, 0)


def nz_eng(d):
    s = d.to_eng_string()
    if d == 0 and s.startswith('-'):
        s = s[1:]
    return s


def main():
    gen()
    print('# S2 oracle vectors for the decimal module (generated; do not edit).')
    print('# Generator: tools/py_oracle.py, seed %d, Python %d.%d, decimal module (libmpdec).' % ((SEED,) + sys.version_info[:2]))
    print('# Each expected value is computed by Python `decimal` (or exact Fractions for powers); see the script.')
    print('# Lines: op|args...|expected   (ERR:<name> = typed error; flags are 1/0 inexact,rounded)')
    for line in out:
        print(line)


if __name__ == '__main__':
    main()
