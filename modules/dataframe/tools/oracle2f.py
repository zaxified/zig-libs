#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Black-box oracle for the Unicode text functions of dataframe S2 wave W8: pandas 3.1 and
polars 2.1 over strings with non-ASCII text, frozen into src/oracle2f_vectors.json and replayed
by src/s2w8_oracle_test.zig. No line of dataframe is consulted here: the expected values are
what the engines answer.

    python tools/oracle2f.py src/oracle2f_vectors.json      (see tools/README.md)

pandas 3 stores a `str` column in Arrow by default, and Arrow's `utf8_upper` is the SIMPLE
case mapping (`ß` stays, no final sigma); the Python `str` methods the pandas documentation
points at are used here (`StringDtype("python")`), and the Arrow answer is reported on stderr
where it differs. A case the engine raises on is reported and left out. Where pandas and
polars both have a function and disagree, both answers are written (`-pd`, `-pl`) and the
replay's `known` list says which one dataframe follows.
"""
import json
import math
import sys
import unicodedata

import numpy as np
import pandas as pd
import polars as pl
import polars.selectors as cs

cases = []
problems = []
notes = []


def case(id, kind, engine, expect, **kw):
    cases.append({"id": id, "kind": kind, "engine": engine, "expect": expect, **kw})


def run(id, fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{id}: {type(e).__name__}: {str(e)[:160]}")


def cell(v):
    if v is None or v is pd.NA:
        return None
    if isinstance(v, (bool, np.bool_)):
        return bool(v)
    if isinstance(v, (int, np.integer)):
        return int(v)
    if isinstance(v, float) and math.isnan(v):
        return None
    return str(v)


def cells(xs):
    return [cell(x) for x in xs]


PY = pd.StringDtype("python", na_value=pd.NA)


def pser(xs):
    return pd.Series(xs, dtype=PY)


def aser(xs):
    return pd.Series(xs, dtype="str")


TEXTS = [
    "Hello World", "hello", "WORLD", "", None, "Ünïcödé", "straße", "STRASSE", "ΣΑΣ", "ὈΔΥΣΣΕΎΣ",
    "İstanbul", "ǆungla", "ﬁne ﬂow", "ŉ", "ǰ", "Ǆ", "ŁÓDŹ", "Žluťoučký kůň", "ÀÉÎÕÜ àéîõü",
    "they're 3rd", "mIxEd CaSe", "ａｂｃ ＡＢＣ １２３", "٣٤٥", "²³", "½", "Ⅻ", "१२३", "日本語",
    "한글", "Ωmega", "ǅ", "ῼ", "é", "é", "x²", "a b", " ", "　", " \t\n",
    "ς", "Σ", "AΣ", "Aς.", "ǈudi", "ÁB́", "Ǳǲǳ", "Ǆ ǅ ǆ", "σίσυφος", "ΧΑΟΣ ΧΑΟΣ.", "ñandú", "øre", "æble",
    "ß ß", "ⅷ", "①②", "Ａ１", "abc123", "ABC", "abc", "Abc Def", "ABC DEF", "Abc def", "1a", "a1",
    "ÉCOLE", "école", "École Normale", "x​y", "٠١", "ʰ", "ª", "Ǆa", "ǅA",
    "'quoted' text", "hello-world", "o'neil", "ÿ", "Ÿ", "ĳ", "Ĳ", "Ა", "ᲀ", "ꭰ", "Ა",
]


def pd_pair(name, f):
    """Python-storage answer; note where the Arrow-backed default differs."""
    r = f(pser(TEXTS))
    try:
        r2 = f(aser(TEXTS))
        diff = [(t, cell(a), cell(b)) for t, a, b in zip(TEXTS, r, r2) if cell(a) != cell(b)]
        if diff:
            notes.append(f"{name}: Arrow-backed pandas differs from Python str on {len(diff)} cells, e.g. {diff[:2]}")
    except Exception as e:  # noqa: BLE001
        notes.append(f"{name}: Arrow-backed pandas raised {type(e).__name__}")
    return cells(r.tolist())


def g_case():
    pdf = pl.DataFrame({"x": TEXTS}, schema={"x": pl.String})
    for name, f, pf in (
        ("lower", lambda s: s.str.lower(), lambda: pl.col("x").str.to_lowercase()),
        ("upper", lambda s: s.str.upper(), lambda: pl.col("x").str.to_uppercase()),
    ):
        def one(name=name, f=f, pf=pf):
            a = pd_pair(name, f)
            b = cells(pdf.select(pf().alias("o"))["o"].to_list())
            case(f"{name}-pd", "expr", "pandas", a, op=name, cols={"x": TEXTS})
            case(f"{name}-pl", "expr", "polars", b, op=name, cols={"x": TEXTS})
            diff = [(t, x, y) for t, x, y in zip(TEXTS, a, b) if x != y]
            notes.append(f"{name}: pandas(Python) vs polars differ on {len(diff)} cells: {diff[:4]}")
        run(name, one)
    for name, f in (
        ("title", lambda s: s.str.title()),
        ("capitalize", lambda s: s.str.capitalize()),
        ("swapcase", lambda s: s.str.swapcase()),
        ("casefold", lambda s: s.str.casefold()),
    ):
        def one(name=name, f=f):
            case(name, "expr", "pandas", pd_pair(name, f), op=name, cols={"x": TEXTS})
        run(name, one)

    def pltitle():
        b = cells(pdf.select(pl.col("x").str.to_titlecase().alias("o"))["o"].to_list())
        case("title-pl", "expr", "polars", b, op="title", cols={"x": TEXTS})
    run("title-pl", pltitle)

    for form in ("NFC", "NFD", "NFKC", "NFKD"):
        def one(form=form):
            a = pd_pair("normalize-" + form, lambda s: s.str.normalize(form))
            case(f"normalize-{form}", "expr", "pandas", a, op="normalize", form=form.lower(), cols={"x": TEXTS})
            if hasattr(pl.Expr.str, "normalize"):
                b = cells(pdf.select(pl.col("x").str.normalize(form).alias("o"))["o"].to_list())
                case(f"normalize-{form}-pl", "expr", "polars", b, op="normalize", form=form.lower(), cols={"x": TEXTS})
                notes.append(f"normalize {form}: polars vs pandas differ on {sum(1 for x, y in zip(a, b) if x != y)} cells")
            else:
                notes.append("polars has no str.normalize")
        run("normalize-" + form, one)


# No engine has an accent fold. The common pandas recipe is `normalize("NFKD")` and dropping
# the combining marks; it agrees with `unaccent` where the text is a Latin letter with
# accents and nothing else (no ł, ß, æ, ligature, compatibility form). Those cells only.
ACC = ["Žluťoučký kůň", "ÀÉÎÕÜ àéîõü", "école", "École Normale", "ñandú", "Ünïcödé", "Ÿ ÿ", "ÁB́", "plain", "", None,
       "crème brûlée", "Dvořák", "Ångström", "naïve façade", "ČŠŽ čšž", "日本語", "ΣΑΣ", "é"]


def g_unaccent():
    def one():
        r = pser(ACC).str.normalize("NFKD")
        want = cells([None if x is pd.NA else "".join(c for c in x if not unicodedata.combining(c)) for x in r])
        case("unaccent-recipe", "expr", "pandas-recipe", want, op="unaccent", cols={"x": ACC})
    run("unaccent", one)


def g_classes():
    for name, op in (
        ("isalpha", "is_alpha"), ("isalnum", "is_alnum"), ("isdigit", "is_digit"), ("isdecimal", "is_decimal"),
        ("isnumeric", "is_numeric"), ("isspace", "is_space"), ("islower", "is_lower"), ("isupper", "is_upper"),
        ("istitle", "is_title"),
    ):
        def one(name=name, op=op):
            a = pd_pair(name, lambda s: getattr(s.str, name)())
            case(name, "expr", "pandas", a, op=op, cols={"x": TEXTS})
        run(name, one)


NAMES = ["abc", "ABC", "abc1", "123", "٣٤٥", "²³", "½", "Žluťoučký", "日本語", "a b", "a_b", "été", "ß", "ǅ", "x²", "Ⅻ", "ａｂ", "１２"]


def g_names():
    def sel(id, f):
        def one():
            df = pl.DataFrame({n: [1] for n in NAMES})
            picked = df.select(f()).columns
            case(id, "selector", "polars", picked, names=NAMES, sel=id.split("-")[1])
        run(id, one)
    sel("sel-alpha", cs.alpha)
    sel("sel-alphanumeric", cs.alphanumeric)
    sel("sel-digit", cs.digit)

    CN = ["abc", "ABC", "Žluťoučký", "straße", "STRASSE", "ΣΑΣ", "İx", "ǆ", "日本", "été", "ÉTÉ", "ﬁ"]

    def ren(op, f):
        def one():
            each = [pl.DataFrame({n: [1]}).select(f()).columns[0] for n in CN]
            case(f"rename-{op}", "rename", "polars", each, names=CN, op=op)
        run("rename-" + op, one)
    ren("lower", lambda: pl.all().name.to_lowercase())
    ren("upper", lambda: pl.all().name.to_uppercase())


for g in (g_case, g_unaccent, g_classes, g_names):
    try:
        g()
    except Exception as e:  # noqa: BLE001
        problems.append(f"{g.__name__}: {type(e).__name__}: {e}")

out = sys.argv[1] if len(sys.argv) > 1 else "oracle2f_vectors.json"
with open(out, "w") as fh:
    json.dump(cases, fh, indent=0, ensure_ascii=False)
    fh.write("\n")
sys.stderr.write(f"{len(cases)} cases, {len(problems)} problems\n")
for n in notes:
    sys.stderr.write("NOTE " + n + "\n")
for p in problems:
    sys.stderr.write("PROBLEM " + p + "\n")
