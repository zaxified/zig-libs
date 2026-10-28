# SPDX-License-Identifier: MIT
"""Generate `src/unicode_tables.zig` and `src/casefold.zig` from the Unicode
Character Database: the classes `\\p{…}` and `\\w \\s \\d` name, and the simple
case-folding orbits `(?i)` uses, with the key scheme and the class definitions
of Rust's `regex-syntax` (whose own tables stop at Unicode 16.0).

The rules, as regex-syntax 0.8.11 / ucd-generate apply them (each checked on
UCD 16.0.0 against that crate's answers, `--compare-with`):

  - binary properties: those of PropList.txt, DerivedCoreProperties.txt,
    emoji/emoji-data.txt, and Bidi_Mirrored (extracted/DerivedBinaryProperties);
  - a bare name is a binary property, else a General_Category value, else a
    Script value (`cf`, `sc`, `lc` are categories, never properties);
  - General_Category: every value but Cs; groups L LC M N P S Z C; Cn is every
    unassigned code point; surrogates are never in a class;
  - Script / Script_Extensions: the values the data lists (no Zzzz, no Hrkt);
    a code point ScriptExtensions.txt does not list has its Script as its
    only extension;
  - Age: cumulative (`age=6.0` is everything assigned by 6.0), no NA;
  - Grapheme_Cluster_Break, Word_Break, Sentence_Break: the values the
    auxiliary files list (no Other/XX);
  - `any`, `ascii`, `assigned` (assigned: not Cn);
  - `\\w` = Alphabetic + M + Nd + Pc + Join_Control, `\\s` = White_Space,
    `\\d` = Nd (UTS #18);
  - case folding: CaseFolding.txt C + S, as orbits.

    tools/ucd_unicode/fetch.sh 17.0.0                  # UCD.zip into tools/ucd_unicode/data/ (and 16.0.0)
    python3 tools/ucd_unicode/gen.py --ucd tools/ucd_unicode/data/17.0.0 -out src
    python3 tools/ucd_unicode/gen.py --ucd tools/ucd_unicode/data/17.0.0 -check src
    # the rules against regex-syntax (cargo, offline): UCD 16.0.0 must give
    # what tools/rust_unicode takes from the crate, byte for byte
    python3 tools/ucd_unicode/gen.py --ucd tools/ucd_unicode/data/16.0.0 --compare-with <rust_unicode -out dir>

Needs `zig` on PATH (`zig fmt --stdin`). The data are Unicode's (Unicode
License v3, see NOTICE); the encoding and this code are ours.
"""

import os
import re
import subprocess
import sys

MAX_CP = 0x10FFFF
HERE = os.path.dirname(os.path.abspath(__file__))
GO_NAMES = os.path.join(HERE, "..", "rust_unicode", "go_names.txt")


def die(m):
    sys.stderr.write(f"ucd_unicode: {m}\n")
    sys.exit(2)


def norm(x):
    """regex-syntax's symbolic name normalisation (UAX44-LM3 plus `is`)."""
    is_ = len(x) >= 2 and x[:2].lower() == "is"
    out = "".join(c.lower() for c in (x[2:] if is_ else x) if c not in " _-" and ord(c) < 0x80)
    if is_ and out == "c":
        out = "isc"
    return out


# ---- ranges ---------------------------------------------------------------


def canon(cps):
    """A sorted, merged range list from a set of code points (surrogates out)."""
    rs = []
    for c in sorted(cps):
        if 0xD800 <= c <= 0xDFFF:
            continue
        # Ranges of `char` merge across the surrogates (`\0-\u{10FFFF}` is one).
        if rs and (rs[-1][1] + 1 == c or (rs[-1][1] == 0xD7FF and c == 0xE000)):
            rs[-1][1] = c
        else:
            rs.append([c, c])
    return tuple((a, b) for a, b in rs)


def rows(path):
    """(lo, hi, fields) for each data line of a UCD file."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            fs = [x.strip() for x in line.split(";")]
            r = fs[0]
            if ".." in r:
                a, b = r.split("..")
                lo, hi = int(a, 16), int(b, 16)
            else:
                lo = hi = int(r, 16)
            yield lo, hi, fs[1:]


def by_value(path):
    out = {}
    for lo, hi, fs in rows(path):
        out.setdefault(fs[0], set()).update(range(lo, hi + 1))
    return out


class Ucd:
    def __init__(self, d):
        self.d = d
        p = lambda *x: os.path.join(d, *x)
        self.version = self._version(p("ReadMe.txt"), p("DerivedAge.txt"))
        # General_Category from UnicodeData (First/Last ranges expanded).
        gc = {}
        first = None
        with open(p("UnicodeData.txt"), encoding="utf-8") as f:
            for line in f:
                fs = line.split(";")
                c, name, cat = int(fs[0], 16), fs[1], fs[2]
                if name.endswith(", First>"):
                    first = c
                    continue
                if name.endswith(", Last>"):
                    for x in range(first, c + 1):
                        gc[x] = cat
                    continue
                gc[c] = cat
        self.gc = gc
        self.props = {}  # canonical binary property -> set
        for f in ("PropList.txt", "DerivedCoreProperties.txt", os.path.join("emoji", "emoji-data.txt")):
            for lo, hi, fs in rows(p(f)):
                if len(fs) != 1:
                    continue  # an enumerated property (InCB; Linker)
                self.props.setdefault(fs[0], set()).update(range(lo, hi + 1))
        bm = by_value(p("extracted", "DerivedBinaryProperties.txt")).get("Bidi_Mirrored")
        if bm is None:
            die("Bidi_Mirrored not in DerivedBinaryProperties.txt")
        self.props["Bidi_Mirrored"] = bm
        self.scripts = by_value(p("Scripts.txt"))
        self.scx = {}
        for lo, hi, fs in rows(p("ScriptExtensions.txt")):
            for c in range(lo, hi + 1):
                self.scx[c] = fs[0].split()
        self.age = by_value(p("DerivedAge.txt"))
        self.breaks = {
            "GCB": by_value(p("auxiliary", "GraphemeBreakProperty.txt")),
            "WB": by_value(p("auxiliary", "WordBreakProperty.txt")),
            "SB": by_value(p("auxiliary", "SentenceBreakProperty.txt")),
        }
        self.fold = {}
        for lo, _, fs in rows(p("CaseFolding.txt")):
            if fs[0] in ("C", "S"):
                self.fold[lo] = int(fs[1], 16)
        self.prop_aliases = []  # (canonical, [aliases], section)
        sec = None
        with open(p("PropertyAliases.txt"), encoding="utf-8") as f:
            for line in f:
                m = re.match(r"#\s+(\w[\w ]*Properties)", line)
                if m:
                    sec = m.group(1)
                body = line.split("#", 1)[0].strip()
                if body:
                    fs = [x.strip() for x in body.split(";")]
                    self.prop_aliases.append((fs[1], fs, sec))
        self.pva = {}  # property short name -> [[short, long, extra…]]
        for line in open(p("PropertyValueAliases.txt"), encoding="utf-8"):
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            fs = [x.strip() for x in body.split(";")]
            vals = fs[1:]
            if fs[0] == "ccc":
                vals = fs[2:]  # `ccc; 0; NR; Not_Reordered`
            self.pva.setdefault(fs[0], []).append(vals)

    @staticmethod
    def _version(readme, age):
        with open(age, encoding="utf-8") as f:
            m = re.match(r"# DerivedAge-(\d+\.\d+\.\d+)\.txt", f.readline())
        if not m:
            die(f"{age}: no version on its first line")
        return m.group(1)


# ---- the model ------------------------------------------------------------

GROUPS = {
    "L": ("Lu", "Ll", "Lt", "Lm", "Lo"),
    "LC": ("Lu", "Ll", "Lt"),
    "M": ("Mn", "Mc", "Me"),
    "N": ("Nd", "Nl", "No"),
    "P": ("Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po"),
    "S": ("Sm", "Sc", "Sk", "So"),
    "Z": ("Zs", "Zl", "Zp"),
    "C": ("Cc", "Cf", "Cs", "Co", "Cn"),
}
# The key prefixes of the seven properties `\p{prop=value}` resolves.
VALUE_PROPS = [("gc", "gc"), ("sc", "sc"), ("scx", "scx"), ("age", "age"), ("GCB", "gcb"), ("SB", "sb"), ("WB", "wb")]


def version_key(v):
    return tuple(int(x) for x in v.split("."))


def build(u):
    all_cps = set(range(0, MAX_CP + 1)) - set(range(0xD800, 0xE000))
    cat = {}
    for c in all_cps:
        cat.setdefault(u.gc.get(c, "Cn"), set()).add(c)
    gc_sets = dict(cat)
    for g, members in GROUPS.items():
        gc_sets[g] = set().union(*(cat.get(m, set()) for m in members))
    gc_sets.pop("Cs", None)
    assigned = all_cps - cat.get("Cn", set())

    sc_short = {v[1]: v[0] for v in u.pva["sc"]}  # long -> short
    sc_sets = {sc_short[k]: v for k, v in u.scripts.items()}
    cp_sc = {}
    for s, cps in sc_sets.items():
        for c in cps:
            cp_sc[c] = s
    scx_sets = {}
    for c in all_cps:
        ext = u.scx.get(c)
        if ext is None:
            s = cp_sc.get(c)
            ext = [s] if s else []
        for s in ext:
            scx_sets.setdefault(s, set()).add(c)

    ages = sorted(u.age, key=version_key)
    age_sets, acc = {}, set()
    for v in ages:
        acc |= u.age[v]
        age_sets[v] = set(acc)

    entries = {}  # key -> range tuple

    def put(key, cps):
        entries[key] = canon(cps)

    # prop=value, for the values the data have.
    def value_keys(prop, sets, id_):
        for vals in u.pva[prop]:
            # The data name a value by its short or its long alias.
            have = [a for a in vals if a in sets]
            if not have:
                continue
            for a in vals:
                put(f"{id_}={norm(a)}", sets[have[0]])

    value_keys("gc", gc_sets, "gc")
    entries["gc=any"] = canon(all_cps)
    entries["gc=ascii"] = canon(range(0, 0x80))
    entries["gc=assigned"] = canon(assigned)
    value_keys("sc", sc_sets, "sc")
    value_keys("sc", scx_sets, "scx")
    age_by_short = {}
    for vals in u.pva["age"]:
        if vals[0] in age_sets:
            age_by_short[vals[0]] = age_sets[vals[0]]
    value_keys("age", age_by_short, "age")
    for prop, id_ in (("GCB", "gcb"), ("SB", "sb"), ("WB", "wb")):
        value_keys(prop, u.breaks[prop], id_)

    # Bare names: a binary property, else a category, else a script.
    binaries = {}
    for canonical, aliases, sec in u.prop_aliases:
        if sec and sec.startswith("Binary") and canonical in u.props:
            for a in aliases:
                binaries[norm(a)] = canonical
    bare = {}
    for vals in u.pva["sc"]:
        if vals[0] in sc_sets:
            for a in vals:
                bare[norm(a)] = sc_sets[vals[0]]
    for vals in u.pva["gc"]:
        if vals[0] in gc_sets:
            for a in vals:
                bare[norm(a)] = gc_sets[vals[0]]
    for a, canonical in binaries.items():
        if a not in ("cf", "sc", "lc"):
            bare[a] = u.props[canonical]
    bare["any"] = all_cps
    bare["ascii"] = set(range(0, 0x80))
    bare["assigned"] = assigned
    for k, cps in bare.items():
        put(k, cps)

    props = {}
    for canonical, aliases, _ in u.prop_aliases:
        for short, id_ in VALUE_PROPS:
            if aliases[0] == short:
                for a in aliases:
                    props[norm(a)] = id_

    alpha = u.props["Alphabetic"]
    word = alpha | gc_sets["M"] | gc_sets["Nd"] | gc_sets["Pc"] | u.props["Join_Control"]
    perl = [("perl_word", canon(word)), ("perl_space", canon(u.props["White_Space"])), ("perl_digit", canon(gc_sets["Nd"]))]
    return entries, props, perl


# ---- encoding (the layout tools/rust_unicode writes) -----------------------


def varint(b, v):
    while v >= 0x80:
        b.append((v & 0x7F) | 0x80)
        v >>= 7
    b.append(v)


def zig_fmt(src):
    r = subprocess.run(["zig", "fmt", "--stdin"], input=src.encode(), capture_output=True)
    if r.returncode != 0:
        die("zig fmt --stdin failed: " + r.stderr.decode())
    return r.stdout.decode()


HEADER = r"""//! The Unicode classes `\p{…}` and `\w \s \d` name in the Rust grammar (and,
//! the names Go lists, in Go's): general categories, scripts, script
//! extensions, binary properties, Age, Grapheme_Cluster_Break, Word_Break,
//! Sentence_Break, `Any`/`ASCII`/`Assigned` -- built from the Unicode
//! Character Database by the rules of Rust's `regex-syntax` (see
//! tools/ucd_unicode/gen.py, which checks them on UCD 16.0.0 against that
//! crate). Regenerate with the command there.
//!
//! Key scheme. The parser normalizes each name as the crate does (drop an
//! `is`/`Is`/`IS`/`iS` prefix, then ASCII-lower-case, then drop ` `, `_`, `-`
//! and every non-ASCII byte; a lone `c` after an `is` prefix stays `isc`).
//!  - `\pL`, `\p{L}`, `\p{Greek}`, `\p{Alphabetic}`: one normalized name, looked
//!    up bare in `names` (a binary property, a general category value or a
//!    script value: the crate's own order, already applied here -- `sc`, `cf`,
//!    `lc` are the categories). `\pL` is the bare name "l".
//!  - `\p{prop=value}`, `\p{prop:value}`: normalize both, find the property in
//!    `props` (spellings of gc, sc, scx, age, gcb, sb, wb only; any other
//!    property, or none, is an error, as in the crate), then look up the key
//!    `<id>=<normalized value>` in `names`, e.g. `gc=lu`, `sc=greek`,
//!    `scx=grek`, `age=1.1`, `gcb=extend`. `!=` and `\P` are negation, done by
//!    the parser, not table entries.
//! Several keys share a base when their classes are equal.
//! `go` marks the bare names Go 1.26's `regexp` also accepts (general
//! categories and their aliases, the scripts Go lists, `any`, `ascii`,
//! `assigned`): the Go-syntax parser refuses the rest.

/// A stored table: `count` ranges in `data[offset..][0..size]`, each two
/// LEB128 varints -- the gap from the end of the previous range (from 0 for
/// the first), then the range's length minus one.
pub const Base = struct { offset: u32, size: u16, count: u16 };
/// A class key (see the header) and the one stored table that is its class.
pub const Name = struct { name: []const u8, base: u16, go: bool };
/// A spelling of a property that `\p{prop=value}` accepts, and the key prefix.
pub const Prop = struct { name: []const u8, id: []const u8 };

"""


def go_names():
    out = set()
    for l in open(GO_NAMES, encoding="utf-8"):
        l = l.strip()
        if l and not l.startswith("#"):
            out.add(l)
    if len(out) < 150:
        die("too few Go names read")
    return out


def gen_tables(version, entries, props, perl, go):
    data = bytearray()
    bases = []  # (offset, size, count, label)
    index = {}

    def place(rs, label):
        off = len(data)
        prev = 0
        for lo, hi in rs:
            varint(data, lo - prev)
            varint(data, hi - lo)
            prev = hi + 1
        bases.append((off, len(data) - off, len(rs), label))
        return len(bases) - 1

    name_base = []
    for k in sorted(entries):
        rs = entries[k]
        i = index.get(rs)
        if i is None:
            i = place(rs, k)
            index[rs] = i
        name_base.append((k, i))
    perl_idx = []
    for n, rs in perl:
        i = index.get(rs)
        if i is None:
            i = place(rs, n)
            index[rs] = i
        perl_idx.append((n, i))
    if len(bases) > 0xFFFF or any(b[1] > 0xFFFF or b[2] > 0xFFFF for b in bases):
        die("a table past the u16 fields")
    max_ranges = max(b[2] for b in bases)
    s = ["// SPDX-License-Identifier: MIT\n"]
    s.append(f"// GENERATED by modules/regex/tools/ucd_unicode (Unicode {version}) -- do not hand-edit.\n")
    s.append(HEADER)
    s.append(f'pub const unicode_version = "{version}";\n/// The most ranges any one table has.\npub const max_ranges = {max_ranges};\n\n')
    s.append("pub const data: []const u8 =\n")
    chunks = [data[i : i + 24] for i in range(0, len(data), 24)]
    for n, ch in enumerate(chunks):
        last = n + 1 == len(chunks)
        s.append('    "' + "".join(f"\\x{c:02x}" for c in ch) + '"' + (";" if last else " ++") + "\n")
    s.append("\npub const bases = [_]Base{\n")
    for off, size, count, label in bases:
        s.append(f".{{ .offset = {off}, .size = {size}, .count = {count} }}, // {label}\n")
    s.append("};\n\n/// The bases of the Perl classes `\\w`, `\\s`, `\\d`.\n")
    for n, i in perl_idx:
        s.append(f"pub const {n}: u16 = {i};\n")
    s.append("\n/// Property spellings that `\\p{prop=value}` resolves, sorted by normalized spelling.\npub const props = [_]Prop{\n")
    for a in sorted(props):
        s.append(f'.{{ .name = "{a}", .id = "{props[a]}" }},\n')
    s.append("};\n\n/// Sorted by key (byte order).\npub const names = [_]Name{\n")
    for k, i in name_base:
        g = k in go or k in ("any", "ascii", "assigned")
        s.append(f'.{{ .name = "{k}", .base = {i}, .go = {"true" if g else "false"} }},\n')
    s.append("};\n")
    sys.stderr.write(f"unicode {version}: {len(bases)} bases, {len(entries)} names, {len(props)} property spellings, {len(data)} bytes of ranges, at most {max_ranges} ranges per table\n")
    return zig_fmt("".join(s))


# ---- case folding (the run encoding tools/rust_unicode writes) -------------


def gen_casefold(version, fold_map):
    parent = {}

    def find(x):
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent[x], parent[x])
            x = parent[x]
        return x

    for c, f in fold_map.items():
        a, b = find(c), find(f)
        if a != b:
            parent[a] = b
    orbit = {}
    for c in set(fold_map) | set(fold_map.values()):
        orbit.setdefault(find(c), []).append(c)
    nxt = {}
    max_orbit = 1
    for members in orbit.values():
        members.sort()
        if len(members) < 2:
            continue
        max_orbit = max(max_orbit, len(members))
        for i, c in enumerate(members):
            nxt[c] = members[(i + 1) % len(members)]
    f = lambda c: nxt.get(c, c)
    two = lambda c: f(f(c)) == c
    runs = []  # [lo, hi, delta, alt]
    for c in range(0, MAX_CP + 1):
        fc = f(c)
        if fc == c:
            continue
        d = fc - c
        if runs:
            l = runs[-1]
            if l[1] + 1 == c:
                if not l[3] and l[2] == d and not (l[0] == l[1] and d == -1):
                    l[1] = c
                    continue
                off = c - l[0]
                pair_start = (l[3] or (l[0] == l[1] and l[2] == 1 and two(l[0]))) and off % 2 == 1
                if pair_start and d == -1 and two(c):
                    l[3] = True
                    l[2] = 0
                    l[1] = c
                    continue
                if l[3] and off % 2 == 0 and d == 1 and two(c) and c + 1 <= MAX_CP and f(c + 1) == c:
                    l[1] = c
                    continue
        runs.append([c, c, d, False])
    for r in runs:
        if r[3] and (r[1] - r[0]) % 2 == 0:
            die(f"odd alternating run {r[0]:x}-{r[1]:x}")
    s = ["// SPDX-License-Identifier: MIT\n"]
    s.append(f"// GENERATED by modules/regex/tools/ucd_unicode (Unicode {version}) -- do not hand-edit.\n")
    s.append(r"""//! Simple case-folding orbits: the code points `(?i)` treats as one letter
//! (Unicode CaseFolding.txt, C + S entries, as orbits -- what Rust's
//! `regex-syntax` gives `(?i)[\x{C}]`). `next` is the orbit successor (the
//! next larger member, the smallest after the largest); following it from any
//! code point comes back to it within `max_orbit` steps. Regenerate with the
//! command in tools/ucd_unicode/gen.py.

/// A run of consecutive code points: the successor of `cp` is `cp + delta`, or
/// for an alternating run (`alt`, upper/lower pairs side by side) `cp + 1` at an
/// even offset from `lo` and `cp - 1` at an odd one; each such pair is a whole orbit.
pub const Run = struct { lo: u21, hi: u21, delta: i32 = 0, alt: bool = false };

""")
    s.append(f'pub const unicode_version = "{version}";\n')
    s.append(f"pub const max_orbit = {max_orbit};\n")
    s.append(f"/// The lowest and highest code point with a fold.\npub const min_fold: u21 = 0x{runs[0][0]:X};\npub const max_fold: u21 = 0x{runs[-1][1]:X};\n\n")
    s.append("pub const runs = [_]Run{\n")
    for lo, hi, d, alt in runs:
        if alt:
            s.append(f".{{ .lo = 0x{lo:X}, .hi = 0x{hi:X}, .alt = true }},\n")
        else:
            s.append(f".{{ .lo = 0x{lo:X}, .hi = 0x{hi:X}, .delta = {d} }},\n")
    s.append("};\n")
    sys.stderr.write(f"casefold {version}: {len(runs)} runs, max orbit {max_orbit}, {len(nxt)} folding code points\n")
    return zig_fmt("".join(s))


# ---- main -----------------------------------------------------------------


def body(text):
    """What two generators must agree on: from `unicode_version` on."""
    i = text.find("pub const unicode_version")
    if i < 0:
        die("no unicode_version line")
    return text[i:]


def main():
    args = sys.argv[1:]
    opts = {}
    while args:
        a = args.pop(0)
        if not args:
            die(f"{a} needs a value")
        opts[a] = args.pop(0)
    ucd = opts.get("--ucd") or die("usage: gen.py --ucd <UCD dir> (-out <dir> | -check <dir> | --compare-with <dir>)")
    u = Ucd(ucd)
    entries, props, perl = build(u)
    tables = gen_tables(u.version, entries, props, perl, go_names())
    fold = gen_casefold(u.version, u.fold)
    out = {"unicode_tables.zig": tables, "casefold.zig": fold}
    if "-out" in opts:
        for f, t in out.items():
            path = os.path.join(opts["-out"], f)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(t)
            sys.stderr.write(f"wrote {path} ({len(t)} bytes)\n")
    elif "-check" in opts:
        bad = False
        for f, t in out.items():
            old = open(os.path.join(opts["-check"], f), encoding="utf-8").read()
            if old.split("\n", 2)[2:] != t.split("\n", 2)[2:]:
                sys.stderr.write(f"{f}: DRIFT -- committed file differs from a fresh build\n")
                bad = True
            else:
                sys.stderr.write(f"{f}: committed file matches a fresh build\n")
        sys.exit(1 if bad else 0)
    elif "--compare-with" in opts:
        # tools/rust_unicode's files (regex-syntax 0.8.11) for the same UCD.
        bad = False
        for f, rf in (("unicode_tables.zig", "unicode16_tables.zig"), ("casefold.zig", "casefold16.zig")):
            theirs = open(os.path.join(opts["--compare-with"], rf), encoding="utf-8").read()
            if body(theirs) != body(out[f]):
                a, b = body(theirs).splitlines(), body(out[f]).splitlines()
                for i, (x, y) in enumerate(zip(a, b)):
                    if x != y:
                        sys.stderr.write(f"{f}: first difference at body line {i + 1}:\n  crate: {x[:160]}\n  ucd:   {y[:160]}\n")
                        break
                else:
                    sys.stderr.write(f"{f}: lengths differ ({len(a)} vs {len(b)} lines)\n")
                bad = True
            else:
                sys.stderr.write(f"{f}: equal to regex-syntax's, byte for byte\n")
        sys.exit(1 if bad else 0)
    else:
        die("one of -out, -check, --compare-with is required")


if __name__ == "__main__":
    main()
