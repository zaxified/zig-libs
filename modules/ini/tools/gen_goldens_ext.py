#!/usr/bin/env python3
"""Capture the goldens `src/oracle_ext_test.zig` checks the opt-in features with.

`gen_goldens.py` pins the two presets' plain reading; this pins what is layered
on it, against the same two implementations, only RUN (GLib is LGPL, see
README.md here):

  * inline comments: RawConfigParser(inline_comment_prefixes=('#', ';'));
  * ConfigParser's defaults: `[DEFAULT]`, empty_lines_in_values=True, its
    strict=True refusal of duplicates, and the bytes of `write()`;
  * allow_no_value=True;
  * BasicInterpolation and ExtendedInterpolation, value and error class;
  * getint, getfloat, getboolean;
  * GKeyFile get_string_list, get_locale_string, get_string, set_string.

Needs: python3 with PyGObject (`gi`) and GLib 2.x. Reproducible: seeded.

    python3 modules/ini/tools/gen_goldens_ext.py > modules/ini/src/testdata/goldens_ext.zig
"""
import configparser, io, platform, random
import gi
gi.require_version('GLib', '2.0')
from gi.repository import GLib


def zig_str(s):
    out = []
    for ch in s.encode():
        if ch == 0x5c: out.append('\\\\')
        elif ch == 0x22: out.append('\\"')
        elif ch == 0x0a: out.append('\\n')
        elif ch == 0x0d: out.append('\\r')
        elif ch == 0x09: out.append('\\t')
        elif 0x20 <= ch < 0x7f: out.append(chr(ch))
        else: out.append('\\x%02x' % ch)
    return '"' + ''.join(out) + '"'


def opt(x):
    return 'null' if x is None else zig_str(x)


def view(c):
    lines = []
    for s in c.sections():
        lines.append('[' + s + ']')
        for k in c.options(s):
            v = c.get(s, k, raw=True)
            lines.append(k + ('=<none>' if v is None else '=' + v.replace('\\', '\\\\').replace('\n', '\\n')))
    return ''.join(l + '\n' for l in lines)


def read(c, text):
    try:
        c.read_string(text)
    except configparser.Error:
        return None
    return c


def texts(shapes, n, seed, first=("[a]", "[b]")):
    rng = random.Random(seed)
    seen = set()
    for _ in range(n):
        lines = [rng.choice(first)] if rng.randrange(8) else []
        for _ in range(rng.randrange(1, 10)):
            lines.append(rng.choice(shapes))
        t = ''.join(l + '\n' for l in lines)
        if t not in seen:
            seen.add(t)
            yield t


INLINE_PROBES = [
    "[a]\nk = v ; c\n", "[a]\nk = v # c\n", "[a]\nk = v;c\n", "[a]\nx ; y = z\n", "[a]\nw = ;\n", "[a]\nw = # c\n",
    "[a] ; c\nk=v\n", "[a]\nk=v\n  more ; c\n", "[a]\nk=v\n  ; c\n  more\n", "[a]\nk=a\t; c\n", "[a]\n; c\n",
    "[a]\nk ; =v\n", "[a]\nk=v ;\n", "[a]\nk=v ; c ; d\n", "[a]\nk=v # c ; d\n", "[a]\nk=v ; c # d\n",
]
INLINE_SHAPES = [
    "k = v ; c", "k=v # c", "x ; y = z", "w = ;", "[a] ; c", "[b] # c", "  more ; c", "  more", "; c", "# c", "", "k=a;b",
    "j=a#b", "  ; c", "z = 1", "[a]x ; y", "m = a ; b # c", "n # c = d",
]

DEFAULT_PROBES = [
    "[DEFAULT]\nd=1\n[a]\nk=2\n", "[a]\nk=2\n[DEFAULT]\nd=1\n", "[DEFAULT]\n[a]\nk=2\n", "[DEFAULT]\nk=def\n[a]\nk=own\nj=1\n[b]\n",
    "[DEFAULT]\nd=1\n", "[a]\nk=1\nk=2\n", "[a]\nk=1\n[a]\nj=2\n", "[a]\nk=1\n[b]\n[a]\nk=2\n", "[DEFAULT]\nd=1\n[DEFAULT]\ne=2\n[a]\n",
    "[DEFAULT]\nd=1\nd=2\n[a]\n", "[a]\nk=x\n\n  y\n", "[a]\nk=x\n\n\n  y\n\n", "[a]\nk=x\n# c\n  y\n", "[a]\nk=x\n  # c\n  y\n",
    "[a]\nk=\n\n  y\n", "[a]\nk=x\n\nj=y\n", "[a]\nk=x\n\n[b]\n", "[a]\nk=x\n\n  y\n\n  z\nj=1\n", "[a]\n\n  k=x\n", "[a]\nk=x\n   \n  y\n",
    "[a]\nk=\n", "[a]\nk=x\n  y\n  z\n", "[a]\nk : v\n",
]
DEFAULT_SHAPES = [
    "[DEFAULT]", "[a]", "[b]", "k=v", "k = w", "j=x:y", "d=1", "", "  ", "# c", "; c", "  # c", "  more", "    deeper", "  j = w", "m:n",
]

NO_VALUE_PROBES = [
    "[a]\nbare\n", "[a]\nbare\nk=v\n", "[a]\nbare\n  more\n", "[a]\nk=v\nbare\n", "[a]\n  bare\n", "bare\n", "[a]\nbare key\n", "[a]\nk=\n",
    "[a]\nbare\n\n  x=1\n", "[a]\nbare\n# c\n  x=1\n", "[a]\n=\n", "[a]\n[b\n", "[a]\nbare\nbare\n",
]
NO_VALUE_SHAPES = ["bare", "k=v", "[b", "  more", "", "# c", "  x=1", "[a]", "j", "=v"]

INTERP_VALUES = [
    "plain", "%(n)s", "%(n)s/%(n)s", "%%", "100%%", "%", "5%", "%x", "%(", "%(n", "%(n)", "%()s", "%(nope)s", "%(self)s", "%(home)s",
    "%(indirect)s", "%(n)sx%%y", "a%(n)", "%(n)d", "%%(n)s", "%(n)s%", "${n}", "$${n}",
    "$", "$$", "$x", "${", "${n", "${}", "${nope}", "${b:v}", "${b:r}", "${nosec:v}", "${a:b:c}", "${home}", "${:v}", "${b:}", "x$${n}y", "${self}", "${n}$",
    "a\n  b%(n)s",
]
INTERP_DOC = "[DEFAULT]\nhome=/h\n[a]\nn=1\nself=%(self)s\nindirect=%(n)s!\nk = {}\n[b]\nv=deep\nr=${{n}}\nn=2\n"


def interp_result(cls, text, s, k):
    c = configparser.ConfigParser(interpolation=cls(), strict=False)
    c.optionxform = str
    c.read_string(text)
    try:
        return 'ok:' + c.get(s, k)
    except configparser.InterpolationSyntaxError:
        return 'err:syntax'
    except configparser.InterpolationDepthError:
        return 'err:depth'
    except configparser.InterpolationMissingOptionError:
        return 'err:missing'


INTS = ["0", "1", "-1", "+1", " 7 ", "\t7", "1_000", "1__0", "_1", "1_", "", " ", "-", "+", "0x10", "0b1", "0o7", "010", "1.0", "1e3", "abc",
        "9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "00", "-0", "1 2", "٣"]
FLOATS = ["0", "1", "-1", "+1", "1.5", ".5", "5.", "-.5e1", "1e5", "1E5", "1e+5", "1e-5", "1_000.5", "1__0.5", "_1.0", "1_.0", "1._5", "1.5_5", "1e1_0", "inf", "INF", "-inf", "+Inf",
         "infinity", "-Infinity", "nan", "NaN", "-nan", "+nan", "", " ", ".", "e5", "1e", "1e+", "0x10", "0x1p3", "1.5.5", "abc", " 2.5 ", "\t2.5", "1e999", "-1e999", "1e-999", "1 2", "infx", "in", "٣"]
BOOLS = ["1", "yes", "true", "on", "0", "no", "false", "off", "YES", "True", "ON", "Off", "2", "", "y", " on", "on "]

LISTS = ["", "a", "a;b", "a;b;", ";", ";;", "a;;b", ";a", "a\\;b;c", "a\\sb;c", "a\\nb", "a\\\\b;c", "a\\tb\\rc", "\\q", "a\\", " a ; b ", "a;b;;", "\\;", "\\;;"]
LOCALE_DOC = "[g]\nN=plain\nN[de]=de\nN[de_DE]=de_DE\nN[de@euro]=de_euro\nN[de_DE@euro]=de_DE_euro\nN[sr@latin]=sr_latin\nN[pt_BR]=pt_BR\nN[pt.UTF-8]=pt_utf8\nN[de_DE.UTF-8]=de_DE_utf8\nM[fr]=only_fr\n"
LOCALES = ["de", "de_DE", "de_AT", "de@euro", "de_DE@euro", "de_AT@euro", "de_DE.UTF-8", "de_DE.UTF-8@euro", "de.UTF-8", "sr", "sr@latin", "sr_RS@latin", "pt", "pt_BR", "pt_PT", "pt_PT.UTF-8", "fr", "en_US", "C", ""]
STRINGS = ["plain", "a\\sb", "a\\nb", "a\\tb", "a\\rb", "a\\\\b", "\\q", "a\\", "\\", "\\;", " x", "x ", "\\s\\s", "a\\;b"]
SET_STRINGS = ["plain", " lead", "  two", "trail ", "a b", "a\\b", "a\nb", "a\tb", "a\rb", "\t", "", "\\s", "[x]", "#c", "a=b", "\n"]


def glib_err(f):
    try:
        return f()
    except GLib.Error:
        return None


def desktop_kf(text):
    # KEEP_TRANSLATIONS: GLib documents it as required for an explicit locale.
    kf = GLib.KeyFile()
    kf.load_from_data(text, len(text.encode()), GLib.KeyFileFlags.KEEP_TRANSLATIONS)
    return kf


def main():
    print('// SPDX-License-Identifier: MIT')
    print('//! Generated by modules/ini/tools/gen_goldens_ext.py -- do not edit.')
    print(f'//! python {platform.python_version()} configparser; GLib {GLib.MAJOR_VERSION}.{GLib.MINOR_VERSION}.{GLib.MICRO_VERSION} GKeyFile.')
    print('//! `null` = the reference refused.')
    print()
    print('pub const View = struct { text: []const u8, view: ?[]const u8 };')
    print('pub const Default = struct { text: []const u8, view: ?[]const u8, strict_refuses: bool, write: ?[]const u8 };')
    print('pub const Interp = struct { extended: bool, text: []const u8, key: []const u8, result: []const u8 };')
    print('pub const Typed = struct { raw: []const u8, result: ?[]const u8 };')
    print('pub const Locale = struct { key: []const u8, locale: []const u8, result: ?[]const u8 };')
    print()

    print('pub const inline_cases = [_]View{')
    for t in list(INLINE_PROBES) + list(texts(INLINE_SHAPES, 400, 20261102)):
        p = configparser.RawConfigParser(comment_prefixes=('#', ';'), inline_comment_prefixes=('#', ';'), strict=False, empty_lines_in_values=False)
        p.optionxform = str
        p = read(p, t)
        print(f'    .{{ .text = {zig_str(t)}, .view = {opt(None if p is None else view(p))} }},')
    print('};\n')

    print('pub const default_cases = [_]Default{')
    for t in list(DEFAULT_PROBES) + list(texts(DEFAULT_SHAPES, 500, 20261103, ("[a]", "[b]", "[DEFAULT]"))):
        p = configparser.ConfigParser(interpolation=None, strict=False)
        p.optionxform = str
        p = read(p, t)
        s = configparser.ConfigParser(interpolation=None, strict=True)
        s.optionxform = str
        strict_ok = read(s, t) is not None
        w = None
        if p is not None:
            b = io.StringIO()
            p.write(b)
            w = b.getvalue()
        print(f'    .{{ .text = {zig_str(t)}, .view = {opt(None if p is None else view(p))}, .strict_refuses = {"false" if strict_ok or p is None else "true"}, .write = {opt(w)} }},')
    print('};\n')

    print('pub const no_value_cases = [_]View{')
    for t in list(NO_VALUE_PROBES) + list(texts(NO_VALUE_SHAPES, 300, 20261104)):
        p = configparser.RawConfigParser(comment_prefixes=('#', ';'), strict=False, empty_lines_in_values=False, allow_no_value=True)
        p.optionxform = str
        p = read(p, t)
        print(f'    .{{ .text = {zig_str(t)}, .view = {opt(None if p is None else view(p))} }},')
    print('};\n')

    print('pub const interp_cases = [_]Interp{')
    for v in INTERP_VALUES:
        t = INTERP_DOC.format(v)
        print(f'    .{{ .extended = false, .text = {zig_str(t)}, .key = "k", .result = {zig_str(interp_result(configparser.BasicInterpolation, t, "a", "k"))} }},')
        print(f'    .{{ .extended = true, .text = {zig_str(t)}, .key = "k", .result = {zig_str(interp_result(configparser.ExtendedInterpolation, t, "a", "k"))} }},')
    for depth in range(6, 14):
        chain = ''.join(f'v{i}=%(v{i+1})s\n' for i in range(depth)) + f'v{depth}=end\n'
        t = '[a]\n' + chain
        print(f'    .{{ .extended = false, .text = {zig_str(t)}, .key = "v0", .result = {zig_str(interp_result(configparser.BasicInterpolation, t, "a", "v0"))} }},')
        chain = ''.join(f'v{i}=${{v{i+1}}}\n' for i in range(depth)) + f'v{depth}=end\n'
        t = '[a]\n' + chain
        print(f'    .{{ .extended = true, .text = {zig_str(t)}, .key = "v0", .result = {zig_str(interp_result(configparser.ExtendedInterpolation, t, "a", "v0"))} }},')
    print('};\n')

    print('pub const int_cases = [_]Typed{')
    for v in INTS:
        try:
            n = int(v)
            r = str(n) if -2**63 <= n < 2**63 else 'overflow'
        except ValueError:
            r = None
        print(f'    .{{ .raw = {zig_str(v)}, .result = {opt(r)} }},')
    print('};\n')

    print('pub const float_cases = [_]Typed{')
    for v in FLOATS:
        try:
            f = float(v)
            r = 'nan' if f != f else 'inf' if f == float('inf') else '-inf' if f == float('-inf') else f.hex()
        except ValueError:
            r = None
        print(f'    .{{ .raw = {zig_str(v)}, .result = {opt(r)} }},')
    print('};\n')

    print('pub const bool_cases = [_]Typed{')
    b = configparser.RawConfigParser()
    for v in BOOLS:
        b.read_dict({'a': {}})
        b.set('a', 'k', v)
        try:
            r = 'true' if b.getboolean('a', 'k') else 'false'
        except ValueError:
            r = None
        print(f'    .{{ .raw = {zig_str(v)}, .result = {opt(r)} }},')
    print('};\n')

    print('pub const list_cases = [_]Typed{')
    for v in LISTS:
        kf = desktop_kf(f'[g]\nk={v}\n')
        items = glib_err(lambda: kf.get_string_list('g', 'k'))
        print(f'    .{{ .raw = {zig_str(v)}, .result = {opt(None if items is None else ''.join(i + chr(31) for i in items))} }},')
    print('};\n')

    print(f'pub const locale_doc = {zig_str(LOCALE_DOC)};')
    print('pub const locale_cases = [_]Locale{')
    kf = desktop_kf(LOCALE_DOC)
    for loc in LOCALES:
        for key in ("N", "M", "absent"):
            print(f'    .{{ .key = "{key}", .locale = {zig_str(loc)}, .result = {opt(glib_err(lambda: kf.get_locale_string("g", key, loc)))} }},')
    print('};\n')

    print('pub const unescape_cases = [_]Typed{')
    for v in STRINGS:
        kf = desktop_kf(f'[g]\nk={v}\n')
        print(f'    .{{ .raw = {zig_str(v)}, .result = {opt(glib_err(lambda: kf.get_string("g", "k")))} }},')
    print('};\n')

    print('pub const escape_cases = [_]Typed{')
    for v in SET_STRINGS:
        kf = GLib.KeyFile()
        kf.set_string('g', 'k', v)
        print(f'    .{{ .raw = {zig_str(v)}, .result = {zig_str(kf.get_value("g", "k"))} }},')
    print('};')


main()
