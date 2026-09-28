#!/usr/bin/env python3
"""Capture the goldens `src/oracle_test.zig` checks this module against.

Runs every probe below, plus seeded random INI-shaped texts, through two
foreign implementations and writes what they made of it to
`src/testdata/goldens.zig`:

  * `python` -- CPython's configparser.RawConfigParser (default delimiters,
    comment_prefixes '#' ';', no inline comments, strict=False,
    empty_lines_in_values=False, interpolation=None, optionxform=str);
  * `desktop` -- GLib's GKeyFile through PyGObject (load_from_data, flags
    NONE; values read with get_value, i.e. raw).

Both are only RUN (black-box oracles); neither one's source is read. GLib is
LGPL, so that is a rule, not a habit (see README.md here).

Needs: python3 with PyGObject (`gi`) and GLib 2.x. Reproducible: the random
corpus is seeded, so rerunning with the same interpreter and GLib rewrites
the same file; the versions used are recorded in its header.

    python3 modules/ini/tools/gen_goldens.py > modules/ini/src/testdata/goldens.zig
"""
import configparser, platform, random, sys
import gi
gi.require_version('GLib', '2.0')
from gi.repository import GLib

PROBES = [
    "[a]\nk=v\n", "[a]\n  k  =  v  \n", "[ a ]\nk=v\n", "[a] junk\nk=v\n", "[a]b]\nk=v\n",
    "[]\nk=v\n", "[a\nk=v\n", "k=v\n[a]\nx=y\n", "[a]\nnovalue\n", "[a]\n=v\n", "[a]\nk=\n",
    "[a]\n; c\nk=v\n", "[a]\n   # c\nk=v\n", "[a]\nk=v ; c\n", "[a]\nk=v # c\n", "[a]\nk: v\n",
    "[a]\nk=a=b\n", "[a]\nk=1\nk=2\n", "[a]\nk=1\n[b]\nx=1\n[a]\nk=2\nm=3\n",
    "[a]\nk=v\n  more\nz=1\n", "[a]\r\nk=v\r\n", "[a]\nk=\"q v\"\n", "[a]\nKey=v\n",
    "[Desktop Entry]\nName[cs]=Ahoj\nName=Hi\n", "[a]\n\tk\t=\tv\t\n", "[a]\nk=a\\sb\\nc\\\\d\n",
    "[a]\nmy key = v\n", "[a]\nk=v", "[a]\nk=v\n\n  more\n", "[a]\nk=v\n  # c\n  more\n",
    "[a]\nk=\n  more\n", "[a]\nk=v\n  j=w\n", "[a]\n  k=v\n  j=w\n", "[a]\n  k=v\n    more\n  j=w\n",
    "[a]\nk=v\n  [b]\n", "  [a]\nk=v\n", "[a]\nk: v\nj=x:y\nm:n=o\n", "[a]\n  more\n", "[a]   \nk=v\n",
    "[a]\nk=v#x\n", "[a]\nk \t= v\n", "[a]\nk=v\n   \n  more\n", "[a]\n[b]\nk=v\n", "[a b]\nk=v\n",
    "[a]\nk=\t v\n", "[a=b\nk=v\n", "[a]\n[a=b\n", "[a]\n[x]=y\n", "", "\n\n", "# only\n",
]

# Lines both references accept in a well-formed file...
GOOD = [
    "[a]", "[b]", "[ a ]", "[a b]", "k=v", "k = v  ", "K=V", "k=", "k = a=b", "\tk\t=\tv\t",
    "k=v ; c", "k=v # c", "x y = z", "Name[cs]=A", "Name=B", "j=x:y", "# c", "  # c", "", "   ",
]
# ...and lines that are wrong somewhere, or read differently by the two.
ODD = [
    "[a] x", "[a]b]", "[]", "[a", "  [b]", "[a=b", "[x]=y", "=v", "k", "k: v", "j:x=y",
    "; c", "  more", "    deeper", "\tt", "  j = w", "a[b]c=v",
]
SHAPES = GOOD + ODD


def python_view(text):
    c = configparser.RawConfigParser(comment_prefixes=('#', ';'), inline_comment_prefixes=None,
                                     strict=False, empty_lines_in_values=False, interpolation=None)
    c.optionxform = str
    try:
        c.read_string(text)
    except Exception:
        return None
    return [(s, [(k, c.get(s, k, raw=True)) for k in c.options(s)]) for s in c.sections()]


def desktop_view(text):
    kf = GLib.KeyFile()
    try:
        kf.load_from_data(text, len(text.encode()), GLib.KeyFileFlags.NONE)
    except Exception:
        return None
    out = []
    for g in kf.get_groups()[0]:
        keys = []
        for k in kf.get_keys(g)[0]:
            if k not in keys:  # get_keys lists a repeated key once per occurrence
                keys.append(k)
        out.append((g, [(k, kf.get_value(g, k)) for k in keys]))
    return out


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


def dump(view):
    """The canonical text `oracle_test.zig` renders from a Document."""
    if view is None:
        return None
    lines = []
    for s, kvs in view:
        lines.append('[' + s + ']')
        for k, v in kvs:
            lines.append(k + '=' + v.replace('\\', '\\\\').replace('\n', '\\n'))
    return ''.join(l + '\n' for l in lines)


def corpus():
    yield from PROBES
    rng = random.Random(20260928)
    eol = lambda: '\r\n' if rng.randrange(8) == 0 else '\n'
    # Mostly well-formed: a header first, then good lines with an odd one in
    # about one text in three -- so the ACCEPT path is most of this half.
    for _ in range(600):
        lines = [rng.choice(["[a]", "[b]", "[ a ]"])]
        for _ in range(rng.randrange(1, 10)):
            lines.append(rng.choice(ODD) if rng.randrange(25) == 0 else rng.choice(GOOD))
        yield ''.join(l + eol() for l in lines)
    # Anything goes: every shape equally likely, mostly refused.
    for _ in range(300):
        yield ''.join(rng.choice(SHAPES) + eol() for _ in range(rng.randrange(1, 10)))


def main():
    print('// SPDX-License-Identifier: MIT')
    print('//! Generated by modules/ini/tools/gen_goldens.py -- do not edit.')
    print(f'//! python {platform.python_version()} configparser; GLib {GLib.MAJOR_VERSION}.{GLib.MINOR_VERSION}.{GLib.MICRO_VERSION} GKeyFile.')
    print('//! `null` = the reference refused the text.')
    print()
    print('pub const Case = struct { text: []const u8, python: ?[]const u8, desktop: ?[]const u8 };')
    print()
    print('pub const cases = [_]Case{')
    seen = set()
    for t in corpus():
        if t in seen:
            continue
        seen.add(t)
        p, d = dump(python_view(t)), dump(desktop_view(t))
        f = lambda x: 'null' if x is None else zig_str(x)
        print(f'    .{{ .text = {zig_str(t)}, .python = {f(p)}, .desktop = {f(d)} }},')
    print('};')


main()
