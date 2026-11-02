#!/usr/bin/env python3
"""Read what our writers wrote with the foreign implementations (live half of
the anchor; GLib is LGPL, only run).

    hw run -- env INI_WRITER_DUMP=.zig-cache/ini-writer.tsv \
        zig test -fllvm --test-filter 'writer oracle' --dep testkit \
        -Mroot=modules/ini/src/root.zig -Mtestkit=modules/testkit/src/root.zig
    python3 modules/ini/tools/writer_oracle.py .zig-cache/ini-writer.tsv

Each line of the dump holds a dialect, a source text, `Document.write`'s output,
the unedited `Editor`'s output, and the `Editor`'s output after a scripted edit
(the key it changed in the last section, the key it removed from the first). The reference reads the source and
each output. Required: `Document.write` and the unedited `Editor` mean what the
source means, the unedited `Editor` is the source byte for byte, and the edited
text means the source plus exactly those edits.
"""
import configparser, sys
import gi
gi.require_version('GLib', '2.0')
from gi.repository import GLib


def read_python(text, full):
    c = configparser.ConfigParser(interpolation=None, strict=False) if full else \
        configparser.RawConfigParser(comment_prefixes=('#', ';'), strict=False, empty_lines_in_values=False, interpolation=None)
    c.optionxform = str
    c.read_string(text)
    out = {}
    if full:
        out['DEFAULT'] = dict(c.defaults())
    for s in c.sections():
        # Only the section's own keys, so an edit there is not confused with
        # what it inherits.
        out[s] = {k: v for k, v in c._sections[s].items()} if full else {k: c.get(s, k, raw=True) for k in c.options(s)}
    return out


def read_desktop(text):
    kf = GLib.KeyFile()
    kf.load_from_data(text, len(text.encode()), GLib.KeyFileFlags.NONE)
    return {g: {k: kf.get_value(g, k) for k in kf.get_keys(g)[0]} for g in kf.get_groups()[0]}


def reader(dialect):
    return {'python': lambda t: read_python(t, False), 'configparser': lambda t: read_python(t, True), 'desktop': read_desktop}[dialect]


def fail(n, why, text, out):
    print(f'line {n}: {why}\n  source: {text!r}\n  output: {out!r}')
    return 1


def main():
    bad = checked = edits = 0
    for n, line in enumerate(open(sys.argv[1]), 1):
        f = line.rstrip('\n').split('\t')
        dialect = f[0]
        text, plain, same, edited, changed, removed, last, first = (bytes.fromhex(x).decode('utf-8', 'surrogateescape') for x in f[1:9])
        read = reader(dialect)
        try:
            want = read(text)
        except Exception:
            continue  # the reference refuses the source; the anchor test covers that
        if same != text:
            bad += fail(n, 'unedited Editor is not the source', text, same)
        try:
            if read(plain) != want:
                bad += fail(n, 'Document.write reads differently', text, plain)
            got = read(edited)
        except Exception as e:
            bad += fail(n, f'reference refused our output: {e}', text, plain + edited)
            continue
        checked += 1
        expect = {s: dict(kv) for s, kv in want.items()}
        if last:
            if changed:
                expect[last][changed] = 'edited value'
            expect[last]['oracle_new'] = 'new value'
            if removed:
                expect[first].pop(removed, None)
                edits += 1
        expect['oracle section'] = {'oracle_key': 'v1\tv2'}
        if got != expect:
            bad += fail(n, f'edited text means {got}, expected {expect}', text, edited)
    print(f'checked {checked} texts, {edits} with a removal, {bad} failures')
    return 1 if bad else 0


sys.exit(main())
