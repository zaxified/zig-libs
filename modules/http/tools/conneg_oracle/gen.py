# SPDX-License-Identifier: MIT
"""Differential oracle for modules/http/src/conneg.zig: Werkzeug (BSD-3) and
python-mimeparse (MIT) answer THIS module's case tables (below). Their
answers are written out as a Zig file that `src/conneg_oracle.zig` replays
hermetically -- no Python at test time. Both libraries are run, never read.

    V=~/.local/share/zig-libs/oracle-venvs/http
    python3 -m venv $V && $V/bin/pip install werkzeug python-mimeparse
    $V/bin/python modules/http/tools/conneg_oracle/gen.py \
        > modules/http/src/conneg_oracle_vectors.zig
    zig fmt modules/http/src/conneg_oracle_vectors.zig

Werkzeug is the primary oracle (Accept, Accept-Language, Accept-Encoding);
mimeparse is a second opinion on media types only, recorded so a divergence
from Werkzeug can say whether a third implementation sides with us.
"""
import sys

import mimeparse
from importlib.metadata import version
from werkzeug.datastructures import Accept, LanguageAccept, MIMEAccept
from werkzeug.http import parse_accept_header

H = "text/html"
P = "text/plain"
J = "application/json"
X = "application/xml"

# (Accept header, server offers in preference order)
MEDIA = [
    ("", [H, P]),
    ("*/*", [H, P]),
    (H, [H, P]),
    (P, [H, P]),
    (J, [H, P]),
    ("text/*", [J, P, H]),
    ("text/*;q=0.5, text/html;q=0", [H, P]),
    ("text/html;q=0", [H]),
    ("*/*;q=0", [H, P]),
    ("*/*;q=0, text/plain", [H, P]),
    ("text/*, text/plain;q=0", [P, H]),
    ("text/html;q=0.3, text/*;q=0.7, */*;q=0.1", [H, P, J]),
    ("application/json;q=0.9, text/html", [J, H]),
    ("application/json, text/html", [H, J]),
    ("application/json, text/html", [J, H]),
    ("text/html;q=0.5, application/json;q=0.5", [J, H]),
    ("TEXT/HTML", [H]),
    ("text/html", ["TEXT/HTML"]),
    ("Text/*", [P]),
    ("text/html;level=1", [H]),
    ("text/html;level=1, text/html;q=0.3", [H]),
    ("text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5",
     ["text/html", "text/plain", "image/jpeg"]),
    ("text/html; q=0.5", [H]),
    ("text/html ;q=0.5 , text/plain", [H, P]),
    ("text/html;Q=0.5, text/plain;q=0.6", [H, P]),
    ("text/html;q=1.0", [H, P]),
    ("text/html;q=1.000, text/plain;q=0.999", [P, H]),
    ("text/html;q=1.5, text/plain;q=0.5", [H, P]),
    ("text/html;q=-1, text/plain;q=0.5", [H, P]),
    ("text/html;q=abc, text/plain;q=0.5", [H, P]),
    ("text/html;q=0.0001, text/plain;q=0.5", [H, P]),
    ("text/html;q=0.1234, text/plain;q=0.12", [H, P]),
    ("text/html;q=.5, text/plain;q=0.4", [H, P]),
    ("text/html;q=, text/plain;q=0.4", [H, P]),
    ("text/html;q=0.5;q=0.9, text/plain;q=0.7", [H, P]),
    ("text/html;q=0.5;ext=1, text/plain;q=0.4", [H, P]),
    ("text, text/plain;q=0.5", [H, P]),
    ("*/html, text/plain;q=0.5", [H, P]),
    ("text/html/x, text/plain;q=0.5", [H, P]),
    ("/html, text/plain;q=0.5", [H, P]),
    (",,text/plain,,", [H, P]),
    (" , ", [H, P]),
    ("text/html, text/html;q=0", [H]),
    ("text/html;q=0, text/html", [H]),
    ("*/*, text/html;q=0", [H, P]),
    ("image/*", [H, P]),
    ("image/*, */*;q=0.1", [H, "image/png"]),
    ("application/*;q=0.8, application/json", [X, J]),
    ("application/vnd.api+json, application/json;q=0.9", [J, "application/vnd.api+json"]),
    ("text/html;charset=utf-8", [H]),
    ("text/html;charset=UTF-8, text/plain", ["text/html", "text/plain"]),
    ('text/html;foo="bar,baz", text/plain;q=0.5', [H, P]),
    ("text/html;q=0.5, text/plain;q=0.5, application/json;q=0.5", [P, J, H]),
    ("text/html\t;q=0.5, text/plain;q=0.4", [H, P]),
    ("text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8",
     [J, H, X]),
    # RFC 9110 §12.5.1's own example, one representation at a time: the
    # quality each gets is the most specific range's.
] + [
    ("text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5", [o])
    for o in ["text/html;level=1", "text/html", "text/plain", "image/jpeg",
              "text/html;level=2", "text/html;level=3"]
] + [
    ("text/html;level=1", ["text/html;level=1"]),
    ("text/html;level=1", ["text/html;level=2", "text/html;level=1"]),
    ("text/html;LEVEL=1", ["text/html;level=1"]),
    ("text/html;charset=utf-8", ["text/html;charset=UTF-8"]),
    ("text/html;level=1, text/*;q=0.5", ["text/html", "text/plain"]),
]

LANG = [
    ("", ["en", "de"]),
    ("*", ["en", "de"]),
    ("de", ["en", "de"]),
    ("en", ["en-US", "de"]),
    ("en-US", ["en", "de"]),
    ("en-US", ["en-us", "de"]),
    ("en-US, en;q=0.5, de;q=0.8", ["en", "de", "en-US"]),
    ("de;q=0, *", ["de", "en"]),
    ("*;q=0, en", ["de", "en"]),
    ("en;q=0", ["en-GB", "de"]),
    ("en-GB;q=0, en", ["en-GB", "en-US"]),
    ("fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5", ["de", "en", "fr", "it"]),
    ("zh-Hant-TW", ["zh-Hant", "zh", "zh-Hant-TW"]),
    ("zh", ["zh-Hant-TW", "en"]),
    ("EN", ["en"]),
    ("en-", ["en", "de"]),
    ("en;q=0.5, de;q=0.5", ["de", "en"]),
    ("x-klingon, en;q=0.1", ["en", "x-klingon"]),
    ("i-default", ["en", "i-default"]),
    ("en;q=2, de;q=0.5", ["en", "de"]),
]

ENC = [
    ("", ["gzip", "identity"]),
    ("gzip", ["gzip", "identity"]),
    ("gzip", ["br", "identity"]),
    ("br, gzip", ["gzip", "br"]),
    ("gzip;q=0.5, br", ["gzip", "br"]),
    ("gzip;q=0", ["gzip", "identity"]),
    ("*", ["br", "gzip"]),
    ("*;q=0", ["gzip", "identity"]),
    ("*;q=0, identity", ["gzip", "identity"]),
    ("identity;q=0", ["identity"]),
    ("gzip;q=0, *;q=0.5", ["gzip", "br", "identity"]),
    ("GZIP", ["gzip"]),
    ("deflate, gzip;q=1.0, *;q=0.5", ["br", "gzip"]),
    ("x-gzip", ["gzip"]),
    ("compress, gzip", ["identity"]),
    ("gzip;q=0.001", ["gzip", "identity"]),
    (" , gzip", ["gzip"]),
    ("gzip;q=abc, br;q=0.5", ["gzip", "br"]),
]


def zstr(s):
    out = ['"']
    for ch in s.encode():
        c = chr(ch)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\t":
            out.append("\\t")
        elif 0x20 <= ch < 0x7F:
            out.append(c)
        else:
            out.append("\\x%02x" % ch)
    out.append('"')
    return "".join(out)


def zopt(s):
    return "null" if s is None else zstr(s)


def zlist(items):
    return "&.{" + ", ".join(zstr(i) for i in items) + "}"


def milli(q):
    return int(round(q * 1000))


def media_ranges(header):
    """Werkzeug's parse, normalised: (range without q, q in milli), header order."""
    acc = parse_accept_header(header, MIMEAccept)
    return [(v.replace(" ", "").lower(), milli(q)) for v, q in acc]


def main():
    w = sys.stdout.write
    w("// SPDX-License-Identifier: MIT\n")
    w("// GENERATED by modules/http/tools/conneg_oracle/gen.py (Werkzeug %s, python-mimeparse %s)\n"
      % (version("werkzeug"), version("python-mimeparse")))
    w("// -- do not hand-edit. Replayed by `conneg_oracle.zig`.\n\n")
    w("pub const MediaCase = struct {\n    accept: []const u8,\n    offers: []const []const u8,\n")
    w("    /// Werkzeug `MIMEAccept.best_match`; null = no acceptable offer.\n    werkzeug: ?[]const u8,\n")
    w("    /// Werkzeug's quality for its winner, milli-units (0 when none).\n    werkzeug_q: u16,\n")
    w("    /// python-mimeparse `best_match`; null = no acceptable offer.\n    mimeparse: ?[]const u8,\n")
    w("    /// python-mimeparse raised on the header (it refuses what it cannot parse).\n    mimeparse_refused: bool,\n")
    w("    /// Werkzeug's parse: each range (lower-case, no spaces, no q) and its q in milli-units,\n")
    w("    /// in Werkzeug's order (most preferred first).\n    ranges: []const Range,\n};\n\n")
    w("pub const Range = struct { range: []const u8, q: u16 };\n\n")
    w("pub const media = [_]MediaCase{\n")
    for header, offers in MEDIA:
        acc = parse_accept_header(header, MIMEAccept)
        wz = acc.best_match(offers) if header.strip() else (offers[0] if offers else None)
        wq = (milli(acc.quality(wz)) if header.strip() else 1000) if wz is not None else 0
        try:
            mp, mp_refused = mimeparse.best_match(offers, header) or None, False
        except mimeparse.MimeTypeParseException:
            mp, mp_refused = None, True
        rs = ", ".join(".{ .range = %s, .q = %d }" % (zstr(r), q) for r, q in media_ranges(header))
        w("    .{ .accept = %s, .offers = %s, .werkzeug = %s, .werkzeug_q = %d, .mimeparse = %s, .mimeparse_refused = %s, .ranges = &.{%s} },\n"
          % (zstr(header), zlist(offers), zopt(wz), wq, zopt(mp), "true" if mp_refused else "false", rs))
    w("};\n\n")

    w("pub const TokenCase = struct { header: []const u8, offers: []const []const u8, werkzeug: ?[]const u8 };\n\n")
    w("/// Werkzeug `LanguageAccept.best_match`.\npub const language = [_]TokenCase{\n")
    for header, tags in LANG:
        acc = parse_accept_header(header, LanguageAccept)
        wz = acc.best_match(tags) if header.strip() else tags[0]
        w("    .{ .header = %s, .offers = %s, .werkzeug = %s },\n" % (zstr(header), zlist(tags), zopt(wz)))
    w("};\n\n")
    w("/// Werkzeug `Accept.best_match` over Accept-Encoding (it knows no implicit `identity`).\n")
    w("pub const encoding = [_]TokenCase{\n")
    for header, codings in ENC:
        acc = parse_accept_header(header, Accept)
        wz = acc.best_match(codings) if header.strip() else codings[0]
        w("    .{ .header = %s, .offers = %s, .werkzeug = %s },\n" % (zstr(header), zlist(codings), zopt(wz)))
    w("};\n")


main()
