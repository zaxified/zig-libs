#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RFC 5322 date-time oracle for datefmt's `parseRfc2822`: Python's
`email.utils.parsedate_tz` as a black box.

Writes `src/mail_date_vectors.zig`, replayed by `src/go_oracle_test.zig` with
no Python at test time:

    python3 -I modules/datefmt/tools/mail_date_oracle.py > modules/datefmt/src/mail_date_vectors.zig
    python3 -I modules/datefmt/tools/mail_date_oracle.py --check   # re-take, compare with the committed file

Python is lenient where RFC 5322 is not (it takes `31 Nov`, hour 24, trailing
text, a wrong weekday) and puts two-digit years 50-68 in 20xx, so every case
carries OUR expectation next to Python's answer:
  agree     ours parses to what Python says (Python's "no zone" = 0);
  reject    ours refuses it, whatever Python says -- the reason is the
            comment on the row;
  own       ours parses to the hand-written value (RFC 5322 grammar Python
            does not follow, e.g. comments between tokens, or §4.3's
            two-digit year rule).
Generated cases are random instants written the ways mail software writes
them (with/without weekday and seconds, any case, a numeric or obsolete zone,
folding, a trailing comment) -- all `agree`.
"""
import email.utils
import platform
import random
import subprocess
import sys

SEED = 2822

# (input, expectation, own value as (y, mo, d, h, mi, s, off_min) or None)
CRAFTED = [
    ("Fri, 21 Nov 1997 09:55:06 -0600", "agree", None),
    ("21 Nov 1997 09:55:06 -0600", "agree", None),
    ("Fri, 21 Nov 1997 09:55 -0600", "agree", None),
    ("Fri, 21 Nov 97 09:55:06 -0600", "agree", None),
    ("Tue, 1 Jul 2003 10:52:37 +0200", "agree", None),
    ("Thu, 13 Feb 1969 23:32:54 -0330", "agree", None),
    ("Mon, 24 Nov 1997 14:22:01 -0800", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 -0000", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 +0000", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 GMT", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 UT", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 EST", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 EDT", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 CST", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 CDT", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 MST", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 MDT", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 PST", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 PDT", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 gmt", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 Z", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 A", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 z", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 -0600 (CST)", "agree", None),
    ("Fri, 21 Nov 1997 09:55:06 -0600 (a (nested) comment)", "agree", None),
    ("fri, 21 nov 1997 09:55:06 -0600", "agree", None),
    ("FRI, 21 NOV 1997 09:55:06 -0600", "agree", None),
    ("Fri,\r\n 21 Nov 1997 09:55:06 -0600", "agree", None),
    ("Fri, 21 Nov 1997\r\n\t09:55:06 -0600", "agree", None),
    ("  Fri, 21 Nov 1997 09:55:06 -0600  ", "agree", None),
    ("Fri, 21  Nov  1997  09:55:06  -0600", "agree", None),
    ("Tue, 29 Feb 2000 00:00:00 +2359", "agree", None),
    ("Fri, 31 Dec 9999 23:59:59 -2359", "agree", None),
    # Four digits are the year itself; Python takes 0000 as a two-digit 00.
    ("Sat, 01 Jan 0000 00:00:00 +0000", "own", (0, 1, 1, 0, 0, 0, 0)),
    ("21 Nov 49 09:55:06 -0600", "agree", None),
    ("21 Nov 00 09:55:06 -0600", "agree", None),
    ("21 Nov 69 09:55:06 -0600", "agree", None),
    # RFC 5322 §4.3: 50-99 -> 19xx; Python (and Go) put 50-68 in 20xx.
    ("Tue, 21 Nov 50 09:55:06 -0600", "own", (1950, 11, 21, 9, 55, 6, -360)),
    ("Thu, 21 Nov 68 09:55:06 -0600", "own", (1968, 11, 21, 9, 55, 6, -360)),
    # Three-digit year: +1900 (§4.3); Python keeps 197.
    ("Fri, 21 Nov 097 09:55:06 -0600", "own", (1997, 11, 21, 9, 55, 6, -360)),
    # Obsolete CFWS between tokens and around ':' (§4.3); Python refuses.
    ("Fri , 21 Nov 1997 09 : 55 : 06 -0600", "own", (1997, 11, 21, 9, 55, 6, -360)),
    ("Fri,(c)21(c)Nov(c)1997(c)09:55:06(c)-0600", "own", (1997, 11, 21, 9, 55, 6, -360)),
    ("Fri, 21 Nov 1997 09:55:06 -0600 (\\) quoted)", "own", (1997, 11, 21, 9, 55, 6, -360)),
    # Refused: not a date in RFC 5322's grammar, or not a real date.
    ("Sat, 21 Nov 1997 09:55:06 -0600", "reject", None),  # wrong weekday
    ("Fri, 31 Nov 1997 09:55:06 -0600", "reject", None),  # no 31 Nov
    ("Fri, 29 Feb 1900 09:55:06 -0600", "reject", None),  # 1900 is not leap
    ("Fri, 21 Nov 1997 24:00:00 -0600", "reject", None),  # hour 24
    ("Fri, 21 Nov 1997 09:60:00 -0600", "reject", None),  # minute 60
    ("Fri, 21 Nov 1997 09:55:60 -0600", "reject", None),  # leap second: DateParts cannot hold it
    ("Fri, 21 Nov 1997 09:55:06 +2400", "reject", None),  # a day of offset
    ("Fri, 21 Nov 1997 09:55:06 -0660", "reject", None),  # offset minutes 60
    ("Fri, 21 Nov 1997 09:55:06 J", "reject", None),  # J is not a zone
    ("Fri, 21 Nov 1997 09:55:06 CET", "reject", None),  # not an obs-zone
    ("Fri, 21 Nov 1997 09:55:06 +060", "reject", None),  # zone digits
    ("Fri, 21 Nov 1997 09:55:06 +06000", "reject", None),
    ("Fri, 21 Nov 1997 09:55:06", "reject", None),  # no zone
    ("Fri, 21 Nov 1997 09:55:06 -0600 garbage", "reject", None),  # trailing text
    ("Fri, 21 Nov 1997 09:55:06 -0600 (unclosed", "reject", None),
    ("Fri, 21 Nov 1997 09:55:06 -0600\r\n", "reject", None),  # CRLF not followed by WSP
    ("Fri, 21 Nov 1997 09:55:06 -0600\r", "reject", None),
    ("Fri 21 Nov 1997 09:55:06 -0600", "reject", None),  # day name without ','
    ("Fri, 121 Nov 1997 09:55:06 -0600", "reject", None),
    ("Fri, 21 November 1997 09:55:06 -0600", "reject", None),
    ("Fri, 21 Nov 19970 09:55:06 -0600", "reject", None),  # five-digit year
    ("Fri, 21 Nov 7 09:55:06 -0600", "reject", None),
    ("Fri, 21 Nov 1997 9:55:06 -0600", "reject", None),  # one-digit hour
    ("Fri, 21 Nov 1997 09:5:06 -0600", "reject", None),
    ("Fri, 21 Nov 1997 09:55:6 -0600", "reject", None),
    ("Fri, 21 Nov 1997 09-55-06 -0600", "reject", None),
    ("Fri, 21Nov 1997 09:55:06 -0600", "reject", None),
    ("Fri, 21 Nov1997 09:55:06 -0600", "reject", None),
    ("Fri, 0 Nov 1997 09:55:06 -0600", "reject", None),
    ("1997-11-21T09:55:06-06:00", "reject", None),
    ("", "reject", None),
    ("Fri,", "reject", None),
]

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
OBS = ["UT", "GMT", "EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT"]


def rand_case(r, s):
    return "".join(c.upper() if r.random() < 0.5 else c.lower() for c in s) if r.random() < 0.2 else s


def generated(r):
    import datetime as dt
    out = []
    while len(out) < 400:
        day = dt.date(1900, 1, 1) + dt.timedelta(days=r.randrange(73049))  # 1900..2099
        h, mi, s = r.randrange(24), r.randrange(60), r.randrange(60)
        parts = []
        if r.random() < 0.8:
            parts.append(rand_case(r, DAYS[day.weekday()]) + ",")
        parts.append(("%d" if r.random() < 0.5 else "%02d") % day.day)
        parts.append(rand_case(r, MONTHS[day.month - 1]))
        if r.random() < 0.15 and (day.year % 100 < 50) == (day.year >= 2000) and day.year % 100 > 68 or \
                (r.random() < 0.15 and day.year >= 2000 and day.year % 100 < 50):
            parts.append("%02d" % (day.year % 100))
        else:
            parts.append("%04d" % day.year)
        parts.append("%02d:%02d" % (h, mi) + (":%02d" % s if r.random() < 0.9 else ""))
        if r.random() < 0.75:
            off = r.randrange(-23 * 60 - 59, 23 * 60 + 60)
            parts.append("%s%02d%02d" % ("-" if off < 0 else "+", abs(off) // 60, abs(off) % 60))
        else:
            parts.append(rand_case(r, r.choice(OBS)))
        sep = [" "] * (len(parts) - 1)
        if r.random() < 0.2:
            sep[r.randrange(len(sep))] = r.choice(["\r\n ", "\r\n\t", "  ", "\t"])
        text = parts[0] + "".join(sp + p for sp, p in zip(sep, parts[1:]))
        if r.random() < 0.15:
            text += " (" + r.choice(["CET", "a comment", "UTC"]) + ")"
        out.append(text)
    return out


def zig_str(s):
    b = ['"']
    for c in s.encode():
        if c in (0x22, 0x5C):
            b.append("\\" + chr(c))
        elif 0x20 <= c < 0x7F:
            b.append(chr(c))
        else:
            b.append("\\x%02x" % c)
    b.append('"')
    return "".join(b)


def py_value(s):
    t = email.utils.parsedate_tz(s)
    if t is None:
        return "null"
    off = "null" if t[9] is None else str(t[9] // 60)
    return ".{ .y = %d, .mo = %d, .d = %d, .h = %d, .mi = %d, .s = %d, .off_min = %s }" % (
        t[0], t[1], t[2], t[3], t[4], t[5], off)


def render():
    r = random.Random(SEED)
    lines = [
        "// SPDX-License-Identifier: MIT",
        "// GENERATED by modules/datefmt/tools/mail_date_oracle.py (Python %s email.utils) -- do not hand-edit."
        % platform.python_version(),
        "//! Python `email.utils.parsedate_tz` answers to this module's own RFC 5322",
        "//! cases, replayed by `go_oracle_test.zig`. Regenerate with the command in",
        "//! tools/mail_date_oracle.py.",
        "",
        "pub const Value = struct { y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32, off_min: ?i32 };",
        "pub const Expect = enum { agree, reject, own };",
        "pub const Case = struct { in: []const u8, py: ?Value, expect: Expect, own: ?Value = null };",
        "",
        "pub const cases = [_]Case{",
    ]
    for text, exp, own in CRAFTED:
        row = ".{ .in = %s, .py = %s, .expect = .%s" % (zig_str(text), py_value(text), exp)
        if own:
            row += ", .own = .{ .y = %d, .mo = %d, .d = %d, .h = %d, .mi = %d, .s = %d, .off_min = %d }" % own
        lines.append(row + " },")
    for text in generated(r):
        lines.append(".{ .in = %s, .py = %s, .expect = .agree }," % (zig_str(text), py_value(text)))
    lines.append("};")
    src = "\n".join(lines) + "\n"
    return subprocess.run(["zig", "fmt", "--stdin"], input=src.encode(), capture_output=True, check=True).stdout


def main():
    out = render()
    if sys.argv[1:] == ["--check"]:
        path = "modules/datefmt/src/mail_date_vectors.zig"
        with open(path, "rb") as f:
            old = f.read()
        # The version line may differ on another runner; every verdict must not.
        strip = lambda b: [ln for ln in b.split(b"\n") if not ln.startswith(b"// GENERATED")]
        if strip(old) != strip(out):
            sys.stderr.write("mail date oracle: DRIFT against %s\n" % path)
            return 1
        sys.stderr.write("mail date oracle: committed vectors match a fresh re-take\n")
        return 0
    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
