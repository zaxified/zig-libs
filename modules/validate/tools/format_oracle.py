#!/usr/bin/env python3
"""Differential oracle for the go-playground formats of `validate`.

Builds a string corpus per format (crafted edge cases + seeded mutations of
valid seeds), asks go-playground/validator v10.30.5 (`go_formats/`,
`validate.Var(s, tag)`) for its verdict on each, and writes
`src/go_format_vectors.zig`: every case with Go's verdict and the verdict the
module must give. Where they differ, a named class in CLASSES decides, with its
reason; `go_format_test.zig` replays the file with no Go.

    python3 modules/validate/tools/format_oracle.py > modules/validate/src/go_format_vectors.zig
    python3 modules/validate/tools/format_oracle.py --check   # re-take, compare

Needs `go` and the module cache of `go_bench/` (no network: GOPROXY=off).
"""

import base64
import json
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "src", "go_format_vectors.zig")

# module Format -> go-playground tag
TAGS = {
    "email": "email",
    "uri": "uri",
    "uuid": "uuid",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "hostname": "hostname_rfc1123",
    "date": "datetime=2006-01-02",
    "date_time": "datetime=2006-01-02T15:04:05Z07:00",
    "uuid3": "uuid3",
    "uuid4": "uuid4",
    "uuid5": "uuid5",
    "uuid_rfc4122": "uuid_rfc4122",
    "http_url": "http_url",
    "https_url": "https_url",
    "base64": "base64",
    "base64_url": "base64url",
    "base64_raw_url": "base64rawurl",
    "hex": "hexadecimal",
    "e164": "e164",
    "alpha": "alpha",
    "alphanumeric": "alphanum",
    "numeric": "numeric",
    "ascii": "ascii",
    "lowercase": "lowercase",
    "uppercase": "uppercase",
    "jwt": "jwt",
    "semver": "semver",
    "cidr": "cidr",
    "mac": "mac",
}

U = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
SEEDS = {
    "email": ["a@example.com", "first.last@sub.example.org", "x+tag@a.io", "a@b",
              "a..b@example.com", ".a@example.com", "a@-example.com", "\"q\"@example.com",
              "a@[127.0.0.1]", "a@example.com.", "ü@example.com", "a@exämple.com",
              "a" * 64 + "@example.com", "a" * 65 + "@example.com", "a b@example.com",
              "a@example..com", "a@ex_ample.com", "@example.com", "a@", ""],
    "uri": ["https://example.com/a?b#c", "mailto:a@b", "urn:isbn:0451450523", "a:", "1a:b",
            "http://[::1]:80/", "http://a b", "http://a/%zz", "http://a/%41", "//a/b", "/a",
            "http://a/#x#y", "file:///etc/passwd", "http://ü.example/", "x:\\y", ""],
    "uuid": [U, U.upper(), "00000000-0000-0000-0000-000000000000", U.replace("-", ""),
             U[:-1], U + "0", "{" + U + "}", U.replace("8", "g", 1), "urn:uuid:" + U],
    "ipv4": ["1.2.3.4", "255.255.255.255", "0.0.0.0", "01.2.3.4", "1.2.3", "1.2.3.4.5",
             "256.1.1.1", "1.2.3.4 ", "::ffff:1.2.3.4", "1.2.3.04", "0x1.2.3.4", ""],
    "ipv6": ["::1", "::", "2001:db8::1", "fe80::1%eth0", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8",
             "1:2:3:4:5:6:7:8:9", "1::2::3", "2001:DB8::1", "[::1]", "1.2.3.4", "02001:db8::1",
             "::ffff:01.2.3.4", ""],
    "hostname": ["example.com", "a", "a-b.c", "-a.com", "a-.com", "1.2.3.4", "a_b.com",
                 "example.com.", "xn--bcher-kva.example", "a" * 63 + ".com", "a" * 64 + ".com",
                 ".".join(["a" * 63] * 4), "ü.com", "a..b", "123", ""],
    "date": ["2024-02-29", "2023-02-29", "2024-13-01", "2024-00-10", "2024-1-01", "0000-01-01",
             "9999-12-31", "2024-04-31", "2024-12-31T00:00:00Z", " 2024-01-01", ""],
    "date_time": ["2024-01-01T00:00:00Z", "2024-01-01T00:00:00+01:00", "2024-01-01t00:00:00z",
                  "2024-01-01T00:00:00", "2024-01-01T23:59:60Z", "2024-01-01T12:00:60Z",
                  "2024-01-01T00:00:00.123456789Z", "2024-01-01 00:00:00Z", "2024-01-01T24:00:00Z",
                  "2024-01-01T00:00:00+24:00", "2024-01-01T00:00:00+0100", "2024-01-01T00:00Z",
                  "2023-02-29T00:00:00Z", "2024-01-01T00:00:00.Z", "2024-01-01T00:00:00-00:00", ""],
    "uuid3": ["6ba7b810-9dad-31d1-80b4-00c04fd430c8", "6ba7b810-9dad-31d1-c0b4-00c04fd430c8",
              "6BA7B810-9DAD-31D1-80B4-00C04FD430C8", U],
    "uuid4": ["6ba7b810-9dad-41d1-80b4-00c04fd430c8", "6ba7b810-9dad-41d1-c0b4-00c04fd430c8",
              "6BA7B810-9DAD-41D1-80B4-00C04FD430C8", "6ba7b810-9dad-41d1-b0b4-00c04fd430c8"],
    "uuid5": ["6ba7b810-9dad-51d1-80b4-00c04fd430c8", "6ba7b810-9dad-51d1-70b4-00c04fd430c8",
              "6BA7B810-9DAD-51D1-90B4-00C04FD430C8"],
    "uuid_rfc4122": [U, U.upper(), "00000000-0000-0000-0000-000000000000",
                     "ffffffff-ffff-ffff-ffff-ffffffffffff", "6ba7b810-9dad-91d1-80b4-00c04fd430c8",
                     "6ba7b810-9dad-01d1-80b4-00c04fd430c8", "6ba7b810-9dad-11d1-c0b4-00c04fd430c8",
                     "6ba7b810-9dad-11d1-00b4-00c04fd430c8"],
    "http_url": ["http://example.com", "https://example.com/a?b=c#d", "http://a:8080/", "http://a:/",
                 "http://u:p@a/", "http://[::1]/", "http://1.2.3.4/", "http://", "http:///a",
                 "ftp://example.com", "HTTP://EXAMPLE.COM", "http://exämple.com/", "http://a/ü",
                 "http://a:99999/", "http://a:port/", "http://a b/", "http://a/%zz", "example.com",
                 "http://a?b", "http://a#f", "http://-a/", "http://a..b/", ""],
    "https_url": ["https://example.com", "http://example.com", "https://a:443/x", "HTTPS://A",
                  "https://", "https://[::1]:8443/", "https://u@a/"],
    "base64": ["", "QQ==", "QUI=", "QUJD", "QQ", "QQ=", "Q===", "QUJD\n", "QU JD", "-_8=", "+/8=",
               "QUJDRA==", "QR==", "====", "QUJDRA"],
    "base64_url": ["", "QQ==", "-_8=", "+/8=", "QQ", "QUJD"],
    "base64_raw_url": ["", "QQ", "QUI", "QUJD", "QQ==", "-_8", "+/8", "Q"],
    "hex": ["", "0", "0x", "0x1f", "0X1F", "abcdef", "ABCDEFG", "1f ", "-1f", "0x0x1"],
    "e164": ["+14155552671", "14155552671", "+0123456789", "+1234567", "+12345678",
             "+123456789012345", "+1234567890123456", "+1 4155552671", "", "+"],
    "alpha": ["abc", "ABC", "", "abc1", "ä", "a b", "a-b"],
    "alphanumeric": ["abc123", "", "abc_", "ä1", "ABC"],
    "numeric": ["0", "-1", "+1", "1.5", "-1.5", ".5", "1.", "1e5", "", "١", "1_000", "--1", "00"],
    "ascii": ["", "abc", "\x7f", "\x80", "ä", "\x00", "\t"],
    "lowercase": ["abc", "", "ABC", "abc1", "1", "ä", "Ä", "ß", "abc DEF", "\xff", "ǅ", "ı", "ﬃ"],
    "uppercase": ["ABC", "", "abc", "ABC1", "1", "Ä", "ä", "ß", "ẞ", "\xff", "ǅ", "İ"],
    "jwt": ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "a.b.", "a.b", "a.b.c.d", "..", "a..c",
            "a=.b.c", "a.b.c=", "", ".b.c", "a+.b.c"],
    "semver": ["1.0.0", "0.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0+build", "1.0.0-0.3.7",
               "01.0.0", "1.0", "1.0.0-", "1.0.0-01", "1.0.0-alpha..1", "v1.0.0", "1.0.0+",
               "1.0.0-x.7.z.92+exp.sha.5114f85", "1.2.3-α", ""],
    "cidr": ["10.0.0.0/8", "10.0.0.1/8", "10.0.0.0/33", "10.0.0.0/08", "10.0.0.0", "::/0",
             "2001:db8::/129", "2001:db8::/032", "1.2.3.4/-1", "1.2.3.4/", "/8", "01.0.0.0/8",
             "::ffff:1.2.3.4/96", "fe80::1%eth0/64", ""],
    "mac": ["00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455", "001122334455",
            "00:11:22:33:44:55:66:77", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33",
            "00:11:22:33:44", "00:11:22:33:44:5g", "00:11-22:33:44:55", "0:11:22:33:44:55",
            "AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55:66", ""],
}

ALPHABET = "aZ09-._:/@%+=#?[]~ \x00\x7f\xc3\xa4\xff"


def mutate(rng, s):
    b = bytearray(s.encode("utf-8", "surrogateescape"))
    op = rng.randrange(5)
    pos = rng.randrange(len(b) + 1)
    ch = ALPHABET[rng.randrange(len(ALPHABET))].encode("latin-1")
    if op == 0 or not b:
        b[pos:pos] = ch
    elif op == 1:
        del b[min(pos, len(b) - 1)]
    elif op == 2:
        b[min(pos, len(b) - 1):min(pos, len(b) - 1) + 1] = ch
    elif op == 3:
        i = min(pos, len(b) - 1)
        c = b[i]
        if 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A:
            b[i] = c ^ 0x20
        else:
            b[i:i] = bytes([c])
    else:
        j = rng.randrange(len(b) + 1)
        a, z = sorted((pos, j))
        b = b[:a] + b[z:]
    return bytes(b)


def corpus():
    rng = random.Random(20261024)
    cases = []
    for fmt in TAGS:
        seen = set()
        seeds = [s.encode("utf-8") if isinstance(s, str) else s for s in SEEDS[fmt]]
        for s in seeds:
            if s not in seen:
                seen.add(s)
                cases.append((fmt, s))
        valid_ish = [s for s in seeds if s]
        n = 0
        while n < 120:
            base = valid_ish[rng.randrange(len(valid_ish))]
            m = mutate(rng, base.decode("utf-8", "surrogateescape"))
            if rng.randrange(3) == 0:
                m = mutate(rng, m.decode("latin-1"))
                m = m if isinstance(m, bytes) else m
            if m not in seen:
                seen.add(m)
                cases.append((fmt, m))
            n += 1
    return cases


def go_verdicts(cases):
    """Go's verdicts; a case is (format, s) or (raw go tag, s)."""
    payload = json.dumps([{"tag": TAGS.get(f, f), "v": base64.b64encode(s).decode()} for f, s in cases])
    env = dict(os.environ)
    env.setdefault("GOPROXY", "off")
    env.setdefault("GOFLAGS", "-mod=readonly")
    r = subprocess.run(["go", "run", "."], cwd=os.path.join(HERE, "go_formats"), input=payload.encode(),
                       capture_output=True, env=env, check=True)
    return json.loads(r.stdout)


# Go's verdict on a related (tag, string) pair, filled by main().
AUX = {}


def dt_offset(s):
    """The offset part of a date-time-shaped string (after the seconds/fraction), or None."""
    if len(s) < 19:
        return None
    i = 19
    if i < len(s) and s[i:i + 1] == b".":
        i += 1
        while i < len(s) and s[i:i + 1].isdigit():
            i += 1
    return s[i:]


def dt_norm(s):
    """What the module's profile reads `s` as, in Go's RFC 3339 spelling: `T`/`Z`
    upper-cased, a leap second as :59, a missing offset as `Z`."""
    if len(s) < 19:
        return s
    b = bytearray(s)
    if b[10:11] == b"t":
        b[10] = ord("T")
    if b[17:19] == b"60":
        b[17:19] = b"59"
    s = bytes(b)
    off = dt_offset(s)
    if off == b"":
        s += b"Z"
    elif off == b"z":
        s = s[:-1] + b"Z"
    return s


def aux_needed(cases):
    """(tag, string) pairs some class needs Go's verdict on."""
    out = [("datetime=2006-01-02T15:04:05Z07:00", dt_norm(s)) for f, s in cases if f == "date_time" and dt_norm(s) != s]
    out += [("ip", s) for f, s in cases if f in ("ipv4", "ipv6") and b"::ffff:" in s.lower()]
    return out


def local_part(s):
    return s[:s.rfind(b"@")] if b"@" in s else s


def domain(s):
    return s[s.rfind(b"@") + 1:] if b"@" in s else b""


def is_hostname(h):
    if not h or len(h) > 253:
        return False
    for label in h.split(b"."):
        if not label or len(label) > 63 or label[:1] == b"-" or label[-1:] == b"-":
            return False
        if not all(c < 0x80 and (chr(c).isalnum() or c == 0x2D) for c in label):
            return False
    return True


def has_scheme(s):
    c = s.find(b":")
    if c <= 0 or not (0x41 <= s[0] <= 0x5A or 0x61 <= s[0] <= 0x7A):
        return False
    return all(chr(x).isalnum() and x < 0x80 or x in b"+-." for x in s[1:c])


def bad_escape(s):
    return any(s[i + 1:i + 3].decode("latin-1").lower().strip("0123456789abcdef") != "" or len(s[i + 1:i + 3]) < 2
               for i in range(len(s)) if s[i] == 0x25)


def brackets_ok(s):
    """`[`/`]` only as the one IP-literal host of an authority (RFC 3986 3.2.2)."""
    if b"[" not in s and b"]" not in s:
        return True
    rest = s[s.find(b":") + 1:] if has_scheme(s) else s
    if not rest.startswith(b"//") or s.count(b"[") != 1 or s.count(b"]") != 1:
        return False
    auth = rest[2:]
    for d in b"/?#":
        auth = auth.split(bytes([d]), 1)[0]
    host = auth.rsplit(b"@", 1)[-1]
    return host.startswith(b"[") and b"]" in host


def outside_rfc3986(s):
    """Something RFC 3986 never admits in a URI: a byte outside its alphabet, a
    second `#`, a malformed escape, a bracket outside an IP-literal host."""
    return (any(c >= 0x80 or c <= 0x20 or c == 0x7F or c in b'"<>\\^`{|}' for c in s) or s.count(b"#") > 1
            or bad_escape(s) or not brackets_ok(s))


def http_host(s):
    rest = s.split(b"://", 1)[1] if b"://" in s else b""
    auth = rest
    for d in b"/?#":
        auth = auth.split(bytes([d]), 1)[0]
    host = auth.rsplit(b"@", 1)[-1]
    if host.startswith(b"["):
        return host
    return host.rsplit(b":", 1)[0] if b":" in host else host


def pct_reg_name_authority(s):
    """`scheme://` + a reg-name host holding a pct-encoded octet + an optional
    all-digit port: exactly the shape URI_PCT_HOST speaks for."""
    rest = s.split(b"://", 1)[1] if b"://" in s else None
    if rest is None:
        return False
    auth = re.split(rb"[/?#]", rest, maxsplit=1)[0]
    host_port = auth.rsplit(b"@", 1)[-1]
    m = re.fullmatch(rb"((?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})+)(?::([0-9]*))?", host_port)
    return m is not None and b"%" in m.group(1)


def uuid_rfc(s):
    t = s.decode("latin-1")
    if len(t) != 36 or any(t[i] != "-" for i in (8, 13, 18, 23)):
        return False
    h = t.replace("-", "")
    if not all(c in "0123456789abcdefABCDEF" for c in h):
        return False
    if h.lower() in ("0" * 32, "f" * 32):
        return True
    return h[12] in "12345678" and h[16].lower() in "89ab"


# Where the module deliberately answers otherwise than go-playground. Each class:
# (name, reason, predicate(fmt, s, go) -> True when it decides the case, verdict).
# The ones marked GO DEFECT are where go-playground breaks the standard its tag
# names; the rest are the module's documented, stricter or laxer, profile.
CLASSES = [
    ("MAPPED_V4", "GO DEFECT: go's ipv4 takes the IPv6 text ::ffff:a.b.c.d (net.IP.To4) and its ipv6 refuses it; RFC 4291 2.5.5.2 makes it an IPv6 address",
     lambda f, s, go: f in ("ipv4", "ipv6") and b"::ffff:" in s.lower() and AUX.get(("ip", s), False) and go == (f == "ipv4"),
     lambda f, s, go: f == "ipv6"),
    ("HOSTNAME_253", "GO DEFECT: go's hostname_rfc1123 has no total length limit; a name is at most 253 characters (RFC 1035 2.3.4: 255 octets on the wire)",
     lambda f, s, go: f == "hostname" and go and len(s) > 253,
     lambda f, s, go: False),
    ("EMAIL_LOCAL_64", "GO DEFECT: go's email takes a local part over 64 octets; RFC 5321 4.5.3.1.1 caps it at 64",
     lambda f, s, go: f == "email" and go and len(local_part(s)) > 64 and not local_part(s).startswith(b'"') and all(c < 0x80 for c in s),
     lambda f, s, go: False),
    ("EMAIL_DOMAIN", "GO DEFECT: go's email takes a domain that is no host name (a2~b.com); RFC 5321 4.1.2 Domain is LDH labels",
     lambda f, s, go: f == "email" and go and all(c < 0x80 for c in s) and not local_part(s).startswith(b'"') and not is_hostname(domain(s)),
     lambda f, s, go: False),
    ("EMAIL_QUOTED", "profile: a dot-atom local part only, no quoted strings (SPEC Format: practical RFC 5321 subset)",
     lambda f, s, go: f == "email" and local_part(s).startswith(b'"'),
     lambda f, s, go: False),
    ("EMAIL_NON_ASCII", "profile: ASCII addresses (RFC 5321); SMTPUTF8 / RFC 6531 not taken",
     lambda f, s, go: f == "email" and any(c >= 0x80 for c in s),
     lambda f, s, go: False),
    ("HTTP_EMPTY_HOST", "GO DEFECT: go's http_url/https_url take an empty host (http://:8080/); RFC 9110 4.2.1: a recipient MUST reject it as invalid",
     lambda f, s, go: f in ("http_url", "https_url") and go and http_host(s) == b"",
     lambda f, s, go: False),
    ("URL_RFC3986_CHARS", "profile: http_url is ASCII RFC 3986 (no raw non-ASCII, space or stray bracket); go takes whatever net/url.Parse does",
     lambda f, s, go: f in ("http_url", "https_url") and go and (outside_rfc3986(s) or (b"[" in s) != (b"]" in s) or b"]" in s and not http_host(s).startswith(b"[")),
     lambda f, s, go: False),
    ("URI_RELATIVE", "profile: uri is RFC 3986 URI (scheme required, JSON Schema 2020-12); relative references are uri_reference; go's uri is net/url.ParseRequestURI, which takes a bare path",
     lambda f, s, go: f == "uri" and go and not has_scheme(s),
     lambda f, s, go: False),
    ("URI_RFC3986_CHARS", "profile: uri admits only RFC 3986 characters (no raw non-ASCII, space, backslash, second #, malformed escape, and `[`/`]` only around an authority's IP-literal host)",
     lambda f, s, go: f == "uri" and go and outside_rfc3986(s),
     lambda f, s, go: False),
    ("URI_PCT_HOST", "profile: RFC 3986 3.2.2 reg-name admits pct-encoded octets (htp://a%41); go's net/url refuses an escape in a host",
     lambda f, s, go: f == "uri" and not go and has_scheme(s) and pct_reg_name_authority(s) and not outside_rfc3986(s),
     lambda f, s, go: True),
    ("UUID_RFC4122_STRICT", "profile: uuid_rfc4122 checks the RFC 9562 version (1-8) and variant (10xx) nibbles, or nil/max; go's checks shape only",
     lambda f, s, go: f == "uuid_rfc4122" and go and not uuid_rfc(s),
     lambda f, s, go: False),
    ("CIDR_PREFIX_ZEROS", "profile: no leading zero in the prefix length (Go's own net/netip.ParsePrefix refuses it too; net.ParseCIDR, which go-playground uses, takes it)",
     lambda f, s, go: f == "cidr" and go and b"/0" in s and not s.endswith(b"/0"),
     lambda f, s, go: False),
    ("DT_OFFSET_24", "GO DEFECT: go's datetime (time.Parse RFC 3339) takes a +24:00 offset; RFC 3339 5.6 time-numoffset hour is 00-23",
     lambda f, s, go: f == "date_time" and go and (dt_offset(s) or b"")[:1] in (b"+", b"-") and (dt_offset(s) or b"")[1:3] >= b"24",
     lambda f, s, go: False),
    ("DT_PROFILE", "profile: date_time also takes lower-case t/z (RFC 3339 5.6 NOTE), a leap second at any time of day and an offset-less local time (SPEC Format; review M4, owner's call); go's time.Parse takes none of them",
     lambda f, s, go: f == "date_time" and not go and dt_norm(s) != s and AUX.get(("datetime=2006-01-02T15:04:05Z07:00", dt_norm(s)), False),
     lambda f, s, go: True),
]


def decide(fmt, s, go):
    for name, _reason, pred, verdict in CLASSES:
        if pred(fmt, s, go):
            return verdict(fmt, s, go), name
    return go, ""


def zig_str(b):
    out = []
    for c in b:
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    return '"' + "".join(out) + '"'


def render(cases, verdicts):
    lines = [
        "// SPDX-License-Identifier: MIT",
        "// GENERATED by tools/format_oracle.py -- do not edit by hand.",
        "// go-playground/validator v10.30.5 verdicts (`validate.Var(s, tag)`) on a",
        "// seeded corpus per format; `want` is the module's required verdict:",
        "// Go's, unless `class` names the deliberate difference (CLASSES in the tool).",
        "",
        "pub const Case = struct { format: []const u8, s: []const u8, go: bool, want: bool, class: []const u8 };",
        "",
        "pub const cases = [_]Case{",
    ]
    for (fmt, s), go in zip(cases, verdicts):
        want, cls = decide(fmt, s, go)
        lines.append('    .{ .format = "%s", .s = %s, .go = %s, .want = %s, .class = "%s" },' % (
            fmt, zig_str(s), "true" if go else "false", "true" if want else "false", cls))
    lines.append("};")
    lines.append("")
    lines.append("pub const classes = [_][]const u8{")
    for name, reason, _p, _v in CLASSES:
        lines.append('    "%s", // %s' % (name, reason))
    lines.append("};")
    return "\n".join(lines) + "\n"


def main():
    cases = corpus()
    aux = aux_needed(cases)
    verdicts = go_verdicts(cases + aux)
    for key, v in zip(aux, verdicts[len(cases):]):
        AUX[key] = v
    text = render(cases, verdicts[:len(cases)])
    if "--check" in sys.argv:
        with open(OUT) as f:
            old = f.read()
        if old != text:
            sys.exit("go_format_vectors.zig differs from a fresh take")
        print("go_format_vectors.zig: %d cases, identical" % len(cases))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
