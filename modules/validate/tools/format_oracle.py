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
import ipaddress
import json
import os
import random
import hashlib
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
TAGS.update({n: n for n in """hexcolor rgb rgba hsl hsla cmyk isbn isbn10 isbn13 issn eth_addr eth_addr_checksum btc_addr btc_addr_bech32 uuid3_rfc4122 uuid4_rfc4122 uuid5_rfc4122 ulid base32 multibyte datauri alphaunicode alphanumunicode cidrv4 cidrv6 fqdn dns_rfc1035_label hostname_rfc952 hostname_port origin urn_rfc2141 urn_rfc8141 html_encoded url_encoded tcp4_addr tcp6_addr tcp_addr udp4_addr udp6_addr udp_addr ip4_addr ip6_addr ip_addr iso3166_1_alpha2 iso3166_1_alpha2_eu iso3166_1_alpha3 iso3166_1_alpha3_eu iso3166_1_alpha_numeric iso3166_1_alpha_numeric_eu iso4217 iso4217_numeric bcp47_language_tag bcp47_strict_language_tag bic_iso_9362_2014 bic credit_card luhn_checksum cve ssn ein cron""".split()})

TAGS["hostname_rfc952"] = "hostname"  # go names the RFC 952 check plain `hostname`

# Tags whose go kind is an integer (the module takes their decimal text).
INT_FORMATS = {"iso4217_numeric"}

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

def _rep(c, n):
    return c * n


SEEDS.update({
    "hexcolor": ["#fff", "#FFFF", "#a1b2c3", "#a1b2c3d4", "#ggg", "fff", "#ff", "#fffff", "#1234567", "#", "", "#FFF "],
    "rgb": ["rgb(0,0,0)", "rgb(255, 255, 255)", "rgb( 1 , 2 , 3 )", "rgb(256,0,0)", "rgb(01,0,0)", "rgb(10%,20%,30%)",
            "rgb(100%,100%,100%)", "rgb(1,2%,3)", "rgb(1,2)", "rgb(1,2,3,4)", "RGB(1,2,3)", "rgb(1,2,3) ", "rgb(-1,0,0)",
            "rgb(255%,0%,0%)", "rgb(1,2,3", "rgb(1.5,2,3)", "rgb(\t1,\n2,\r3\f)", ""],
    "rgba": ["rgba(0,0,0,0)", "rgba(0,0,0,1)", "rgba(0,0,0,0.5)", "rgba(10%,20%,30%,0.1)", "rgba(0,0,0,1.0)",
             "rgba(0,0,0,0.05)", "rgba(0,0,0,.5)", "rgba(1,2,3)", "rgba(255,255,255,2)", "rgba(0,0,0,0.)",
             "rgba(0,0,0,0x)", "rgba(1, 2, 3, 0.25)", "rgba(1,2%,3,1)", "rgba(0,0,0,0.5 )", "rgba(0,0,0,01)", ""],
    "hsl": ["hsl(0,0%,0%)", "hsl(360, 100%, 100%)", "hsl(361,0%,0%)", "hsl(120,50,50)", "hsl(120,101%,50%)",
            "hsl(0,0%,0%", "hsl(001,0%,0%)", "hsl( 120 , 50% , 50% )", "hsl(120,50%)", "HSL(1,1%,1%)", ""],
    "hsla": ["hsla(0,0%,0%,0)", "hsla(360,100%,100%,1)", "hsla(10,20%,30%,0.4)", "hsla(10,20%,30%)",
             "hsla(10,20%,30%,0.04)", "hsla(10,20%,30%,1.0)", "hsla(10,20%,30%,2)", "hsla(361,20%,30%,1)", ""],
    "cmyk": ["cmyk(0%,0%,0%,0%)", "cmyk(100%, 50%, 25%, 0%)", "cmyk(101%,0%,0%,0%)", "cmyk(0%,0%,0%)",
             "cmyk(05%,0%,0%,0%)", "cmyk(0%,0%,0%,0% )", " cmyk(0%,0%,0%,0%)", "cmyk(0,0,0,0)", "cmyk( 0%,0%,0%,0%)", ""],
    "isbn10": ["0-306-40615-2", "0306406152", "080442957X", "0-8044-2957-X", "0306406153", "0 306 40615 2", "030640615",
               "03064061522", "0-3-0-6-4-0-6-1-5-2", "0306406152 ", "0-306-40615-2-", "080442957x", "---0306406152", "0-3-0-6406152", ""],
    "isbn13": ["978-3-16-148410-0", "9783161484100", "978-0-306-40615-7", "9783161484101", "9770306406157",
               "979-10-90636-07-1", "978 3 16 148410 0", "9780306406157", "978-0-306-4061-57", "97803064061577", "978030640615", ""],
    "isbn": ["978-3-16-148410-0", "0-306-40615-2", "080442957X", "0306406153", "9783161484101", "978-0-306-40615-7", "1234567890", ""],
    "issn": ["0378-5955", "0317-8471", "2434-561X", "2434-5611", "03785955", "0378-595", "0378-5955X", "1050-124X", "1050-124x", ""],
    "eth_addr": ["0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
                 "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26",
                 "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0x", "0x123", "52908400098527886E0F7030069857D2E4169EE7",
                 "0X52908400098527886E0F7030069857D2E4169EE7", "0x52908400098527886E0F7030069857D2E4169EEG", ""],
    "eth_addr_checksum": ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                          "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
                          "0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
                          "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26",
                          "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                          "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAEd", "0x"],
    "btc_addr": ['3R2cuenjG5nFubqX9Wzuukdin2YfLYZyD1', '3Yg3NMrPjaD4Z95AnyyExy1tiz8ZBycf7WQ', '11A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                 "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "0A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                 "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf", "1111111111111111111114oLvT2", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNO",
                 "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNal", "1" * 26, "1" + "z" * 34, ""],
    "btc_addr_bech32": ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ",
                        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc1sw50qgdz25j",
                        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "Bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
                        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "bc1", "bc1q", ""],
    "uuid3_rfc4122": ["6ba7b810-9dad-31d1-80b4-00c04fd430c8", "6ba7b810-9dad-31d1-c0b4-00c04fd430c8",
                      "6BA7B810-9DAD-31D1-80B4-00C04FD430C8", U, "6ba7b810-9dad-41d1-80b4-00c04fd430c8"],
    "uuid4_rfc4122": ["6ba7b810-9dad-41d1-80b4-00c04fd430c8", "6ba7b810-9dad-41d1-c0b4-00c04fd430c8",
                      "6BA7B810-9DAD-41D1-80B4-00C04FD430C8", "6ba7b810-9dad-41d1-b0b4-00c04fd430c8", "6ba7b810-9dad-41d1-Bab4-00c04fd430c8"],
    "uuid5_rfc4122": ["6ba7b810-9dad-51d1-80b4-00c04fd430c8", "6ba7b810-9dad-51d1-70b4-00c04fd430c8",
                      "6BA7B810-9DAD-51D1-90B4-00C04FD430C8", "6ba7b810-9dad-51d1-a0b4-00c04fd430c8"],
    "ulid": ["7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01arz3ndektsv4rrffq69g5fav", "01ARZ3NDEKTSV4RRFFQ69G5FA", "01ARZ3NDEKTSV4RRFFQ69G5FAVV",
             "01ARZ3NDEKTSV4RRFFQ69G5FAU", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "0000000000000000000000000I",
             "01ARZ3NDEKTſV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV", ""],
    "base32": ["MFRGG===", "MFRGGZDF", "MFRGGZDFMY======", "MFRGGZDFMZTQ====", "mfrgg===", "MFRGG", "MFRG1===", "MFRGG==",
               "========", "", "MFRGGZDF=", "AAAAAAAA", "MFRGGZDFMZTWQ===", "MFRGGZD=", "MFRGGZ==", "ME======"],
    "multibyte": ["abc", "ä", "日本語", "", "a\x80", "\xff", "abcé", "a\x00b", "\x7f"],
    "datauri": ["data:,Hello%20World", "data:,", "data:text/plain;base64,", "data:foo,SGVsbG8=", "data:;charset=utf-8,a", "data:text/plain;charset=utf-8;base64,QUJD", "data:a/b;c,d", "data:,%zz", "data:,a b", "data:text/plain;base64,SGVsbG8=", "data:image/png;base64,iVBORw0KGgo=", "data:,QUJD", "data:text/plain,hello",
                "data:text/plain;base64,", "dat:x,QUJD", "data:text/plain;base64,QUJD,QUJD", "data:text/plain;base64",
                "DATA:text/plain;base64,QUJD", "data:;base64,QUJD", "data:text/plain;base64,QUJ", "", "xdata:,QUJD"],
    "alphaunicode": ["abc", "日本語", "Ünïcödé", "abc1", "", "a b", "Σίσυφος",
                     "١٢٣", "a_b", "ǅ", "\xc3\x28", "ª", "Ⅰ", "²", "ͅ", "̀", "á"],
    "alphanumunicode": ["abc123", "日本語1", "١٢٣", "Ⅷ", "²", "a-b", "", "½", "๑a", "abc\xff", "ͅ"],
    "cidrv4": ["10.0.0.0/8", "10.0.0.1/8", "192.168.1.0/24", "0.0.0.0/0", "1.2.3.4/32", "::/0", "2001:db8::/32", "::ffff:1.2.3.4/96",
               "::ffff:0.0.0.0/96", "10.0.0.0/33", "10.0.0.0/08", "10.0.0.0", "/8", "01.0.0.0/8", "1.2.3.4/-1", "1.2.3.4/", ""],
    "cidrv6": ["::/0", "2001:db8::/32", "2001:db8::1/128", "fe80::1/64", "::1/128", "::ffff:1.2.3.4/96", "::ffff:1.2.3.4/128",
               "2001:db8::/129", "2001:db8::/032", "10.0.0.0/8", "fe80::1%eth0/64", "2001:db8::", "", "1:2:3:4:5:6:7:8/64"],
    "fqdn": ["example.com", "example.com.", "a.b.c.d.example.org", "localhost", "a.b", "1.2.3.4", "a.1", "a-.com", "-a.com", "a..b",
             "example.com..", "a.b-", "xn--bcher-kva.example", "a" * 63 + ".com", "a" * 64 + ".com", ".".join(["a" * 63] * 4) + ".com",
             "exa_mple.com", ".", " ", "ü.com", "example.c0m", "example.123", "a.b.", "1.2.3.a", "a.-b"],
    "dns_rfc1035_label": ["a", "abc", "a-b", "a1", "1a", "a-", "-a", "A", "a" * 63, "a" * 64, "", "a_b", "a--b", "a.b", "ab1-c2"],
    "hostname_rfc952": ["example.com", "a", "1a.com", "a-b.c", "-a", "a-", "a.1b", "a..b", "ü", "a" * 63, "a" * 64 + ".x",
                        ".".join(["a" * 63] * 4), "A.B", "a.b-", "1.2.3.4", ""],
    "hostname_port": ["example.com:+80", "example.com:80", "localhost:8080", ":80", "1.2.3.4:80", "[::1]:80", "::1:80", "example.com", "example.com:",
                      "example.com:0", "example.com:65535", "example.com:65536", "example.com:+80", "example.com:-1", "example.com:http",
                      "[host]:80", "host:80:90", "[example.com]:443", "a_b:80", "example.com:080", " example.com:80", "[::1", "[]:80",
                      "a[b]:80", "example.com:0080", "example.com:" + "9" * 12, ".".join(["a" * 63] * 4) + ".com:80"],
    "origin": ["https://example.com", "http://example.com:8080", "https://example.com/", "https://example.com/a", "https://example.com?x",
               "https://example.com#", "https://user@example.com", "ftp://example.com", "HTTPS://EXAMPLE.COM", "http://[::1]:80",
               "http://[::1]", "http://1.2.3.4", "http://a:0", "http://a:65536", "http://a:", "http://", "example.com",
               "http://exa mple.com", "http://a.b:80:90", "http://::1", "http://[1.2.3.4]", "http://%61.com", "http://[fe80::1%25en0]",
               "//example.com", "http:example.com", "http://a/b", "http://-a.com", "https://a.b.c:443", "http://a:00080",
               "http://[::1]:", "http://[::1]x", "http://@a", "https://" + ".".join(["a" * 63] * 4) + ".com"],
    "urn_rfc2141": ["urn:isbn:0451450523", "urn:ietf:rfc:2648", "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", "URN:ISBN:0451450523",
                    "urn:a:b", "urn:-a:b", "urn:a-:b", "urn::b", "urn:isbn:", "urn:isbn", "isbn:0451", "urn:isbn:04 51", "urn:isbn:%41",
                    "urn:isbn:%4", "urn:isbn:%zz", "urn:isbn:a/b?c#d", "urn:isbn:a=b", "urn:" + "a" * 32 + ":x", "urn:" + "a" * 33 + ":x",
                    "urn:example:a~b", "urn:urn:x", "urn:ab:c", "urn:a1:b", "urn:ab-c:d", "urn:ab:cä", "urn:ab:c d", "urn:ab:c%", ""],
    "urn_rfc8141": ["urn:example:a123,z456", "urn:example:a123,z456?+abc", "urn:example:a123,z456?=xyz", "urn:example:a123?+r?=q#f",
                    "urn:example:1/406/47452/2#f", "urn:example:a?", "urn:example:a#", "urn:example:a?+", "urn:example:a?=", "urn:example:a/b",
                    "urn:example:/a", "urn:example:a b", "urn:a:b", "urn:ab:c", "urn:ab-:c", "urn:isbn:0451450523", "URN:EXAMPLE:A", "urn:example:",
                    "urn:example:a%41", "urn:example:a%4", "urn:example:a?+b?+c", "urn:example:a?=b?=c", "urn:example:a#b#c", "urn:example:a?+b#",
                    "urn:example:a?+b?=c#d", "urn:example:a?b", "urn:example:a?+/?", "urn:example:a:b@c", "urn:example:a[b]", "urn:example:a#/?", ""],
    "html_encoded": ["&lt;", "&amp;", "&#x41;", "&#65;", "&#6", "hello", "<b>", "&quot;", "a &gt b", "&amp", "&#xzz;", "&lt", "& lt;", "&gt;&lt;", "",
                     "&#X41;", "&#xa", "&#ab", "&apos;", "&nbsp;", "&amp;amp;"],
    "url_encoded": ["a%20b", "%", "%2", "%zz", "%41%42", "100%", "a b", "", "%%41", "a%2Fb", "%C3%A4", "ä", "a+b", "%4G", "x%", "%00"],
    "tcp4_addr": ["1.2.3.4:80", "1.2.3.4", "1.2.3.4:", "1.2.3.4:0", "1.2.3.4:65535", "1.2.3.4:65536", "1.2.3.4:http", "1.2.3.4:080",
                  "256.1.1.1:80", "localhost:80", "[::1]:80", "::1", "01.2.3.4:80", "::ffff:1.2.3.4:80", "[::ffff:1.2.3.4]:80",
                  "1.2.3.4:80:80", ":80", "1.2.3.4:-1", "1.2.3.4:+80", "1.2.3.4: 80", "1.2.3.4:0000080", "", "1.2.3.4:https"],
    "tcp6_addr": ["]:80", "[::1]:80", "[2001:db8::1]:443", "[::1]", "::1", "[::1]:", "[::1]:http", "[fe80::1%eth0]:80", "[::ffff:1.2.3.4]:80",
                  "1.2.3.4:80", "[1.2.3.4]:80", "[::1]:65536", "[::1]:0", "[::1]:80x", "[:::1]:80", "[::1]:80]", "[[::1]:80",
                  "[2001:DB8::1]:8080", "[::ffff:0102:0304]:80", "::1:80", "[::1]:https", ""],
    "tcp_addr": ["]:80", "1.2.3.4:80", "[::1]:80", "1.2.3.4", "::1", "[::ffff:1.2.3.4]:80", "localhost:80", "1.2.3.4:", "[::1]:", "[::1]:ssh",
                 "1.2.3.4:65536", "[2001:db8::1]:443", "[::]:0", "0.0.0.0:0", ""],
    "udp4_addr": ["1.2.3.4:53", "1.2.3.4", "1.2.3.4:", "1.2.3.4:0", "1.2.3.4:65536", "1.2.3.4:domain", "::ffff:1.2.3.4:53", "[::1]:53",
                  "1.2.3.4:053", "localhost:53", ""],
    "udp6_addr": ["]:80", "[::1]:53", "[2001:db8::1]:53", "[::1]", "::1", "[::1]:", "[::ffff:1.2.3.4]:53", "1.2.3.4:53", "[::1]:domain", "[fe80::1%eth0]:53", ""],
    "udp_addr": ["]:80", "1.2.3.4:53", "[::1]:53", "1.2.3.4", "[::ffff:1.2.3.4]:53", "[::1]:", "1.2.3.4:domain", "localhost:53", ""],
    "ip4_addr": ["1.2.3.4", "::ffff:1.2.3.4", "1.2.3.4:80", "0.0.0.0", "255.255.255.255", "01.2.3.4", "1.2.3", "localhost", "::1", "", "1.2.3.4 "],
    "ip6_addr": ["::1", "2001:db8::1", "::ffff:1.2.3.4", "fe80::1%eth0", "[::1]", "1.2.3.4", "", "::", "1:2:3:4:5:6:7:8", "1::2::3"],
    "ip_addr": ["1.2.3.4", "::1", "::ffff:1.2.3.4", "fe80::1%eth0", "localhost", "1.2.3.4:80", "[::1]", "", "256.0.0.1", "::"],
    "iso3166_1_alpha2": ["US", "CZ", "us", "XX", "", "USA", "840", "GB", "UK", "EU", "AX", "XK", "ZZ", "U", "US ", "cz"],
    "iso3166_1_alpha2_eu": ["CZ", "DE", "FR", "US", "GB", "GR", "EL", "de", "", "HR", "SE"],
    "iso3166_1_alpha3": ["USA", "CZE", "XXX", "usa", "US", "GBR", "UKR", "", "ABW", "XKX", "ZZZ", "USAA"],
    "iso3166_1_alpha3_eu": ["CZE", "DEU", "USA", "GBR", "GRC", "", "deu", "SWE"],
    "iso3166_1_alpha_numeric": ["840", "203", "004", "4", "0840", "1840", "-840", "+840", "000", "999", "  840", "840 ", "8x0", "", "040", "40", "1000", "203.0"],
    "iso3166_1_alpha_numeric_eu": ["203", "276", "840", "40", "040", "1203", "+276", ""],
    "iso4217": ["USD", "CZK", "EUR", "usd", "XXX", "XTS", "XAU", "ABC", "", "EURO", "GBP", "BTC", "USN", "EU", "XDR"],
    "iso4217_numeric": ["840", "203", "978", "8", "008", "0840", "999", "000", "-840", "8x", "", "0", "00", "985", "+840", "1840", "٨٤٠"],
    "bcp47_language_tag": ["en", "en-US", "en-us", "zh-Hant-TW", "sr-Latn-RS", "de-CH-1996", "en-US-x-twain", "x-private", "i-klingon", "en_US",
                           "xx", "xxx", "123", "e", "", "en-", "-en", "en--US", "zh-cmn-Hans-CN", "en-a-bbb-x-a-ccc", "en-u-ca-gregory", "es-419",
                           "en-Latn-US-boont", "sl-rozaj-biske", "hy-Latn-IT-arevela", "de-DE-u-co-phonebk", "qaa", "en-US-x-", "abcde", "abcdefgh",
                           "abcdefghi", "en-ABCDEFGHI", "en-1234", "fr-FR-1606nict", "ja-Latn-hepburn-heploc", "art-lojban", "zh-min-nan", "EN-us",
                           "en-US-US", "en-a", "en-a-b", "en-x", "x", "i-default", "sgn-BE-FR", "abcd", "abcd-efgh", "en-ZZ", "en-Zzzz", "und", "root"],
    "bcp47_strict_language_tag": ["en", "en-US", "en-us", "zh-Hant-TW", "sr-Latn-RS", "de-CH-1996", "en-US-x-twain", "x-private", "i-klingon", "en_US",
                                  "xx", "xxx", "123", "e", "", "en-", "zh-cmn-Hans-CN", "en-a-bbb-x-a-ccc", "es-419", "en-Latn-US-boont",
                                  "sl-rozaj-biske", "qaa", "abcde", "abcd", "en-1234", "fr-FR-1606nict", "art-lojban", "zh-min-nan", "EN-us",
                                  "en-US-US", "en-a-bbb", "x-a-b-c", "x-abcdefghi", "und", "yue-HK", "zh-yue-HK", "en-yue", "sgn-BE-FR", "de-1901", "en-US-1996"],
    "bic_iso_9362_2014": ["DEUTDEFF", "DEUTDEFF500", "deutdeff", "DEUTDEF", "DEUTDEFF50", "DEUT1EFF", "DEUTDE1F", "12345678", "DEUTDEFFXXX", "AAAA", "", "DeUtDeFf", "DEUTDEFF5000"],
    "bic": ["DEUTDEFF", "DEUTDEFF500", "deutdeff", "DEUTDEF", "DEUT1EFF", "DEUTDE1F", "1234DEFF", "D3UTDEFF", "DEUTDEFFXXX", "AAAA", "", "DEUTDEFF50", "DEUTDEFF5000", "DEUTDEF1"],
    "credit_card": ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111112", "378282246310005", "3782 8224 6310 005",
                    "6011111111111117", "30569309025904", "5555555555554444", "4222222222222", "0000000000000", "411111111111", "41111111111111111111",
                    "4111  1111 1111 1111", "41 11 1111 1111 1111", "1234567890123456", "4111 1111 1111 111a", " 4111111111111111", "",
                    "0000 0000 0000", "4111 1111 1111 1111 1111", "4111 1111 1111 1111 111", "٤111111111111111"],
    "luhn_checksum": ["4111111111111111", "79927398713", "79927398710", "0", "00", "18", "19", "1a", "12 34", "-18", "  ", "5555555555554444",
                      "1234567812345670", "٣", "", "000", "1", "+18", "0000000000"],
    "cve": ["CVE-2021-0000", "CVE-2021-00001", "CVE-1998-1234", "CVE-2021-1234567890123456789", "CVE-2021-12345678901234567890", "CVE-2021-44228", "CVE-1999-0001", "CVE-1999-0000", "CVE-2000-0001", "CVE-1998-1234", "CVE-2021-1234567", "CVE-2021-0100",
            "CVE-2021-0010", "CVE-2021-0001", "CVE-2021-001", "cve-2021-1234", "CVE-2021-0a01", "CVE-2021-01é1", "CVE-2021-12345",
            "CVE-2021-00012", "CVE-3000-1234", "CVE-2021-", "CVE-2021-0000", "CVE-2021-0x01", "CVE-2021-00-1", "CVE-20211-1234", ""],
    "ssn": ["123-45-6789", "123 45 6789", "123-45-6780", "123-00-6789", "000-12-3456", "123456789", "123-45-0000", "123_45_6789", "123-4-56789",
            "666-12-3456", "987-65-4321", "12a-45-6789", "123-45-6789 ", "", "123.45.6789", "123-45 6789", "123-10-0001", "123-45-0001", "123-45-6789\n"],
    "ein": ["12-3456789", "123456789", "12-345678", "12-34567890", "1-23456789", "ab-cdefghi", "12–3456789", "٣٣-٣٣٣٣٣٣٣", "12-3456789\n", ""],
    "cron": ["* * * * *", "0 0 * * *", "*/5 * * * *", "0 0 1 1 *", "@daily", "@yearly", "@hourly", "@reboot", "@every 1h30m", "@every 5s",
             "@every 1", "@every", "@every 1h 30m", "@weekly", "@foo", "0 0 * * * *", "0 0 * * * * *", "0 0 * * * * * *", "* * * *", "0 0 L * *",
             "0 9-17 * * MON-FRI", "0 0 1,15 * *", "? ? ? ? ?", "0 0 ? * 5#2", "  * * * * *", "* * * * * ", "a b c d e", "aa bb cc dd ee",
             "0 0 * * a", "@every 1µs", "@every 100ms", "@every 1x", "*  *  *  *  *", "@every 1m5s", "@every 1ms", "@every 1hh", "@annually", "@monthly",
             "0 0 * * *\t", "*/5 * * * * *", "-1 * * * *", "1/2 * * * *"],
})


ALPHABET = "aZ09-._:/@%+=#?[]~ \x00\x7f\xc3\xa4\xff"
# Characters the grammars of the second-wave formats hinge on; used for those only.
ALPHABET_X = ALPHABET + "(),;&*!$'<>\\|{}\"^`xX"


def mutate(rng, s, alphabet=ALPHABET):
    b = bytearray(s.encode("utf-8", "surrogateescape"))
    op = rng.randrange(5)
    pos = rng.randrange(len(b) + 1)
    ch = alphabet[rng.randrange(len(alphabet))].encode("latin-1")
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


NEW_FORMATS = set("""hexcolor rgb rgba hsl hsla cmyk isbn isbn10 isbn13 issn eth_addr eth_addr_checksum btc_addr btc_addr_bech32 uuid3_rfc4122 uuid4_rfc4122 uuid5_rfc4122 ulid base32 multibyte datauri alphaunicode alphanumunicode cidrv4 cidrv6 fqdn dns_rfc1035_label hostname_rfc952 hostname_port origin urn_rfc2141 urn_rfc8141 html_encoded url_encoded tcp4_addr tcp6_addr tcp_addr udp4_addr udp6_addr udp_addr ip4_addr ip6_addr ip_addr iso3166_1_alpha2 iso3166_1_alpha2_eu iso3166_1_alpha3 iso3166_1_alpha3_eu iso3166_1_alpha_numeric iso3166_1_alpha_numeric_eu iso4217 iso4217_numeric bcp47_language_tag bcp47_strict_language_tag bic_iso_9362_2014 bic credit_card luhn_checksum cve ssn ein cron""".split())


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
            alpha = ALPHABET_X if fmt in NEW_FORMATS else ALPHABET
            m = mutate(rng, base.decode("utf-8", "surrogateescape"), alpha)
            if rng.randrange(3) == 0:
                m = mutate(rng, m.decode("latin-1"), alpha)
                m = m if isinstance(m, bytes) else m
            if m not in seen:
                seen.add(m)
                cases.append((fmt, m))
            n += 1
    return cases


def go_verdicts(cases):
    """Go's verdicts; a case is (format, s) or (raw go tag, s)."""
    payload = json.dumps([{"tag": TAGS.get(f, f), "v": base64.b64encode(s).decode(), "int": f in INT_FORMATS}
                          for f, s in cases])
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
    out += [("ip", s) for f, s in cases if f in ("ipv4", "ipv6", "ip4_addr", "ip6_addr") and mapped(s)]
    out += [("cidr", s) for f, s in cases if f in ("cidrv4", "cidrv6") and mapped(s)]
    out += [(f, alpha_sub(s)) for f, s in cases if f in ("rgba", "hsla") and alpha_sub(s) not in (None, s)]
    return out


def mapped(s):
    return b"::ffff:" in s.lower()


WS = rb"[ \t\n\f\r]"


def alpha_sub(s):
    """rgba / hsla: `s` with its alpha token replaced by `1` when this module's profile
    (0, 1, 0.d+, 1.0+) takes it and by `x` when not; None when `s` has no alpha slot.
    go's verdict on the result says whether the rest of the string is fine."""
    m = re.fullmatch(rb"(.*," + WS + rb"*)([^,() \t\n\f\r]*)(" + WS + rb"*\))", s, re.S)
    if not m:
        return None
    ok = re.fullmatch(rb"0|1|0\.[0-9]+|1\.0+", m.group(2)) is not None
    return m.group(1) + (b"1" if ok else b"x") + m.group(3)


def max_host_run(s):
    runs = re.findall(rb"[A-Za-z0-9.\-]+", s)
    return max((len(r) for r in runs), default=0)


B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def py_bech32(s):
    """A mainnet segwit address per BIP 173 / BIP 350: go's checks, with the bech32m constant
    for witness versions 1..16."""
    t = s.decode("latin-1")
    if not re.fullmatch(r"bc1[02-9ac-hj-np-z]{7,76}|BC1[02-9AC-HJ-NP-Z]{7,76}", t) or len(t) % 8 in (0, 3, 5):
        return False
    t = t.lower()
    dp = [B32.index(c) for c in t[3:]]
    ver = dp[0]
    if ver > 16 or (ver == 0 and len(t) not in (42, 62)):
        return False
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    p = 1
    for v in [3, 3, 0, 2, 3] + dp:
        b = p >> 25
        p = ((p & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                p ^= gen[i]
    if p != (1 if ver == 0 else 0x2bc830a3):
        return False
    n = len(dp) - 7
    pad = n * 5 % 8
    if pad and dp[n] & ((1 << pad) - 1):
        return False  # BIP 173: "MUST be all zeroes"
    return 2 <= n * 5 // 8 <= 40


def py_btc(s):
    """Base58Check by big integer, not by the Zig code's byte loop."""
    a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    t = s.decode("latin-1")
    if not 26 <= len(t) <= 35 or t[0] not in "13" or any(c not in a for c in t):
        return False
    n = 0
    for c in t:
        n = n * 58 + a.index(c)
    if n >> 200:
        return False
    b = n.to_bytes(25, "big")
    if b[0] != (0 if t[0] == "1" else 5):
        return False
    if len(t) - len(t.lstrip("1")) != len(b) - len(b.lstrip(b"\0")):
        return False
    return hashlib.sha256(hashlib.sha256(b[:21]).digest()).digest()[:4] == b[21:]


def py_datauri(s):
    tok = r"[!#$%&'*+\-.0-9A-Z^_`a-z{|}~]+"
    uric = r"(?:[A-Za-z0-9;/?:@&=+$,\-_.!~*'()]|%[0-9A-Fa-f]{2})*"
    pv = r"(?:[A-Za-z0-9/?:@&=+$\-_.!~*'()]|%[0-9A-Fa-f]{2})*"
    head = rf"data:(?:{tok}/{tok})?(?:;{tok}={pv})*"
    t = s.decode("latin-1")
    return (re.fullmatch(head + r";base64,(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", t) is not None
            or re.fullmatch(head + "," + uric, t) is not None)


GRANDFATHERED = ("en-gb-oed|i-ami|i-bnn|i-default|i-enochian|i-hak|i-klingon|i-lux|i-mingo|i-navajo|i-pwn|i-tao|i-tay|"
                 "i-tsu|sgn-be-fr|sgn-be-nl|sgn-ch-de|art-lojban|cel-gaulish|no-bok|no-nyn|zh-guoyu|zh-hakka|zh-min|"
                 "zh-min-nan|zh-xiang")


def py_lang(s, strict):
    """RFC 5646 section 2.1 well-formed (grandfathered, privateuse or langtag); strict: a 2-3 letter language."""
    lang = r"[a-z]{2,3}(?:-[a-z]{3}){0,3}" + ("" if strict else r"|[a-z]{4}|[a-z]{5,8}")
    langtag = (r"(?:" + lang + r")(?:-[a-z]{4})?(?:-(?:[a-z]{2}|[0-9]{3}))?(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*"
               r"(?:-[0-9a-wyz](?:-[a-z0-9]{2,8})+)*(?:-x(?:-[a-z0-9]{1,8})+)?")
    return re.fullmatch("(?:" + GRANDFATHERED + r")|x(?:-[a-z0-9]{1,8})+|" + langtag, s.decode("latin-1"), re.I | re.A) is not None


def py_sock6(s):
    m = re.fullmatch(rb"\[([0-9A-Fa-f:.]+)\]:([0-9]+)", s)
    if not m or int(m.group(2)) > 65535:
        return False
    try:
        ipaddress.IPv6Address(m.group(1).decode())
        return True
    except ValueError:
        return False


PCH = r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})"


def py_urn2141(s):
    # RFC 2141 2.1: the NID "urn" MUST NOT be used; 2.3.2: "/", "?", "#" are reserved, %-encode them.
    return re.fullmatch(r"(?i:urn):(?!(?i:urn):)[A-Za-z0-9][A-Za-z0-9\-]{0,31}:(?:[A-Za-z0-9()+,\-.:=@;$_!*']|%[0-9A-Fa-f]{2})+",
                        s.decode("latin-1")) is not None


def py_urn8141(s):
    return re.fullmatch(r"(?i:urn):[A-Za-z0-9][A-Za-z0-9\-]{0,30}[A-Za-z0-9]:" + PCH.replace("(?:", "(?:", 1) + r"(?:" + PCH + r"|/)*"
                        r"(?:\?\+" + PCH + r"(?:" + PCH + r"|[/?])*)?(?:\?=" + PCH + r"(?:" + PCH + r"|[/?])*)?(?:#(?:" + PCH + r"|[/?])*)?",
                        s.decode("latin-1")) is not None


SOCKS = ("tcp4_addr", "tcp6_addr", "tcp_addr", "udp4_addr", "udp6_addr", "udp_addr")


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
     lambda f, s, go: f in ("ipv4", "ipv6", "ip4_addr", "ip6_addr") and mapped(s) and AUX.get(("ip", s), False) and go == (f in ("ipv4", "ip4_addr")),
     lambda f, s, go: f in ("ipv6", "ip6_addr")),
    ("HOSTNAME_253", "GO DEFECT: go's hostname_rfc1123 (and hostname_rfc952, hostname_port, origin) has no total length limit; a name is at most 253 characters (RFC 1035 2.3.4: 255 octets on the wire)",
     lambda f, s, go: f in ("hostname", "hostname_rfc952", "hostname_port", "origin") and go and max_host_run(s) > 253,
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
     lambda f, s, go: f in ("cidr", "cidrv4", "cidrv6") and go and b"/0" in s and not s.endswith(b"/0"),
     lambda f, s, go: False),
    ("DT_OFFSET_24", "GO DEFECT: go's datetime (time.Parse RFC 3339) takes a +24:00 offset; RFC 3339 5.6 time-numoffset hour is 00-23",
     lambda f, s, go: f == "date_time" and go and (dt_offset(s) or b"")[:1] in (b"+", b"-") and (dt_offset(s) or b"")[1:3] >= b"24",
     lambda f, s, go: False),
    ("DT_PROFILE", "profile: date_time also takes lower-case t/z (RFC 3339 5.6 NOTE), a leap second at any time of day and an offset-less local time (SPEC Format; review M4, owner's call); go's time.Parse takes none of them",
     lambda f, s, go: f == "date_time" and not go and dt_norm(s) != s and AUX.get(("datetime=2006-01-02T15:04:05Z07:00", dt_norm(s)), False),
     lambda f, s, go: True),
    ("CIDR_MAPPED", "GO DEFECT: go's cidrv4 takes the IPv6 text ::ffff:a.b.c.d/n (net.IP.To4) and its cidrv6 refuses it; RFC 4291 2.5.5.2 makes it an IPv6 prefix",
     lambda f, s, go: f in ("cidrv4", "cidrv6") and mapped(s) and AUX.get(("cidr", s), False) and go == (f == "cidrv4") and not re.search(rb"/0[0-9]", s),
     lambda f, s, go: f == "cidrv6"),
    ("SOCK6_MAPPED", "GO DEFECT: go's tcp6_addr/tcp_addr/udp6_addr/udp_addr refuse [::ffff:a.b.c.d]:port (net.IP.To4); RFC 4291 2.5.5.2 makes it an IPv6 address",
     lambda f, s, go: f in ("tcp6_addr", "tcp_addr", "udp6_addr", "udp_addr") and not go and mapped(s) and py_sock6(s),
     lambda f, s, go: True),
    ("ADDR_PORT_NUMERIC", "profile: syntax only, so the port is 1+ decimal digits, 0-65535; go also resolves an empty port (host:) and a service name (host:http) through the system resolver",
     lambda f, s, go: f in SOCKS and go and re.fullmatch(rb"[0-9]+", s.rsplit(b":", 1)[-1]) is None,
     lambda f, s, go: False),
    ("URN2141_PCT", "GO DEFECT: go-urn's RFC 2141 parser takes any two characters after a percent sign (urn:isbn:%zz); RFC 2141 2.2 requires two hex digits",
     lambda f, s, go: f == "urn_rfc2141" and go and re.search(rb"%(?![0-9A-Fa-f]{2})", s) is not None,
     lambda f, s, go: False),
    ("BTC_ADDR_STRUCTURE", "GO DEFECT: go checks only the checksum of the low 25 bytes, so a wrong version byte, a number past 25 bytes and an extra leading 1 pass; a P2PKH address is version 0, a P2SH address version 5, 25 bytes (en.bitcoin.it Base58Check encoding)",
     lambda f, s, go: f == "btc_addr" and go and not py_btc(s),
     lambda f, s, go: False),
    ("DATAURI_RFC2397", "GO DEFECT: go reads whatever follows the first comma as base64 and ignores the head; RFC 2397 3: dataurl := \"data:\" [ mediatype ] [ \";base64\" ] \",\" data, and without ;base64 the data is URL characters",
     lambda f, s, go: f == "datauri" and go != py_datauri(s),
     lambda f, s, go: py_datauri(s)),
    ("CVE_SCHEMA", "GO DEFECT: go's cve regex writes [^0] where a digit is meant and adds year and leading-zero rules; CVE JSON 5 schema cveId: ^CVE-[0-9]{4}-[0-9]{4,19}$",
     lambda f, s, go: f == "cve" and go != (re.fullmatch(rb"CVE-[0-9]{4}-[0-9]{4,19}", s) is not None),
     lambda f, s, go: re.fullmatch(rb"CVE-[0-9]{4}-[0-9]{4,19}", s) is not None),
    ("ULID_OVERFLOW", "GO DEFECT: go takes a first character above 7; ulid/spec: the largest valid ULID is 7ZZZZZZZZZZZZZZZZZZZZZZZZZ, anything larger should be rejected to prevent overflow bugs",
     lambda f, s, go: f == "ulid" and go and s[:1] not in (b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7") and all(c < 0x80 for c in s),
     lambda f, s, go: False),
    ("FQDN_LDH", "GO DEFECT: go takes a label ending in a hyphen; RFC 5321 4.1.2: Ldh-str = *( ALPHA / DIGIT / \"-\" ) Let-dig",
     lambda f, s, go: f == "fqdn" and go and re.search(rb"-(?:\.|$)", s) is not None,
     lambda f, s, go: False),
    ("HOSTPORT_SIGN", "GO DEFECT: go reads the port with ParseInt, so host:+80 passes; RFC 3986 3.2.3: port = *DIGIT",
     lambda f, s, go: f == "hostname_port" and go and re.fullmatch(rb"[0-9]+", s.rsplit(b":", 1)[-1]) is None,
     lambda f, s, go: False),
    ("URN8141_QUERY", "GO DEFECT: go-urn refuses a second `?+` inside an r-component and a `?=` inside a q-component; RFC 8141 2 ABNF: r-component = pchar *( pchar / \"/\" / \"?\" ), q-component likewise",
     lambda f, s, go: f == "urn_rfc8141" and not go and py_urn8141(s),
     lambda f, s, go: True),
    ("BECH32M", "GO DEFECT: go's btc_addr_bech32 checks the bech32 constant for every witness version, so it refuses every taproot address; BIP 350 uses bech32m for versions 1-16",
     lambda f, s, go: f == "btc_addr_bech32" and go != py_bech32(s),
     lambda f, s, go: py_bech32(s)),
    ("ISO_NUMERIC_3_DIGITS", "profile: an ISO 3166-1 / 4217 numeric code is exactly three digits; go reads Atoi(s) % 1000 (so +840 and 1840 pass) and, for 4217, an integer (so 8 passes)",
     lambda f, s, go: f in ("iso3166_1_alpha_numeric", "iso3166_1_alpha_numeric_eu", "iso4217_numeric") and go and re.fullmatch(rb"[0-9]{3}", s) is None,
     lambda f, s, go: False),
    ("BCP47_TABLES", "profile: RFC 5646 2.1 syntax only; go consults x/text's CLDR tables (or the IANA registry for the strict form), so a well-formed tag with an unknown subtag (en-ZZ, xx) fails there",
     lambda f, s, go: f in ("bcp47_language_tag", "bcp47_strict_language_tag") and not go and py_lang(s, f.startswith("bcp47_strict")),
     lambda f, s, go: True),
    ("BCP47_LAXER", "profile: RFC 5646 2.1 syntax only; go's x/text also reads spellings the grammar does not have (en_US with an underscore, tags of unregistered shapes)",
     lambda f, s, go: f in ("bcp47_language_tag", "bcp47_strict_language_tag") and go and not py_lang(s, f.startswith("bcp47_strict")),
     lambda f, s, go: False),
    ("ULID_UNICODE_FOLD", "GO DEFECT: go's (?i) folds K to U+212A and S to U+017F, so a ULID may hold a Kelvin sign or a long s; ULID is Crockford base32 (ASCII)",
     lambda f, s, go: f == "ulid" and go and any(c >= 0x80 for c in s),
     lambda f, s, go: False),
    ("RGBA_ALPHA", "GO DEFECT: go's alpha is `(?:0.[1-9]*)|[01]` with an unescaped dot, so 0x and 0- pass while 0.05 and 1.0 fail; a CSS alpha is a number 0..1",
     lambda f, s, go: f in ("rgba", "hsla") and alpha_sub(s) is not None and AUX.get((f, alpha_sub(s)), go) != go,
     lambda f, s, go: AUX[(f, alpha_sub(s))]),
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
