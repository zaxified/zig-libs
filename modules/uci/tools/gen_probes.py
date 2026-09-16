#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hand-written grammar probe corpus.

Each probe isolates ONE documented grammar rule of the module (SPEC.md /
README.md / root.zig doc comment) so a DIFFER pins that exact rule against the
real libuci parser.

  gen_probes.py <out-dir>
"""
import os, sys

P = {
    # ── quoting / escaping ────────────────────────────────────────────────
    "q01_single_no_escape":     "config t\n\toption v 'a\\nb'\n",
    "q02_double_backslash_n":   'config t\n\toption v "a\\nb"\n',
    "q03_double_esc_quote":     'config t\n\toption v "a\\"b"\n',
    "q04_double_esc_squote":    "config t\n\toption v \"a\\'b\"\n",
    "q05_double_esc_bslash":    'config t\n\toption v "a\\\\b"\n',
    "q06_bare_backslash":       "config t\n\toption v a\\nb\n",
    "q07_bare_backslash_esc_sp": "config t\n\toption v a\\ b\n",
    "q08_concat_segments":      "config t\n\toption v 'a'\"b\"c\n",
    "q09_empty_single":         "config t\n\toption v ''\n",
    "q10_empty_double":         'config t\n\toption v ""\n',

    # ── comments ─────────────────────────────────────────────────────────
    "c01_hash_midword":         "config t\n\toption v a#b\n",
    "c02_hash_after_quote":     "config t\n\toption v 'a'#b\n",
    "c03_hash_start_of_token":  "config t\n\toption v 'a' # trailing\n",
    "c04_hash_in_squotes":      "config t\n\toption v 'a # b'\n",
    "c05_hash_full_line":       "# a comment\nconfig t\n\toption v x\n",
    "c06_hash_in_key":          "config t\n\toption a#b v\n",
    "c07_hash_in_type":         "config t#x\n\toption v y\n",

    # ── line structure ───────────────────────────────────────────────────
    "l01_multiline_single_q":   "config t\n\toption v 'line1\nline2'\n",
    "l02_multiline_double_q":   'config t\n\toption v "line1\nline2"\n',
    "l03_backslash_continue":   "config t\n\toption v abc\\\ndef\n",
    "l04_backslash_cont_dq":    'config t\n\toption v "abc\\\ndef"\n',
    "l05_crlf":                 "config t\r\n\toption v x\r\n",
    "l06_no_trailing_newline":  "config t\n\toption v x",
    "l07_semicolon_two_cmds":   "config t\n\toption a 1; option b 2\n",
    "l08_semicolon_config":     "config t; option a 1\n",

    # ── name / type / key character classes ──────────────────────────────
    "n01_name_with_dash":       "config t 'my-lan'\n\toption v x\n",
    "n02_name_with_dot":        "config t 'my.lan'\n\toption v x\n",
    "n03_name_with_space":      "config t 'my lan'\n\toption v x\n",
    "n04_name_at_bracket":      "config t '@t[0]'\n\toption v x\n",
    "n05_key_with_dash":        "config t\n\toption dest-port 1\n",
    "n06_key_with_dot":         "config t\n\toption a.b 1\n",
    "n07_key_with_space":       "config t\n\toption 'a b' 1\n",
    "n08_key_empty":            "config t\n\toption '' 1\n",
    "n09_type_empty":           "config ''\n\toption v x\n",
    "n10_type_with_space":      "config 'a b' 'n'\n\toption v x\n",
    "n11_type_high_byte":       "config t\xc3\xa9\n\toption v x\n",
    "n12_name_high_byte":       "config t 'n\xc3\xa9'\n\toption v x\n",
    "n13_key_high_byte":        "config t\n\toption k\xc3\xa9 v\n",
    "n14_name_equals":          "config t 'a=b'\n\toption v x\n",

    # ── control bytes in values ──────────────────────────────────────────
    "b01_value_vt":             "config t\n\toption v 'a\x0bb'\n",
    "b02_value_soh":            "config t\n\toption v 'a\x01b'\n",
    "b03_value_del":            "config t\n\toption v 'a\x7fb'\n",
    "b04_value_tab_quoted":     "config t\n\toption v 'a\tb'\n",
    "b05_value_high":           "config t\n\toption v 'a\xffb'\n",

    # ── section / option semantics ───────────────────────────────────────
    "s01_dup_named_section":    "config interface 'lan'\n\toption proto 'static'\n\nconfig interface 'lan'\n\toption proto 'none'\n",
    "s02_dup_named_diff_type":  "config interface 'lan'\n\toption a 1\n\nconfig rule 'lan'\n\toption b 2\n",
    "s03_dup_option":           "config t\n\toption k old\n\toption k new\n",
    "s04_list_accumulate":      "config t\n\tlist l a\n\tlist l b\n",
    "s05_option_then_list":     "config t\n\toption k v\n\tlist k w\n",
    "s06_list_then_option":     "config t\n\tlist k v\n\toption k w\n",
    "s07_empty_quoted_name":    "config t ''\n\toption v x\n",
    "s08_anon_sections":        "config rule\n\toption x 1\nconfig rule\n\toption x 2\n",
    "s09_option_no_section":    "option a b\n",
    "s10_config_no_type":       "config\n",
    "s11_option_no_value":      "config t\n\toption k\n",
    "s12_too_many_args":        "config t\n\toption k v extra\n",
    "s13_config_three_args":    "config a b c\n",
    "s14_bad_keyword":          "config t\nfoo bar\n",

    # ── package statement ────────────────────────────────────────────────
    "p01_package_line":         "package other\nconfig t\n\toption v x\n",
    "p02_package_twice":        "package a\nconfig t\n\toption v 1\npackage b\nconfig u\n\toption v 2\n",
    "p03_package_no_name":      "package\n",

    # ── unterminated ─────────────────────────────────────────────────────
    "u01_unterm_single":        "config t\n\toption v 'abc\n",
    "u02_unterm_double":        'config t\n\toption v "abc\n',
    "u03_trailing_backslash":   'config t\n\toption v "abc\\\n',
    "u04_lone_quote_eof":       "config t\n\toption v '\n",
}


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, body in P.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(body.encode("latin-1"))
    print(f"{len(P)} probes -> {out}")


if __name__ == "__main__":
    main()
