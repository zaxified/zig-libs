#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Capture how the REAL `uci` binary reads small config files, for the module's
# "real uci grammar capture" test (`src/root.zig`), which replays the result
# hermetically from `src/testdata/grammar_capture.txt`.
#
#   modules/uci/tools/capture-grammar.sh /path/to/uci > modules/uci/src/testdata/grammar_capture.txt
#
# The binary is a BLACK-BOX oracle only (root NOTICE §0). libuci is LGPL-2.1:
# build it, run it, never read or copy its source. One way to get a binary
# with no install (libubox is not needed):
#
#   git clone --depth 1 https://git.openwrt.org/project/uci.git uci && cd uci
#   printf '/* capture */\n' > uci_config.h
#   gcc -O1 -std=gnu99 -I. -DUCI_PREFIX='"/nonexistent"' -o uci \
#       libuci.c file.c util.c delta.c parse.c cli.c
#
# Each probe is a whole config file named `p`. The record is its bytes, and
# either `uci -c <dir> show p` stdout (exit 0) or `err` (non-zero exit). The
# module's test compares the load/refuse verdict and, for a load, the same
# `show` rendering of the parsed model.
#
# Audit A1 U8 (backslash outside quotes), U9 (`;`), U10 (empty values), U19
# (`package` line), U25 (a repeated section name), plus keyword forms. Two
# measured divergences are left out on purpose, because the module keeps its
# own stricter rule there (audit
# A1 U11): `list l ''` then `option l 'x'`, and `option v 'x'` then
# `list v ''`, both of which real uci merges and this module refuses -- the
# same holds when the two lines sit in two blocks of one merged section (U25).

set -euo pipefail

uci=${1:?usage: capture-grammar.sh /path/to/uci}
dir=$(mktemp -d)
trap 'rm -f "$dir/p"; rmdir "$dir"' EXIT

S="config t 'n'\n\t" # the section most probes put their line in

probes=(
  # U8: backslash outside quotes
  "${S}option v a\\\\nb\n"
  "${S}option v a\\\\ b\n"
  "${S}option v a\\\\\\\\b\n"
  "${S}option v a\\\\#b\n"
  "${S}option v a\\\\'b\n"
  "${S}option v ab\\\\\n\toption w c\n"
  "${S}option v 'x'\\\\'y'\n"
  "${S}option v\\\\ k x\n"
  "${S}option v \\\\\n"
  "${S}option v ab\\\\\ncd\n"
  "${S}option v ab\\\\"
  "${S}option v ab\\\\\r\ncd\n"
  "${S}option v \\\\\n\toption w x\n"
  "${S}option v 'a'\\\\\nb\n"
  "${S}option v \\\\t\n"
  "${S}option v a\\\\;b\n"
  "${S}option v a\\\\\"b\n"
  "conf\\\\ig t 'n'\n\toption v x\n"
  "${S}option v ab\\\\\n\n\toption w x\n"
  "${S}option a \"a\\\\\nb\"\n"
  "${S}option a 'a\\\\\nb'\n"
  "${S}option a \"a\\\\\r\nb\"\n"
  "${S}option a a\\\\\r\nb\n"
  "${S}option a x\\\\\n;option b 2\n"
  "${S}option a 'x'\\\\\n;option b 2\n"
  "${S}option a a\\\\bc;d e\n"
  "${S}option a \\\\bcd;o c d\n"
  "${S}option a a\\\\b\\\\c;o c d\n"
  "${S}option a 'x'\\\\bc;o c d\n"
  "${S}option a a\\\\ ;o c d\n"
  "${S}option a a\\\\;;o c d\n"
  "${S}option a\\\\bc;d e\n"
  "${S}option a b\\\\\n"
  # U9: `;`
  "config t 'n'; option x 1\n"
  "${S}option a 1; option b 2\n"
  "${S}option a '1;2'\n"
  "${S}option a 1;2\n"
  "${S}option a 1 ;option b 2\n"
  "${S}option a 1;\n"
  "${S}option a 1;;option b 2\n"
  "config t 'n';\n\toption a 1\n"
  "${S}; option a 1\n"
  "${S}option a 1 # c; option b 2\n"
  "${S}option a \"x\";option b 2\n"
  "${S}option a 1 ; option b 2\n"
  "${S}option a 'x'y;option b 2\n"
  "${S}option a 1 ;\n"
  "${S}option a 1 ; \n\toption b 2\n"
  "${S}option a 1 ;; option b 2\n"
  "${S}option a 'x';\n"
  "${S}option a 1 ; # c\n"
  "${S}option a x;#\n"
  "config t 'n' ; option x 1 ; option y 2\n"
  "${S}option a 1 ;option b\n"
  "${S}option a 'x';list l 'y'\n"
  "${S}option a 'x' ;option b 2;option c 3\n"
  "${S}option a x#y ;option b 2\n"
  "${S}option a ;option b 2\n"
  "${S}option a 1;option b 2\n"
  "${S}option a x'y';option b 2\n"
  "${S}option a 'x'y;z\n"
  "${S}option a 'x';;option b 2\n"
  "${S}option a 'x';option b\n"
  "${S}option a 'x';'option' b 2\n"
  "${S}option a \"x\" ;x\n"
  "${S}option a x;y z\n"
  "${S}list l 1;2\n"
  "${S}option;\n"
  "${S}option a 'x'y;\n"
  "${S}option a 1 ;#\n"
  "${S}option a 1 ;option b 2 ;\n"
  "${S}option a x';'\n"
  "${S}option a ';'x;y\n"
  "${S}option a x;'y'\n"
  "${S}option 'a';option b 2\n"
  "${S}option a;option b 2\n"
  "${S}option a ;b\n"
  "${S}option a ; b\n"
  "${S}option a;\n"
  "${S}option a ;\n"
  "${S}option a b;c d\n"
  "${S}option a 'b';c d\n"
  "${S}option a b c;d\n"
  "${S}option a b 'c';d\n"
  "${S}option a b'c'd;e f\n"
  "${S}option a b\\\\ ;c\n"
  "${S}option a '' ;option b 2\n"
  "${S}option a b ;\toption c 3\n"
  "config t;option a 1\n"
  "config 't';option a 1\n"
  "config t n;option x 1\n"
  "${S}option ;a b\n"
  "config ;x\n"
  ";\n"
  "${S}list l ;x\n"
  "config t ;x\n"
  "config t 'n' ;\n"
  "config t ;\n"
  "${S}option a \"b\\\\\";\" ;option c 1\n"
  "${S}option a b ;config u 'v'\n"
  "${S}list l ;\n"
  # U10: empty values
  "${S}option v ''\n"
  "${S}option v \"\"\n"
  "${S}option v 'x'\n\toption v ''\n"
  "${S}list l ''\n"
  "${S}list l 'a'\n\tlist l ''\n\tlist l 'b'\n"
  "${S}option v ''''\n"
  "${S}option v\n"
  "${S}list l 'a'\n\toption l ''\n"
  "${S}option v ''\n\toption v 'y'\n"
  "${S}option v ''\n\tlist v 'a'\n"
  "${S}list l\n"
  "${S}option a-b ''\n"
  # U19: package line
  "package other\nconfig t 'n'\n\toption x A\n"
  "config t 'n'\n\toption x A\npackage other\nconfig t 'm'\n\toption y B\n"
  "package\nconfig t 'n'\n"
  "package a b\nconfig t 'n'\n"
  "package a-b!\nconfig t 'n'\n"
  "package 'ok'\nconfig t 'n'\n"
  "package \"o\"k\nconfig t 'n'\n"
  "package p1 ;config t 'x'\n"
  # keywords
  "c t 'n'\n\to x 1\n\tl y 2\n"
  "${S}opt a b\n"
  "${S}optionx a b\n"
  "cfg x\n"
  "${S}p x\n"
  "${S}O a b\n"
  "${S}'option' a b\n"
  "${S}option\n"
  "config\n"
  # U25: a config block reusing a section name
  "config t 'a'\n\toption x '1'\n\nconfig t 'a'\n\toption x '2'\n"
  "config t 'a'\n\toption x '1'\n\toption y 'keep'\n\nconfig t 'a'\n\toption x '2'\n\toption z 'new'\n"
  "config t 'a'\n\tlist l '1'\n\tlist l '2'\n\nconfig t 'a'\n\tlist l '3'\n"
  "config t 'a'\n\toption x '1'\n\nconfig t 'b'\n\toption x 'b'\n\nconfig u\n\toption x 'anon'\n\nconfig t 'a'\n\toption x '2'\n"
  "config t 'a'\n\toption x '1'\n\nconfig u 'a'\n\toption x '2'\n"
  "config t 'a'\n\toption x '1'\n\nconfig t 'a'\n"
  "config t 'a'\n\toption x '1'\n\nconfig t 'a'\n\toption x '2'\n\nconfig t 'a'\n\toption y '3'\n"
  "config t\n\toption x '1'\n\nconfig t\n\toption x '2'\n"
)

echo "# Real \`uci show\` of each probe file \`p\`: \`in\` = file bytes (hex),"
echo "# \`out\` = stdout (hex) of a load, \`err\` = the binary refused the file."
echo "# Generated by modules/uci/tools/capture-grammar.sh; do not edit by hand."
for probe in "${probes[@]}"; do
  printf '%b' "$probe" > "$dir/p"
  echo "in $(od -An -v -tx1 "$dir/p" | tr -d ' \n')"
  if out=$("$uci" -c "$dir" show p 2>/dev/null); then
    printf 'out %s\n' "$(printf '%s\n' "$out" | od -An -v -tx1 | tr -d ' \n')"
  else
    echo "err"
  fi
done
