#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Fetch the Unicode Character Database a table generation reads:
#   tools/ucd_unicode/fetch.sh 17.0.0    # the tables' version
#   tools/ucd_unicode/fetch.sh 16.0.0    # regex-syntax's, for `gen.py --compare-with`
# into tools/ucd_unicode/data/<version>/ (gitignored; re-fetchable). The data
# are Unicode's, under the Unicode License v3 (see the module's NOTICE).
set -euo pipefail
v=${1:?usage: fetch.sh <unicode version, e.g. 17.0.0>}
dir="$(cd "$(dirname "$0")" && pwd)/data/$v"
mkdir -p "$dir"
curl -sfL --max-time 300 -o "$dir/UCD.zip" "https://www.unicode.org/Public/$v/ucd/UCD.zip"
(cd "$dir" && unzip -q -o UCD.zip && rm UCD.zip) # the text files only: repo checks read every file
echo "fetched UCD $v into $dir"
