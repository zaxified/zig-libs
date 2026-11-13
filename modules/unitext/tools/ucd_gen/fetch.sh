#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Fetch the Unicode Character Database files gen.py reads:
#   tools/ucd_gen/fetch.sh 18.0.0     # the tables' version
#   tools/ucd_gen/fetch.sh 17.0.0     # Rust 1.93's and ICU 78's version, for restrict_vectors.py / latin_ascii_diff.py
#   tools/ucd_gen/fetch.sh 16.0.0     # CPython 3.14's unicodedata version, for the oracle comparison
# (Scripts.txt and Blocks.txt only for tools/latin_ascii_diff.py)
# into tools/ucd_gen/data/<version>/ (gitignored; re-fetchable). The data are
# Unicode's, under the Unicode License v3 (see the module's NOTICE).
set -euo pipefail
v=${1:?usage: fetch.sh <unicode version, e.g. 18.0.0>}
dir="$(cd "$(dirname "$0")" && pwd)/data/$v"
tmp="$(mktemp -d)"
trap 'rm -r "$tmp"' EXIT
mkdir -p "$dir/extracted"
curl -sfL --max-time 300 -o "$tmp/UCD.zip" "https://www.unicode.org/Public/$v/ucd/UCD.zip"
(cd "$tmp" && unzip -q -o UCD.zip UnicodeData.txt SpecialCasing.txt CaseFolding.txt CompositionExclusions.txt \
    DerivedNormalizationProps.txt DerivedCoreProperties.txt NormalizationTest.txt PropList.txt \
    Scripts.txt Blocks.txt \
    extracted/DerivedNumericType.txt extracted/DerivedGeneralCategory.txt)
cp "$tmp"/*.txt "$dir/"
cp "$tmp"/extracted/*.txt "$dir/extracted/"
echo "fetched UCD $v into $dir"
