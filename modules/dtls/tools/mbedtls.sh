#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Fetches, verifies and builds the second live DTLS 1.2 peer of
# `tools/interop.zig`: Mbed TLS's `ssl_server2` / `ssl_client2` test programs.
#
# Mbed TLS is dual Apache-2.0 / GPL-2.0-or-later. It is used ONLY as a
# black-box peer driven over a loopback UDP socket; none of its source is
# read for, copied into or linked into this module.
#
# Everything lands in .interop-peers/dtls-mbedtls/ at the repository root
# (gitignored, and outside modules/ so the licence and catalogue checks, which
# walk the file system, never see foreign source):
#   dl/     the release tarball, checked against the sha256 below
#   src/    the unpacked tree
#   build/  the CMake build tree (no install step)
#
# Run from the repository root. The build is heavy enough to go through the
# machine's job budget where one exists, e.g.
#     hw run --slots 1 --name mbedtls -- modules/dtls/tools/mbedtls.sh
# Then `zig build interop-dtls -- --version 12` runs the `-mbedtls` cases
# against the two programs it finds under build/programs/ssl/.
#
# The pinned release is 3.6.7, the 3.6 LTS line (2026-07-07). The hash is the
# one published in the release notes on
# https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7 for the
# official asset `mbedtls-3.6.7.tar.bz2` (not GitHub's generated
# source.tar.gz, which lacks the framework/ submodule).
#
# Reviewed before the first build (2026-11-24): the release tarball ships its
# generated files and defaults GEN_FILES=OFF; with ENABLE_TESTING=OFF the only
# configure-time command is `scripts/config.py get ...` (local, reads the
# config header). No CMake file fetches anything (no FetchContent,
# ExternalProject or file(DOWNLOAD)). The default `mbedtls_config.h` already
# enables DTLS 1.2, HelloVerifyRequest, the RFC 9146 connection ID (COMPAT 0,
# i.e. the standard form), PSK, ECDHE-PSK, GCM, CCM and ChaCha20-Poly1305, so
# the configuration is not edited.
set -euo pipefail

version=3.6.7
sha256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
url="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${version}/mbedtls-${version}.tar.bz2"

top=.interop-peers/dtls-mbedtls
[ -d modules/dtls/tools ] || { echo "run from the repository root" >&2; exit 2; }
mkdir -p "$top/dl" "$top/src"
tarball="$top/dl/mbedtls-${version}.tar.bz2"
[ -f "$tarball" ] || curl -sSfL -o "$tarball" "$url"
echo "${sha256}  ${tarball}" | sha256sum -c -
srcdir="$top/src/mbedtls-${version}"
[ -d "$srcdir" ] || tar -xjf "$tarball" -C "$top/src"

cmake -S "$srcdir" -B "$top/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTING=OFF \
    -DENABLE_PROGRAMS=ON \
    -DGEN_FILES=OFF \
    -DDISABLE_PACKAGE_CONFIG_AND_INSTALL=ON
cmake --build "$top/build" --target ssl_server2 ssl_client2 -j "$(nproc)"
# Read by tools/interop.zig for the 1.2 transcript header.
echo "Mbed TLS ${version} (mbedtls-${version}.tar.bz2 sha256 ${sha256})" > "$top/VERSION"
ls -l "$top/build/programs/ssl/ssl_server2" "$top/build/programs/ssl/ssl_client2"
