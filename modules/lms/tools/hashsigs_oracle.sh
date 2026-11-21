#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Black-box oracle for lms (CONVENTIONS §9): cisco/hash-sigs (BSD-3-Clause),
# built from a pinned commit with its own SHA-256 (no OpenSSL headers needed),
# driven only through its `demo` program and the wire formats (HSS public key
# and signature bytes, RFC 8554 §6 / §6.4).
#
#   modules/lms/tools/hashsigs_oracle.sh build
#       fetch + build `demo` into .zig-cache/lms-hashsigs/
#   modules/lms/tools/hashsigs_oracle.sh theirs <parm set> <message file> <out dir>
#       a fresh hash-sigs key (`demo genkey`, parameter set as demo takes it:
#       "5/1", "5/2", "10/4,5/8"...) and one signature of the message:
#       <out dir>/key.pub, <out dir>/msg.sig (raw bytes)
#   modules/lms/tools/hashsigs_oracle.sh verify <pub file> <message file> <sig file>
#       hash-sigs' verdict on a public key / signature made elsewhere (ours)
#
# The W1/W2 vectors in src/kat_test.zig (`hash-sigs` section) came from `theirs`
# with "5/1" and "5/2"; the reverse direction (our signatures accepted by
# hash-sigs) was checked with `verify` on the output of tools/emit.zig.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
COMMIT=77688282cbfc0070f5355efeae8d2ea2f57b9168
DIR=.zig-cache/lms-hashsigs
SRC=$DIR/hash-sigs-$COMMIT

build() {
    mkdir -p "$DIR"
    if [[ ! -x $DIR/demo ]]; then
        [[ -d $SRC ]] || curl -sSfL "https://github.com/cisco/hash-sigs/archive/$COMMIT.tar.gz" | tar xz -C "$DIR"
        # Its own SHA-256 instead of OpenSSL's.
        sed -i 's/#define USE_OPENSSL 1/#define USE_OPENSSL 0/' "$SRC/sha256.h"
        (cd "$SRC" && cc -O2 -w -o ../demo demo.c hss.c hss_alloc.c hss_aux.c hss_common.c hss_compute.c \
            hss_generate.c hss_keygen.c hss_param.c hss_reserve.c hss_sign.c hss_sign_inc.c \
            hss_thread_pthread.c hss_verify.c hss_verify_inc.c hss_zeroize.c lm_common.c \
            lm_ots_common.c lm_ots_sign.c lm_ots_verify.c lm_verify.c endian.c hash.c \
            hss_derive.c sha256.c -lpthread)
    fi
}

case "${1:-}" in
build) build ;;
theirs)
    build
    out=$(realpath -m "$4")
    mkdir -p "$out"
    cp "$3" "$out/msg"
    (cd "$out" && "$OLDPWD/$DIR/demo" genkey key "$2" >/dev/null && "$OLDPWD/$DIR/demo" sign key msg >/dev/null)
    ;;
verify)
    build
    tmp=$(mktemp -d "$DIR/verify.XXXXXX")
    cp "$2" "$tmp/key.pub"
    cp "$3" "$tmp/msg"
    cp "$4" "$tmp/msg.sig"
    (cd "$tmp" && "$OLDPWD/$DIR/demo" verify key msg)
    ;;
*) sed -n '3,20p' "$0"; exit 2 ;;
esac
