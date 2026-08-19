#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Reachability/size probe for the plaintext-only http.Client split
# (requestPlain/requestStreamingPlain/putFilePlain — see
# ../src/Client.zig's dialPlain/dialTls doc comments). NOT wired into the
# repo's `zig build` (see ./README.md for why this is a standalone,
# documented probe rather than a unit test or a repo-wide `check-*` step).
#
# For each of two targets (x86_64-linux-musl, and mips-linux-musleabi — a
# big-endian MIPS32 target, the other one the consumer originally measured),
# builds via ./build.zig four executables that each perform the two call sites
# that consumer measured (one plaintext PUT upload, one plaintext GET + streamRemaining
# fetch, both to an IP literal that refuses the connection — this probe
# measures the LINKED BINARY, not a live exchange):
#   - probe_before      through request()/putFile()             (TLS-capable, stripped)
#   - probe_after       through requestPlain()/putFilePlain()    (the new split, stripped)
#   - probe_before_syms same as probe_before, symbols kept
#   - probe_after_syms  same as probe_after,  symbols kept
# `_syms` exist ONLY because a stripped binary has no symbol table at all —
# `nm` on one is vacuous either way, not evidence of anything — so the size
# comparison and the symbol check necessarily use different builds of the
# same source, same target, same optimize mode.
#
# Usage: modules/http/sizeprobe/run.sh   (run from anywhere)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CRYPTO_GREP='tls\.Client|Certificate|X25519|P256|P384|Sha1|Sha256|Sha3|Sha512|\bRsa\b|MlKem|ml_kem|Aegis|Aes(128|256)?Gcm|ChaCha20Poly1305'

run_target() {
    local target="$1" label="$2"
    # Nested under the repo's usual `zig-out/`/`.zig-cache/` gitignore
    # patterns (not `zig-out-$label/`) so a stray run never risks a
    # multi-hundred-KB static binary getting `git add -A`ed by accident.
    local out="zig-out/$label"
    rm -rf "$out" ".zig-cache/$label"
    zig build -Dtarget="$target" -Doptimize=ReleaseSmall \
        --prefix "$out" --cache-dir ".zig-cache/$label" \
        --summary none

    local before after delta
    before=$(stat -c%s "$out/bin/probe_before")
    after=$(stat -c%s "$out/bin/probe_after")
    delta=$((before - after))

    echo "== $label ($target, ReleaseSmall, static) =="
    echo "probe_before: $before bytes"
    echo "probe_after:  $after bytes"
    echo "delta:        $delta bytes saved"
    echo

    local hits
    hits=$(nm -C "$out/bin/probe_after_syms" 2>/dev/null | grep -iE "$CRYPTO_GREP" || true)
    if [ -n "$hits" ]; then
        echo "FAIL ($label): probe_after_syms references TLS/crypto symbols:"
        echo "$hits"
        return 1
    fi
    local contrast
    contrast=$(nm -C "$out/bin/probe_before_syms" 2>/dev/null | grep -icE "$CRYPTO_GREP" || true)
    echo "PASS ($label): zero TLS/certificate/curve/hash symbols in probe_after_syms"
    echo "     (contrast: probe_before_syms has $contrast such symbols — the grep is not vacuous)"
    echo
}

status=0
run_target "x86_64-linux-musl" "x86_64" || status=1
run_target "mips-linux-musleabi" "mips32be" || status=1

exit "$status"
