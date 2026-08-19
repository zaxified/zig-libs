#!/usr/bin/env bash
# Reachability gate for the plaintext http.Client split
# (`Client.zig`'s `dialPlain`/`dialTls`, reached only via
# `requestPlain`/`requestStreamingPlain`/`putFilePlain` -- see
# modules/http/sizeprobe/README.md). That directory is the ONLY proof of the
# split's whole claim -- that the plaintext entry points never pull the TLS
# stack in -- and it has its own standalone build.zig that nothing in the
# repo referenced: not the root build.zig, not scripts/test.sh, not CI. An
# artefact whose check never runs is worse than none, because it still looks
# authoritative (the lesson this repo paid for the same day on the
# generated Portability table -- see check-portable-table).
#
# Level chosen: build BOTH probes (before/after, stripped + `_syms`) and
# assert `probe_after_syms` links ZERO TLS/certificate/curve/hash symbols --
# the property that actually matters, and stable under unrelated code churn.
# NOT the exact-byte-count level (`sizeprobe/run.sh`'s size table): a byte
# count drifts with every unrelated stdlib/toolchain change and is exactly
# the kind of assertion that gets disabled once it starts failing for
# reasons that have nothing to do with TLS reachability.
#
# ONE target only: x86_64-linux-musl. `sizeprobe/run.sh` also cross-builds
# mips-linux-musleabi (big-endian MIPS32) for the measured size DELTA on
# both of that consumer's targets, but the property this gate checks -- whether the
# plaintext call graph references TLS/crypto decls at all -- is a Sema
# reachability fact, not a codegen one: it does not vary by target the way
# the 32-bit/big-endian bugs `check-portable` hunts for do (see that gate's
# doc in build.zig for the class of defect an architecture actually
# changes). A second cross-compile roughly doubles this step's wall time
# for zero additional coverage of what it is asserting, so one target is a
# reachability probe, not a portability claim; the mips leg stays in
# `run.sh`, run by hand before a tag.
#
# Silent on success: scripts/test.sh's `step` treats ANY stderr as a FAIL
# even when the exit code is 0.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../modules/http/sizeprobe" && pwd)"
cd "$HERE"

CRYPTO_GREP='tls\.Client|Certificate|X25519|P256|P384|Sha1|Sha256|Sha3|Sha512|\bRsa\b|MlKem|ml_kem|Aegis|Aes(128|256)?Gcm|ChaCha20Poly1305'
OUT="zig-out/gate"
CACHE=".zig-cache/gate"

build_err=$(zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSmall \
    --prefix "$OUT" --cache-dir "$CACHE" --summary none 2>&1)
rc=$?
if [[ $rc -ne 0 ]]; then
    echo "check-http-sizeprobe: modules/http/sizeprobe failed to build for x86_64-linux-musl" >&2
    echo "$build_err" >&2
    exit 1
fi
if [[ -n "$build_err" ]]; then
    echo "check-http-sizeprobe: build exited 0 but produced output (must be silent on success)" >&2
    echo "$build_err" >&2
    exit 1
fi

for bin in probe_before probe_after probe_before_syms probe_after_syms; do
    if [[ ! -x "$OUT/bin/$bin" ]]; then
        echo "check-http-sizeprobe: $OUT/bin/$bin was not produced" >&2
        exit 1
    fi
done

after_hits=$(nm -C "$OUT/bin/probe_after_syms" 2>/dev/null | grep -iE "$CRYPTO_GREP" || true)
if [[ -n "$after_hits" ]]; then
    echo "check-http-sizeprobe: probe_after_syms references TLS/crypto symbols:" >&2
    echo "$after_hits" >&2
    echo "  requestPlain/requestStreamingPlain/putFilePlain (Client.zig's dialPlain) are" >&2
    echo "  no longer TLS-free -- see modules/http/sizeprobe/README.md for what this" >&2
    echo "  split promises and modules/http/CONVENTIONS.md-adjacent Client.zig doc" >&2
    echo "  comments on dialPlain/dialConn for the reachability trap that broke it before." >&2
    exit 1
fi

before_hits=$(nm -C "$OUT/bin/probe_before_syms" 2>/dev/null | grep -icE "$CRYPTO_GREP" || true)
if [[ "$before_hits" -eq 0 ]]; then
    echo "check-http-sizeprobe: probe_before_syms has ZERO TLS/crypto symbol matches" >&2
    echo "  probe_before goes through request()/putFile(), which DO use TLS -- so a" >&2
    echo "  zero-hit result here means the CRYPTO_GREP pattern stopped matching a real" >&2
    echo "  reference, which would make the zero-hit check on probe_after_syms above" >&2
    echo "  prove nothing. Fix the pattern before trusting that check again." >&2
    exit 1
fi

exit 0
