#!/usr/bin/env bash
# Regenerate the independent-oracle material behind `modules/dnssec`'s
# `src/oracle_vectors.zig`.
#
# WHY THIS FILE EXISTS. The generated header of `oracle_vectors.zig` credits
# `scratchpad/dnssec-oracle/extract.py`; `SPEC.md` and `README.md` credited
# `scratchpad/n/` and called it "ephemeral". Neither path is in the repo, and
# the two records disagreed with each other -- so the module's strongest anchor
# had no re-takeable recipe at all. Same shape as the ranking script this
# campaign had to move out of a session scratchpad: a scratchpad does not
# survive a reboot, and an anchor you cannot re-take is an assertion.
#
# WHAT IT DOES. Builds a small zone, signs it once per algorithm the module
# implements (plus an NSEC3 pass), and has an INDEPENDENT implementation --
# ldns, not this repo -- verify each result. Every step is the one the header
# claims: `ldns-keygen`/`ldns-signzone` to produce, `ldns-verify-zone` to check.
#
# WHAT IT DOES NOT DO, stated so nobody mistakes it for more than it is: it
# does not reproduce the COMMITTED vectors byte for byte. Those were signed
# with keys that no longer exist, and DNSSEC signatures are not deterministic
# across fresh keys. What it restores is the provenance CHAIN -- fresh material
# from the same tools, independently verified -- so a reader can confirm the
# module agrees with ldns on new inputs, and so the extraction step (wire rdata
# -> the `Vec` literals in `oracle_vectors.zig`) has something to read from.
# That extractor is the piece that was lost; it is not reconstructed here.
#
# Usage: scripts/gen/gen-dnssec-oracle.sh [outdir]
set -euo pipefail

OUT="${1:-.zig-cache/dnssec-oracle}"
mkdir -p "$OUT"          # .zig-cache, never /tmp: /tmp is tmpfs on the dev host
cd "$OUT"

for tool in ldns-keygen ldns-signzone ldns-verify-zone; do
    command -v "$tool" >/dev/null || {
        echo "gen-dnssec-oracle: $tool not found on PATH (Debian/Ubuntu: ldnsutils)" >&2
        exit 2
    }
done

cat > example.zone <<'ZONE'
$TTL 3600
example.	IN	SOA	ns.example. admin.example. 1 3600 900 604800 3600
example.	IN	NS	ns.example.
ns.example.	IN	A	192.0.2.1
www.example.	IN	A	192.0.2.2
ZONE

# Algorithm number -> (ldns name, key bits). These are exactly the algorithms
# `modules/dnssec/src/rdata.zig`'s `algorithm` struct names AND `keys.zig`
# implements a verifier for; an algorithm this repo cannot verify has no
# business in an oracle for it.
run() { # <label> <alg-number> <ldns-name> <bits> [extra signzone flags...]
    local label="$1" num="$2" name="$3" bits="$4"; shift 4
    local key out="signed-$label"
    key="$(ldns-keygen -a "$name" -b "$bits" example.)"
    ldns-signzone "$@" -o example. -f "$out" example.zone "$key" >/dev/null
    ldns-verify-zone "$out" >/dev/null
    echo "alg $num ($name)${*:+ $*}: signed and INDEPENDENTLY verified -> $OUT/$out"
}

run 8-rsasha256   8  RSASHA256        2048
run 13-ecdsap256  13 ECDSAP256SHA256  256
run 15-ed25519    15 ED25519          256
# NSEC3 pass, for the nsec3 side of the module -- its own output name, or it
# would silently overwrite the NSEC one signed with the same algorithm.
run 13-nsec3      13 ECDSAP256SHA256  256 -n

echo
echo "Done. Artefacts in $OUT. The extraction step into oracle_vectors.zig's"
echo "\`Vec\` literals is NOT automated -- see this file's header."
