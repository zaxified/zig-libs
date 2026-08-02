#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regenerates the `openssl_byname_*` goldens in modules/ocsp/src/goldens.zig:
# an OCSP response from a DIRECT responder whose ResponderID is byName. No
# public CA was found emitting that combination, so OpenSSL plays the CA.
#
# OpenSSL is the oracle, not this repo: it builds the Name, the DER and the
# RSA-SHA256 signature, and verifies its own output before the bytes are
# frozen. The frozen bytes are what the test gate reads — this script is never
# run by the build.
#
# Usage: scripts/gen-ocsp-byname.sh <outdir>
#
# Then paste the printed arrays into goldens.zig and update the pinned
# `producedAt`/`thisUpdate` epoch (printed at the end) in the tests.
set -euo pipefail

out="${1:?usage: gen-ocsp-byname.sh <outdir>}"
mkdir -p "$out"
cd "$out"

openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.pem -days 7300 -nodes \
  -subj "/C=XX/O=zig-libs test/CN=zig-libs OCSP test CA" -sha256
openssl req -newkey rsa:2048 -keyout leaf.key -out leaf.csr -nodes \
  -subj "/C=XX/O=zig-libs test/CN=leaf.test" -sha256
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 0x1234 \
  -days 7300 -sha256 -out leaf.pem

# The responder's index: one valid ("V") entry for the leaf's serial.
printf 'V\t%s\t\t1234\tunknown\t/C=XX/O=zig-libs test/CN=leaf.test\n' \
  "$(openssl x509 -in leaf.pem -noout -enddate | sed 's/notAfter=//' | date -u -f - +%y%m%d%H%M%SZ)" \
  > index.txt

openssl ocsp -issuer ca.pem -cert leaf.pem -reqout req.der -no_nonce
# -rsigner is the CA itself => direct responder. OpenSSL's default ResponderID
# is byName (`-resp_key_id` would make it byKey, which DigiCert's golden
# already covers). -resp_no_certs keeps the fixture to the direct shape.
openssl ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key \
  -reqin req.der -respout resp.der -resp_no_certs

# OpenSSL's own verdict on its own bytes — the anchor's authority.
openssl ocsp -respin resp.der -CAfile ca.pem -issuer ca.pem -cert leaf.pem -no_nonce

openssl x509 -in ca.pem -outform der -out ca.der
openssl x509 -in leaf.pem -outform der -out leaf.der

python3 - <<'PY'
def emit(name, path):
    b = open(path, 'rb').read()
    print(f"pub const {name} = [_]u8{{")
    for i in range(0, len(b), 16):
        print("    " + " ".join(f"0x{x:02x}," for x in b[i:i + 16]))
    print("};\n")
emit("openssl_byname_issuer_der", "ca.der")
emit("openssl_byname_leaf_der", "leaf.der")
emit("openssl_byname_response_der", "resp.der")
PY

produced=$(openssl ocsp -respin resp.der -text -noverify 2>/dev/null |
  sed -n 's/^ *Produced At: //p')
echo "# producedAt = thisUpdate = $produced = $(date -u -d "$produced" +%s)"
