#!/usr/bin/env bash
# Recipe for src/testdata/certs/chain-*: a three-level ECDSA P-256 chain for
# `PeerVerify.chain` (RFC 5280 path building through an intermediate):
#   chain-root      self-signed CA ("dtls-chain-root"), pathlen 1
#   chain-inter     CA signed by the root ("dtls-chain-intermediate"), pathlen 0
#   chain-leaf      end entity signed by the intermediate, SAN dtls-chain.test,
#                   EKU serverAuth; chain-leaf-key.bin is its raw 32-byte scalar
# Validity 2026-07-21 .. 2036-07-18 like the other fixtures (certauth_kat_vectors.zig).
# Needs: openssl 3.x, python3 with `cryptography`. Run from modules/dtls.
set -euo pipefail
out=src/testdata/certs
work=$(mktemp -d)
trap 'rm -f "$work"/*; rmdir "$work"' EXIT
start=20260721000000Z
end=20360718000000Z
for n in root inter leaf; do openssl ecparam -name prime256v1 -genkey -noout -out "$work/$n.key"; done
cat > "$work/ext.cnf" <<'CNF'
[root]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[inter]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:dtls-chain.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF
openssl req -new -key "$work/root.key" -subj /CN=dtls-chain-root -out "$work/root.csr"
openssl x509 -req -in "$work/root.csr" -signkey "$work/root.key" -not_before $start -not_after $end \
  -extfile "$work/ext.cnf" -extensions root -outform der -out $out/chain-root-cert.der
openssl req -new -key "$work/inter.key" -subj /CN=dtls-chain-intermediate -out "$work/inter.csr"
openssl x509 -req -in "$work/inter.csr" -CA $out/chain-root-cert.der -CAform DER -CAkey "$work/root.key" \
  -not_before $start -not_after $end -set_serial 2 -extfile "$work/ext.cnf" -extensions inter -outform der -out $out/chain-inter-cert.der
openssl req -new -key "$work/leaf.key" -subj /CN=dtls-chain-leaf -out "$work/leaf.csr"
openssl x509 -req -in "$work/leaf.csr" -CA $out/chain-inter-cert.der -CAform DER -CAkey "$work/inter.key" \
  -not_before $start -not_after $end -set_serial 3 -extfile "$work/ext.cnf" -extensions leaf -outform der -out $out/chain-leaf-cert.der
python3 -I -c '
import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key
k = load_pem_private_key(open(sys.argv[1], "rb").read(), None)
open(sys.argv[2], "wb").write(k.private_numbers().private_value.to_bytes(32, "big"))
' "$work/leaf.key" $out/chain-leaf-key.bin
