#!/usr/bin/env bash
# Recipe for src/testdata/certs/ocsp-*: an ECDSA P-256 CA and leaf whose CA key
# signs an OCSP response for the leaf, for the live stapling case
# (`cert-server-ocsp` in tools/interop.zig: a wolfSSL client with OCSP stapling
# verifies the response OUR server staples). The CA key is generated, used and
# thrown away; only certificates, the leaf's raw 32-byte scalar and the response
# are kept.
#   ocsp-ca-cert.der     self-signed CA ("dtls-ocsp-ca")
#   ocsp-leaf-cert.der   end entity (CN dtls-ocsp-leaf), signed by the CA
#   ocsp-leaf-key.bin    the leaf's raw scalar
#   ocsp-response.der    a "good" OCSPResponse for the leaf, signed by the CA,
#                        valid for 3650 days from generation
# Validity of the certificates: 2026-07-21 .. 2036-07-18 like the other fixtures.
# Needs: openssl 3.x, python3. Run from modules/dtls.
set -euo pipefail
out=src/testdata/certs
work=$(mktemp -d)
trap 'rm -f "$work"/*; rmdir "$work"' EXIT
start=20260721000000Z
end=20360718000000Z
for n in ca leaf; do openssl ecparam -name prime256v1 -genkey -noout -out "$work/$n.key"; done
cat > "$work/ext.cnf" <<'CNF'
[ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF
openssl req -new -key "$work/ca.key" -subj "/CN=dtls-ocsp-ca" -out "$work/ca.csr"
openssl x509 -req -in "$work/ca.csr" -signkey "$work/ca.key" -not_before $start -not_after $end \
  -extfile "$work/ext.cnf" -extensions ca -set_serial 1 -out "$work/ca.pem"
openssl req -new -key "$work/leaf.key" -subj "/CN=dtls-ocsp-leaf" -out "$work/leaf.csr"
openssl x509 -req -in "$work/leaf.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -not_before $start -not_after $end \
  -extfile "$work/ext.cnf" -extensions leaf -set_serial 2 -out "$work/leaf.pem"
# OpenSSL's CA database format: status, expiry, revocation, serial (hex), file, subject.
printf 'V\t360718000000Z\t\t02\tunknown\t/CN=dtls-ocsp-leaf\n' > "$work/index.txt"
openssl ocsp -issuer "$work/ca.pem" -cert "$work/leaf.pem" -no_nonce -reqout "$work/req.der"
openssl ocsp -index "$work/index.txt" -CA "$work/ca.pem" -rsigner "$work/ca.pem" -rkey "$work/ca.key" \
  -reqin "$work/req.der" -respout "$work/resp.der" -ndays 3650
openssl ocsp -respin "$work/resp.der" -issuer "$work/ca.pem" -cert "$work/leaf.pem" -CAfile "$work/ca.pem" -no_nonce
openssl x509 -in "$work/ca.pem" -outform DER -out "$out/ocsp-ca-cert.der"
openssl x509 -in "$work/leaf.pem" -outform DER -out "$out/ocsp-leaf-cert.der"
openssl ec -in "$work/leaf.key" -outform DER -out "$work/leaf.der" 2>/dev/null
python3 -I -c 'import sys; d=open(sys.argv[1],"rb").read(); assert d[5:7]==b"\x04\x20"; open(sys.argv[2],"wb").write(d[7:39])' "$work/leaf.der" "$out/ocsp-leaf-key.bin"
cp "$work/resp.der" "$out/ocsp-response.der"
