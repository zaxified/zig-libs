# tlsclient test chains

Certificates only (no keys kept), written by openssl so the verifier cannot
mirror a misreading of its own. All P-256, ten years from 2026-09-24.

| file | issuer | what it is |
|---|---|---|
| `root.pem` | self | the trust anchor (`CA:TRUE`, keyCertSign) |
| `inter.pem` | root | intermediate (`CA:TRUE, pathlen:0`) |
| `leaf.pem` | inter | server leaf, `CA:FALSE`, SAN `DNS:good.example.test`, EKU serverAuth |
| `forged.pem` | **leaf** (signed with leaf's key) | SAN `DNS:victim.example.test` -- the ziglang/zig #35877 attack |
| `leaf-client.pem` | inter | `CA:FALSE`, EKU clientAuth only |

`leaf.key.pem` and `forged.key.pem` are kept for `tools/openssl-oracle.sh`,
which serves these chains with `openssl s_server`; they are throwaway keys.

Client certificates (2026-10-04, for the TLS 1.3 client-auth interop): a
separate throwaway CA (`client-ca.pem`, key discarded) and three leaves with
EKU clientAuth -- `client-p256.pem`, `client-p384.pem`, `client-ed25519.pem` --
whose throwaway private keys are kept as DER (`*.key.der`: SEC1 for the EC
ones, PKCS#8 for Ed25519) so the test can cut the raw scalar/seed at a fixed,
prefix-checked offset.

```sh
E="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
openssl req -x509 $E -keyout cca.key -out client-ca.pem -days 3650 -subj "/CN=tlsclient test client CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
cl() { # name keyopts serial
  openssl req $2 -keyout $1.key.pem -out $1.csr -subj "/CN=$1"
  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n" > c.cnf
  openssl x509 -req -in $1.csr -CA client-ca.pem -CAkey cca.key -set_serial $3 -days 3650 -extfile c.cnf -out $1.pem
}
cl client-p256 "-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes" 10
cl client-p384 "-newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes" 11
cl client-ed25519 "-newkey ed25519 -nodes" 12
for k in client-p256 client-p384; do openssl ec -in $k.key.pem -outform DER -out $k.key.der; done
openssl pkey -in client-ed25519.key.pem -outform DER -out client-ed25519.key.der
rm cca.key c.cnf client-*.csr client-*.key.pem
```

Regenerate (from this directory):

```sh
E="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
openssl req -x509 $E -keyout root.key -out root.pem -days 3650 -subj "/CN=tlsclient test root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req $E -keyout inter.key -out inter.csr -subj "/CN=tlsclient test intermediate"
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > ca.cnf
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -set_serial 2 -days 3650 -extfile ca.cnf -out inter.pem
leaf() { # name key-name CA CA-key serial san eku
  openssl req $E -keyout $2 -out $1.csr -subj "/CN=$1"
  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=$6\nextendedKeyUsage=$7\n" > leaf.cnf
  openssl x509 -req -in $1.csr -CA $3 -CAkey $4 -set_serial $5 -days 3650 -extfile leaf.cnf -out $1.pem
}
leaf leaf leaf.key.pem inter.pem inter.key 3 DNS:good.example.test serverAuth
leaf forged forged.key.pem leaf.pem leaf.key.pem 4 DNS:victim.example.test serverAuth
leaf leaf-client client.key inter.pem inter.key 5 DNS:good.example.test clientAuth
rm root.key inter.key client.key inter.csr leaf.csr forged.csr leaf-client.csr ca.cnf leaf.cnf
```
