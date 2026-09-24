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
