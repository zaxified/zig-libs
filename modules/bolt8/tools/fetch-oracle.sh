#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Builds the BOLT#8 interop oracle out of lnd's own `brontide` package —
# FETCHED here, never vendored, which is what keeps this module's clean-room
# `NOTICE` ("no reference implementation's source ... was ported or consulted
# as a design reference") true: the oracle is a VERIFICATION instrument run
# against this module from the outside, never a design reference read while
# writing `src/`.
#
# WHAT IT NEEDS: `curl`, `python3`, Go 1.21+, network access to raw GitHub and
# the Go module proxy.
# WHAT IT PRODUCES: in <workdir>, a `main` package (`oraclebin` once built)
# that speaks the BOLT#8 interop peer role over stdin/stdout — see
# `oracle_main.go`'s own header for the wire protocol.
#
# Licence, checked at the source fetched below: lnd's own `LICENSE`
# (https://raw.githubusercontent.com/lightningnetwork/lnd/master/LICENSE) is
# MIT. `go mod tidy` additionally pulls `github.com/btcsuite/btcd/btcec/v2`
# (ISC, `btcsuite/btcd`'s own `LICENSE`) and `golang.org/x/crypto` (BSD-3-Clause,
# the Go team's standard licence) — both permissive, checked the same way at
# `go mod tidy` time in `$GOMODCACHE`.
#
# Usage:
#   ./fetch-oracle.sh <workdir>
# then:
#   cd <workdir> && go build -o oraclebin .
set -eu
W="${1:?usage: fetch-oracle.sh <workdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$W/brontide" "$W/keychain"
cd "$W"

B=https://raw.githubusercontent.com/lightningnetwork/lnd/master
curl -sfL -o brontide/noise.go   "$B/brontide/noise.go"
curl -sfL -o keychain/ecdh.go    "$B/keychain/ecdh.go"

# brontide imports lnd's keychain by its full module path; point it at ours.
sed -i 's|"github.com/lightningnetwork/lnd/keychain"|"oracle/keychain"|' brontide/noise.go

# keychain/ecdh.go also carries PubKeyECDH, which drags in the rest of the
# keychain package. Keep only PrivKeyECDH (used verbatim) and declare the
# SingleKeyECDH interface locally.
python3 - keychain/ecdh.go <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
i = s.index('// PrivKeyECDH is an implementation')
head = '''package keychain

import (
\t"crypto/sha256"

\t"github.com/btcsuite/btcd/btcec/v2"
)

// SingleKeyECDH is lnd's keychain interface (keychain/interface.go), reduced
// here to the two methods brontide actually uses.
type SingleKeyECDH interface {
\tPubKey() *btcec.PublicKey
\tECDH(pub *btcec.PublicKey) ([32]byte, error)
}

'''
open(p, 'w').write(head + s[i:].replace('var _ SingleKeyECDH = (*PubKeyECDH)(nil)\n', ''))
PY

cp "$HERE/oracle_main.go" ./main.go

go mod init oracle 2>/dev/null || true
go get github.com/btcsuite/btcd/btcec/v2 golang.org/x/crypto
go mod tidy
echo "oracle sources ready in $W"
