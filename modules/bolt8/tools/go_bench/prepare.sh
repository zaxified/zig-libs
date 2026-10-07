#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Builds the Go side of `zig build bench-bolt8` out of lnd's own `brontide`
# package (FETCHED, never vendored: see ../fetch-oracle.sh for why), into a
# scratch directory. Same adaptation as fetch-oracle.sh -- the keychain import
# is pointed at a local trimmed copy of keychain/ecdh.go -- but pinned to the
# reference tag instead of master.
#
# Usage: prepare.sh <lnd source dir> <work dir>
#   <lnd source dir> holds brontide/noise.go and keychain/ecdh.go as fetched
#   from raw.githubusercontent.com/lightningnetwork/lnd/v0.21.3-beta/ (the
#   sha256 sums are checked below). Needs python3, Go 1.21+ and network access
#   to the Go module proxy for btcec/v2 and x/crypto (module downloads only).
# Produces <work dir>/gobench.
set -eu
SRC="${1:?usage: prepare.sh <lnd source dir> <work dir>}"
W="${2:?usage: prepare.sh <lnd source dir> <work dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "15fea7c6f6fe58c40da054269b6ff70187fdfc5e8da8366a8251816ae5427ec3  $SRC/brontide/noise.go" | sha256sum -c --quiet - ||
  { echo "prepare.sh: brontide/noise.go is not lnd v0.21.3-beta's" >&2; exit 2; }
echo "5048abe2df13c495d2a10560b8cfd35e4f9881f36fb0135fd6b534f0bac46c11  $SRC/keychain/ecdh.go" | sha256sum -c --quiet - ||
  { echo "prepare.sh: keychain/ecdh.go is not lnd v0.21.3-beta's" >&2; exit 2; }

mkdir -p "$W/brontide" "$W/keychain"
cp "$SRC/brontide/noise.go" "$W/brontide/noise.go"
cp "$SRC/keychain/ecdh.go" "$W/keychain/ecdh.go"
cp "$HERE/main.go" "$W/main.go"
cd "$W"

sed -i 's|"github.com/lightningnetwork/lnd/keychain"|"bench/keychain"|' brontide/noise.go

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

[ -f go.mod ] || go mod init bench
go get github.com/btcsuite/btcd/btcec/v2 golang.org/x/crypto
go mod tidy
go list -m github.com/btcsuite/btcd/btcec/v2 golang.org/x/crypto >&2
go build -o gobench .
