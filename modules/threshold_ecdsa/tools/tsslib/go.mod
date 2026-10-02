module ziglibs.local/threshold_ecdsa/tsslib-oracle

go 1.23

require (
	github.com/bnb-chain/tss-lib/v3 v3.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
)

require (
	filippo.io/bigmod v0.1.0 // indirect
	github.com/agl/ed25519 v0.0.0-20200225211852-fd4d107ace12 // indirect
	github.com/btcsuite/btcd v0.23.4 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/ipfs/go-log v1.0.5 // indirect
	github.com/ipfs/go-log/v2 v2.1.3 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.13.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

// Copied from tss-lib's own go.mod (replace directives are not inherited).
replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
