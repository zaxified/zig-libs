package main

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/v3/crypto/paillier"
)

func pkOf(n *big.Int) *paillier.PublicKey { return &paillier.PublicKey{N: n} }

func skOf(n, lambdaN, phi, p, q *big.Int) *paillier.PrivateKey {
	return &paillier.PrivateKey{PublicKey: paillier.PublicKey{N: n}, LambdaN: lambdaN, PhiN: phi, P: p, Q: q}
}
