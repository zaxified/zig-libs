// SPDX-License-Identifier: MIT

// Go side of `zig build bench-bn254` (modules/bn254/tools/bench.zig): times
// gnark-crypto v0.19.2's BN254 pairing on the same inputs the Zig side
// uses (P = [a]G1, Q = [b]G2 from the standard generators, a and b fixed).
// One line per workload: name, ns/op, and a check value (1 for the pairing
// check that holds; 0 where nothing is compared — gnark's final
// exponentiation returns a fixed power of the canonical pairing, so the
// reduced values differ from the Zig side's by design). Timing matches the
// Zig side: double the batch until it takes over 100 ms, keep the best of
// five.
package main

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func timeIt(name string, check uint64, f func()) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, float64(best.Nanoseconds())/float64(n), check)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <a decimal> <b decimal>")
		os.Exit(2)
	}
	a, ok1 := new(big.Int).SetString(os.Args[1], 10)
	b, ok2 := new(big.Int).SetString(os.Args[2], 10)
	if !ok1 || !ok2 {
		fmt.Fprintln(os.Stderr, "bad scalar")
		os.Exit(2)
	}
	_, _, g1, g2 := bn254.Generators()
	var p, pab bn254.G1Affine
	var q bn254.G2Affine
	p.ScalarMultiplication(&g1, a)
	q.ScalarMultiplication(&g2, b)
	ab := new(big.Int).Mul(a, b)
	pab.ScalarMultiplication(&g1, ab)
	pab.Neg(&pab)

	ok, err := bn254.PairingCheck([]bn254.G1Affine{p, pab}, []bn254.G2Affine{q, g2})
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "pairing check failed", err)
		os.Exit(1)
	}

	var sinkE bn254.GT
	var sinkB bool
	timeIt("pairing_1", 0, func() {
		sinkE, _ = bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	})
	timeIt("check_2", 1, func() {
		sinkB, _ = bn254.PairingCheck([]bn254.G1Affine{p, pab}, []bn254.G2Affine{q, g2})
	})
	timeIt("miller_2", 0, func() {
		sinkE, _ = bn254.MillerLoop([]bn254.G1Affine{p, pab}, []bn254.G2Affine{q, g2})
	})
	_ = sinkE
	_ = sinkB
}
