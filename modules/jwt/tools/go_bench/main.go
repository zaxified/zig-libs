// SPDX-License-Identifier: MIT
//
// Go side of `zig build bench-jwt` (modules/jwt/tools/bench.zig): times
// github.com/golang-jwt/jwt/v5 (the reference; Go standard-library crypto
// underneath) signing and verifying a typical access token, for the one
// workload named by the second argument (`go.<alg>_<sign|verify>`, alg =
// hs256, es256, eddsa), over the keys and claims the Zig program writes into
// the directory given as the first. Prints one line: name, ns/op, 0 (no
// cycle counter on this side, so the comparison is by wall time), and the
// token length (sign) or 1 (verify).
//
// verify = jwt.Parse with the algorithm pinned, issuer, audience and
// expiry required -- the same checks as the Zig side's `parseAndVerify`.
// The run named `interop` verifies the Zig side's tokens (`zig_<alg>.jwt`)
// and writes this side's (`go_<alg>.jwt`) for the Zig side to verify.
//
// Built by bench.zig in a copy under .zig-cache with GOPROXY=off,
// GOFLAGS=-mod=mod and GOTOOLCHAIN=local: the module must already be in the
// Go module cache (`go mod download github.com/golang-jwt/jwt/v5@v5.3.1`);
// go.sum pins it.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuer = "https://issuer.example.com"
const audience = "api.example.com"

var dir string

func slurp(name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return b
}

type alg struct {
	method  jwt.SigningMethod
	signKey any
	verKey  any
}

func bench(name string, f func() int) {
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
	best := time.Duration(1 << 62)
	count := 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	fmt.Printf("%s\t%.1f\t0\t%d\n", name, float64(best.Nanoseconds())/float64(n), count)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: jwt_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir = os.Args[1]
	w := os.Args[2]
	ver := "golang-jwt/jwt/v5 ?"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/golang-jwt/jwt/v5" {
				ver = "golang-jwt/jwt/v5 " + d.Version
			}
		}
		ver += ", " + bi.GoVersion
	}
	fmt.Fprintln(os.Stderr, ver)

	hmacKey := slurp("hs256.key")
	ecKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), slurp("es256.key"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "es256 key:", err)
		os.Exit(1)
	}
	edKey := ed25519.NewKeyFromSeed(slurp("eddsa.seed"))
	algs := map[string]alg{
		"hs256": {jwt.SigningMethodHS256, hmacKey, hmacKey},
		"es256": {jwt.SigningMethodES256, ecKey, &ecKey.PublicKey},
		"eddsa": {jwt.SigningMethodEdDSA, edKey, edKey.Public()},
	}
	claims := jwt.MapClaims{
		"iss": issuer, "sub": "user-1234567890", "aud": audience,
		"exp": 4102444800, "nbf": 1700000000, "iat": 1700000000, "scope": "read write",
	}
	sign := func(a alg) string {
		s, err := jwt.NewWithClaims(a.method, claims).SignedString(a.signKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sign:", err)
			os.Exit(1)
		}
		return s
	}
	verify := func(a alg, tok string) error {
		_, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return a.verKey, nil },
			jwt.WithValidMethods([]string{a.method.Alg()}), jwt.WithIssuer(issuer),
			jwt.WithAudience(audience), jwt.WithExpirationRequired())
		return err
	}

	if w == "interop" {
		for name, a := range algs {
			if err := verify(a, string(slurp("zig_"+name+".jwt"))); err != nil {
				fmt.Fprintf(os.Stderr, "golang-jwt rejects the Zig side's %s token: %v\n", name, err)
				os.Exit(1)
			}
			if err := os.WriteFile(filepath.Join(dir, "go_"+name+".jwt"), []byte(sign(a)), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}
	var name, op string
	if _, err := fmt.Sscanf(w, "go.%5s_%s", &name, &op); err != nil {
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
	a, ok := algs[name]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
	switch op {
	case "sign":
		bench(w, func() int { return len(sign(a)) })
	case "verify":
		tok := sign(a)
		bench(w, func() int {
			if err := verify(a, tok); err != nil {
				fmt.Fprintln(os.Stderr, "verify:", err)
				os.Exit(1)
			}
			return 1
		})
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
}
