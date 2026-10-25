// SPDX-License-Identifier: MIT
//
// Go side of `zig build interop-jwt` (modules/jwt/tools/interop.zig): the
// reference, github.com/golang-jwt/jwt/v5, judging the case table the Zig
// program writes. Two modes, over the keys in the work directory (first
// argument; the same files bench-jwt writes: hmac.key, es256.key, es384.key,
// es512.key, eddsa.seed, rsa.n/d/p/q):
//
//	sign    signs one fixed access token per algorithm and writes
//	        go_<alg>.jwt (alg = HS256 ... EdDSA, the JWS names)
//	judge   reads cases.tsv (`id \t key family \t now \t iss \t aud \t token`)
//	        and prints one line per case: `id \t ok` or `id \t reject \t <error>`
//
// judge = jwt.Parse with the methods of the case's key family allowed (the
// Zig module fixes the family by the key's type, not one alg), issuer and
// audience required, expiry required, no leeway, the clock pinned to the
// case's `now`. Nothing else is configured: the parser's defaults (no strict
// base64, no padding) are what a golang-jwt user gets.
//
// Built by interop.zig in a copy under .zig-cache with GOPROXY=off and
// GOTOOLCHAIN=local: golang-jwt v5.3.1 must already be in the Go module cache;
// go.sum pins it.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var dir string

func slurp(name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return b
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

type family struct {
	methods []string
	verKey  any
}

func main() {
	if len(os.Args) != 3 {
		die("usage: jwt_oracle <work dir> <sign|judge>")
	}
	dir = os.Args[1]
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

	hmacKey := slurp("hmac.key")
	ec := func(c elliptic.Curve, name string) *ecdsa.PrivateKey {
		k, err := ecdsa.ParseRawPrivateKey(c, slurp(name))
		if err != nil {
			die("%s: %v", name, err)
		}
		return k
	}
	ec256, ec384, ec521 := ec(elliptic.P256(), "es256.key"), ec(elliptic.P384(), "es384.key"), ec(elliptic.P521(), "es512.key")
	edKey := ed25519.NewKeyFromSeed(slurp("eddsa.seed"))
	num := func(name string) *big.Int { return new(big.Int).SetBytes(slurp(name)) }
	rsaKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: num("rsa.n"), E: 65537},
		D:         num("rsa.d"),
		Primes:    []*big.Int{num("rsa.p"), num("rsa.q")},
	}
	rsaKey.Precompute()
	if err := rsaKey.Validate(); err != nil {
		die("rsa key: %v", err)
	}

	switch os.Args[2] {
	case "sign":
		claims := jwt.MapClaims{
			"iss": "https://issuer.example.com", "sub": "go-signed", "aud": "api.example.com",
			"exp": 2000000000, "nbf": 1700000000, "iat": 1700000000,
		}
		signers := []struct {
			m   jwt.SigningMethod
			key any
		}{
			{jwt.SigningMethodHS256, hmacKey}, {jwt.SigningMethodHS384, hmacKey}, {jwt.SigningMethodHS512, hmacKey},
			{jwt.SigningMethodES256, ec256}, {jwt.SigningMethodES384, ec384}, {jwt.SigningMethodES512, ec521},
			{jwt.SigningMethodEdDSA, edKey},
			{jwt.SigningMethodRS256, rsaKey}, {jwt.SigningMethodRS384, rsaKey}, {jwt.SigningMethodRS512, rsaKey},
			{jwt.SigningMethodPS256, rsaKey}, {jwt.SigningMethodPS384, rsaKey}, {jwt.SigningMethodPS512, rsaKey},
		}
		for _, s := range signers {
			tok, err := jwt.NewWithClaims(s.m, claims).SignedString(s.key)
			if err != nil {
				die("sign %s: %v", s.m.Alg(), err)
			}
			if err := os.WriteFile(filepath.Join(dir, "go_"+s.m.Alg()+".jwt"), []byte(tok), 0o644); err != nil {
				die("%v", err)
			}
		}
	case "judge":
		families := map[string]family{
			"hmac":  {[]string{"HS256", "HS384", "HS512"}, hmacKey},
			"p256":  {[]string{"ES256"}, &ec256.PublicKey},
			"p384":  {[]string{"ES384"}, &ec384.PublicKey},
			"p521":  {[]string{"ES512"}, &ec521.PublicKey},
			"ed":    {[]string{"EdDSA"}, edKey.Public()},
			"rsa":   {[]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, &rsaKey.PublicKey},
		}
		f, err := os.Open(filepath.Join(dir, "cases.tsv"))
		if err != nil {
			die("%v", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for sc.Scan() {
			cols := strings.Split(sc.Text(), "\t")
			if len(cols) != 6 {
				die("bad case line %q", sc.Text())
			}
			fam, ok := families[cols[1]]
			if !ok {
				die("unknown key family %q", cols[1])
			}
			now, err := strconv.ParseInt(cols[2], 10, 64)
			if err != nil {
				die("bad now %q", cols[2])
			}
			_, err = jwt.Parse(cols[5], func(*jwt.Token) (any, error) { return fam.verKey, nil },
				jwt.WithValidMethods(fam.methods), jwt.WithIssuer(cols[3]), jwt.WithAudience(cols[4]),
				jwt.WithExpirationRequired(), jwt.WithLeeway(0),
				jwt.WithTimeFunc(func() time.Time { return time.Unix(now, 0) }))
			if err != nil {
				fmt.Fprintf(out, "%s\treject\t%s\n", cols[0], strings.ReplaceAll(err.Error(), "\t", " "))
			} else {
				fmt.Fprintf(out, "%s\tok\n", cols[0])
			}
		}
		if err := sc.Err(); err != nil {
			die("%v", err)
		}
	default:
		die("unknown mode %q", os.Args[2])
	}
}
