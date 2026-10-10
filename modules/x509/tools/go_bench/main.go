// SPDX-License-Identifier: MIT

// Go side of `zig build bench-x509` (modules/x509/tools/bench.zig): times Go's
// standard-library crypto/x509 (the module's reference; stdlib only, no
// third-party code) verifying certificate chains, through its public API only.
//
//	go_bench <dir> gen            writes the chains the Zig side also reads:
//	                              <kind>_leaf.der, <kind>_inter.der,
//	                              <kind>_root.der for kind in ecdsa256, rsa2048,
//	                              mixed (P-256 leaf under RSA-2048 CAs), plus
//	                              now.txt (the verification time, Unix seconds)
//	go_bench <dir> verify_<kind>  one op = what a TLS client does with a
//	                              received [leaf, intermediate] list and its
//	                              trust store: ParseCertificate x 2, add the
//	                              intermediate to a fresh pool, Verify against
//	                              a root pool built once (hostname and
//	                              serverAuth EKU checked)
//
// Prints one line for a verify workload: name, ns/op, cycles/op (0: no
// counter here, the driver then compares wall time), chain length (leaf to
// root) of the verified path. Timing matches the Zig side: double the batch
// until it takes over 100 ms, then keep the best of five.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const host = "bench.example.test"

var sink int

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func timeIt(f func() int) (float64, int) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
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
	return float64(best.Nanoseconds()) / float64(n), count
}

type keyGen func() crypto.Signer

func ec256() crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die(err)
	}
	return k
}

func rsa2048() crypto.Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		die(err)
	}
	return k
}

var serial int64

func issue(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) []byte {
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		die(err)
	}
	return der
}

func genChain(dir, kind string, root, inter, leaf keyGen, now time.Time) {
	rk, ik, lk := root(), inter(), leaf()
	nb, na := now.Add(-time.Hour), now.Add(10*365*24*time.Hour)
	rootT := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Bench Root " + kind}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER := issue(rootT, rootT, rk.Public(), rk)
	rootC, err := x509.ParseCertificate(rootDER)
	if err != nil {
		die(err)
	}
	interT := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Bench Intermediate " + kind}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER := issue(interT, rootC, ik.Public(), rk)
	interC, err := x509.ParseCertificate(interDER)
	if err != nil {
		die(err)
	}
	leafT := &x509.Certificate{
		Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER := issue(leafT, interC, lk.Public(), ik)
	for name, der := range map[string][]byte{"leaf": leafDER, "inter": interDER, "root": rootDER} {
		if err := os.WriteFile(filepath.Join(dir, kind+"_"+name+".der"), der, 0o644); err != nil {
			die(err)
		}
	}
}

func readNow(dir string) time.Time {
	b, err := os.ReadFile(filepath.Join(dir, "now.txt"))
	if err != nil {
		die(err)
	}
	s, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		die(err)
	}
	return time.Unix(s, 0)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> gen|verify_<kind>")
		os.Exit(2)
	}
	dir, w := os.Args[1], os.Args[2]
	if w == "gen" {
		now := time.Now().Truncate(time.Second)
		if err := os.WriteFile(filepath.Join(dir, "now.txt"), []byte(strconv.FormatInt(now.Unix(), 10)), 0o644); err != nil {
			die(err)
		}
		genChain(dir, "ecdsa256", ec256, ec256, ec256, now)
		genChain(dir, "rsa2048", rsa2048, rsa2048, rsa2048, now)
		genChain(dir, "mixed", rsa2048, rsa2048, ec256, now)
		return
	}
	kind, ok := strings.CutPrefix(w, "verify_")
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown workload %s\n", w)
		os.Exit(2)
	}
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, kind+"_"+n+".der"))
		if err != nil {
			die(err)
		}
		return b
	}
	leafDER, interDER := read("leaf"), read("inter")
	rootC, err := x509.ParseCertificate(read("root"))
	if err != nil {
		die(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootC)
	now := readNow(dir)
	fmt.Fprintf(os.Stderr, "Go %s crypto/x509\n", strings.TrimPrefix(runtime.Version(), "go"))
	ns, count := timeIt(func() int {
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			die(err)
		}
		inter, err := x509.ParseCertificate(interDER)
		if err != nil {
			die(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(inter)
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: pool, CurrentTime: now, DNSName: host,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			die(err)
		}
		return len(chains[0])
	})
	fmt.Printf("%s\t%.1f\t0\t%d\n", w, ns, count)
}
