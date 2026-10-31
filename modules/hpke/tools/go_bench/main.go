// SPDX-License-Identifier: MIT
//
// Go side of `zig build bench-hpke` (modules/hpke/tools/bench.zig): times the
// Go 1.26 standard library's crypto/hpke (the reference; standard library
// only, no third-party module) for the workload named by the second argument,
// over the keys the Zig program writes into the directory given as the first.
//
// Workloads: go.<suite>_<op>, suite = x25519, p256, p384, p521 (each with
// the RFC-paired HKDF and AES-128-GCM) or x25519cc (X25519, HKDF-SHA256,
// ChaCha20Poly1305), or a draft-ietf-hpke-pq KEM (mlkem768, mlkem1024, xwing,
// mlkem768p256, mlkem1024p384, xwingshake); op = keygen, setupS, setupR, seal64, open64, seal16k,
// open16k, export. Prints one line: name, ns/op, 0 (no cycle counter on this
// side, so the comparison is by wall time), and the output size the Zig side
// must agree with (the public key, `enc`, 1 for setupR, the ciphertext, the
// plaintext, 32 for the export).
//
// The run named `interop` opens what the Zig side sealed (`zig_<suite>.*`)
// and writes this side's (`go_<suite>.*`) for the Zig side to open.
//
// Open is timed on fresh contexts: a Recipient cannot be rewound, so a
// Sender seals a chunk of messages untimed and only the Recipient's Open
// calls are on the clock; the chunk is then thrown away.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

var info = []byte("bench info")

const (
	aad        = "interop-aad"
	exporterCx = "interop-export"
)

var dir string

func fail(a ...any) {
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func slurp(name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fail(err)
	}
	return b
}

func spit(name string, b []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		fail(err)
	}
}

// Plaintexts: the same bytes on both sides.
func ptShort() []byte {
	p := make([]byte, 64)
	for i := range p {
		p[i] = byte(i*7 + 1)
	}
	return p
}

func ptLong() []byte {
	p := make([]byte, 16384)
	for i := range p {
		p[i] = byte(i*31 + 5)
	}
	return p
}

type suite struct {
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}

var suites = map[string]suite{
	"x25519":   {hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"p256":     {hpke.DHKEM(ecdh.P256()), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"p384":     {hpke.DHKEM(ecdh.P384()), hpke.HKDFSHA384(), hpke.AES128GCM()},
	"p521":     {hpke.DHKEM(ecdh.P521()), hpke.HKDFSHA512(), hpke.AES128GCM()},
	"x25519cc": {hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()},
	// draft-ietf-hpke-pq (Go 1.26): HKDF-SHA256 + AES-128-GCM, X-Wing also over SHAKE256.
	"mlkem768":      {hpke.MLKEM768(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"mlkem1024":     {hpke.MLKEM1024(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"xwing":         {hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"mlkem768p256":  {hpke.MLKEM768P256(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"mlkem1024p384": {hpke.MLKEM1024P384(), hpke.HKDFSHA256(), hpke.AES128GCM()},
	"xwingshake":    {hpke.MLKEM768X25519(), hpke.SHAKE256(), hpke.AES128GCM()},
}

func must[T any](v T, err error) T {
	if err != nil {
		fail(err)
	}
	return v
}

// batch doubles n until f(n) takes over 100 ms, then keeps the best of five
// runs of f(n); f(n) returns the time its n operations took.
func batch(name string, f func(n int) time.Duration, count func() int) {
	n := 1
	for f(n) <= 100*time.Millisecond {
		n *= 2
	}
	best := time.Duration(1 << 62)
	for k := 0; k < 5; k++ {
		if d := f(n); d < best {
			best = d
		}
	}
	fmt.Printf("%s\t%.1f\t0\t%d\n", name, float64(best.Nanoseconds())/float64(n), count())
}

// bench times n calls of g, whole.
func bench(name string, g func() int) {
	last := 0
	batch(name, func(n int) time.Duration {
		t := time.Now()
		for i := 0; i < n; i++ {
			last = g()
		}
		return time.Since(t)
	}, func() int { return last })
}

// benchOpen times only Open: chunk messages are sealed (untimed) by a fresh
// Sender, a fresh Recipient opens them in order.
func benchOpen(name string, s suite, pk hpke.PublicKey, sk hpke.PrivateKey, pt []byte, chunk int) {
	last := 0
	batch(name, func(n int) time.Duration {
		var total time.Duration
		cts := make([][]byte, chunk)
		for done := 0; done < n; {
			enc, snd, err := hpke.NewSender(pk, s.kdf, s.aead, info)
			if err != nil {
				fail(err)
			}
			rcv := must(hpke.NewRecipient(enc, sk, s.kdf, s.aead, info))
			m := min(chunk, n-done)
			for i := 0; i < m; i++ {
				cts[i] = must(snd.Seal(nil, pt))
			}
			runtime.GC()
			t := time.Now()
			for i := 0; i < m; i++ {
				p, err := rcv.Open(nil, cts[i])
				if err != nil {
					fail("open:", err)
				}
				last = len(p)
			}
			total += time.Since(t)
			done += m
		}
		return total
	}, func() int { return last })
}

func keys(name string, s suite) (hpke.PublicKey, hpke.PrivateKey) {
	sk := must(s.kem.NewPrivateKey(slurp(name + ".sk")))
	pk := sk.PublicKey()
	if !bytes.Equal(pk.Bytes(), slurp(name+".pk")) {
		fail(name, ": the public key derived here differs from the Zig side's")
	}
	return pk, sk
}

func interop() {
	for name, s := range suites {
		pk, sk := keys(name, s)
		// Zig sealed, we open.
		enc := slurp("zig_" + name + ".enc")
		rcv := must(hpke.NewRecipient(enc, sk, s.kdf, s.aead, info))
		for i, want := range [][]byte{ptShort(), ptLong()} {
			got, err := rcv.Open([]byte(aad), slurp(fmt.Sprintf("zig_%s.ct%d", name, i)))
			if err != nil {
				fail(name, ": Go cannot open the Zig side's message", i, ":", err)
			}
			if !bytes.Equal(got, want) {
				fail(name, ": message", i, "opened to other bytes")
			}
		}
		if !bytes.Equal(must(rcv.Export(exporterCx, 32)), slurp("zig_"+name+".exp")) {
			fail(name, ": the exports differ (Zig sealed)")
		}
		// We seal, Zig opens.
		enc2, snd, err := hpke.NewSender(pk, s.kdf, s.aead, info)
		if err != nil {
			fail(err)
		}
		spit("go_"+name+".enc", enc2)
		for i, pt := range [][]byte{ptShort(), ptLong()} {
			spit(fmt.Sprintf("go_%s.ct%d", name, i), must(snd.Seal([]byte(aad), pt)))
		}
		spit("go_"+name+".exp", must(snd.Export(exporterCx, 32)))
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: hpke_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir = os.Args[1]
	w := os.Args[2]
	ver := "Go crypto/hpke"
	if bi, ok := debug.ReadBuildInfo(); ok {
		ver += ", " + bi.GoVersion
	}
	fmt.Fprintln(os.Stderr, ver)

	if w == "interop" {
		interop()
		return
	}
	rest, ok := strings.CutPrefix(w, "go.")
	name, op, ok2 := strings.Cut(rest, "_")
	s, ok3 := suites[name]
	if !ok || !ok2 || !ok3 {
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
	pk, sk := keys(name, s)
	short, long := ptShort(), ptLong()

	switch op {
	case "keygen":
		bench(w, func() int {
			k := must(s.kem.GenerateKey())
			return len(k.PublicKey().Bytes())
		})
	case "setupS":
		bench(w, func() int {
			enc, _, err := hpke.NewSender(pk, s.kdf, s.aead, info)
			if err != nil {
				fail(err)
			}
			return len(enc)
		})
	case "setupR":
		enc, _, err := hpke.NewSender(pk, s.kdf, s.aead, info)
		if err != nil {
			fail(err)
		}
		bench(w, func() int {
			if _, err := hpke.NewRecipient(enc, sk, s.kdf, s.aead, info); err != nil {
				fail(err)
			}
			return 1
		})
	case "seal64", "seal16k":
		pt := short
		if op == "seal16k" {
			pt = long
		}
		_, snd, err := hpke.NewSender(pk, s.kdf, s.aead, info)
		if err != nil {
			fail(err)
		}
		bench(w, func() int { return len(must(snd.Seal(nil, pt))) })
	case "open64":
		benchOpen(w, s, pk, sk, short, 4096)
	case "open16k":
		benchOpen(w, s, pk, sk, long, 256)
	case "export":
		_, snd, err := hpke.NewSender(pk, s.kdf, s.aead, info)
		if err != nil {
			fail(err)
		}
		bench(w, func() int { return len(must(snd.Export(exporterCx, 32))) })
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
}
