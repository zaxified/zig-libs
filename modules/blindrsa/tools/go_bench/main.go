// SPDX-License-Identifier: MIT

// Go side of `zig build bench-blindrsa` (modules/blindrsa/tools/bench.zig):
// Cloudflare CIRCL v1.6.1 `blindsign/blindrsa` (RFC 9474), the measurable
// stand-in for the RFC. Two phases, both given the work directory:
//
//	blind     make sure the RSA keys exist (generated once with crypto/rsa and
//	          kept as PKCS#1 DER), run the whole protocol on the message the
//	          Zig side wrote (msg.bin) for two variants and both key sizes, and
//	          write what the Zig side needs: <tag>.prepared, <tag>.blinded
//	          (for the Zig signer), <tag>.go_blindsig, <tag>.go_sig.
//	finalize  replay the same Blind (the randomness is a fixed hash stream, so
//	          the client state is rebuilt exactly), finalize the blind
//	          signature the Zig signer made, verify the signature the Zig
//	          client made, then time blind / blindSign / finalize / verify.
//	          One line per workload: name, ns/op, output length.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. Standard library plus CIRCL only.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// stream is a deterministic io.Reader: SHA-256(seed || counter) blocks.
type stream struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func (s *stream) Read(p []byte) (int, error) {
	for n := 0; n < len(p); {
		if len(s.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], s.ctr)
			s.ctr++
			h := sha256.Sum256(append(append([]byte{}, s.seed...), c[:]...))
			s.buf = h[:]
		}
		k := copy(p[n:], s.buf)
		s.buf = s.buf[k:]
		n += k
	}
	return len(p), nil
}

type variant struct {
	name string
	v    blindrsa.Variant
}

var variants = []variant{
	{"rand", blindrsa.SHA384PSSRandomized},
	{"zero", blindrsa.SHA384PSSZeroDeterministic},
}

var sizes = []int{2048, 4096}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "go_bench: "+format+"\n", a...)
	os.Exit(1)
}

func must[T any](v T, err error) T {
	if err != nil {
		die("%v", err)
	}
	return v
}

func loadKey(dir string, bits int) *rsa.PrivateKey {
	path := filepath.Join(dir, fmt.Sprintf("key%d.der", bits))
	der, err := os.ReadFile(path)
	if err != nil {
		k := must(rsa.GenerateKey(rand.Reader, bits))
		der = x509.MarshalPKCS1PrivateKey(k)
		if err := os.WriteFile(path, der, 0o600); err != nil {
			die("%v", err)
		}
		pub := x509.MarshalPKCS1PublicKey(&k.PublicKey)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("pub%d.der", bits)), pub, 0o644); err != nil {
			die("%v", err)
		}
	}
	return must(x509.ParsePKCS1PrivateKey(der))
}

func timeIt(f func() int) (float64, int) {
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
	return float64(best.Nanoseconds()) / float64(n), count
}

func write(dir, name string, b []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		die("%v", err)
	}
}

func read(dir, name string) []byte { return must(os.ReadFile(filepath.Join(dir, name))) }

func main() {
	if len(os.Args) != 3 {
		die("usage: go_bench <dir> blind|finalize")
	}
	dir, phase := os.Args[1], os.Args[2]
	msg := read(dir, "msg.bin")
	fmt.Fprintf(os.Stderr, "CIRCL v1.6.1 blindsign/blindrsa")

	for _, bits := range sizes {
		key := loadKey(dir, bits)
		signer := blindrsa.NewSigner(key)
		for _, va := range variants {
			tag := fmt.Sprintf("%d_%s", bits, va.name)
			client := must(blindrsa.NewClient(va.v, &key.PublicKey))
			det := &stream{seed: []byte("blindrsa-bench " + tag)}
			prepared := must(client.Prepare(det, msg))
			blinded, state := must2(client.Blind(det, prepared))

			switch phase {
			case "blind":
				blindSig := must(signer.BlindSign(blinded))
				sig := must(client.Finalize(state, blindSig))
				write(dir, tag+".prepared", prepared)
				write(dir, tag+".blinded", blinded)
				write(dir, tag+".go_blindsig", blindSig)
				write(dir, tag+".go_sig", sig)
			case "finalize":
				if !bytes.Equal(blinded, read(dir, tag+".blinded")) {
					die("%s: the replayed Blind differs from the first one", tag)
				}
				oursBlindSig := read(dir, tag+".ours_blindsig")
				if _, err := client.Finalize(state, oursBlindSig); err != nil {
					die("%s: CIRCL cannot finalize the blind signature made by the Zig signer: %v", tag, err)
				}
				if err := client.Verify(read(dir, tag+".ours_prepared"), read(dir, tag+".ours_sig")); err != nil {
					die("%s: CIRCL rejects the signature made by the Zig client: %v", tag, err)
				}
				blindSig := must(signer.BlindSign(blinded))
				sig := must(client.Finalize(state, blindSig))
				row := func(name string, f func() int) {
					ns, n := timeIt(f)
					fmt.Printf("%s_%s\t%.1f\t%d\n", tag, name, ns, n)
				}
				row("blind", func() int {
					b, _, err := client.Blind(rand.Reader, prepared)
					if err != nil {
						die("%v", err)
					}
					return len(b)
				})
				row("blindsign", func() int {
					b, err := signer.BlindSign(blinded)
					if err != nil {
						die("%v", err)
					}
					return len(b)
				})
				row("finalize", func() int {
					b, err := client.Finalize(state, blindSig)
					if err != nil {
						die("%v", err)
					}
					return len(b)
				})
				row("verify", func() int {
					if err := client.Verify(prepared, sig); err != nil {
						die("%v", err)
					}
					return len(sig)
				})
			default:
				die("unknown phase %q", phase)
			}
		}
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		die("%v", err)
	}
	return a, b
}
