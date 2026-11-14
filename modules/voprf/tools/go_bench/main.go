// SPDX-License-Identifier: MIT

// Go side of `zig build bench-voprf` (modules/voprf/tools/bench.zig):
// Cloudflare CIRCL v1.6.1 `oprf` (RFC 9497), the measurable reference. Two
// phases, both given the work directory the Zig side filled (msg.bin, and per
// <suite>_<mode> tag the blind scalar <tag>.blind in RFC 9497 serialization):
//
//	prep  derive the key with oprf.DeriveKey(seed, info), run the client's
//	      DeterministicBlind with the shared blind and the CIRCL server on
//	      it, and write sk/pk, FullEvaluate, the blinded element and the
//	      CIRCL evaluation (+ proof) for the Zig side to check and finalize.
//	run   replay the same DeterministicBlind, finalize the evaluation the Zig
//	      server made (verifying its proof in VOPRF/POPRF; the output must
//	      equal FullEvaluate), then time blind / blindEvaluate / finalize /
//	      fullEvaluate. One line per workload: name, ns/op, output length.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five. Standard library plus CIRCL only (CIRCL pulls
// go-ristretto and x/crypto, pure Go plus one amd64 field-mul assembly file).
//
// go.mod pin: CIRCL v1.6.1 asks for golang.org/x/crypto v0.11.1-0.20230711...,
// which is not in the offline module cache, so go.mod pins the cached
// x/crypto v0.13.0 (and x/sys v0.12.0 through it). CIRCL uses only the
// pure-Go blake2/sha3 packages from it; nothing is downloaded (GOPROXY=off).
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/zk/dleq"
)

type suite struct {
	name string
	s    oprf.Suite
}

var suites = []suite{
	{"r255", oprf.SuiteRistretto255},
	{"p256", oprf.SuiteP256},
	{"p384", oprf.SuiteP384},
	{"p521", oprf.SuiteP521},
}

type mode struct {
	name string
	m    oprf.Mode
}

var modes = []mode{
	{"oprf", oprf.BaseMode},
	{"voprf", oprf.VerifiableMode},
	{"poprf", oprf.PartialObliviousMode},
}

var (
	seed    = bytes.Repeat([]byte{0xa3}, 32)
	keyInfo = []byte("bench key")
	info    = []byte("bench info")
)

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

// role bundles one suite x mode as closures over CIRCL's client and server
// types for that mode.
type role struct {
	blindDet  func() (*oprf.FinalizeData, *oprf.EvaluationRequest)
	blindRand func() (*oprf.FinalizeData, *oprf.EvaluationRequest)
	evaluate  func(*oprf.EvaluationRequest) *oprf.Evaluation
	finalize  func(*oprf.FinalizeData, *oprf.Evaluation) ([]byte, error)
	full      func() []byte
	key       *oprf.PrivateKey
}

func first(o [][]byte, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return o[0], nil
}

func newRole(su suite, mo mode, input, blindBytes []byte) role {
	key := must(oprf.DeriveKey(su.s, mo.m, seed, keyInfo))
	sc := su.s.Group().NewScalar()
	if err := sc.UnmarshalBinary(blindBytes); err != nil {
		die("blind scalar: %v", err)
	}
	blinds := []oprf.Blind{sc}
	inputs := [][]byte{input}
	r := role{key: key}
	ev := func(e *oprf.Evaluation, err error) *oprf.Evaluation {
		if err != nil {
			die("evaluate: %v", err)
		}
		return e
	}
	two := func(f *oprf.FinalizeData, q *oprf.EvaluationRequest, err error) (*oprf.FinalizeData, *oprf.EvaluationRequest) {
		if err != nil {
			die("blind: %v", err)
		}
		return f, q
	}
	switch mo.m {
	case oprf.BaseMode:
		c := oprf.NewClient(su.s)
		s := oprf.NewServer(su.s, key)
		r.blindDet = func() (*oprf.FinalizeData, *oprf.EvaluationRequest) { return two(c.DeterministicBlind(inputs, blinds)) }
		r.blindRand = func() (*oprf.FinalizeData, *oprf.EvaluationRequest) { return two(c.Blind(inputs)) }
		r.evaluate = func(q *oprf.EvaluationRequest) *oprf.Evaluation { return ev(s.Evaluate(q)) }
		r.finalize = func(f *oprf.FinalizeData, e *oprf.Evaluation) ([]byte, error) { return first(c.Finalize(f, e)) }
		r.full = func() []byte { return must(s.FullEvaluate(input)) }
	case oprf.VerifiableMode:
		c := oprf.NewVerifiableClient(su.s, key.Public())
		s := oprf.NewVerifiableServer(su.s, key)
		r.blindDet = func() (*oprf.FinalizeData, *oprf.EvaluationRequest) { return two(c.DeterministicBlind(inputs, blinds)) }
		r.blindRand = func() (*oprf.FinalizeData, *oprf.EvaluationRequest) { return two(c.Blind(inputs)) }
		r.evaluate = func(q *oprf.EvaluationRequest) *oprf.Evaluation { return ev(s.Evaluate(q)) }
		r.finalize = func(f *oprf.FinalizeData, e *oprf.Evaluation) ([]byte, error) { return first(c.Finalize(f, e)) }
		r.full = func() []byte { return must(s.FullEvaluate(input)) }
	case oprf.PartialObliviousMode:
		c := oprf.NewPartialObliviousClient(su.s, key.Public())
		s := oprf.NewPartialObliviousServer(su.s, key)
		r.blindDet = func() (*oprf.FinalizeData, *oprf.EvaluationRequest) { return two(c.DeterministicBlind(inputs, blinds)) }
		r.blindRand = func() (*oprf.FinalizeData, *oprf.EvaluationRequest) { return two(c.Blind(inputs)) }
		r.evaluate = func(q *oprf.EvaluationRequest) *oprf.Evaluation { return ev(s.Evaluate(q, info)) }
		r.finalize = func(f *oprf.FinalizeData, e *oprf.Evaluation) ([]byte, error) { return first(c.Finalize(f, e, info)) }
		r.full = func() []byte { return must(s.FullEvaluate(input, info)) }
	}
	return r
}

func main() {
	if len(os.Args) != 3 {
		die("usage: go_bench <dir> prep|run")
	}
	dir, phase := os.Args[1], os.Args[2]
	if phase != "prep" && phase != "run" {
		die("unknown phase %q", phase)
	}
	input := read(dir, "msg.bin")
	fmt.Fprintf(os.Stderr, "CIRCL v1.6.1 oprf")

	for _, su := range suites {
		g := su.s.Group()
		for _, mo := range modes {
			tag := su.name + "_" + mo.name
			r := newRole(su, mo, input, read(dir, tag+".blind"))
			fd, req := r.blindDet()
			switch phase {
			case "prep":
				write(dir, tag+".sk", must(r.key.MarshalBinary()))
				write(dir, tag+".pk", must(r.key.Public().MarshalBinary()))
				write(dir, tag+".go_full", r.full())
				write(dir, tag+".go_blinded", must(req.Elements[0].MarshalBinaryCompress()))
				e := r.evaluate(req)
				write(dir, tag+".go_eval", must(e.Elements[0].MarshalBinaryCompress()))
				if mo.m != oprf.BaseMode {
					write(dir, tag+".go_proof", must(e.Proof.MarshalBinary()))
				}
			case "run":
				// The evaluation the Zig server made for the same blinded element.
				el := g.NewElement()
				if err := el.UnmarshalBinary(read(dir, tag+".ours_eval")); err != nil {
					die("%s: cannot parse our evaluated element: %v", tag, err)
				}
				oe := &oprf.Evaluation{Elements: []oprf.Evaluated{el}}
				if mo.m != oprf.BaseMode {
					oe.Proof = new(dleq.Proof)
					if err := oe.Proof.UnmarshalBinary(g, read(dir, tag+".ours_proof")); err != nil {
						die("%s: cannot parse our proof: %v", tag, err)
					}
				}
				out, err := r.finalize(fd, oe)
				if err != nil {
					die("%s: CIRCL cannot finalize the evaluation made by the Zig server: %v", tag, err)
				}
				if !bytes.Equal(out, read(dir, tag+".go_full")) {
					die("%s: CIRCL's finalize of our evaluation differs from its FullEvaluate", tag)
				}
				e := r.evaluate(req)
				row := func(name string, f func() int) {
					ns, n := timeIt(f)
					fmt.Printf("%s_%s\t%.1f\t%d\n", tag, name, ns, n)
				}
				row("blind", func() int {
					_, q := r.blindRand()
					return len(must(q.Elements[0].MarshalBinaryCompress()))
				})
				row("blindeval", func() int {
					x := r.evaluate(req)
					return len(must(x.Elements[0].MarshalBinaryCompress()))
				})
				row("finalize", func() int {
					o, err := r.finalize(fd, e)
					if err != nil {
						die("%v", err)
					}
					return len(o)
				})
				row("fulleval", func() int { return len(r.full()) })
			}
		}
	}
}
