// SPDX-License-Identifier: MIT
//
// Go side of `zig build bench-hashdigest` (modules/hashdigest/tools/bench.zig):
// times Go's one-shot digest + `encoding/hex` (`hex.Encode` into a reused
// buffer) -- the survey's reference for this module -- for the one workload
// named by the second argument (`go.<algo>_<size>`), over `msg<size>.bin` in
// the directory given as the first. Algorithms: crypto/sha256 (Sum256,
// Sum224), crypto/sha512 (Sum512, Sum384, Sum512_256), crypto/sha3 (Sum256,
// Sum512) and golang.org/x/crypto/blake2b (Sum256). Prints one line: name,
// ns/op, 0 (no cycle counter on this side), hex characters per op. The run
// named `interop` writes `go_<algo>.hex` of msg65536.bin for every algorithm.
//
// Built by bench.zig in a copy under .zig-cache with GOPROXY=off,
// GOFLAGS=-mod=mod and GOTOOLCHAIN=local: x/crypto must already be in the Go
// module cache (`go mod download golang.org/x/crypto@v0.57.0`); go.sum pins it.
package main

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

var out [128]byte

func enc(sum []byte) int { return hex.Encode(out[:], sum) }

var algos = map[string]func([]byte) int{
	"sha256":     func(b []byte) int { s := sha256.Sum256(b); return enc(s[:]) },
	"sha224":     func(b []byte) int { s := sha256.Sum224(b); return enc(s[:]) },
	"sha384":     func(b []byte) int { s := sha512.Sum384(b); return enc(s[:]) },
	"sha512":     func(b []byte) int { s := sha512.Sum512(b); return enc(s[:]) },
	"sha512_256": func(b []byte) int { s := sha512.Sum512_256(b); return enc(s[:]) },
	"sha3_256":   func(b []byte) int { s := sha3.Sum256(b); return enc(s[:]) },
	"sha3_512":   func(b []byte) int { s := sha3.Sum512(b); return enc(s[:]) },
	"blake2b256": func(b []byte) int { s := blake2b.Sum256(b); return enc(s[:]) },
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: hashdigest_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, w := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "Go "+runtime.Version()+" (x/crypto v0.57.0 for BLAKE2b)")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return b
	}
	if w == "interop" {
		msg := read("msg65536.bin")
		for name, f := range algos {
			n := f(msg)
			if err := os.WriteFile(filepath.Join(dir, "go_"+name+".hex"), out[:n], 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}
	rest, ok := strings.CutPrefix(w, "go.")
	us := strings.LastIndexByte(rest, '_')
	if !ok || us < 0 || algos[rest[:us]] == nil {
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
	f, msg := algos[rest[:us]], read("msg"+rest[us+1:]+".bin")
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			f(msg)
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best, count := time.Duration(1<<62), 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f(msg)
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	fmt.Printf("%s\t%.1f\t0\t%d\n", w, float64(best.Nanoseconds())/float64(n), count)
}
