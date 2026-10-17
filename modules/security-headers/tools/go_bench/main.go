// SPDX-License-Identifier: MIT

// Go side of `zig build bench-security-headers`
// (modules/security-headers/tools/bench.zig): times github.com/unrolled/secure
// v1.17.0 (pinned by go.mod/go.sum) through its public API only, for the one
// workload named by the second argument (the first is the work directory the
// Zig program writes `csp_nonce.policy` into). Prints one line: name, ns/op,
// result count (tab-separated). One op = 64 responses.
//
// The lowest level that isolates the header work is `Secure.Process(w, r)`: it
// builds the header set and writes it into w.Header(), with no handler, no
// HTTP parsing and no serialisation. w is a minimal ResponseWriter holding one
// http.Header map that is cleared between responses (httptest's recorder would
// add a snapshot clone and a body buffer to every response); r is built once,
// outside the timed region.
//
//	apply_default / apply_static
//	            the default header set (9 headers, see bench.zig for the list
//	            and for what is left out on the Zig side so both emit the same)
//	csp_nonce   only Content-Security-Policy: the policy from csp_nonce.policy
//	            with "$NONCE" in script-src and style-src, a fresh 16-byte
//	            nonce per response (crypto/rand, base64 without padding)
//
// count = sum over responses of (headers + name bytes + value bytes); the
// nonce text is 22 bytes on both sides, so the sums agree.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unrolled/secure"
)

const perOp = 64

var sink int

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

// A ResponseWriter that only holds the header map.
type hdrs struct{ h http.Header }

func (w *hdrs) Header() http.Header         { return w.h }
func (w *hdrs) WriteHeader(int)             {}
func (w *hdrs) Write(p []byte) (int, error) { return len(p), nil }

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]

	var opt secure.Options
	switch name {
	case "apply_default", "apply_static":
		opt = secure.Options{
			STSSeconds:                    31536000,
			STSIncludeSubdomains:          true,
			ForceSTSHeader:                true, // the request is plain HTTP; ours has no such gate
			ContentTypeNosniff:            true,
			FrameDeny:                     true,
			ReferrerPolicy:                "no-referrer",
			CrossOriginOpenerPolicy:       "same-origin",
			CrossOriginResourcePolicy:     "same-origin",
			CustomBrowserXssValue:         "0",
			XDNSPrefetchControl:           "off",
			XPermittedCrossDomainPolicies: "none",
		}
	case "csp_nonce":
		b, err := os.ReadFile(filepath.Join(dir, "csp_nonce.policy"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		opt = secure.Options{ContentSecurityPolicy: strings.TrimSpace(string(b))}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	s := secure.New(opt)
	r, err := http.NewRequest("GET", "http://t/", nil)
	if err != nil {
		panic(err)
	}
	w := &hdrs{h: http.Header{}}

	ns, count := timeIt(func() int {
		sum := 0
		for i := 0; i < perOp; i++ {
			clear(w.h)
			if err := s.Process(w, r); err != nil {
				panic(err)
			}
			for k, v := range w.h {
				sum += 1 + len(k)
				for _, x := range v {
					sum += len(x)
				}
			}
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
