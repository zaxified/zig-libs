// SPDX-License-Identifier: MIT

// Go side of `zig build bench-aaa-gate` (modules/aaa-gate/tools/bench.zig):
// times labstack/echo v5.4.0 `middleware.KeyAuthWithConfig` (pinned by
// go.mod/go.sum) as middleware of an echo instance with one trivial route,
// over the request bytes the Zig program writes into the directory given as
// the first argument, for the one workload named by the second, through
// echo's public API only. Prints one line: name, ns/op, result count
// (tab-separated). One op = every request (64) once.
//
// Workloads (the `_plain` twin of each runs the same bytes through an echo
// instance WITHOUT the middleware; the Zig side subtracts it, see bench.zig):
//
//	bearer_ok          KeyLookup "header:Authorization:Bearer ", valid token
//	bearer_denied      same lookup, a token that is on no list (401)
//	api_key_header_ok  KeyLookup "header:X-Api-Key"
//	api_key_query_ok   KeyLookup "query:api_key"
//	no_credential      the bearer lookup, no credential sent (401)
//	basic_ok           BasicAuthWithConfig, a valid user:password
//	basic_denied       same, a wrong password (401)
//
// echo leaves the comparison to the Validator. The VERDICT validator gives the
// same guarantee aaa-gate does (owner decision 2026-10-17: compare like for
// like): only SHA-256 digests of the configured credentials are kept, the
// presented value is hashed and compared against EVERY digest with
// subtle.ConstantTimeCompare, no early exit — neither length nor content
// leaks. A workload name ending in `_raw` uses echo's documented "SECURE"
// KeyAuthValidator example instead (ConstantTimeCompare against the raw keys,
// return on the first match — it leaks the key length and keeps the raw
// secrets): printed as information, not in the verdict. Each op is Echo.ServeHTTP
// over requests parsed once beforehand (http.ReadRequest, untimed), into a
// ResponseWriter that renders the
// status line, headers and body into a buffer (as a server would put them
// on the wire). count = the sum of the status codes.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

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

// A ResponseWriter that renders what a server would put on the wire.
type wire struct {
	h      http.Header
	buf    bytes.Buffer
	status int
}

func (w *wire) Header() http.Header { return w.h }
func (w *wire) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	fmt.Fprintf(&w.buf, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	w.h.Write(&w.buf)
	w.buf.WriteString("\r\n")
}
func (w *wire) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.buf.Write(p)
}

// The three configured keys (the same for tokens and API keys, as in bench.zig).
var keys = [][]byte{
	[]byte("tok-alpha-0123456789abcdef"),
	[]byte("tok-bravo-0123456789abcdef"),
	[]byte("tok-charlie-0123456789abcd"),
}

var digests = func() [][32]byte {
	var out [][32]byte
	for _, k := range keys {
		out = append(out, sha256.Sum256(k))
	}
	return out
}()

// The three Basic users: "user-<i>" with the key as password.
var basicDigests = func() [][32]byte {
	var out [][32]byte
	for i, k := range keys {
		out = append(out, sha256.Sum256([]byte(fmt.Sprintf("user-%d:%s", i, k))))
	}
	return out
}()

func digestMatch(set [][32]byte, d [32]byte) bool {
	found := 0
	for i := range set {
		found |= subtle.ConstantTimeCompare(d[:], set[i][:])
	}
	return found == 1
}

// The verdict validator: aaa-gate's guarantee (digests, every one compared).
func hashedValidator(c *echo.Context, key string, source middleware.ExtractorSource) (bool, error) {
	return digestMatch(digests, sha256.Sum256([]byte(key))), nil
}

func basicHashed(c *echo.Context, user, password string) (bool, error) {
	return digestMatch(basicDigests, sha256.Sum256([]byte(user+":"+password))), nil
}

func basicRaw(c *echo.Context, user, password string) (bool, error) {
	for i, k := range keys {
		if subtle.ConstantTimeCompare([]byte(user), []byte(fmt.Sprintf("user-%d", i))) == 1 &&
			subtle.ConstantTimeCompare([]byte(password), k) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// echo's KeyAuthValidator documentation's constant-time example (`_raw`).
func validator(c *echo.Context, key string, source middleware.ExtractorSource) (bool, error) {
	kb := []byte(key)
	for _, k := range keys {
		if subtle.ConstantTimeCompare(kb, k) == 1 {
			return true, nil
		}
	}
	return false, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	b, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Parsed once, outside the timed region: the layer is "router + middleware
	// + response rendering", not head parsing (as on the Zig side).
	var reqs []*http.Request
	for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(l)))
		if err != nil {
			panic(err)
		}
		reqs = append(reqs, req)
	}

	lookup := ""
	raw := strings.HasSuffix(name, "_raw")
	base := strings.TrimSuffix(strings.TrimSuffix(name, "_plain"), "_raw")
	switch base {
	case "bearer_ok", "bearer_denied", "no_credential":
		lookup = "header:Authorization:Bearer "
	case "api_key_header_ok":
		lookup = "header:X-Api-Key"
	case "api_key_query_ok":
		lookup = "query:api_key"
	case "basic_ok", "basic_denied":
		lookup = "basic"
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}

	e := echo.New()
	if !strings.HasSuffix(name, "_plain") {
		switch {
		case lookup == "basic" && raw:
			e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{Validator: basicRaw}))
		case lookup == "basic":
			e.Use(middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{Validator: basicHashed}))
		case raw:
			e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{KeyLookup: lookup, Validator: validator}))
		default:
			e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{KeyLookup: lookup, Validator: hashedValidator}))
		}
	}
	e.GET("/", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })

	ns, count := timeIt(func() int {
		sum := 0
		for _, req := range reqs {
			w := &wire{h: http.Header{}}
			e.ServeHTTP(w, req)
			if w.status == 0 {
				w.WriteHeader(http.StatusOK)
			}
			sum += w.status
		}
		return sum
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
