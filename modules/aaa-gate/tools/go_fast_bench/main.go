// SPDX-License-Identifier: MIT

// Go side of the "fastest in the field" part of the aaa-gate benchmark
// (modules/aaa-gate/tools/bench.zig, `go_bench/` is the labstack/echo
// reference): times the fast Go contenders over the SAME request bytes
// (`<work dir>/<workload>.wire`, written by bench.zig), at the same layer:
// router + middleware + the response rendered into a buffer, requests parsed
// once outside the timed region, no sockets.
//
//	go_fast_bench <contender> <work dir> <workload>
//
// contenders (versions pinned by go.mod/go.sum):
//
//	fiber2  gofiber/fiber v2.52.16  middleware/keyauth + middleware/basicauth,
//	                                driven through app.Handler() on a
//	                                fasthttp.RequestCtx
//	fiber3  gofiber/fiber v3.6.1    same, v3 API (extractors, native Users)
//	gin     gin-gonic/gin v1.12.0   BasicAuth only (gin has no key/bearer
//	                                middleware); gin.Engine.ServeHTTP
//
// workloads: bearer_ok bearer_denied api_key_header_ok api_key_query_ok
// no_credential basic_ok basic_denied, each also as `<w>_plain` (no middleware,
// the twin the Zig side subtracts) and, where the contender has a second
// validator kind, `<w>_raw`.
//
// VALIDATORS. The verdict validator gives aaa-gate's guarantee (owner decision
// 2026-10-17, like for like): only SHA-256 digests of the configured
// credentials kept, the presented value hashed and compared against EVERY
// digest with subtle.ConstantTimeCompare, no early exit. `_raw` is the
// contender's other path (raw secrets in memory, compared directly): INFORMATION
// ONLY, not in the verdict. fiber3 basic_* use the library's own `Users` with
// "{SHA256}" digests (a digest-only store built in; counts as like for like).
// gin's BasicAuth keeps the secrets (as base64 header strings) and compares the
// whole header with ConstantTimeCompare: it can only run as `_raw`.
//
// Output: `name<TAB>ns/op<TAB>count`; one op = every request (64) once; count =
// sum of status codes. Timing as in go_bench: double the batch until it takes
// over 100 ms, then best of five.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	fiber2 "github.com/gofiber/fiber/v2"
	basicauth2 "github.com/gofiber/fiber/v2/middleware/basicauth"
	keyauth2 "github.com/gofiber/fiber/v2/middleware/keyauth"
	fiber3 "github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	basicauth3 "github.com/gofiber/fiber/v3/middleware/basicauth"
	keyauth3 "github.com/gofiber/fiber/v3/middleware/keyauth"
	"github.com/valyala/fasthttp"
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

// The three configured keys (the same strings as bench.zig and go_bench).
var keys = []string{
	"tok-alpha-0123456789abcdef",
	"tok-bravo-0123456789abcdef",
	"tok-charlie-0123456789abcd",
}

var digests = func() [][32]byte {
	var out [][32]byte
	for _, k := range keys {
		out = append(out, sha256.Sum256([]byte(k)))
	}
	return out
}()

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

func hashedKey(key string) bool    { return digestMatch(digests, sha256.Sum256([]byte(key))) }
func hashedBasic(u, p string) bool { return digestMatch(basicDigests, sha256.Sum256([]byte(u+":"+p))) }
func rawKey(key string) bool {
	kb := []byte(key)
	for _, k := range keys {
		if subtle.ConstantTimeCompare(kb, []byte(k)) == 1 {
			return true
		}
	}
	return false
}
func rawBasic(u, p string) bool {
	for i, k := range keys {
		if subtle.ConstantTimeCompare([]byte(u), []byte(fmt.Sprintf("user-%d", i))) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(k)) == 1 {
			return true
		}
	}
	return false
}

func readWire(dir, name string) [][]byte {
	b, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var out [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		out = append(out, []byte(l))
	}
	return out
}

// ---- fasthttp-based (fiber v2 / v3) ----

// runFast drives app.Handler() over requests parsed once into RequestCtx; each
// op resets the response and re-sets the request URI (so the lazily cached
// URI / query-args parse is redone per request, as echo's url.Values is; the
// plain twin pays the same) and renders the response as a server would.
func runFast(h fasthttp.RequestHandler, wires [][]byte) (float64, int) {
	ctxs := make([]*fasthttp.RequestCtx, len(wires))
	uris := make([][]byte, len(wires))
	for i, w := range wires {
		c := &fasthttp.RequestCtx{}
		if err := c.Request.Read(bufio.NewReader(bytes.NewReader(w))); err != nil {
			panic(err)
		}
		uris[i] = append([]byte(nil), c.Request.RequestURI()...)
		ctxs[i] = c
	}
	var sinkBuf bytes.Buffer
	bw := bufio.NewWriterSize(&sinkBuf, 4096)
	return timeIt(func() int {
		sum := 0
		for i, c := range ctxs {
			c.Response.Reset()
			c.Request.SetRequestURIBytes(uris[i])
			h(c)
			sinkBuf.Reset()
			bw.Reset(&sinkBuf)
			_ = c.Response.Write(bw)
			_ = bw.Flush()
			sum += c.Response.StatusCode()
		}
		return sum
	})
}

func fiber2App(base, name string, plain, raw bool) *fiber2.App {
	app := fiber2.New(fiber2.Config{DisableStartupMessage: true})
	if !plain {
		switch base {
		case "bearer_ok", "bearer_denied", "no_credential", "api_key_header_ok", "api_key_query_ok":
			lookup, scheme := "header:Authorization", "Bearer"
			if base == "api_key_header_ok" {
				lookup, scheme = "header:X-Api-Key", ""
			} else if base == "api_key_query_ok" {
				lookup, scheme = "query:api_key", ""
			}
			f := hashedKey
			if raw {
				f = rawKey
			}
			app.Use(keyauth2.New(keyauth2.Config{KeyLookup: lookup, AuthScheme: scheme,
				Validator: func(c *fiber2.Ctx, key string) (bool, error) { return f(key), nil }}))
		case "basic_ok", "basic_denied":
			if raw { // the library's own Users map (raw passwords)
				app.Use(basicauth2.New(basicauth2.Config{Users: map[string]string{
					"user-0": keys[0], "user-1": keys[1], "user-2": keys[2]}}))
			} else {
				app.Use(basicauth2.New(basicauth2.Config{Authorizer: hashedBasic}))
			}
		}
	}
	app.Get("/", func(c *fiber2.Ctx) error { return c.SendString("ok") })
	return app
}

func fiber3App(base, name string, plain, raw bool) *fiber3.App {
	app := fiber3.New()
	if !plain {
		switch base {
		case "bearer_ok", "bearer_denied", "no_credential", "api_key_header_ok", "api_key_query_ok":
			ex := extractors.FromAuthHeader("Bearer")
			if base == "api_key_header_ok" {
				ex = extractors.FromHeader("X-Api-Key")
			} else if base == "api_key_query_ok" {
				ex = extractors.FromQuery("api_key")
			}
			f := hashedKey
			if raw {
				f = rawKey
			}
			app.Use(keyauth3.New(keyauth3.Config{Extractor: ex,
				Validator: func(c fiber3.Ctx, key string) (bool, error) { return f(key), nil }}))
		case "basic_ok", "basic_denied":
			if raw { // Authorizer over the raw passwords
				app.Use(basicauth3.New(basicauth3.Config{Authorizer: func(u, p string, c fiber3.Ctx) bool { return rawBasic(u, p) }}))
			} else {
				users := map[string]string{}
				for i, k := range keys {
					sum := sha256.Sum256([]byte(k))
					users[fmt.Sprintf("user-%d", i)] = "{SHA256}" + base64.StdEncoding.EncodeToString(sum[:])
				}
				app.Use(basicauth3.New(basicauth3.Config{Users: users}))
			}
		}
	}
	app.Get("/", func(c fiber3.Ctx) error { return c.SendString("ok") })
	return app
}

// ---- net/http based (gin) ----

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

func runGin(base string, plain bool, wires [][]byte) (float64, int) {
	gin.SetMode(gin.ReleaseMode)
	e := gin.New()
	if !plain {
		e.Use(gin.BasicAuth(gin.Accounts{"user-0": keys[0], "user-1": keys[1], "user-2": keys[2]}))
	}
	e.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	var reqs []*http.Request
	for _, w := range wires {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(w)))
		if err != nil {
			panic(err)
		}
		reqs = append(reqs, req)
	}
	return timeIt(func() int {
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
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <fiber2|fiber3|gin> <work dir> <workload>")
		os.Exit(2)
	}
	who, dir, name := os.Args[1], os.Args[2], os.Args[3]
	plain := strings.HasSuffix(name, "_plain")
	raw := strings.HasSuffix(name, "_raw")
	base := strings.TrimSuffix(strings.TrimSuffix(name, "_plain"), "_raw")
	wires := readWire(dir, name)
	var ns float64
	var count int
	switch who {
	case "fiber2":
		ns, count = runFast(fiber2App(base, name, plain, raw).Handler(), wires)
	case "fiber3":
		ns, count = runFast(fiber3App(base, name, plain, raw).Handler(), wires)
	case "gin":
		if !strings.HasPrefix(base, "basic_") || (!plain && !raw) {
			fmt.Printf("%s\tunsupported\t0\n", name)
			os.Exit(3)
		}
		ns, count = runGin(base, plain, wires)
	default:
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
