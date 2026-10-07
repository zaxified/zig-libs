// SPDX-License-Identifier: MIT

// Differential oracle for router's chi-parity surface: go-chi/chi v5.3.2
// (MIT, the module's declared reference), run as a black box through its
// public API (NewRouter, Method, ServeHTTP, RouteContext). The inputs are
// OURS -- seeded route tables and requests below; chi only answers them, and
// the answers are written out as a Zig file that `src/chi_oracle_test.zig`
// replays hermetically. No chi source was read or ported.
//
//	cd modules/router/tools/go_chi_oracle
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -out ../../src/chi_vectors.zig
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -check ../../src/chi_vectors.zig
//
// Needs github.com/go-chi/chi/v5 (pinned by go.mod/go.sum) in the module
// cache: `GOTOOLCHAIN=go1.26.0 go mod download` once, with network; and `zig`
// on PATH (the output goes through `zig fmt --stdin`).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

const seed = 0x636869726f757465 // "chiroute"

var rnd = rand.New(rand.NewPCG(seed, seed^0x5a5a))

const (
	nTables   = 60
	nRequests = 60
)

var methods = []string{"GET", "POST", "PUT", "DELETE"}

var staticWords = []string{"a", "b", "users", "v1", "x.y", "a-b"}

var denseShapes = []string{
	"a", "v1", "x.y", "{p0}", "{p0}.json", "{p0}.{q0}", "v{p0}", "{p0}-{q0}", "pre{p0}", "{p0}~x", "a{p0}_{q0}.txt",
	"{p0:[0-9]+}", "{p0:[a-z]+}", "{p0:[0-9]+}.json", "v{p0:[0-9]+}", "{p0:[a-c]+}-{q0}",
}

// One pattern segment at depth d. Capture names are fixed per depth, so two
// routes of a table never disagree on a name at one position (both routers
// refuse that, differently); every in-segment shape the module documents is
// drawn.
func patternSegment(d int, last bool) string {
	p := fmt.Sprintf("p%d", d)
	q := fmt.Sprintf("q%d", d)
	r := rnd.IntN(100)
	switch {
	case r < 45:
		return staticWords[rnd.IntN(len(staticWords))]
	case r < 60:
		return "{" + p + "}"
	case r < 90:
		// Literals after a capture start with punctuation that no capture
		// value holds (see `values`), so chi's split and this module's
		// coincide on every generated request -- the divergences are the
		// crafted table's business.
		shapes := []string{
			"{" + p + "}.json", "{" + p + "}.{" + q + "}", "v{" + p + "}", "{" + p + "}-{" + q + "}",
			"pre{" + p + "}", "{" + p + "}~x", "a{" + p + "}_{" + q + "}.txt",
			// Regexp constraints, no top-level alternation (chi anchors
			// `^re$` by pasting, which splits an alternation — a crafted
			// divergence below).
			"{" + p + ":[0-9]+}", "{" + p + ":[a-z]+}", "{" + p + ":[0-9]+}.json", "v{" + p + ":[0-9]+}", "{" + p + ":[a-c]+}-{" + q + "}",
		}
		return shapes[rnd.IntN(len(shapes))]
	default:
		if last {
			return "*"
		}
		return staticWords[0]
	}
}

func genPattern() string {
	depth := 1 + rnd.IntN(3)
	var segs []string
	for d := 0; d < depth; d++ {
		s := patternSegment(d, d == depth-1)
		segs = append(segs, s)
		if s == "*" {
			break
		}
	}
	p := "/" + strings.Join(segs, "/")
	if !strings.HasSuffix(p, "*") && rnd.IntN(10) == 0 {
		p += "/"
	}
	return p
}

// Path segments for the generated requests: capture values ([0-9a-z], never
// a bare prefix literal like "v" or "pre"), alone or joined by the shapes'
// punctuation, each delimiter at most once per segment -- the domain where
// chi's first-byte split and this module's first-occurrence split agree and
// no capture comes out empty.
var values = []string{"1", "42", "ab", "c7", "xyz", "users", "a", "b", "json", "txt"}

func segmentWord() string {
	v := values[rnd.IntN(len(values))]
	switch rnd.IntN(9) {
	case 0:
		return v + "." + values[rnd.IntN(len(values))]
	case 1:
		return v + "-" + values[rnd.IntN(len(values))]
	case 2:
		return "v" + v
	case 3:
		return "pre" + v
	case 4:
		return v + "~x"
	case 5:
		return "a" + v + "_" + values[rnd.IntN(len(values))] + ".txt"
	case 6:
		return staticWords[rnd.IntN(len(staticWords))]
	default:
		return v
	}
}

func genPath() string {
	depth := 1 + rnd.IntN(4)
	var segs []string
	for d := 0; d < depth; d++ {
		segs = append(segs, segmentWord())
	}
	p := "/" + strings.Join(segs, "/")
	if rnd.IntN(8) == 0 {
		p += "/"
	}
	return p
}

type route struct{ method, pattern string }

type answer struct {
	method, path string
	status       int
	pattern      string
	params       [][2]string
	allow        []string
}

func handler(w http.ResponseWriter, r *http.Request) {
	rc := chi.RouteContext(r.Context())
	var b strings.Builder
	b.WriteString(rc.RoutePattern())
	for i, k := range rc.URLParams.Keys {
		fmt.Fprintf(&b, "\x00%s\x00%s", k, rc.URLParams.Values[i])
	}
	w.Write([]byte(b.String()))
}

// register adds a route, reporting false when chi refuses it (it panics).
func register(mux *chi.Mux, rt route) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	mux.Method(rt.method, rt.pattern, http.HandlerFunc(handler))
	return true
}

func ask(mux *chi.Mux, method, path string) answer {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	a := answer{method: method, path: path, status: w.Code}
	if w.Code == 200 {
		parts := strings.Split(w.Body.String(), "\x00")
		a.pattern = parts[0]
		for i := 1; i+1 < len(parts); i += 2 {
			a.params = append(a.params, [2]string{parts[i], parts[i+1]})
		}
	}
	a.allow = append(a.allow, w.Header().Values("Allow")...)
	sort.Strings(a.allow)
	return a
}

func zstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\x%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

const header = `pub const Route = struct { method: []const u8, pattern: []const u8 };
pub const Param = struct { name: []const u8, value: []const u8 };
/// chi's answer: status 200 (with the matched pattern and captures), 404 or
/// 405 (with the methods chi's Allow listed, sorted).
pub const Case = struct {
    method: []const u8,
    path: []const u8,
    status: u16,
    pattern: []const u8 = "",
    params: []const Param = &.{},
    allow: []const []const u8 = &.{},
};
/// ` + "`routes`" + `: the ones chi registered (it panics on a few the generator draws;
/// ` + "`refused`" + ` counts them), in order.
pub const Table = struct { routes: []const Route, refused: u16, cases: []const Case };

`

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	check := flag.String("check", "", "re-take and compare with this committed file")
	flag.Parse()

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/router/tools/go_chi_oracle (%s, github.com/go-chi/chi/v5 v5.3.2) -- do not hand-edit.\n", runtime.Version())
	b.WriteString("//! go-chi/chi answers to this module's own route tables and requests,\n")
	b.WriteString("//! replayed by `chi_oracle_test.zig`. Regenerate with the command in tools/go_chi_oracle/main.go.\n\n")
	b.WriteString(header)
	b.WriteString("pub const tables = [_]Table{\n")
	for t := 0; t < nTables; t++ {
		mux := chi.NewRouter()
		var routes []route
		refused := 0
		seen := map[route]bool{}
		// Every fourth table is dense: every shape at one position, so the
		// precedence between sibling patterns decides the answers.
		var drawn []string
		if t%4 == 0 {
			for _, sh := range denseShapes {
				drawn = append(drawn, "/"+sh)
				if rnd.IntN(2) == 0 {
					drawn = append(drawn, "/"+sh+"/{p1}")
				}
			}
		}
		for i, n := 0, 2+rnd.IntN(10); i < n; i++ {
			drawn = append(drawn, genPattern())
		}
		for _, pat := range drawn {
			rt := route{methods[rnd.IntN(len(methods))], pat}
			if seen[rt] {
				continue
			}
			seen[rt] = true
			if register(mux, rt) {
				routes = append(routes, rt)
			} else {
				refused++
			}
		}
		b.WriteString(".{ .routes = &.{")
		for _, rt := range routes {
			fmt.Fprintf(&b, ".{ .method = %s, .pattern = %s },", zstr(rt.method), zstr(rt.pattern))
		}
		fmt.Fprintf(&b, "}, .refused = %d, .cases = &.{\n", refused)
		for i := 0; i < nRequests; i++ {
			// Half the requests are a registered pattern with its captures
			// filled from the path vocabulary, so most of them reach a route.
			// Those mostly ask with the route's own method.
			var path string
			method := methods[rnd.IntN(len(methods))]
			if i%2 == 0 && len(routes) > 0 {
				rt := routes[rnd.IntN(len(routes))]
				path = fillPattern(rt.pattern)
				if rnd.IntN(4) != 0 {
					method = rt.method
				}
			} else {
				path = genPath()
			}
			writeCase(&b, ask(mux, method, path))
		}
		b.WriteString("} },\n")
	}
	b.WriteString("};\n\n")
	emitDivergences(&b)

	// The committed file is `zig fmt` clean (the repository's pre-commit
	// gate), so the re-take is formatted the same way before any comparison.
	fmtCmd := exec.Command("zig", "fmt", "--stdin")
	fmtCmd.Stdin = bytes.NewReader(b.Bytes())
	fmtCmd.Stderr = os.Stderr
	formatted, err := fmtCmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "zig fmt --stdin:", err)
		os.Exit(2)
	}
	b.Reset()
	b.Write(formatted)

	switch {
	case *check != "":
		old, err := os.ReadFile(*check)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		// The GENERATED line names the Go version; a runner with another
		// patch release passes when every answer agrees.
		if !bytes.Equal(dropVersionLine(old), dropVersionLine(b.Bytes())) {
			ol := strings.Split(string(old), "\n")
			nl := strings.Split(b.String(), "\n")
			for i := 0; i < len(ol) || i < len(nl); i++ {
				var x, y string
				if i < len(ol) {
					x = ol[i]
				}
				if i < len(nl) {
					y = nl[i]
				}
				if x != y {
					fmt.Fprintf(os.Stderr, "DRIFT at line %d:\n  committed: %s\n  re-taken:  %s\n", i+1, x, y)
					break
				}
			}
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "chi oracle: committed vectors match a fresh re-take")
	case *out != "":
		if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		os.Stdout.Write(b.Bytes())
	}
}

func dropVersionLine(b []byte) []byte {
	lines := bytes.Split(b, []byte("\n"))
	var keep [][]byte
	for _, l := range lines {
		if !bytes.HasPrefix(l, []byte("// GENERATED ")) {
			keep = append(keep, l)
		}
	}
	return bytes.Join(keep, []byte("\n"))
}

// fillPattern turns a registered pattern into a request path: every capture
// gets a value from the path vocabulary (sometimes one that fits the shape,
// sometimes not), a final `*` one to three segments.
func fillPattern(p string) string {
	var out strings.Builder
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '{':
			j := strings.IndexByte(p[i:], '}')
			out.WriteString(captureValue())
			i += j
		case '*':
			for k, n := 0, rnd.IntN(3); k < n; k++ {
				if k > 0 {
					out.WriteByte('/')
				}
				out.WriteString(segmentWord())
			}
		default:
			out.WriteByte(p[i])
		}
	}
	return out.String()
}

func captureValue() string { return values[rnd.IntN(len(values))] }

// The documented divergences (README "Patterns inside a segment"), one crafted
// table: chi's answers to requests where an empty capture (EMPTY) or chi's
// first-byte split (SPLIT) decides. The replay pins this module's own,
// different answer to each.
var divergenceRoutes = []route{
	{"GET", "/files/{name}.{ext}"},
	{"GET", "/x/{id}suf"},
	{"GET", "/w/{a}.json"},
	{"GET", "/w/{a}.{b}"},
	{"GET", "/q/a{x}b{y}c"},
	{"GET", "/v/v{n}/b"},
	{"GET", "/r/{x:a|b}"},
}

var divergenceRequests = [][2]string{
	{"GET", "/files/.b"},
	{"GET", "/x/suf"},
	{"GET", "/v/v/b"},
	{"POST", "/v/v/b"},
	{"GET", "/x/asufsuf"},
	{"GET", "/w/a.b.json"},
	{"GET", "/q/a1b2cc"},
	{"GET", "/r/ab"},
}

func emitDivergences(b *bytes.Buffer) {
	mux := chi.NewRouter()
	b.WriteString("pub const divergence_routes = [_]Route{")
	for _, rt := range divergenceRoutes {
		if !register(mux, rt) {
			fmt.Fprintln(os.Stderr, "chi refuses a divergence route:", rt.pattern)
			os.Exit(2)
		}
		fmt.Fprintf(b, ".{ .method = %s, .pattern = %s },", zstr(rt.method), zstr(rt.pattern))
	}
	b.WriteString("};\n")
	b.WriteString("pub const divergences = [_]Case{\n")
	for _, rq := range divergenceRequests {
		writeCase(b, ask(mux, rq[0], rq[1]))
	}
	b.WriteString("};\n")
}

func writeCase(b *bytes.Buffer, a answer) {
	fmt.Fprintf(b, ".{ .method = %s, .path = %s, .status = %d", zstr(a.method), zstr(a.path), a.status)
	if a.status == 200 {
		fmt.Fprintf(b, ", .pattern = %s, .params = &.{", zstr(a.pattern))
		for _, p := range a.params {
			fmt.Fprintf(b, ".{ .name = %s, .value = %s },", zstr(p[0]), zstr(p[1]))
		}
		b.WriteString("}")
	}
	if len(a.allow) != 0 {
		b.WriteString(", .allow = &.{")
		for _, m := range a.allow {
			b.WriteString(zstr(m) + ",")
		}
		b.WriteString("}")
	}
	b.WriteString(" },\n")
}
