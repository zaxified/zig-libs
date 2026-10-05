// SPDX-License-Identifier: MIT

// Differential oracle for modules/cookies/src/jar.zig: Go's net/http/cookiejar
// (with resp.Cookies() parsing the Set-Cookie fields) runs our own scenarios
// -- sequences of "these Set-Cookie fields arrived from URL" and "what does a
// request to URL send" -- and the answers become src/jar_go_vectors.zig,
// replayed by src/jar_go_oracle.zig with no Go at test time.
//
//	cd modules/cookies/tools/go_oracle && go run . -out ../../src/jar_go_vectors.zig
//
// The public suffix list on Go's side says "the last label" for every name;
// ours gets an empty list, whose implicit `*` rule says the same. Stdlib only.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

type lastLabel struct{}

func (lastLabel) PublicSuffix(domain string) string {
	if i := strings.LastIndexByte(domain, '.'); i >= 0 {
		return domain[i+1:]
	}
	return domain
}
func (lastLabel) String() string { return "last label" }

type step struct {
	url    string
	fields []string // a set step; nil = a get step
}

func set(u string, fields ...string) step { return step{u, fields} }
func get(u string) step                   { return step{u, nil} }

type scenario struct {
	id    string
	steps []step
}

const w = "http://www.example.test/"

var scenarios = []scenario{
	{"host-only", []step{set(w, "a=1"), get(w), get("http://example.test/"), get("http://x.www.example.test/")}},
	{"domain-parent", []step{set(w, "a=1; Domain=example.test"), get("http://example.test/"), get("http://a.b.example.test/"), get("http://other.test/")}},
	{"domain-leading-dot", []step{set(w, "a=1; Domain=.example.test"), get("http://a.example.test/")}},
	{"domain-uppercase", []step{set(w, "a=1; Domain=EXAMPLE.test"), get("http://a.example.test/")}},
	{"domain-public-suffix", []step{set(w, "a=1; Domain=test"), get(w), get("http://other.test/")}},
	{"domain-is-host-suffix", []step{set("http://test/", "a=1; Domain=test"), get("http://test/"), get("http://x.test/")}},
	{"domain-mismatch", []step{set(w, "a=1; Domain=other.test"), get("http://other.test/"), get(w)}},
	{"domain-sibling", []step{set(w, "a=1; Domain=api.example.test"), get("http://api.example.test/")}},
	{"domain-empty", []step{set(w, "a=1; Domain="), get(w), get("http://example.test/")}},
	{"domain-self", []step{set(w, "a=1; Domain=www.example.test"), get(w), get("http://x.www.example.test/")}},
	{"ip-host", []step{set("http://192.0.2.1/", "a=1"), get("http://192.0.2.1/"), get("http://192.0.2.1:8080/")}},
	{"ip-domain-self", []step{set("http://192.0.2.1/", "a=1; Domain=192.0.2.1"), get("http://192.0.2.1/")}},
	{"ip-domain-suffix", []step{set("http://192.0.2.1/", "a=1; Domain=0.2.1"), get("http://192.0.2.1/")}},
	{"port-ignored", []step{set("http://www.example.test:8080/", "a=1"), get(w), get("http://www.example.test:9090/")}},
	{"path-default", []step{set("http://h.test/a/b/page", "a=1"), get("http://h.test/a/b/x"), get("http://h.test/a/b"), get("http://h.test/a/"), get("http://h.test/a/bc")}},
	{"path-default-root", []step{set("http://h.test/page", "a=1"), get("http://h.test/other")}},
	{"path-attr", []step{set("http://h.test/x/y", "a=1; Path=/p"), get("http://h.test/p"), get("http://h.test/p/q"), get("http://h.test/pq"), get("http://h.test/x/y")}},
	{"path-attr-trailing-slash", []step{set("http://h.test/", "a=1; Path=/p/"), get("http://h.test/p"), get("http://h.test/p/q")}},
	{"path-attr-relative", []step{set("http://h.test/x/y", "a=1; Path=rel"), get("http://h.test/x/z"), get("http://h.test/")}},
	{"path-order", []step{set("http://h.test/", "short=1; Path=/", "long=1; Path=/a/b", "mid=1; Path=/a"), get("http://h.test/a/b/c")}},
	{"creation-order", []step{set("http://h.test/", "z=1", "a=1", "m=1"), get("http://h.test/")}},
	{"replace-keeps-order", []step{set("http://h.test/", "a=1", "b=1"), set("http://h.test/", "a=2"), get("http://h.test/")}},
	{"same-name-two-paths", []step{set("http://h.test/", "a=1", "a=2; Path=/x"), get("http://h.test/x/y")}},
	{"secure-from-https", []step{set("https://h.test/", "s=1; Secure"), get("https://h.test/"), get("http://h.test/")}},
	{"secure-from-http", []step{set("http://h.test/", "s=1; Secure"), get("https://h.test/")}},
	{"secure-shadow", []step{set("https://h.test/", "s=1; Secure"), set("http://h.test/", "s=2"), get("https://h.test/"), get("http://h.test/")}},
	{"max-age-zero", []step{set("http://h.test/", "a=1"), set("http://h.test/", "a=1; Max-Age=0"), get("http://h.test/")}},
	{"max-age-negative", []step{set("http://h.test/", "a=1"), set("http://h.test/", "a=1; Max-Age=-1"), get("http://h.test/")}},
	{"max-age-future", []step{set("http://h.test/", "a=1; Max-Age=3600"), get("http://h.test/")}},
	{"max-age-invalid", []step{set("http://h.test/", "a=1; Max-Age=abc"), get("http://h.test/")}},
	{"max-age-over-expires", []step{set("http://h.test/", "a=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT"), get("http://h.test/")}},
	{"expires-past", []step{set("http://h.test/", "a=1"), set("http://h.test/", "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"), get("http://h.test/")}},
	{"expires-future", []step{set("http://h.test/", "a=1; Expires=Fri, 01 Jan 2100 00:00:00 GMT"), get("http://h.test/")}},
	{"expires-rfc850", []step{set("http://h.test/", "a=1"), set("http://h.test/", "a=1; Expires=Thursday, 01-Jan-70 00:00:00 GMT"), get("http://h.test/")}},
	{"expires-asctime-past", []step{set("http://h.test/", "a=1"), set("http://h.test/", "a=1; Expires=Thu Jan  1 00:00:00 1970"), get("http://h.test/")}},
	{"expires-garbage", []step{set("http://h.test/", "a=1; Expires=tomorrow"), get("http://h.test/")}},
	{"expires-dashes-past", []step{set("http://h.test/", "a=1"), set("http://h.test/", "a=1; Expires=Thu, 01-Jan-1970 00:00:00 GMT"), get("http://h.test/")}},
	{"value-empty", []step{set("http://h.test/", "a="), get("http://h.test/")}},
	{"value-quoted", []step{set("http://h.test/", `a="x y"`), get("http://h.test/")}},
	{"value-quoted-plain", []step{set("http://h.test/", `a="xy"`), get("http://h.test/")}},
	{"value-space", []step{set("http://h.test/", "a=x y"), get("http://h.test/")}},
	{"value-comma", []step{set("http://h.test/", "a=x,y"), get("http://h.test/")}},
	{"value-equals", []step{set("http://h.test/", "a=x=y"), get("http://h.test/")}},
	{"value-ows", []step{set("http://h.test/", "a =  1  ; Path=/"), get("http://h.test/")}},
	{"name-space", []step{set("http://h.test/", "a b=1"), get("http://h.test/")}},
	{"name-empty", []step{set("http://h.test/", "=1"), get("http://h.test/")}},
	{"no-equals", []step{set("http://h.test/", "justname"), get("http://h.test/")}},
	{"attr-case", []step{set("http://h.test/x", "a=1; PATH=/; DOMAIN=h.test; MAX-AGE=60"), get("http://h.test/")}},
	{"attr-last-wins", []step{set("http://h.test/", "a=1; Path=/x; Path=/"), get("http://h.test/")}},
	{"httponly-sent", []step{set("http://h.test/", "a=1; HttpOnly"), get("http://h.test/")}},
	{"samesite-sent", []step{set("http://h.test/", "a=1; SameSite=Strict"), get("http://h.test/")}},
	{"case-sensitive-names", []step{set("http://h.test/", "A=1", "a=2"), get("http://h.test/")}},
	{"host-case", []step{set("http://H.Test/", "a=1"), get("http://h.test/")}},
	{"localhost", []step{set("http://localhost/", "a=1; Domain=localhost"), get("http://localhost/")}},
}

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	flag.Parse()
	now := time.Now().Unix()

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/cookies/tools/go_oracle (%s) -- do not hand-edit.\n", runtime.Version())
	fmt.Fprintf(&b, "//! Go's net/http/cookiejar on our scenarios; replayed by `jar_go_oracle.zig`.\n\n")
	fmt.Fprintf(&b, "pub const go_version = %s;\n", zigStr(runtime.Version()))
	fmt.Fprintf(&b, "/// When the scenarios ran (Unix seconds): the replay's clock.\npub const now: i64 = %d;\n\n", now)
	fmt.Fprintf(&b, "/// `fields` set = Set-Cookie fields from `url`; null = a request to `url`, which Go answered with `go`.\n")
	fmt.Fprintf(&b, "pub const Step = struct { url: []const u8, fields: ?[]const []const u8 = null, go: []const u8 = \"\" };\n")
	fmt.Fprintf(&b, "pub const Scenario = struct { id: []const u8, steps: []const Step };\n\n")
	fmt.Fprintf(&b, "pub const scenarios = [_]Scenario{\n")
	for _, sc := range scenarios {
		jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: lastLabel{}})
		var steps []string
		for _, st := range sc.steps {
			u, err := url.Parse(st.url)
			if err != nil {
				panic(err)
			}
			if st.fields != nil {
				resp := &http.Response{Header: http.Header{"Set-Cookie": st.fields}}
				jar.SetCookies(u, resp.Cookies())
				var fs []string
				for _, f := range st.fields {
					fs = append(fs, zigStr(f))
				}
				steps = append(steps, fmt.Sprintf(".{ .url = %s, .fields = %s }", zigStr(st.url), zigList(fs)))
				continue
			}
			var pairs []string
			for _, c := range jar.Cookies(u) {
				pairs = append(pairs, c.Name+"="+c.Value)
			}
			steps = append(steps, fmt.Sprintf(".{ .url = %s, .go = %s }", zigStr(st.url), zigStr(strings.Join(pairs, "; "))))
		}
		fmt.Fprintf(&b, "    .{ .id = %s, .steps = %s },\n", zigStr(sc.id), zigList(steps))
	}
	fmt.Fprintf(&b, "};\n")

	if *out == "" {
		os.Stdout.Write(b.Bytes())
		return
	}
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func zigStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// zigList renders a list literal the way `zig fmt` does.
func zigList(items []string) string {
	switch len(items) {
	case 0:
		return "&.{}"
	case 1:
		return "&.{" + items[0] + "}"
	}
	return "&.{ " + strings.Join(items, ", ") + " }"
}
