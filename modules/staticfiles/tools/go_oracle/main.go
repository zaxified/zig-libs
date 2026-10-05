// SPDX-License-Identifier: MIT

// Differential oracle for modules/staticfiles: Go's standard library
// net/http (http.FileServer and http.ServeContent) as an independent
// implementation, asked over a real loopback socket with the very request
// bytes the replay feeds this module. The cases and the file tree are OURS;
// Go only answers. The answers are written as a Zig file that
// src/go_oracle_test.zig replays hermetically -- no Go at test time.
//
//	cd modules/staticfiles/tools/go_oracle && go run . -out ../../src/go_oracle_vectors.zig
//	cd modules/staticfiles/tools/go_oracle && go run . -check ../../src/go_oracle_vectors.zig
//
// Two areas:
//   - paths: GET/HEAD/other methods of raw request targets against
//     http.FileServer(http.Dir(root)) -- which file is served, what is
//     refused, where a redirect points;
//   - cond: preconditions and ranges on one 100-byte file through
//     http.ServeContent, with the validators this module emits (Last-Modified
//     and its size-mtime ETag, weak by default, strong as an option).
//
// Stdlib only, no network beyond loopback.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type file struct{ path, data string }

// The tree under root. A path ending in "/" is a directory. Symlinks are
// listed separately. secret.txt lives NEXT TO root, never inside it.
var files = []file{
	{"index.html", "<p>root</p>\n"},
	{"a.txt", "alpha\n"},
	{"UPPER.TXT", "upper\n"},
	{"big.bin", bigBody()},
	{"dir/", ""},
	{"dir/index.html", "<p>dir</p>\n"},
	{"dir/b.txt", "bravo\n"},
	{"dir/.env", "dotenv\n"},
	{"nodir/", ""},
	{"nodir/c.txt", "charlie\n"},
	{".hidden", "hidden\n"},
	{".git/", ""},
	{".git/config", "gitconfig\n"},
	{"sp ace.txt", "space\n"},
	{"\xc4\x8d.txt", "c-caron\n"},
	{"pct%41.txt", "pct\n"},
	{"x+y.txt", "plus\n"},
	{"semi;colon.txt", "semi\n"},
	{"noext", "noext\n"},
	{"empty.txt", ""},
}

type link struct{ path, target string }

var links = []link{
	{"lnk.txt", "a.txt"},
	{"esc.txt", "../secret.txt"},
	{"escdir", ".."},
}

const secret = "SECRET-OUTSIDE-ROOT\n"

// RFC 9110's example instant; every file and directory gets it.
var mtime = time.Unix(784111777, 0).UTC()

const (
	imfAt     = "Sun, 06 Nov 1994 08:49:37 GMT"
	imfBefore = "Sun, 06 Nov 1994 08:49:36 GMT"
	imfAfter  = "Sun, 06 Nov 1994 08:49:38 GMT"
)

// The validators this module derives from size and mtime (hex, see
// buildETag), handed to ServeContent so both sides compare the same tags.
var (
	tagStrong = fmt.Sprintf(`"%x-%x"`, len(bigBody()), mtime.Unix())
	tagWeak   = "W/" + tagStrong
)

func bigBody() string {
	var b [100]byte
	for i := range b {
		b[i] = byte('A' + i%26)
	}
	return string(b[:])
}

type reqCase struct {
	id      string
	area    string // "paths" | "cond"
	method  string
	target  string
	headers []string
	strong  bool // cond only: the ETag is strong
}

func pathCases() []reqCase {
	targets := []string{
		"/", "/a.txt", "/A.TXT", "/UPPER.TXT", "/upper.txt", "/a.txt/", "/a.txt.", "/a.txt%00", "/a%2etxt",
		"/%61.txt", "/a.tx%74", "/dir", "/dir/", "/dir/index.html", "/index.html", "/dir/b.txt", "/dir//b.txt",
		"//a.txt", "/./a.txt", "/dir/./b.txt", "/dir/../a.txt", "/../a.txt", "/..%2fa.txt", "/%2e%2e/a.txt",
		"/%2e%2e%2fsecret.txt", "/../secret.txt", "/dir/../../secret.txt", "/dir%2fb.txt", "/dir%2Fb.txt",
		"/dir\\b.txt", "/dir%5cb.txt", "/nodir", "/nodir/", "/nodir/c.txt", "/.hidden", "/dir/.env", "/%2ehidden",
		"/.git/config", "/.git/", "/sp%20ace.txt", "/sp+ace.txt", "/%C4%8D.txt", "/%c4%8d.txt", "/\xc4\x8d.txt",
		"/pct%2541.txt", "/pct%41.txt", "/missing", "/missing/", "/dir/missing", "/a.txt?x=1", "/a.txt?",
		"/a.txt#f", "/a.txt;p=1", "/semi;colon.txt", "/semi%3Bcolon.txt", "/x+y.txt", "/x%2By.txt", "/x%2by.txt",
		"/lnk.txt", "/esc.txt", "/escdir/secret.txt", "/escdir/", "/%", "/%zz", "/%2", "/%2f", "/a.txt%2f",
		"/dir/b.txt/..", "/dir/b.txt/.", "/.", "/..", "/dir/..", "/dir/.", "/noext", "/empty.txt",
		"/" + strings.Repeat("a", 300), "/dir/" + strings.Repeat("b", 256) + "/x", "/a.txt%20", "/a.txt%09",
		"/%00", "/dir%00/b.txt", "/a.txt\\", "/.%2e/a.txt", "/%2e/a.txt", "/dir/%2e%2e/a.txt",
	}
	var cs []reqCase
	for i, t := range targets {
		cs = append(cs, reqCase{id: fmt.Sprintf("p%02d", i), area: "paths", method: "GET", target: t})
	}
	for i, m := range []string{"HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"} {
		cs = append(cs, reqCase{id: fmt.Sprintf("m%d", i), area: "paths", method: m, target: "/a.txt"})
	}
	cs = append(cs, reqCase{id: "m_head_dir", area: "paths", method: "HEAD", target: "/dir"})
	cs = append(cs, reqCase{id: "m_head_missing", area: "paths", method: "HEAD", target: "/missing"})
	return cs
}

func condCases() []reqCase {
	conds := [][]string{
		nil,
		{"If-None-Match: " + tagStrong}, {"If-None-Match: " + tagWeak}, {"If-None-Match: *"},
		{`If-None-Match: "other"`}, {`If-None-Match: "a", ` + tagStrong}, {"If-None-Match: " + tagStrong + ", *"},
		{"If-Match: " + tagStrong}, {"If-Match: " + tagWeak}, {"If-Match: *"}, {`If-Match: "other"`},
		{"If-Modified-Since: " + imfAt}, {"If-Modified-Since: " + imfBefore}, {"If-Modified-Since: " + imfAfter},
		{"If-Modified-Since: garbage"},
		{"If-Unmodified-Since: " + imfAt}, {"If-Unmodified-Since: " + imfBefore}, {"If-Unmodified-Since: " + imfAfter},
		{"If-None-Match: \"other\"", "If-Modified-Since: " + imfAfter},
		{"If-None-Match: " + tagStrong, "If-Modified-Since: " + imfBefore},
		{`If-Match: "other"`, "If-Unmodified-Since: " + imfAfter},
		{"If-Match: " + tagStrong, "If-Unmodified-Since: " + imfBefore},
		{"If-Range: " + tagStrong}, {"If-Range: " + tagWeak}, {`If-Range: "other"`},
		{"If-Range: " + imfAt}, {"If-Range: " + imfBefore}, {"If-Range: " + imfAfter}, {"If-Range: garbage"},
	}
	ranges := []string{
		"", "bytes=0-9", "bytes=90-", "bytes=-10", "bytes=0-0", "bytes=99-99", "bytes=99-", "bytes=0-200",
		"bytes=100-", "bytes=-0", "bytes=50-10", "bytes=0-9,20-29", "bytes=0-9,5-14", "bytes=200-300,0-1",
		"items=0-9", "bytes=", "bytes=abc", "bytes=-", "bytes= 0-9", "bytes=0-9 ", "bytes=00-09", "BYTES=0-9",
	}
	var cs []reqCase
	for _, strong := range []bool{false, true} {
		for ci, c := range conds {
			for ri, r := range ranges {
				h := append([]string{}, c...)
				if r != "" {
					h = append(h, "Range: "+r)
				}
				mode := "w"
				if strong {
					mode = "s"
				}
				cs = append(cs, reqCase{id: fmt.Sprintf("c%s%02d_%02d", mode, ci, ri), area: "cond", method: "GET", target: "/big.bin", headers: h, strong: strong})
			}
		}
		for ri, r := range []string{"", "bytes=0-9", "bytes=200-"} {
			h := []string{}
			if r != "" {
				h = append(h, "Range: "+r)
			}
			cs = append(cs, reqCase{id: fmt.Sprintf("chead_%v_%d", strong, ri), area: "cond", method: "HEAD", target: "/big.bin", headers: h, strong: strong})
		}
	}
	return cs
}

type answer struct {
	status        int
	location      string
	contentRange  string
	contentLength string
	body          []byte
}

func ask(addr string, c reqCase) (answer, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return answer{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: t\r\n", c.method, c.target)
	for _, h := range c.headers {
		fmt.Fprintf(conn, "%s\r\n", h)
	}
	fmt.Fprintf(conn, "Connection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: c.method})
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// A multipart/byteranges boundary is random per response: pin it.
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil && params["boundary"] != "" {
		body = bytes.ReplaceAll(body, []byte(params["boundary"]), []byte("BOUNDARY"))
	}
	return answer{
		status:        resp.StatusCode,
		location:      resp.Header.Get("Location"),
		contentRange:  resp.Header.Get("Content-Range"),
		contentLength: resp.Header.Get("Content-Length"),
		body:          body,
	}, nil
}

func buildTree(base string) (string, error) {
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte(secret), 0o644); err != nil {
		return "", err
	}
	for _, f := range files {
		p := filepath.Join(root, f.path)
		if strings.HasSuffix(f.path, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				return "", err
			}
			continue
		}
		if err := os.WriteFile(p, []byte(f.data), 0o644); err != nil {
			return "", err
		}
	}
	for _, l := range links {
		if err := os.Symlink(l.target, filepath.Join(root, l.path)); err != nil {
			return "", err
		}
	}
	for i := len(files) - 1; i >= 0; i-- { // files before their directories
		if err := os.Chtimes(filepath.Join(root, files[i].path), mtime, mtime); err != nil {
			return "", err
		}
	}
	return root, nil
}

func serveContent(root, tag string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filepath.Join(root, "big.bin"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		w.Header().Set("Etag", tag)
		http.ServeContent(w, r, "big.bin", mtime, f)
	})
}

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	check := flag.String("check", "", "regenerate and compare with this committed vectors file")
	flag.Parse()

	base, err := os.MkdirTemp("", "staticfiles-oracle-")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(base)
	root, err := buildTree(base)
	if err != nil {
		fail(err)
	}
	fs := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer fs.Close()
	weak := httptest.NewServer(serveContent(root, tagWeak))
	defer weak.Close()
	strong := httptest.NewServer(serveContent(root, tagStrong))
	defer strong.Close()

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/staticfiles/tools/go_oracle (%s) -- do not hand-edit.\n", runtime.Version())
	fmt.Fprintf(&b, "//! Go net/http FileServer and ServeContent answers to this module's own cases,\n")
	fmt.Fprintf(&b, "//! replayed by `go_oracle_test.zig`. Regenerate with the command in tools/go_oracle/main.go.\n\n")
	fmt.Fprintf(&b, "pub const go_version = %s;\n\n", zigStr(runtime.Version()))
	b.WriteString(`/// The tree under the served root; a path ending in "/" is a directory.
pub const File = struct { path: []const u8, data: []const u8 };
pub const Link = struct { path: []const u8, target: []const u8 };
pub const Area = enum { paths, cond };
pub const Case = struct {
    id: []const u8,
    area: Area,
    method: []const u8,
    target: []const u8,
    /// Extra request header lines, without CRLF.
    headers: []const []const u8,
    /// cond only: the representation's ETag is strong (Options.strong_etag).
    strong: bool,
    status: u16,
    location: ?[]const u8,
    content_range: ?[]const u8,
    content_length: ?[]const u8,
    body: []const u8,
};

`)
	fmt.Fprintf(&b, "pub const mtime_s: i64 = %d;\n", mtime.Unix())
	fmt.Fprintf(&b, "pub const secret = %s;\n\n", zigStr(secret))
	b.WriteString("pub const files = [_]File{\n")
	for _, f := range files {
		fmt.Fprintf(&b, "    .{ .path = %s, .data = %s },\n", zigStr(f.path), zigStr(f.data))
	}
	b.WriteString("};\n\npub const links = [_]Link{\n")
	for _, l := range links {
		fmt.Fprintf(&b, "    .{ .path = %s, .target = %s },\n", zigStr(l.path), zigStr(l.target))
	}
	b.WriteString("};\n\npub const cases = [_]Case{\n")
	for _, c := range append(pathCases(), condCases()...) {
		addr := fs.Listener.Addr().String()
		if c.area == "cond" {
			addr = weak.Listener.Addr().String()
			if c.strong {
				addr = strong.Listener.Addr().String()
			}
		}
		a, err := ask(addr, c)
		if err != nil {
			fail(fmt.Errorf("%s: %v", c.id, err))
		}
		hs := make([]string, len(c.headers))
		for i, h := range c.headers {
			hs[i] = zigStr(h)
		}
		fmt.Fprintf(&b, "    .{ .id = %s, .area = .%s, .method = %s, .target = %s, .headers = %s, .strong = %v, .status = %d, .location = %s, .content_range = %s, .content_length = %s, .body = %s },\n",
			zigStr(c.id), c.area, zigStr(c.method), zigStr(c.target), zlist(hs), c.strong, a.status,
			optStr(a.location), optStr(a.contentRange), optStr(a.contentLength), zigStr(string(a.body)))
	}
	b.WriteString("};\n")

	if *check != "" {
		old, err := os.ReadFile(*check)
		if err != nil {
			fail(err)
		}
		if !bytes.Equal(old, b.Bytes()) {
			fail(fmt.Errorf("%s is stale: Go, the tree or the case tables moved -- regenerate and re-judge the divergences", *check))
		}
		fmt.Println("vectors are fresh")
		return
	}
	if *out == "" {
		os.Stdout.Write(b.Bytes())
		return
	}
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func optStr(s string) string {
	if s == "" {
		return "null"
	}
	return zigStr(s)
}

// zlist lays out a Zig `&.{...}` the way `zig fmt` does.
func zlist(items []string) string {
	switch len(items) {
	case 0:
		return "&.{}"
	case 1:
		return "&.{" + items[0] + "}"
	}
	return "&.{ " + strings.Join(items, ", ") + " }"
}

// zigStr renders s as a Zig string literal: printable ASCII as is, \r \n \t
// by name, everything else as \xHH. Byte-exact.
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
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
