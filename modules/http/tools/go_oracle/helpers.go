// SPDX-License-Identifier: MIT

// Area helpers: the handler-side helpers a Go user reaches for --
// http.Redirect, http.Error / http.NotFound and Request.BasicAuth -- driven
// through net/http/httptest's recorder. Inputs are ours; Go only answers.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
)

type redirectCase struct {
	id, method, target, location string
	code                         int
	// presetCT: the handler set a Content-Type before calling Redirect.
	presetCT bool
}

var redirectCases = []redirectCase{
	{"abs-path", "GET", "/a/b", "/x", 302, false},
	{"abs-path-301", "GET", "/a/b", "/x", 301, false},
	{"abs-path-303", "POST", "/a/b", "/x", 303, false},
	{"abs-path-307", "GET", "/a/b", "/x", 307, false},
	{"abs-path-308", "GET", "/a/b", "/x", 308, false},
	{"rel-sibling", "GET", "/a/b", "c", 302, false},
	{"rel-sibling-dir", "GET", "/a/b/", "c", 302, false},
	{"rel-dotdot", "GET", "/a/b/c", "../d", 302, false},
	{"rel-dotdot-past-root", "GET", "/a", "../../d", 302, false},
	{"rel-dot", "GET", "/a/b", "./d", 302, false},
	{"rel-trailing-slash", "GET", "/a/b", "d/", 302, false},
	{"abs-trailing-slash", "GET", "/a/b", "/d/", 302, false},
	{"abs-clean", "GET", "/", "/a//b/./c/../d", 302, false},
	{"rel-query", "GET", "/a/b", "c?x=1&y=../z", 302, false},
	{"abs-query", "GET", "/a/b", "/c/../d?q=/../", 302, false},
	{"rel-query-only", "GET", "/a/b", "?x=1", 302, false},
	{"rel-fragment", "GET", "/a/b", "c#frag", 302, false},
	{"empty-location", "GET", "/a/b", "", 302, false},
	{"root", "GET", "/", "x", 302, false},
	{"absolute-url", "GET", "/a", "https://example.com/p?q=1", 302, false},
	{"absolute-url-dots", "GET", "/a", "https://example.com/a/../b", 302, false},
	{"scheme-relative", "GET", "/a", "//example.com/p", 302, false},
	{"mailto", "GET", "/a", "mailto:x@example.com", 302, false},
	{"non-ascii", "GET", "/a", "/\xc4\x8d/x", 302, false},
	{"percent-kept", "GET", "/a", "/%C4%8D/%2F", 302, false},
	{"html-escape", "GET", "/a", "/x?a=<b>&c=\"d\"'", 302, false},
	{"space", "GET", "/a", "/a b", 302, false},
	{"head", "HEAD", "/a/b", "/x", 302, false},
	{"post", "POST", "/a/b", "/x", 302, false},
	{"put-307", "PUT", "/a/b", "/x", 307, false},
	{"preset-ct-get", "GET", "/a/b", "/x", 302, true},
	{"preset-ct-head", "HEAD", "/a/b", "/x", 302, true},
	{"colon-in-path", "GET", "/a", "/b:c", 302, false},
	{"rel-colon-first", "GET", "/a/b", "c:d", 302, false},
	{"rel-colon-after-slash", "GET", "/a/b", "./c:d", 302, false},
	{"backslash-abs", "GET", "/a", "/\\example.com", 302, false},
	{"backslash-rel", "GET", "/a/b", "c\\d", 302, false},
}

type errorCase struct {
	id, message string
	code        int
	// preset: response headers the handler set before calling Error.
	preset [][2]string
	// notFound: call http.NotFound instead (message/code ignored).
	notFound bool
}

var errorCases = []errorCase{
	{"plain-500", "boom", 500, nil, false},
	{"plain-400", "bad request", 400, nil, false},
	{"empty-message", "", 503, nil, false},
	{"message-newline", "line1\nline2", 422, nil, false},
	{"html-not-escaped", "<b>x</b>", 400, nil, false},
	{"preset-headers", "boom", 500, [][2]string{
		{"Content-Length", "123"}, {"Content-Type", "application/json"}, {"Content-Encoding", "gzip"},
		{"Etag", "\"v1\""}, {"Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT"}, {"Cache-Control", "max-age=60"},
		{"X-Custom", "kept"},
	}, false},
	{"not-found", "", 0, nil, true},
}

var basicAuthInputs = []string{
	"Basic dXNlcjpwYXNz",            // user:pass
	"basic dXNlcjpwYXNz",            // scheme case
	"BASIC dXNlcjpwYXNz",            // scheme case
	"Basic  dXNlcjpwYXNz",           // two spaces
	"Basic\tdXNlcjpwYXNz",           // tab
	"Basic dXNlcjpwYXNz ",           // trailing space
	"Basic dXNlcg==",                // "user", no colon
	"Basic OnBhc3M=",                // ":pass"
	"Basic dXNlcjo=",                // "user:"
	"Basic Og==",                    // ":"
	"Basic dTpwOnE=",                // "u:p:q"
	"Basic dXNlcjpwYXNz=",           // bad padding
	"Basic dXNlcjpwYXN",             // missing padding ("user:pas" unpadded)
	"Basic !!!",                     // not base64
	"Basic ",                        // empty credentials
	"Basic",                         // no space
	"Bearer dXNlcjpwYXNz",           // other scheme
	"Basic xJ06xI0=",                // UTF-8 "č:č"
	"Basic /w==",                    // 0xff: not UTF-8
	"Basic dXNlcjpwYXNz,Basic eA==", // two credentials in one field
	"",                              // empty header
}

func emitHelpers(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const RedirectCase = struct {\n    id: []const u8,\n    method: []const u8,\n    target: []const u8,\n    location: []const u8,\n    code: u16,\n    preset_ct: bool,\n")
	fmt.Fprintf(b, "    /// What Go's recorder holds after http.Redirect.\n    status: u16,\n    out_location: ?[]const u8,\n    content_type: ?[]const u8,\n    body: []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's http.Redirect.\npub const redirect = [_]RedirectCase{\n")
	for _, c := range redirectCases {
		req := httptest.NewRequest(c.method, "http://example.test"+c.target, nil)
		rec := httptest.NewRecorder()
		if c.presetCT {
			rec.Header().Set("Content-Type", "text/plain")
		}
		http.Redirect(rec, req, c.location, c.code)
		res := rec.Result()
		fmt.Fprintf(b, "    .{ .id = %s, .method = %s, .target = %s, .location = %s, .code = %d, .preset_ct = %t, .status = %d, .out_location = %s, .content_type = %s, .body = %s },\n",
			zigStr(c.id), zigStr(c.method), zigStr(c.target), zigStr(c.location), c.code, c.presetCT,
			res.StatusCode, zigOptStr(headerPtr(res.Header, "Location")), zigOptStr(headerPtr(res.Header, "Content-Type")), zigStr(rec.Body.String()))
	}
	fmt.Fprintf(b, "};\n\n")

	fmt.Fprintf(b, "pub const ErrorCase = struct {\n    id: []const u8,\n    message: []const u8,\n    code: u16,\n    preset: []const [2][]const u8,\n    not_found: bool,\n")
	fmt.Fprintf(b, "    status: u16,\n    /// Every response header after the call, names canonical, sorted.\n    headers: []const [2][]const u8,\n    body: []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's http.Error / http.NotFound.\npub const errors = [_]ErrorCase{\n")
	for _, c := range errorCases {
		rec := httptest.NewRecorder()
		for _, h := range c.preset {
			rec.Header().Set(h[0], h[1])
		}
		if c.notFound {
			http.NotFound(rec, httptest.NewRequest("GET", "/missing", nil))
		} else {
			http.Error(rec, c.message, c.code)
		}
		res := rec.Result()
		var presetItems []string
		for _, h := range c.preset {
			presetItems = append(presetItems, fmt.Sprintf(".{ %s, %s }", zigStr(h[0]), zigStr(h[1])))
		}
		names := make([]string, 0, len(res.Header))
		for k := range res.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		var hdrItems []string
		for _, k := range names {
			hdrItems = append(hdrItems, fmt.Sprintf(".{ %s, %s }", zigStr(k), zigStr(strings.Join(res.Header[k], ", "))))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .message = %s, .code = %d, .preset = %s, .not_found = %t, .status = %d, .headers = %s, .body = %s },\n",
			zigStr(c.id), zigStr(c.message), c.code, zigList(presetItems), c.notFound, res.StatusCode, zigList(hdrItems), zigStr(rec.Body.String()))
	}
	fmt.Fprintf(b, "};\n\n")

	fmt.Fprintf(b, "pub const BasicAuthCase = struct { authorization: []const u8, ok: bool, user: []const u8, password: []const u8 };\n\n")
	fmt.Fprintf(b, "/// Go's Request.BasicAuth.\npub const basic_auth = [_]BasicAuthCase{\n")
	for _, in := range basicAuthInputs {
		req := httptest.NewRequest("GET", "/", nil)
		if in != "" {
			req.Header.Set("Authorization", in)
		}
		u, p, ok := req.BasicAuth()
		fmt.Fprintf(b, "    .{ .authorization = %s, .ok = %t, .user = %s, .password = %s },\n", zigStr(in), ok, zigStr(u), zigStr(p))
	}
	fmt.Fprintf(b, "};\n\n")
}

func headerPtr(h http.Header, name string) *string {
	if v, ok := h[http.CanonicalHeaderKey(name)]; ok && len(v) > 0 {
		s := v[0]
		return &s
	}
	return nil
}
