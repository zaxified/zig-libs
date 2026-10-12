// SPDX-License-Identifier: MIT

// Area crossorigin: Go 1.25's http.CrossOriginProtection -- Check's verdict
// over method x Sec-Fetch-Site x Origin x Host, AddTrustedOrigin's validation,
// and the default denial response. Trusted origin "https://partner.example",
// bypass pattern "/hook/". Inputs are ours; Go only answers.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

type coCase struct {
	id, method, host, path string
	headers                [][2]string
}

func coCases() []coCase {
	var cs []coCase
	add := func(id, method, host, path string, h ...[2]string) {
		cs = append(cs, coCase{id, method, host, path, h})
	}
	sfs := func(v string) [2]string { return [2]string{"Sec-Fetch-Site", v} }
	org := func(v string) [2]string { return [2]string{"Origin", v} }

	for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "PROPFIND", "get"} {
		add("method-"+m+"-cross", m, "a.example", "/", sfs("cross-site"))
	}
	for _, v := range []string{"same-origin", "none", "same-site", "cross-site", "SAME-ORIGIN", "bogus"} {
		add("sfs-"+strings.ReplaceAll(v, " ", "_"), "POST", "a.example", "/", sfs(v))
	}
	add("sfs-empty", "POST", "a.example", "/", sfs(""))
	add("sfs-empty-origin-other", "POST", "a.example", "/", sfs(""), org("https://b.example"))
	add("sfs-cross-trusted", "POST", "a.example", "/", sfs("cross-site"), org("https://partner.example"))
	add("sfs-cross-trusted-slash", "POST", "a.example", "/", sfs("cross-site"), org("https://partner.example/"))
	add("sfs-cross-trusted-case", "POST", "a.example", "/", sfs("cross-site"), org("https://PARTNER.example"))
	add("sfs-cross-bypass", "POST", "a.example", "/hook/x", sfs("cross-site"))
	add("sfs-cross-bypass-root", "POST", "a.example", "/hook", sfs("cross-site"))
	add("sfs-same-origin-other-origin", "POST", "a.example", "/", sfs("same-origin"), org("https://b.example"))

	add("no-headers", "POST", "a.example", "/")
	origins := []string{
		"https://a.example", "http://a.example", "ftp://a.example", "//a.example", "a.example",
		"https://a.example:443", "https://A.example", "https://a.example/", "https://a.example/path?q#f",
		"https://user@a.example", "https://u:p@a.example", "https://a.example.", "https://b.example",
		"null", "https://a.ex%61mple", "https://a.example%zz", "https://a example", "https:a.example",
		"https://a.example:", "https://a.example:x", "https://[::1]", "", "https://a.example#",
		"https://a.example?", "HTTPS://a.example", "1https://a.example", ":https://a.example",
		"https://partner.example", "https://b.example@a.example", "https://a.example\\@b.example",
	}
	for i, o := range origins {
		add(fmt.Sprintf("origin-%02d", i), "POST", "a.example", "/", org(o))
	}
	add("origin-port-host", "POST", "a.example:8080", "/", org("https://a.example:8080"))
	add("origin-port-host-missing", "POST", "a.example:8080", "/", org("https://a.example"))
	add("origin-ipv6", "POST", "[::1]:8080", "/", org("http://[::1]:8080"))
	add("origin-bypass", "POST", "a.example", "/hook/y", org("https://b.example"))
	return cs
}

var coOrigins = []string{
	"https://example.com", "http://example.com:8080", "example.com", "https://", "https://example.com/",
	"https://example.com?x", "https://example.com#f", "https://u@example.com", "https://example.com:x",
	"null", "", "HTTPS://Example.COM", "https://example.com:", "https://[::1]:443", "//example.com",
	"https://exa mple.com", "https://ex%41mple.com", "https://ex%zzmple.com", "chrome-extension://abcdef",
	"https://example.com/path",
}

func emitCrossOrigin(b *bytes.Buffer) {
	prot := http.NewCrossOriginProtection()
	if err := prot.AddTrustedOrigin("https://partner.example"); err != nil {
		panic(err)
	}
	prot.AddInsecureBypassPattern("/hook/")

	fmt.Fprintf(b, "pub const CrossOriginCase = struct {\n    id: []const u8,\n    method: []const u8,\n    host: []const u8,\n    path: []const u8,\n")
	fmt.Fprintf(b, "    /// Request header lines, CRLF-terminated.\n    headers: []const u8,\n    /// Check's error text; \"\" = allowed.\n    err: []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's CrossOriginProtection.Check (trusted https://partner.example, bypass /hook/).\npub const crossorigin = [_]CrossOriginCase{\n")
	for _, c := range coCases() {
		req := httptest.NewRequest(c.method, "http://placeholder"+c.path, nil)
		req.Host = c.host
		var hb strings.Builder
		for _, h := range c.headers {
			req.Header.Add(h[0], h[1])
			hb.WriteString(h[0] + ": " + h[1] + "\r\n")
		}
		msg := ""
		if err := prot.Check(req); err != nil {
			msg = err.Error()
		}
		fmt.Fprintf(b, "    .{ .id = %s, .method = %s, .host = %s, .path = %s, .headers = %s, .err = %s },\n",
			zigStr(c.id), zigStr(c.method), zigStr(c.host), zigStr(c.path), zigStr(hb.String()), zigStr(msg))
	}
	fmt.Fprintf(b, "};\n\n")

	fmt.Fprintf(b, "pub const TrustedOriginCase = struct { origin: []const u8, ok: bool };\n\n")
	fmt.Fprintf(b, "/// Go's AddTrustedOrigin: accepted or refused.\npub const trusted_origin = [_]TrustedOriginCase{\n")
	for _, o := range coOrigins {
		err := http.NewCrossOriginProtection().AddTrustedOrigin(o)
		fmt.Fprintf(b, "    .{ .origin = %s, .ok = %v },\n", zigStr(o), err == nil)
	}
	fmt.Fprintf(b, "};\n\n")

	// The default denial, through Handler.
	h := prot.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("POST", "http://a.example/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	fmt.Fprintf(b, "/// Go's default denial (Handler without SetDenyHandler).\n")
	fmt.Fprintf(b, "pub const crossorigin_deny = .{ .status = %d, .content_type = %s, .body = %s };\n\n",
		rec.Code, zigStr(rec.Header().Get("Content-Type")), zigStr(rec.Body.String()))
}
