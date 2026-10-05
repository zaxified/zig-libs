// SPDX-License-Identifier: MIT

// Area serve: conditional requests (If-Match, If-None-Match,
// If-Modified-Since, If-Unmodified-Since, If-Range) and byte ranges, asked of
// net/http.ServeContent over a 100-byte representation. Recorded: the status,
// the single Content-Range, and each part's range of a multipart/byteranges
// answer.
package main

import (
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

const serveSize = 100

// The representation's validators. lastMod is RFC 9110's example instant.
var serveLastMod = time.Unix(784111777, 0).UTC()

const (
	imfAt     = "Sun, 06 Nov 1994 08:49:37 GMT"
	imfBefore = "Sun, 06 Nov 1994 08:49:36 GMT"
	imfAfter  = "Sun, 06 Nov 1994 08:49:38 GMT"
)

type serveCase struct {
	id      string
	method  string
	etag    string // "" = the representation has no ETag
	lastMod bool   // false = no Last-Modified
	headers []string
}

func sc(id string, headers ...string) serveCase {
	return serveCase{id: id, method: "GET", etag: `"v1"`, lastMod: true, headers: headers}
}

func (c serveCase) with(f func(*serveCase)) serveCase { f(&c); return c }

func method(m string) func(*serveCase) { return func(c *serveCase) { c.method = m } }
func etag(e string) func(*serveCase)   { return func(c *serveCase) { c.etag = e } }
func noLastMod() func(*serveCase)      { return func(c *serveCase) { c.lastMod = false } }

// rangeValues are Range header values tried alone on a plain GET.
var rangeValues = []string{
	"bytes=0-9", "bytes=-10", "bytes=90-", "bytes=95-200", "bytes=99-99", "bytes=100-",
	"bytes=-0", "bytes=0-0", "bytes=5-4", "bytes=", "bytes=,", "bytes=0-9,", "bytes=,0-9",
	"bytes=0-9,,20-29", "bytes = 0-9", "Bytes=0-9", "BYTES=0-9", "bytes=0-9 ", " bytes=0-9",
	"bytes=0 -9", "bytes=0- 9", "bytes=-", "bytes=--1", "bytes=a-b", "bytes=0x0-9",
	"bytes=+1-9", "bytes=1-+9", "items=0-9", "bytes=0-9,20-29", "bytes=0-9,5-14",
	"bytes=0-,0-,0-", "bytes=0-49,50-99", "bytes=0-49,50-100", "bytes=-200", "bytes=200-300",
	"bytes=200-300,0-9", "bytes=99999999999999999999-", "bytes=0-99999999999999999999",
	"bytes=18446744073709551615-", "bytes=-18446744073709551616", "bytes=0-9\t", "bytes=\t0-9",
	"bytes=0-9;x", "bytes=0-9 , 20-29", "bytes=1-1,3-3,5-5", "bytes=-1,-1",
	"bytes=0-9, bytes=20-29",
}

func serveCases() []serveCase {
	cs := []serveCase{
		sc("plain"),
		sc("head-plain").with(method("HEAD")),

		// If-None-Match (weak comparison)
		sc("inm-hit", `If-None-Match: "v1"`),
		sc("inm-miss", `If-None-Match: "v2"`),
		sc("inm-weak-hit", `If-None-Match: W/"v1"`),
		sc("inm-star", `If-None-Match: *`),
		sc("inm-list-hit", `If-None-Match: "a", "v1"`),
		sc("inm-list-nospace", `If-None-Match: "a","v1"`),
		sc("inm-unquoted", `If-None-Match: v1`),
		sc("inm-comma-in-tag", `If-None-Match: "v1,x"`).with(etag(`"v1,x"`)),
		sc("inm-comma-in-tag-list", `If-None-Match: "a", "v1,x"`).with(etag(`"v1,x"`)),
		sc("inm-empty", `If-None-Match:`),
		sc("inm-hit-head", `If-None-Match: "v1"`).with(method("HEAD")),
		sc("inm-hit-post", `If-None-Match: "v1"`).with(method("POST")),
		sc("inm-star-post", `If-None-Match: *`).with(method("POST")),
		sc("inm-current-weak", `If-None-Match: "v1"`).with(etag(`W/"v1"`)),
		sc("inm-no-etag", `If-None-Match: "v1"`).with(etag("")),
		sc("inm-star-no-etag", `If-None-Match: *`).with(etag("")),
		sc("inm-hit-ims-after", `If-None-Match: "v1"`, "If-Modified-Since: "+imfBefore),
		sc("inm-miss-ims-hit", `If-None-Match: "v2"`, "If-Modified-Since: "+imfAt),

		// If-Match (strong comparison)
		sc("im-hit", `If-Match: "v1"`),
		sc("im-miss", `If-Match: "v2"`),
		sc("im-weak", `If-Match: W/"v1"`),
		sc("im-star", `If-Match: *`),
		sc("im-star-no-etag", `If-Match: *`).with(etag("")),
		sc("im-current-weak", `If-Match: "v1"`).with(etag(`W/"v1"`)),
		sc("im-list-hit", `If-Match: "a", "v1"`),
		sc("im-comma-in-tag", `If-Match: "v1,x"`).with(etag(`"v1,x"`)),
		sc("im-miss-put", `If-Match: "v2"`).with(method("PUT")),
		sc("im-hit-ius-fail", `If-Match: "v1"`, "If-Unmodified-Since: "+imfBefore),
		sc("im-empty", `If-Match:`),

		// If-Unmodified-Since
		sc("ius-at", "If-Unmodified-Since: "+imfAt),
		sc("ius-before", "If-Unmodified-Since: "+imfBefore),
		sc("ius-after", "If-Unmodified-Since: "+imfAfter),
		sc("ius-bad-date", "If-Unmodified-Since: yesterday"),
		sc("ius-no-lastmod", "If-Unmodified-Since: "+imfBefore).with(noLastMod()),

		// If-Modified-Since
		sc("ims-at", "If-Modified-Since: "+imfAt),
		sc("ims-before", "If-Modified-Since: "+imfBefore),
		sc("ims-after", "If-Modified-Since: "+imfAfter),
		sc("ims-rfc850", "If-Modified-Since: Sunday, 06-Nov-94 08:49:37 GMT"),
		sc("ims-asctime", "If-Modified-Since: Sun Nov  6 08:49:37 1994"),
		sc("ims-bad-date", "If-Modified-Since: yesterday"),
		sc("ims-lowercase-gmt", "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 gmt"),
		sc("ims-utc", "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 UTC"),
		sc("ims-wrong-weekday", "If-Modified-Since: Mon, 06 Nov 1994 08:49:37 GMT"),
		sc("ims-feb-31", "If-Modified-Since: Thu, 31 Feb 2000 00:00:00 GMT"),
		sc("ims-hour-24", "If-Modified-Since: Sun, 06 Nov 1994 24:00:00 GMT"),
		sc("ims-leap-second", "If-Modified-Since: Sun, 06 Nov 1994 08:49:60 GMT"),
		sc("ims-rfc850-yy69", "If-Modified-Since: Sunday, 06-Nov-69 08:49:37 GMT"),
		sc("ims-rfc850-yy70", "If-Modified-Since: Thursday, 01-Jan-70 00:00:00 GMT"),
		sc("ims-post", "If-Modified-Since: "+imfAt).with(method("POST")),
		sc("ims-no-lastmod", "If-Modified-Since: "+imfAt).with(noLastMod()),

		// If-Range
		sc("ir-etag-hit", "Range: bytes=0-9", `If-Range: "v1"`),
		sc("ir-etag-miss", "Range: bytes=0-9", `If-Range: "v2"`),
		sc("ir-etag-weak", "Range: bytes=0-9", `If-Range: W/"v1"`),
		sc("ir-current-weak", "Range: bytes=0-9", `If-Range: "v1"`).with(etag(`W/"v1"`)),
		sc("ir-date-hit", "Range: bytes=0-9", "If-Range: "+imfAt),
		sc("ir-date-after", "Range: bytes=0-9", "If-Range: "+imfAfter),
		sc("ir-date-before", "Range: bytes=0-9", "If-Range: "+imfBefore),
		sc("ir-bad", "Range: bytes=0-9", "If-Range: whatever"),
		sc("ir-no-range", `If-Range: "v1"`),
		sc("ir-date-no-lastmod", "Range: bytes=0-9", "If-Range: "+imfAt).with(noLastMod()),

		// Range with methods and preconditions
		sc("range-head", "Range: bytes=0-9").with(method("HEAD")),
		sc("range-post", "Range: bytes=0-9").with(method("POST")),
		sc("range-inm-miss", "Range: bytes=0-9", `If-None-Match: "v2"`),
		sc("range-inm-hit", "Range: bytes=0-9", `If-None-Match: "v1"`),
		sc("range-two-headers", "Range: bytes=0-9", "Range: bytes=20-29"),
	}
	for i, v := range rangeValues {
		cs = append(cs, sc(fmt.Sprintf("range-%02d", i), "Range: "+v))
	}
	return cs
}

type serveResult struct {
	status       int
	contentRange string
	parts        [][2]int64
}

func runServe(c serveCase) serveResult {
	req := httptest.NewRequest(c.method, "/r", nil)
	for _, h := range c.headers {
		name, value, _ := strings.Cut(h, ":")
		req.Header.Add(name, strings.TrimLeft(value, " "))
	}
	rec := httptest.NewRecorder()
	if c.etag != "" {
		rec.Header().Set("Etag", c.etag)
	}
	mod := time.Time{}
	if c.lastMod {
		mod = serveLastMod
	}
	http.ServeContent(rec, req, "r", mod, strings.NewReader(strings.Repeat("0123456789", serveSize/10)))

	r := serveResult{status: rec.Code, contentRange: rec.Header().Get("Content-Range")}
	mt, params, _ := mime.ParseMediaType(rec.Header().Get("Content-Type"))
	if r.status == 206 && mt == "multipart/byteranges" {
		mr := multipart.NewReader(bytes.NewReader(rec.Body.Bytes()), params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				break
			}
			var s, e, total int64
			fmt.Sscanf(p.Header.Get("Content-Range"), "bytes %d-%d/%d", &s, &e, &total)
			r.parts = append(r.parts, [2]int64{s, e})
		}
	}
	return r
}

func emitServe(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const ServeCase = struct {\n")
	fmt.Fprintf(b, "    id: []const u8,\n    method: []const u8,\n    etag: ?[]const u8,\n    last_modified: ?i64,\n")
	fmt.Fprintf(b, "    /// Request header lines, CRLF-terminated.\n    headers: []const u8,\n")
	fmt.Fprintf(b, "    status: u16,\n    content_range: []const u8,\n    /// Inclusive [first, last] of each multipart/byteranges part.\n    parts: []const [2]u64,\n};\n\n")
	fmt.Fprintf(b, "pub const serve_size = %d;\n\n", serveSize)
	fmt.Fprintf(b, "/// Go's http.ServeContent over a %d-byte representation.\n", serveSize)
	fmt.Fprintf(b, "pub const serve = [_]ServeCase{\n")
	for _, c := range serveCases() {
		r := runServe(c)
		etagLit := "null"
		if c.etag != "" {
			etagLit = zigStr(c.etag)
		}
		lm := "null"
		if c.lastMod {
			lm = fmt.Sprint(serveLastMod.Unix())
		}
		var hb strings.Builder
		for _, h := range c.headers {
			hb.WriteString(h + "\r\n")
		}
		var parts []string
		for _, p := range r.parts {
			parts = append(parts, fmt.Sprintf(".{ %d, %d }", p[0], p[1]))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .method = %s, .etag = %s, .last_modified = %s, .headers = %s, .status = %d, .content_range = %s, .parts = %s },\n",
			zigStr(c.id), zigStr(c.method), etagLit, lm, zigStr(hb.String()), r.status, zigStr(r.contentRange), zigList(parts))
	}
	fmt.Fprintf(b, "};\n\n")
}
