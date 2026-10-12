// SPDX-License-Identifier: MIT

// Area client_gzip: transparent gzip in an HTTP/1.1 client. A loopback peer
// reads the request head, writes the case's response bytes and closes; Go's
// http.Transport with its default compression (DisableCompression false)
// does the round trip. Recorded: the Accept-Encoding Go sent ("" = none),
// whether it decoded (Response.Uncompressed), the Content-Encoding and
// ContentLength it shows the caller, and the body it hands over (null =
// reading it failed).
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type gzipCase struct {
	id     string
	method string
	// One caller request header, "Name: value", or "".
	header string
	resp   string
}

// gz is a gzip member of s as Go's own writer makes it (MTIME 0, no name).
func gz(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func gzCL(ce, body string) string {
	return okHead + "Content-Encoding: " + ce + "\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
}

func flip(s string, at int) string {
	if at < 0 {
		at += len(s)
	}
	b := []byte(s)
	b[at] ^= 1
	return string(b)
}

// withFlags rewrites the header of member m to carry FNAME "n.txt" and,
// when crc is true, an FHCRC whose value is `crc16`.
func withFlags(m string, crc bool, crc16 uint16) string {
	h := []byte(m[:10])
	h[3] = 0x08
	out := string(h) + "n.txt\x00"
	if crc {
		h[3] |= 0x02
		out = string(h) + "n.txt\x00" + string([]byte{byte(crc16), byte(crc16 >> 8)})
	}
	return out + m[10:]
}

var (
	gzHello = gz("hello gzip")
	gzLarge = gz(strings.Repeat("the quick brown fox jumps over the lazy dog\n", 3000))
)

func gzipCases() []gzipCase {
	c := func(id, resp string) gzipCase { return gzipCase{id, "GET", "", resp} }
	chunked := okHead + "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" +
		fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(gzHello), gzHello)
	return []gzipCase{
		// ── decoded ──
		c("cl", gzCL("gzip", gzHello)),
		c("chunked", chunked),
		c("large", gzCL("gzip", gzLarge)),
		c("multi-member", gzCL("gzip", gz("first,")+gz("second"))),
		c("empty-body", gzCL("gzip", "")),
		c("204", "HTTP/1.1 204 No Content\r\nContent-Encoding: gzip\r\n\r\n"),
		c("ce-upper", gzCL("GZIP", gzHello)),
		c("ce-dup-first-gzip", okHead+"Content-Encoding: gzip\r\nContent-Encoding: br\r\nContent-Length: "+fmt.Sprint(len(gzHello))+"\r\n\r\n"+gzHello),
		c("fname", gzCL("gzip", withFlags(gzHello, false, 0))),
		// ── not asked for, or not decoded ──
		{"head", "HEAD", "", okHead + "Content-Encoding: gzip\r\nContent-Length: " + fmt.Sprint(len(gzHello)) + "\r\n\r\n"},
		{"caller-ae-gzip", "GET", "Accept-Encoding: gzip", gzCL("gzip", gzHello)},
		{"caller-ae-identity", "GET", "Accept-Encoding: identity", gzCL("gzip", gzHello)},
		{"range", "GET", "Range: bytes=0-", gzCL("gzip", gzHello)},
		c("x-gzip", gzCL("x-gzip", gzHello)),
		c("ce-list", gzCL("gzip, identity", gzHello)),
		c("ce-deflate", gzCL("deflate", "xyz")),
		c("no-ce", okHead+"Content-Length: 5\r\n\r\nhello"),
		// ── broken gzip ──
		c("not-gzip", gzCL("gzip", "hello")),
		c("bad-crc", gzCL("gzip", flip(gzHello, -8))),
		c("bad-isize", gzCL("gzip", flip(gzHello, -1))),
		c("cut-deflate", gzCL("gzip", gzHello[:len(gzHello)/2])),
		c("cut-trailer", gzCL("gzip", gzHello[:len(gzHello)-3])),
		c("cut-header", gzCL("gzip", gzHello[:5])),
		c("trailing-garbage", gzCL("gzip", gzHello+"junk")),
		c("trailing-zeros", gzCL("gzip", gzHello+"\x00\x00\x00\x00")),
		c("bad-fhcrc", gzCL("gzip", withFlags(gzHello, true, 0xabcd))),
	}
}

type gzipResult struct {
	ae           string
	status       int // 0: RoundTrip failed
	uncompressed bool
	ce           string
	cl           int64
	body         *string // nil: reading the body failed
}

func runGzip(c gzipCase) gzipResult {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	ae := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ae <- ""
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		got := ""
		for { // the request head, up to its blank line
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "accept-encoding") {
				got = strings.TrimSpace(value)
			}
		}
		ae <- got
		conn.Write([]byte(c.resp))
	}()

	tr := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(c.method, "http://"+ln.Addr().String()+"/", nil)
	if c.header != "" {
		name, value, _ := strings.Cut(c.header, ": ")
		req.Header.Set(name, value)
	}
	resp, err := tr.RoundTrip(req)
	r := gzipResult{ae: <-ae}
	if err != nil {
		return r
	}
	defer resp.Body.Close()
	r.status = resp.StatusCode
	r.uncompressed = resp.Uncompressed
	r.ce = resp.Header.Get("Content-Encoding")
	r.cl = resp.ContentLength
	if b, err := io.ReadAll(resp.Body); err == nil {
		s := string(b)
		r.body = &s
	}
	return r
}

func emitClientGzip(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const GzipCase = struct {\n    id: []const u8,\n    method: []const u8,\n")
	fmt.Fprintf(b, "    /// One caller request header, \"Name: value\", or \"\".\n    header: []const u8,\n    response: []const u8,\n")
	fmt.Fprintf(b, "    /// The Accept-Encoding Go sent; \"\" = none.\n    accept_encoding: []const u8,\n")
	fmt.Fprintf(b, "    /// 0: the round trip failed.\n    status: u16,\n    uncompressed: bool,\n")
	fmt.Fprintf(b, "    /// The Content-Encoding the caller sees; \"\" = none.\n    content_encoding: []const u8,\n")
	fmt.Fprintf(b, "    /// Response.ContentLength; -1 = unknown.\n    content_length: i64,\n")
	fmt.Fprintf(b, "    /// null: reading the body failed.\n    body: ?[]const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's http.Transport with default compression against a peer that answers with `response` and closes.\n")
	fmt.Fprintf(b, "pub const client_gzip = [_]GzipCase{\n")
	for _, c := range gzipCases() {
		r := runGzip(c)
		fmt.Fprintf(b, "    .{ .id = %s, .method = %s, .header = %s, .response = %s, .accept_encoding = %s, .status = %d, .uncompressed = %t, .content_encoding = %s, .content_length = %d, .body = %s },\n",
			zigStr(c.id), zigStr(c.method), zigStr(c.header), zigStr(c.resp), zigStr(r.ae), r.status, r.uncompressed, zigStr(r.ce), r.cl, zigOptStr(r.body))
	}
	fmt.Fprintf(b, "};\n\n")
}
