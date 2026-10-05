// SPDX-License-Identifier: MIT

// Area client: how an HTTP/1.1 client frames a response. A loopback peer
// reads the request head, writes the case's response bytes and closes; Go's
// http.Transport (RoundTrip: no redirects, no gzip, no keep-alive) reads it.
// Recorded: the status it returns (0 = the round trip failed) and the body
// (null = reading it failed).
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type clientCase struct {
	id     string
	method string
	resp   string
}

func cc(id, resp string) clientCase { return clientCase{id, "GET", resp} }

const okHead = "HTTP/1.1 200 OK\r\n"

var clientCases = []clientCase{
	// ── body framing ──
	cc("cl", okHead+"Content-Length: 5\r\n\r\nhello"),
	cc("cl-zero", okHead+"Content-Length: 0\r\n\r\n"),
	cc("cl-short-body", okHead+"Content-Length: 9\r\n\r\nhello"),
	cc("cl-long-body", okHead+"Content-Length: 3\r\n\r\nhello"),
	cc("cl-dup-same", okHead+"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
	cc("cl-dup-differ", okHead+"Content-Length: 5\r\nContent-Length: 3\r\n\r\nhello"),
	cc("cl-list-same", okHead+"Content-Length: 5, 5\r\n\r\nhello"),
	cc("cl-plus", okHead+"Content-Length: +5\r\n\r\nhello"),
	cc("cl-minus", okHead+"Content-Length: -1\r\n\r\nhello"),
	cc("cl-hex", okHead+"Content-Length: 0x5\r\n\r\nhello"),
	cc("cl-overflow", okHead+"Content-Length: 99999999999999999999\r\n\r\nhello"),
	cc("until-close", okHead+"\r\nhello world"),
	cc("until-close-http10", "HTTP/1.0 200 OK\r\n\r\nhello"),
	cc("chunked", okHead+"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
	cc("chunked-ext", okHead+"Transfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n0\r\n\r\n"),
	cc("chunked-trailer", okHead+"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n"),
	cc("chunked-truncated", okHead+"Transfer-Encoding: chunked\r\n\r\n5\r\nhel"),
	cc("chunked-no-last", okHead+"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
	cc("chunked-bad-size", okHead+"Transfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n"),
	cc("chunked-overflow", okHead+"Transfer-Encoding: chunked\r\n\r\nfffffffffffffffff\r\nhello\r\n0\r\n\r\n"),
	cc("chunked-lf-only", okHead+"Transfer-Encoding: chunked\r\n\r\n5\nhello\n0\n\n"),
	cc("chunked-data-too-long", okHead+"Transfer-Encoding: chunked\r\n\r\n3\r\nhello\r\n0\r\n\r\n"),
	cc("chunked-upper", okHead+"Transfer-Encoding: CHUNKED\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
	cc("te-and-cl", okHead+"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
	cc("te-gzip-chunked", okHead+"Transfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
	cc("te-chunked-gzip", okHead+"Transfer-Encoding: chunked, gzip\r\n\r\nhello"),
	cc("te-chunked-chunked", okHead+"Transfer-Encoding: chunked, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
	cc("te-two-fields", okHead+"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
	cc("te-identity", okHead+"Transfer-Encoding: identity\r\n\r\nhello"),
	cc("te-unknown", okHead+"Transfer-Encoding: foo\r\n\r\nhello"),
	cc("te-http10-chunked", "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),

	// ── statuses without a body ──
	cc("204-with-cl", "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello"),
	cc("304-with-cl", "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhello"),
	{"head-with-cl", "HEAD", okHead + "Content-Length: 5\r\n\r\nhello"},
	{"head-chunked", "HEAD", okHead + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"},
	cc("1xx-then-200", "HTTP/1.1 100 Continue\r\n\r\n"+okHead+"Content-Length: 2\r\n\r\nok"),
	cc("103-then-200", "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"+okHead+"Content-Length: 2\r\n\r\nok"),
	cc("two-1xx", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\n"+okHead+"Content-Length: 2\r\n\r\nok"),
	cc("1xx-only", "HTTP/1.1 100 Continue\r\n\r\n"),

	// ── status line ──
	cc("no-reason", "HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok"),
	cc("no-reason-space", "HTTP/1.1 200 \r\nContent-Length: 2\r\n\r\nok"),
	cc("reason-spaces", "HTTP/1.1 200 All Good Here\r\nContent-Length: 2\r\n\r\nok"),
	cc("lowercase-version", "http/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("version-1.2", "HTTP/1.2 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("version-2.0", "HTTP/2.0 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("status-4-digits", "HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("status-2-digits", "HTTP/1.1 99 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("status-600", "HTTP/1.1 600 Odd\r\nContent-Length: 2\r\n\r\nok"),
	cc("status-letters", "HTTP/1.1 2x0 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("double-space", "HTTP/1.1  200 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("leading-space", " HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	cc("no-status-line", "hello"),
	cc("empty-response", ""),
	cc("lf-only-head", "HTTP/1.1 200 OK\nContent-Length: 2\n\nok"),
	cc("reason-ctl", "HTTP/1.1 200 O\x01K\r\nContent-Length: 2\r\n\r\nok"),

	// ── header fields ──
	cc("obs-fold", okHead+"X-A: 1\r\n 2\r\nContent-Length: 2\r\n\r\nok"),
	cc("header-no-colon", okHead+"NoColon\r\nContent-Length: 2\r\n\r\nok"),
	cc("space-before-colon", okHead+"X-A : 1\r\nContent-Length: 2\r\n\r\nok"),
	cc("space-before-colon-cl", okHead+"Content-Length : 2\r\n\r\nok"),
	cc("header-value-nul", okHead+"X-A: a\x00b\r\nContent-Length: 2\r\n\r\nok"),
	cc("header-value-high", okHead+"X-A: \xc4\x8d\r\nContent-Length: 2\r\n\r\nok"),
	cc("header-bare-cr", okHead+"X-A: a\rb\r\nContent-Length: 2\r\n\r\nok"),
	cc("header-name-bad-char", okHead+"X(A: 1\r\nContent-Length: 2\r\n\r\nok"),
}

type clientResult struct {
	status int     // 0: RoundTrip failed
	body   *string // nil: reading the body failed
}

func runClient(c clientCase) clientResult {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		for { // the request head, up to its blank line
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		conn.Write([]byte(c.resp))
	}()

	tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(c.method, "http://"+ln.Addr().String()+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return clientResult{}
	}
	defer resp.Body.Close()
	r := clientResult{status: resp.StatusCode}
	if b, err := io.ReadAll(resp.Body); err == nil {
		s := string(b)
		r.body = &s
	}
	return r
}

func emitClient(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const ClientCase = struct {\n    id: []const u8,\n    method: []const u8,\n    response: []const u8,\n")
	fmt.Fprintf(b, "    /// 0: the round trip failed.\n    status: u16,\n    /// null: reading the body failed.\n    body: ?[]const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's http.Transport.RoundTrip against a peer that answers with `response` and closes.\n")
	fmt.Fprintf(b, "pub const client = [_]ClientCase{\n")
	for _, c := range clientCases {
		r := runClient(c)
		fmt.Fprintf(b, "    .{ .id = %s, .method = %s, .response = %s, .status = %d, .body = %s },\n",
			zigStr(c.id), zigStr(c.method), zigStr(c.resp), r.status, zigOptStr(r.body))
	}
	fmt.Fprintf(b, "};\n\n")
}
