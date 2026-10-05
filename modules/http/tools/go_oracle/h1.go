// SPDX-License-Identifier: MIT

// Area h1: which requests on one HTTP/1.1 connection reach the handler, with
// what method, target and body, and whether the server itself answers an
// error. Asked of a real net/http.Server over loopback: the client writes the
// case's bytes, half-closes, and reads until the server closes.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type h1Case struct {
	id   string
	wire string
}

// crlf joins request lines with CRLF; the last element is appended as is
// (the body, or "" after the blank line).
func crlf(lines ...string) string {
	var b bytes.Buffer
	for i, l := range lines {
		b.WriteString(l)
		if i < len(lines)-1 {
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// get is a well-formed GET with the given extra header lines.
func get(extra ...string) string {
	lines := append([]string{"GET / HTTP/1.1", "Host: x"}, extra...)
	lines = append(lines, "", "")
	return crlf(lines...)
}

func post(headers []string, body string) string {
	lines := append([]string{"POST /p HTTP/1.1", "Host: x"}, headers...)
	lines = append(lines, "", body)
	return crlf(lines...)
}

var h1Cases = []h1Case{
	// ── baseline ──
	{"get", get()},
	{"get-no-host-1.1", crlf("GET / HTTP/1.1", "", "")},
	{"get-no-host-1.0", crlf("GET / HTTP/1.0", "", "")},
	{"get-two-host", get("Host: y")},
	{"get-host-empty", crlf("GET / HTTP/1.1", "Host:", "", "")},
	{"get-host-bad-char", crlf("GET / HTTP/1.1", "Host: a b", "", "")},
	{"get-host-userinfo", crlf("GET / HTTP/1.1", "Host: u@x", "", "")},
	{"pipeline-two-get", get() + get()},
	{"pipeline-after-close", get("Connection: close") + get()},
	{"http10-keepalive-pipeline", crlf("GET / HTTP/1.0", "Connection: keep-alive", "", "") + get()},
	{"leading-crlf", "\r\n" + get()},
	{"leading-two-crlf", "\r\n\r\n" + get()},

	// ── request line ──
	{"lf-only-lines", "GET / HTTP/1.1\nHost: x\n\n"},
	{"bare-cr-line-end", "GET / HTTP/1.1\rHost: x\r\n\r\n"},
	{"double-space-request-line", crlf("GET  / HTTP/1.1", "Host: x", "", "")},
	{"tab-request-line", crlf("GET\t/ HTTP/1.1", "Host: x", "", "")},
	{"trailing-space-request-line", crlf("GET / HTTP/1.1 ", "Host: x", "", "")},
	{"lowercase-method", crlf("get / HTTP/1.1", "Host: x", "", "")},
	{"extension-method", crlf("PURGE / HTTP/1.1", "Host: x", "", "")},
	{"bad-method-char", crlf("GE(T / HTTP/1.1", "Host: x", "", "")},
	{"lowercase-version", crlf("GET / http/1.1", "Host: x", "", "")},
	{"version-1.2", crlf("GET / HTTP/1.2", "Host: x", "", "")},
	{"version-2.0", crlf("GET / HTTP/2.0", "Host: x", "", "")},
	{"version-0.9", crlf("GET /", "", "")},
	{"version-leading-zero", crlf("GET / HTTP/01.1", "Host: x", "", "")},
	{"absolute-form", crlf("GET http://x/a?b HTTP/1.1", "Host: x", "", "")},
	{"options-asterisk", crlf("OPTIONS * HTTP/1.1", "Host: x", "", "")},
	{"get-asterisk", crlf("GET * HTTP/1.1", "Host: x", "", "")},
	{"connect-authority", crlf("CONNECT x:443 HTTP/1.1", "Host: x:443", "", "")},
	{"target-no-slash", crlf("GET a HTTP/1.1", "Host: x", "", "")},
	{"target-with-fragment", crlf("GET /a#f HTTP/1.1", "Host: x", "", "")},
	{"target-ctl-char", crlf("GET /a\x01 HTTP/1.1", "Host: x", "", "")},
	{"target-high-byte", crlf("GET /\xc4\x8d HTTP/1.1", "Host: x", "", "")},

	// ── header fields ──
	{"obs-fold", crlf("GET / HTTP/1.1", "Host: x", "X-A: 1", " 2", "", "")},
	{"space-before-colon", crlf("GET / HTTP/1.1", "Host: x", "X-A : 1", "", "")},
	{"empty-header-name", crlf("GET / HTTP/1.1", "Host: x", ": 1", "", "")},
	{"header-no-colon", crlf("GET / HTTP/1.1", "Host: x", "X-A", "", "")},
	{"header-name-bad-char", crlf("GET / HTTP/1.1", "Host: x", "X(A: 1", "", "")},
	{"header-value-nul", crlf("GET / HTTP/1.1", "Host: x", "X-A: a\x00b", "", "")},
	{"header-value-ctl", crlf("GET / HTTP/1.1", "Host: x", "X-A: a\x01b", "", "")},
	{"header-value-del", crlf("GET / HTTP/1.1", "Host: x", "X-A: a\x7fb", "", "")},
	{"header-value-bare-cr", crlf("GET / HTTP/1.1", "Host: x", "X-A: a\rb", "", "")},
	{"header-value-high", crlf("GET / HTTP/1.1", "Host: x", "X-A: \xc4\x8d", "", "")},
	{"header-value-tab", crlf("GET / HTTP/1.1", "Host: x", "X-A: a\tb", "", "")},
	{"first-header-whitespace", crlf("GET / HTTP/1.1", " Host: x", "", "")},

	// ── Content-Length ──
	{"cl-body", post([]string{"Content-Length: 5"}, "hello")},
	{"cl-zero", post([]string{"Content-Length: 0"}, "")},
	{"cl-short-body", post([]string{"Content-Length: 9"}, "hello")},
	{"cl-then-pipeline", post([]string{"Content-Length: 5"}, "hello") + get()},
	{"cl-dup-same", post([]string{"Content-Length: 5", "Content-Length: 5"}, "hello")},
	{"cl-dup-differ", post([]string{"Content-Length: 5", "Content-Length: 6"}, "hello!")},
	{"cl-list-same", post([]string{"Content-Length: 5, 5"}, "hello")},
	{"cl-plus", post([]string{"Content-Length: +5"}, "hello")},
	{"cl-minus", post([]string{"Content-Length: -5"}, "hello")},
	{"cl-leading-zero", post([]string{"Content-Length: 05"}, "hello")},
	{"cl-hex", post([]string{"Content-Length: 0x5"}, "hello")},
	{"cl-trailing-space", post([]string{"Content-Length: 5 "}, "hello")},
	{"cl-inner-space", post([]string{"Content-Length: 5 5"}, "hello")},
	{"cl-empty", post([]string{"Content-Length:"}, "")},
	{"cl-overflow", post([]string{"Content-Length: 99999999999999999999"}, "hello")},
	{"get-with-cl-body", crlf("GET / HTTP/1.1", "Host: x", "Content-Length: 2", "", "hi")},
	{"post-no-length-1.1", post(nil, "") + get()},

	// ── Transfer-Encoding ──
	{"te-chunked", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-pipeline", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n") + get()},
	{"te-chunked-upper", post([]string{"Transfer-Encoding: CHUNKED"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-twice-list", post([]string{"Transfer-Encoding: chunked, chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-two-fields", post([]string{"Transfer-Encoding: chunked", "Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-gzip-chunked", post([]string{"Transfer-Encoding: gzip, chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-gzip", post([]string{"Transfer-Encoding: chunked, gzip"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-identity", post([]string{"Transfer-Encoding: identity", "Content-Length: 5"}, "hello")},
	{"te-xchunked", post([]string{"Transfer-Encoding: xchunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-trailing-ws", post([]string{"Transfer-Encoding: chunked "}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-vtab", post([]string{"Transfer-Encoding: \x0bchunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-empty", post([]string{"Transfer-Encoding:"}, "")},
	{"te-two-fields-gzip-chunked", post([]string{"Transfer-Encoding: gzip", "Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-two-fields-chunked-gzip", post([]string{"Transfer-Encoding: chunked", "Transfer-Encoding: gzip"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-two-fields-empty-chunked", post([]string{"Transfer-Encoding:", "Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-http10-cl", crlf("POST /p HTTP/1.0", "Transfer-Encoding: chunked", "Content-Length: 3", "", "5\r\nhello\r\n0\r\n\r\n")},
	{"te-and-cl", post([]string{"Content-Length: 4", "Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"cl-and-te", post([]string{"Transfer-Encoding: chunked", "Content-Length: 4"}, "5\r\nhello\r\n0\r\n\r\n")},
	{"te-chunked-http10", crlf("POST /p HTTP/1.0", "Transfer-Encoding: chunked", "", "5\r\nhello\r\n0\r\n\r\n")},

	// ── chunked framing ──
	{"chunk-upper-hex", post([]string{"Transfer-Encoding: chunked"}, "A\r\n0123456789\r\n0\r\n\r\n")},
	{"chunk-leading-zeros", post([]string{"Transfer-Encoding: chunked"}, "0005\r\nhello\r\n0\r\n\r\n")},
	{"chunk-ext", post([]string{"Transfer-Encoding: chunked"}, "5;a=b\r\nhello\r\n0\r\n\r\n")},
	{"chunk-ext-quoted", post([]string{"Transfer-Encoding: chunked"}, "5;a=\"b;c\"\r\nhello\r\n0\r\n\r\n")},
	{"chunk-ext-ws", post([]string{"Transfer-Encoding: chunked"}, "5 ;a=b\r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-trailing-space", post([]string{"Transfer-Encoding: chunked"}, "5 \r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-leading-space", post([]string{"Transfer-Encoding: chunked"}, " 5\r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-plus", post([]string{"Transfer-Encoding: chunked"}, "+5\r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-0x", post([]string{"Transfer-Encoding: chunked"}, "0x5\r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-empty", post([]string{"Transfer-Encoding: chunked"}, "\r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-overflow", post([]string{"Transfer-Encoding: chunked"}, "fffffffffffffffff\r\nhello\r\n0\r\n\r\n")},
	{"chunk-size-16-digits", post([]string{"Transfer-Encoding: chunked"}, "0000000000000005\r\nhello\r\n0\r\n\r\n")},
	{"chunk-data-too-long", post([]string{"Transfer-Encoding: chunked"}, "3\r\nhello\r\n0\r\n\r\n")},
	{"chunk-missing-crlf", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello0\r\n\r\n")},
	{"chunk-lf-only", post([]string{"Transfer-Encoding: chunked"}, "5\nhello\n0\n\n")},
	{"chunk-data-lf-only", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\n0\r\n\r\n")},
	{"chunk-bare-cr", post([]string{"Transfer-Encoding: chunked"}, "5\rhello\r\n0\r\n\r\n")},
	{"chunk-trailer", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n")},
	{"chunk-trailer-bad", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\nX T: 1\r\n\r\n")},
	{"chunk-trailer-then-get", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n") + get()},
	{"chunk-last-missing-crlf", post([]string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n")},
	{"chunk-two-chunks", post([]string{"Transfer-Encoding: chunked"}, "2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n")},
	{"chunk-smuggle-te-cl", crlf("POST /p HTTP/1.1", "Host: x", "Content-Length: 6", "Transfer-Encoding: chunked", "", "0\r\n\r\nG")},
}

var statusRe = regexp.MustCompile(`HTTP/1\.[01] (\d{3}) `)

type h1Call struct {
	method, target string
	body           *string // nil: reading the body failed
}

type h1Result struct {
	calls  []h1Call
	reject int // first status the server sent that is not the handler's 200; 0 = none
}

func runH1(srvAddr string, rec *h1Recorder, wire string) h1Result {
	rec.reset()
	c, err := net.DialTimeout("tcp", srvAddr, 3*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(wire)); err != nil {
		log.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()
	resp, _ := io.ReadAll(c) // the server closes after EOF or after an error answer
	c.Close()
	rec.wait()

	r := h1Result{calls: rec.take()}
	for _, m := range statusRe.FindAllSubmatch(resp, -1) {
		code, _ := strconv.Atoi(string(m[1]))
		if code != 200 {
			r.reject = code
			break
		}
	}
	return r
}

type h1Recorder struct {
	mu     sync.Mutex
	calls  []h1Call
	active sync.WaitGroup
}

func (r *h1Recorder) reset() { r.mu.Lock(); r.calls = nil; r.mu.Unlock() }
func (r *h1Recorder) wait()  { r.active.Wait() }
func (r *h1Recorder) take() []h1Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *h1Recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.active.Add(1)
	defer r.active.Done()
	call := h1Call{method: req.Method, target: req.RequestURI}
	if b, err := io.ReadAll(req.Body); err == nil {
		s := string(b)
		call.body = &s
	}
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
	w.Write([]byte("ok"))
}

func emitH1(b *bytes.Buffer) {
	rec := &h1Recorder{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: rec, ReadTimeout: 3 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(ln)
	defer srv.Close()

	fmt.Fprintf(b, "pub const H1Call = struct { method: []const u8, target: []const u8, body: ?[]const u8 };\n")
	fmt.Fprintf(b, "pub const H1Case = struct { id: []const u8, wire: []const u8, calls: []const H1Call, reject: u16 };\n\n")
	fmt.Fprintf(b, "/// Go's net/http.Server on each wire: the handler calls it made, and the\n")
	fmt.Fprintf(b, "/// first non-200 status the server answered itself (0 = none).\n")
	fmt.Fprintf(b, "pub const h1 = [_]H1Case{\n")
	for _, c := range h1Cases {
		r := runH1(ln.Addr().String(), rec, c.wire)
		var calls []string
		for _, call := range r.calls {
			calls = append(calls, fmt.Sprintf(".{ .method = %s, .target = %s, .body = %s }", zigStr(call.method), zigStr(call.target), zigOptStr(call.body)))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .wire = %s, .calls = %s, .reject = %d },\n", zigStr(c.id), zigStr(c.wire), zigList(calls), r.reject)
	}
	fmt.Fprintf(b, "};\n\n")
}
