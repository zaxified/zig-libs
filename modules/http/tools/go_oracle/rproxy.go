// SPDX-License-Identifier: MIT

// Area rproxy: what a reverse proxy does to the header section on its way
// through. Go's httputil.ReverseProxy (NewSingleHostReverseProxy: the
// classic Director, which keeps the client's Host and APPENDS the peer to
// X-Forwarded-For -- the shape proxy.ProxyHandler has with rewrite_host =
// false) sits between a raw loopback client and a raw loopback backend. The
// backend records the exact request head and body the proxy sent; the client
// records the response head the proxy returned. Each case adds header lines
// to the request and to the backend's response.
//
// Recorded heads are normalised: field names lower-cased, values trimmed,
// lines sorted by name (stable), and the fields each proxy owns by design
// dropped -- framing (Content-Length, Transfer-Encoding), per-hop Connection,
// and the headers only one side injects (Via, X-Forwarded-Proto,
// X-Forwarded-Host, User-Agent on the way up; Date, Server on the way back).
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type rpCase struct {
	id        string
	method    string
	reqExtra  string // header lines added to the request
	body      string // request body; framing added from bodyMode
	chunked   bool
	respExtra string // header lines added to the backend's response
}

func rp(id, reqExtra, respExtra string) rpCase { return rpCase{id: id, method: "GET", reqExtra: reqExtra, respExtra: respExtra} }

var rpCases = []rpCase{
	rp("plain", "", ""),
	rp("conn-keep-alive", "Connection: keep-alive\r\n", ""),
	rp("conn-close", "Connection: close\r\n", ""),
	rp("conn-lists-one", "Connection: X-Secret\r\nX-Secret: 1\r\nX-Keep: 2\r\n", ""),
	rp("conn-lists-two", "Connection: x-secret, X-Other\r\nX-Secret: 1\r\nX-Other: 2\r\nX-Keep: 3\r\n", ""),
	rp("conn-two-lines", "Connection: X-A\r\nConnection: X-B\r\nX-A: 1\r\nX-B: 2\r\nX-Keep: 3\r\n", ""),
	rp("conn-lower", "connection: X-Secret\r\nx-secret: 1\r\n", ""),
	rp("conn-empty-elems", "Connection: ,X-Secret,\r\nX-Secret: 1\r\n", ""),
	rp("conn-lists-end-to-end", "Connection: Content-Type\r\nContent-Type: text/plain\r\n", ""),
	rp("conn-lists-te", "Connection: TE\r\nTE: trailers\r\n", ""),
	rp("conn-lists-xff", "Connection: X-Forwarded-For\r\nX-Forwarded-For: 6.6.6.6\r\n", ""),
	rp("keep-alive", "Keep-Alive: timeout=5\r\n", ""),
	rp("proxy-connection", "Proxy-Connection: keep-alive\r\n", ""),
	rp("proxy-authorization", "Proxy-Authorization: Basic YTpi\r\n", ""),
	rp("proxy-other", "Proxy-Foo: x\r\n", ""),
	rp("te-trailers", "TE: trailers\r\n", ""),
	rp("te-gzip-trailers", "TE: gzip, trailers\r\n", ""),
	rp("te-gzip", "TE: gzip\r\n", ""),
	rp("trailer", "Trailer: X-T\r\n", ""),
	rp("upgrade", "Upgrade: websocket\r\n", ""),
	rp("xff-one", "X-Forwarded-For: 10.0.0.1\r\n", ""),
	rp("xff-two-lines", "X-Forwarded-For: 10.0.0.1\r\nX-Forwarded-For: 10.0.0.2\r\n", ""),
	rp("xff-list", "X-Forwarded-For: 10.0.0.1, 10.0.0.2\r\n", ""),
	rp("forwarded", "Forwarded: for=192.0.2.1\r\n", ""),
	rp("cookie-two-lines", "Cookie: a=1\r\nCookie: b=2\r\n", ""),
	rp("authorization", "Authorization: Bearer t\r\n", ""),
	{id: "post-cl", method: "POST", reqExtra: "Content-Type: text/plain\r\n", body: "abc"},
	{id: "post-chunked", method: "POST", reqExtra: "Content-Type: text/plain\r\n", body: "abc", chunked: true},
	// ── the backend's response ──
	rp("resp-conn-lists", "", "Connection: X-Back\r\nX-Back: 1\r\nX-Keep: 2\r\n"),
	rp("resp-conn-two-lines", "", "Connection: X-A\r\nConnection: X-B\r\nX-A: 1\r\nX-B: 2\r\n"),
	rp("resp-keep-alive", "", "Keep-Alive: timeout=5\r\n"),
	rp("resp-proxy-authenticate", "", "Proxy-Authenticate: Basic\r\n"),
	rp("resp-proxy-other", "", "Proxy-Foo: x\r\n"),
	rp("resp-upgrade", "", "Upgrade: h2c\r\n"),
	rp("resp-trailer", "", "Trailer: X-T\r\n"),
	rp("resp-set-cookie-two", "", "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n"),
	rp("resp-te", "", "TE: trailers\r\n"),
}

// rpWire is the request a case sends to the proxy.
func rpWire(c rpCase) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s /p?q=1 HTTP/1.1\r\nHost: front.example\r\nAccept-Encoding: identity\r\n%s", c.method, c.reqExtra)
	switch {
	case c.chunked:
		fmt.Fprintf(&b, "Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(c.body), c.body)
	case c.body != "":
		fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(c.body), c.body)
	default:
		b.WriteString("\r\n")
	}
	return b.String()
}

// rpResponse is what the backend answers a case with.
func rpResponse(c rpCase) string {
	return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n" + c.respExtra + "\r\nok"
}

var rpUpIgnore = map[string]bool{"connection": true, "content-length": true, "transfer-encoding": true, "via": true, "x-forwarded-proto": true, "x-forwarded-host": true, "user-agent": true}
var rpDownIgnore = map[string]bool{"connection": true, "content-length": true, "transfer-encoding": true, "via": true, "date": true, "server": true}

// rpNorm splits a raw head into its first line and normalised field lines.
func rpNorm(head string, ignore map[string]bool) (string, []string) {
	lines := strings.Split(strings.TrimSuffix(head, "\r\n\r\n"), "\r\n")
	var out []string
	for _, l := range lines[1:] {
		i := strings.IndexByte(l, ':')
		if i < 0 {
			continue
		}
		name := strings.ToLower(l[:i])
		if ignore[name] {
			continue
		}
		out = append(out, name+": "+strings.TrimSpace(l[i+1:]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.SplitN(out[i], ":", 2)[0] < strings.SplitN(out[j], ":", 2)[0]
	})
	return lines[0], out
}

// rpReadMessage reads one message (head + body by Content-Length or chunked)
// from r and returns the head and the decoded body.
func rpReadMessage(r *bufio.Reader) (string, string, error) {
	var head strings.Builder
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return "", "", err
		}
		head.WriteString(l)
		if l == "\r\n" {
			break
		}
	}
	h := head.String()
	lower := strings.ToLower(h)
	if i := strings.Index(lower, "\r\ncontent-length:"); i >= 0 {
		v := h[i+len("\r\ncontent-length:"):]
		v = strings.TrimSpace(v[:strings.Index(v, "\r\n")])
		n, _ := strconv.Atoi(v)
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", "", err
		}
		return h, string(buf), nil
	}
	if strings.Contains(lower, "\r\ntransfer-encoding: chunked") {
		var body strings.Builder
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return "", "", err
			}
			n, _ := strconv.ParseInt(strings.TrimSpace(strings.SplitN(l, ";", 2)[0]), 16, 64)
			if n == 0 {
				for { // trailer section
					t, err := r.ReadString('\n')
					if err != nil || t == "\r\n" {
						return h, body.String(), err
					}
				}
			}
			buf := make([]byte, n+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return "", "", err
			}
			body.Write(buf[:n])
		}
	}
	return h, "", nil
}

type rpOutcome struct {
	upLine string
	up     []string
	upBody string
	status int
	down   []string
}

func emitRProxy(b *bytes.Buffer) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()
	type seen struct{ head, body string }
	seenCh := make(chan seen, 1)
	var current rpCase
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			r := bufio.NewReader(conn)
			h, body, err := rpReadMessage(r)
			if err == nil {
				seenCh <- seen{h, body}
				io.WriteString(conn, rpResponse(current))
			}
			conn.Close()
		}
	}()

	target, _ := url.Parse("http://" + backend.Addr().String())
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{DisableKeepAlives: true, DisableCompression: true}
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: proxy, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(front)
	defer srv.Close()

	fmt.Fprintf(b, "pub const RProxyCase = struct {\n    id: []const u8,\n    /// The request the client sends to the proxy.\n    wire: []const u8,\n")
	fmt.Fprintf(b, "    /// Header lines the backend adds to its `200 OK` (`Content-Length: 2`, `Content-Type: text/plain`, body `ok`).\n    resp_extra: []const u8,\n")
	fmt.Fprintf(b, "    /// What Go's proxy sent the backend: request line, normalised field lines, body.\n")
	fmt.Fprintf(b, "    up_line: []const u8,\n    up: []const []const u8,\n    up_body: []const u8,\n")
	fmt.Fprintf(b, "    /// What Go's proxy returned to the client: status and normalised field lines.\n    status: u16,\n    down: []const []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// httputil.NewSingleHostReverseProxy between a raw client and a raw backend.\n")
	fmt.Fprintf(b, "pub const rproxy = [_]RProxyCase{\n")
	for _, c := range rpCases {
		current = c
		conn, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			log.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, rpWire(c))
		dh, _, err := rpReadMessage(bufio.NewReader(conn))
		conn.Close()
		if err != nil {
			log.Fatalf("rproxy %s: %v", c.id, err)
		}
		var up seen
		select {
		case up = <-seenCh:
		case <-time.After(5 * time.Second):
			log.Fatalf("rproxy %s: backend saw nothing", c.id)
		}
		upLine, upLines := rpNorm(up.head, rpUpIgnore)
		statusLine, downLines := rpNorm(dh, rpDownIgnore)
		status, _ := strconv.Atoi(strings.Fields(statusLine)[1])
		upLine = strings.TrimSuffix(upLine, " HTTP/1.1")
		var ups, downs []string
		for _, l := range upLines {
			ups = append(ups, zigStr(l))
		}
		for _, l := range downLines {
			downs = append(downs, zigStr(l))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .wire = %s, .resp_extra = %s, .up_line = %s, .up = %s, .up_body = %s, .status = %d, .down = %s },\n",
			zigStr(c.id), zigStr(rpWire(c)), zigStr(c.respExtra), zigStr(upLine), zigList(ups), zigStr(up.body), status, zigList(downs))
	}
	fmt.Fprintf(b, "};\n\n")
}
