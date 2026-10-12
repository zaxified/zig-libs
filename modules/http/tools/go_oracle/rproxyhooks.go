// SPDX-License-Identifier: MIT

// Area rproxy_hooks: httputil.ReverseProxy's hooks -- Rewrite (with SetURL,
// SetXForwarded, edits of Out), ModifyResponse (status, headers, body, an
// error) and ErrorHandler (a hook error, a dead backend) -- each case one
// hook profile, between the same raw client and raw backend as area rproxy.
// The Zig side drives proxy.ProxyHandler with hooks doing the same edits.
//
// Normalisation as in rproxy, except that X-Forwarded-Host/-Proto are
// compared (Rewrite decides them) and the backend's own address in Host is
// written as "backend" (its port differs between the two runs).
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type rhCase struct{ id, profile string }

var rhCases = []rhCase{
	{"rewrite-bare", "rewrite-bare"},
	{"rewrite-xfwd", "rewrite-xfwd"},
	{"rewrite-keep-host", "rewrite-keep-host"},
	{"rewrite-edit", "rewrite-edit"},
	{"modify", "modify"},
	{"modify-body", "modify-body"},
	{"modify-error", "modify-error"},
	{"error-dead", "error-dead"},
	{"dead-default", "dead-default"},
}

// The one request every case sends: forwarding claims of its own, a field a
// hook drops, one it keeps.
const rhWire = "GET /p?q=1 HTTP/1.1\r\nHost: front.example\r\nAccept-Encoding: identity\r\n" +
	"X-Forwarded-For: 10.0.0.1\r\nX-Forwarded-Host: claimed.example\r\nX-Forwarded-Proto: https\r\n" +
	"Forwarded: for=192.0.2.1\r\nX-Drop: 1\r\nX-Keep: 2\r\n\r\n"

// What the live backend answers.
const rhResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nX-Back: 1\r\nX-Keep: 2\r\n\r\nok"

func rhErrorHandler(rw http.ResponseWriter, _ *http.Request, _ error) {
	rw.Header().Set("Content-Type", "text/plain")
	rw.Header().Set("X-Err", "1")
	rw.WriteHeader(418)
	io.WriteString(rw, "handled")
}

func rhProxy(profile string, live, dead *url.URL) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{
		Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true},
		ErrorLog:  log.New(io.Discard, "", 0),
	}
	director := httputil.NewSingleHostReverseProxy(live).Director
	switch profile {
	case "rewrite-bare":
		p.Rewrite = func(r *httputil.ProxyRequest) { r.SetURL(live) }
	case "rewrite-xfwd":
		p.Rewrite = func(r *httputil.ProxyRequest) { r.SetURL(live); r.SetXForwarded() }
	case "rewrite-keep-host":
		p.Rewrite = func(r *httputil.ProxyRequest) { r.SetURL(live); r.Out.Host = r.In.Host; r.SetXForwarded() }
	case "rewrite-edit":
		p.Rewrite = func(r *httputil.ProxyRequest) {
			r.SetURL(live)
			r.Out.URL.Path = "/rewritten"
			r.Out.URL.RawQuery = "x=1"
			r.Out.Header.Set("X-Added", "1")
			r.Out.Header.Del("X-Drop")
		}
	case "modify":
		p.Director = director
		p.ModifyResponse = func(res *http.Response) error {
			res.StatusCode = 201
			res.Header.Set("X-Mod", "1")
			res.Header.Del("X-Back")
			return nil
		}
	case "modify-body":
		p.Director = director
		p.ModifyResponse = func(res *http.Response) error {
			res.Body = io.NopCloser(strings.NewReader("replaced"))
			res.ContentLength = 8
			res.Header.Set("Content-Length", "8")
			return nil
		}
	case "modify-error":
		p.Director = director
		p.ModifyResponse = func(*http.Response) error { return errors.New("refused") }
		p.ErrorHandler = rhErrorHandler
	case "error-dead":
		p.Director = httputil.NewSingleHostReverseProxy(dead).Director
		p.ErrorHandler = rhErrorHandler
	case "dead-default":
		p.Director = httputil.NewSingleHostReverseProxy(dead).Director
	default:
		log.Fatalf("rproxy_hooks: unknown profile %q", profile)
	}
	return p
}

func emitRProxyHooks(b *bytes.Buffer) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()
	type seen struct{ head, body string }
	seenCh := make(chan seen, 1)
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			h, body, err := rpReadMessage(bufio.NewReader(conn))
			if err == nil {
				seenCh <- seen{h, body}
				io.WriteString(conn, rhResponse)
			}
			conn.Close()
		}
	}()
	// A port nothing listens on: bind, note it, close.
	deadL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	deadAddr := deadL.Addr().String()
	deadL.Close()

	live, _ := url.Parse("http://" + backend.Addr().String())
	dead, _ := url.Parse("http://" + deadAddr)
	var current *httputil.ReverseProxy
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Handler:  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.ServeHTTP(w, r) }),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go srv.Serve(front)
	defer srv.Close()

	upIgnore := map[string]bool{"connection": true, "content-length": true, "transfer-encoding": true, "via": true, "user-agent": true}
	fmt.Fprintf(b, "pub const RProxyHookCase = struct {\n    id: []const u8,\n    /// The hook profile (see `rproxy_hooks` in go_oracle.zig).\n    profile: []const u8,\n")
	fmt.Fprintf(b, "    /// What Go's proxy sent the backend; `up_line` empty when no request reached it.\n    up_line: []const u8,\n    up: []const []const u8,\n")
	fmt.Fprintf(b, "    /// What Go's proxy returned to the client.\n    status: u16,\n    down: []const []const u8,\n    down_body: []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// The request every rproxy_hooks case sends.\npub const rproxy_hooks_wire = %s;\n\n", zigStr(rhWire))
	fmt.Fprintf(b, "/// What the live backend answers.\npub const rproxy_hooks_response = %s;\n\n", zigStr(rhResponse))
	fmt.Fprintf(b, "/// httputil.ReverseProxy with Rewrite / ModifyResponse / ErrorHandler.\npub const rproxy_hooks = [_]RProxyHookCase{\n")
	for _, c := range rhCases {
		current = rhProxy(c.profile, live, dead)
		conn, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			log.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, rhWire)
		dh, dbody, err := rpReadMessage(bufio.NewReader(conn))
		conn.Close()
		if err != nil {
			log.Fatalf("rproxy_hooks %s: %v", c.id, err)
		}
		var up seen
		select {
		case up = <-seenCh:
		case <-time.After(300 * time.Millisecond): // the dead-backend cases reach nothing
		}
		var upLine string
		var ups []string
		if up.head != "" {
			l, lines := rpNorm(strings.ReplaceAll(up.head, backend.Addr().String(), "backend"), upIgnore)
			upLine = strings.TrimSuffix(l, " HTTP/1.1")
			for _, x := range lines {
				ups = append(ups, zigStr(x))
			}
		}
		statusLine, downLines := rpNorm(dh, rpDownIgnore)
		status, _ := strconv.Atoi(strings.Fields(statusLine)[1])
		var downs []string
		for _, x := range downLines {
			downs = append(downs, zigStr(x))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .profile = %s, .up_line = %s, .up = %s, .status = %d, .down = %s, .down_body = %s },\n",
			zigStr(c.id), zigStr(c.profile), zigStr(upLine), zigList(ups), status, zigList(downs), zigStr(dbody))
	}
	fmt.Fprintf(b, "};\n\n")
}
