// SPDX-License-Identifier: MIT

// Mode -h2tls PORTFILE: a live peer for the interop lane's ALPN phase
// (tools/interop.zig), not part of the generated vectors. Two TLS listeners
// on loopback, each with a fresh self-signed certificate: "h2" offers h2 and
// http/1.1 by ALPN, "h1" offers neither (HTTP/1.1). Both answer:
//
//	/fields    the request as net/http's server saw it: proto, method, host,
//	           then every header field "name: value", sorted
//	/trailers  a body, then a trailer X-Checksum
//	/gz        a gzip-encoded body
//	/redirect  302 to /fields
//	/echo      the request body
//	/go        Go's own Transport (the listener's certificate trusted, h2
//	           attempted) sends the same GET /fields to this listener and
//	           answers with what it got back -- Go's request beside ours.
//
// Writes "h2=<port> h1=<port>\n" to PORTFILE once both listen, and serves
// until stdin reaches EOF (the lane closes it), so `go run` leaves no child.
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
)

// h2tlsGzipPlain is what /gz decodes to.
const h2tlsGzipPlain = "gzip over h2, decoded by the client\n"

func h2tlsHandler(self **httptest.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/fields", func(w http.ResponseWriter, r *http.Request) {
		var lines []string
		for name, values := range r.Header {
			for _, v := range values {
				lines = append(lines, strings.ToLower(name)+": "+v)
			}
		}
		sort.Strings(lines)
		fmt.Fprintf(w, "proto: %s\nmethod: %s\nhost: %s\n%s\n", r.Proto, r.Method, r.Host, strings.Join(lines, "\n"))
	})
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		io.WriteString(w, "body before trailers")
		w.Header().Set("X-Checksum", "c0ffee")
	})
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		io.WriteString(zw, h2tlsGzipPlain)
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(b.Bytes())
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fields", http.StatusFound)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		s := *self
		req, _ := http.NewRequest("GET", s.URL+"/fields", nil)
		req.Header.Set("X-Custom", "v")
		res, err := s.Client().Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		io.Copy(w, res.Body)
	})
	return mux
}

func h2tlsMain(portFile string) {
	var h2, h1 *httptest.Server
	h2 = httptest.NewUnstartedServer(h2tlsHandler(&h2))
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()
	h1 = httptest.NewUnstartedServer(h2tlsHandler(&h1))
	h1.StartTLS()
	defer h1.Close()
	port := func(s *httptest.Server) string { return s.URL[strings.LastIndexByte(s.URL, ':')+1:] }
	if err := os.WriteFile(portFile, []byte("h2="+port(h2)+" h1="+port(h1)+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
	io.Copy(io.Discard, os.Stdin)
}
