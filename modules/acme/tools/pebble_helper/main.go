// SPDX-License-Identifier: MIT

// Helpers for tools/pebble.sh, the acme module's Pebble anchor. Standard
// library only.
//
//	pebble_helper serve -scratch DIR
//	    a recording TLS reverse proxy on 127.0.0.1:14001 in front of Pebble
//	    (127.0.0.1:14000): every exchange goes to DIR/transcript.jsonl, and
//	    GET /__scenario/<name> marks where a scenario starts (not forwarded);
//	    and the TLS-ALPN-01 listener on 127.0.0.1:5001 (ALPN acme-tls/1),
//	    which serves the validation certificate the acme client publishes --
//	    fetched per handshake from tools/interop.zig's material endpoint
//	    (http://127.0.0.1:5003/alpn/<sni>: cert DER, then the key PEM).
//	pebble_helper gen DIR/transcript.jsonl OUT.zig
//	    the transcript as Zig, for src/pebble_replay_test.zig.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Exchange struct {
	Scenario string              `json:"scenario"`
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     string              `json:"body"`
}

var keptHeaders = []string{"Content-Type", "Location", "Replay-Nonce", "Retry-After", "Link"}

func serve(scratch string) error {
	certFile := filepath.Join(scratch, "localhost.pem")
	keyFile := filepath.Join(scratch, "localhost.key")
	caPEM, err := os.ReadFile(filepath.Join(scratch, "ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	log, err := os.Create(filepath.Join(scratch, "transcript.jsonl"))
	if err != nil {
		return err
	}
	var mu sync.Mutex
	scenario := ""
	enc := json.NewEncoder(log)

	up, _ := url.Parse("https://127.0.0.1:14000")
	rp := httputil.NewSingleHostReverseProxy(up)
	rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}
	director := rp.Director
	rp.Director = func(r *http.Request) {
		host := r.Host
		director(r)
		r.Host = host // Pebble builds its URLs from Host: keep the client pointed at the proxy
	}
	rp.ModifyResponse = func(res *http.Response) error {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		res.Body = io.NopCloser(bytes.NewReader(body))
		h := map[string][]string{}
		for _, k := range keptHeaders {
			if v := res.Header.Values(k); len(v) > 0 {
				h[k] = v
			}
		}
		mu.Lock()
		defer mu.Unlock()
		return enc.Encode(Exchange{Scenario: scenario, Method: res.Request.Method, Path: res.Request.URL.RequestURI(),
			Status: res.StatusCode, Headers: h, Body: string(body)})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/__scenario/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		scenario = strings.TrimPrefix(r.URL.Path, "/__scenario/")
		mu.Unlock()
		w.WriteHeader(204)
	})
	mux.Handle("/", rp)
	errc := make(chan error, 2)
	go func() { errc <- http.ListenAndServeTLS("127.0.0.1:14001", certFile, keyFile, mux) }()

	alpn := &tls.Config{
		NextProtos: []string{"acme-tls/1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				res, err := http.Get("http://127.0.0.1:5003/alpn/" + hello.ServerName)
				if err == nil && res.StatusCode == 200 {
					b, _ := io.ReadAll(res.Body)
					res.Body.Close()
					der, keyPEM, ok := bytes.Cut(b, []byte("\n--KEY--\n"))
					if !ok {
						return nil, errors.New("material: no key separator")
					}
					blk, _ := pem.Decode(keyPEM)
					if blk == nil {
						return nil, errors.New("material: key is not PEM")
					}
					key, err := x509.ParseECPrivateKey(blk.Bytes)
					if err != nil {
						return nil, err
					}
					return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
				}
				if res != nil {
					res.Body.Close()
				}
				time.Sleep(20 * time.Millisecond)
			}
			return nil, fmt.Errorf("no TLS-ALPN-01 material for %q", hello.ServerName)
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:5001", alpn)
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake() // the validator only needs the handshake
			}()
		}
	}()
	return <-errc
}

func zstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func gen(in, out string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/acme/tools/pebble.sh (Pebble %s, %s) -- do not hand-edit.\n", os.Getenv("PEBBLE_VERSION"), runtime.Version())
	b.WriteString("//! What Pebble answered the acme client, per scenario, replayed by `pebble_replay_test.zig`.\n")
	b.WriteString("//! URLs inside bodies and headers point at `origin`; the replay rewrites them to its own.\n\n")
	b.WriteString("pub const origin = \"https://localhost:14001\";\n\n")
	b.WriteString("pub const Header = struct { name: []const u8, value: []const u8 };\n")
	b.WriteString("pub const Exchange = struct { scenario: []const u8, method: []const u8, path: []const u8, status: u16, headers: []const Header, body: []const u8 };\n\n")
	b.WriteString("pub const exchanges = [_]Exchange{\n")
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e Exchange
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return err
		}
		if e.Scenario == "" {
			continue
		}
		var hs []string
		names := make([]string, 0, len(e.Headers))
		for k := range e.Headers {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			for _, v := range e.Headers[k] {
				hs = append(hs, fmt.Sprintf(".{ .name = %s, .value = %s }", zstr(k), zstr(v)))
			}
		}
		fmt.Fprintf(&b, "    .{ .scenario = %s, .method = %s, .path = %s, .status = %d, .headers = &.{ %s }, .body = %s },\n",
			zstr(e.Scenario), zstr(e.Method), zstr(e.Path), e.Status, strings.Join(hs, ", "), zstr(e.Body))
	}
	if err := sc.Err(); err != nil {
		return err
	}
	b.WriteString("};\n")
	return os.WriteFile(out, []byte(b.String()), 0o644)
}

func main() {
	var err error
	switch {
	case len(os.Args) == 4 && os.Args[1] == "serve" && os.Args[2] == "-scratch":
		err = serve(os.Args[3])
	case len(os.Args) == 4 && os.Args[1] == "gen":
		err = gen(os.Args[2], os.Args[3])
	default:
		fmt.Fprintln(os.Stderr, "usage: pebble_helper serve -scratch DIR | gen TRANSCRIPT OUT.zig")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pebble_helper:", err)
		os.Exit(1)
	}
}
