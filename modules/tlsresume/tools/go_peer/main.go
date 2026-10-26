// SPDX-License-Identifier: MIT

// The Go crypto/tls peer of `tools/interop.zig`: a client (TLS 1.3, or 1.2
// with -tls12) or, with -serve12, a TLS 1.2 server, both recording every
// octet they exchange so the interop program can read the plaintext
// handshake messages.
//
//	go build -o go-peer tools/go_peer/main.go
//	go-peer -addr 127.0.0.1:4433 -ca p256.pem [-servername localhost]
//	    [-tls12] [-sess-out FILE] [-sess-in FILE] [-record FILE]
//	    [-send TEXT] [-expect TEXT]
//	go-peer -serve12 -cert FILE -key FILE [-n 2]
//
// Client: verify the server for -servername against -ca, report the session
// ("key: value" lines: version, suite, resumed, and saved with -sess-out),
// send -send (default "ping\n"), read to EOF and exit 0 only if -expect
// (default "pong") arrived. -sess-out writes the last session the server
// issued, -sess-in offers the one in FILE (ResumptionState /
// NewResumptionState; TLS 1.2 tickets as well as 1.3). -record FILE writes
// the raw connection as chunks: one direction octet ('c' client to server,
// 's' server to client), a big-endian u32 length, the octets.
//
// Server (-serve12): TLS 1.2 only, session tickets on (Go's default, its own
// ticket keys), prints "listening: HOST:PORT", serves -n connections one
// after another: read up to "ping\n", answer "pong\n", close_notify.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type fileCache struct {
	in    *tls.ClientSessionState
	out   string
	saved bool
}

func (c *fileCache) Get(string) (*tls.ClientSessionState, bool) {
	return c.in, c.in != nil
}

func (c *fileCache) Put(_ string, cs *tls.ClientSessionState) {
	if c.out == "" || cs == nil {
		return
	}
	ticket, state, err := cs.ResumptionState()
	if err != nil || state == nil {
		fail("session: %v", err)
	}
	b, err := state.Bytes()
	if err != nil {
		fail("session: %v", err)
	}
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(ticket)))
	buf = append(append(buf, ticket...), b...)
	if err := os.WriteFile(c.out, buf, 0o600); err != nil {
		fail("%v", err)
	}
	c.saved = true
}

func loadSession(path string) *tls.ClientSessionState {
	buf, err := os.ReadFile(path)
	if err != nil {
		fail("%v", err)
	}
	if len(buf) < 4 || uint32(len(buf)-4) < binary.BigEndian.Uint32(buf) {
		fail("%s: truncated", path)
	}
	n := binary.BigEndian.Uint32(buf)
	state, err := tls.ParseSessionState(buf[4+n:])
	if err != nil {
		fail("%s: %v", path, err)
	}
	cs, err := tls.NewResumptionState(buf[4:4+n], state)
	if err != nil {
		fail("%s: %v", path, err)
	}
	return cs
}

// recorder is a net.Conn that keeps every octet read and written, in order.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	log []byte
}

func (r *recorder) add(dir byte, p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, dir)
	r.log = binary.BigEndian.AppendUint32(r.log, uint32(len(p)))
	r.log = append(r.log, p...)
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.add('s', p[:n])
	}
	return n, err
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	if n > 0 {
		r.add('c', p[:n])
	}
	return n, err
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "go-peer: "+format+"\n", a...)
	os.Exit(1)
}

func serve12(certFile, keyFile string, n int) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fail("server certificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		fail("listen: %v", err)
	}
	defer ln.Close()
	fmt.Printf("listening: %s\n", ln.Addr())
	os.Stdout.Sync()
	for i := 0; i < n; i++ {
		c, err := ln.Accept()
		if err != nil {
			fail("accept: %v", err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || line != "ping\n" {
			fail("connection %d: read %q: %v", i, line, err)
		}
		if _, err := c.Write([]byte("pong\n")); err != nil {
			fail("connection %d: write: %v", i, err)
		}
		c.Close()
	}
}

func main() {
	addr := flag.String("addr", "", "host:port")
	caFile := flag.String("ca", "", "PEM file of trusted certificates")
	serverName := flag.String("servername", "localhost", "name to verify (and send as SNI)")
	tls12 := flag.Bool("tls12", false, "TLS 1.2 only")
	sessOut := flag.String("sess-out", "", "write the server's last session here")
	sessIn := flag.String("sess-in", "", "offer the session in this file")
	record := flag.String("record", "", "write the raw connection here")
	send := flag.String("send", "ping\n", "what to send once connected")
	expect := flag.String("expect", "pong", "what the answer must contain")
	server := flag.Bool("serve12", false, "be a TLS 1.2 server instead")
	certFile := flag.String("cert", "", "server certificate (PEM), with -serve12")
	keyFile := flag.String("key", "", "the server certificate's private key (PEM)")
	count := flag.Int("n", 2, "connections to serve, with -serve12")
	flag.Parse()

	if *server {
		serve12(*certFile, *keyFile, *count)
		return
	}
	pem, err := os.ReadFile(*caFile)
	if err != nil {
		fail("%v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fail("no certificate in %s", *caFile)
	}
	cfg := &tls.Config{
		RootCAs:    roots,
		ServerName: *serverName,
		MinVersion: tls.VersionTLS13,
	}
	if *tls12 {
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
	}
	cache := &fileCache{out: *sessOut}
	if *sessIn != "" {
		cache.in = loadSession(*sessIn)
	}
	if *sessIn != "" || *sessOut != "" {
		cfg.ClientSessionCache = cache
	}

	raw, err := net.DialTimeout("tcp", *addr, 10*time.Second)
	if err != nil {
		fail("dial: %v", err)
	}
	rec := &recorder{Conn: raw}
	defer func() {
		if *record != "" {
			if err := os.WriteFile(*record, rec.log, 0o600); err != nil {
				fail("%v", err)
			}
		}
	}()
	conn := tls.Client(rec, cfg)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		fail("handshake: %v", err)
	}
	cs := conn.ConnectionState()
	fmt.Printf("version: %s\n", tls.VersionName(cs.Version))
	fmt.Printf("suite: %s\n", tls.CipherSuiteName(cs.CipherSuite))
	fmt.Printf("resumed: %v\n", cs.DidResume)
	if _, err := conn.Write([]byte(*send)); err != nil {
		fail("write: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil && len(got) == 0 {
		fail("read: %v", err)
	}
	if !strings.Contains(string(got), *expect) {
		fail("no %q in %q", *expect, got)
	}
	fmt.Printf("received: %s\n", strings.TrimSpace(string(got)))
	conn.Close()
	if *sessOut != "" {
		fmt.Printf("saved: %v\n", cache.saved)
	}
}
