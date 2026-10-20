// SPDX-License-Identifier: MIT

// The Go crypto/tls client for `tools/interop.zig`: connect, verify the
// server's certificate against -ca for -servername, report the session,
// send "ping\n", read to EOF (the server answers "pong\n" and closes) and
// exit 0 only if "pong" arrived and the server closed with close_notify.
//
//	go build -o go-client tools/go_client/main.go
//	go-client -addr 127.0.0.1:4433 -ca p256.pem -servername localhost \
//	    [-groups X25519MLKEM768,X25519] [-alpn h2,http/1.1] [-nosni]
//	    [-sess-out FILE] [-sess-in FILE]
//
// The report, one "key: value" per line on stdout, names what the
// interop case expects: version, suite, group, alpn, peer_certs, hrr,
// resumed, and (with -sess-out) saved. -sess-out writes the last session
// ticket the server sent to FILE; -sess-in offers the one in FILE (Go's
// ClientSessionState serialization, ResumptionState / NewResumptionState).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

var groupNames = map[string]tls.CurveID{
	"X25519MLKEM768": tls.X25519MLKEM768,
	"X25519":         tls.X25519,
	"P-256":          tls.CurveP256,
	"P-384":          tls.CurveP384,
	"P-521":          tls.CurveP521,
}

// fileCache holds at most one session: the one loaded from -sess-in, and
// the last one the server issued, written to -sess-out.
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

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "go-client: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	addr := flag.String("addr", "", "host:port")
	caFile := flag.String("ca", "", "PEM file of trusted certificates")
	serverName := flag.String("servername", "localhost", "name to verify (and send as SNI)")
	noSNI := flag.Bool("nosni", false, "send no server_name; verify -servername anyway")
	groups := flag.String("groups", "", "comma-separated curve preferences (Go's default if empty)")
	alpn := flag.String("alpn", "", "comma-separated ALPN offers")
	sessOut := flag.String("sess-out", "", "write the server's last session ticket here")
	sessIn := flag.String("sess-in", "", "offer the session ticket in this file")
	flag.Parse()

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
	if *noSNI {
		// Go sends SNI from ServerName; to send none, verify by hand.
		cfg.ServerName = ""
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			opts := x509.VerifyOptions{Roots: roots, DNSName: *serverName, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	if *groups != "" {
		for _, g := range strings.Split(*groups, ",") {
			id, ok := groupNames[g]
			if !ok {
				fail("unknown group %q", g)
			}
			cfg.CurvePreferences = append(cfg.CurvePreferences, id)
		}
	}
	if *alpn != "" {
		cfg.NextProtos = strings.Split(*alpn, ",")
	}
	cache := &fileCache{out: *sessOut}
	if *sessIn != "" {
		cache.in = loadSession(*sessIn)
	}
	if *sessIn != "" || *sessOut != "" {
		cfg.ClientSessionCache = cache
	}

	conn, err := tls.Dial("tcp", *addr, cfg)
	if err != nil {
		fail("handshake: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	cs := conn.ConnectionState()
	fmt.Printf("version: %s\n", tls.VersionName(cs.Version))
	fmt.Printf("suite: %s\n", tls.CipherSuiteName(cs.CipherSuite))
	fmt.Printf("group: %s\n", cs.CurveID)
	fmt.Printf("alpn: %s\n", cs.NegotiatedProtocol)
	fmt.Printf("peer_certs: %d\n", len(cs.PeerCertificates))
	fmt.Printf("hrr: %v\n", cs.HelloRetryRequest)
	fmt.Printf("resumed: %v\n", cs.DidResume)

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		fail("write: %v", err)
	}
	// io.ReadAll returns nil only on a clean close (close_notify); a TCP
	// close without one is an error here.
	got, err := io.ReadAll(conn)
	if err != nil {
		fail("read: %v (got %q)", err, got)
	}
	if !strings.Contains(string(got), "pong") {
		fail("no pong: %q", got)
	}
	fmt.Printf("received: %s", got)
	if *sessOut != "" {
		fmt.Printf("saved: %v\n", cache.saved)
	}
}
