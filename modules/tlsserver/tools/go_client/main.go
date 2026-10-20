// SPDX-License-Identifier: MIT

// The Go crypto/tls client for `tools/interop.zig`: connect, verify the
// server's certificate against -ca for -servername, report the session,
// send "ping\n", read to EOF (the server answers "pong\n" and closes) and
// exit 0 only if "pong" arrived and the server closed with close_notify.
//
//	go build -o go-client tools/go_client/main.go
//	go-client -addr 127.0.0.1:4433 -ca p256.pem -servername localhost \
//	    [-groups X25519MLKEM768,X25519] [-alpn h2,http/1.1] [-nosni]
//
// The report, one "key: value" per line on stdout, names what the
// interop case expects: version, suite, group, alpn, peer_certs.
package main

import (
	"crypto/tls"
	"crypto/x509"
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
}
