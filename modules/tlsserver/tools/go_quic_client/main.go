// SPDX-License-Identifier: MIT

// The Go crypto/tls QUIC client (RFC 9001, tls.QUICClient) for
// `tools/interop.zig`'s QUIC cases. There is no QUIC transport: the
// handshake data the TLS stack hands over goes to the server over TCP in
// frames of one level octet (0 Initial, 1 Early, 2 Handshake,
// 3 Application), a 4-octet big-endian length and the data, and the
// server's come back the same way. The client verifies the server's
// certificate against -ca for -servername and reports, one "key: value"
// per line on stdout:
//
//	secret: <read|write> <level> <suite hex> <secret hex>   (each key the stack installs)
//	peer_tp: <hex>    the server's transport parameters
//	alpn, resumed, done
//
// A frame of level 0xff from the server ends the exchange.
//
// The interop program checks the secrets against the server's own (the
// client's write secret at a level is the server's read secret there).
//
//	go build -o go-quic-client tools/go_quic_client/main.go
//	go-quic-client -addr 127.0.0.1:4433 -ca p256.pem -servername localhost \
//	    -tp HEX [-alpn h3] [-groups X25519,P-256] [-sess-out FILE] [-sess-in FILE] [-early]
//	    [-cert FILE -key FILE]
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

var groupNames = map[string]tls.CurveID{
	"X25519MLKEM768": tls.X25519MLKEM768,
	"X25519":         tls.X25519,
	"P-256":          tls.CurveP256,
	"P-384":          tls.CurveP384,
}

var levelNames = map[tls.QUICEncryptionLevel]string{
	tls.QUICEncryptionLevelInitial:     "initial",
	tls.QUICEncryptionLevelEarly:       "early",
	tls.QUICEncryptionLevelHandshake:   "handshake",
	tls.QUICEncryptionLevelApplication: "application",
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "go-quic-client: "+format+"\n", a...)
	os.Exit(1)
}

// fileCache holds at most one session: the one loaded from -sess-in, and
// the last one the server issued, written to -sess-out.
type fileCache struct {
	in  *tls.ClientSessionState
	out string
}

func (c *fileCache) Get(string) (*tls.ClientSessionState, bool) { return c.in, c.in != nil }

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
		fail("session bytes: %v", err)
	}
	var out []byte
	out = binary.BigEndian.AppendUint32(out, uint32(len(ticket)))
	out = append(out, ticket...)
	out = append(out, b...)
	if err := os.WriteFile(c.out, out, 0o600); err != nil {
		fail("write %s: %v", c.out, err)
	}
	fmt.Println("saved: true")
}

func loadSession(path string) *tls.ClientSessionState {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	if len(b) < 4 || int(binary.BigEndian.Uint32(b)) > len(b)-4 {
		fail("%s: malformed", path)
	}
	n := binary.BigEndian.Uint32(b)
	state, err := tls.ParseSessionState(b[4+n:])
	if err != nil {
		fail("parse session: %v", err)
	}
	cs, err := tls.NewResumptionState(b[4:4+n], state)
	if err != nil {
		fail("resumption state: %v", err)
	}
	return cs
}

func writeFrame(w *bufio.Writer, level tls.QUICEncryptionLevel, data []byte) {
	var h [5]byte
	h[0] = byte(level)
	binary.BigEndian.PutUint32(h[1:], uint32(len(data)))
	if _, err := w.Write(h[:]); err != nil {
		fail("write: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		fail("write: %v", err)
	}
}

func main() {
	addr := flag.String("addr", "", "server address")
	caFile := flag.String("ca", "", "PEM trust anchor")
	serverName := flag.String("servername", "localhost", "SNI and verified name")
	tpHex := flag.String("tp", "", "this client's transport parameters (hex)")
	alpn := flag.String("alpn", "h3", "ALPN protocols, comma-separated")
	groups := flag.String("groups", "", "key-exchange groups, comma-separated")
	sessOut := flag.String("sess-out", "", "write the server's last ticket here")
	sessIn := flag.String("sess-in", "", "offer the session in this file")
	early := flag.Bool("early", false, "offer 0-RTT on a resumption")
	certFile := flag.String("cert", "", "client certificate (PEM), for a server that asks")
	keyFile := flag.String("key", "", "its private key (PEM)")
	flag.Parse()

	pem, err := os.ReadFile(*caFile)
	if err != nil {
		fail("read %s: %v", *caFile, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fail("%s: no certificate", *caFile)
	}
	tp, err := hex.DecodeString(*tpHex)
	if err != nil {
		fail("-tp: %v", err)
	}
	cache := &fileCache{out: *sessOut}
	if *sessIn != "" {
		cache.in = loadSession(*sessIn)
	}
	conf := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		RootCAs:            roots,
		ServerName:         *serverName,
		NextProtos:         strings.Split(*alpn, ","),
		ClientSessionCache: cache,
	}
	if *certFile != "" {
		pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fail("client certificate: %v", err)
		}
		conf.Certificates = []tls.Certificate{pair}
	}
	if *groups != "" {
		for _, g := range strings.Split(*groups, ",") {
			id, ok := groupNames[g]
			if !ok {
				fail("unknown group %s", g)
			}
			conf.CurvePreferences = append(conf.CurvePreferences, id)
		}
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		fail("dial: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: conf, EnableSessionEvents: true})
	q.SetTransportParameters(tp)
	if err := q.Start(context.Background()); err != nil {
		fail("start: %v", err)
	}
	done := false
	for {
		ev := q.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			if err := w.Flush(); err != nil {
				fail("flush: %v", err)
			}
			var h [5]byte
			if _, err := io.ReadFull(r, h[:]); err != nil {
				if done && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
					fmt.Println("done: true")
					return
				}
				fail("read: %v", err)
			}
			if h[0] == 0xff {
				// The server is done (after its tickets).
				if !done {
					fail("server ended before the handshake did")
				}
				fmt.Println("done: true")
				return
			}
			data := make([]byte, binary.BigEndian.Uint32(h[1:]))
			if _, err := io.ReadFull(r, data); err != nil {
				fail("read: %v", err)
			}
			if err := q.HandleData(tls.QUICEncryptionLevel(h[0]), data); err != nil {
				fail("handle data at level %d: %v", h[0], err)
			}
		case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
			dir := "read"
			if ev.Kind == tls.QUICSetWriteSecret {
				dir = "write"
			}
			fmt.Printf("secret: %s %s %04x %x\n", dir, levelNames[ev.Level], ev.Suite, ev.Data)
		case tls.QUICWriteData:
			writeFrame(w, ev.Level, ev.Data)
		case tls.QUICTransportParameters:
			fmt.Printf("peer_tp: %x\n", ev.Data)
		case tls.QUICTransportParametersRequired:
			q.SetTransportParameters(tp)
		case tls.QUICHandshakeDone:
			cs := q.ConnectionState()
			fmt.Printf("alpn: %s\nresumed: %v\nearly: %v\n", cs.NegotiatedProtocol, cs.DidResume, *early)
			done = true
		case tls.QUICResumeSession:
			// Go offers 0-RTT whenever the ticket allows it: only with -early.
			if ev.SessionState != nil {
				ev.SessionState.EarlyData = ev.SessionState.EarlyData && *early
			}
		case tls.QUICStoreSession:
			if err := q.StoreSession(ev.SessionState); err != nil {
				fail("store session: %v", err)
			}
		case tls.QUICRejectedEarlyData:
			fmt.Println("early_rejected: true")
		}
	}
}
