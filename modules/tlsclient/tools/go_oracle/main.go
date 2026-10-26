// SPDX-License-Identifier: MIT

// Go side of `zig build interop-tlsclient` (modules/tlsclient/tools/interop.zig):
// Go's standard-library crypto/tls (the module's scope reference; stdlib only)
// as the SERVER of every case and as the REFERENCE CLIENT that judges it.
//
//	go_oracle <dir>
//
// builds a PKI (ECDSA P-256 root and intermediates; leaves of every key type
// the client verifies; the broken chains), opens one loopback listener per
// case, runs Go's client against each one first and records what it saw, writes
// <dir>/cases.tsv (one row per case, columns in `header` below) and the
// files the rows name (trust anchors as <root>.der + <root>.pem; client
// certificates as DER, their keys raw: the ECDSA scalar, the Ed25519 seed, a
// PKCS#1 RSAPrivateKey), prints READY, and serves until killed.
//
// On every handshake the server writes one line to its client before
// anything else, what IT saw of the connection:
//
//	v=<version> cs=<suite> g=<group> hrr=<0|1> alpn=<proto|-> res=<0|1> peer=<n> sn=<sni|-> ekm=<hex>
//
// (hex code points, `peer` = client certificates verified, `ekm` = 32 octets
// of ExportKeyingMaterial("EXPERIMENTAL-zl-interop", nil)), then `bulk` octets
// of the pattern i*31+7 (mod 256) when the case asks for them, then
// close_notify. A client's verdict is "ok" when the handshake succeeds AND
// that line arrives; the line is compared between the two clients, and with
// the client's own view of the connection.
package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	host       = "srv.interop.test"
	ekmLabel   = "EXPERIMENTAL-zl-interop"
	header     = "id\tfamily\texpect\tport\thost\tmin\tmax\tgroups\tshares\talpn\tccert\troot\ttwice\tbulk\tstaple\tscts\tgo\tgo_line\twhy"
	pattern    = 31
	bulkMiB    = 1 << 20
	tls12      = tls.VersionTLS12
	tls13      = tls.VersionTLS13
	clientRoot = "client_root"
)

var dir string

func die(err error) {
	fmt.Fprintln(os.Stderr, "go_oracle:", err)
	os.Exit(1)
}

// ── PKI ──────────────────────────────────────────────────────────────────

var serial int64

type node struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(kind string) crypto.Signer {
	var k crypto.Signer
	var err error
	switch kind {
	case "p256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa2048":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		k, err = rsa.GenerateKey(rand.Reader, 3072)
	case "rsa4096":
		k, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = fmt.Errorf("key kind %s", kind)
	}
	if err != nil {
		die(err)
	}
	return k
}

func issue(tmpl *x509.Certificate, parent *node, key crypto.Signer) *node {
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		die(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		die(err)
	}
	return &node{der: der, cert: c, key: key}
}

var now = time.Now()

func caTmpl(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTmpl(names ...string) *x509.Certificate {
	t := &x509.Certificate{
		Subject: pkix.Name{CommonName: "interop leaf"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			t.IPAddresses = append(t.IPAddresses, ip)
		} else {
			t.DNSNames = append(t.DNSNames, n)
		}
	}
	return t
}

// writeRoot writes a trust anchor as <name>.der and <name>.pem.
func writeRoot(name string, der []byte) {
	write(name+".der", der)
	write(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func write(name string, b []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		die(err)
	}
}

// rawExt wraps DER `value` as an extension the template cannot express.
func rawExt(oid asn1.ObjectIdentifier, critical bool, value []byte) pkix.Extension {
	return pkix.Extension{Id: oid, Critical: critical, Value: value}
}

func tlv(tag byte, body []byte) []byte {
	n := len(body)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

// ── cases ────────────────────────────────────────────────────────────────

type ccase struct {
	id, family, expect, why string
	server                  *tls.Config
	host                    string
	min, max                uint16
	groups, shares          []tls.CurveID // client restriction (both clients); nil = defaults
	alpn                    []string
	ccert                   string // client certificate kind, "" none
	root                    string // trust anchor file for both clients
	twice                   bool   // connect twice with a session cache, the second line is judged
	bulk                    int
	staple                  string
	scts                    []string
	// filled in
	port            int
	goVerdict, line string
}

var clientCerts = map[string]tls.Certificate{}

func serverCert(chain []*node) tls.Certificate {
	c := tls.Certificate{PrivateKey: chain[0].key}
	for _, n := range chain {
		c.Certificate = append(c.Certificate, n.der)
	}
	return c
}

func serve(c *ccase) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		die(err)
	}
	c.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go answer(conn, c)
		}
	}()
}

func answer(conn net.Conn, c *ccase) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	tc := tls.Server(conn, c.server)
	if err := tc.Handshake(); err != nil {
		return
	}
	st := tc.ConnectionState()
	ekm, err := st.ExportKeyingMaterial(ekmLabel, nil, 32)
	ekmHex := "-"
	if err == nil {
		ekmHex = hex.EncodeToString(ekm)
	}
	b2i := map[bool]int{false: 0, true: 1}
	orDash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	peer := 0
	if len(st.VerifiedChains) > 0 {
		peer = len(st.PeerCertificates)
	}
	line := fmt.Sprintf("v=%04x cs=%04x g=%04x hrr=%d alpn=%s res=%d peer=%d sn=%s ekm=%s\n",
		st.Version, st.CipherSuite, uint16(st.CurveID), b2i[st.HelloRetryRequest], orDash(st.NegotiatedProtocol),
		b2i[st.DidResume], peer, orDash(st.ServerName), ekmHex)
	if _, err := io.WriteString(tc, line); err != nil {
		return
	}
	if c.bulk > 0 {
		buf := make([]byte, c.bulk)
		for i := range buf {
			buf[i] = byte(i*pattern + 7)
		}
		if _, err := tc.Write(buf); err != nil {
			return
		}
	}
	_ = tc.Close()
}

// goClient is the reference verdict: Go's client with the options the row
// gives our client.
func goClient(c *ccase, roots *x509.CertPool) (string, string) {
	cache := tls.NewLRUClientSessionCache(4)
	cfg := &tls.Config{RootCAs: roots, ServerName: c.host, MinVersion: c.min, MaxVersion: c.max, NextProtos: c.alpn}
	if c.groups != nil {
		cfg.CurvePreferences = c.groups
	}
	if c.ccert != "" {
		cfg.Certificates = []tls.Certificate{clientCerts[c.ccert]}
	}
	if c.twice {
		cfg.ClientSessionCache = cache
	}
	n := 1
	if c.twice {
		n = 2
	}
	var line string
	for i := 0; i < n; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", c.port), 10*time.Second)
		if err != nil {
			die(err)
		}
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		tc := tls.Client(conn, cfg)
		r := bufio.NewReader(tc)
		l, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			return "err", sanitize(err.Error())
		}
		if c.bulk > 0 {
			buf := make([]byte, c.bulk)
			if _, err := io.ReadFull(r, buf); err != nil {
				conn.Close()
				return "err", sanitize("bulk: " + err.Error())
			}
			for j := range buf {
				if buf[j] != byte(j*pattern+7) {
					conn.Close()
					return "err", "bulk: pattern"
				}
			}
		}
		st := tc.ConnectionState()
		ekm, _ := st.ExportKeyingMaterial(ekmLabel, nil, 32)
		line = strings.TrimSpace(l)
		if !strings.HasSuffix(line, "ekm="+hex.EncodeToString(ekm)) {
			conn.Close()
			return "err", "go client: exporter differs from the server's"
		}
		tc.Close()
	}
	return "ok", line
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

func hexList(g []tls.CurveID) string {
	if g == nil {
		return "-"
	}
	var parts []string
	for _, x := range g {
		parts = append(parts, fmt.Sprintf("%04x", uint16(x)))
	}
	return strings.Join(parts, ",")
}

func orDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_oracle <work dir>")
		os.Exit(2)
	}
	dir = os.Args[1]

	// The trust anchors: one ECDSA P-256 root over most rows, an all-RSA
	// chain's root, an Ed25519 chain's root, a stranger's root.
	root := issue(caTmpl("ZL Interop Root"), nil, newKey("p256"))
	writeRoot("root", root.der)
	rsaRoot := issue(caTmpl("ZL Interop RSA Root"), nil, newKey("rsa2048"))
	writeRoot("rsa_root", rsaRoot.der)
	edRoot := issue(caTmpl("ZL Interop Ed25519 Root"), nil, newKey("ed25519"))
	writeRoot("ed_root", edRoot.der)
	stranger := issue(caTmpl("ZL Interop Root"), nil, newKey("p256")) // same name, other key
	inter := issue(caTmpl("ZL Interop Intermediate"), root, newKey("p256"))
	rsaInter := issue(caTmpl("ZL Interop RSA Intermediate"), rsaRoot, newKey("rsa2048"))
	edInter := issue(caTmpl("ZL Interop Ed25519 Intermediate"), edRoot, newKey("ed25519"))

	leafOf := func(kind string, parent *node, t *x509.Certificate) []*node {
		return []*node{issue(t, parent, newKey(kind)), parent}
	}
	std := func(kind string) []*node { return leafOf(kind, inter, leafTmpl(host)) }

	// Client certificates (signed by their own CA, which the servers trust).
	clientCA := issue(caTmpl("ZL Interop Client CA"), nil, newKey("p256"))
	writeRoot(clientRoot, clientCA.der)
	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCA.cert)
	for _, kind := range []string{"p256", "p384", "ed25519", "rsa2048"} {
		t := leafTmpl()
		t.Subject.CommonName = "client " + kind
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		n := issue(t, clientCA, newKey(kind))
		clientCerts[kind] = tls.Certificate{Certificate: [][]byte{n.der}, PrivateKey: n.key}
		write("client_"+kind+".der", n.der)
		var raw []byte
		switch k := n.key.(type) {
		case *ecdsa.PrivateKey:
			raw = k.D.FillBytes(make([]byte, (k.Curve.Params().BitSize+7)/8))
		case ed25519.PrivateKey:
			raw = k.Seed()
		case *rsa.PrivateKey:
			raw = x509.MarshalPKCS1PrivateKey(k)
		}
		write("client_"+kind+".key", raw)
	}

	var cases []*ccase
	add := func(c *ccase) {
		if c.expect == "" {
			c.expect = "agree"
		}
		if c.host == "" {
			c.host = host
		}
		if c.root == "" {
			c.root = "root"
		}
		if c.min == 0 {
			c.min = tls12
		}
		if c.max == 0 {
			c.max = tls13
		}
		cases = append(cases, c)
	}
	cfg := func(chain []*node, f func(*tls.Config)) *tls.Config {
		c := &tls.Config{Certificates: []tls.Certificate{serverCert(chain)}}
		if f != nil {
			f(c)
		}
		return c
	}
	vname := map[uint16]string{tls12: "12", tls13: "13"}

	// version: server range x client range.
	p256 := std("p256")
	for _, sv := range [][2]uint16{{tls12, tls12}, {tls13, tls13}, {tls12, tls13}} {
		for _, cv := range [][2]uint16{{tls12, tls13}, {tls13, tls13}, {tls12, tls12}} {
			sv := sv
			add(&ccase{id: fmt.Sprintf("version-s%s%s-c%s%s", vname[sv[0]], vname[sv[1]], vname[cv[0]], vname[cv[1]]), family: "version",
				server: cfg(p256, func(c *tls.Config) { c.MinVersion, c.MaxVersion = sv[0], sv[1] }), min: cv[0], max: cv[1]})
		}
	}

	// suite12: every TLS 1.2 AEAD suite, the server forced to one; bulk data.
	rsa2048 := std("rsa2048")
	for _, s := range []struct {
		name  string
		id    uint16
		chain []*node
	}{
		{"ecdhe-ecdsa-aes128gcm", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, p256},
		{"ecdhe-ecdsa-aes256gcm", tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, p256},
		{"ecdhe-ecdsa-chacha20", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, p256},
		{"ecdhe-rsa-aes128gcm", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, rsa2048},
		{"ecdhe-rsa-aes256gcm", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, rsa2048},
		{"ecdhe-rsa-chacha20", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, rsa2048},
	} {
		s := s
		add(&ccase{id: "suite12-" + s.name, family: "suite12", bulk: bulkMiB,
			server: cfg(s.chain, func(c *tls.Config) { c.MaxVersion = tls12; c.CipherSuites = []uint16{s.id} })})
	}
	// suite13: TLS 1.3 with bulk data (Go picks the suite).
	add(&ccase{id: "suite13-bulk", family: "suite13", bulk: bulkMiB, server: cfg(p256, nil)})

	// group: the server forced to one group (HelloRetryRequest for the ones
	// without a share), both versions; then the client restricted.
	gname := map[tls.CurveID]string{tls.X25519MLKEM768: "x25519mlkem768", tls.X25519: "x25519", tls.CurveP256: "p256", tls.CurveP384: "p384", tls.CurveP521: "p521"}
	for _, g := range []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		g := g
		add(&ccase{id: "group13-server-" + gname[g], family: "group", server: cfg(p256, func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{g} })})
		if g != tls.X25519MLKEM768 {
			add(&ccase{id: "group12-server-" + gname[g], family: "group", server: cfg(p256, func(c *tls.Config) { c.MaxVersion = tls12; c.CurvePreferences = []tls.CurveID{g} })})
		}
		add(&ccase{id: "group13-client-" + gname[g], family: "group", server: cfg(p256, nil), groups: []tls.CurveID{g}})
	}
	add(&ccase{id: "group13-nooverlap", family: "group", server: cfg(p256, func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP521} }), groups: []tls.CurveID{tls.X25519}})

	// leafkey: every leaf key type, both versions (the leaf signs the handshake).
	for _, k := range []string{"p256", "p384", "p521", "rsa2048", "rsa3072", "rsa4096", "ed25519"} {
		chain := std(k)
		for _, v := range []uint16{tls12, tls13} {
			v := v
			add(&ccase{id: "leafkey-" + k + "-" + vname[v], family: "leafkey", server: cfg(chain, func(c *tls.Config) { c.MinVersion, c.MaxVersion = v, v })})
		}
	}
	add(&ccase{id: "chain-all-rsa", family: "chain", root: "rsa_root", server: cfg(leafOf("rsa2048", rsaInter, leafTmpl(host)), nil)})
	add(&ccase{id: "chain-all-ed25519", family: "chain", root: "ed_root", server: cfg(leafOf("ed25519", edInter, leafTmpl(host)), nil)})

	// chain: names, validity, path rules.
	add(&ccase{id: "chain-wildcard", family: "chain", host: "a.wild.interop.test", server: cfg(leafOf("p256", inter, leafTmpl("*.wild.interop.test")), nil)})
	add(&ccase{id: "chain-wildcard-two-labels", family: "chain", host: "a.b.wild.interop.test", server: cfg(leafOf("p256", inter, leafTmpl("*.wild.interop.test")), nil)})
	add(&ccase{id: "chain-wrong-host", family: "chain", host: "other.interop.test", server: cfg(p256, nil)})
	add(&ccase{id: "chain-host-case", family: "chain", host: "SRV.Interop.TEST", server: cfg(p256, nil)})
	add(&ccase{id: "chain-ip-san", family: "chain", host: "127.0.0.1", server: cfg(leafOf("p256", inter, leafTmpl("127.0.0.1")), nil)})
	add(&ccase{id: "chain-ip-host-dns-san", family: "chain", host: "127.0.0.1", server: cfg(p256, nil)})
	add(&ccase{id: "chain-cn-only", family: "chain", server: cfg(leafOf("p256", inter, func() *x509.Certificate {
		t := leafTmpl()
		t.Subject.CommonName = host
		return t
	}()), nil)})
	expired := leafTmpl(host)
	expired.NotBefore, expired.NotAfter = now.Add(-48*time.Hour), now.Add(-time.Hour)
	add(&ccase{id: "chain-expired", family: "chain", server: cfg(leafOf("p256", inter, expired), nil)})
	notYet := leafTmpl(host)
	notYet.NotBefore = now.Add(time.Hour)
	add(&ccase{id: "chain-not-yet-valid", family: "chain", server: cfg(leafOf("p256", inter, notYet), nil)})
	add(&ccase{id: "chain-untrusted-root", family: "chain", server: cfg(leafOf("p256", issue(caTmpl("ZL Interop Intermediate"), stranger, newKey("p256")), leafTmpl(host)), nil)})
	add(&ccase{id: "chain-no-intermediate", family: "chain", server: cfg(leafOf("p256", inter, leafTmpl(host))[:1], nil)})
	// A leaf signed by another leaf's key (std #35877): Go refuses, so must we.
	other := issue(leafTmpl("other.interop.test"), inter, newKey("p256"))
	add(&ccase{id: "chain-leaf-signs-leaf", family: "chain", server: cfg([]*node{issue(leafTmpl(host), other, newKey("p256")), other, inter}, nil)})
	plen := caTmpl("ZL Interop Intermediate pathlen0")
	plen.MaxPathLen, plen.MaxPathLenZero = 0, true
	plenInter := issue(plen, root, newKey("p256"))
	sub := issue(caTmpl("ZL Interop Sub"), plenInter, newKey("p256"))
	add(&ccase{id: "chain-pathlen-exceeded", family: "chain", server: cfg([]*node{issue(leafTmpl(host), sub, newKey("p256")), sub, plenInter}, nil)})
	ekuClient := leafTmpl(host)
	ekuClient.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	add(&ccase{id: "chain-eku-client-only", family: "chain", server: cfg(leafOf("p256", inter, ekuClient), nil)})
	ekuAny := leafTmpl(host)
	ekuAny.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	add(&ccase{id: "chain-eku-any", family: "chain", server: cfg(leafOf("p256", inter, ekuAny), nil)})
	ncInterT := caTmpl("ZL Interop NC Intermediate")
	ncInterT.PermittedDNSDomains = []string{"permitted.test"}
	ncInter := issue(ncInterT, root, newKey("p256"))
	add(&ccase{id: "chain-nc-dns-outside", family: "chain", server: cfg(leafOf("p256", ncInter, leafTmpl(host)), nil)})
	add(&ccase{id: "chain-nc-dns-inside", family: "chain", host: "a.permitted.test", server: cfg(leafOf("p256", ncInter, leafTmpl("a.permitted.test")), nil)})
	ncExT := caTmpl("ZL Interop NC Excluded Intermediate")
	ncExT.ExcludedDNSDomains = []string{"interop.test"}
	ncEx := issue(ncExT, root, newKey("p256"))
	add(&ccase{id: "chain-nc-dns-excluded", family: "chain", server: cfg(leafOf("p256", ncEx, leafTmpl(host)), nil)})

	// The leads (x509's, at the TLS layer): Go does not process directoryName
	// name constraints, and reads an empty extendedKeyUsage as "any".
	evil, err := asn1.Marshal(pkix.Name{Organization: []string{"Evil Org"}}.ToRDNSequence())
	if err != nil {
		die(err)
	}
	ncDir := tlv(0x30, tlv(0xa1, tlv(0x30, tlv(0xa4, evil))))
	dirInterT := caTmpl("ZL Interop DirName NC Intermediate")
	dirInterT.ExtraExtensions = []pkix.Extension{rawExt(asn1.ObjectIdentifier{2, 5, 29, 30}, false, ncDir)}
	dirInter := issue(dirInterT, root, newKey("p256"))
	evilLeaf := leafTmpl(host)
	evilLeaf.Subject.Organization = []string{"Evil Org"}
	add(&ccase{id: "chain-nc-dirname-excluded", family: "chain", expect: "stricter",
		why:    "RFC 5280 4.2.1.10: the leaf's subject O=Evil Org lies in the intermediate's excluded directoryName subtree; Go does not process directoryName constraints",
		server: cfg(leafOf("p256", dirInter, evilLeaf), nil)})
	add(&ccase{id: "chain-nc-dirname-outside", family: "chain", server: cfg(leafOf("p256", dirInter, leafTmpl(host)), nil)})
	emptyEku := leafTmpl(host)
	emptyEku.ExtKeyUsage = nil
	emptyEku.ExtraExtensions = []pkix.Extension{rawExt(asn1.ObjectIdentifier{2, 5, 29, 37}, false, []byte{0x30, 0x00})}
	add(&ccase{id: "chain-empty-eku", family: "chain", expect: "stricter",
		why:    "RFC 5280 4.2.1.12: extendedKeyUsage is SIZE (1..MAX); Go reads an empty one as no restriction",
		server: cfg(leafOf("p256", inter, emptyEku), nil)})

	// alpn.
	h2h1 := []string{"h2", "http/1.1"}
	add(&ccase{id: "alpn-overlap", family: "alpn", alpn: []string{"http/1.1", "h2"}, server: cfg(p256, func(c *tls.Config) { c.NextProtos = h2h1 })})
	add(&ccase{id: "alpn-overlap-12", family: "alpn", alpn: []string{"http/1.1", "h2"}, server: cfg(p256, func(c *tls.Config) { c.NextProtos = h2h1; c.MaxVersion = tls12 })})
	add(&ccase{id: "alpn-no-overlap", family: "alpn", alpn: []string{"h3"}, server: cfg(p256, func(c *tls.Config) { c.NextProtos = h2h1 })})
	add(&ccase{id: "alpn-server-none", family: "alpn", alpn: h2h1, server: cfg(p256, nil)})
	add(&ccase{id: "alpn-client-none", family: "alpn", server: cfg(p256, func(c *tls.Config) { c.NextProtos = h2h1 })})

	// clientauth: the server requires and verifies a client certificate.
	for _, k := range []string{"p256", "p384", "ed25519", "rsa2048"} {
		for _, v := range []uint16{tls12, tls13} {
			v := v
			c := &ccase{id: "clientauth-" + k + "-" + vname[v], family: "clientauth", ccert: k,
				server: cfg(p256, func(c *tls.Config) {
					c.MinVersion, c.MaxVersion = v, v
					c.ClientAuth, c.ClientCAs = tls.RequireAndVerifyClientCert, clientPool
				})}
			if k == "ed25519" && v == tls12 {
				c.expect = "gap"
				c.why = "deliberately not: Ed25519 client keys in TLS 1.2 (SPEC Backlog); Go signs the 1.2 handshake with Ed25519"
			}
			add(c)
		}
	}
	add(&ccase{id: "clientauth-required-none", family: "clientauth",
		server: cfg(p256, func(c *tls.Config) { c.ClientAuth, c.ClientCAs = tls.RequireAndVerifyClientCert, clientPool })})
	add(&ccase{id: "clientauth-requested-none", family: "clientauth",
		server: cfg(p256, func(c *tls.Config) { c.ClientAuth, c.ClientCAs = tls.RequestClientCert, clientPool })})
	add(&ccase{id: "clientauth-requested-given", family: "clientauth", ccert: "p256",
		server: cfg(p256, func(c *tls.Config) { c.ClientAuth, c.ClientCAs = tls.VerifyClientCertIfGiven, clientPool })})

	// resume: the second connection of two, through a session cache.
	add(&ccase{id: "resume-13", family: "resume", twice: true, server: cfg(p256, nil)})
	add(&ccase{id: "resume-13-alpn", family: "resume", twice: true, alpn: h2h1, server: cfg(p256, func(c *tls.Config) { c.NextProtos = h2h1 })})
	add(&ccase{id: "resume-12", family: "resume", twice: true, expect: "gap",
		why:    "TLS 1.2 session resumption not implemented (SPEC Backlog); Go resumes",
		server: cfg(p256, func(c *tls.Config) { c.MaxVersion = tls12 })})
	add(&ccase{id: "resume-13-tickets-off", family: "resume", twice: true, server: cfg(p256, func(c *tls.Config) { c.SessionTicketsDisabled = true })})

	// staple: an OCSP response and two SCTs stapled by the server.
	for _, v := range []uint16{tls12, tls13} {
		v := v
		sc := serverCert(p256)
		sc.OCSPStaple = []byte("zl-interop-ocsp-" + vname[v])
		sc.SignedCertificateTimestamps = [][]byte{[]byte("zl-sct-one"), []byte("zl-sct-two")}
		add(&ccase{id: "staple-" + vname[v], family: "staple", staple: string(sc.OCSPStaple), scts: []string{"zl-sct-one", "zl-sct-two"},
			server: &tls.Config{Certificates: []tls.Certificate{sc}, MinVersion: v, MaxVersion: v}})
	}

	// Serve, judge with Go's client, write the table.
	pools := map[string]*x509.CertPool{}
	for name, n := range map[string]*node{"root": root, "rsa_root": rsaRoot, "ed_root": edRoot} {
		p := x509.NewCertPool()
		p.AddCert(n.cert)
		pools[name] = p
	}
	for _, c := range cases {
		serve(c)
	}
	var b strings.Builder
	b.WriteString(header + "\n")
	for _, c := range cases {
		c.goVerdict, c.line = goClient(c, pools[c.root])
		ccert := c.ccert
		if ccert == "" {
			ccert = "-"
		}
		staple := c.staple
		if staple == "" {
			staple = "-"
		}
		why := c.why
		if why == "" {
			why = "-"
		}
		twice := 0
		if c.twice {
			twice = 1
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%d\t%s\t%04x\t%04x\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
			c.id, c.family, c.expect, c.port, c.host, c.min, c.max, hexList(c.groups), hexList(c.shares), orDash(c.alpn),
			ccert, c.root, twice, c.bulk, staple, orDash(c.scts), c.goVerdict, c.line, why)
	}
	write("cases.tsv", []byte(b.String()))
	fmt.Printf("READY %s %d\n", strings.TrimPrefix(runtime.Version(), "go"), len(cases))
	select {}
}
