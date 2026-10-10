// SPDX-License-Identifier: MIT

// Go side of `zig build bench-tlsclient` (modules/tlsclient/tools/bench.zig):
// Go's standard-library crypto/tls (the module's reference; stdlib only), as
// the TLS server both clients talk to and as the reference client.
//
//	go_bench <dir> serve               generates two chains (ecdsa256: ECDSA
//	                                   P-256 root, intermediate, leaf; rsa2048:
//	                                   RSA-2048 throughout), listens on two
//	                                   loopback ports, writes root_<kind>.pem
//	                                   and port_<kind>.txt into <dir>, prints
//	                                   READY, then answers handshakes until
//	                                   killed. Default crypto/tls server
//	                                   config (TLS 1.3 preferred, tickets on).
//	go_bench <dir> handshake_<kind>    the client: one op = dial 127.0.0.1,
//	                                   tls.Client(...).Handshake() verifying the
//	                                   chain against the root and the name
//	                                   bench.example.test, close.
//
// The client prints one line: name, ns/op, user-mode cycles/op, 1. The cycles
// are those of the OS thread the handshake runs on (perf_event_open, user
// mode only, the goroutine is pinned with LockOSThread), the same quantity
// the Zig side counts for its own thread; the server runs in another process
// and is not in it. Timing matches the Zig side: double the batch until it
// takes over 100 ms, then keep the best of five.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const host = "bench.example.test"

var sink int

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

var serial int64

func issue(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) []byte {
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		die(err)
	}
	return der
}

func newKey(kind string) crypto.Signer {
	if kind == "rsa2048" {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			die(err)
		}
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die(err)
	}
	return k
}

// chain returns the server's tls.Certificate (leaf, intermediate) and the root DER.
func chain(kind string) (tls.Certificate, []byte) {
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(10*365*24*time.Hour)
	rk, ik, lk := newKey(kind), newKey(kind), newKey(kind)
	rootT := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Bench Root " + kind}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER := issue(rootT, rootT, rk.Public(), rk)
	rootC, err := x509.ParseCertificate(rootDER)
	if err != nil {
		die(err)
	}
	interT := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Bench Intermediate " + kind}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER := issue(interT, rootC, ik.Public(), rk)
	interC, err := x509.ParseCertificate(interDER)
	if err != nil {
		die(err)
	}
	leafT := &x509.Certificate{
		Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER := issue(leafT, interC, lk.Public(), ik)
	return tls.Certificate{Certificate: [][]byte{leafDER, interDER}, PrivateKey: lk}, rootDER
}

func serve(dir string) {
	for _, kind := range []string{"ecdsa256", "rsa2048"} {
		cert, rootDER := chain(kind)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
		if err := os.WriteFile(filepath.Join(dir, "root_"+kind+".pem"), pemBytes, 0o644); err != nil {
			die(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			die(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := os.WriteFile(filepath.Join(dir, "port_"+kind+".txt"), []byte(strconv.Itoa(port)), 0o644); err != nil {
			die(err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					tc := tls.Server(c, cfg)
					_ = tc.Handshake()
					_ = tc.Close()
				}()
			}
		}()
	}
	fmt.Println("READY")
	select {}
}

// perf opens a user-mode CPU-cycle counter for the calling thread (0 if the
// kernel refuses).
func perfOpen() int {
	var attr [16]uint64 // 128 bytes
	attr[0] = 0 | 128<<32
	attr[1] = 0           // PERF_COUNT_HW_CPU_CYCLES
	attr[5] = 1<<5 | 1<<6 // exclude_kernel, exclude_hv
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&attr[0])), 0, ^uintptr(0), ^uintptr(0), 0, 0)
	if errno != 0 {
		return -1
	}
	return int(fd)
}

func perfRead(fd int) float64 {
	if fd < 0 {
		return 0
	}
	var v uint64
	_, _, errno := syscall.Syscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&v)), 8)
	if errno != 0 {
		return 0
	}
	return float64(v)
}

func timeIt(fd int, f func() int) (float64, float64, int) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best, bestc := time.Duration(1<<63-1), 1e300
	count := 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		c0 := perfRead(fd)
		for i := 0; i < n; i++ {
			count = f()
		}
		c := perfRead(fd) - c0
		if d := time.Since(t); d < best {
			best = d
		}
		if c < bestc {
			bestc = c
		}
	}
	if fd < 0 {
		bestc = 0
	}
	return float64(best.Nanoseconds()) / float64(n), bestc / float64(n), count
}

func client(dir, kind string) {
	runtime.LockOSThread()
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			die(err)
		}
		return strings.TrimSpace(string(b))
	}
	port := read("port_" + kind + ".txt")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(read("root_" + kind + ".pem"))) {
		die(fmt.Errorf("bad root pem"))
	}
	cfg := &tls.Config{RootCAs: roots, ServerName: host}
	addr := "127.0.0.1:" + port
	fmt.Fprintf(os.Stderr, "Go %s crypto/tls\n", strings.TrimPrefix(runtime.Version(), "go"))
	fd := perfOpen()
	ns, cyc, count := timeIt(fd, func() int {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			die(err)
		}
		tc := tls.Client(c, cfg)
		if err := tc.Handshake(); err != nil {
			die(err)
		}
		if tc.ConnectionState().Version != tls.VersionTLS13 {
			die(fmt.Errorf("not TLS 1.3"))
		}
		_ = tc.Close()
		return 1
	})
	fmt.Printf("handshake_%s\t%.1f\t%.1f\t%d\n", kind, ns, cyc, count)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> serve|handshake_<kind>")
		os.Exit(2)
	}
	dir, w := os.Args[1], os.Args[2]
	if w == "serve" {
		serve(dir)
		return
	}
	if kind, ok := strings.CutPrefix(w, "handshake_"); ok {
		client(dir, kind)
		return
	}
	fmt.Fprintf(os.Stderr, "unknown workload %s\n", w)
	os.Exit(2)
}
