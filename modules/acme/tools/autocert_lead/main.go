// SPDX-License-Identifier: MIT

// The acme module's lead over the reference, measured: golang.org/x/crypto
// acme/autocert (BSD-3-Clause, read in full before it was built) driven
// against Pebble, counting what it asks the CA for. run.sh starts Pebble.
//
//	fleet: two autocert Managers on one DirCache — the deployment its docs
//	       allow ("Multiple Managers can share the same Cache") — get the
//	       first handshake for one name at the same moment. Counted: orders
//	       finalized, i.e. certificates issued for that one name.
//	renew: one Manager with RenewBefore = 30 days (autocert's default until
//	       2025, still the value most configurations spell out) against a CA
//	       that issues 24-hour certificates (step-ca's default). Counted:
//	       certificates issued in the 10 s after the first handshake.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// counter counts the CA requests that matter, by Pebble's URL paths.
type counter struct {
	inner     http.RoundTripper
	orders    atomic.Int64 // POST /order-plz (newOrder)
	finalized atomic.Int64 // POST /finalize-order/… (a certificate is issued)
}

func (c *counter) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost {
		switch {
		case r.URL.Path == "/order-plz":
			c.orders.Add(1)
		case strings.HasPrefix(r.URL.Path, "/finalize-order/"):
			c.finalized.Add(1)
		}
	}
	return c.inner.RoundTrip(r)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "autocert_lead:", err)
		os.Exit(1)
	}
}

func newManager(dir string, cache autocert.Cache, cnt *counter, renewBefore time.Duration) *autocert.Manager {
	m := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       cache,
		RenewBefore: renewBefore,
		Client:      &acme.Client{DirectoryURL: dir, HTTPClient: &http.Client{Transport: cnt}},
	}
	return m
}

// serve answers the CA's validation requests: TLS-ALPN-01 on :5001 and
// HTTP-01 on :5002, both through `front` — like a load balancer, the CA
// reaches one node; the others' challenge data comes from the shared cache.
func serve(front *autocert.Manager) func() {
	ln, err := net.Listen("tcp", "127.0.0.1:5001")
	must(err)
	tln := tls.NewListener(ln, front.TLSConfig())
	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	hs := &http.Server{Addr: "127.0.0.1:5002", Handler: front.HTTPHandler(nil)}
	go hs.ListenAndServe()
	return func() { ln.Close(); hs.Close() }
}

func hello(name string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:   name,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

func main() {
	scenario := flag.String("scenario", "", "fleet | renew")
	dir := flag.String("dir", "https://localhost:14000/dir", "Pebble directory")
	caFile := flag.String("ca", "", "PEM of the CA that signed Pebble's HTTPS certificate")
	scratch := flag.String("scratch", "", "directory for the DirCache")
	flag.Parse()

	pem, err := os.ReadFile(*caFile)
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		must(fmt.Errorf("no certificate in %s", *caFile))
	}
	cnt := &counter{inner: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	cache := autocert.DirCache(*scratch)

	switch *scenario {
	case "fleet":
		m1 := newManager(*dir, cache, cnt, 0)
		m2 := newManager(*dir, cache, cnt, 0)
		m2.HTTPHandler(nil) // both nodes answer HTTP-01, as in a fleet
		stop := serve(m1)
		defer stop()
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i, m := range []*autocert.Manager{m1, m2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = m.GetCertificate(hello("fleet.test"))
			}()
		}
		close(start)
		wg.Wait()
		fmt.Printf("fleet: node1 err=%v node2 err=%v\n", errs[0], errs[1])
		fmt.Printf("fleet: orders=%d certificates_issued=%d (one name, two nodes, one cache)\n",
			cnt.orders.Load(), cnt.finalized.Load())
	case "renew":
		m := newManager(*dir, cache, cnt, 30*24*time.Hour)
		stop := serve(m)
		defer stop()
		c, err := m.GetCertificate(hello("renew.test"))
		must(err)
		fmt.Printf("renew: first certificate notBefore=%s notAfter=%s (lifetime %s)\n",
			c.Leaf.NotBefore.UTC().Format(time.RFC3339), c.Leaf.NotAfter.UTC().Format(time.RFC3339),
			c.Leaf.NotAfter.Sub(c.Leaf.NotBefore))
		first := cnt.finalized.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		<-ctx.Done()
		cancel()
		fmt.Printf("renew: certificates_issued=%d in the 10 s after the first (RenewBefore=720h)\n",
			cnt.finalized.Load()-first)
	default:
		must(fmt.Errorf("-scenario fleet|renew"))
	}
}
