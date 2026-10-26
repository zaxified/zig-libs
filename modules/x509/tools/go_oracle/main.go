// SPDX-License-Identifier: MIT
//
// go_oracle: behaviour oracle for modules/x509. Reads one JSON case per line on
// stdin (see tools/gen_names_fixtures.py), prints one JSON verdict per case.
// Go public API only (crypto/x509); stdlib only.
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

type Case struct {
	ID            string   `json:"id"`
	Probe         string   `json:"probe"`
	Roots         []string `json:"roots"`
	Intermediates []string `json:"intermediates"`
	Leaf          string   `json:"leaf"`
	Time          int64    `json:"time"`
	DNSName       *string  `json:"dns_name"`
	KeyUsages     []string `json:"key_usages"`
	Mode          string   `json:"mode"`
	Host          string   `json:"host"`
	Policies      []string `json:"policies"`
}

type Result struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	ErrType string `json:"err_type"`
	Reason  *int   `json:"reason"`
	Msg     string `json:"msg"`
	NChains int    `json:"nchains"`
}

var ekus = map[string]x509.ExtKeyUsage{
	"any":    x509.ExtKeyUsageAny,
	"server": x509.ExtKeyUsageServerAuth,
	"client": x509.ExtKeyUsageClientAuth,
	"code":   x509.ExtKeyUsageCodeSigning,
	"email":  x509.ExtKeyUsageEmailProtection,
	"time":   x509.ExtKeyUsageTimeStamping,
	"ocsp":   x509.ExtKeyUsageOCSPSigning,
}

func parse(p string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("bad pem")
	}
	return x509.ParseCertificate(b.Bytes)
}

func fail(r *Result, err error) {
	r.OK = false
	r.ErrType = fmt.Sprintf("%T", err)
	r.Msg = err.Error()
	var cie x509.CertificateInvalidError
	if errors.As(err, &cie) {
		v := int(cie.Reason)
		r.Reason = &v
	}
}

func run(c Case) Result {
	r := Result{ID: c.ID}
	leaf, err := parse(c.Leaf)
	if err != nil {
		fail(&r, err)
		r.Msg = "parse leaf: " + r.Msg
		return r
	}
	switch c.Mode {
	case "parse":
		r.OK = true
		return r
	case "hostname":
		if err := leaf.VerifyHostname(c.Host); err != nil {
			fail(&r, err)
			return r
		}
		r.OK = true
		return r
	}
	roots := x509.NewCertPool()
	for _, p := range c.Roots {
		rc, err := parse(p)
		if err != nil {
			fail(&r, err)
			r.Msg = "parse root: " + r.Msg
			return r
		}
		roots.AddCert(rc)
	}
	inter := x509.NewCertPool()
	for _, p := range c.Intermediates {
		ic, err := parse(p)
		if err != nil {
			fail(&r, err)
			r.Msg = "parse intermediate: " + r.Msg
			return r
		}
		inter.AddCert(ic)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: time.Unix(c.Time, 0)}
	if c.DNSName != nil {
		opts.DNSName = *c.DNSName
	}
	for _, k := range c.KeyUsages {
		e, ok := ekus[k]
		if !ok {
			fail(&r, fmt.Errorf("oracle: unknown key usage %q", k))
			return r
		}
		opts.KeyUsages = append(opts.KeyUsages, e)
	}
	for _, ps := range c.Policies {
		o, err := x509.ParseOID(ps)
		if err != nil {
			fail(&r, fmt.Errorf("oracle: bad policy OID %q: %v", ps, err))
			return r
		}
		opts.CertificatePolicies = append(opts.CertificatePolicies, o)
	}
	chains, err := leaf.Verify(opts)
	if err != nil {
		fail(&r, err)
		return r
	}
	r.OK = true
	r.NChains = len(chains)
	return r
}

// Cases come from stdin, or from the file named by the first argument
// (tools/interop.zig); the Go version goes to stderr.
func main() {
	var in io.Reader = os.Stdin
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer f.Close()
		in = f
	}
	fmt.Fprintln(os.Stderr, runtime.Version())
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var c Case
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			enc.Encode(Result{ID: "?", Msg: "bad json: " + err.Error(), ErrType: "oracle"})
			continue
		}
		enc.Encode(run(c))
	}
}
