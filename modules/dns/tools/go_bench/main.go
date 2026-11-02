// SPDX-License-Identifier: BSD-3-Clause

// Go side of `zig build bench-dns` (modules/dns/tools/bench.zig): times
// golang.org/x/net/dns/dnsmessage v0.59.0 over the corpus the Zig program
// writes into the directory given as the first argument, for the one workload
// named by the second. Prints one line: name, ns/op, result count
// (tab-separated). One op = all 64 inputs. See bench.zig for what each
// workload does and how the count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var sink uint64

func timeIt(f func() uint64) (float64, uint64) {
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
	best := time.Duration(1<<63 - 1)
	var count uint64
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func readMsgs(path string) [][]byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	var out [][]byte
	for len(b) > 0 {
		n := int(b[0])<<8 | int(b[1])
		out = append(out, b[2:2+n])
		b = b[2+n:]
	}
	return out
}

// nameLen is the length of the name text without the root dot, as the Zig
// side counts it; the String() allocation is the Go counterpart of ours
// being strings already.
func nameLen(n dnsmessage.Name) uint64 {
	s := strings.TrimSuffix(n.String(), ".")
	return uint64(len(s))
}

func countRecord(r *dnsmessage.Resource) uint64 {
	t := 1 + nameLen(r.Header.Name)
	if _, ok := r.Body.(*dnsmessage.OPTResource); !ok {
		t += uint64(r.Header.TTL)
	}
	switch b := r.Body.(type) {
	case *dnsmessage.AResource:
		for _, v := range b.A {
			t += uint64(v)
		}
	case *dnsmessage.AAAAResource:
		for _, v := range b.AAAA {
			t += uint64(v)
		}
	case *dnsmessage.CNAMEResource:
		t += nameLen(b.CNAME)
	case *dnsmessage.NSResource:
		t += nameLen(b.NS)
	case *dnsmessage.PTRResource:
		t += nameLen(b.PTR)
	case *dnsmessage.MXResource:
		t += uint64(b.Pref) + nameLen(b.MX)
	case *dnsmessage.TXTResource:
		for _, s := range b.TXT {
			t += uint64(len(s))
		}
	case *dnsmessage.SRVResource:
		t += uint64(b.Port) + nameLen(b.Target)
	case *dnsmessage.OPTResource:
		t += uint64(r.Header.Class)
	}
	return t
}

func decode(msg []byte) uint64 {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		die(err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		die(err)
	}
	an, err := p.AllAnswers()
	if err != nil {
		die(err)
	}
	au, err := p.AllAuthorities()
	if err != nil {
		die(err)
	}
	ad, err := p.AllAdditionals()
	if err != nil {
		die(err)
	}
	var t uint64
	for _, q := range qs {
		t += 1 + nameLen(q.Name)
	}
	for _, sec := range [][]dnsmessage.Resource{an, au, ad} {
		for i := range sec {
			t += countRecord(&sec[i])
		}
	}
	return t
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "golang.org/x/net/dns/dnsmessage v0.59.0")
	var f func() uint64
	switch name {
	case "enc_query":
		b, err := os.ReadFile(filepath.Join(dir, "names.txt"))
		if err != nil {
			die(err)
		}
		var names []dnsmessage.Name
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			names = append(names, dnsmessage.MustNewName(l+"."))
		}
		root := dnsmessage.MustNewName(".")
		f = func() uint64 {
			var t uint64
			for _, n := range names {
				b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{RecursionDesired: true})
				if err := b.StartQuestions(); err != nil {
					die(err)
				}
				if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
					die(err)
				}
				if err := b.StartAdditionals(); err != nil {
					die(err)
				}
				h := dnsmessage.ResourceHeader{Name: root}
				if err := h.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
					die(err)
				}
				if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
					die(err)
				}
				out, err := b.Finish()
				if err != nil {
					die(err)
				}
				for _, c := range out {
					t += uint64(c)
				}
			}
			return t
		}
	case "dec_small", "dec_big", "dec_ptr", "names_deep":
		msgs := readMsgs(filepath.Join(dir, name+".bin"))
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				t += decode(m)
			}
			return t
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
