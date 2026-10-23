// SPDX-License-Identifier: MIT

// "Fastest in the field" side of `zig build bench-cookies`
// (modules/cookies/tools/bench.zig): times valyala/fasthttp v1.76.0 (pinned by
// go.mod/go.sum) over the same headers and cookie specs the Zig program writes
// into the directory given as the first argument, for the one workload named
// by the second and the contender named by the third (only "fasthttp" today).
// Prints one line, tab-separated: name, ns/op, count and, for `build`, a
// fourth field `canon` (see below). One op = every header / spec once.
//
//	parse_find  RequestHeader: drop the cookies, feed the header value, then
//	            Cookie("sid"); count = value bytes found + hits
//	parse_all   same feed, then range over Cookies(); count = sum of
//	            name+value bytes
//	build       prebuilt fasthttp.Cookie per spec, AppendBytes into one
//	            reused buffer; count = sum of output bytes
//
// What differs from the reference side (Go net/http), stated so the rows are
// not read as more than they are:
//   - fasthttp has no public "parse this Cookie header" function. The feed is
//     RequestHeader.SetCanonical("Cookie", value), which runs the same
//     parseRequestCookies that header.Read runs (it validates cookie values),
//     after DelAllCookies; the extra copy of the value into the header's own
//     buffer is charged to fasthttp.
//   - build: AppendBytes does no validation (net/http and ours do; the inputs
//     are valid for all), appends into a reused buffer instead of allocating a
//     string, writes the attribute names in lower case ("max-age", "domain",
//     "path", "secure") and in another order. The byte sum therefore differs
//     from the reference's; `canon` is the byte sum of the output after ASCII
//     lower-casing, which is order- and case-independent, and is what the
//     Zig side compares for this contender. It is computed in an untimed pass.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var sink int

func timeIt(f func() int) (float64, int) {
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
	count := 0
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

func lines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func sum(b []byte) int {
	t := 0
	for _, c := range b {
		t += int(c)
	}
	return t
}

func sumLower(b []byte) int {
	t := 0
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		t += int(c)
	}
	return t
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: go_fast_bench <work dir> <workload> <contender>")
		os.Exit(2)
	}
	dir, name, who := os.Args[1], os.Args[2], os.Args[3]
	if who != "fasthttp" {
		fmt.Fprintln(os.Stderr, "unknown contender", who)
		os.Exit(2)
	}
	var headers [][]byte
	for _, h := range lines(filepath.Join(dir, "headers.txt")) {
		headers = append(headers, []byte(h))
	}
	var specs []fasthttp.Cookie
	for _, l := range lines(filepath.Join(dir, "specs.tsv")) {
		f := strings.Split(l, "\t")
		age, _ := strconv.Atoi(f[4])
		ss, _ := strconv.Atoi(f[7])
		specs = append(specs, fasthttp.Cookie{})
		c := &specs[len(specs)-1]
		c.SetKey(f[0])
		c.SetValue(f[1])
		if f[2] != "" {
			c.SetPath(f[2])
		}
		if f[3] != "" {
			c.SetDomain(f[3])
		}
		c.SetMaxAge(age)
		c.SetSecure(f[5] == "1")
		c.SetHTTPOnly(f[6] == "1")
		switch ss {
		case 1:
			c.SetSameSite(fasthttp.CookieSameSiteLaxMode)
		case 2:
			c.SetSameSite(fasthttp.CookieSameSiteStrictMode)
		case 3:
			c.SetSameSite(fasthttp.CookieSameSiteNoneMode)
		}
	}

	var hdr fasthttp.RequestHeader
	cookieKey := []byte("Cookie")
	sid := "sid"
	feed := func(h []byte) {
		hdr.DelAllCookies()
		hdr.SetCanonical(cookieKey, h)
	}
	var buf []byte

	var f func() int
	canon := -1
	switch name {
	case "parse_find":
		f = func() int {
			t := 0
			for _, h := range headers {
				feed(h)
				if v := hdr.Cookie(sid); v != nil {
					t += sum(v) + 1
				}
			}
			return t
		}
	case "parse_all":
		f = func() int {
			t := 0
			for _, h := range headers {
				feed(h)
				for k, v := range hdr.Cookies() {
					t += sum(k) + sum(v)
				}
			}
			return t
		}
	case "build":
		f = func() int {
			t := 0
			for i := range specs {
				buf = specs[i].AppendBytes(buf[:0])
				t += sum(buf)
			}
			return t
		}
		canon = 0
		for i := range specs {
			buf = specs[i].AppendBytes(buf[:0])
			canon += sumLower(buf)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	if canon >= 0 {
		fmt.Printf("%s\t%.1f\t%d\t%d\n", name, ns, count, canon)
	} else {
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
	}
}
