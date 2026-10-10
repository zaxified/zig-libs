// SPDX-License-Identifier: MIT

// Go side of `zig build bench-cookies` (modules/cookies/tools/bench.zig): times
// Go's net/http cookie code over the headers and cookie specs the Zig program
// writes into the directory given as the first argument, for the one workload
// named by the second. Prints one line: name, ns/op, result count
// (tab-separated). One op = every header / spec once. Standard library only.
//
//	parse_find  http.Request{Header}.Cookie("sid"); count = value bytes found + hits
//	parse_all   http.ParseCookie(header); count = sum of name+value bytes
//	build       (&http.Cookie{...}).String(); count = sum of output bytes
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

func sum(s string) int {
	t := 0
	for i := 0; i < len(s); i++ {
		t += int(s[i])
	}
	return t
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	headers := lines(filepath.Join(dir, "headers.txt"))
	var reqs []*http.Request
	for _, h := range headers {
		reqs = append(reqs, &http.Request{Header: http.Header{"Cookie": {h}}})
	}
	var specs []http.Cookie
	for _, l := range lines(filepath.Join(dir, "specs.tsv")) {
		f := strings.Split(l, "\t")
		age, _ := strconv.Atoi(f[4])
		ss, _ := strconv.Atoi(f[7])
		c := http.Cookie{Name: f[0], Value: f[1], Path: f[2], Domain: f[3], MaxAge: age, Secure: f[5] == "1", HttpOnly: f[6] == "1"}
		switch ss {
		case 1:
			c.SameSite = http.SameSiteLaxMode
		case 2:
			c.SameSite = http.SameSiteStrictMode
		case 3:
			c.SameSite = http.SameSiteNoneMode
		}
		specs = append(specs, c)
	}

	var f func() int
	switch name {
	case "parse_find":
		f = func() int {
			t := 0
			for _, r := range reqs {
				if c, err := r.Cookie("sid"); err == nil {
					t += sum(c.Value) + 1
				}
			}
			return t
		}
	case "parse_all":
		f = func() int {
			t := 0
			for _, h := range headers {
				cs, err := http.ParseCookie(h)
				if err != nil {
					panic(err)
				}
				for _, c := range cs {
					t += sum(c.Name) + sum(c.Value)
				}
			}
			return t
		}
	case "build":
		f = func() int {
			t := 0
			for i := range specs {
				t += sum(specs[i].String())
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
