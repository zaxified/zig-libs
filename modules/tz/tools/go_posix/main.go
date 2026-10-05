// SPDX-License-Identifier: MIT

// Third vote for gen_posix_kat.py: Go's time package evaluating POSIX TZ
// strings (a footer-only TZif through time.LoadLocationFromTZData). Reads one
// string per line on stdin, prints one JSON object per string: the offset at
// -lo and every change before -hi. Stdlib only, no network.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type off struct {
	Off int  `json:"off"`
	Dst bool `json:"dst"`
}

func tzif(posix string) []byte {
	block := func() []byte {
		b := []byte("TZif2")
		b = append(b, make([]byte, 15)...)
		for _, n := range []uint32{0, 0, 0, 0, 1, 4} {
			b = binary.BigEndian.AppendUint32(b, n)
		}
		b = append(b, 0, 0, 0, 0, 0, 0) // ttinfo: utoff 0, isdst 0, abbrind 0
		return append(b, "UTC\x00"...)
	}
	out := append(block(), block()...)
	return append(out, "\n"+posix+"\n"...)
}

func main() {
	lo := flag.Int64("lo", 0, "range start (Unix seconds)")
	hi := flag.Int64("hi", 0, "range end (Unix seconds)")
	flag.Parse()
	sc := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		s := sc.Text()
		loc, err := time.LoadLocationFromTZData(s, tzif(s))
		if err != nil {
			fmt.Fprintln(os.Stderr, s, err)
			os.Exit(1)
		}
		at := func(u int64) off {
			t := time.Unix(u, 0).In(loc)
			_, o := t.Zone()
			return off{o, t.IsDST()}
		}
		first := at(*lo)
		var changes [][3]any
		u, o := *lo, first
		for u < *hi {
			v := min(u+3600, *hi)
			if p := at(v); p != o {
				a, b := u, v
				for b-a > 1 {
					m := (a + b) / 2
					if at(m) == o {
						a = m
					} else {
						b = m
					}
				}
				n := at(b)
				changes = append(changes, [3]any{b, n.Off, n.Dst})
				u, o = b, n
				continue
			}
			u = v
		}
		enc.Encode(map[string]any{"s": s, "first": first, "changes": changes})
	}
}
