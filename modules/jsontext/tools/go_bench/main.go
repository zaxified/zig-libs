// SPDX-License-Identifier: MIT

// Go side of `zig build bench-jsontext` (modules/jsontext/tools/bench.zig):
// times encoding/json's string encoder (an Encoder with SetEscapeHTML(false)
// into a reused buffer) on four string shapes of 64 B and 4 KiB. One line per
// workload: name, ns/op. The strings are generated exactly as `fill` in
// bench.zig does. Timing matches the Zig side: double the batch until it takes
// over 100 ms, best of five. Standard library only.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

func fill(n, shape int) string {
	b := make([]byte, n)
	switch shape {
	case 0:
		for i := range b {
			b[i] = byte('a' + i*7%26)
		}
	case 1:
		unit := "abc\xc3\xa9xyz\xe2\x82\xacdef\xf0\x9f\x98\x80 "
		k := 0
		for k+len(unit) <= n {
			copy(b[k:], unit)
			k += len(unit)
		}
		for ; k < n; k++ {
			b[k] = 'x'
		}
	case 2:
		for i := range b {
			switch {
			case i%16 == 7:
				b[i] = 0xE2
			case i%4 == 3:
				b[i] = 0xFF
			default:
				b[i] = byte('a' + i%26)
			}
		}
	default:
		for i := range b {
			switch i % 3 {
			case 0:
				b[i] = byte(i % 32)
			case 1:
				b[i] = '"'
			default:
				b[i] = byte('a' + i%26)
			}
		}
	}
	return string(b)
}

func main() {
	shapes := []string{"ascii", "utf8", "ill", "ctrl"}
	sizes := []int{64, 4096}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	once := func(s string) {
		buf.Reset()
		if err := enc.Encode(s); err != nil {
			panic(err)
		}
	}
	for si, shape := range shapes {
		for _, size := range sizes {
			s := fill(size, si)
			n := 1
			for {
				t := time.Now()
				for i := 0; i < n; i++ {
					once(s)
				}
				if time.Since(t) > 100*time.Millisecond {
					break
				}
				n *= 2
			}
			best := time.Duration(1<<63 - 1)
			for k := 0; k < 5; k++ {
				t := time.Now()
				for i := 0; i < n; i++ {
					once(s)
				}
				if d := time.Since(t); d < best {
					best = d
				}
			}
			fmt.Printf("%s_%d\t%.1f\n", shape, size, float64(best.Nanoseconds())/float64(n))
		}
	}
}
