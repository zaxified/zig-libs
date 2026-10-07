// SPDX-License-Identifier: MIT

// Go side of `zig build bench-entropy` (modules/entropy/tools/bench.zig):
// times Go's crypto/rand.Read filling 32 B, 4 KiB and 1 MiB buffers. One line
// per workload: name, ns/op, the buffer length. Timing matches the Zig side:
// double the batch until it takes over 100 ms, best of five. Standard library
// only.
package main

import (
	"crypto/rand"
	"fmt"
	"time"
)

func main() {
	names := []string{"fill_32", "fill_4k", "fill_1m"}
	sizes := []int{32, 4096, 1 << 20}
	for w, name := range names {
		buf := make([]byte, sizes[w])
		n := 1
		for {
			t := time.Now()
			for i := 0; i < n; i++ {
				rand.Read(buf)
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
				rand.Read(buf)
			}
			if d := time.Since(t); d < best {
				best = d
			}
		}
		fmt.Printf("%s\t%.1f\t%d\n", name, float64(best.Nanoseconds())/float64(n), len(buf))
	}
}
