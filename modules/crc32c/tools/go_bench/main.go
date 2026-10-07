// SPDX-License-Identifier: MIT

// Go side of `zig build bench-crc32c` (modules/crc32c/tools/bench.zig): times
// Go's hash/crc32 with the Castagnoli table (SSE4.2 on amd64) over the
// buffer that program writes. One line per workload: name, ns/op, the CRC.
// Timing matches the Zig side. Standard library only.
package main

import (
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"time"
)

var sink uint32

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir>")
		os.Exit(2)
	}
	data, err := os.ReadFile(filepath.Join(os.Args[1], "data.bin"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	names := []string{"crc_64", "crc_1k", "crc_64k", "crc_1m"}
	sizes := []int{64, 1024, 65536, 1 << 20}
	for w, name := range names {
		buf := data[:sizes[w]]
		n := 1
		for {
			t := time.Now()
			for i := 0; i < n; i++ {
				sink += crc32.Checksum(buf, castagnoli)
			}
			if time.Since(t) > 100*time.Millisecond {
				break
			}
			n *= 2
		}
		best := time.Duration(1<<63 - 1)
		var crc uint32
		for k := 0; k < 5; k++ {
			t := time.Now()
			for i := 0; i < n; i++ {
				crc = crc32.Checksum(buf, castagnoli)
			}
			if d := time.Since(t); d < best {
				best = d
			}
		}
		fmt.Printf("%s\t%.1f\t%d\n", name, float64(best.Nanoseconds())/float64(n), crc)
	}
}
