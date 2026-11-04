// SPDX-License-Identifier: BSD-3-Clause

// Go side of `zig build bench-tar` (modules/tar/tools/bench.zig): times Go's
// archive/tar (standard library only) over the archives the Zig program writes
// into the directory given as the first argument, for the one workload named
// by the second. Prints one line: name, ns/op, result count (tab-separated).
// See bench.zig for what each workload does and how the count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
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

func readAll(data []byte) uint64 {
	tr := tar.NewReader(bytes.NewReader(data))
	buf := make([]byte, 32*1024)
	var t uint64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return t
		}
		if err != nil {
			die(err)
		}
		t += uint64(h.Size) + uint64(h.Uid) + uint64(h.Gid) + uint64(h.ModTime.Unix()) + uint64(len(h.Name)) + uint64(len(h.Linkname))
		for {
			n, err := tr.Read(buf)
			t += uint64(n)
			if err == io.EOF {
				break
			}
			if err != nil {
				die(err)
			}
		}
	}
}

type countW struct{ n uint64 }

func (c *countW) Write(p []byte) (int, error) {
	c.n += uint64(len(p))
	return len(p), nil
}

type member struct {
	hdr  tar.Header
	body []byte
}

func load(data []byte) []member {
	tr := tar.NewReader(bytes.NewReader(data))
	var out []member
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			die(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			die(err)
		}
		hh := *h
		hh.Format = tar.FormatUnknown // let Go choose; it picks USTAR for these
		hh.Uname, hh.Gname = "", ""
		out = append(out, member{hh, b})
	}
}

func main() {
	if len(os.Args) != 3 {
		die(fmt.Errorf("usage: go_bench DIR WORKLOAD"))
	}
	dir, name := os.Args[1], os.Args[2]
	read := func(f string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			die(err)
		}
		return b
	}
	fmt.Fprintln(os.Stderr, "Go archive/tar, standard library")
	var f func() uint64
	switch name {
	case "read_many":
		data := read("many.tar")
		f = func() uint64 { return readAll(data) }
	case "read_pax":
		data := read("pax.tar")
		f = func() uint64 { return readAll(data) }
	case "read_big":
		data := read("big.tar")
		f = func() uint64 { return readAll(data) }
	case "write_many":
		ms := load(read("many.tar"))
		f = func() uint64 {
			cw := &countW{}
			tw := tar.NewWriter(cw)
			for i := range ms {
				h := ms[i].hdr
				if err := tw.WriteHeader(&h); err != nil {
					die(err)
				}
				if _, err := tw.Write(ms[i].body); err != nil {
					die(err)
				}
			}
			if err := tw.Close(); err != nil {
				die(err)
			}
			return cw.n
		}
	case "write_big":
		chunk := make([]byte, 64*1024)
		const size = 32 << 20
		f = func() uint64 {
			cw := &countW{}
			tw := tar.NewWriter(cw)
			h := tar.Header{Name: "big.bin", Mode: 0o644, Uid: 1000, Gid: 1000, Size: size, ModTime: time.Unix(1600000000, 0), Typeflag: tar.TypeReg}
			if err := tw.WriteHeader(&h); err != nil {
				die(err)
			}
			for left := size; left > 0; left -= len(chunk) {
				if _, err := tw.Write(chunk); err != nil {
					die(err)
				}
			}
			if err := tw.Close(); err != nil {
				die(err)
			}
			return cw.n
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
