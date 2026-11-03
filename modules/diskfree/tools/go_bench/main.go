// SPDX-License-Identifier: MIT

// Go side of `zig build bench-diskfree` (modules/diskfree/tools/bench.zig):
// times github.com/moby/sys/mountinfo v0.7.3 (the reference),
// github.com/prometheus/procfs v0.21.1 (a second mountinfo reader) and
// golang.org/x/sys v0.49.0 `unix.Statfs`, over the corpus the Zig program
// writes into the directory given as the first argument, for the one workload
// named by the second. Prints one line: name, ns/op, result count
// (tab-separated). See bench.zig for what each workload does and how the
// count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/moby/sys/mountinfo"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "moby/sys/mountinfo v0.7.3, prometheus/procfs v0.21.1, golang.org/x/sys v0.49.0")
	var f func() uint64
	switch name {
	case "parse_mountinfo":
		// Same work as ours: every row to a record with unescaped root,
		// mount point, fs type and source, ids and device numbers as ints.
		data, err := os.ReadFile(filepath.Join(dir, "mountinfo.txt"))
		if err != nil {
			die(err)
		}
		f = func() uint64 {
			ms, err := mountinfo.GetMountsFromReader(bytes.NewReader(data), nil)
			if err != nil {
				die(err)
			}
			var t uint64
			for _, m := range ms {
				t += uint64(m.ID + m.Parent + m.Major + m.Minor)
				t += uint64(len(m.Root) + len(m.Mountpoint) + len(m.FSType) + len(m.Source))
			}
			return t
		}
	case "live_moby":
		f = func() uint64 {
			ms, err := mountinfo.GetMounts(nil)
			if err != nil {
				die(err)
			}
			t := uint64(len(ms))
			for _, m := range ms {
				t += uint64(m.ID + m.Parent)
			}
			return t
		}
	case "live_procfs":
		f = func() uint64 {
			ms, err := procfs.GetMounts()
			if err != nil {
				die(err)
			}
			t := uint64(len(ms))
			for _, m := range ms {
				t += uint64(m.MountID + m.ParentID)
			}
			return t
		}
	case "statfs":
		f = func() uint64 {
			var st unix.Statfs_t
			if err := unix.Statfs("/", &st); err != nil {
				die(err)
			}
			return uint64(st.Blocks) + uint64(st.Namelen) + uint64(st.Type)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
