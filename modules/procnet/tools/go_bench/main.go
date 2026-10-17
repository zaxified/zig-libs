// SPDX-License-Identifier: MIT

// Go side of `zig build bench-procnet` (modules/procnet/tools/bench.zig): times
// github.com/prometheus/procfs v0.21.1 (pinned by go.mod/go.sum) reading THIS
// process's /proc files through its public API only, for the one row named by
// the first argument. Prints one line: name, ns/op, result count
// (tab-separated). One op = one read + parse of the file.
//
// procfs has no parse-from-bytes entry point (Proc.Stat, Proc.Limits, ... open
// the file themselves; the parsers are unexported), so there are no parse_*
// rows: every row is read + parse on both sides.
//
// The result count is a cheap invariant both sides compute identically (the two
// programs are different processes, so utime/vsize/fd counts legitimately
// differ); see bench.zig for the definition per row.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/prometheus/procfs"
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

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "procfs error:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <row>")
		os.Exit(2)
	}
	name := os.Args[1]
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		fail(err)
	}
	p, err := fs.Self()
	if err != nil {
		fail(err)
	}
	pid := os.Getpid()

	var f func() int
	switch name {
	case "pid_stat":
		f = func() int {
			s, err := p.Stat()
			if err != nil {
				fail(err)
			}
			return b2i(s.PID == pid && (s.State == "R" || s.State == "S" || s.State == "D") && s.VSize > 0 && s.Starttime > 0)
		}
	case "pid_limits":
		f = func() int {
			l, err := p.Limits()
			if err != nil {
				fail(err)
			}
			// All but OpenFiles: the Go runtime raises its soft RLIMIT_NOFILE.
			var sum uint64
			for _, v := range []uint64{l.CPUTime, l.FileSize, l.DataSize, l.StackSize, l.CoreFileSize, l.ResidentSet, l.Processes, l.LockedMemory, l.AddressSpace, l.FileLocks, l.PendingSignals, l.MsqqueueSize, l.NicePriority, l.RealtimePriority, l.RealtimeTimeout} {
				sum += v
			}
			return int(sum & 0x7fffffffffffffff)
		}
	case "pid_status":
		f = func() int {
			s, err := p.NewStatus()
			if err != nil {
				fail(err)
			}
			ok := s.TGID == pid && s.PID == pid && s.VmRSS > 0 && s.VmSize >= s.VmRSS
			return int(s.UIDs[0]) + 7*int(s.GIDs[0]) + 1000000000*b2i(ok)
		}
	case "pid_io":
		f = func() int {
			s, err := p.IO()
			if err != nil {
				fail(err)
			}
			return b2i(s.RChar > 0 && s.SyscR > 0)
		}
	case "fd_count":
		f = func() int {
			n, err := p.FileDescriptorsLen()
			if err != nil {
				fail(err)
			}
			return b2i(n >= 3 && n < 256)
		}
	case "pid_netstat":
		f = func() int {
			s, err := p.Netstat()
			if err != nil {
				fail(err)
			}
			return b2i(s.InOctets != nil && s.OutOctets != nil && *s.InOctets > 0 && *s.OutOctets > 0)
		}
	case "net_unix":
		f = func() int {
			u, err := fs.NetUNIX()
			if err != nil {
				fail(err)
			}
			return b2i(len(u.Rows) > 0)
		}
	case "net_dev":
		f = func() int {
			d, err := fs.NetDev()
			if err != nil {
				fail(err)
			}
			_, lo := d["lo"]
			return len(d)*10 + b2i(lo)
		}
	case "stat":
		f = func() int {
			s, err := fs.Stat()
			if err != nil {
				fail(err)
			}
			return len(s.CPU)*10 + b2i(s.BootTime > 1500000000)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown row", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
