// SPDX-License-Identifier: MIT

// Go side of `zig build bench-procrun` (modules/procrun/tools/bench.zig): times
// os/exec (Go standard library only, no dependencies) on the same child
// commands as the Zig side. Usage: go_bench <work dir> <workload>; prints one
// line: name, ns/op, count (tab-separated). The work dir is unused (kept so
// all foreign sides share one command line).
//
//	spawn_true         200 x /bin/true, sequential: exec.Command(..).Run(), stdin,
//	                   stdout, stderr all nil (= /dev/null). count = 200 clean exits
//	capture_100m       `head -c 104857600 /dev/zero`, cmd.Output() (stdout into a
//	                   bytes buffer by a goroutine; stderr nil -> os/exec keeps a
//	                   small saver for ExitError). count = bytes
//	cat_roundtrip      32 MiB through `cat`: cmd.Stdin = bytes.Reader, cmd.Output().
//	                   count = bytes + byte sum (the sum is computed on the first
//	                   op only, outside the timing; later ops check the length)
//	capture_small_cap  the 100 MiB producer, StdoutPipe: read 1 KiB through
//	                   io.LimitReader, then io.Copy(io.Discard) to drain; count =
//	                   the 1024 kept bytes
//	concurrent_true    8 goroutines x 50 x /bin/true Run(). count = 400 clean exits
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bigBytes = 100 << 20
	catBytes = 32 << 20
	smallCap = 1024
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

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runTrue() bool {
	return exec.Command("/bin/true").Run() == nil
}

func bigProducer() *exec.Cmd {
	return exec.Command("/usr/bin/head", "-c", fmt.Sprint(bigBytes), "/dev/zero")
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	name := os.Args[2]
	fmt.Fprintln(os.Stderr, "Go os/exec", runtime.Version())

	var f func() int
	switch name {
	case "spawn_true":
		f = func() int {
			n := 0
			for i := 0; i < 200; i++ {
				if runTrue() {
					n++
				}
			}
			return n
		}
	case "capture_100m":
		f = func() int {
			out, err := bigProducer().Output()
			must(err)
			return len(out)
		}
	case "cat_roundtrip":
		in := make([]byte, catBytes)
		for i := range in {
			in[i] = byte(i*31 + 7)
		}
		var sum int
		first := true
		f = func() int {
			cmd := exec.Command("/bin/cat")
			cmd.Stdin = bytes.NewReader(in)
			out, err := cmd.Output()
			must(err)
			if len(out) != len(in) {
				must(fmt.Errorf("cat returned %d bytes", len(out)))
			}
			if first {
				first = false
				if !bytes.Equal(out, in) {
					must(fmt.Errorf("cat output differs"))
				}
				for _, b := range out {
					sum += int(b)
				}
			}
			return len(out) + sum
		}
	case "capture_small_cap":
		f = func() int {
			cmd := bigProducer()
			p, err := cmd.StdoutPipe()
			must(err)
			must(cmd.Start())
			kept, err := io.ReadAll(io.LimitReader(p, smallCap))
			must(err)
			_, err = io.Copy(io.Discard, p)
			must(err)
			must(cmd.Wait())
			return len(kept)
		}
	case "concurrent_true":
		f = func() int {
			var n atomic.Int64
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 50; i++ {
						if runTrue() {
							n.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			return int(n.Load())
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
