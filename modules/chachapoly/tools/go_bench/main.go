// SPDX-License-Identifier: BSD-3-Clause

// Go side of `zig build bench-chachapoly` (modules/chachapoly/tools/bench.zig):
// times golang.org/x/crypto v0.58.0 chacha20poly1305 (RFC 8439, 96-bit nonce;
// amd64 assembly with AVX2) over the key, nonce, associated data and messages
// the Zig program writes into the directory given as the first argument, for
// the one workload named by the second (`go.enc_64`, `go.dec_1424`, ...).
// Prints one line: name, ns/op, user-mode cycles/op (0 without a cycle
// counter), bytes produced per op (tab-separated).
//
// The pairing with the C and Zig sides: the same key, nonce, 13 bytes of AD
// and message; the cipher is constructed ONCE (chacha20poly1305.New copies the
// key; the per-call state setup is inside Seal/Open, as ours is inside
// encryptInto); one op = one Seal or Open into a reused buffer (no
// allocation). Timing matches: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
)

var sink uint64
var cycFd = -1

// cyclesOpen opens a user-mode CPU cycle counter (perf_event_open with a
// 64-byte struct perf_event_attr: type HARDWARE, config CPU_CYCLES,
// exclude_kernel and exclude_hv), the same counter the C side uses.
func cyclesOpen() {
	var a [8]uint64
	a[0] = 0 | 64<<32 // type = PERF_TYPE_HARDWARE (0), size = 64
	a[1] = 0          // config = PERF_COUNT_HW_CPU_CYCLES
	a[5] = 1<<5 | 1<<6
	fd, _, e := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&a[0])), 0, ^uintptr(0), ^uintptr(0), 0, 0)
	if e == 0 {
		cycFd = int(fd)
	}
}

func cyclesRead() uint64 {
	if cycFd < 0 {
		return 0
	}
	var b [8]byte
	if n, err := syscall.Read(cycFd, b[:]); n != 8 || err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}

func timeIt(f func() uint64) (float64, float64, uint64) {
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
	bestc := ^uint64(0)
	var count uint64
	for k := 0; k < 5; k++ {
		t := time.Now()
		c0 := cyclesRead()
		for i := 0; i < n; i++ {
			count = f()
		}
		c := cyclesRead() - c0
		if d := time.Since(t); d < best {
			best = d
		}
		if c < bestc {
			bestc = c
		}
	}
	cyc := 0.0
	if cycFd >= 0 {
		cyc = float64(bestc) / float64(n)
	}
	return float64(best.Nanoseconds()) / float64(n), cyc, count
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func slurp(dir, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		die(err)
	}
	return b
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	key, nonce, ad := slurp(dir, "key32.bin"), slurp(dir, "nonce.bin"), slurp(dir, "ad.bin")
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		die(err)
	}
	fmt.Fprintln(os.Stderr, "golang.org/x/crypto v0.58.0 chacha20poly1305")
	if name == "interop" {
		msg := slurp(dir, "msg1420.bin")
		if err := os.WriteFile(filepath.Join(dir, "go_ct.bin"), aead.Seal(nil, nonce, msg, ad), 0o644); err != nil {
			die(err)
		}
		return
	}
	rest, ok := strings.CutPrefix(name, "go.")
	op, sz, ok2 := strings.Cut(rest, "_")
	size, err := strconv.Atoi(sz)
	if !ok || !ok2 || err != nil || (op != "enc" && op != "dec") {
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	msg := slurp(dir, "msg"+sz+".bin")
	sealed := aead.Seal(nil, nonce, msg, ad)
	out := make([]byte, 0, size+16)
	// The cycle counter belongs to one OS thread: keep the goroutine on it.
	runtime.LockOSThread()
	cyclesOpen()
	var ns, cyc float64
	var count uint64
	if op == "enc" {
		ns, cyc, count = timeIt(func() uint64 { return uint64(len(aead.Seal(out[:0], nonce, msg, ad))) })
	} else {
		ns, cyc, count = timeIt(func() uint64 {
			r, err := aead.Open(out[:0], nonce, sealed, ad)
			if err != nil {
				die(err)
			}
			return uint64(len(r))
		})
	}
	fmt.Printf("%s\t%.1f\t%.1f\t%d\n", name, ns, cyc, count)
}
