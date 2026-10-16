// SPDX-License-Identifier: MIT
//
// Go side of `zig build bench-aescbc` (modules/aescbc/tools/bench.zig): times
// Go's crypto/cipher CBC (the card's reference) over the key, IV and messages
// the Zig program writes into the directory given as the first argument, for
// the one workload named by the second. Prints one line: name, ns/op,
// user-mode cycles/op (0 without a counter), bytes produced per op. The run
// named `interop` writes `go_cbc.bin` (the 16 KiB message under AES-256-CBC).
// Standard library only.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var sink int

func perfOpen() int {
	var attr [16]uint64 // 128 bytes
	attr[0] = 0 | 128<<32
	attr[1] = 0           // PERF_COUNT_HW_CPU_CYCLES
	attr[5] = 1<<5 | 1<<6 // exclude_kernel, exclude_hv
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&attr[0])), 0, ^uintptr(0), ^uintptr(0), 0, 0)
	if errno != 0 {
		return -1
	}
	return int(fd)
}

func perfRead(fd int) float64 {
	if fd < 0 {
		return 0
	}
	var v uint64
	_, _, errno := syscall.Syscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&v)), 8)
	if errno != 0 {
		return 0
	}
	return float64(v)
}

func bench(name string, f func() int) {
	runtime.LockOSThread()
	fd := perfOpen()
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
	best, bestc := time.Duration(1<<63-1), 1e300
	count := 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		c0 := perfRead(fd)
		for i := 0; i < n; i++ {
			count = f()
		}
		c := perfRead(fd) - c0
		if d := time.Since(t); d < best {
			best = d
		}
		if c < bestc {
			bestc = c
		}
	}
	if fd < 0 {
		bestc = 0
	}
	fmt.Printf("%s\t%.1f\t%.1f\t%d\n", name, float64(best.Nanoseconds())/float64(n), bestc/float64(n), count)
}

func must(b []byte, err error) []byte {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return b
}

// unpad is PKCS#7 removal as a Go user writes it (crypto/cipher has none).
func unpad(b []byte) int {
	n := int(b[len(b)-1])
	if n == 0 || n > 16 {
		return -1
	}
	for _, x := range b[len(b)-n:] {
		if int(x) != n {
			return -1
		}
	}
	return len(b) - n
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, w := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, runtime.Version(), "crypto/cipher")
	key := must(os.ReadFile(filepath.Join(dir, "key32.bin")))
	iv := must(os.ReadFile(filepath.Join(dir, "iv.bin")))
	msg := must(os.ReadFile(filepath.Join(dir, "msg16384.bin")))
	ct := must(os.ReadFile(filepath.Join(dir, "ct16384.bin")))
	pad := must(os.ReadFile(filepath.Join(dir, "pad1024.bin")))
	blk, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := make([]byte, len(msg))
	if w == "interop" {
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, msg)
		must(nil, os.WriteFile(filepath.Join(dir, "go_cbc.bin"), out, 0o644))
		return
	}
	enc := func(n int) func() int {
		return func() int {
			cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out[:n], msg[:n])
			return n
		}
	}
	dec := func(n int) func() int {
		return func() int {
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out[:n], ct[:n])
			return n
		}
	}
	switch w {
	case "enc_16384":
		bench(w, enc(16384))
	case "dec_16384":
		bench(w, dec(16384))
	case "enc_64":
		bench(w, enc(64))
	case "dec_64":
		bench(w, dec(64))
	case "oneshot_dec_1024":
		bench(w, func() int {
			b, _ := aes.NewCipher(key)
			cipher.NewCBCDecrypter(b, iv).CryptBlocks(out[:1024], ct[:1024])
			return 1024
		})
	case "stream_enc_1008":
		// Padding by hand, as a Go user must (crypto/cipher has none).
		buf := make([]byte, 1024)
		bench(w, func() int {
			copy(buf, msg[:1008])
			for i := 1008; i < 1024; i++ {
				buf[i] = 16
			}
			cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out[:1024], buf)
			return 1024
		})
	case "pkcs7_dec_1024":
		bench(w, func() int {
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out[:1024], pad)
			return unpad(out[:1024])
		})
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", w)
		os.Exit(2)
	}
}
