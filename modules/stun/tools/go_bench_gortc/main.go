// SPDX-License-Identifier: BSD-3-Clause

// Go side of `zig build bench-stun`: the same program as ../go_bench/main.go against
// gortc.io/stun v1.23.0 (the "fastest" candidate), over the corpus the Zig
// program writes into the directory given as the first argument, for the one
// workload named by the second. Prints one line: name, ns/op, result count
// (tab-separated). One op = all 64 inputs. See bench.zig for what each
// workload does and how the count is formed.
//
// `../go_bench_gortc/main.go` is this file with the import line changed to
// gortc.io/stun v1.23.0 (pion's ancestor, same API): keep them in step.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	stun "gortc.io/stun"
)

const (
	rejected = 1
	accepted = 1000
	password = "VOkJxbRl1RmTxUk/WvJxBt"
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

// readMsgs reads the corpus: each message is a 2-byte big-endian length and
// the bytes.
func readMsgs(path string) [][]byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	var msgs [][]byte
	for len(b) >= 2 {
		n := int(b[0])<<8 | int(b[1])
		if len(b) < 2+n {
			die(fmt.Errorf("%s: truncated corpus", path))
		}
		msgs = append(msgs, b[2:2+n])
		b = b[2+n:]
	}
	return msgs
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench DIR WORKLOAD")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	var f func() uint64
	switch name {
	case "enc_req":
		txids := readMsgs(filepath.Join(dir, "enc_req.bin"))
		m := stun.New()
		integrity := stun.NewShortTermIntegrity(password)
		f = func() uint64 {
			var t uint64
			for _, id := range txids {
				var tid [stun.TransactionIDSize]byte
				copy(tid[:], id)
				if err := m.Build(stun.NewTransactionIDSetter(tid), stun.BindingRequest,
					stun.NewSoftware("zig-libs bench"), stun.NewUsername("evtj:h6vY"),
					integrity, stun.Fingerprint); err != nil {
					die(err)
				}
				for _, c := range m.Raw {
					t += uint64(c)
				}
			}
			return t
		}
	case "dec_resp":
		msgs := readMsgs(filepath.Join(dir, name+".bin"))
		m := stun.New()
		integrity := stun.NewShortTermIntegrity(password)
		f = func() uint64 {
			var t uint64
			for _, raw := range msgs {
				m.Raw = append(m.Raw[:0], raw...)
				if err := m.Decode(); err != nil {
					die(err)
				}
				var xa stun.XORMappedAddress
				if err := xa.GetFrom(m); err != nil {
					die(err)
				}
				ip := xa.IP
				if v4 := ip.To4(); v4 != nil {
					ip = v4
				}
				t += uint64(xa.Port)
				for _, c := range ip {
					t += uint64(c)
				}
				if stun.Fingerprint.Check(m) == nil {
					t++
				}
				if integrity.Check(m) == nil {
					t++
				}
			}
			return t
		}
	case "dec_garbage":
		msgs := readMsgs(filepath.Join(dir, name+".bin"))
		m := stun.New()
		f = func() uint64 {
			var t uint64
			for _, raw := range msgs {
				m.Raw = append(m.Raw[:0], raw...)
				if m.Decode() != nil {
					t += rejected
				} else {
					t += accepted
				}
			}
			return t
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
