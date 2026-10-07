// SPDX-License-Identifier: MIT

// Go side of `zig build bench-bolt8` (modules/bolt8/tools/bench.zig): times
// lnd's `brontide` Machine, in memory, over the keys and messages that program
// writes into the work directory (the only argument), and writes what brontide
// produced from the same fixed keys (the three acts, and the first transport
// frame of each message size) for the Zig side to compare byte for byte.
//
// This file is built by `prepare.sh` next to the FETCHED brontide and keychain
// packages (module "bench"); nothing from lnd lives in this repository.
// One line per workload: name, ns/op, bytes on the wire per op. Timing matches
// the Zig side: double the batch until it takes over 100 ms, then keep the
// best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"bench/brontide"
	"bench/keychain"
)

func fixedKey(b byte) *btcec.PrivateKey {
	k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{b}, 32))
	return k
}

var (
	lsI = fixedKey(0x11) // initiator static
	lsR = fixedKey(0x21) // responder static
	eI  = fixedKey(0x12) // initiator ephemeral
	eR  = fixedKey(0x22) // responder ephemeral
)

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "go_bench: FATAL %v\n", err)
		os.Exit(3)
	}
}

func gen(k *btcec.PrivateKey) func(*brontide.Machine) {
	return brontide.EphemeralGenerator(func() (*btcec.PrivateKey, error) { return k, nil })
}

// handshake runs all three acts between a fresh initiator and responder and
// returns both machines plus the 166 act bytes.
func handshake() (*brontide.Machine, *brontide.Machine, []byte) {
	ini := brontide.NewBrontideMachine(true, &keychain.PrivKeyECDH{PrivKey: lsI}, lsR.PubKey(), gen(eI))
	rsp := brontide.NewBrontideMachine(false, &keychain.PrivKeyECDH{PrivKey: lsR}, nil, gen(eR))
	a1, err := ini.GenActOne()
	must(err)
	must(rsp.RecvActOne(a1))
	a2, err := rsp.GenActTwo()
	must(err)
	must(ini.RecvActTwo(a2))
	a3, err := ini.GenActThree()
	must(err)
	must(rsp.RecvActThree(a3))
	acts := append(append(append([]byte{}, a1[:]...), a2[:]...), a3[:]...)
	return ini, rsp, acts
}

// send encrypts msg on ini and returns the wire bytes; the buffer is left
// holding them for the receiver.
func send(ini *brontide.Machine, msg []byte, wire *bytes.Buffer) {
	wire.Reset()
	must(ini.WriteMessage(msg))
	_, err := ini.Flush(wire)
	must(err)
}

func timeIt(f func() int) (float64, int) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			f()
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gobench <work dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		must(err)
		return b
	}
	m1k, m64k := read("msg_1k.bin"), read("msg_64k.bin")

	// What brontide produces from the fixed keys, for the Zig side to compare.
	_, _, acts := handshake()
	must(os.WriteFile(filepath.Join(dir, "go_acts.bin"), acts, 0o644))
	for _, w := range []struct {
		name string
		msg  []byte
	}{{"go_frame_1k.bin", m1k}, {"go_frame_64k.bin", m64k}} {
		ini, _, _ := handshake()
		var wire bytes.Buffer
		send(ini, w.msg, &wire)
		must(os.WriteFile(filepath.Join(dir, w.name), wire.Bytes(), 0o644))
	}

	ns, n := timeIt(func() int {
		_, _, a := handshake()
		return len(a)
	})
	fmt.Printf("handshake\t%.1f\t%d\n", ns, n)

	ini, rsp, _ := handshake()
	var wire bytes.Buffer
	for _, w := range []struct {
		name string
		msg  []byte
	}{{"xfer_1k", m1k}, {"xfer_64k", m64k}} {
		ns, n := timeIt(func() int {
			send(ini, w.msg, &wire)
			size := wire.Len()
			got, err := rsp.ReadMessage(&wire)
			must(err)
			if len(got) != len(w.msg) {
				must(fmt.Errorf("short message"))
			}
			return size
		})
		fmt.Printf("%s\t%.1f\t%d\n", w.name, ns, n)
	}
}
