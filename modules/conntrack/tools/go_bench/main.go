// SPDX-License-Identifier: MIT

// Go side of `zig build bench-conntrack` (modules/conntrack/tools/bench.zig):
// times github.com/ti-mo/conntrack v0.6.0 (MIT) decoding the corpus the Zig
// program writes into the directory given as the first argument, for the one
// workload named by the second. Prints one line: name, ns/op, count
// (tab-separated). One op = all 64 flows. See bench.zig for what each
// workload does and how the count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
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

// readFrames reads the Zig side's length-prefixed records (u16 big-endian
// length, then the bytes).
func readFrames(path string) [][]byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	var out [][]byte
	for len(b) > 0 {
		n := int(b[0])<<8 | int(b[1])
		out = append(out, b[2:2+n])
		b = b[2+n:]
	}
	return out
}

// tally adds up, per decoded flow, exactly what the Zig side adds up.
func tally(f *conntrack.Flow) uint64 {
	var t uint64
	t += uint64(f.TupleOrig.Proto.SourcePort) + uint64(f.TupleOrig.Proto.DestinationPort)
	t += uint64(f.TupleReply.Proto.SourcePort) + uint64(f.TupleReply.Proto.DestinationPort)
	t += uint64(f.Status) + uint64(f.Timeout) + uint64(f.Mark) + uint64(f.ID) + uint64(f.Use)
	t += uint64(f.Zone)
	t += f.CountersOrig.Packets + f.CountersOrig.Bytes + f.CountersReply.Packets + f.CountersReply.Bytes
	if f.ProtoInfo.TCP != nil {
		t += uint64(f.ProtoInfo.TCP.State)
	}
	if !f.Timestamp.Start.IsZero() {
		t += uint64(f.Timestamp.Start.UnixNano())
	}
	s := f.TupleOrig.IP.SourceAddress
	d := f.TupleOrig.IP.DestinationAddress
	if s.Is4() {
		a := s.As4()
		t += uint64(a[0])
	} else {
		a := s.As16()
		t += uint64(a[0])
	}
	if d.Is4() {
		a := d.As4()
		t += uint64(a[3])
	} else {
		a := d.As16()
		t += uint64(a[15])
	}
	return t
}

func decode(m netlink.Message) uint64 {
	var e conntrack.Event
	if err := e.Unmarshal(m); err != nil {
		die(err)
	}
	return tally(e.Flow)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench DIR WORKLOAD")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	var f func() uint64
	switch name {
	case "dec_flow":
		// One message each, already framed: the typed decode alone.
		var msgs []netlink.Message
		for _, p := range readFrames(filepath.Join(dir, "dec_flow.bin")) {
			msgs = append(msgs, netlink.Message{
				Header: netlink.Header{Length: uint32(16 + len(p)), Type: 0x0100, Flags: netlink.Create | netlink.Excl},
				Data:   p,
			})
		}
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				t += decode(m)
			}
			return t
		}
	case "dec_dgram":
		// Whole datagrams of 16 messages: framing and decode, as a dump
		// reply arrives.
		dgrams := readFrames(filepath.Join(dir, "dec_dgram.bin"))
		f = func() uint64 {
			var t uint64
			for _, d := range dgrams {
				// x/netlink exports the per-message parser only: walk the
				// datagram by nlmsg_len (little-endian host, 4-byte aligned).
				for len(d) >= 16 {
					n := int(binary.LittleEndian.Uint32(d[0:4]))
					var m netlink.Message
					if err := m.UnmarshalBinary(d[:n]); err != nil {
						die(err)
					}
					t += decode(m)
					d = d[(n+3)&^3:]
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
