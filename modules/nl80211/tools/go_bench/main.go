// SPDX-License-Identifier: MIT

// Go side of `zig build bench-nl80211` (modules/nl80211/tools/bench.zig):
// times github.com/mdlayher/wifi v0.10.0 (MIT) decoding the corpus the Zig
// program writes into the directory given as the first argument, for the one
// workload named by the second. Prints one line: name, ns/op, count
// (tab-separated). One op = all 64 messages. See bench.zig for what each
// workload does and how the count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/wifi"
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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench DIR WORKLOAD")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	frames := readFrames(filepath.Join(dir, name+".bin"))
	var f func() uint64
	switch name {
	case "dec_iface":
		// The interface messages of one dump, decoded in one call (the
		// package's exported entry point takes the whole list).
		var msgs []genetlink.Message
		for _, p := range frames {
			msgs = append(msgs, genetlink.Message{Data: p})
		}
		f = func() uint64 {
			ifis, err := wifi.ParseInterfaces(msgs)
			if err != nil {
				die(err)
			}
			var t uint64
			for _, i := range ifis {
				t += uint64(i.Index) + uint64(i.PHY) + uint64(i.Type) + uint64(i.Device)
				t += uint64(i.Frequency) + uint64(i.ChannelWidth)
				t += uint64(len(i.Name)) + uint64(i.Name[0])
				t += uint64(i.HardwareAddr[0]) + uint64(i.HardwareAddr[5])
			}
			return t
		}
	case "dec_station":
		// One station message each; the exported parser takes the attribute
		// bytes of one.
		f = func() uint64 {
			var t uint64
			for _, p := range frames {
				s, err := wifi.ParseStationInfo(p)
				if err != nil {
					die(err)
				}
				t += uint64(s.InterfaceIndex) + uint64(s.HardwareAddr[0]) + uint64(s.HardwareAddr[5])
				t += uint64(s.Connected / time.Second) + uint64(s.Inactive/time.Millisecond)
				t += uint64(s.ReceivedBytes) + uint64(s.TransmittedBytes)
				t += uint64(s.ReceivedPackets) + uint64(s.TransmittedPackets)
				t += uint64(s.TransmitRetries) + uint64(s.TransmitFailed) + uint64(s.BeaconLoss)
				t += uint64(int64(s.Signal)+200) + uint64(int64(s.SignalAverage)+200)
				// Bitrate: bits/s here, 100 kbit/s units on the Zig side.
				t += uint64(s.ReceiveBitrate/100000) + uint64(s.TransmitBitrate/100000)
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
