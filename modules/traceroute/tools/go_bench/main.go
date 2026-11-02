// SPDX-License-Identifier: BSD-3-Clause

// Go side of `zig build bench-traceroute` (modules/traceroute/tools/bench.zig):
// times golang.org/x/net/icmp v0.61.0 over the corpus the Zig program writes
// into the directory given as the first argument, for the one workload named
// by the second. Prints one line: name, ns/op, result count (tab-separated).
// One op = all 64 inputs. See bench.zig for what each workload does and how
// the count is formed.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protoICMP   = 1 // iana.ProtocolICMP (internal to x/net)
	payloadSize = 24
	notOurs     = 1000000
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

func readMsgs(path string) [][]byte {
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

// checksum is a copy of x/net/icmp's unexported function (RFC 1071).
// ParseMessage never verifies the ICMP checksum; ours does, so the Go side
// does it too.
func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

// decode returns notOurs for a packet that is not a Time Exceeded /
// Destination Unreachable quoting an echo request of ours (the Zig side
// returns the same for what parseV4 does not call an ICMP error), else the
// sum described in bench.zig.
func decode(b []byte) uint64 {
	if len(b) < 8 || checksum(b) != 0 {
		return notOurs
	}
	m, err := icmp.ParseMessage(protoICMP, b)
	if err != nil {
		return notOurs
	}
	typ, ok := m.Type.(ipv4.ICMPType)
	if !ok {
		return notOurs
	}
	var data []byte
	var exts []icmp.Extension
	switch body := m.Body.(type) {
	case *icmp.TimeExceeded:
		data, exts = body.Data, body.Extensions
	case *icmp.DstUnreach:
		data, exts = body.Data, body.Extensions
	default:
		return notOurs
	}
	h, err := ipv4.ParseHeader(data)
	if err != nil || len(data) < h.Len+8 {
		return notOurs
	}
	q, err := icmp.ParseMessage(protoICMP, data[h.Len:])
	if err != nil || q.Type != ipv4.ICMPTypeEcho {
		return notOurs
	}
	e, ok := q.Body.(*icmp.Echo)
	if !ok {
		return notOurs
	}
	t := uint64(typ) + uint64(m.Code) + uint64(e.ID) + uint64(e.Seq)
	for _, c := range h.Dst.To4() {
		t += uint64(c)
	}
	for _, x := range exts {
		if ls, ok := x.(*icmp.MPLSLabelStack); ok {
			for _, l := range ls.Labels {
				t += uint64(l.Label) + uint64(l.TC) + uint64(l.TTL)
				if l.S {
					t++
				}
			}
			break
		}
	}
	return t
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "golang.org/x/net/icmp v0.61.0")
	var f func() uint64
	switch name {
	case "enc_echo_v4", "enc_echo_v6":
		b, err := os.ReadFile(filepath.Join(dir, "enc_echo.bin"))
		if err != nil {
			die(err)
		}
		var ids [][2]int
		for i := 0; i+4 <= len(b); i += 4 {
			ids = append(ids, [2]int{int(b[i])<<8 | int(b[i+1]), int(b[i+2])<<8 | int(b[i+3])})
		}
		var typ icmp.Type = ipv4.ICMPTypeEcho
		if name == "enc_echo_v6" {
			typ = ipv6.ICMPTypeEchoRequest
		}
		zeros := make([]byte, payloadSize)
		f = func() uint64 {
			var t uint64
			for _, id := range ids {
				msg := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id[0], Seq: id[1], Data: zeros}}
				out, err := msg.Marshal(nil)
				if err != nil {
					die(err)
				}
				for _, c := range out {
					t += uint64(c)
				}
			}
			return t
		}
	case "dec_te", "dec_ext":
		msgs := readMsgs(filepath.Join(dir, name+".bin"))
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				t += decode(m)
			}
			return t
		}
	case "dec_garbage":
		msgs := readMsgs(filepath.Join(dir, name+".bin"))
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				if decode(m) == notOurs {
					t++
				} else {
					t += 1000
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
