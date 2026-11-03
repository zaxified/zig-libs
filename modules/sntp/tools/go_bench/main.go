// SPDX-License-Identifier: MIT

// Go side of `zig build bench-sntp` (modules/sntp/tools/bench.zig): times
// beevik/ntp v1.6.0 over the corpus the Zig program writes into the directory
// given as the first argument, for the workload named by the second. Prints
// one line: name, ns/op, result count (tab-separated). One op = 64 complete
// exchanges.
//
// beevik/ntp exports no codec: its request encoder, response parser and
// offset/RTT arithmetic are unexported steps inside QueryWithOptions. So the
// whole of that function runs, with the network cut out through its own hooks:
// Dialer returns an in-memory net.Conn (Write captures the request, Read hands
// back the canned reply with the request's random origin cookie patched in),
// GetSystemTime returns two fixed instants (T1, T4). What is timed per
// exchange: build the request (incl. its 8-byte crypto/rand cookie), parse the
// reply, check the origin, offset, RTT, MinError, RootDistance, then
// Response.Validate. No socket syscall, no real clock read.
//
// The Go module cache must hold beevik/ntp v1.6.0 and its requirements
// (GOPROXY=off); see modules/sntp/tools/README.md.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/beevik/ntp"
)

var sink uint64

type fakeConn struct {
	reply []byte
	req   [48]byte
	have  bool
}

func (c *fakeConn) Read(b []byte) (int, error) {
	copy(b, c.reply)
	copy(b[24:32], c.req[40:48]) // origin = the request's transmit cookie
	return len(c.reply), nil
}
func (c *fakeConn) Write(b []byte) (int, error) { copy(c.req[:], b); return len(b), nil }
func (c *fakeConn) Close() error                { return nil }
func (c *fakeConn) LocalAddr() net.Addr         { return nil }
func (c *fakeConn) RemoteAddr() net.Addr        { return nil }
func (c *fakeConn) SetDeadline(time.Time) error { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

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

func main() {
	if len(os.Args) < 3 {
		die(fmt.Errorf("usage: go_bench DIR NAME"))
	}
	dir, name := os.Args[1], os.Args[2]
	if name != "exchange" {
		die(fmt.Errorf("unknown workload %q", name))
	}
	fmt.Fprintln(os.Stderr, "beevik/ntp v1.6.0, Go full QueryWithOptions over an in-memory Conn")
	msgs := readMsgs(filepath.Join(dir, "replies.bin"))
	hdr, err := os.ReadFile(filepath.Join(dir, "clock.bin")) // t1 unix ns, t4 unix ns (u64 BE each)
	if err != nil {
		die(err)
	}
	t1 := time.Unix(0, int64(binary.BigEndian.Uint64(hdr[0:8]))).UTC()
	t4 := time.Unix(0, int64(binary.BigEndian.Uint64(hdr[8:16]))).UTC()

	conn := &fakeConn{}
	calls := 0
	opt := ntp.QueryOptions{
		Version: 4,
		Timeout: time.Second,
		Dialer:  func(string, string) (net.Conn, error) { return conn, nil },
		GetSystemTime: func() time.Time {
			calls++
			if calls&1 == 1 {
				return t1
			}
			return t4
		},
	}
	once := func() uint64 {
		var t uint64
		for _, m := range msgs {
			conn.reply = m
			calls = 0
			r, err := ntp.QueryWithOptions("192.0.2.1", opt)
			if err != nil {
				t += 1_000_000_000_000
				continue
			}
			if r.Validate() != nil {
				t += 1_000_000_000_000
				continue
			}
			t += uint64(r.ClockOffset) + uint64(r.RTT) + uint64(r.MinError) + uint64(r.RootDistance)
		}
		return t
	}
	ns, count := timeIt(once)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
