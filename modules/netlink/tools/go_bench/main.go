// SPDX-License-Identifier: MIT

// Go side of `zig build bench-netlink` (modules/netlink/tools/bench.zig):
// times github.com/vishvananda/netlink v1.3.1 (Apache-2.0) over the corpus the
// Zig program writes into the directory given as the first argument, for the
// one workload named by the second. Prints one line: name, ns/op, result
// count (tab-separated). One op = all 64 inputs. See bench.zig for what each
// workload does and how the count is formed.
//
// The decoders and the route encoder of vishvananda/netlink are unexported
// (the package decodes inside its dump loops and encodes inside RouteAdd,
// which also sends); link_stub.go reaches them with go:linkname, so what is
// timed is that package's own decode/encode code, not a re-implementation.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
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

func sum(b []byte) uint64 {
	var t uint64
	for _, c := range b {
		t += uint64(c)
	}
	return t
}

func decodeLink(m []byte) uint64 {
	l, err := netlink.LinkDeserialize(&unix.NlMsghdr{Type: unix.RTM_NEWLINK}, m)
	if err != nil {
		die(err)
	}
	a := l.Attrs()
	t := uint64(a.Index) + uint64(a.MTU) + uint64(a.TxQLen) + uint64(a.OperState) +
		uint64(a.ParentIndex) + uint64(a.MasterIndex) + sum([]byte(a.Name)) + sum(a.HardwareAddr)
	if a.Statistics != nil {
		t += a.Statistics.RxBytes + a.Statistics.TxBytes
	}
	switch v := l.(type) {
	case *netlink.Vlan:
		t += uint64(v.VlanId)
	case *netlink.Vxlan:
		t += uint64(v.VxlanId) + uint64(v.Port) + uint64(v.TTL) + sum(v.Group) + uint64(v.VtepDevIndex)
	}
	return t
}

func decodeAddr(m []byte) uint64 {
	a, _, err := parseAddr(m)
	if err != nil {
		die(err)
	}
	ones, _ := a.Mask.Size()
	return uint64(a.LinkIndex) + uint64(ones) + uint64(a.Scope) + sum(a.IP) + uint64(a.ValidLft) +
		uint64(a.PreferedLft) + uint64(a.Flags) + sum([]byte(a.Label))
}

func decodeRoute(m []byte) uint64 {
	r, err := deserializeRoute(m)
	if err != nil {
		die(err)
	}
	t := uint64(r.LinkIndex) + uint64(r.Priority) + uint64(r.Table) + uint64(r.MTU) + sum(r.Gw) + sum(r.Src)
	if r.Dst != nil {
		t += sum(r.Dst.IP)
	}
	for _, nh := range r.MultiPath {
		t += uint64(nh.LinkIndex) + uint64(nh.Hops) + 1 + sum(nh.Gw)
	}
	return t
}

func decodeNeigh(m []byte) uint64 {
	n, err := netlink.NeighDeserialize(m)
	if err != nil {
		die(err)
	}
	return uint64(n.LinkIndex) + uint64(n.State) + uint64(n.Flags) + uint64(n.Type) + sum(n.IP) + sum(n.HardwareAddr)
}

// One encode record: dst[4] plen gw[4] oif prio table mtu (u32s little-endian).
const recLen = 4 + 1 + 4 + 4 + 4 + 4 + 4

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "github.com/vishvananda/netlink v1.3.1")
	var f func() uint64
	decoders := map[string]func([]byte) uint64{
		"dec_link": decodeLink, "dec_addr": decodeAddr, "dec_route": decodeRoute, "dec_neigh": decodeNeigh,
	}
	if dec, ok := decoders[name]; ok {
		msgs := readMsgs(filepath.Join(dir, name+".bin"))
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				t += dec(m)
			}
			return t
		}
	} else if name == "enc_route" {
		b, err := os.ReadFile(filepath.Join(dir, "enc_route.bin"))
		if err != nil {
			die(err)
		}
		var routes []netlink.Route
		for i := 0; i+recLen <= len(b); i += recLen {
			r := b[i : i+recLen]
			plen := int(r[4])
			routes = append(routes, netlink.Route{
				Dst:       &net.IPNet{IP: net.IP(r[0:4]), Mask: net.CIDRMask(plen, 32)},
				Gw:        net.IP(r[5:9]),
				LinkIndex: int(le32(r[9:])),
				Priority:  int(le32(r[13:])),
				Table:     int(le32(r[17:])),
				MTU:       int(le32(r[21:])),
				Protocol:  unix.RTPROT_BOOT,
			})
		}
		f = func() uint64 {
			var t uint64
			for i := range routes {
				// What RouteAdd does before it sends: a request with the
				// create flags, the default rtmsg, the route's attributes.
				req := nl.NewNetlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
				msg := nl.NewRtMsg()
				if err := prepareRouteReq(nil, &routes[i], req, msg); err != nil {
					die(err)
				}
				out := req.Serialize()
				// The sequence number is the process's counter: skip the header.
				t += uint64(len(out)) + sum(out[16:])
			}
			return t
		}
	} else {
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
