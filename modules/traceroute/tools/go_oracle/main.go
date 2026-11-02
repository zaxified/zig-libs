// SPDX-License-Identifier: MIT

// Differential oracle for modules/traceroute: golang.org/x/net/icmp (BSD-3-Clause)
// as an independent implementation of the RFC 5837 Interface Information
// object. The inputs are OURS (the case tables below); Go marshals each one
// into a Time Exceeded / Destination Unreachable multipart message, parses
// that message back with its own decoder, and the parsed fields are written
// out as a Zig file that the module's tests replay with no Go.
//
//	cd modules/traceroute/tools/go_oracle
//	GOFLAGS=-mod=mod GOPROXY=off go run . -out ../../src/if_info_vectors.zig
//
// x/net's InterfaceInfo can only marshal a name or an MTU together with an
// ifIndex; the other combinations are encoded byte by byte here from RFC 5837
// section 4 and wrapped in the same multipart framing through RawExtension.
// Those cases are marked "raw" in their id, and Go's parser still gives the
// verdict for them.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	protoICMP   = 1
	protoICMPv6 = 58

	bitIfIndex = 0x08
	bitAddr    = 0x04
	bitName    = 0x02
	bitMTU     = 0x01
)

// spec is one Interface Information object to emit.
type spec struct {
	role    int
	ifindex int // 0 = absent
	addr    bool
	name    string // "" = absent
	mtu     int    // 0 = absent
}

func (s spec) ctype() int {
	t := s.role << 6
	if s.ifindex != 0 {
		t |= bitIfIndex
	}
	if s.addr {
		t |= bitAddr
	}
	if s.name != "" {
		t |= bitName
	}
	if s.mtu != 0 {
		t |= bitMTU
	}
	return t
}

func (s spec) viaLib() bool { return s.ifindex != 0 || (s.name == "" && s.mtu == 0) }

var names = []string{"e", "xe0", "ge-0/0/1", "Ethernet1/12", "Loopback0", "TenGigabitEthernet0/1/0/12.4094", strings.Repeat("n", 63)}

var (
	v4addr = net.IPv4(198, 51, 100, 7)
	v6addr = net.ParseIP("2001:db8:0:1::7")
)

// rawObject encodes s per RFC 5837 section 4 (field order ifIndex, IP address,
// name, MTU; the name sub-object's length octet counts itself and is a
// multiple of four).
func rawObject(s spec, v6 bool) []byte {
	var body []byte
	if s.ifindex != 0 {
		body = binary.BigEndian.AppendUint32(body, uint32(s.ifindex))
	}
	if s.addr {
		if v6 {
			body = binary.BigEndian.AppendUint16(body, 2)
			body = append(body, 0, 0)
			body = append(body, v6addr.To16()...)
		} else {
			body = binary.BigEndian.AppendUint16(body, 1)
			body = append(body, 0, 0)
			body = append(body, v4addr.To4()...)
		}
	}
	if s.name != "" {
		l := (1 + len(s.name) + 3) &^ 3
		sub := make([]byte, l)
		sub[0] = byte(l)
		copy(sub[1:], s.name)
		body = append(body, sub...)
	}
	if s.mtu != 0 {
		body = binary.BigEndian.AppendUint32(body, uint32(s.mtu))
	}
	b := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(b, uint16(4+len(body)))
	b[2], b[3] = 2, byte(s.ctype())
	return append(b, body...)
}

func (s spec) ext(v6 bool) icmp.Extension {
	if !s.viaLib() {
		return &icmp.RawExtension{Data: rawObject(s, v6)}
	}
	ifi := &icmp.InterfaceInfo{Class: 2, Type: s.ctype()}
	if s.ifindex != 0 {
		ifi.Interface = &net.Interface{Index: s.ifindex, Name: s.name, MTU: s.mtu}
	}
	if s.addr {
		if v6 {
			ifi.Addr = &net.IPAddr{IP: v6addr}
		} else {
			ifi.Addr = &net.IPAddr{IP: v4addr}
		}
	}
	return ifi
}

// quoted is the original datagram: an IP header and the first 8 bytes of a UDP
// datagram, which x/net pads to the 128 bytes RFC 4884 requires.
func quoted(v6 bool) []byte {
	if v6 {
		b := make([]byte, 48)
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:], 8)
		b[6], b[7] = 17, 1
		copy(b[8:], net.ParseIP("2001:db8::1").To16())
		copy(b[24:], net.ParseIP("2001:db8:ffff::2").To16())
		binary.BigEndian.PutUint16(b[40:], 40000)
		binary.BigEndian.PutUint16(b[42:], 33434)
		binary.BigEndian.PutUint16(b[44:], 8)
		return b
	}
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 28)
	b[8], b[9] = 1, 17
	copy(b[12:], []byte{10, 0, 0, 1})
	copy(b[16:], []byte{10, 0, 1, 2})
	binary.BigEndian.PutUint16(b[20:], 40000)
	binary.BigEndian.PutUint16(b[22:], 33434)
	binary.BigEndian.PutUint16(b[24:], 8)
	return b
}

type parsed struct {
	role    int
	ifindex *int
	addr    []byte
	name    string
	mtu     *int
}

type testCase struct {
	id    string
	v6    bool
	bytes []byte
	infos []parsed
}

func build(id string, v6, dest bool, exts []icmp.Extension) testCase {
	var typ icmp.Type
	proto := protoICMP
	switch {
	case !v6 && !dest:
		typ = ipv4.ICMPTypeTimeExceeded
	case !v6 && dest:
		typ = ipv4.ICMPTypeDestinationUnreachable
	case v6 && !dest:
		typ = ipv6.ICMPTypeTimeExceeded
		proto = protoICMPv6
	default:
		typ = ipv6.ICMPTypeDestinationUnreachable
		proto = protoICMPv6
	}
	var body icmp.MessageBody
	if dest {
		body = &icmp.DstUnreach{Data: quoted(v6), Extensions: exts}
	} else {
		body = &icmp.TimeExceeded{Data: quoted(v6), Extensions: exts}
	}
	m := icmp.Message{Type: typ, Code: 0, Body: body}
	b, err := m.Marshal(nil)
	if err != nil {
		fatalf("%s: marshal: %v", id, err)
	}
	back, err := icmp.ParseMessage(proto, b)
	if err != nil {
		fatalf("%s: x/net cannot parse its own message: %v", id, err)
	}
	var got []icmp.Extension
	switch bd := back.Body.(type) {
	case *icmp.TimeExceeded:
		got = bd.Extensions
	case *icmp.DstUnreach:
		got = bd.Extensions
	default:
		fatalf("%s: parsed body %T", id, back.Body)
	}
	tc := testCase{id: id, v6: v6, bytes: b}
	for _, e := range got {
		ifi, ok := e.(*icmp.InterfaceInfo)
		if !ok {
			continue
		}
		p := parsed{role: ifi.Type >> 6}
		if ifi.Type&bitIfIndex != 0 {
			v := ifi.Interface.Index
			p.ifindex = &v
		}
		if ifi.Type&bitAddr != 0 {
			if ifi.Addr.IP.To4() != nil && !v6 {
				p.addr = []byte(ifi.Addr.IP.To4())
			} else {
				p.addr = []byte(ifi.Addr.IP.To16())
			}
		}
		if ifi.Type&bitName != 0 {
			p.name = ifi.Interface.Name
		}
		if ifi.Type&bitMTU != 0 {
			v := ifi.Interface.MTU
			p.mtu = &v
		}
		tc.infos = append(tc.infos, p)
	}
	return tc
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "go_oracle: "+f+"\n", a...)
	os.Exit(1)
}

// crossCheck: the parsed fields must be what was marshalled (a disagreement
// between x/net's encoder and decoder is not a vector, it is a bug to read).
func crossCheck(tc testCase, specs []spec) {
	if len(tc.infos) != len(specs) {
		fatalf("%s: %d objects in, %d out", tc.id, len(specs), len(tc.infos))
	}
	for i, s := range specs {
		p := tc.infos[i]
		ok := p.role == s.role && p.name == s.name &&
			(p.ifindex == nil) == (s.ifindex == 0) && (s.ifindex == 0 || *p.ifindex == s.ifindex) &&
			(p.mtu == nil) == (s.mtu == 0) && (s.mtu == 0 || *p.mtu == s.mtu) &&
			(p.addr == nil) == !s.addr
		if !ok {
			fatalf("%s: object %d: in %+v, parsed %+v", tc.id, i, s, p)
		}
	}
}

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	flag.Parse()

	var cases []testCase
	add := func(id string, v6, dest bool, specs ...spec) {
		exts := make([]icmp.Extension, 0, len(specs)+1)
		for _, s := range specs {
			exts = append(exts, s.ext(v6))
		}
		tc := build(id, v6, dest, exts)
		crossCheck(tc, specs)
		cases = append(cases, tc)
	}
	fam := func(v6 bool) string {
		if v6 {
			return "v6"
		}
		return "v4"
	}

	// Every role x every subset of {ifIndex, address, name, MTU}, both
	// families; the message type alternates so both are covered for every
	// role and every field.
	n := 0
	for _, v6 := range []bool{false, true} {
		for role := 0; role < 4; role++ {
			for mask := 0; mask < 16; mask++ {
				s := spec{role: role}
				if mask&1 != 0 {
					s.ifindex = 1 + 1000*role + mask*37
				}
				s.addr = mask&2 != 0
				if mask&4 != 0 {
					s.name = names[n%len(names)]
				}
				if mask&8 != 0 {
					s.mtu = []int{576, 1280, 1500, 9000, 65535}[n%5]
				}
				dest := n%2 == 1
				kind := "te"
				if dest {
					kind = "du"
				}
				id := fmt.Sprintf("%s %s role%d mask%02d", fam(v6), kind, role, mask)
				if !s.viaLib() {
					id += " raw"
				}
				add(id, v6, dest, s)
				n++
			}
		}
	}

	// Two and four objects in one message, in x/net's emission order.
	for _, v6 := range []bool{false, true} {
		in := spec{role: 0, ifindex: 12, addr: true, name: "xe-0/0/1", mtu: 1500}
		outg := spec{role: 2, ifindex: 13, addr: true, name: "xe-0/0/2", mtu: 9000}
		sub := spec{role: 1, ifindex: 120, name: "xe-0/0/1.120"}
		nh := spec{role: 3, addr: true}
		add(fam(v6)+" te in+out", v6, false, in, outg)
		add(fam(v6)+" du four roles", v6, true, in, sub, outg, nh)
		add(fam(v6)+" te out+in order", v6, false, outg, in)
	}

	// An MPLS label stack (class 1) ahead of the object: the walker must skip
	// it.
	for _, v6 := range []bool{false, true} {
		exts := []icmp.Extension{
			&icmp.MPLSLabelStack{Class: 1, Type: 1, Labels: []icmp.MPLSLabel{{Label: 300, TC: 1, S: true, TTL: 64}}},
			spec{role: 0, ifindex: 7, name: "lo0"}.ext(v6),
		}
		tc := build(fam(v6)+" te mpls then if", v6, false, exts)
		crossCheck(tc, []spec{{role: 0, ifindex: 7, name: "lo0"}})
		cases = append(cases, tc)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/traceroute/tools/go_oracle (%s, golang.org/x/net v0.61.0) -- do not hand-edit.\n", runtime.Version())
	fmt.Fprintf(&b, "//! icmp.Message.Marshal output carrying RFC 5837 Interface Information objects, with\n")
	fmt.Fprintf(&b, "//! the fields x/net's own parser reads back, replayed by `root.zig`'s tests.\n")
	fmt.Fprintf(&b, "//! Regenerate with the command in tools/go_oracle/main.go.\n\n")
	b.WriteString(`pub const Info = struct {
    role: u2,
    ifindex: ?u32 = null,
    /// 4 or 16 bytes.
    addr: ?[]const u8 = null,
    name: []const u8 = "",
    mtu: ?u32 = null,
};

pub const Case = struct {
    id: []const u8,
    v6: bool,
    /// The ICMP message, from its type octet on, as hex.
    hex: []const u8,
    infos: []const Info,
};

pub const cases = [_]Case{
`)
	for _, tc := range cases {
		fmt.Fprintf(&b, "    .{ .id = %q, .v6 = %v, .hex = \"%s\", .infos = &.{", tc.id, tc.v6, hex.EncodeToString(tc.bytes))
		for i, p := range tc.infos {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " .{ .role = %d", p.role)
			if p.ifindex != nil {
				fmt.Fprintf(&b, ", .ifindex = %d", *p.ifindex)
			}
			if p.addr != nil {
				fmt.Fprintf(&b, ", .addr = \"%s\"", hexEscape(p.addr))
			}
			if p.name != "" {
				fmt.Fprintf(&b, ", .name = %q", p.name)
			}
			if p.mtu != nil {
				fmt.Fprintf(&b, ", .mtu = %d", *p.mtu)
			}
			b.WriteString(" }")
		}
		b.WriteString(" } },\n")
	}
	b.WriteString("};\n")

	if *out == "" {
		os.Stdout.Write(b.Bytes())
		return
	}
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
		fatalf("%v", err)
	}
	fmt.Fprintf(os.Stderr, "go_oracle: %d cases -> %s\n", len(cases), *out)
}

func hexEscape(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		fmt.Fprintf(&s, `\x%02x`, c)
	}
	return s.String()
}
