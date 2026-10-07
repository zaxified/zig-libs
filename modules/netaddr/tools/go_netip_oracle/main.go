// SPDX-License-Identifier: MIT

// Differential oracle for netaddr's Go-parity surface: Go's net/netip and
// go4.org/netipx (both BSD-3-Clause, the module's declared reference), run
// as black boxes through their public API. The inputs are OURS -- crafted
// tables and seeded random cases below; Go only answers them, and the
// answers are written out as a Zig file that `src/netip_oracle_test.zig`
// replays hermetically. No Go source was read or ported.
//
//	cd modules/netaddr/tools/go_netip_oracle
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -out ../../src/netip_vectors.zig
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -check ../../src/netip_vectors.zig
//
// Needs go4.org/netipx (pinned by go.mod/go.sum) in the module cache:
// `GOTOOLCHAIN=go1.26.0 go mod download` once, with network; and `zig` on
// PATH (the output goes through `zig fmt --stdin`).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"go4.org/netipx"
)

const seed = 0x6e6574697078 // "netipx"

var rnd = rand.New(rand.NewPCG(seed, seed^0x5a5a))

// ── address generators ──────────────────────────────────────────────────────

var v4Special = []string{
	"0.0.0.0", "0.0.0.1", "255.255.255.255", "255.255.255.254", "127.0.0.1", "127.255.255.255",
	"169.254.0.0", "169.254.255.255", "224.0.0.0", "224.0.0.255", "224.0.1.0", "239.255.255.255",
	"10.0.0.0", "172.16.0.0", "172.31.255.255", "192.168.0.0", "100.64.0.0", "1.1.1.1",
}

var v6Special = []string{
	"::", "::1", "::2", "fe80::", "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fec0::1",
	"ff01::1", "ff02::1", "ff02::2", "ff05::1", "ff0e::1", "ff11::1", "ff12::1", "ff15::1", "ff00::",
	"fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2000::", "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"2001:db8::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:0.0.0.0",
	"::ffff:255.255.255.255", "::ffff:127.0.0.1", "::ffff:169.254.1.1", "::ffff:224.0.0.1",
	"::ffff:224.0.1.1", "::ffff:10.0.0.1", "::ffff:1.2.3.4", "::1:0:0:0", "::fffe:ffff:ffff",
	"64:ff9b::1.2.3.4", "::1.2.3.4",
}

var zones = []string{"eth0", "1", "a%b", "]", "a:b", "z", "lo", "wlp2s0", strings.Repeat("z", 31)}

func randV4() netip.Addr {
	switch rnd.IntN(4) {
	case 0:
		return netip.MustParseAddr(v4Special[rnd.IntN(len(v4Special))])
	case 1: // a small window, so neighbours and ranges collide
		return netip.AddrFrom4([4]byte{10, 0, 0, byte(rnd.IntN(256))})
	default:
		var b [4]byte
		for i := range b {
			b[i] = byte(rnd.IntN(256))
		}
		return netip.AddrFrom4(b)
	}
}

func randV6() netip.Addr {
	switch rnd.IntN(5) {
	case 0:
		return netip.MustParseAddr(v6Special[rnd.IntN(len(v6Special))])
	case 1:
		var b [16]byte
		copy(b[:], netip.MustParseAddr("2001:db8::").AsSlice())
		b[15] = byte(rnd.IntN(256))
		return netip.AddrFrom16(b)
	case 2: // IPv4-mapped
		v := randV4().As4()
		return netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: v[0], 13: v[1], 14: v[2], 15: v[3]})
	default:
		var b [16]byte
		for i := range b {
			b[i] = byte(rnd.IntN(256))
		}
		// zero runs give the formatter something to choose between
		for i := rnd.IntN(8); i < 8 && rnd.IntN(3) != 0; i++ {
			b[2*i], b[2*i+1] = 0, 0
		}
		return netip.AddrFrom16(b)
	}
}

func randAddr() netip.Addr {
	if rnd.IntN(2) == 0 {
		return randV4()
	}
	return randV6()
}

func randZoned() netip.Addr {
	a := randAddr()
	if a.Is6() && rnd.IntN(4) == 0 {
		a = a.WithZone(zones[rnd.IntN(len(zones))])
	}
	return a
}

func randPrefix() netip.Prefix {
	a := randAddr()
	bits := rnd.IntN(a.BitLen() + 1)
	if rnd.IntN(3) == 0 { // near the ends, where off-by-ones live
		bits = []int{0, 1, a.BitLen() - 1, a.BitLen()}[rnd.IntN(4)]
	}
	return netip.PrefixFrom(a, bits) // host bits kept
}

// ── Zig output ──────────────────────────────────────────────────────────────

func zs(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func zsList(xs []string) string {
	if len(xs) == 0 {
		return "&.{}"
	}
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = zs(x)
	}
	return "&.{ " + strings.Join(q, ", ") + " }"
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// ── cases ───────────────────────────────────────────────────────────────────

var addrCrafted = []string{
	"fe80::1%eth0", "fe80::1%", "1.2.3.4%eth0", "::ffff:1.2.3.4%x", "fe80::1%a%b", "fe80::1%]",
	"fe80::1%a b", "fe80::1%%", "::1%1", "%eth0", "fe80::1%" + strings.Repeat("z", 31),
	"fe80::1%" + strings.Repeat("z", 32), "1.2.3.4", "::", "::ffff:1.2.3.4", "fe80::1%\x00",
}

func emitAddrs(b *bytes.Buffer) {
	texts := append([]string{}, addrCrafted...)
	texts = append(texts, v4Special...)
	texts = append(texts, v6Special...)
	for range 600 {
		texts = append(texts, randZoned().String())
	}
	b.WriteString("pub const addrs = [_]Addr{\n")
	for _, t := range texts {
		a, err := netip.ParseAddr(t)
		if err != nil {
			fmt.Fprintf(b, "    .{ .text = %s, .ok = false },\n", zs(t))
			continue
		}
		var f []string
		for _, kv := range []struct {
			name string
			on   bool
		}{
			{"global_unicast", a.IsGlobalUnicast()}, {"link_local_multicast", a.IsLinkLocalMulticast()},
			{"interface_local_multicast", a.IsInterfaceLocalMulticast()}, {"private", a.IsPrivate()},
			{"loopback", a.IsLoopback()}, {"multicast", a.IsMulticast()},
			{"link_local_unicast", a.IsLinkLocalUnicast()}, {"unspecified", a.IsUnspecified()},
			{"is4in6", a.Is4In6()},
		} {
			if kv.on {
				f = append(f, "."+kv.name+" = true")
			}
		}
		flags := ".{}"
		if len(f) > 0 {
			flags = ".{ " + strings.Join(f, ", ") + " }"
		}
		next, prev := "", ""
		if n := a.Next(); n.IsValid() {
			next = n.String()
		}
		if p := a.Prev(); p.IsValid() {
			prev = p.String()
		}
		fmt.Fprintf(b, "    .{ .text = %s, .ok = true, .str = %s, .expanded = %s, .zone = %s, .bits = %d, .flags = %s, .next = %s, .prev = %s },\n",
			zs(t), zs(a.String()), zs(a.StringExpanded()), zs(a.Zone()), a.BitLen(), flags, zs(next), zs(prev))
	}
	b.WriteString("};\n\n")
}

func cmp3(c int) int { return c }

func emitAddrCompare(b *bytes.Buffer) {
	b.WriteString("pub const addr_compare = [_]Cmp{\n")
	for i := range 800 {
		x := randZoned()
		y := randZoned()
		switch i % 4 {
		case 0: // same address, maybe different zone
			y = x.WithZone(zones[rnd.IntN(len(zones))])
			if rnd.IntN(2) == 0 {
				y = x.WithZone("")
			}
		case 1: // neighbours
			if n := x.Next(); n.IsValid() {
				y = n
			}
		}
		fmt.Fprintf(b, "    .{ .a = %s, .b = %s, .order = %d },\n", zs(x.String()), zs(y.String()), cmp3(x.Compare(y)))
	}
	b.WriteString("};\n\n")
}

var addrPortCrafted = []string{
	"1.2.3.4:80", "1.2.3.4:080", "1.2.3.4:0080", "1.2.3.4:+80", "[1.2.3.4]:80", "::1:80", "[::1]:80",
	"[fe80::1%eth0]:80", "1.2.3.4:", "1.2.3.4:65536", "1.2.3.4:65535", "[::ffff:1.2.3.4]:1",
	"[fe80::1%]]:80", "[fe80::1%a:b]:80", "[::1]80", "[::1%]:80", "example.com:80", "[]:80", "", ":80",
	"1.2.3.4", "[::1]", "0.0.0.0:0", "1.2.3.4:-1", "1.2.3.4: 80", "[::1]:8 0", "1.2.3.4:0x50",
}

func emitAddrPorts(b *bytes.Buffer) {
	texts := append([]string{}, addrPortCrafted...)
	for range 300 {
		texts = append(texts, netip.AddrPortFrom(randZoned(), uint16(rnd.IntN(65536))).String())
	}
	b.WriteString("pub const addr_ports = [_]AddrPortCase{\n")
	for _, t := range texts {
		ap, err := netip.ParseAddrPort(t)
		if err != nil {
			fmt.Fprintf(b, "    .{ .text = %s, .ok = false },\n", zs(t))
		} else {
			fmt.Fprintf(b, "    .{ .text = %s, .ok = true, .str = %s },\n", zs(t), zs(ap.String()))
		}
	}
	b.WriteString("};\n\n")
	b.WriteString("pub const addr_port_compare = [_]Cmp{\n")
	for range 300 {
		x := netip.AddrPortFrom(randZoned(), uint16(rnd.IntN(4)))
		y := netip.AddrPortFrom(x.Addr(), uint16(rnd.IntN(4)))
		if rnd.IntN(2) == 0 {
			y = netip.AddrPortFrom(randZoned(), uint16(rnd.IntN(4)))
		}
		fmt.Fprintf(b, "    .{ .a = %s, .b = %s, .order = %d },\n", zs(x.String()), zs(y.String()), cmp3(x.Compare(y)))
	}
	b.WriteString("};\n\n")
}

func emitPrefixes(b *bytes.Buffer) {
	b.WriteString("pub const prefix_compare = [_]PrefixCmp{\n")
	for i := range 800 {
		x := randPrefix()
		y := randPrefix()
		switch i % 3 {
		case 0: // same network, other length or host bits
			y = netip.PrefixFrom(x.Addr(), rnd.IntN(x.Addr().BitLen()+1))
		case 1:
			m := x.Masked()
			y = netip.PrefixFrom(m.Addr(), x.Bits())
		}
		fmt.Fprintf(b, "    .{ .a = %s, .b = %s, .netip = %d, .netipx = %d },\n",
			zs(x.String()), zs(y.String()), x.Compare(y), netipx.ComparePrefix(x, y))
	}
	b.WriteString("};\n\n")

	b.WriteString("pub const addr_prefix = [_]AddrPrefix{\n")
	for range 300 {
		a := randAddr()
		bits := rnd.IntN(a.BitLen() + 3)
		p, err := a.Prefix(bits)
		out := ""
		if err == nil {
			out = p.String()
		}
		last := ""
		if err == nil {
			last = netipx.PrefixLastIP(p).String()
		}
		fmt.Fprintf(b, "    .{ .addr = %s, .bits = %d, .prefix = %s, .last = %s },\n", zs(a.String()), bits, zs(out), zs(last))
	}
	b.WriteString("};\n\n")

	texts := []string{"192.0.2.1", "192.0.2.1/24", "2001:db8::68/96", "192.0.2.1/33", "x", "", "/24",
		"192.0.2.1/", "fe80::1%eth0", "fe80::1%eth0/64", "1.2.3.4/024", "::/0"}
	for range 100 {
		if rnd.IntN(2) == 0 {
			texts = append(texts, randPrefix().String())
		} else {
			texts = append(texts, randAddr().String())
		}
	}
	b.WriteString("pub const prefix_or_addr = [_]TextResult{\n")
	for _, t := range texts {
		a, err := netipx.ParsePrefixOrAddr(t)
		if err != nil {
			fmt.Fprintf(b, "    .{ .text = %s, .ok = false },\n", zs(t))
		} else {
			fmt.Fprintf(b, "    .{ .text = %s, .ok = true, .str = %s },\n", zs(t), zs(a.String()))
		}
	}
	b.WriteString("};\n\n")
}

func randRange() netipx.IPRange {
	if rnd.IntN(5) == 0 { // exactly one prefix
		return netipx.RangeOfPrefix(randPrefix().Masked())
	}
	x := randAddr()
	y := x
	switch rnd.IntN(3) {
	case 0:
		if x.Is4() {
			y = randV4()
		} else {
			y = randV6()
		}
	case 1: // a short span
		for range rnd.IntN(20) {
			if n := y.Next(); n.IsValid() {
				y = n
			}
		}
	default:
		y = randAddr() // maybe another family
	}
	if y.Less(x) && rnd.IntN(4) != 0 {
		x, y = y, x
	}
	return netipx.IPRangeFrom(x, y)
}

func emitRanges(b *bytes.Buffer) {
	texts := []string{"1.2.3.4-1.2.3.10", "fe80::1%a-fe80::2%a", "1.2.3.4-::1", "1.2.3.5-1.2.3.4",
		"1.2.3.4 - 1.2.3.5", "1.2.3.4-1.2.3.4", "1.2.3.4", "-", "1.2.3.4-", "-1.2.3.4",
		"0.0.0.0-255.255.255.255", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1.2.3.4-1.2.3.5-1.2.3.6",
		"fe80::1%eth-0-fe80::2"}
	var ranges []netipx.IPRange
	for range 250 {
		r := randRange()
		ranges = append(ranges, r)
		texts = append(texts, r.From().String()+"-"+r.To().String())
	}
	b.WriteString("pub const ranges = [_]RangeCase{\n")
	for _, t := range texts {
		r, err := netipx.ParseIPRange(t)
		if err != nil {
			fmt.Fprintf(b, "    .{ .text = %s, .ok = false },\n", zs(t))
			continue
		}
		one := ""
		if p, ok := r.Prefix(); ok {
			one = p.String()
		}
		fmt.Fprintf(b, "    .{ .text = %s, .ok = true, .str = %s, .prefix = %s, .prefixes = %s },\n",
			zs(t), zs(r.String()), zs(one), zsList(prefixStrings(r.Prefixes())))
	}
	b.WriteString("};\n\n")

	b.WriteString("pub const range_pairs = [_]RangePair{\n")
	for i := range 400 {
		x := ranges[rnd.IntN(len(ranges))]
		y := randRange()
		switch i % 4 {
		case 0:
			y = ranges[rnd.IntN(len(ranges))]
		case 1: // touching in one address, from either side
			if rnd.IntN(2) == 0 {
				y = netipx.IPRangeFrom(x.To(), randAddr())
			} else {
				y = netipx.IPRangeFrom(randAddr(), x.From())
			}
		}
		a := x.From()
		switch rnd.IntN(3) {
		case 0:
			a = randAddr()
		case 1:
			a = x.To()
			if n := a.Next(); n.IsValid() && rnd.IntN(2) == 0 {
				a = n
			}
		}
		// Valid ranges only as text; an invalid one is written from-to raw.
		fmt.Fprintf(b, "    .{ .a = %s, .b = %s, .overlaps = %v, .addr = %s, .contains = %v },\n",
			zs(x.From().String()+"-"+x.To().String()), zs(y.From().String()+"-"+y.To().String()),
			x.Overlaps(y), zs(a.String()), x.Contains(a))
	}
	b.WriteString("};\n\n")
}

// ── sets ────────────────────────────────────────────────────────────────────

type op struct {
	kind string
	arg  string
}

// Small worlds so operations interact: one v4 /24 and one v6 /120, plus
// occasional far-away prefixes and the family edges.
func setAddr(v6 bool) netip.Addr {
	if v6 {
		var b [16]byte
		copy(b[:], netip.MustParseAddr("2001:db8::").AsSlice())
		b[15] = byte(rnd.IntN(256))
		if rnd.IntN(10) == 0 {
			return randV6()
		}
		return netip.AddrFrom16(b)
	}
	if rnd.IntN(10) == 0 {
		return randV4()
	}
	return netip.AddrFrom4([4]byte{10, 0, 0, byte(rnd.IntN(256))})
}

func setPrefix(v6 bool) netip.Prefix {
	a := setAddr(v6)
	w := a.BitLen()
	bits := w - rnd.IntN(9) // /24../32 in the window
	if rnd.IntN(12) == 0 {
		bits = rnd.IntN(w + 1)
	}
	return netip.PrefixFrom(a, bits)
}

func setRange(v6 bool) netipx.IPRange {
	x, y := setAddr(v6), setAddr(v6)
	if y.Less(x) {
		x, y = y, x
	}
	return netipx.IPRangeFrom(x, y)
}

func randOps(n int) []op {
	var ops []op
	for range n {
		v6 := rnd.IntN(3) == 0
		switch k := rnd.IntN(16); {
		case k < 3:
			ops = append(ops, op{"add_prefix", setPrefix(v6).String()})
		case k < 6:
			r := setRange(v6)
			ops = append(ops, op{"add_range", r.String()})
		case k < 7:
			ops = append(ops, op{"add", setAddr(v6).String()})
		case k < 9:
			ops = append(ops, op{"remove_prefix", setPrefix(v6).String()})
		case k < 11:
			ops = append(ops, op{"remove_range", setRange(v6).String()})
		case k < 12:
			ops = append(ops, op{"remove", setAddr(v6).String()})
		case k < 13:
			ops = append(ops, op{"complement", ""})
		default:
			var ps []string
			for range 1 + rnd.IntN(3) {
				ps = append(ps, setPrefix(rnd.IntN(3) == 0).String())
			}
			ops = append(ops, op{"intersect", strings.Join(ps, ",")})
		}
	}
	return ops
}

func apply(ops []op) *netipx.IPSet {
	var b netipx.IPSetBuilder
	for _, o := range ops {
		switch o.kind {
		case "add":
			b.Add(netip.MustParseAddr(o.arg))
		case "add_prefix":
			b.AddPrefix(netip.MustParsePrefix(o.arg))
		case "add_range":
			b.AddRange(netipx.MustParseIPRange(o.arg))
		case "remove":
			b.Remove(netip.MustParseAddr(o.arg))
		case "remove_prefix":
			b.RemovePrefix(netip.MustParsePrefix(o.arg))
		case "remove_range":
			b.RemoveRange(netipx.MustParseIPRange(o.arg))
		case "complement":
			b.Complement()
		case "intersect":
			var ib netipx.IPSetBuilder
			for _, p := range strings.Split(o.arg, ",") {
				ib.AddPrefix(netip.MustParsePrefix(p))
			}
			is, err := ib.IPSet()
			if err != nil {
				panic(err)
			}
			b.Intersect(is)
		}
	}
	s, err := b.IPSet()
	if err != nil {
		panic(err)
	}
	return s
}

func emitSets(b *bytes.Buffer) {
	type built struct {
		ops []op
		set *netipx.IPSet
	}
	var sets []built
	b.WriteString("pub const sets = [_]SetCase{\n")
	for i := range 120 {
		ops := randOps(1 + rnd.IntN(10))
		if i < 4 { // degenerate: empty, full, full minus a hole, one address
			ops = [][]op{{}, {{"complement", ""}}, {{"complement", ""}, {"remove", "10.0.0.7"}}, {{"add", "::"}}}[i]
		}
		s := apply(ops)
		sets = append(sets, built{ops, s})
		fmt.Fprintf(b, "    .{\n        .ops = &.{")
		for _, o := range ops {
			fmt.Fprintf(b, " .{ .kind = .%s, .arg = %s },", o.kind, zs(o.arg))
		}
		fmt.Fprintf(b, " },\n        .prefixes = %s,\n", zsList(prefixStrings(s.Prefixes())))
		var rs []string
		for _, r := range s.Ranges() {
			rs = append(rs, r.String())
		}
		fmt.Fprintf(b, "        .ranges = %s,\n        .probes = &.{\n", zsList(rs))
		for range 12 {
			v6 := rnd.IntN(3) == 0
			switch rnd.IntN(5) {
			case 0:
				a := setAddr(v6)
				if rnd.IntN(4) == 0 { // the mapped twin of a v4 member never counts
					a = netip.AddrFrom16(setAddr(false).As16())
				}
				fmt.Fprintf(b, "            .{ .kind = .contains, .arg = %s, .yes = %v },\n", zs(a.String()), s.Contains(a))
			case 1:
				p := setPrefix(v6)
				fmt.Fprintf(b, "            .{ .kind = .contains_prefix, .arg = %s, .yes = %v },\n", zs(p.String()), s.ContainsPrefix(p))
			case 2:
				r := setRange(v6)
				fmt.Fprintf(b, "            .{ .kind = .contains_range, .arg = %s, .yes = %v },\n", zs(r.String()), s.ContainsRange(r))
			case 3:
				p := setPrefix(v6)
				fmt.Fprintf(b, "            .{ .kind = .overlaps_prefix, .arg = %s, .yes = %v },\n", zs(p.String()), s.OverlapsPrefix(p))
			default:
				r := setRange(v6)
				fmt.Fprintf(b, "            .{ .kind = .overlaps_range, .arg = %s, .yes = %v },\n", zs(r.String()), s.OverlapsRange(r))
			}
		}
		b.WriteString("        },\n        .free = &.{\n")
		for _, bits := range []uint8{0, 24, 30, 32, 64, 120, 128, uint8(rnd.IntN(129))} {
			p, rest, ok := s.RemoveFreePrefix(bits)
			if !ok {
				fmt.Fprintf(b, "            .{ .bits = %d, .prefix = \"\", .rest = &.{} },\n", bits)
				continue
			}
			var rr []string
			for _, r := range rest.Ranges() {
				rr = append(rr, r.String())
			}
			fmt.Fprintf(b, "            .{ .bits = %d, .prefix = %s, .rest = %s },\n", bits, zs(p.String()), zsList(rr))
		}
		b.WriteString("        },\n    },\n")
	}
	b.WriteString("};\n\n")

	b.WriteString("pub const set_pairs = [_]SetPair{\n")
	for range 400 {
		i, j := rnd.IntN(len(sets)), rnd.IntN(len(sets))
		fmt.Fprintf(b, "    .{ .a = %d, .b = %d, .overlaps = %v, .equal = %v },\n", i, j, sets[i].set.Overlaps(sets[j].set), sets[i].set.Equal(sets[j].set))
	}
	b.WriteString("};\n")
}

const header = `/// One ParseAddr verdict: the text Go's String/StringExpanded give, the
/// zone, BitLen, the predicates that hold, and Next/Prev ("" = none).
pub const Flags = packed struct {
    global_unicast: bool = false,
    link_local_multicast: bool = false,
    interface_local_multicast: bool = false,
    private: bool = false,
    loopback: bool = false,
    multicast: bool = false,
    link_local_unicast: bool = false,
    unspecified: bool = false,
    is4in6: bool = false,
};
pub const Addr = struct {
    text: []const u8,
    ok: bool,
    str: []const u8 = "",
    expanded: []const u8 = "",
    zone: []const u8 = "",
    bits: u8 = 0,
    flags: Flags = .{},
    next: []const u8 = "",
    prev: []const u8 = "",
};
/// Go's Compare of two values written as Go's String writes them.
pub const Cmp = struct { a: []const u8, b: []const u8, order: i8 };
pub const AddrPortCase = struct { text: []const u8, ok: bool, str: []const u8 = "" };
/// netip Prefix.Compare and netipx ComparePrefix of the same pair.
pub const PrefixCmp = struct { a: []const u8, b: []const u8, netip: i8, netipx: i8 };
/// Addr.Prefix(bits) ("" = error) and netipx PrefixLastIP of it.
pub const AddrPrefix = struct { addr: []const u8, bits: u8, prefix: []const u8, last: []const u8 };
pub const TextResult = struct { text: []const u8, ok: bool, str: []const u8 = "" };
/// ParseIPRange, then String, Prefix ("" = not one) and Prefixes.
pub const RangeCase = struct {
    text: []const u8,
    ok: bool,
    str: []const u8 = "",
    prefix: []const u8 = "",
    prefixes: []const []const u8 = &.{},
};
/// a.Overlaps(b) and a.Contains(addr); a/b are "from-to", maybe invalid.
pub const RangePair = struct { a: []const u8, b: []const u8, overlaps: bool, addr: []const u8, contains: bool };
pub const OpKind = enum { add, add_prefix, add_range, remove, remove_prefix, remove_range, complement, intersect };
/// One builder call; ` + "`intersect`" + `'s argument is a comma-separated prefix list.
pub const Op = struct { kind: OpKind, arg: []const u8 };
pub const ProbeKind = enum { contains, contains_prefix, contains_range, overlaps_prefix, overlaps_range };
pub const Probe = struct { kind: ProbeKind, arg: []const u8, yes: bool };
/// RemoveFreePrefix(bits): the prefix ("" = not ok) and the rest's Ranges.
pub const Free = struct { bits: u8, prefix: []const u8, rest: []const []const u8 };
pub const SetCase = struct {
    ops: []const Op,
    prefixes: []const []const u8,
    ranges: []const []const u8,
    probes: []const Probe,
    free: []const Free,
};
/// Overlaps/Equal between sets[a] and sets[b].
pub const SetPair = struct { a: usize, b: usize, overlaps: bool, equal: bool };

`

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	check := flag.String("check", "", "re-take and compare with this committed file")
	flag.Parse()

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/netaddr/tools/go_netip_oracle (%s net/netip, go4.org/netipx v0.0.0-20260823151212-3075585bcbeb) -- do not hand-edit.\n", runtime.Version())
	b.WriteString("//! Go net/netip + netipx answers to this module's own cases, replayed by\n")
	b.WriteString("//! `netip_oracle_test.zig`. Regenerate with the command in tools/go_netip_oracle/main.go.\n\n")
	b.WriteString(header)
	emitAddrs(&b)
	emitAddrCompare(&b)
	emitAddrPorts(&b)
	emitPrefixes(&b)
	emitRanges(&b)
	emitSets(&b)

	// The committed file is `zig fmt` clean (the repository's pre-commit
	// gate), so the re-take is formatted the same way before any comparison.
	fmtCmd := exec.Command("zig", "fmt", "--stdin")
	fmtCmd.Stdin = bytes.NewReader(b.Bytes())
	fmtCmd.Stderr = os.Stderr
	formatted, err := fmtCmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "zig fmt --stdin:", err)
		os.Exit(2)
	}
	b.Reset()
	b.Write(formatted)

	switch {
	case *check != "":
		old, err := os.ReadFile(*check)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !bytes.Equal(old, b.Bytes()) {
			ol := strings.Split(string(old), "\n")
			nl := strings.Split(b.String(), "\n")
			for i := 0; i < len(ol) || i < len(nl); i++ {
				var x, y string
				if i < len(ol) {
					x = ol[i]
				}
				if i < len(nl) {
					y = nl[i]
				}
				if x != y {
					fmt.Fprintf(os.Stderr, "DRIFT at line %d:\n  committed: %s\n  re-taken:  %s\n", i+1, x, y)
					break
				}
			}
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "netip oracle: committed vectors match a fresh re-take")
	case *out != "":
		if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		os.Stdout.Write(b.Bytes())
	}
}
