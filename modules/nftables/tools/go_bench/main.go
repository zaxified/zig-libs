// SPDX-License-Identifier: MIT

// Go side of `zig build bench-nftables` (modules/nftables/tools/bench.zig):
// times github.com/google/nftables (Apache-2.0) through its public API over
// the corpus the Zig program writes into the directory given as the first
// argument, for the one workload named by the second. Prints one line: name,
// ns/op, count (tab-separated). One op = 64 rules. See bench.zig for what
// each workload does and how the count is formed.
//
// No socket and no kernel are involved: the library's own test seam
// (`nftables.WithTestDial`) stands in for the netlink socket, so `Flush` and
// `GetRules` run their real code (batching, message building, reply
// handling, typed expression parsing) against an in-memory peer.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
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

// verdictCode is the kernel's verdict number (NF_DROP 0, NF_ACCEPT 1).
func verdictCode(k expr.VerdictKind) uint64 { return uint64(uint32(int32(k))) }

// tally adds up, per decoded expression, exactly what the Zig side adds up.
func tally(exprs []expr.Any) uint64 {
	var t uint64
	for _, e := range exprs {
		t++
		switch x := e.(type) {
		case *expr.Meta:
			t += uint64(x.Key)
		case *expr.Cmp:
			t += uint64(x.Op) + uint64(len(x.Data)) + uint64(x.Data[0])
		case *expr.Payload:
			t += uint64(x.Base) + uint64(x.Offset) + uint64(x.Len)
		case *expr.Bitwise:
			t += uint64(x.Len) + uint64(x.Mask[0])
		case *expr.Ct:
			t += uint64(x.Key)
		case *expr.Counter:
			t += x.Packets + x.Bytes
		case *expr.Verdict:
			t += verdictCode(x.Kind)
		case *expr.Lookup:
			t += uint64(len(x.SetName))
		default:
			die(fmt.Errorf("unexpected expression %T", e))
		}
	}
	return t
}

// rule parameters, as the Zig side writes them:
// shape u8, plen u8, port u16 BE, addr [4]u8, mask [4]u8.
type params struct {
	shape byte
	plen  byte
	port  uint16
	addr  [4]byte
	mask  [4]byte
}

func parse(p []byte) params {
	var r params
	r.shape, r.plen = p[0], p[1]
	r.port = uint16(p[2])<<8 | uint16(p[3])
	copy(r.addr[:], p[4:8])
	copy(r.mask[:], p[8:12])
	return r
}

func ipMask(plen byte) []byte {
	m := make([]byte, 4)
	for i := 0; i < 4; i++ {
		bits := int(plen) - 8*i
		switch {
		case bits >= 8:
			m[i] = 0xff
		case bits > 0:
			m[i] = byte(0xff << (8 - bits))
		}
	}
	return m
}

func exprsFor(r params) []expr.Any {
	switch r.shape {
	case 0: // tcp dport P counter accept
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(r.port >> 8), byte(r.port)}},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}
	case 1: // ip saddr A/N drop (N not a multiple of 8: mask + compare)
		m := ipMask(r.plen)
		masked := []byte{r.addr[0] & m[0], r.addr[1] & m[1], r.addr[2] & m[2], r.addr[3] & m[3]}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: m, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: masked},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}
	case 2: // ip saddr @blocked drop
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: "blocked"},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}
	case 3: // iifname "lo" accept
		name := make([]byte, 16)
		copy(name, "lo")
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}
	default: // ct state mask != 0 accept
		return []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: r.mask[:], Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench DIR WORKLOAD")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	tbl := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
	ch := &nftables.Chain{Name: "input", Table: tbl}
	var f func() uint64
	switch name {
	case "enc_rule":
		var rules [][]expr.Any
		for _, p := range readFrames(filepath.Join(dir, "enc_rule.bin")) {
			rules = append(rules, exprsFor(parse(p)))
		}
		var sent uint64
		c, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			if len(req) > 1 { // the batch; later calls are receive polls
				sent = uint64(len(req))
			}
			return nil, nil
		}))
		if err != nil {
			die(err)
		}
		f = func() uint64 {
			for _, r := range rules {
				c.AddRule(&nftables.Rule{Table: tbl, Chain: ch, Exprs: r})
			}
			if err := c.Flush(); err != nil {
				die(err)
			}
			return sent // BATCH_BEGIN + 64 rules + BATCH_END
		}
	case "dec_rule":
		var msgs []netlink.Message
		for _, p := range readFrames(filepath.Join(dir, "dec_rule.bin")) {
			msgs = append(msgs, netlink.Message{
				Header: netlink.Header{Length: uint32(16 + len(p)), Type: 0x0a06},
				Data:   p,
			})
		}
		// Multipart turns the LAST message into the terminating Done:
		// append a throwaway one for it to consume.
		reply, err := nltest.Multipart(append(msgs, netlink.Message{Data: []byte{0, 0, 0, 0}}))
		if err != nil {
			die(err)
		}
		c, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			out := make([]netlink.Message, len(reply))
			copy(out, reply)
			for i := range out {
				out[i].Header.Sequence = req[0].Header.Sequence
				out[i].Header.PID = req[0].Header.PID
			}
			return out, nil
		}))
		if err != nil {
			die(err)
		}
		f = func() uint64 {
			rules, err := c.GetRules(tbl, ch)
			if err != nil {
				die(err)
			}
			var t uint64
			for _, r := range rules {
				t += r.Handle + tally(r.Exprs)
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
