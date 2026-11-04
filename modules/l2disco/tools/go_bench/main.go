// SPDX-License-Identifier: BSD-3-Clause

// Go side of `zig build bench-l2disco` (modules/l2disco/tools/bench.zig):
// times github.com/gopacket/gopacket v1.7.2 (BSD-3-Clause, layers package)
// over the corpus the Zig program writes into the directory given as the
// first argument, for the one workload named by the second. Prints one line:
// name, ns/op, result count (tab-separated). One op = all 64 inputs. See
// bench.zig for what each workload does and how the count is formed.
//
// gopacket exposes LLDP and CDP only through its packet path
// (gopacket.NewPacket with NoCopy: the layer and its Info layer are both
// decoded, their TLV values and strings built), the others through
// DecodeFromBytes on a reused layer -- the fast path of the library, used
// here for ARP, DHCPv4, DHCPv6 and ICMPv6 Router Advertisement.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
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

func lldp(b []byte) uint64 {
	p := gopacket.NewPacket(b, layers.LayerTypeLinkLayerDiscovery, gopacket.DecodeOptions{NoCopy: true})
	l, ok := p.Layer(layers.LayerTypeLinkLayerDiscovery).(*layers.LinkLayerDiscovery)
	if !ok {
		die(fmt.Errorf("lldp: not decoded: %v", p.ErrorLayer()))
	}
	info, ok := p.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo)
	if !ok {
		die(fmt.Errorf("lldp: no info layer: %v", p.ErrorLayer()))
	}
	t := uint64(l.ChassisID.Subtype) + uint64(len(l.ChassisID.ID)) + uint64(l.PortID.Subtype) + uint64(len(l.PortID.ID)) + uint64(l.TTL)
	t += uint64(len(info.SysName)) + uint64(len(info.SysDescription)) + uint64(len(info.PortDescription))
	t += capBits(info.SysCapabilities.SystemCap) + capBits(info.SysCapabilities.EnabledCap)
	t += uint64(len(info.OrgTLVs))
	// The typed decode of the organisationally specific TLVs, as ours does
	// per TLV (`OrgSpecific.decode`).
	// The values go into the count: ours sums the same three (last TLV wins).
	if v, err := info.Decode8021(); err == nil {
		t += uint64(v.PVID)
	}
	if v, err := info.Decode8023(); err == nil {
		t += uint64(v.MTU)
	}
	if v, err := info.DecodeMedia(); err == nil {
		t += uint64(v.NetworkPolicy.VLANId)
	}
	return t
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// capBits packs gopacket's capability bools back into the wire word.
func capBits(c layers.LLDPCapabilities) uint64 {
	return b2u(c.Other) | b2u(c.Repeater)<<1 | b2u(c.Bridge)<<2 | b2u(c.WLANAP)<<3 | b2u(c.Router)<<4 |
		b2u(c.Phone)<<5 | b2u(c.DocSis)<<6 | b2u(c.StationOnly)<<7
}

func cdp(b []byte) uint64 {
	p := gopacket.NewPacket(b, layers.LayerTypeCiscoDiscovery, gopacket.DecodeOptions{NoCopy: true})
	c, ok := p.Layer(layers.LayerTypeCiscoDiscovery).(*layers.CiscoDiscovery)
	if !ok {
		die(fmt.Errorf("cdp: not decoded: %v", p.ErrorLayer()))
	}
	info, ok := p.Layer(layers.LayerTypeCiscoDiscoveryInfo).(*layers.CiscoDiscoveryInfo)
	if !ok {
		die(fmt.Errorf("cdp: no info layer: %v", p.ErrorLayer()))
	}
	t := uint64(c.Version) + uint64(c.TTL) + uint64(len(info.DeviceID)) + uint64(len(info.PortID))
	t += uint64(len(info.Platform)) + uint64(len(info.Version)) + uint64(info.NativeVLAN) + uint64(len(info.Addresses))
	return t
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "github.com/gopacket/gopacket v1.7.5, github.com/insomniacslk/dhcp c6bb46ad3f3a (rows *_idhcp)")
	file := name
	if n := len(name); n > 6 && name[n-6:] == "_idhcp" {
		file = name[:n-6]
	}
	msgs := readMsgs(filepath.Join(dir, file+".bin"))
	var f func() uint64
	switch name {
	case "lldp":
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				t += lldp(m)
			}
			return t
		}
	case "cdp":
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				t += cdp(m)
			}
			return t
		}
	case "arp":
		var a layers.ARP
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				if err := a.DecodeFromBytes(m, gopacket.NilDecodeFeedback); err != nil {
					die(err)
				}
				t += uint64(a.Operation) + uint64(len(a.SourceHwAddress)+len(a.SourceProtAddress)+len(a.DstHwAddress)+len(a.DstProtAddress))
				for _, c := range a.SourceProtAddress {
					t += uint64(c)
				}
				for _, c := range a.DstProtAddress {
					t += uint64(c)
				}
			}
			return t
		}
	case "dhcp4":
		var d layers.DHCPv4
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				if err := d.DecodeFromBytes(m, gopacket.NilDecodeFeedback); err != nil {
					die(err)
				}
				t += uint64(d.Operation) + uint64(d.Xid) + uint64(d.Secs) + uint64(d.Flags)
				for _, c := range d.YourClientIP.To4() {
					t += uint64(c)
				}
				// The typed fields ours fills in one pass, found by a scan.
				for _, o := range d.Options {
					switch o.Type {
					case layers.DHCPOptMessageType:
						t += uint64(o.Data[0])
					case layers.DHCPOptLeaseTime:
						t += uint64(o.Data[0])<<24 | uint64(o.Data[1])<<16 | uint64(o.Data[2])<<8 | uint64(o.Data[3])
					case layers.DHCPOptServerID:
						for _, c := range o.Data {
							t += uint64(c)
						}
					case layers.DHCPOptHostname:
						t += uint64(len(o.Data))
					}
				}
			}
			return t
		}
	case "dhcp4_idhcp":
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				d, err := dhcpv4.FromBytes(m)
				if err != nil {
					die(err)
				}
				x := d.TransactionID
				t += uint64(d.OpCode) + (uint64(x[0])<<24 | uint64(x[1])<<16 | uint64(x[2])<<8 | uint64(x[3])) + uint64(d.NumSeconds) + uint64(d.Flags)
				for _, c := range d.YourIPAddr.To4() {
					t += uint64(c)
				}
				t += uint64(d.MessageType())
				t += uint64(d.IPAddressLeaseTime(0) / time.Second)
				for _, c := range d.ServerIdentifier().To4() {
					t += uint64(c)
				}
				t += uint64(len(d.HostName()))
			}
			return t
		}
	case "dhcp6_idhcp":
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				d, err := dhcpv6.MessageFromBytes(m)
				if err != nil {
					die(err)
				}
				x := d.TransactionID
				t += uint64(d.MessageType) + (uint64(x[0])<<16 | uint64(x[1])<<8 | uint64(x[2]))
				for _, o := range d.Options.Options {
					t += uint64(o.Code()) + 1
				}
			}
			return t
		}
	case "dhcp6":
		var d layers.DHCPv6
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				if err := d.DecodeFromBytes(m, gopacket.NilDecodeFeedback); err != nil {
					die(err)
				}
				t += uint64(d.MsgType) + uint64(d.TransactionID[0])<<16 + uint64(d.TransactionID[1])<<8 + uint64(d.TransactionID[2])
				for _, o := range d.Options {
					t += uint64(o.Code) + 1
				}
			}
			return t
		}
	case "nd_ra":
		var r layers.ICMPv6RouterAdvertisement
		f = func() uint64 {
			var t uint64
			for _, m := range msgs {
				if err := r.DecodeFromBytes(m[4:], gopacket.NilDecodeFeedback); err != nil {
					die(err)
				}
				t += uint64(r.HopLimit) + uint64(r.Flags) + uint64(r.RouterLifetime) + uint64(r.ReachableTime) + uint64(r.RetransTimer)
				t += uint64(len(r.Options))
				for _, o := range r.Options {
					t += uint64(o.Type)
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
