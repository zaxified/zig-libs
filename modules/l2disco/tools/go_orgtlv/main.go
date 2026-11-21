// Oracle for the vendor org-specific LLDP TLVs `src/lldp.zig` decodes beyond
// what tcpdump prints (802.1Qbg EVB, Cisco-OUI PoE, Profinet): the facts
// gopacket v1.7.5 (BSD-3-Clause) reads from each TLV. Offline, from the module
// cache that tools/go_bench filled:
//
//     GOFLAGS=-mod=mod GOPROXY=off go run .
//
// The output is pasted into the tests as frozen expectations.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func tlv(t int, v []byte) []byte {
	h := uint16(t)<<9 | uint16(len(v))
	return append([]byte{byte(h >> 8), byte(h)}, v...)
}

func org(oui []byte, sub byte, info []byte) []byte {
	v := append(append([]byte{}, oui...), sub)
	return tlv(127, append(v, info...))
}

func frame(orgTLV []byte) []byte {
	var f []byte
	f = append(f, tlv(1, []byte{4, 0, 1, 2, 3, 4, 5})...)
	f = append(f, tlv(2, []byte{5, 'e', 't', 'h', '0'})...)
	f = append(f, tlv(3, []byte{0, 120})...)
	f = append(f, orgTLV...)
	return append(f, 0, 0)
}

func info(o []byte) *layers.LinkLayerDiscoveryInfo {
	p := gopacket.NewPacket(frame(o), layers.LayerTypeLinkLayerDiscovery, gopacket.Default)
	l := p.Layer(layers.LayerTypeLinkLayerDiscoveryInfo)
	if l == nil {
		panic("no info layer: " + fmt.Sprint(p.ErrorLayer()))
	}
	return l.(*layers.LinkLayerDiscoveryInfo)
}

func dec(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	// 802.1Qbg EVB, OUI 00-13-BF subtype 0: supported 0x00c3, enabled 0x0083, 32 VSIs, 16 configured, RTE 17.
	evb := info(org([]byte{0x00, 0x13, 0xbf}, 0, dec("00c3008300200010"+"11")))
	q, err := evb.Decode8021Qbg()
	fmt.Printf("evb err=%v %+v\n", err, q.EVBSettings)

	// Cisco-OUI PoE, OUI 00-01-42 subtype 1.
	for _, b := range []byte{0x05, 0x0a, 0x0f, 0x00} {
		c, err := info(org([]byte{0x00, 0x01, 0x42}, 1, []byte{b})).DecodeCisco2()
		fmt.Printf("cisco %02x err=%v %+v\n", b, err, c)
	}

	pn := []byte{0x00, 0x0e, 0xcf}
	d1, _ := info(org(pn, 1, dec("0000000a0000000b0000000c0000000d0000000e"))).DecodeProfinet()
	fmt.Printf("pn delay %+v\n", d1.PNIODelay)
	d2, _ := info(org(pn, 2, dec("00010002"))).DecodeProfinet()
	fmt.Printf("pn port %+v\n", d2.PNIOPortStatus)
	d4, _ := info(org(pn, 4, dec("000102030405060708090a0b0c0d0e0f"+"8001"))).DecodeProfinet()
	fmt.Printf("pn mrp %x %04x\n", d4.PNIOMRPPortStatus.UUID, d4.PNIOMRPPortStatus.Status)
	d5, _ := info(org(pn, 5, dec("0a0b0c0d0e0f"))).DecodeProfinet()
	fmt.Printf("pn mac %x\n", d5.ChassisMAC)
	d6, _ := info(org(pn, 6, dec("0a0b0c0d0e0f"+"00112233445566778899aabbccddeeff"+"ffeeddccbbaa99887766554433221100"+"80000064"+"00000000"+"80000032"+"c8000000"))).DecodeProfinet()
	p := d6.PNIOPTCPStatus
	fmt.Printf("pn ptcp master=%x sub=%x ir=%x period=%v/%d red=%v/%d orange=%v/%d green=%v/%d\n", p.MasterAddress, p.SubdomainUUID, p.IRDataUUID, p.PeriodValid, p.PeriodLength, p.RedPeriodValid, p.RedPeriodBegin, p.OrangePeriodValid, p.OrangePeriodBegin, p.GreenPeriodValid, p.GreenPeriodBegin)
	// A too short one: gopacket reports an error.
	_, err = info(org(pn, 1, dec("00000001"))).DecodeProfinet()
	fmt.Printf("pn short err=%v\n", err)
	_, err = info(org([]byte{0x00, 0x13, 0xbf}, 0, dec("00c30083002000"))).Decode8021Qbg()
	fmt.Printf("evb short err=%v\n", err)
}
