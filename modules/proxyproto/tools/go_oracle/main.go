// SPDX-License-Identifier: MIT

// Differential oracle for modules/proxyproto: pires/go-proxyproto v0.16.0,
// driven through its public API only (ParseUDPDatagram, Header.Format,
// Header.TLVs/SetTLVs, HeaderProxyFromAddrs, tlvparse.SSL) on in-memory bytes.
// No file, network, environment or process access.
//
// Protocol: one request per line on stdin, one answer per line on stdout.
//
//	P <hex>    parse the bytes.  Answer: OK <canon> crc=<c> | ERR <name>
//	G <desc>   write a header from the description.  Answer: H <hex> | E <name>
//
// <canon> is the canonical verdict compared with the Zig side (see
// tools/interop.zig for its definition). <desc> is described there as well.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"strconv"
	"strings"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/pires/go-proxyproto/tlvparse"
)

var errNames = []struct {
	err  error
	name string
}{
	{proxyproto.ErrNoProxyProtocol, "NoProxyProtocol"},
	{proxyproto.ErrCantReadVersion1Header, "CantReadVersion1Header"},
	{proxyproto.ErrVersion1HeaderTooLong, "Version1HeaderTooLong"},
	{proxyproto.ErrLineMustEndWithCrlf, "LineMustEndWithCrlf"},
	{proxyproto.ErrCantReadProtocolVersionAndCommand, "CantReadProtocolVersionAndCommand"},
	{proxyproto.ErrCantReadAddressFamilyAndProtocol, "CantReadAddressFamilyAndProtocol"},
	{proxyproto.ErrCantReadLength, "CantReadLength"},
	{proxyproto.ErrUnsupportedProtocolVersionAndCommand, "UnsupportedProtocolVersionAndCommand"},
	{proxyproto.ErrUnsupportedAddressFamilyAndProtocol, "UnsupportedAddressFamilyAndProtocol"},
	{proxyproto.ErrInvalidLength, "InvalidLength"},
	{proxyproto.ErrInvalidAddress, "InvalidAddress"},
	{proxyproto.ErrInvalidPortNumber, "InvalidPortNumber"},
	{proxyproto.ErrUnknownProxyProtocolVersion, "UnknownProxyProtocolVersion"},
}

func errName(err error) string {
	for _, e := range errNames {
		if errors.Is(err, e.err) {
			return e.name
		}
	}
	return "Other"
}

func famName(t proxyproto.AddressFamilyAndProtocol) string {
	switch t {
	case proxyproto.TCPv4:
		return "tcp4"
	case proxyproto.TCPv6:
		return "tcp6"
	case proxyproto.UDPv4:
		return "udp4"
	case proxyproto.UDPv6:
		return "udp6"
	case proxyproto.UnixStream:
		return "unixs"
	case proxyproto.UnixDatagram:
		return "unixd"
	}
	return "unspec"
}

func addrText(a net.Addr) string {
	switch x := a.(type) {
	case *net.TCPAddr:
		return hex.EncodeToString(x.IP) + ":" + strconv.Itoa(x.Port)
	case *net.UDPAddr:
		return hex.EncodeToString(x.IP) + ":" + strconv.Itoa(x.Port)
	case *net.UnixAddr:
		return "u:" + hex.EncodeToString([]byte(x.Name))
	}
	return "-"
}

func tlvText(h *proxyproto.Header) string {
	tlvs, err := h.TLVs()
	if err != nil {
		return "ERR"
	}
	if len(tlvs) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(tlvs))
	for _, t := range tlvs {
		if t.Type == proxyproto.PP2_TYPE_NOOP {
			parts = append(parts, "04:-")
		} else {
			parts = append(parts, fmt.Sprintf("%02x:%s", byte(t.Type), hex.EncodeToString(t.Value)))
		}
	}
	return strings.Join(parts, ",")
}

// crcState checks the CRC32C TLV of a parsed v2 PROXY header with the standard
// library's Castagnoli table (go-proxyproto itself does not verify it).
func crcState(h *proxyproto.Header, raw []byte, n int) string {
	var alen int
	switch {
	case h.TransportProtocol.IsIPv4():
		alen = 12
	case h.TransportProtocol.IsIPv6():
		alen = 36
	case h.TransportProtocol.IsUnix():
		alen = 216
	}
	if 16+alen > n {
		return "none"
	}
	i := 16 + alen
	off, cnt, bad := -1, 0, false
	for i < n {
		if n-i < 3 {
			return "none" // structure error is reported through tlvs=ERR
		}
		l := int(binary.BigEndian.Uint16(raw[i+1 : i+3]))
		if i+3+l > n {
			return "none"
		}
		if raw[i] == 0x03 {
			cnt++
			if l != 4 {
				bad = true
			}
			off = i + 3
		}
		i += 3 + l
	}
	if cnt == 0 {
		return "none"
	}
	if cnt > 1 || bad {
		return "malformed"
	}
	buf := append([]byte(nil), raw[:n]...)
	copy(buf[off:off+4], []byte{0, 0, 0, 0})
	want := binary.BigEndian.Uint32(raw[off : off+4])
	if crc32.Checksum(buf, crc32.MakeTable(crc32.Castagnoli)) == want {
		return "ok"
	}
	return "bad"
}

func doParse(data []byte) string {
	h, payload, err := proxyproto.ParseUDPDatagram(data)
	if err != nil {
		return "ERR " + errName(err)
	}
	// consumed = datagram length - payload length
	n := len(data) - len(payload)
	var canon string
	switch {
	case h.Command.IsLocal():
		canon = fmt.Sprintf("v%d L - - - - n=%d", h.Version, n)
	default:
		canon = fmt.Sprintf("v%d P %s %s %s %s n=%d", h.Version, famName(h.TransportProtocol),
			addrText(h.SourceAddr), addrText(h.DestinationAddr), tlvOrDash(h), n)
	}
	crc := "none"
	if h.Version == 2 && !h.Command.IsLocal() {
		crc = crcState(h, data, n)
	}
	return "OK " + canon + " crc=" + crc
}

func tlvOrDash(h *proxyproto.Header) string {
	if h.Version != 2 {
		return "-"
	}
	return tlvText(h)
}

// ssl checks the extra SSL TLV validation of tlvparse: printed for P answers
// only when the caller asks with "S <hex>".
func doSSL(data []byte) string {
	h, _, err := proxyproto.ParseUDPDatagram(data)
	if err != nil {
		return "ERR " + errName(err)
	}
	tlvs, err := h.TLVs()
	if err != nil {
		return "ERR TLV"
	}
	for _, t := range tlvs {
		if t.Type == proxyproto.PP2_TYPE_SSL {
			if _, err := tlvparse.SSL(t); err != nil {
				return "SSLBAD"
			}
			return "SSLOK"
		}
	}
	return "NOSSL"
}

func unhex(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex " + s)
	}
	return b
}

func parseIPPort(s string) (net.IP, int) {
	i := strings.IndexByte(s, ':')
	p, _ := strconv.Atoi(s[i+1:])
	return net.IP(unhex(s[:i])), p
}

// doWrite: desc = <ver> <cmd> <fam> <src> <dst> <tlvs> <crc>
func doWrite(desc string) string {
	f := strings.Split(desc, " ")
	if len(f) != 7 {
		return "E BadDesc"
	}
	ver, _ := strconv.Atoi(f[0])
	var h *proxyproto.Header
	overridden := false
	if f[1] == "L" {
		h = proxyproto.HeaderProxyFromAddrs(byte(ver), nil, nil)
	} else {
		var src, dst net.Addr
		var want proxyproto.AddressFamilyAndProtocol
		switch f[2] {
		case "tcp4", "tcp6":
			si, sp := parseIPPort(f[3])
			di, dp := parseIPPort(f[4])
			src, dst = &net.TCPAddr{IP: si, Port: sp}, &net.TCPAddr{IP: di, Port: dp}
			want = proxyproto.TCPv4
			if f[2] == "tcp6" {
				want = proxyproto.TCPv6
			}
		case "udp4", "udp6":
			si, sp := parseIPPort(f[3])
			di, dp := parseIPPort(f[4])
			src, dst = &net.UDPAddr{IP: si, Port: sp}, &net.UDPAddr{IP: di, Port: dp}
			want = proxyproto.UDPv4
			if f[2] == "udp6" {
				want = proxyproto.UDPv6
			}
		case "unixs", "unixd":
			nw, want2 := "unix", proxyproto.UnixStream
			if f[2] == "unixd" {
				nw, want2 = "unixgram", proxyproto.UnixDatagram
			}
			src = &net.UnixAddr{Net: nw, Name: string(unhex(strings.TrimPrefix(f[3], "u:")))}
			dst = &net.UnixAddr{Net: nw, Name: string(unhex(strings.TrimPrefix(f[4], "u:")))}
			want = want2
		default:
			return "E BadDesc"
		}
		h = proxyproto.HeaderProxyFromAddrs(byte(ver), src, dst)
		if h.TransportProtocol != want {
			// HeaderProxyFromAddrs infers the family from the addresses (a
			// v4-mapped pair under TCP6 becomes TCP4): build the header the
			// description asks for directly.
			h = &proxyproto.Header{Version: byte(ver), Command: proxyproto.PROXY, TransportProtocol: want, SourceAddr: src, DestinationAddr: dst}
			overridden = true
		}
	}
	suffix := ""
	if overridden {
		suffix = " hp-override"
	}
	var tl []proxyproto.TLV
	if f[5] != "-" {
		for _, p := range strings.Split(f[5], ",") {
			c := strings.IndexByte(p, ':')
			t, _ := strconv.ParseUint(p[:c], 16, 8)
			tl = append(tl, proxyproto.TLV{Type: proxyproto.PP2Type(t), Value: unhex(p[c+1:])})
		}
	}
	crc := f[6] == "1"
	if crc {
		// The CRC32C TLV is appended by the oracle (go-proxyproto has no writer
		// for it): zero field, checksum over the whole header, set the field.
		tl = append(tl, proxyproto.TLV{Type: proxyproto.PP2_TYPE_CRC32C, Value: []byte{0, 0, 0, 0}})
	}
	if len(tl) != 0 {
		if err := h.SetTLVs(tl); err != nil {
			return "E " + errName(err)
		}
	}
	b, err := h.Format()
	if err != nil {
		return "E " + errName(err)
	}
	if crc {
		binary.BigEndian.PutUint32(b[len(b)-4:], crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	}
	return "H " + hex.EncodeToString(b) + suffix
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			fmt.Fprintln(out, "ERR BadLine")
			continue
		}
		arg := line[2:]
		switch line[0] {
		case 'P':
			var b []byte
			if arg != "-" {
				var err error
				if b, err = hex.DecodeString(arg); err != nil {
					fmt.Fprintln(out, "ERR BadHex")
					continue
				}
			}
			fmt.Fprintln(out, doParse(b))
		case 'S':
			b, err := hex.DecodeString(arg)
			if err != nil {
				fmt.Fprintln(out, "ERR BadHex")
				continue
			}
			fmt.Fprintln(out, doSSL(b))
		case 'G':
			fmt.Fprintln(out, doWrite(arg))
		default:
			fmt.Fprintln(out, "ERR BadLine")
		}
	}
}
