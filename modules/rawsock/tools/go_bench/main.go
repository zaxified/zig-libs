// SPDX-License-Identifier: MIT

// Go side of `zig build bench-rawsock` (modules/rawsock/tools/bench.zig):
// gopacket/pcapgo (savefile read and write, pcap and pcapng) and
// golang.org/x/net/bpf (the classic-BPF virtual machine) over the files the Zig
// program wrote into the directory given as the first argument. Prints one
// line: name, ns/op, count (tab-separated); stderr is the banner.
//
// Neither package compiles tcpdump expressions: the compile rows have no Go
// candidate. pcapgo returns each packet through `ZeroCopyReadPacketData`
// (no per-packet allocation), the closest to a slice reader it has.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/bpf"
)

const nExpr = 8
const nRunFrames = 2000

type frame struct {
	ci   gopacket.CaptureInfo
	data []byte
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadProgs(dir, prefix string) []*bpf.VM {
	vms := make([]*bpf.VM, nExpr)
	for i := range vms {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%s%d.bin", prefix, i)))
		must(err)
		raw := make([]bpf.RawInstruction, len(b)/8)
		for j := range raw {
			raw[j] = bpf.RawInstruction{
				Op: binary.LittleEndian.Uint16(b[j*8:]),
				Jt: b[j*8+2], Jf: b[j*8+3],
				K: binary.LittleEndian.Uint32(b[j*8+4:]),
			}
		}
		ins, ok := bpf.Disassemble(raw)
		if !ok {
			fmt.Fprintln(os.Stderr, "x/net/bpf cannot disassemble program", i)
			os.Exit(3)
		}
		vm, err := bpf.NewVM(ins)
		must(err)
		vms[i] = vm
	}
	return vms
}

func main() {
	if len(os.Args) < 3 {
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	fmt.Fprintln(os.Stderr, "gopacket v1.7.2 pcapgo + golang.org/x/net v0.55.0 bpf")

	read := func(file string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, file))
		must(err)
		return b
	}
	var op func() uint64
	switch name {
	case "pcap_read":
		file := read("frames.pcap")
		op = func() uint64 {
			r, err := pcapgo.NewReader(bytes.NewReader(file))
			must(err)
			var sum uint64
			for {
				d, ci, err := r.ZeroCopyReadPacketData()
				if err == io.EOF {
					break
				}
				must(err)
				sum += uint64(ci.CaptureLength) + uint64(ci.Length) + uint64(ci.Timestamp.UnixMicro())
				_ = d
			}
			return sum
		}
	case "pcapng_read":
		file := read("frames.pcapng")
		op = func() uint64 {
			r, err := pcapgo.NewNgReader(bytes.NewReader(file), pcapgo.DefaultNgReaderOptions)
			must(err)
			var sum uint64
			for {
				d, ci, err := r.ZeroCopyReadPacketData()
				if err == io.EOF {
					break
				}
				must(err)
				sum += uint64(ci.CaptureLength) + uint64(ci.Length) + uint64(ci.Timestamp.UnixMicro())
				_ = d
			}
			return sum
		}
	case "pcap_write":
		file := read("frames.pcap")
		r, err := pcapgo.NewReader(bytes.NewReader(file))
		must(err)
		var frames []frame
		for {
			d, ci, err := r.ReadPacketData()
			if err == io.EOF {
				break
			}
			must(err)
			frames = append(frames, frame{ci, d})
		}
		buf := bytes.NewBuffer(make([]byte, 0, len(file)+4096))
		op = func() uint64 {
			buf.Reset()
			w := pcapgo.NewWriter(buf)
			must(w.WriteFileHeader(262144, layers.LinkTypeEthernet))
			for _, f := range frames {
				must(w.WritePacket(f.ci, f.data))
			}
			return uint64(buf.Len())
		}
	case "filter_run", "filter_run_lp":
		prefix := "prog_"
		if name == "filter_run_lp" {
			prefix = "prog_lp_"
		}
		vms := loadProgs(dir, prefix)
		file := read("frames.pcap")
		r, err := pcapgo.NewReader(bytes.NewReader(file))
		must(err)
		var frames [][]byte
		for len(frames) < nRunFrames {
			d, _, err := r.ReadPacketData()
			if err == io.EOF {
				break
			}
			must(err)
			frames = append(frames, d)
		}
		op = func() uint64 {
			var n uint64
			for _, vm := range vms {
				for _, f := range frames {
					v, err := vm.Run(f)
					if err == nil && v != 0 {
						n++
					}
				}
			}
			return n
		}
	default:
		os.Exit(2)
	}

	reps := 1
	for {
		t := time.Now()
		for i := 0; i < reps; i++ {
			op()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		reps *= 2
	}
	best := time.Duration(1 << 62)
	var count uint64
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < reps; i++ {
			count = op()
		}
		if d := time.Since(t) / time.Duration(reps); d < best {
			best = d
		}
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, float64(best.Nanoseconds()), count)
}
