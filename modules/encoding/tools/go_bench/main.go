// SPDX-License-Identifier: MIT

// Go side of `zig build bench-encoding` (modules/encoding/tools/bench.zig):
// golang.org/x/text (v0.42.0, pinned in go.mod/go.sum, built with GOPROXY=off)
// over the SAME generated files the Zig side reads.
//
//	go_bench <work dir> <workload>           time it: name, ns/op, count (stderr: banner)
//	go_bench <work dir> <workload> check     print "output-length fnv1a64" once
//
// The workload table (name, kind, input file) is mirrored in bench.zig and
// rust_bench/src/main.rs. One op = the whole input through the whole-buffer
// API (`Decoder.Bytes` / `Encoder.Bytes`, the result a fresh slice); the count
// is the output length in bytes.
//
//	dec1250     charmap.Windows1250.NewDecoder().Bytes
//	decutf8     unicode.UTF8.NewDecoder().Bytes (malformed -> U+FFFD, maximal subparts)
//	u16dec      unicode.UTF16(LittleEndian, IgnoreBOM).NewDecoder().Bytes
//	u16enc      the same, NewEncoder().Bytes
//	enc1250     charmap.Windows1250.NewEncoder().Bytes
//	enc1250u    the Encoder's Transform in a loop; an unrepresentable rune
//	            (RepertoireError) writes '?' and the rune is skipped. Not
//	            encoding.ReplaceUnsupported: that writes the charmap's own
//	            replacement 0x1a, ours is '?'.
//	stream*     Transform(dst, chunk, atEOF) over 4 KiB chunks into one reused
//	            buffer; an incomplete trailing sequence is carried to the next chunk
//	celldec     one Decoder.Bytes per 20-byte cell (one Decoder, reset by Bytes)
//	cellenc     one Encoder.Bytes per cell
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

const chunk = 4096

type kind int

const (
	dec1250 kind = iota
	decUTF8
	u16dec
	u16enc
	enc1250
	enc1250u
	stream1250
	streamUTF8
	cellDec
	cellEnc
)

var works = []struct {
	name string
	k    kind
	file string
}{
	{"dec_1250_ascii", dec1250, "ascii-v1.bin"},
	{"dec_1250_czech", dec1250, "cz1250-v1.bin"},
	{"enc_1250_ascii", enc1250, "ascii-v1.bin"},
	{"enc_1250_czech", enc1250, "czutf8-v1.txt"},
	{"enc_1250_unmap", enc1250u, "unmap-v1.txt"},
	{"dec_utf8_ascii", decUTF8, "ascii-v1.bin"},
	{"dec_utf8_multi", decUTF8, "multi-v1.txt"},
	{"dec_utf8_bad", decUTF8, "bad-v1.txt"},
	{"u16_to_utf8", u16dec, "multi16-v1.bin"},
	{"utf8_to_u16", u16enc, "multi-v1.txt"},
	{"stream_1250", stream1250, "cz1250-v1.bin"},
	{"stream_utf8", streamUTF8, "multi-v1.txt"},
	{"cell_dec", cellDec, "cells1250-v1.bin"},
	{"cell_enc", cellEnc, "cellsutf8-v1.bin"},
}

var sink uint64

func fail(err error) {
	fmt.Fprintln(os.Stderr, "go_bench:", err)
	os.Exit(1)
}

// out: length always, FNV-1a-64 only when hashing.
type out struct {
	n       uint64
	h       uint64
	hashing bool
}

func (o *out) take(s []byte) {
	o.n += uint64(len(s))
	if o.hashing {
		for _, b := range s {
			o.h = (o.h ^ uint64(b)) * 0x100000001b3
		}
	} else if len(s) > 0 {
		sink += uint64(s[len(s)-1])
	}
}

func cells(data []byte) [][]byte {
	var v [][]byte
	for i := 0; i < len(data); {
		n := int(data[i])
		v = append(v, data[i+1:i+1+n])
		i += 1 + n
	}
	return v
}

func must(b []byte, err error) []byte {
	if err != nil {
		fail(err)
	}
	return b
}

func encode1250u(src []byte) []byte {
	t := charmap.Windows1250.NewEncoder()
	dst := make([]byte, len(src)+16)
	i, o := 0, 0
	for {
		nd, ns, err := t.Transform(dst[o:], src[i:], true)
		o += nd
		i += ns
		if err == nil {
			return dst[:o]
		}
		if err == transform.ErrShortDst || err == transform.ErrShortSrc {
			fail(fmt.Errorf("unexpected %v", err))
		}
		// RepertoireError: skip the rune, write '?'.
		_, sz := utf8.DecodeRune(src[i:])
		i += sz
		dst[o] = '?'
		o++
	}
}

func stream(t transform.Transformer, data []byte, o *out) {
	dst := make([]byte, 4*(chunk+4)+8)
	buf := make([]byte, 0, chunk+8)
	n := (len(data) + chunk - 1) / chunk
	for k := 0; k < n; k++ {
		hi := (k + 1) * chunk
		if hi > len(data) {
			hi = len(data)
		}
		buf = append(buf, data[k*chunk:hi]...)
		last := k+1 == n
		nd, ns, err := t.Transform(dst, buf, last)
		if err != nil && err != transform.ErrShortSrc {
			fail(err)
		}
		o.take(dst[:nd])
		buf = append(buf[:0], buf[ns:]...)
	}
}

func run(k kind, data []byte, cs [][]byte, o *out) {
	switch k {
	case dec1250:
		o.take(must(charmap.Windows1250.NewDecoder().Bytes(data)))
	case decUTF8:
		o.take(must(unicode.UTF8.NewDecoder().Bytes(data)))
	case u16dec:
		o.take(must(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(data)))
	case u16enc:
		o.take(must(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes(data)))
	case enc1250:
		o.take(must(charmap.Windows1250.NewEncoder().Bytes(data)))
	case enc1250u:
		o.take(encode1250u(data))
	case stream1250:
		stream(charmap.Windows1250.NewDecoder(), data, o)
	case streamUTF8:
		stream(unicode.UTF8.NewDecoder(), data, o)
	case cellDec:
		d := charmap.Windows1250.NewDecoder()
		for _, c := range cs {
			o.take(must(d.Bytes(c)))
		}
	case cellEnc:
		var e *encoding.Encoder = charmap.Windows1250.NewEncoder()
		for _, c := range cs {
			o.take(must(e.Bytes(c)))
		}
	}
}

func main() {
	if len(os.Args) != 3 && !(len(os.Args) == 4 && os.Args[3] == "check") {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload> [check]")
		os.Exit(2)
	}
	check := len(os.Args) == 4
	idx := -1
	for i, w := range works {
		if w.name == os.Args[2] {
			idx = i
		}
	}
	if idx < 0 {
		fail(fmt.Errorf("unknown workload %q", os.Args[2]))
	}
	w := works[idx]
	data, err := os.ReadFile(filepath.Join(os.Args[1], w.file))
	if err != nil {
		fail(err)
	}
	var cs [][]byte
	if w.k == cellDec || w.k == cellEnc {
		cs = cells(data)
	}
	if check {
		o := out{h: 0xcbf29ce484222325, hashing: true}
		run(w.k, data, cs, &o)
		fmt.Printf("%d %d\n", o.n, o.h)
		return
	}
	op := func() uint64 {
		o := out{h: 0xcbf29ce484222325}
		run(w.k, data, cs, &o)
		return o.n
	}
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += op()
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
			count = op()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	fmt.Fprintf(os.Stderr, "%s golang.org/x/text v0.42.0 (whole-buffer Bytes API, default GC)\n", runtime.Version())
	fmt.Printf("%s\t%.1f\t%d\n", w.name, float64(best.Nanoseconds())/float64(n), count)
}
