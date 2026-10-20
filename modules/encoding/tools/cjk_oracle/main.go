// SPDX-License-Identifier: MIT

// Differential oracle for modules/encoding `cjk`: golang.org/x/text
// (BSD-3-Clause) encoding/{japanese,korean,simplifiedchinese,traditionalchinese}
// answers over generated inputs. Go is an oracle, not an authority: its
// answers are dumped here, compared against a literal transliteration of the
// WHATWG Encoding Standard (`std_ref.py`, which also freezes the result into
// ../../src/cjk_oracle_vectors.zig), and every disagreement is classified.
//
//	cd modules/encoding/tools/cjk_oracle
//	GOPROXY=off go run . -out "$DUMP"                 # inputs.txt + answers-*.bin
//	python3 -I std_ref.py "$DUMP" > ../../src/cjk_oracle_vectors.zig
//
// Needs golang.org/x/text v0.42.0 in the module cache (go.sum pins it).
//
// Domains (the same enumerations are rebuilt by std_ref.py and by
// src/cjk_test.zig, so only the random inputs travel, in inputs.txt):
//
//	d1  every single byte                     d2  every two-byte string
//	d3  0x8F + every two-byte string          d4  gb18030 four-byte forms
//	d5  random byte strings (shared)          d6  ISO-2022-JP token strings
//	e1  every code point, one at a time (strict: unmappable = ERR)
//	e2  random UTF-8 strings (shared), WHATWG "html" error mode
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
)

type enc struct {
	name string
	e    encoding.Encoding
	// the oracle for the DECODER (the Standard's GBK decoder is gb18030's)
	d encoding.Encoding
}

var encs = []enc{
	{"shift_jis", japanese.ShiftJIS, japanese.ShiftJIS},
	{"euc_jp", japanese.EUCJP, japanese.EUCJP},
	{"iso_2022_jp", japanese.ISO2022JP, japanese.ISO2022JP},
	{"euc_kr", korean.EUCKR, korean.EUCKR},
	{"gb18030", simplifiedchinese.GB18030, simplifiedchinese.GB18030},
	{"gbk", simplifiedchinese.GBK, simplifiedchinese.GB18030},
	{"big5", traditionalchinese.Big5, traditionalchinese.Big5},
}

const errMark = 0xFFFFFFFF

func decode(e encoding.Encoding, in []byte) []byte {
	out, err := e.NewDecoder().Bytes(in)
	if err != nil {
		return nil
	}
	return out
}

func decodeOK(e encoding.Encoding, in []byte) ([]byte, bool) {
	out, err := e.NewDecoder().Bytes(in)
	return out, err == nil
}

type writer struct{ buf []byte }

func (w *writer) rec(b []byte, ok bool) {
	if !ok {
		w.buf = binary.LittleEndian.AppendUint32(w.buf, errMark)
		return
	}
	w.buf = binary.LittleEndian.AppendUint32(w.buf, uint32(len(b)))
	w.buf = append(w.buf, b...)
}

func (w *writer) flush(path string) {
	if err := os.WriteFile(path, w.buf, 0o644); err != nil {
		panic(err)
	}
}

// e1Cps: the same list as std_ref.py and cjk_test.zig.
func e1Cps() []rune {
	var cps []rune
	for c := rune(0); c < 0x30000; c++ {
		if c >= 0xD800 && c <= 0xDFFF {
			continue
		}
		cps = append(cps, c)
	}
	for c := rune(0x30000); c <= 0x10FFFF; c += 7 {
		cps = append(cps, c)
	}
	cps = append(cps, 0x10FFFF)
	return cps
}

func hexs(b []byte) string { return fmt.Sprintf("%x", b) }

func randomDecodeInputs(r *rand.Rand, n int) [][]byte {
	special := []byte{0x80, 0xFF, 0xFE, 0x8E, 0x8F, 0xA0, 0xA1, 0xDF, 0xE0, 0x9F, 0xFC, 0x7F, 0x00, 0x1B}
	ascii := []byte("AaZz09()$@BJI\\~-/ \r\n.")
	var out [][]byte
	for i := 0; i < n; i++ {
		l := 1 + r.IntN(12)
		b := make([]byte, l)
		for j := range b {
			switch k := r.IntN(100); {
			case k < 35:
				b[j] = byte(0x81 + r.IntN(0x7E)) // 0x81..0xFE
			case k < 55:
				b[j] = ascii[r.IntN(len(ascii))]
			case k < 65:
				b[j] = byte(0x30 + r.IntN(10))
			case k < 80:
				b[j] = byte(0x40 + r.IntN(0x3F)) // trail range
			default:
				b[j] = special[r.IntN(len(special))]
			}
		}
		out = append(out, b)
	}
	return out
}

func randomIsoInputs(r *rand.Rand, n int) [][]byte {
	toks := [][]byte{
		[]byte("\x1b$B"), []byte("\x1b$@"), []byte("\x1b(B"), []byte("\x1b(J"), []byte("\x1b(I"),
		[]byte("\x1b$(D"), []byte("\x1b"), []byte("\x1b$"), []byte("\x1b("), []byte("\x1b(X"), []byte("\x1b$A"),
		[]byte("\x0e"), []byte("\x0f"), []byte("\\"), []byte("~"), []byte("A"), []byte("\x00"), []byte("\x7f"), []byte("\x80"),
	}
	var out [][]byte
	for i := 0; i < n; i++ {
		var b []byte
		for t := 1 + r.IntN(8); t > 0; t-- {
			switch k := r.IntN(100); {
			case k < 35:
				b = append(b, toks[r.IntN(len(toks))]...)
			case k < 60:
				b = append(b, byte(0x21+r.IntN(0x5E)), byte(0x21+r.IntN(0x5E)))
			case k < 75:
				b = append(b, byte(0x21+r.IntN(0x5E)))
			case k < 90:
				b = append(b, byte(0x21+r.IntN(0x3F))) // katakana range
			default:
				b = append(b, byte(r.IntN(256)))
			}
		}
		out = append(out, b)
	}
	return out
}

func randomEncodeInputs(r *rand.Rand, n int) [][]byte {
	pools := [][2]rune{
		{0x20, 0x7E}, {0x0, 0x1F}, {0x5C, 0x5C}, {0x7E, 0x7E}, {0xA5, 0xA5}, {0x203E, 0x203E}, {0x2212, 0x2212},
		{0xFF61, 0xFF9F}, {0x4E00, 0x9FA5}, {0x3041, 0x3093}, {0x30A1, 0x30F6}, {0xAC00, 0xD7A3}, {0xA0, 0xFF},
		{0x80, 0x80}, {0x20AC, 0x20AC}, {0xE5E5, 0xE5E5}, {0xE78D, 0xE796}, {0xE81E, 0xE864}, {0xFFFD, 0xFFFD},
		{0x20000, 0x2A6DF}, {0x1F600, 0x1F64F}, {0x10FFFF, 0x10FFFF}, {0x2550, 0x2550}, {0x255E, 0x255E},
		{0x5341, 0x5341}, {0x5345, 0x5345}, {0xCA, 0xCA}, {0xEA, 0xEA}, {0x304, 0x304}, {0x30C, 0x30C},
		{0xE000, 0xE0FF}, {0x3000, 0x303F}, {0xFF01, 0xFF5E}, {0xFFE0, 0xFFE6}, {0x2010, 0x2030},
	}
	var out [][]byte
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for l := 1 + r.IntN(10); l > 0; l-- {
			p := pools[r.IntN(len(pools))]
			sb.WriteRune(p[0] + rune(r.IntN(int(p[1]-p[0])+1)))
		}
		out = append(out, []byte(sb.String()))
	}
	return out
}

func main() {
	dir := flag.String("out", "", "directory for inputs.txt and answers-*.bin")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: go run . -out DIR")
		os.Exit(2)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		panic(err)
	}
	r := rand.New(rand.NewPCG(0xC1CADA, 0x5EED))
	d5 := randomDecodeInputs(r, 2500)
	d6 := randomIsoInputs(r, 1500)
	e2 := randomEncodeInputs(r, 1500)
	var sb strings.Builder
	for _, set := range []struct {
		n  string
		in [][]byte
	}{{"d5", d5}, {"d6", d6}, {"e2", e2}} {
		for _, b := range set.in {
			fmt.Fprintf(&sb, "%s %s\n", set.n, hexs(b))
		}
	}
	if err := os.WriteFile(filepath.Join(*dir, "inputs.txt"), []byte(sb.String()), 0o644); err != nil {
		panic(err)
	}
	cps := e1Cps()
	for _, c := range encs {
		dump := func(name string, f func(w *writer)) {
			w := &writer{}
			f(w)
			w.flush(filepath.Join(*dir, fmt.Sprintf("answers-%s-%s.bin", c.name, name)))
		}
		dec := func(in []byte, w *writer) {
			o, ok := decodeOK(c.d, in)
			w.rec(o, ok)
		}
		dump("d1", func(w *writer) {
			for i := 0; i < 256; i++ {
				dec([]byte{byte(i)}, w)
			}
		})
		dump("d2", func(w *writer) {
			for i := 0; i < 65536; i++ {
				dec([]byte{byte(i >> 8), byte(i)}, w)
			}
		})
		dump("d3", func(w *writer) {
			for i := 0; i < 65536; i++ {
				dec([]byte{0x8F, byte(i >> 8), byte(i)}, w)
			}
		})
		if c.name == "gb18030" || c.name == "gbk" {
			dump("d4", func(w *writer) {
				for a := 0x81; a <= 0xFE; a++ {
					for b := 0x30; b <= 0x39; b++ {
						for cc := 0x81; cc <= 0xFE; cc++ {
							for d := 0x30; d <= 0x39; d++ {
								dec([]byte{byte(a), byte(b), byte(cc), byte(d)}, w)
							}
						}
					}
				}
			})
		}
		dump("d5", func(w *writer) {
			for _, in := range d5 {
				dec(in, w)
			}
		})
		if c.name == "iso_2022_jp" {
			dump("d6", func(w *writer) {
				for _, in := range d6 {
					dec(in, w)
				}
			})
		}
		dump("e1", func(w *writer) {
			for _, cp := range cps {
				o, err := c.e.NewEncoder().Bytes([]byte(string(cp)))
				w.rec(o, err == nil)
			}
		})
		dump("e2", func(w *writer) {
			for _, in := range e2 {
				o, err := encoding.HTMLEscapeUnsupported(c.e.NewEncoder()).Bytes(in)
				w.rec(o, err == nil)
			}
		})
	}
	fmt.Println("ok")
}
