// SPDX-License-Identifier: MIT

// Area read: archives built here -- by Go's Writer from entry tables, and
// header by header from raw fields -- and what Go's Reader returns for them.
package main

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

type readCase struct {
	id   string
	data []byte
}

// ── raw header construction ─────────────────────────────────────────────────

type hdr [512]byte

// newHdr: a POSIX ustar header ("ustar\0" "00") for a regular file, the
// numeric fields in the zero-padded 7/11-digit + NUL form GNU tar writes.
func newHdr(name string, typ byte, size int64) *hdr {
	var h hdr
	copy(h[0:100], name)
	copy(h[100:108], "0000644\x00")
	copy(h[108:116], "0001750\x00")
	copy(h[116:124], "0001750\x00")
	copy(h[124:136], fmt.Sprintf("%011o\x00", size))
	copy(h[136:148], "13627356000\x00") // 1600000000
	h[156] = typ
	copy(h[257:263], "ustar\x00")
	copy(h[263:265], "00")
	return &h
}

// set overwrites the field at off with exactly the bytes of v, zero-filling
// the rest of the field (n bytes long).
func (h *hdr) set(off, n int, v string) *hdr {
	for i := off; i < off+n; i++ {
		h[i] = 0
	}
	copy(h[off:off+n], v)
	return h
}

func (h *hdr) magicGNU() *hdr  { copy(h[257:265], "ustar  \x00"); return h }
func (h *hdr) magicNone() *hdr { return h.set(257, 8, "") }

// b256 writes v into the field as the GNU/star base-256 form: a leading
// 0x80 (positive) or 0xff (negative, two's complement) and big-endian bytes.
func (h *hdr) b256(off, n int, v int64) *hdr {
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], uint64(v))
	fill := byte(0)
	if v < 0 {
		fill = 0xff
	}
	for i := off; i < off+n; i++ {
		h[i] = fill
	}
	copy(h[off+n-8:off+n], be[:])
	if v >= 0 {
		h[off] = 0x80
	} else {
		h[off] = 0xff
	}
	return h
}

// sum: the checksum field as "%06o\0 " over the unsigned byte sum.
func (h *hdr) sum() []byte {
	copy(h[148:156], "        ")
	var s int64
	for _, c := range h {
		s += int64(c)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", s))
	return h[:]
}

// raw: the block as is, checksum field untouched.
func (h *hdr) raw() []byte { return h[:] }

func pad(content string) []byte {
	b := []byte(content)
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

var trailer = make([]byte, 1024)

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// file: one regular-file header + its content, checksummed.
func file(name, content string) []byte {
	return cat(newHdr(name, '0', int64(len(content))).sum(), pad(content))
}

// pax: an 'x' header carrying exactly the bytes of payload.
func pax(payload string) []byte {
	return cat(newHdr("././@PaxHeader", 'x', int64(len(payload))).sum(), pad(payload))
}

// rec: one well-formed pax record "<len> key=value\n".
func rec(key, value string) string {
	body := len(key) + len(value) + 2
	n := body + 2
	for len(fmt.Sprint(n))+1+body != n {
		n = len(fmt.Sprint(n)) + 1 + body
	}
	return fmt.Sprintf("%d %s=%s\n", n, key, value)
}

func gnuLong(typ byte, payload string) []byte {
	h := newHdr("././@LongLink", typ, int64(len(payload)))
	h.magicGNU()
	return cat(h.sum(), pad(payload))
}

// ── Go-written archives ─────────────────────────────────────────────────────

func unix(sec int64, nsec int64) time.Time { return time.Unix(sec, nsec) }

type goEntry struct {
	h       tar.Header
	content string
}

func goFile(name, content string) goEntry {
	return goEntry{tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Uid: 1000, Gid: 1000, Size: int64(len(content)), ModTime: unix(1600000000, 0)}, content}
}

func goSets() map[string][]goEntry {
	long150 := strings.Repeat("d", 49) + "/" + strings.Repeat("e", 100)
	long300 := strings.Repeat("p", 300)
	f := func(mut func(*tar.Header)) goEntry {
		e := goFile("f.txt", "content\n")
		mut(&e.h)
		return e
	}
	return map[string][]goEntry{
		"basic": {
			goFile("a.txt", "hello\n"),
			{tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: unix(1600000000, 0)}, ""},
			{tar.Header{Name: "d/link", Typeflag: tar.TypeSymlink, Linkname: "../a.txt", Mode: 0o777, ModTime: unix(1600000000, 0)}, ""},
			{tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "a.txt", Mode: 0o644, ModTime: unix(1600000000, 0)}, ""},
			goFile("empty", ""),
			goFile("b512", strings.Repeat("x", 512)),
			goFile("b513", strings.Repeat("y", 513)),
		},
		"bigid":       {f(func(h *tar.Header) { h.Uid = 3000000; h.Gid = 4000001 })},
		"negtime":     {f(func(h *tar.Header) { h.ModTime = unix(-1, 0) }), f(func(h *tar.Header) { h.ModTime = unix(-315619200, 0) })},
		"bigtime":     {f(func(h *tar.Header) { h.ModTime = unix(10000000000, 0) })},
		"nsec":        {f(func(h *tar.Header) { h.ModTime = unix(1727700007, 123456789) }), f(func(h *tar.Header) { h.ModTime = unix(-2, 750000000) })},
		"longpath150": {goFile(long150, "deep\n")},
		"longpath300": {goFile(long300, "deeper\n")},
		"longlink":    {{tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: strings.Repeat("t", 150), Mode: 0o777, ModTime: unix(1600000000, 0)}, ""}},
		"nonascii":    {goFile("\xc4\x8d.txt", "c\n")},
		"modebits":    {f(func(h *tar.Header) { h.Mode = 0o4755 }), f(func(h *tar.Header) { h.Mode = 0o7777 })},
		"names":       {f(func(h *tar.Header) { h.Uname = "user"; h.Gname = "group" })},
		"xattr":       {f(func(h *tar.Header) { h.PAXRecords = map[string]string{"SCHILY.xattr.user.k": "v"} })},
		"devs": {
			{tar.Header{Name: "null", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3, Mode: 0o666, ModTime: unix(1600000000, 0)}, ""},
			{tar.Header{Name: "fifo", Typeflag: tar.TypeFifo, Mode: 0o644, ModTime: unix(1600000000, 0)}, ""},
		},
	}
}

func goWritten() []readCase {
	formats := []struct {
		name string
		f    tar.Format
	}{{"ustar", tar.FormatUSTAR}, {"pax", tar.FormatPAX}, {"gnu", tar.FormatGNU}}
	sets := goSets()
	order := []string{"basic", "bigid", "negtime", "bigtime", "nsec", "longpath150", "longpath300", "longlink", "nonascii", "modebits", "names", "xattr", "devs"}
	var out []readCase
	for _, s := range order {
		for _, fm := range formats {
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			ok := true
			for _, e := range sets[s] {
				h := e.h
				h.Format = fm.f
				if err := tw.WriteHeader(&h); err != nil {
					ok = false // this format cannot carry the set: no case
					break
				}
				if _, err := tw.Write([]byte(e.content)); err != nil {
					ok = false
					break
				}
			}
			if !ok || tw.Close() != nil {
				continue
			}
			out = append(out, readCase{"go_" + fm.name + "_" + s, buf.Bytes()})
		}
	}
	// A pax global header, then a file (Go returns the 'g' header itself).
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "global", PAXRecords: map[string]string{"comment": "all"}, Format: tar.FormatPAX})
	h := goFile("after-global", "g\n").h
	h.Format = tar.FormatPAX
	tw.WriteHeader(&h)
	tw.Write([]byte("g\n"))
	tw.Close()
	out = append(out, readCase{"go_pax_global", buf.Bytes()})
	return out
}

// ── crafted archives ────────────────────────────────────────────────────────

func crafted() []readCase {
	var c []readCase
	add := func(id string, parts ...[]byte) { c = append(c, readCase{id, cat(parts...)}) }
	withTrailer := func(id string, parts ...[]byte) { add(id, append(parts, trailer)...) }

	// typeflag NUL (old "regular file") and the trailing-slash convention
	withTrailer("regA_file", newHdr("f", 0, 3).sum(), pad("abc"))
	withTrailer("regA_slash", newHdr("dir/", 0, 0).sum())
	withTrailer("reg0_slash", newHdr("dir/", '0', 0).sum())

	// magic variants and the prefix field
	withTrailer("prefix_posix", newHdr("name", '0', 0).set(345, 155, "pre").sum())
	withTrailer("prefix_v7", newHdr("name", '0', 0).magicNone().set(345, 155, "pre").sum())
	withTrailer("prefix_gnu", newHdr("name", '0', 0).magicGNU().set(345, 155, "pre").sum())
	withTrailer("prefix_version_nul", newHdr("name", '0', 0).set(263, 2, "").set(345, 155, "pre").sum())
	withTrailer("prefix_star", newHdr("name", '0', 0).set(345, 131, "pre").set(508, 4, "tar\x00").sum())
	withTrailer("name100_nonul", newHdr(strings.Repeat("n", 100), '0', 0).sum())
	withTrailer("prefix155_nonul", newHdr(strings.Repeat("n", 100), '0', 0).set(345, 155, strings.Repeat("p", 155)).sum())
	withTrailer("link100_nonul", newHdr("l", '2', 0).set(157, 100, strings.Repeat("t", 100)).sum())
	withTrailer("name_nul_junk", newHdr("ab\x00cd", '0', 0).sum())

	// base-256 numeric fields (GNU/star)
	withTrailer("uid_b256", newHdr("f", '0', 0).b256(108, 8, 3000000).sum())
	withTrailer("gid_b256", newHdr("f", '0', 0).b256(116, 8, 4000001).sum())
	withTrailer("uid_b256_2p32", newHdr("f", '0', 0).b256(108, 8, 1<<32).sum())
	withTrailer("uid_b256_neg", newHdr("f", '0', 0).b256(108, 8, -1).sum())
	withTrailer("mode_b256", newHdr("f", '0', 0).b256(100, 8, 0o644).sum())
	withTrailer("mtime_b256_neg1", newHdr("f", '0', 0).b256(136, 12, -1).sum())
	withTrailer("mtime_b256_1960", newHdr("f", '0', 0).b256(136, 12, -315619200).sum())
	withTrailer("mtime_b256_big", newHdr("f", '0', 0).b256(136, 12, 10000000000).sum())
	withTrailer("size_b256_small", newHdr("f", '0', 0).b256(124, 12, 5).sum(), pad("12345"))
	withTrailer("size_b256_neg", newHdr("f", '0', 0).b256(124, 12, -1).sum())

	// octal field shapes
	withTrailer("uid_garbage", newHdr("f", '0', 0).set(108, 8, "12x4567\x00").sum())
	withTrailer("uid_inner_space", newHdr("f", '0', 0).set(108, 8, "12 3456\x00").sum())
	withTrailer("uid_8digits", newHdr("f", '0', 0).set(108, 8, "77777777").sum())
	withTrailer("uid_spaces", newHdr("f", '0', 0).set(108, 8, "        ").sum())
	withTrailer("uid_empty", newHdr("f", '0', 0).set(108, 8, "").sum())
	withTrailer("uid_space_padded", newHdr("f", '0', 0).set(108, 8, "  1750 \x00").sum())
	withTrailer("uid_digit8", newHdr("f", '0', 0).set(108, 8, "0001758\x00").sum())
	withTrailer("mode_garbage", newHdr("f", '0', 0).set(100, 8, "06z4\x00").sum())
	withTrailer("mtime_garbage", newHdr("f", '0', 0).set(136, 12, "1362735600x\x00").sum())
	withTrailer("size_garbage", newHdr("f", '0', 0).set(124, 12, "0000000000z\x00").sum(), pad("12345"))
	withTrailer("size_12digits", newHdr("f", '0', 0).set(124, 12, "000000000005").sum(), pad("12345"))
	withTrailer("size_spaces", newHdr("f", '0', 0).set(124, 12, "          5 ").sum(), pad("12345"))
	withTrailer("size_plus", newHdr("f", '0', 0).set(124, 12, "+5\x00").sum(), pad("12345"))

	// checksum
	signed := newHdr("\xff\xfe-high", '0', 0)
	var s int64
	copy(signed[148:156], "        ")
	for _, b := range signed {
		s += int64(int8(b))
	}
	copy(signed[148:156], fmt.Sprintf("%06o\x00 ", s))
	withTrailer("checksum_signed", signed.raw())
	bad := newHdr("f", '0', 0)
	bad.sum()
	bad[148] = '7'
	withTrailer("checksum_bad", bad.raw())
	withTrailer("checksum_garbage", newHdr("f", '0', 0).set(148, 8, "abc\x00    ").raw())
	nospace := newHdr("f", '0', 0)
	nospace.sum()
	copy(nospace[148:156], fmt.Sprintf("%07o\x00", sumOf(nospace)))
	withTrailer("checksum_7digits", nospace.raw())
	withTrailer("checksum_empty", newHdr("f", '0', 0).set(148, 8, "").raw())

	// typeflags and the content each one carries
	withTrailer("type7", newHdr("c", '7', 3).sum(), pad("abc"))
	for _, t := range "123456" {
		withTrailer(fmt.Sprintf("type%c_claims_size", t), newHdr("x", byte(t), 512).sum(), file("hidden", "h"))
	}
	withTrailer("typeX_unknown", newHdr("u", 'X', 3).sum(), pad("abc"))
	withTrailer("typeV_volume", newHdr("vol", 'V', 0).magicGNU().sum(), file("a", "1"))

	// GNU 'L' / 'K'
	withTrailer("gnuL", gnuLong('L', strings.Repeat("L", 120)+"\x00"), file("short", "1"))
	withTrailer("gnuL_nonul", gnuLong('L', strings.Repeat("L", 120)), file("short", "1"))
	withTrailer("gnuL_inner_nul", gnuLong('L', "ab\x00cd\x00"), file("short", "1"))
	withTrailer("gnuL_empty", gnuLong('L', ""), file("short", "1"))
	withTrailer("gnuL_twice", gnuLong('L', "first\x00"), gnuLong('L', "second\x00"), file("short", "1"))
	withTrailer("gnuL_dangling", gnuLong('L', "orphan\x00"))
	withTrailer("gnuK", gnuLong('K', strings.Repeat("K", 120)+"\x00"), newHdr("s", '2', 0).set(157, 100, "short").sum())
	withTrailer("gnuK_on_file", gnuLong('K', "target\x00"), file("plain", "1"))
	withTrailer("gnuL_then_pax", gnuLong('L', "gnu-name\x00"), pax(rec("path", "pax-name")), file("short", "1"))
	withTrailer("pax_then_gnuL", pax(rec("path", "pax-name")), gnuLong('L', "gnu-name\x00"), file("short", "1"))
	withTrailer("gnuL_then_regular_twice", gnuLong('L', "only-first\x00"), file("one", "1"), file("two", "2"))

	// pax records
	px := func(id string, payload string, parts ...[]byte) {
		if len(parts) == 0 {
			parts = [][]byte{file("hdr-name", "abc")}
		}
		withTrailer("pax_"+id, append([][]byte{pax(payload)}, parts...)...)
	}
	px("path", rec("path", "from/pax"))
	px("path_empty", rec("path", ""))
	px("path_nul", rec("path", "a\x00b"))
	px("path_dup", rec("path", "one")+rec("path", "two"))
	px("linkpath", rec("linkpath", "far"), newHdr("s", '2', 0).set(157, 100, "near").sum())
	px("linkpath_on_file", rec("linkpath", "far"))
	px("size", rec("size", "5"), newHdr("f", '0', 0).sum(), pad("12345"))
	px("size_neg", rec("size", "-1"))
	px("size_plus", rec("size", "+3"))
	px("size_space", rec("size", " 3"))
	px("size_empty", rec("size", ""))
	px("size_huge", rec("size", "99999999999999999999"))
	px("uid", rec("uid", "3000000")+rec("gid", "4000001"))
	px("uid_plus", rec("uid", "+5"))
	px("uid_neg", rec("uid", "-5"))
	px("uid_space", rec("uid", " 5"))
	px("uid_2p32", rec("uid", "4294967296"))
	px("uid_2p31", rec("uid", "2147483648"))
	px("uid_garbage", rec("uid", "12x"))
	px("uid_empty", rec("uid", ""))
	px("mtime", rec("mtime", "1727700007.123456789"))
	px("mtime_neg_frac", rec("mtime", "-1.25"))
	px("mtime_neg_zero_frac", rec("mtime", "-0.5"))
	px("mtime_trailing_dot", rec("mtime", "1."))
	px("mtime_leading_dot", rec("mtime", ".5"))
	px("mtime_plus", rec("mtime", "+1"))
	px("mtime_exp", rec("mtime", "1e3"))
	px("mtime_minus_only", rec("mtime", "-"))
	px("mtime_10_frac_digits", rec("mtime", "1.1234567891"))
	px("mtime_huge", rec("mtime", "99999999999999999999"))
	px("mtime_empty", rec("mtime", ""))
	px("unknown_key", rec("comment", "anything"))
	px("unknown_key_nul", rec("comment", "a\x00b"))
	px("xattr_nul", rec("SCHILY.xattr.user.bin", "a\x00b"))
	px("key_empty", "6 =ab\n")
	px("no_equals", "9 noequal\n")
	px("len_short", "5 path=abc\n")
	px("len_long", "99 path=abc\n")
	px("len_zero", "0 path=abc\n")
	px("len_leading_zero", "014 path=abc\n")
	px("len_plus", "+13 path=abc\n")
	px("no_newline", "12 path=abcX")
	px("no_space", "13path=abc\n\n")
	px("empty_payload", "")
	px("key_with_space", rec("my key", "v"))
	withTrailer("pax_dangling", pax(rec("path", "orphan")))
	withTrailer("pax_twice", pax(rec("path", "first")), pax(rec("path", "second")), file("hdr", "1"))
	withTrailer("pax_applies_once", pax(rec("path", "only-first")+rec("uid", "77")), file("one", "1"), file("two", "2"))
	withTrailer("pax_global_then_file", cat(newHdr("g", 'g', int64(len(rec("path", "global-path")))).sum(), pad(rec("path", "global-path"))), file("own-name", "1"))

	// archive end
	add("no_trailer", file("a", "1"))
	add("one_zero_block", file("a", "1"), make([]byte, 512))
	add("zero_block_then_header", file("a", "1"), make([]byte, 512), file("b", "2"), trailer)
	add("zero_block_then_garbage", file("a", "1"), make([]byte, 512), bytes.Repeat([]byte{'G'}, 512))
	add("eof_mid_header", file("a", "1"), newHdr("b", '0', 1).sum()[:300])
	add("eof_mid_content", newHdr("a", '0', 100).sum(), []byte("short"))
	add("eof_mid_padding", newHdr("a", '0', 3).sum(), []byte("abc"), make([]byte, 100))
	add("eof_after_content_block", newHdr("a", '0', 3).sum(), pad("abc"))
	add("garbage_block", bytes.Repeat([]byte{'G'}, 512), trailer)
	add("empty", nil)
	return c
}

func sumOf(h *hdr) int64 {
	var s int64
	for i, c := range h {
		if i >= 148 && i < 156 {
			c = ' '
		}
		s += int64(c)
	}
	return s
}

// ── Go's verdicts ───────────────────────────────────────────────────────────

// verdict reads data with Go's Reader: every header with its content, then
// the error that stopped it (nil at a clean end).
func verdict(data []byte) ([]string, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var entries []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return entries, err
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return entries, err
		}
		entries = append(entries, zigEntry(h, content))
	}
}

func zigEntry(h *tar.Header, content []byte) string {
	sec := h.ModTime.Unix()
	nsec := h.ModTime.Nanosecond()
	if h.ModTime.IsZero() {
		sec, nsec = 0, 0
	}
	return fmt.Sprintf(".{ .name = %s, .typeflag = 0x%02x, .mode = %d, .uid = %d, .gid = %d, .mtime = %d, .nsec = %d, .size = %d, .link = %s, .content = %s }",
		zigStr(h.Name), h.Typeflag, h.Mode, h.Uid, h.Gid, sec, nsec, h.Size, zigStr(h.Linkname), zigStr(string(content)))
}

func emitCases(b *bytes.Buffer, name, doc string, cases []readCase) {
	fmt.Fprintf(b, "%s\npub const %s = [_]Case{\n", doc, name)
	for _, c := range cases {
		entries, err := verdict(c.data)
		e := "null"
		if err != nil {
			e = zigStr(err.Error())
		}
		fmt.Fprintf(b, "    .{\n        .id = %s,\n        .archive = %s,\n        .entries = %s,\n        .err = %s,\n    },\n",
			zigStr(c.id), zigArchive(c.data), zigListIndented(entries), e)
	}
	fmt.Fprintf(b, "};\n\n")
}

func zigListIndented(items []string) string {
	if len(items) == 0 {
		return "&.{}"
	}
	return "&.{\n            " + strings.Join(items, ",\n            ") + ",\n        }"
}

func emitRead(b *bytes.Buffer) {
	emitCases(b, "go_written", "/// Archives Go's own Writer produced (USTAR, PAX, GNU) for entry tables in read.go.", goWritten())
	emitCases(b, "crafted", "/// Archives built header by header in read.go: field shapes, typeflags, GNU and pax records, archive ends.", crafted())
}
