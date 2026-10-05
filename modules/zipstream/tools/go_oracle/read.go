// SPDX-License-Identifier: MIT

// Area read: archives built here -- by Go's Writer from entry tables, and
// record by record from raw fields -- and what Go's Reader returns for them.
package main

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
	"time"
)

type readCase struct {
	id   string
	data []byte
}

// ── raw archive construction ────────────────────────────────────────────────

const (
	dosDate2020 = (40 << 9) | (3 << 5) | 3          // 2020-03-03
	dosTime2020 = (12 << 11) | (34 << 5) | (56 / 2) // 12:34:56
)

type zent struct {
	name      string
	lname     *string // the local header's name, when it differs
	content   []byte  // uncompressed bytes (CRC and size are computed from them)
	method    uint16  // 0 store, 8 deflate; any other: payload is content as is
	payload   []byte  // the stored bytes, overriding what method would produce
	flags     uint16
	date, tim *uint16
	madeBy    uint16
	extAttr   uint32
	extraL    []byte
	extraC    []byte
	comment   string
	crc       *uint32 // central and local
	csize     *uint32
	usize     *uint32
	lcrc      *uint32 // local only
	lsize     *uint32 // local compressed and uncompressed size
	desc      int     // 0 none, 1 data descriptor with signature, 2 without
	zip64     bool    // central sizes/offset as 0xFFFFFFFF + a zip64 extra
	localOff  *uint32
}

type zopt struct {
	prefix      []byte // bytes before the first local header (offsets NOT adjusted)
	absPrefix   []byte // bytes before the first local header, offsets adjusted
	comment     string
	countDelta  int
	cdOffDelta  int64
	cdSizeDelta int64
	disk        uint16
	zip64eocd   bool
	truncate    int // drop this many bytes from the end
}

func u16p(v uint16) *uint16 { return &v }
func u32p(v uint32) *uint32 { return &v }
func strp(v string) *string { return &v }

func rawDeflate(b []byte) []byte {
	var out bytes.Buffer
	w, _ := flate.NewWriter(&out, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func le(parts ...any) []byte {
	var b bytes.Buffer
	for _, p := range parts {
		binary.Write(&b, binary.LittleEndian, p)
	}
	return b.Bytes()
}

func buildZip(ents []zent, o zopt) []byte {
	var out bytes.Buffer
	out.Write(o.prefix)
	out.Write(o.absPrefix)
	base := uint32(len(o.prefix))
	var cd bytes.Buffer
	for _, e := range ents {
		payload := e.payload
		if payload == nil {
			if e.method == 8 {
				payload = rawDeflate(e.content)
			} else {
				payload = e.content
			}
		}
		crc := crc32.ChecksumIEEE(e.content)
		if e.crc != nil {
			crc = *e.crc
		}
		csize, usize := uint32(len(payload)), uint32(len(e.content))
		if e.csize != nil {
			csize = *e.csize
		}
		if e.usize != nil {
			usize = *e.usize
		}
		date, tim := uint16(dosDate2020), uint16(dosTime2020)
		if e.date != nil {
			date = *e.date
		}
		if e.tim != nil {
			tim = *e.tim
		}
		lname := e.name
		if e.lname != nil {
			lname = *e.lname
		}
		flags := e.flags
		lcrc, lcs, lus := crc, csize, usize
		if e.desc != 0 {
			flags |= 8
			lcrc, lcs, lus = 0, 0, 0
		}
		if e.lcrc != nil {
			lcrc = *e.lcrc
		}
		if e.lsize != nil {
			lcs, lus = *e.lsize, *e.lsize
		}
		off := uint32(out.Len()) - base
		if e.localOff != nil {
			off = *e.localOff
		}
		out.Write(le(uint32(0x04034b50), uint16(20), flags, e.method, tim, date, lcrc, lcs, lus, uint16(len(lname)), uint16(len(e.extraL))))
		out.WriteString(lname)
		out.Write(e.extraL)
		out.Write(payload)
		switch e.desc {
		case 1:
			out.Write(le(uint32(0x08074b50), crc, csize, usize))
		case 2:
			out.Write(le(crc, csize, usize))
		}
		extraC := e.extraC
		ccs, cus, coff := csize, usize, off
		if e.zip64 {
			extraC = append(le(uint16(1), uint16(24), uint64(usize), uint64(csize), uint64(off)), extraC...)
			ccs, cus, coff = 0xffffffff, 0xffffffff, 0xffffffff
		}
		madeBy := e.madeBy
		if madeBy == 0 {
			madeBy = 20
		}
		cd.Write(le(uint32(0x02014b50), madeBy, uint16(20), flags, e.method, tim, date, crc, ccs, cus,
			uint16(len(e.name)), uint16(len(extraC)), uint16(len(e.comment)), uint16(0), uint16(0), e.extAttr, coff))
		cd.WriteString(e.name)
		cd.Write(extraC)
		cd.WriteString(e.comment)
	}
	cdOff := int64(out.Len()) - int64(base) + o.cdOffDelta
	cdSize := int64(cd.Len()) + o.cdSizeDelta
	out.Write(cd.Bytes())
	count := len(ents) + o.countDelta
	if o.zip64eocd {
		eocd64Off := uint64(out.Len()) - uint64(base)
		out.Write(le(uint32(0x06064b50), uint64(44), uint16(45), uint16(45), uint32(0), uint32(0), uint64(count), uint64(count), uint64(cdSize), uint64(cdOff)))
		out.Write(le(uint32(0x07064b50), uint32(0), eocd64Off, uint32(1)))
		out.Write(le(uint32(0x06054b50), uint16(0), uint16(0), uint16(0xffff), uint16(0xffff), uint32(0xffffffff), uint32(0xffffffff), uint16(len(o.comment))))
	} else {
		out.Write(le(uint32(0x06054b50), o.disk, o.disk, uint16(count), uint16(count), uint32(cdSize), uint32(cdOff), uint16(len(o.comment))))
	}
	out.WriteString(o.comment)
	b := out.Bytes()
	return b[:len(b)-o.truncate]
}

func ent(name, content string) zent { return zent{name: name, content: []byte(content)} }
func dent(name, content string) zent {
	return zent{name: name, content: []byte(content), method: 8}
}

// utExtra: an Info-ZIP extended timestamp record with flags and the given
// times (each 4 bytes, little-endian, signed).
func utExtra(flags byte, times ...int32) []byte {
	b := le(uint16(0x5455), uint16(1+4*len(times)), flags)
	for _, t := range times {
		b = append(b, le(t)...)
	}
	return b
}

// ── Go-written archives ─────────────────────────────────────────────────────

func goWritten() []readCase {
	var out []readCase
	add := func(id string, build func(w *zip.Writer)) {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		build(w)
		if err := w.Close(); err != nil {
			fmt.Fprintln(os.Stderr, id, err)
			os.Exit(1)
		}
		out = append(out, readCase{"go_" + id, buf.Bytes()})
	}
	put := func(w *zip.Writer, h *zip.FileHeader, content string) {
		f, err := w.CreateHeader(h)
		if err != nil {
			fmt.Fprintln(os.Stderr, h.Name, err)
			os.Exit(1)
		}
		f.Write([]byte(content))
	}
	// Every set but "basic" carries a time: Go's Writer leaves the DOS date
	// 0 without one, which "basic" alone keeps (see dos_zero_date).
	stamp := time.Date(2024, 9, 30, 12, 40, 6, 0, time.UTC)
	big := strings.Repeat("the quick brown fox jumps over the lazy dog 0123456789\n", 1500)
	add("basic", func(w *zip.Writer) {
		put(w, &zip.FileHeader{Name: "a.txt", Method: zip.Deflate}, "hello\n")
		put(w, &zip.FileHeader{Name: "s.txt", Method: zip.Store}, "stored\n")
		put(w, &zip.FileHeader{Name: "d/", Method: zip.Store}, "")
		put(w, &zip.FileHeader{Name: "d/empty", Method: zip.Deflate}, "")
		put(w, &zip.FileHeader{Name: "big.txt", Method: zip.Deflate}, big)
	})
	add("modified", func(w *zip.Writer) {
		put(w, &zip.FileHeader{Name: "t2024", Method: zip.Store, Modified: time.Date(2024, 9, 30, 12, 40, 7, 0, time.UTC)}, "x")
		put(w, &zip.FileHeader{Name: "t1970", Method: zip.Store, Modified: time.Unix(0, 0).UTC()}, "x")
		put(w, &zip.FileHeader{Name: "t2100", Method: zip.Store, Modified: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}, "x")
		put(w, &zip.FileHeader{Name: "todd", Method: zip.Store, Modified: time.Date(2024, 9, 30, 12, 40, 7, 0, time.FixedZone("x", 7200))}, "x")
	})
	add("mode", func(w *zip.Writer) {
		for _, m := range []os.FileMode{0o644, 0o755, 0o4755 | os.ModeSetuid, os.ModeSetgid | 0o2750, os.ModeSticky | 0o1777, 0o600} {
			h := &zip.FileHeader{Name: fmt.Sprintf("m%o", m.Perm()), Method: zip.Store, Modified: stamp}
			h.SetMode(m)
			put(w, h, "m")
		}
	})
	add("utf8", func(w *zip.Writer) {
		put(w, &zip.FileHeader{Name: "\xc4\x8d.txt", Method: zip.Store, Modified: stamp}, "c")
		put(w, &zip.FileHeader{Name: "ascii.txt", Method: zip.Store, Modified: stamp}, "a")
		put(w, &zip.FileHeader{Name: "\xc4\x8d-nonutf8.txt", Method: zip.Store, NonUTF8: true, Modified: stamp}, "n")
	})
	add("comment", func(w *zip.Writer) {
		w.SetComment("archive comment")
		put(w, &zip.FileHeader{Name: "c", Method: zip.Store, Comment: "entry comment", Modified: stamp}, "c")
	})
	add("raw", func(w *zip.Writer) {
		data := rawDeflate([]byte("raw deflate\n"))
		f, _ := w.CreateRaw(&zip.FileHeader{Name: "raw", Method: zip.Deflate, Modified: stamp, CRC32: crc32.ChecksumIEEE([]byte("raw deflate\n")),
			CompressedSize64: uint64(len(data)), UncompressedSize64: 12})
		f.Write(data)
	})
	return out
}

// ── crafted archives ────────────────────────────────────────────────────────

func crafted() []readCase {
	var c []readCase
	add := func(id string, ents []zent, o zopt) { c = append(c, readCase{id, buildZip(ents, o)}) }

	add("store", []zent{ent("a.txt", "hello\n")}, zopt{})
	add("deflate", []zent{dent("a.txt", strings.Repeat("hello\n", 100))}, zopt{})
	add("empty_archive", nil, zopt{})
	add("backslash_name", []zent{ent("dir\\file.txt", "x")}, zopt{})
	add("dir_entry", []zent{ent("d/", ""), ent("d/f", "f")}, zopt{})
	add("dir_entry_with_content", []zent{ent("d/", "hidden")}, zopt{})
	add("empty_name", []zent{ent("", "x")}, zopt{})
	add("name_nul", []zent{ent("a\x00b", "x")}, zopt{})
	add("duplicate_names", []zent{ent("same", "one"), ent("same", "two")}, zopt{})
	add("abs_and_dotdot", []zent{ent("/etc/passwd", "p"), ent("../up", "u")}, zopt{})
	add("long_name_300", []zent{ent(strings.Repeat("n", 300), "x")}, zopt{})

	// local vs central header
	add("local_name_differs", []zent{{name: "central", lname: strp("local-name"), content: []byte("x")}}, zopt{})
	add("local_extra_differs", []zent{{name: "f", content: []byte("x"), extraL: bytes.Repeat([]byte{0xAB}, 37)}}, zopt{})
	add("local_crc_wrong", []zent{{name: "f", content: []byte("x"), lcrc: u32p(0xdeadbeef)}}, zopt{})
	add("local_size_wrong", []zent{{name: "f", content: []byte("xyz"), lsize: u32p(999)}}, zopt{})
	add("descriptor_sig", []zent{{name: "f", content: []byte("described"), method: 8, desc: 1}}, zopt{})
	add("descriptor_nosig", []zent{{name: "f", content: []byte("described"), method: 8, desc: 2}}, zopt{})
	add("descriptor_store", []zent{{name: "f", content: []byte("stored+desc"), desc: 1}}, zopt{})
	add("local_off_garbage", []zent{{name: "f", content: []byte("x"), localOff: u32p(3)}}, zopt{})
	add("local_off_past_end", []zent{{name: "f", content: []byte("x"), localOff: u32p(1 << 20)}}, zopt{})
	add("local_off_shared", []zent{ent("first", "shared"), {name: "second", content: []byte("shared"), localOff: u32p(0)}}, zopt{})

	// integrity
	add("crc_wrong", []zent{{name: "f", content: []byte("payload"), crc: u32p(1)}}, zopt{})
	add("crc_wrong_deflate", []zent{{name: "f", content: []byte(strings.Repeat("p", 500)), method: 8, crc: u32p(1)}}, zopt{})
	add("usize_short_deflate", []zent{{name: "f", content: []byte(strings.Repeat("abc", 100)), method: 8, usize: u32p(10)}}, zopt{})
	add("usize_long_deflate", []zent{{name: "f", content: []byte(strings.Repeat("abc", 100)), method: 8, usize: u32p(1000)}}, zopt{})
	add("store_csize_ne_usize", []zent{{name: "f", content: []byte("0123456789"), usize: u32p(5)}}, zopt{})
	add("store_csize_short", []zent{{name: "f", content: []byte("0123456789"), csize: u32p(5)}}, zopt{})
	add("deflate_garbage", []zent{{name: "f", content: []byte("abc"), method: 8, payload: []byte{0xff, 0xff, 0xff, 0xff}}}, zopt{})
	add("deflate_trailing_junk", []zent{{name: "f", content: []byte("abc"), method: 8, payload: append(rawDeflate([]byte("abc")), "JUNK"...)}}, zopt{})
	add("deflate_truncated", []zent{{name: "f", content: []byte(strings.Repeat("q", 400)), method: 8, payload: rawDeflate([]byte(strings.Repeat("q", 400)))[:3]}}, zopt{})

	// methods and flags
	add("method_bzip2", []zent{ent("ok", "fine"), {name: "bz", content: []byte("x"), method: 12}}, zopt{})
	add("method_aes99", []zent{{name: "aes", content: []byte("x"), method: 99}}, zopt{})
	add("encrypted_flag", []zent{{name: "enc", content: []byte("x"), flags: 1}}, zopt{})
	add("utf8_flag", []zent{{name: "\xc4\x8d.txt", content: []byte("x"), flags: 1 << 11}}, zopt{})
	add("cp437_name", []zent{{name: "\x87.txt", content: []byte("x")}}, zopt{})

	// times
	add("dos_zero_date", []zent{{name: "f", content: []byte("x"), date: u16p(0), tim: u16p(0)}}, zopt{})
	add("dos_month13", []zent{{name: "f", content: []byte("x"), date: u16p((40 << 9) | (13 << 5) | 1)}}, zopt{})
	add("dos_feb30", []zent{{name: "f", content: []byte("x"), date: u16p((40 << 9) | (2 << 5) | 30)}}, zopt{})
	add("dos_hour24", []zent{{name: "f", content: []byte("x"), tim: u16p(24 << 11)}}, zopt{})
	add("dos_sec60", []zent{{name: "f", content: []byte("x"), tim: u16p(30)}}, zopt{})
	add("dos_1980_min", []zent{{name: "f", content: []byte("x"), date: u16p((0 << 9) | (1 << 5) | 1), tim: u16p(0)}}, zopt{})
	add("dos_2107_max", []zent{{name: "f", content: []byte("x"), date: u16p((127 << 9) | (12 << 5) | 31), tim: u16p((23 << 11) | (59 << 5) | 29)}}, zopt{})
	add("ut_mtime", []zent{{name: "f", content: []byte("x"), extraC: utExtra(1, 1727700007)}}, zopt{})
	add("ut_negative", []zent{{name: "f", content: []byte("x"), extraC: utExtra(1, -1)}}, zopt{})
	add("ut_no_mtime_flag", []zent{{name: "f", content: []byte("x"), extraC: utExtra(2, 1727700007)}}, zopt{})
	add("ut_local_only", []zent{{name: "f", content: []byte("x"), extraL: utExtra(1, 1727700007)}}, zopt{})
	add("ut_short", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x5455), uint16(3), byte(1), uint16(7))}}, zopt{})
	add("ut_overrun", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x5455), uint16(40), byte(1), int32(1727700007))}}, zopt{})
	add("ut_after_other", []zent{{name: "f", content: []byte("x"), extraC: append(le(uint16(0xcafe), uint16(2), uint16(0)), utExtra(1, 1727700007)...)}}, zopt{})
	add("ut_twice", []zent{{name: "f", content: []byte("x"), extraC: append(utExtra(1, 1000000000), utExtra(1, 2000000000)...)}}, zopt{})
	add("ut_zero_date", []zent{{name: "f", content: []byte("x"), date: u16p(0), tim: u16p(0), extraC: utExtra(1, 1727700007)}}, zopt{})
	add("unix_extra_000d", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x000d), uint16(12), uint32(1600000000), uint32(1727700007), uint16(1000), uint16(1000))}}, zopt{})
	add("infozip_ux_5855", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x5855), uint16(8), uint32(1600000000), uint32(1727700007))}}, zopt{})
	add("ut_then_ntfs", []zent{{name: "f", content: []byte("x"), extraC: append(utExtra(1, 1000000000), le(uint16(0x000a), uint16(32), uint32(0), uint16(1), uint16(24), uint64(133720000000000000), uint64(0), uint64(0))...)}}, zopt{})
	add("ntfs_then_ut", []zent{{name: "f", content: []byte("x"), extraC: append(le(uint16(0x000a), uint16(32), uint32(0), uint16(1), uint16(24), uint64(133720000000000000), uint64(0), uint64(0)), utExtra(1, 1000000000)...)}}, zopt{})
	add("ntfs_short", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x000a), uint16(12), uint32(0), uint16(1), uint16(24), uint32(5))}}, zopt{})
	add("ut_2100_unsigned", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x5455), uint16(5), byte(1), uint32(4102444800))}}, zopt{})
	add("ntfs_extra", []zent{{name: "f", content: []byte("x"), extraC: le(uint16(0x000a), uint16(32), uint32(0), uint16(1), uint16(24), uint64(133720000000000000), uint64(0), uint64(0))}}, zopt{})

	// attributes
	add("unix_0644", []zent{{name: "f", content: []byte("x"), madeBy: 3<<8 | 20, extAttr: 0o100644 << 16}}, zopt{})
	add("unix_setuid", []zent{{name: "f", content: []byte("x"), madeBy: 3<<8 | 20, extAttr: 0o104755 << 16}}, zopt{})
	add("unix_zero_attr", []zent{{name: "f", content: []byte("x"), madeBy: 3<<8 | 20}}, zopt{})
	add("unix_symlink", []zent{{name: "l", content: []byte("target"), madeBy: 3<<8 | 20, extAttr: 0o120777 << 16}}, zopt{})
	add("unix_dir_attr_file_name", []zent{{name: "notslash", content: []byte(""), madeBy: 3<<8 | 20, extAttr: 0o040755 << 16}}, zopt{})
	add("dos_readonly", []zent{{name: "f", content: []byte("x"), extAttr: 0x01}}, zopt{})
	add("dos_dir_attr", []zent{{name: "notslash", content: []byte(""), extAttr: 0x10}}, zopt{})
	add("ntfs_host_attr", []zent{{name: "f", content: []byte("x"), madeBy: 10<<8 | 20, extAttr: 0o100644 << 16}}, zopt{})
	add("macos_host_unix_bits", []zent{{name: "f", content: []byte("x"), madeBy: 19<<8 | 20, extAttr: 0o100755 << 16}}, zopt{})

	// end of central directory
	add("eocd_comment", []zent{ent("f", "x")}, zopt{comment: "hello comment"})
	add("eocd_comment_fake_sig", []zent{ent("f", "x")}, zopt{comment: "PK\x05\x06" + strings.Repeat("\x00", 18)})
	add("eocd_comment_len_wrong", []zent{ent("f", "x")}, zopt{comment: "abc", truncate: 1})
	add("sfx_prefix_unadjusted", []zent{ent("f", "x"), ent("g", "y")}, zopt{prefix: bytes.Repeat([]byte{'S'}, 100)})
	add("sfx_prefix_adjusted", []zent{ent("f", "x")}, zopt{absPrefix: bytes.Repeat([]byte{'S'}, 100)})
	add("count_more", []zent{ent("f", "x"), ent("g", "y")}, zopt{countDelta: 1})
	add("count_less", []zent{ent("f", "x"), ent("g", "y")}, zopt{countDelta: -1})
	add("cd_offset_past_end", []zent{ent("f", "x")}, zopt{cdOffDelta: 1000})
	add("cd_offset_short", []zent{ent("f", "x")}, zopt{cdOffDelta: -5})
	add("cd_size_more", []zent{ent("f", "x")}, zopt{cdSizeDelta: 10})
	add("cd_size_less", []zent{ent("f", "x")}, zopt{cdSizeDelta: -10})
	add("multi_disk", []zent{ent("f", "x")}, zopt{disk: 1})
	add("no_eocd", []zent{ent("f", "x")}, zopt{truncate: 22})
	add("truncated_mid_cd", []zent{ent("f", "x")}, zopt{truncate: 30})
	add("zip64_extra", []zent{{name: "f", content: []byte("zip64 sizes"), zip64: true}}, zopt{zip64eocd: true})
	add("zip64_eocd_only", []zent{ent("f", "x"), ent("g", "y")}, zopt{zip64eocd: true})
	add("zip64_extra_no_eocd64", []zent{{name: "f", content: []byte("zip64 sizes"), zip64: true}}, zopt{})
	add("entry_comment", []zent{{name: "f", content: []byte("x"), comment: "about f"}}, zopt{})
	c = append(c, readCase{"not_a_zip", []byte("this is not a zip archive at all, just text that is long enough")})
	c = append(c, readCase{"zero_bytes", []byte{}})
	return c
}

// ── Go's verdicts ───────────────────────────────────────────────────────────

func zigEntry(f *zip.File) string {
	mtime := "null"
	if !f.Modified.IsZero() {
		mtime = fmt.Sprint(f.Modified.Unix())
	}
	mode := "null"
	if f.CreatorVersion>>8 == 3 && f.ExternalAttrs>>16 != 0 {
		m := f.Mode()
		p := uint32(m.Perm())
		if m&os.ModeSetuid != 0 {
			p |= 0o4000
		}
		if m&os.ModeSetgid != 0 {
			p |= 0o2000
		}
		if m&os.ModeSticky != 0 {
			p |= 0o1000
		}
		mode = fmt.Sprint(p)
	}
	content, openErr := "", "null"
	rc, err := f.Open()
	if err == nil {
		var data []byte
		data, err = io.ReadAll(rc)
		rc.Close()
		content = string(data)
	}
	if err != nil {
		openErr = zigStr(err.Error())
	}
	return fmt.Sprintf(".{ .name = %s, .method = %d, .crc32 = 0x%08x, .compressed_size = %d, .uncompressed_size = %d, .mtime = %s, .mode = %s, .non_utf8 = %t, .content = %s, .open_err = %s }",
		zigStr(f.Name), f.Method, f.CRC32, f.CompressedSize64, f.UncompressedSize64, mtime, mode, f.NonUTF8, zigStr(content), openErr)
}

func emitCases(b *bytes.Buffer, name, doc string, cases []readCase) {
	fmt.Fprintf(b, "%s\npub const %s = [_]Case{\n", doc, name)
	for _, c := range cases {
		r, err := zip.NewReader(bytes.NewReader(c.data), int64(len(c.data)))
		e := "null"
		var entries []string
		// ErrInsecurePath comes WITH a usable reader: Go only flags the names.
		if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
			e = zigStr(err.Error())
		} else {
			for _, f := range r.File {
				entries = append(entries, zigEntry(f))
			}
		}
		fmt.Fprintf(b, "    .{\n        .id = %s,\n        .archive = %s,\n        .err = %s,\n        .entries = %s,\n    },\n",
			zigStr(c.id), zigArchive(c.data), e, zigListIndented(entries))
	}
	fmt.Fprintf(b, "};\n\n")
}

func zigListIndented(items []string) string {
	if len(items) == 0 {
		return "&.{}"
	}
	return "&.{\n            " + strings.Join(items, ",\n            ") + ",\n        }"
}
