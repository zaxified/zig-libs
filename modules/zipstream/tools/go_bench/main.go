// SPDX-License-Identifier: MIT

// Go side of `zig build bench-zipstream` (modules/zipstream/tools/bench.zig):
// Go's archive/zip over the SAME files the Zig side reads. Standard library
// only.
//
//	go_bench <work dir> gen                  build the fixture archives (once) from data-v1.xml
//	go_bench <work dir> <workload>           time it: name, ns/op, count (stderr: banner)
//	go_bench <work dir> <workload> check     print the workload's check line once
//	go_bench <work dir> readcheck <file>     read every entry of <file>: "entries bytes crcsum"
//
// Reader workloads (zip.OpenReader, io.Copy(io.Discard, entry reader)):
//
//	xlsx     xlsx-v1.zip: one ~200 MiB deflate sheet plus small parts, all entries read
//	store    store-v1.zip: one 512 MiB Stored entry
//	cdopen   many-v1.zip: open 100 000 tiny entries, linear search of the last name; no data read
//	small    small-v1.zip: 10 000 small deflate entries, read one by one
//
// count = bytes read + sum of the entries' CRC-32 (cdopen: entries + index of
// the name found + the CRC sum); the Zig side must produce the same value.
//
// Writer workloads (the first 256 MiB of data-v1.xml, in memory, one entry,
// archive into a counting discard writer; Go's Deflate is level 6, its
// DefaultCompression): wdeflate, wstore (CreateHeader, one Write of the whole
// data), sdeflate, sstore (64 KiB Writes). count = uncompressed bytes; the
// compressed size is printed by `check`.
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	writeBytes  = 256 << 20
	xlsxBytes   = 200 << 20
	storeBytes  = 512 << 20
	manyEntries = 100_000
	smallCount  = 10_000
	chunk       = 64 << 10
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "go_bench:", err)
	os.Exit(1)
}

type counter struct{ n uint64 }

func (c *counter) Write(p []byte) (int, error) { c.n += uint64(len(p)); return len(p), nil }

func fileData(dir string, n int) []byte {
	f, err := os.Open(filepath.Join(dir, "data-v1.xml"))
	if err != nil {
		fail(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := io.ReadFull(f, b); err != nil {
		fail(err)
	}
	return b
}

func add(zw *zip.Writer, name string, method uint16, data []byte) {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
	if err != nil {
		fail(err)
	}
	if _, err := w.Write(data); err != nil {
		fail(err)
	}
}

func build(path string, fill func(zw *zip.Writer)) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "go_bench: generating", filepath.Base(path))
	f, err := os.Create(path + ".tmp")
	if err != nil {
		fail(err)
	}
	zw := zip.NewWriter(f)
	fill(zw)
	if err := zw.Close(); err != nil {
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		fail(err)
	}
}

func gen(dir string) {
	all := true
	for _, n := range []string{"xlsx", "store", "many", "small"} {
		if _, err := os.Stat(filepath.Join(dir, n+"-v1.zip")); err != nil {
			all = false
		}
	}
	if all {
		return
	}
	data := fileData(dir, storeBytes)
	build(filepath.Join(dir, "xlsx-v1.zip"), func(zw *zip.Writer) {
		add(zw, "[Content_Types].xml", zip.Deflate, []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`))
		add(zw, "xl/workbook.xml", zip.Deflate, []byte(`<workbook><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`))
		add(zw, "xl/worksheets/sheet1.xml", zip.Deflate, data[:xlsxBytes])
		add(zw, "xl/styles.xml", zip.Deflate, data[:5000])
	})
	build(filepath.Join(dir, "store-v1.zip"), func(zw *zip.Writer) {
		add(zw, "xl/worksheets/sheet1.xml", zip.Store, data)
	})
	build(filepath.Join(dir, "many-v1.zip"), func(zw *zip.Writer) {
		for i := 0; i < manyEntries; i++ {
			add(zw, fmt.Sprintf("xl/worksheets/rows/r%06d.xml", i), zip.Store, []byte("<c/>"))
		}
	})
	build(filepath.Join(dir, "small-v1.zip"), func(zw *zip.Writer) {
		r := rand.New(rand.NewPCG(1, 2))
		for i := 0; i < smallCount; i++ {
			n := 1000 + r.IntN(3000)
			off := r.IntN(len(data) - n)
			add(zw, fmt.Sprintf("s%05d.xml", i), zip.Deflate, data[off:off+n])
		}
	})
}

type result struct{ entries, bytes, crc uint64 }

// readArchive reads every entry (data=true), or only lists them and looks for
// `find` by a linear walk (data=false: bytes = index found + 1).
func readArchive(path string, data bool, find string) result {
	zr, err := zip.OpenReader(path)
	if err != nil {
		fail(err)
	}
	defer zr.Close()
	var res result
	for i, f := range zr.File {
		res.entries++
		res.crc += uint64(f.CRC32)
		if !data && res.bytes == 0 && f.Name == find {
			res.bytes = uint64(i) + 1
		}
		if data {
			rc, err := f.Open()
			if err != nil {
				fail(err)
			}
			n, err := io.Copy(io.Discard, rc)
			if err != nil {
				fail(err)
			}
			rc.Close()
			res.bytes += uint64(n)
		}
	}
	return res
}

func (r result) count() uint64 { return r.bytes + r.crc + r.entries }

func writeArchive(w io.Writer, data []byte, method uint16, streamed bool) {
	zw := zip.NewWriter(w)
	f, err := zw.CreateHeader(&zip.FileHeader{Name: "xl/worksheets/sheet1.xml", Method: method})
	if err != nil {
		fail(err)
	}
	if streamed {
		for off := 0; off < len(data); off += chunk {
			if _, err := f.Write(data[off:min(off+chunk, len(data))]); err != nil {
				fail(err)
			}
		}
	} else if _, err := f.Write(data); err != nil {
		fail(err)
	}
	if err := zw.Close(); err != nil {
		fail(err)
	}
}

func timeIt(f func() uint64) (float64, uint64) {
	// The pilot call counts as a sample: these ops take seconds.
	reps := 1
	if s := os.Getenv("BENCH_REPS"); s != "" {
		fmt.Sscan(s, &reps)
	}
	best := time.Duration(1<<63 - 1)
	var count uint64
	for k := 0; k < reps; k++ {
		t := time.Now()
		count = f()
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()), count
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload> [check]")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	switch name {
	case "gen":
		gen(dir)
		return
	case "readcheck":
		r := readArchive(os.Args[3], true, "")
		fmt.Printf("%d %d %d\n", r.entries, r.bytes, r.crc)
		return
	}
	check := len(os.Args) == 4 && os.Args[3] == "check"
	var op func() uint64
	switch name {
	case "xlsx", "store", "small":
		path := filepath.Join(dir, map[string]string{"xlsx": "xlsx-v1.zip", "store": "store-v1.zip", "small": "small-v1.zip"}[name])
		if check {
			r := readArchive(path, true, "")
			fmt.Printf("%d %d %d\n", r.entries, r.bytes, r.crc)
			return
		}
		op = func() uint64 { return readArchive(path, true, "").count() }
	case "cdopen":
		path := filepath.Join(dir, "many-v1.zip")
		last := fmt.Sprintf("xl/worksheets/rows/r%06d.xml", manyEntries-1)
		if check {
			r := readArchive(path, false, last)
			fmt.Printf("%d %d %d\n", r.entries, r.bytes, r.crc)
			return
		}
		op = func() uint64 { return readArchive(path, false, last).count() }
	case "wdeflate", "wstore", "sdeflate", "sstore":
		data := fileData(dir, writeBytes)
		method := zip.Deflate
		if name == "wstore" || name == "sstore" {
			method = zip.Store
		}
		streamed := name[0] == 's'
		if check {
			var buf bytes.Buffer
			writeArchive(&buf, data, method, streamed)
			if err := os.WriteFile(filepath.Join(dir, "out-go-"+name+".zip"), buf.Bytes(), 0o644); err != nil {
				fail(err)
			}
			fmt.Printf("1 %d %d %d\n", len(data), crc32.ChecksumIEEE(data), buf.Len())
			return
		}
		op = func() uint64 {
			var c counter
			writeArchive(&c, data, method, streamed)
			return uint64(len(data))
		}
	default:
		fail(fmt.Errorf("unknown workload %q", name))
	}
	ns, count := timeIt(op)
	fmt.Fprintf(os.Stderr, "reference: Go archive/zip, %s\n", runtime.Version())
	fmt.Printf("%s\t%.0f\t%d\n", name, ns, count)
}
