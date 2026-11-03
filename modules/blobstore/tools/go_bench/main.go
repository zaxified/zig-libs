// SPDX-License-Identifier: MIT

// Go side of `zig build bench-blobstore` (modules/blobstore/tools/bench.zig).
// Times two Go stores over the same workloads as ours, for the one workload
// named by the second argument, in a fresh subdirectory of the first. Prints
// one line: name, ns/op, count (tab-separated); stderr is the banner.
//
//	reference  github.com/ipfs/go-ds-flatfs v0.6.1 (MIT), sync=true:
//	           temp file, write, fsync, close, rename, fsync of the directory
//	           -- the same crash protocol as our put.
//	fastest?   github.com/peterbourgon/diskv/v3 v3.0.1 (MIT), TempDir set,
//	           sync=true: temp file, write, fsync, rename (no directory fsync).
//
// flatfs and diskv key by a caller-supplied name, so the Go side hashes with
// crypto/sha256 and uses the hex digest as the key: the same work as our
// content-addressed put. One op = 16 blobs of 4 KiB (put_1m: one of 1 MiB).
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	flatfs "github.com/ipfs/go-ds-flatfs"
	"github.com/ipfs/go-datastore"
	"github.com/peterbourgon/diskv/v3"
)

const (
	nBlobs   = 16
	smallLen = 4096
	bigLen   = 1 << 20
)

var sink uint64

func die(err error) {
	fmt.Fprintln(os.Stderr, "go_bench:", err)
	os.Exit(1)
}

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
	best := 1e300
	var count uint64
	for r := 0; r < 5; r++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
			sink += count
		}
		if d := float64(time.Since(t).Nanoseconds()) / float64(n); d < best {
			best = d
		}
	}
	return best, count
}

// blob fills dst (a copy of base) with a header that makes (gen, i) unique.
func blob(base []byte, dst []byte, gen uint64, i int) []byte {
	copy(dst, base)
	binary.LittleEndian.PutUint64(dst[0:8], gen)
	binary.LittleEndian.PutUint64(dst[8:16], uint64(i))
	return dst
}

func key(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type store interface {
	put(k string, b []byte) error
	get(k string) ([]byte, error)
	has(k string) bool
}

type flat struct{ ds *flatfs.Datastore }

func (s flat) put(k string, b []byte) error {
	return s.ds.Put(context.Background(), datastore.NewKey(k), b)
}
func (s flat) get(k string) ([]byte, error) { return s.ds.Get(context.Background(), datastore.NewKey(k)) }
func (s flat) has(k string) bool {
	ok, _ := s.ds.Has(context.Background(), datastore.NewKey(k))
	return ok
}

type dv struct{ d *diskv.Diskv }

func (s dv) put(k string, b []byte) error { return s.d.WriteStream(k, bytes.NewReader(b), true) }
func (s dv) get(k string) ([]byte, error) { return s.d.Read(k) }
func (s dv) has(k string) bool            { return s.d.Has(k) }

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	diskvSide := strings.HasSuffix(name, "_diskv")
	op := strings.TrimSuffix(name, "_diskv")
	root := filepath.Join(dir, "go-"+name)
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		die(err)
	}
	defer os.RemoveAll(root)

	var st store
	if diskvSide {
		fmt.Fprintln(os.Stderr, "github.com/peterbourgon/diskv/v3 v3.0.1 (TempDir, sync=true)")
		d := diskv.New(diskv.Options{
			BasePath:  filepath.Join(root, "s"),
			TempDir:   filepath.Join(root, "t"),
			Transform: func(k string) []string { return []string{k[:2]} },
			PathPerm:  0o755,
			FilePerm:  0o644,
		})
		st = dv{d}
	} else {
		fmt.Fprintln(os.Stderr, "github.com/ipfs/go-ds-flatfs v0.6.1 (sync=true)")
		ds, err := flatfs.CreateOrOpen(filepath.Join(root, "s"), flatfs.Prefix(2), true)
		if err != nil {
			die(err)
		}
		defer ds.Close()
		st = flat{ds}
	}

	baseSmall := make([]byte, smallLen)
	for i := range baseSmall {
		baseSmall[i] = byte(i*131 + 7)
	}
	baseBig := make([]byte, bigLen)
	for i := range baseBig {
		baseBig[i] = byte(i*131 + 7)
	}
	buf := make([]byte, bigLen)
	var gen uint64

	var f func() uint64
	switch op {
	case "put":
		f = func() uint64 {
			gen++
			var t uint64
			for i := 0; i < nBlobs; i++ {
				b := blob(baseSmall, buf[:smallLen], gen, i)
				if err := st.put(key(b), b); err != nil {
					die(err)
				}
				t++
			}
			return t
		}
	case "put_1m":
		f = func() uint64 {
			gen++
			b := blob(baseBig, buf[:bigLen], gen, 0)
			if err := st.put(key(b), b); err != nil {
				die(err)
			}
			return bigLen
		}
	case "get", "has":
		keys := make([]string, nBlobs)
		for i := range keys {
			b := blob(baseSmall, buf[:smallLen], 0, i)
			keys[i] = key(b)
			if err := st.put(keys[i], b); err != nil {
				die(err)
			}
		}
		if op == "get" {
			f = func() uint64 {
				var t uint64
				for _, k := range keys {
					b, err := st.get(k)
					if err != nil {
						die(err)
					}
					t += uint64(len(b))
				}
				return t
			}
		} else {
			f = func() uint64 {
				var t uint64
				for _, k := range keys {
					if st.has(k) {
						t++
					}
				}
				return t
			}
		}
	default:
		die(fmt.Errorf("unknown workload %q", name))
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
