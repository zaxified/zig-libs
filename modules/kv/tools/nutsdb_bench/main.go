// SPDX-License-Identifier: MIT

// A "fastest in the field" side of `zig build bench-kv` (modules/kv/tools/bench.zig):
// github.com/nutsdb/nutsdb v1.1.0 (pinned by go.mod/go.sum), same data, rows and
// timing as tools/go_bench/main.go (rosedb), store-specific calls only. In the
// Bitcask model the field is defined by (owner, 2026-10-25): keys in RAM, values
// on disk -- `HintKeyAndRAMIdxMode`; nutsdb's default also keeps every VALUE in
// RAM (its scan is then 10x faster than any log read, and not the same store).
// One `Update` per put and one `View` per get, as the other sides do one call
// per op; `SyncEnable` (fsync per commit) only on put_sync_100.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nutsdb/nutsdb"
)

const (
	nKeys  = 100_000
	valLen = 100
	getN   = 20_000
	batchW = 1000
	syncW  = 100
	seed   = 0x6b767472
)

var sink int

func splitmix(s *uint64) uint64 {
	*s += 0x9e3779b97f4a7c15
	z := *s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func key(id uint32) []byte { return []byte(fmt.Sprintf("k%08d", id)) }

func fillVal(v []byte, id uint32) {
	for i := range v {
		v[i] = byte((uint64(id) + uint64(i)) % 251)
	}
}

func timeIt(f func() int) (float64, int) {
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
	count := 0
	for r := 0; r < 5; r++ {
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

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const bucket = "b"

func openNuts(dir string, sync bool) *nutsdb.DB {
	opts := nutsdb.DefaultOptions
	opts.Dir = dir
	opts.EntryIdxMode = nutsdb.HintKeyAndRAMIdxMode // keys in RAM, values on disk
	opts.SyncEnable = sync                          // default is true; false for the no-fsync rows
	db, err := nutsdb.Open(opts)
	must(err)
	return db
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: bench <work dir> <workload>")
		os.Exit(2)
	}
	work, name := os.Args[1], os.Args[2]

	perm := make([]uint32, nKeys)
	for i := range perm {
		perm[i] = uint32(i)
	}
	st := uint64(seed)
	for i := nKeys - 1; i > 0; i-- {
		j := int(splitmix(&st) % uint64(i+1))
		perm[i], perm[j] = perm[j], perm[i]
	}
	keys := make([][]byte, nKeys)
	for id := range keys {
		keys[id] = key(uint32(id))
	}

	dir := filepath.Join(work, "nutsdb-"+name)
	must(os.RemoveAll(dir))
	defer os.RemoveAll(dir)

	put := func(db *nutsdb.DB, k, v []byte) {
		must(db.Update(func(tx *nutsdb.Tx) error {
			return tx.Put(bucket, k, v, nutsdb.Persistent)
		}))
	}

	db := openNuts(dir, false)
	must(db.Update(func(tx *nutsdb.Tx) error {
		return tx.NewBucket(nutsdb.DataStructureBTree, bucket)
	}))
	v := make([]byte, valLen)
	for i := 0; i < nKeys; i++ {
		id := perm[i]
		fillVal(v, id)
		put(db, keys[id], v)
	}
	durable := name == "put_sync_100"
	if durable {
		// SyncEnable (fsync at every commit) is an Open-time option: reopen
		// with it on, after the (untimed) load.
		must(db.Close())
		db = openNuts(dir, true)
	}

	pos := 0
	gen := uint32(0)
	write := func(n int, update bool) int {
		s := 0
		for j := 0; j < n; j++ {
			var id uint32
			var k []byte
			if update {
				id = perm[(pos+j)%nKeys]
				k = keys[id]
			} else {
				id = uint32(nKeys + pos + j)
				k = key(id)
			}
			fillVal(v, id+gen)
			put(db, k, v)
			s += 1 + valLen
		}
		pos += n
		gen++
		return s
	}

	scanAll := func() int {
		s := 0
		must(db.View(func(tx *nutsdb.Tx) error {
			it := nutsdb.NewIterator(tx, bucket, nutsdb.IteratorOptions{})
			if it == nil {
				return fmt.Errorf("nil iterator")
			}
			defer it.Release()
			for ok := it.Valid(); ok; ok = it.Next() {
				_ = it.Key()
				val, err := it.Value()
				if err != nil {
					return err
				}
				s += 1 + len(val)
			}
			return nil
		}))
		return s
	}

	var f func() int
	switch name {
	case "get_hit":
		f = func() int {
			s := 0
			for i := 0; i < getN; i++ {
				must(db.View(func(tx *nutsdb.Tx) error {
					got, err := tx.Get(bucket, keys[perm[i]])
					s += 1 + len(got)
					return err
				}))
			}
			return s
		}
	case "put_new_1k":
		f = func() int { return write(batchW, false) }
	case "update_1k":
		f = func() int { return write(batchW, true) }
	case "put_sync_100":
		f = func() int { return write(syncW, false) }
	case "scan":
		f = scanAll
	case "open_100k":
		keysNum := scanAll() // untimed sanity: 1+valLen per key
		keysNum /= 1 + valLen
		must(db.Close())
		db = nil
		f = func() int {
			d := openNuts(dir, false)
			must(d.Close())
			return keysNum
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, c := timeIt(f)
	if db != nil {
		must(db.Close())
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, c)
}
