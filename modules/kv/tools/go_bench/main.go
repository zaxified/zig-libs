// SPDX-License-Identifier: MIT

// Go side of `zig build bench-kv` (modules/kv/tools/bench.zig): times
// github.com/rosedblabs/rosedb/v2 v2.4.0 (pinned by go.mod/go.sum) through its
// public API, for the one workload named by the second argument, in a fresh
// directory under the first. Prints one line: name, ns/op, result count
// (tab-separated).
//
// Data, identical on both sides: N = 100000 keys "k%08d" of a permutation of
// 0..N-1 (Fisher-Yates driven by splitmix64, seed 0x6b767472), values of 100
// bytes with byte i = (id+i) % 251, loaded before the row. One op:
//
//	get_hit       getN point gets, permuted order (rosedb returns a fresh slice)
//	put_new_1k    1000 puts of NEW keys, no fsync (Options.Sync = false)
//	update_1k     1000 overwrites of existing keys, no fsync
//	put_sync_100  100 puts of new keys, each followed by DB.Sync (an fsync;
//	              see the note in main on why not Options.Sync)
//	scan          every key and value (Ascend)
//	open_100k     Open + Close of the loaded store (rebuild of the index)
//	map_baseline  getN lookups in a Go map (net baseline, not in the verdict)
//
// count = hits + value bytes read, or puts + value bytes written, or keys
// indexed by an open. Timing matches the Zig side: double the batch until one
// batch takes over 100 ms, then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rosedblabs/rosedb/v2"
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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
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

	if name == "map_baseline" {
		m := make(map[string][]byte, nKeys)
		for id := 0; id < nKeys; id++ {
			v := make([]byte, valLen)
			fillVal(v, uint32(id))
			m[string(keys[id])] = v
		}
		ns, c := timeIt(func() int {
			s := 0
			for i := 0; i < getN; i++ {
				if v, ok := m[string(keys[perm[i]])]; ok {
					s += 1 + len(v)
				}
			}
			return s
		})
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, c)
		return
	}

	// A directory of our own under the work dir: rosedb also uses the
	// sibling "<dir>-merge", which therefore stays under it too.
	dir := filepath.Join(work, "rosedb-"+name)
	must(os.RemoveAll(dir))
	must(os.RemoveAll(dir + "-merge"))
	defer os.RemoveAll(dir + "-merge")
	defer os.RemoveAll(dir)

	opts := rosedb.DefaultOptions
	opts.DirPath = dir
	db, err := rosedb.Open(opts)
	must(err)
	v := make([]byte, valLen)
	for i := 0; i < nKeys; i++ {
		id := perm[i]
		fillVal(v, id)
		must(db.Put(keys[id], v))
	}
	must(db.Sync())

	pos := 0
	gen := uint32(0)
	durable := name == "put_sync_100"
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
			must(db.Put(k, v))
			if durable {
				// Not Options.Sync = true: in v2.4.0 that never fsyncs a
				// Put (Commit goes through wal.WriteAll, which does not sync,
				// and the batch skips its own sync because the DB option is
				// set). An explicit Sync per Put is a durable write.
				must(db.Sync())
			}
			s += 1 + valLen
		}
		pos += n
		gen++
		return s
	}

	var f func() int
	switch name {
	case "get_hit":
		f = func() int {
			s := 0
			for i := 0; i < getN; i++ {
				got, err := db.Get(keys[perm[i]])
				must(err)
				s += 1 + len(got)
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
		f = func() int {
			s := 0
			db.Ascend(func(k []byte, v []byte) (bool, error) {
				s += 1 + len(v)
				return true, nil
			})
			return s
		}
	case "open_100k":
		// Count once, outside the timing: Stat also walks the directory.
		keysNum := int(db.Stat().KeysNum)
		must(db.Close())
		db = nil
		f = func() int {
			d, err := rosedb.Open(opts)
			must(err)
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
