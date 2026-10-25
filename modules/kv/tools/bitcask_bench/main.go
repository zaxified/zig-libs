// SPDX-License-Identifier: MIT

// A "fastest in the field" side of `zig build bench-kv` (modules/kv/tools/bench.zig):
// git.mills.io/prologic/bitcask v1.0.2 (pinned by go.mod/go.sum), same data, rows
// and timing as tools/go_bench/main.go (rosedb), store-specific calls only.
// Default options (1 MB datafiles; sealed ones are read through mmap,
// internal/data/datafile.go:76-79), `WithSync(true)` only on put_sync_100. Its
// scan is `Fold` over the keys plus a `Get` each (no key+value iterator); its
// open loads a saved index instead of replaying the log.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"git.mills.io/prologic/bitcask"
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

	dir := filepath.Join(work, "bitcask-"+name)
	must(os.RemoveAll(dir))
	defer os.RemoveAll(dir)

	// Defaults, except: put_sync_100 uses WithSync(true) (Put then fsyncs the
	// datafile itself); the load phase and all other rows use the default
	// (Sync=false). The persisted config.json carries Sync into later opens,
	// so put_sync_100 reopens with the option after the untimed load.
	db, err := bitcask.Open(dir)
	must(err)
	v := make([]byte, valLen)
	for i := 0; i < nKeys; i++ {
		id := perm[i]
		fillVal(v, id)
		must(db.Put(keys[id], v))
	}
	must(db.Sync())
	durable := name == "put_sync_100"
	if durable {
		must(db.Close())
		db, err = bitcask.Open(dir, bitcask.WithSync(true))
		must(err)
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
			must(db.Put(k, v))
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
		// No key+value iterator: Fold yields keys (index order), the value
		// is then a Get per key.
		f = func() int {
			s := 0
			must(db.Fold(func(k []byte) error {
				val, err := db.Get(k)
				if err != nil {
					return err
				}
				s += 1 + len(val)
				return nil
			}))
			return s
		}
	case "open_100k":
		keysNum := db.Len()
		must(db.Close())
		db = nil
		f = func() int {
			d, err := bitcask.Open(dir)
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
