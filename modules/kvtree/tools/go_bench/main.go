// SPDX-License-Identifier: MIT

// Go side of `zig build bench-kvtree` (modules/kvtree/tools/bench.zig): times
// go.etcd.io/bbolt v1.5.0 (pinned by go.mod/go.sum) through its public API,
// for the one workload named by the second argument, in the directory given
// as the first. Prints one line: name, ns/op, result count (tab-separated).
//
// Data, identical on both sides: N = 100000 keys "k%08d" of a permutation of
// 0..N-1 (Fisher-Yates driven by splitmix64, seed 0x6b767472), values of 100
// bytes with byte i = (id+i) % 251. One op:
//
//	get_hit        getN point gets, permuted order, one View per op
//	scan           full ordered scan of the N keys, one View per op
//	put_txn_1k     one Update of 1000 puts of NEW keys + commit (fsync)
//	update_txn_1k  one Update of 1000 overwrites of existing keys + commit
//	bucket_get     like get_hit
//	map_baseline   getN lookups in a Go map (net baseline, not in the verdict)
//
// bbolt has no keys outside a bucket, so every row keeps the keys in the one
// bucket "b" (get_hit and bucket_get are therefore the same code here; on the
// kvtree side get_hit reads the root tree and bucket_get a bucket). bbolt
// returns a slice into its mmap; the gets copy it into a reused buffer, as the
// Zig side copies the value out of the store (allocate + free per get), so the
// two are like for like. bbolt reads from the mmap (no syscall per get), the
// Zig side preads through kv.FsStorage -- that difference is part of what is
// compared. Default options: NoSync=false, so every commit fsyncs.
//
// count = hits + value bytes read (gets, scan) or puts + value bytes written
// (write rows). Timing matches the Zig side: double the batch until one batch
// takes over 100 ms, then keep the best of five.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	nKeys  = 100_000
	valLen = 100
	getN   = 20_000
	batchW = 1000
	seed   = 0x6b767472
)

var bucketName = []byte("b")

var sink int

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
	for k := 0; k < 5; k++ {
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

type splitmix struct{ s uint64 }

func (r *splitmix) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// permutation of 0..n-1, Fisher-Yates from the top, j = next() % (i+1).
func permutation(n int) []uint32 {
	p := make([]uint32, n)
	for i := range p {
		p[i] = uint32(i)
	}
	r := splitmix{seed}
	for i := n - 1; i > 0; i-- {
		j := int(r.next() % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// "k" + id as 8 zero-padded decimal digits, written by hand (no fmt).
func putKey(b *[9]byte, id uint32) []byte {
	b[0] = 'k'
	for i := 8; i >= 1; i-- {
		b[i] = byte('0' + id%10)
		id /= 10
	}
	return b[:]
}

func fillVal(v []byte, id uint32) {
	for i := range v {
		v[i] = byte((uint64(id) + uint64(i)) % 251)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	perm := permutation(nKeys)
	keys := make([][]byte, nKeys)
	for id := range keys {
		var kb [9]byte
		keys[id] = append([]byte(nil), putKey(&kb, uint32(id))...)
	}

	if name == "map_baseline" {
		vals := make([]byte, nKeys*valLen)
		m := make(map[string][]byte, nKeys)
		for id := 0; id < nKeys; id++ {
			v := vals[id*valLen : (id+1)*valLen]
			fillVal(v, uint32(id))
			m[string(keys[id])] = v
		}
		skeys := make([]string, getN)
		for i := range skeys {
			skeys[i] = string(keys[perm[i]])
		}
		ns, count := timeIt(func() int {
			sum := 0
			for _, k := range skeys {
				if v, ok := m[k]; ok {
					sum += 1 + len(v)
				}
			}
			return sum
		})
		fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
		return
	}

	path := filepath.Join(dir, "bbolt-"+name+".db")
	os.Remove(path)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		fail(err)
	}
	defer os.Remove(path)
	defer db.Close()

	// Setup, untimed: the store holds the N keys, written in one transaction.
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(bucketName)
		if err != nil {
			return err
		}
		var v [valLen]byte
		for i := 0; i < nKeys; i++ {
			id := perm[i]
			fillVal(v[:], id)
			if err := b.Put(keys[id], v[:]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail(err)
	}

	var fn func() int
	switch name {
	case "get_hit", "bucket_get":
		buf := make([]byte, valLen)
		fn = func() int {
			sum := 0
			err := db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucketName)
				for i := 0; i < getN; i++ {
					if v := b.Get(keys[perm[i]]); v != nil {
						sum += 1 + copy(buf, v)
					}
				}
				return nil
			})
			if err != nil {
				fail(err)
			}
			return sum
		}
	case "scan":
		fn = func() int {
			sum := 0
			err := db.View(func(tx *bolt.Tx) error {
				c := tx.Bucket(bucketName).Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					sum += 1 + len(v)
				}
				return nil
			})
			if err != nil {
				fail(err)
			}
			return sum
		}
	case "put_txn_1k", "update_txn_1k":
		update := name == "update_txn_1k"
		pos := 0
		gen := uint32(0)
		fn = func() int {
			sum := 0
			err := db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucketName)
				var kb [9]byte
				var v [valLen]byte
				for j := 0; j < batchW; j++ {
					var id uint32
					var k []byte
					if update {
						id = perm[(pos+j)%nKeys]
						k = keys[id]
					} else {
						id = uint32(nKeys + pos + j)
						k = putKey(&kb, id)
					}
					fillVal(v[:], id+gen)
					if err := b.Put(k, v[:]); err != nil {
						return err
					}
					sum += 1 + valLen
				}
				return nil
			})
			if err != nil {
				fail(err)
			}
			pos += batchW
			gen++
			return sum
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(fn)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
