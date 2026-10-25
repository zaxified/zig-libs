// SPDX-License-Identifier: MIT
// bbolt side of the damaged-file probe (backs the kvtree "never crashes on a
// damaged file" Ahead claim). Exit: 0 CLEAN, 10 WRONG, 11 ERROR.
// A Go panic / fatal error exits 2 (never recovered here), a signal kills.
package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

const N = 2000

func key(i int) []byte { return []byte(fmt.Sprintf("k%08d", i)) }
func val(id int) []byte {
	v := make([]byte, 100)
	for i := range v {
		v[i] = byte((id + i) % 251)
	}
	return v
}
func fail(what string, err error) {
	fmt.Fprintf(os.Stderr, "ERROR %s %v\n", what, err)
	os.Exit(11)
}

func main() {
	path := os.Args[2] + "/t.db"
	db, err := bolt.Open(path, 0o644, &bolt.Options{Timeout: time.Second})
	if err != nil {
		fail("open", err)
	}
	if os.Args[1] == "build" {
		err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucket([]byte("b"))
			if err != nil {
				return err
			}
			for i := 0; i < N; i++ {
				if err := b.Put(key(i), val(i)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			fail("build", err)
		}
		if err := db.Close(); err != nil {
			fail("close", err)
		}
		return
	}
	wrong := ""
	structural := false
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("b"))
		if b == nil {
			structural = true
			return nil
		}
		for i := 0; i < N; i++ {
			g := b.Get(key(i))
			if g == nil {
				structural = true
			} else if !bytes.Equal(g, val(i)) {
				wrong = "value-only"
			}
		}
		n := 0
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if n >= N {
				structural = true
				break
			}
			if !bytes.Equal(k, key(n)) {
				structural = true
			} else if !bytes.Equal(v, val(n)) {
				wrong = "value-only"
			}
			n++
		}
		if n != N {
			structural = true
		}
		return nil
	})
	if err != nil {
		fail("view", err)
	}
	if err := db.Close(); err != nil {
		fail("close", err)
	}
	if structural {
		wrong = "structural"
	}
	if wrong != "" {
		fmt.Fprintln(os.Stderr, "WRONG", wrong)
		os.Exit(10)
	}
}
