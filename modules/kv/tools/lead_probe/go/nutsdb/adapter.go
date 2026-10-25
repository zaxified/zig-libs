// SPDX-License-Identifier: MIT
// nutsdb v1.1.0 adapter for the kv lead probe (common.go holds the shared driver;
// run.sh copies it next to this file at build time). Backs the kv
// "Ahead" claims on read-only open, torn tail and flipped byte.
package main

import (
	"errors"

	"github.com/nutsdb/nutsdb"
)

const bucket = "b"

type st struct{ db *nutsdb.DB }

func (s st) Put(k, v []byte) error {
	return s.db.Update(func(tx *nutsdb.Tx) error { return tx.Put(bucket, k, v, nutsdb.Persistent) })
}
func (s st) Get(k []byte) (out []byte, found bool, err error) {
	err = s.db.View(func(tx *nutsdb.Tx) error {
		v, e := tx.Get(bucket, k)
		if e != nil {
			return e
		}
		out = append([]byte(nil), v...)
		return nil
	})
	if err != nil && (errors.Is(err, nutsdb.ErrNotFoundKey) || errors.Is(err, nutsdb.ErrNotFoundBucket)) {
		return nil, false, nil
	}
	return out, err == nil, err
}
func (s st) Close() error { return s.db.Close() }

func openStore(dir, role string, seg int64) (kvs, error) {
	o := nutsdb.DefaultOptions
	o.Dir = dir
	o.EntryIdxMode = nutsdb.HintKeyAndRAMIdxMode
	o.SyncEnable = false
	if seg > 0 {
		o.SegmentSize = seg
	}
	db, err := nutsdb.Open(o)
	if err != nil {
		return nil, err
	}
	s := st{db}
	if role == "rw" {
		// create bucket if absent
		err = db.Update(func(tx *nutsdb.Tx) error { return tx.NewBucket(nutsdb.DataStructureBTree, bucket) })
		_ = err // exists on reopen
	}
	return s, nil
}
func refreshStore(s kvs, dir string) (kvs, error) {
	s.Close()
	return openStore(dir, "ro", 0)
}
