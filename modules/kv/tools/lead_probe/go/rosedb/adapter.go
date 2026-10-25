// SPDX-License-Identifier: MIT
// rosedb v2.4.0 adapter for the kv lead probe (common.go holds the shared driver;
// run.sh copies it next to this file at build time). Backs the kv
// "Ahead" claims on read-only open, torn tail and flipped byte.
package main

import "github.com/rosedblabs/rosedb/v2"

type st struct{ db *rosedb.DB }

func (s st) Put(k, v []byte) error { return s.db.Put(k, v) }
func (s st) Get(k []byte) ([]byte, bool, error) {
	v, err := s.db.Get(k)
	if err == rosedb.ErrKeyNotFound {
		return nil, false, nil
	}
	return v, err == nil, err
}
func (s st) Close() error { return s.db.Close() }

// no read-only option: "ro" is a plain second open.
func openStore(dir, role string, seg int64) (kvs, error) {
	o := rosedb.DefaultOptions
	o.DirPath = dir
	o.Sync = false
	if seg > 0 {
		o.SegmentSize = seg
	}
	db, err := rosedb.Open(o)
	if err != nil {
		return nil, err
	}
	return st{db}, nil
}
func refreshStore(s kvs, dir string) (kvs, error) {
	s.Close()
	return openStore(dir, "ro", 0)
}
