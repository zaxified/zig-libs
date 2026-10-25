// SPDX-License-Identifier: MIT
// prologic/bitcask v1.0.2 adapter for the kv lead probe (common.go holds the shared driver;
// run.sh copies it next to this file at build time). Backs the kv
// "Ahead" claims on read-only open, torn tail and flipped byte.
package main

import (
	"os"

	"git.mills.io/prologic/bitcask"
)

type st struct{ db *bitcask.Bitcask }

func (s st) Put(k, v []byte) error { return s.db.Put(k, v) }
func (s st) Get(k []byte) ([]byte, bool, error) {
	v, err := s.db.Get(k)
	if err == bitcask.ErrKeyNotFound {
		return nil, false, nil
	}
	return v, err == nil, err
}
func (s st) Close() error { return s.db.Close() }

func openStore(dir, role string, seg int64) (kvs, error) {
	var opts []bitcask.Option
	if seg > 0 {
		opts = append(opts, bitcask.WithMaxDatafileSize(int(seg)))
	}
	if os.Getenv("BC_RECOVER") == "1" {
		opts = append(opts, bitcask.WithAutoRecovery(true))
	}
	db, err := bitcask.Open(dir, opts...)
	if err != nil {
		return nil, err
	}
	return st{db}, nil
}
func refreshStore(s kvs, dir string) (kvs, error) {
	s.Close()
	return openStore(dir, "ro", 0)
}
