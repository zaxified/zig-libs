// SPDX-License-Identifier: MIT
// Shared command-line driver of the Go side of the kv lead probe (backs the
// kv "Ahead" claims on read-only open, torn tail and flipped byte). One copy
// here; run.sh copies it into each store module next to its adapter.go, which
// supplies openStore/refreshStore. Same CLI as zig/probe.zig.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

type kvs interface {
	Put(k, v []byte) error
	Get(k []byte) (v []byte, found bool, err error)
	Close() error
}

func key(id int) []byte { return []byte(fmt.Sprintf("k%08d", id)) }
func val(id int) []byte {
	v := make([]byte, 100)
	for i := range v {
		v[i] = byte((id + i) % 251)
	}
	return v
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// check ids [a,b): prints ok/wrong/missing/err counts.
func check(s kvs, a, b int) {
	ok, wrong, missing, errs := 0, 0, 0, 0
	first := ""
	for id := a; id < b; id++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					errs++
					if first == "" {
						first = fmt.Sprint("PANIC in get: ", r)
					}
				}
			}()
			v, found, err := s.Get(key(id))
			switch {
			case err != nil:
				errs++
				if first == "" {
					first = err.Error()
				}
			case !found:
				missing++
			case bytes.Equal(v, val(id)):
				ok++
			default:
				wrong++
			}
		}()
	}
	fmt.Printf("check [%d,%d) ok=%d wrong=%d missing=%d err=%d firsterr=%q\n", a, b, ok, wrong, missing, errs, first)
}

func openOrDie(dir, role string, seg int64) kvs {
	s, err := openStore(dir, role, seg)
	if err != nil {
		fmt.Printf("open=ERR %q\n", err.Error())
		os.Exit(0)
	}
	fmt.Printf("open=OK\n")
	return s
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC %v\n", r)
			fmt.Fprintf(os.Stderr, "%s\n", debug.Stack())
			os.Exit(3)
		}
	}()
	a := os.Args
	switch a[1] {
	case "write": // dir n seg
		s := openOrDie(a[2], "rw", int64(atoi(a[4])))
		for i := 0; i < atoi(a[3]); i++ {
			if err := s.Put(key(i), val(i)); err != nil {
				fmt.Println("put ERR", err)
				os.Exit(1)
			}
		}
		fmt.Println("close:", s.Close())
	case "check": // dir n [ro]
		role := "rw"
		if len(a) > 4 {
			role = a[4]
		}
		s := openOrDie(a[2], role, 0)
		check(s, 0, atoi(a[3]))
		s.Close()
	case "putnew":
		s := openOrDie(a[2], "rw", 0)
		fmt.Println("put:", s.Put([]byte("newkey"), []byte("newvalue-0123456789")))
		fmt.Println("close:", s.Close())
	case "getnew":
		s := openOrDie(a[2], "rw", 0)
		v, found, err := s.Get([]byte("newkey"))
		switch {
		case err != nil:
			fmt.Printf("newkey=ERR %q\n", err.Error())
		case !found:
			fmt.Println("newkey=MISSING")
		case string(v) == "newvalue-0123456789":
			fmt.Println("newkey=OK")
		default:
			fmt.Println("newkey=WRONG")
		}
		s.Close()
	case "holder": // dir n ; stdin: "more A B" | "quit"
		s := openOrDie(a[2], "rw", 0)
		for i := 0; i < atoi(a[3]); i++ {
			if err := s.Put(key(i), val(i)); err != nil {
				fmt.Println("put ERR", err)
			}
		}
		fmt.Println("READY")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 0 {
				continue
			}
			if f[0] == "more" {
				for i := atoi(f[1]); i < atoi(f[2]); i++ {
					s.Put(key(i), val(i))
				}
				fmt.Println("DONE")
			} else if f[0] == "quit" {
				break
			}
		}
		fmt.Println("close:", s.Close())
	case "reader": // dir ; stdin: "check A B" | "refresh" | "put" | "quit"
		s := openOrDie(a[2], "ro", 0)
		fmt.Println("READY")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 0 {
				continue
			}
			switch f[0] {
			case "check":
				check(s, atoi(f[1]), atoi(f[2]))
			case "refresh":
				s2, err := refreshStore(s, a[2])
				if err != nil {
					fmt.Printf("refresh=ERR %q\n", err.Error())
				} else {
					s = s2
					fmt.Println("refresh=OK")
				}
			case "put":
				fmt.Printf("put-on-reader: %v\n", s.Put([]byte("rk"), []byte("rv")))
			case "quit":
				fmt.Println("close:", s.Close())
				return
			}
			os.Stdout.Sync()
		}
	}
}
