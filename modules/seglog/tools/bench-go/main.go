// SPDX-License-Identifier: MIT

// bench-go runs seglog-bench's scenarios against other logs, through their
// public APIs, so seglog's numbers have something to stand beside:
//
//	bench-go <impl> <scenario> <dir> <payload bytes> <records> [batch]
//
// impl: tidwall (github.com/tidwall/wal), wlog (Prometheus tsdb/wlog, no
// compression), wlog-zstd, wlog-snappy. Scenarios and the TSV line are those
// of ../../example/bench.zig; every durable write is followed by the
// implementation's own sync (tidwall: NoSync off; wlog: Sync()).
package main

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/prometheus/prometheus/util/compression"
	"github.com/prometheus/prometheus/tsdb/wlog"
	"github.com/tidwall/wal"
)

type logImpl interface {
	write(recs [][]byte) error // durable when it returns
	close() error
}

type tidwallLog struct {
	l    *wal.Log
	next uint64
}

func (t *tidwallLog) write(recs [][]byte) error {
	if len(recs) == 1 {
		t.next++
		return t.l.Write(t.next, recs[0])
	}
	var b wal.Batch
	for _, r := range recs {
		t.next++
		b.Write(t.next, r)
	}
	return t.l.WriteBatch(&b)
}
func (t *tidwallLog) close() error { return t.l.Close() }

type wlogLog struct{ w *wlog.WL }

func (p *wlogLog) write(recs [][]byte) error {
	if err := p.w.Log(recs...); err != nil {
		return err
	}
	return p.w.Sync()
}
func (p *wlogLog) close() error { return p.w.Close() }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func wlogCompression(impl string) compression.Type {
	switch impl {
	case "wlog-zstd":
		return compression.Zstd
	case "wlog-snappy":
		return compression.Snappy
	}
	return compression.None
}

func open(impl, dir string) (logImpl, error) {
	switch impl {
	case "tidwall":
		l, err := wal.Open(dir, &wal.Options{NoSync: false})
		if err != nil {
			return nil, err
		}
		last, err := l.LastIndex()
		if err != nil {
			return nil, err
		}
		return &tidwallLog{l: l, next: last}, nil
	case "wlog", "wlog-zstd", "wlog-snappy":
		w, err := wlog.New(quiet, nil, dir, wlogCompression(impl))
		if err != nil {
			return nil, err
		}
		return &wlogLog{w: w}, nil
	}
	return nil, fmt.Errorf("unknown impl %q", impl)
}

// readAll scans every record and returns how many it saw.
func readAll(impl, dir string) (uint64, error) {
	var n uint64
	var sum byte
	switch impl {
	case "tidwall":
		l, err := wal.Open(dir, &wal.Options{NoCopy: true})
		if err != nil {
			return 0, err
		}
		defer l.Close()
		first, _ := l.FirstIndex()
		last, _ := l.LastIndex()
		for i := first; i <= last && last > 0; i++ {
			d, err := l.Read(i)
			if err != nil {
				return n, err
			}
			sum += d[0]
			n++
		}
	default:
		sr, err := wlog.NewSegmentsReader(dir)
		if err != nil {
			return 0, err
		}
		defer sr.Close()
		r := wlog.NewReader(sr)
		for r.Next() {
			sum += r.Record()[0]
			n++
		}
		if r.Err() != nil {
			return n, r.Err()
		}
	}
	_ = sum
	return n, nil
}

func dirBytes(dir string) int64 {
	var total int64
	filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "bench-go:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 6 {
		fmt.Fprintln(os.Stderr, "usage: bench-go tidwall|wlog|wlog-zstd|wlog-snappy append|batch|read|open <new dir> <payload bytes> <records> [batch]")
		os.Exit(2)
	}
	impl, scen, dir := os.Args[1], os.Args[2], os.Args[3]
	payloadLen, _ := strconv.Atoi(os.Args[4])
	records, _ := strconv.ParseUint(os.Args[5], 10, 64)
	batchN := 1
	seeks := 0
	if len(os.Args) > 6 {
		batchN, _ = strconv.Atoi(os.Args[6])
	}
	switch scen {
	case "append":
		batchN = 1
	case "read", "open", "seek":
		if scen == "seek" {
			seeks = batchN
		}
		batchN = 1000
	case "batch":
	default:
		die(fmt.Errorf("unknown scenario %q", scen))
	}
	if _, err := os.Stat(dir); err == nil {
		die(fmt.Errorf("%s exists", dir))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		die(err)
	}
	// Incompressible and distinct per slot, as the Zig side.
	buf := make([]byte, payloadLen*batchN)
	rand.New(rand.NewSource(0x5e9109)).Read(buf)
	views := make([][]byte, batchN)
	for i := range views {
		views[i] = buf[i*payloadLen : (i+1)*payloadLen]
	}

	l, err := open(impl, dir)
	if err != nil {
		die(err)
	}
	t0 := time.Now()
	var written uint64
	for written < records {
		n := uint64(batchN)
		if records-written < n {
			n = records - written
		}
		if err := l.write(views[:n]); err != nil {
			die(err)
		}
		written += n
	}
	elapsed := time.Since(t0)
	if err := l.close(); err != nil {
		die(err)
	}
	bytes := dirBytes(dir)

	switch scen {
	case "read":
		r0 := time.Now()
		n, err := readAll(impl, dir)
		elapsed = time.Since(r0)
		if err != nil {
			die(err)
		}
		if n != records {
			die(fmt.Errorf("read %d of %d records", n, records))
		}
	case "seek":
		if impl != "tidwall" {
			die(fmt.Errorf("seek: only tidwall reads by index"))
		}
		l2, err := wal.Open(dir, &wal.Options{NoCopy: true})
		if err != nil {
			die(err)
		}
		rng := rand.New(rand.NewSource(42))
		s0 := time.Now()
		for i := 0; i < seeks; i++ {
			idx := uint64(rng.Int63n(int64(records))) + 1
			if _, err := l2.Read(idx); err != nil {
				die(err)
			}
		}
		elapsed = time.Since(s0)
		l2.Close()
	case "open":
		o0 := time.Now()
		l2, err := open(impl, dir)
		elapsed = time.Since(o0)
		if err != nil {
			die(err)
		}
		l2.close()
	}
	if err := os.RemoveAll(dir); err != nil {
		die(err)
	}

	secs := elapsed.Seconds()
	recsF := float64(records)
	if scen == "seek" {
		recsF = float64(seeks)
	}
	payloadMB := recsF * float64(payloadLen) / 1e6
	perRec := float64(bytes)/float64(records) - float64(payloadLen)
	fmt.Printf("%s\t%s\t%d\t%d\t%d\t%.4f\t%.0f\t%.1f\t%.1f\n",
		impl, scen, payloadLen, records, batchN, secs, recsF/secs, payloadMB/secs, perRec)
}
