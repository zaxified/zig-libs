// SPDX-License-Identifier: MIT

// Go side of `zig build bench-websocket` (modules/websocket/tools/bench.zig):
// times github.com/coder/websocket v1.8.15 (pinned by go.mod/go.sum) as a
// server, through its public API only (Accept, Conn.Reader, Conn.Write), on
// the frames the Zig program writes into the directory given as the first
// argument, for the one workload named by the second. Prints one line:
// name, ns/op, result count (tab-separated).
//
// The connection is an in-memory net.Conn: reads cycle over the workload's
// client frames (`<name>.wire`), writes are counted and dropped -- the
// equivalent of the Zig side's fixed reader and discarding writer, with no
// socket in either number.
//
//	read_*   one op = read every message of the wire file to its end
//	write_*  one op = write the messages described by `<name>.wire`
//	         (the plain payloads, \x00-separated) as server frames
//
// count = messages + payload bytes delivered (read) or messages written
// (write). *_deflate workloads negotiate permessage-deflate in coder's
// CompressionNoContextTakeover mode; the read wire was compressed by the Zig
// module, so an equal count also says coder decoded it.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coder/websocket"
)

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

// memConn: reads cycle over `in` forever, writes are counted and dropped.
type memConn struct {
	in      []byte
	at      int
	written int
}

func (c *memConn) Read(p []byte) (int, error) {
	if c.at == len(c.in) {
		c.at = 0
	}
	n := copy(p, c.in[c.at:])
	c.at += n
	return n, nil
}
func (c *memConn) Write(p []byte) (int, error)        { c.written += len(p); return len(p), nil }
func (c *memConn) Close() error                       { return nil }
func (c *memConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

// hijacker: the http.ResponseWriter Accept writes the 101 to and takes the
// connection from.
type hijacker struct {
	h    http.Header
	conn *memConn
}

func (w *hijacker) Header() http.Header         { return w.h }
func (w *hijacker) Write(p []byte) (int, error) { return len(p), nil }
func (w *hijacker) WriteHeader(int)             {}
func (w *hijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func accept(conn *memConn, deflate bool) *websocket.Conn {
	req, _ := http.NewRequest("GET", "http://t/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	opts := &websocket.AcceptOptions{}
	if deflate {
		req.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
		opts.CompressionMode = websocket.CompressionNoContextTakeover
	}
	c, err := websocket.Accept(&hijacker{h: http.Header{}, conn: conn}, req, opts)
	if err != nil {
		panic(err)
	}
	c.SetReadLimit(1 << 20)
	return c
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	b, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	deflate := strings.HasSuffix(name, "_deflate")
	ctx := context.Background()
	var ns float64
	var count int
	if strings.HasPrefix(name, "read_") {
		meta, err := os.ReadFile(filepath.Join(dir, name+".count"))
		if err != nil {
			panic(err)
		}
		var msgs int
		fmt.Sscanf(string(meta), "%d", &msgs)
		conn := &memConn{in: b}
		c := accept(conn, deflate)
		buf := make([]byte, 1<<20)
		ns, count = timeIt(func() int {
			sum := 0
			for i := 0; i < msgs; i++ {
				_, r, err := c.Reader(ctx)
				if err != nil {
					panic(err)
				}
				for {
					n, err := r.Read(buf)
					sum += n
					if err == io.EOF {
						break
					}
					if err != nil {
						panic(err)
					}
				}
				sum++
			}
			return sum
		})
	} else {
		var payloads [][]byte
		for _, p := range bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0}) {
			payloads = append(payloads, p)
		}
		typ := websocket.MessageText
		if strings.Contains(name, "binary") {
			typ = websocket.MessageBinary
		}
		conn := &memConn{}
		c := accept(conn, deflate)
		ns, count = timeIt(func() int {
			for _, p := range payloads {
				if err := c.Write(ctx, typ, p); err != nil {
					panic(err)
				}
			}
			return len(payloads)
		})
	}
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
