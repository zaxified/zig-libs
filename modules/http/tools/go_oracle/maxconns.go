// SPDX-License-Identifier: MIT

// Area max_conns: http.Transport.MaxConnsPerHost. A loopback peer answers
// every request on a connection with a fixed 200 (or one with
// `Connection: close`), each answer held back hold_ms and until want
// requests are in flight at once (1 s at most), so an uncapped client shows
// more than want in flight. n goroutines send one GET each at the same
// time. Recorded: the most requests the peer saw in flight at once, the
// connections it accepted, and how many round trips failed.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const maxConnsHoldMs = 100

type maxConnsCase struct {
	id          string
	cap         int
	n           int
	keepAlive   bool // false = DisableKeepAlives
	serverClose bool // the peer answers `Connection: close`
}

func maxConnsCases() []maxConnsCase {
	return []maxConnsCase{
		{"uncapped", 0, 4, true, false},
		{"cap2", 2, 6, true, false},
		{"cap1", 1, 4, true, false},
		{"cap3-n2", 3, 2, true, false},
		{"cap2-no-keepalive", 2, 6, false, false},
		{"cap2-server-close", 2, 6, true, true},
	}
}

func (c maxConnsCase) want() int {
	if c.cap == 0 || c.cap > c.n {
		return c.n
	}
	return c.cap
}

type maxConnsPeer struct {
	want     int32
	close    bool
	mu       sync.Mutex
	inFlight int32
	maxSeen  int32
	accepts  atomic.Int32
}

func (p *maxConnsPeer) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		// Read one request head (GETs carry no body).
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		p.mu.Lock()
		p.inFlight++
		if p.inFlight > p.maxSeen {
			p.maxSeen = p.inFlight
		}
		p.mu.Unlock()
		start := time.Now()
		for {
			p.mu.Lock()
			enough := p.inFlight >= p.want
			p.mu.Unlock()
			el := time.Since(start)
			if (enough && el >= maxConnsHoldMs*time.Millisecond) || el >= time.Second {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		p.mu.Lock()
		p.inFlight--
		p.mu.Unlock()
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
		if p.close {
			resp += "Connection: close\r\n"
		}
		if _, err := conn.Write([]byte(resp + "\r\nok")); err != nil || p.close {
			return
		}
	}
}

type maxConnsResult struct {
	maxInFlight, accepts, failures int
}

func runMaxConns(c maxConnsCase) maxConnsResult {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	p := &maxConnsPeer{want: int32(c.want()), close: c.serverClose}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			p.accepts.Add(1)
			go p.serve(conn)
		}
	}()

	tr := &http.Transport{MaxConnsPerHost: c.cap, DisableKeepAlives: !c.keepAlive, MaxIdleConnsPerHost: 8}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	url := "http://" + ln.Addr().String() + "/"
	var failures atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < c.n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(url)
			if err != nil {
				failures.Add(1)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	return maxConnsResult{int(p.maxSeen), int(p.accepts.Load()), int(failures.Load())}
}

func emitMaxConns(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const MaxConnsCase = struct {\n    id: []const u8,\n    /// Transport.MaxConnsPerHost; 0 = unlimited.\n    cap: u16,\n")
	fmt.Fprintf(b, "    /// Concurrent single-GET goroutines.\n    n: u16,\n    /// false = DisableKeepAlives.\n    keep_alive: bool,\n")
	fmt.Fprintf(b, "    /// The peer answers `Connection: close`.\n    server_close: bool,\n")
	fmt.Fprintf(b, "    /// Most requests the peer saw in flight at once.\n    max_in_flight: u16,\n")
	fmt.Fprintf(b, "    /// Connections the peer accepted.\n    accepts: u16,\n    failures: u16,\n};\n\n")
	fmt.Fprintf(b, "/// Hold time of the peer's answers (ms), shared with the replay.\npub const max_conns_hold_ms = %d;\n\n", maxConnsHoldMs)
	fmt.Fprintf(b, "/// Go's http.Transport{MaxConnsPerHost} against a peer that holds each answer (see tools/go_oracle/maxconns.go).\n")
	fmt.Fprintf(b, "pub const max_conns = [_]MaxConnsCase{\n")
	for _, c := range maxConnsCases() {
		r := runMaxConns(c)
		fmt.Fprintf(b, "    .{ .id = %s, .cap = %d, .n = %d, .keep_alive = %t, .server_close = %t, .max_in_flight = %d, .accepts = %d, .failures = %d },\n",
			zigStr(c.id), c.cap, c.n, c.keepAlive, c.serverClose, r.maxInFlight, r.accepts, r.failures)
	}
	fmt.Fprintf(b, "};\n\n")
}
