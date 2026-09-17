// SPDX-License-Identifier: MIT
// Oracles B and C: real loopback WebSocket servers from two independent Go
// implementations (coder/websocket, gorilla/websocket). Each case's frame bytes
// are masked and written straight onto a raw TCP connection after a hand-rolled
// RFC 6455 handshake; whatever the foreign server writes back is recorded verbatim.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	coder "github.com/coder/websocket"
	gorilla "github.com/gorilla/websocket"
)

var maskKey = [4]byte{0x37, 0xfa, 0x21, 0x3d}

func maskFrame(d []byte) []byte {
	b1 := d[1]
	if b1&0x80 != 0 {
		panic("already masked")
	}
	l7 := b1 & 0x7f
	hl := 2
	if l7 == 126 {
		hl = 4
	} else if l7 == 127 {
		hl = 10
	}
	head := append([]byte{}, d[:hl]...)
	head[1] |= 0x80
	pay := d[hl:]
	out := append(head, maskKey[:]...)
	for i, b := range pay {
		out = append(out, b^maskKey[i%4])
	}
	return out
}

type result struct {
	Accept   string `json:"accept"`
	ReplyHex string `json:"reply_hex"`
	Err      string `json:"err"`
}

func probe(addr, name string, frame []byte) result {
	var r result
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		r.Err = "dial: " + err.Error()
		return r
	}
	defer c.Close()
	req := "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(req)); err != nil {
		r.Err = "write req: " + err.Error()
		return r
	}
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			r.Err = "read resp: " + err.Error()
			return r
		}
		if len(line) > 22 && strings.EqualFold(line[:21], "sec-websocket-accept:") {
			r.Accept = strings.TrimSpace(line[21 : len(line)-2])
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := c.Write(maskFrame(frame)); err != nil {
		r.Err = "write frame: " + err.Error()
		return r
	}
	c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := br.Read(buf)
	if n > 0 {
		r.ReplyHex = hex.EncodeToString(buf[:n])
	}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

func startCoder() string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		c, err := coder.Accept(w, req, &coder.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(1 << 21)
		ctx := context.Background()
		for {
			_, _, err := c.Read(ctx)
			if err != nil {
				return
			}
		}
	})
	go http.Serve(ln, mux)
	return ln.Addr().String()
}

func startGorilla() string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	up := gorilla.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		c, err := up.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadLimit(1 << 21)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})
	go http.Serve(ln, mux)
	return ln.Addr().String()
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cases map[string]string
	if err := json.Unmarshal(raw, &cases); err != nil {
		panic(err)
	}
	coderAddr := startCoder()
	gorillaAddr := startGorilla()
	time.Sleep(200 * time.Millisecond)

	out := map[string]map[string]result{"coder": {}, "gorilla": {}}
	for name, h := range cases {
		f, _ := hex.DecodeString(h)
		out["coder"][name] = probe(coderAddr, name, f)
		out["gorilla"][name] = probe(gorillaAddr, name, f)
	}
	enc, _ := json.MarshalIndent(map[string]any{
		"oracles": map[string]string{"coder": "github.com/coder/websocket v1.8.15", "gorilla": "github.com/gorilla/websocket v1.5.3"},
		"results": out,
	}, "", " ")
	os.WriteFile(os.Args[2], enc, 0644)
	fmt.Println("wrote", os.Args[2], len(cases), "cases")
}
