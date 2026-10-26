// SPDX-License-Identifier: MIT

// Go side of `zig build interop-websocket` (modules/websocket/tools/interop.zig):
// two independent Go WebSocket implementations, github.com/coder/websocket
// v1.8.15 (the module's scope reference, ISC) and github.com/gorilla/websocket
// v1.5.3 (BSD-2-Clause), through their public APIs only, as live peers.
//
//	go_oracle serve
//	go_oracle client <coder|gorilla> <ws-url> <scenario>
//
// `serve` opens one loopback listener per library, prints
//
//	READY <go version> coder=<port> gorilla=<port>
//
// and serves until killed. Every connection names its case in the query
// (`?case=<id>`); when the handler is done it records one line for it, which
// `GET /report?case=<id>` on the same listener returns (waiting up to 5 s for
// it). The paths:
//
//	/echo          echo every message back (subprotocols offered: chat, echo)
//	/deflate       the same with permessage-deflate, no context takeover
//	/ping          the server pings ("zl-ping"), waits for the pong, then
//	               sends the text "ping-ok:<payload>" and echoes
//	/close/<code>  the server closes at once with <code> and "zl-bye"
//	/frag          the server sends a 4096-byte text message in fragments,
//	               then echoes; the client sends it back
//	/frag-deflate  the same, compressed
//
// An echo handler records `closed=<code> msgs=<n> proto=<p|-> ext=<0|1>`
// (`closed=err:<text>` when the connection ended without a close frame).
//
// `client` dials the given URL with that library's client, runs one
// scenario and prints one line, `ok <detail>` or `err <detail>`:
//
//	echo           the message suite (see suite()) out and back, close 1000
//	deflate        the suite with permessage-deflate offered
//	frag           one 4096-byte text message written in four fragments
//	frag-deflate   the same with permessage-deflate offered
//	ping           a ping, its pong awaited, then close 1000
//	sping          (on /ping) the server's ping answered, its "ping-ok" read
//	close          close with 4001 "zl-client-bye", the echo checked
//	servclose      read until the server closes; print its code and reason
//	subproto       offer chat and echo; print what was selected, close 1000
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	coder "github.com/coder/websocket"
	gorilla "github.com/gorilla/websocket"
)

const fragLen = 4096

// pattern returns n bytes: ASCII for text, i*31+7 for binary -- the same
// function as interop.zig's `pattern`.
func pattern(n int, text bool) []byte {
	b := make([]byte, n)
	for i := range b {
		if text {
			b[i] = byte('a' + i%26)
		} else {
			b[i] = byte(i*31 + 7)
		}
	}
	return b
}

type msg struct {
	text bool
	data []byte
}

// suite is the echo scenario's message list -- the same list as
// interop.zig's `suite`: every length-form boundary, both opcodes,
// multi-byte UTF-8, and 1 MiB.
func suite() []msg {
	var out []msg
	for _, n := range []int{0, 1, 125, 126, 127, 65535, 65536, 1 << 20} {
		out = append(out, msg{true, pattern(n, true)}, msg{false, pattern(n, false)})
	}
	out = append(out, msg{true, []byte("žluťoučký kůň úpěl ďábelské ódy — 😀 €")})
	return out
}

// ── reports ─────────────────────────────────────────────────────────────

type reports struct {
	mu   sync.Mutex
	cond *sync.Cond
	m    map[string]string
}

func newReports() *reports {
	r := &reports{m: map[string]string{}}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *reports) put(id, line string) {
	r.mu.Lock()
	r.m[id] = line
	r.mu.Unlock()
	r.cond.Broadcast()
}

func (r *reports) get(id string) string {
	deadline := time.Now().Add(5 * time.Second)
	go func() { time.Sleep(5 * time.Second); r.cond.Broadcast() }()
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if l, ok := r.m[id]; ok {
			return l
		}
		if time.Now().After(deadline) {
			return "none"
		}
		r.cond.Wait()
	}
}

func serveReport(rep *reports, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, rep.get(r.URL.Query().Get("case")))
}

func extFlag(h http.Header) string {
	if strings.Contains(h.Get("Sec-WebSocket-Extensions"), "permessage-deflate") {
		return "1"
	}
	return "0"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ── coder server ────────────────────────────────────────────────────────

func coderClosed(err error) string {
	if s := coder.CloseStatus(err); s != -1 {
		return strconv.Itoa(int(s))
	}
	return "err:" + strings.ReplaceAll(err.Error(), " ", "_")
}

func coderEcho(ctx context.Context, c *coder.Conn, msgs int) string {
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return fmt.Sprintf("closed=%s msgs=%d", coderClosed(err), msgs)
		}
		msgs++
		if err := c.Write(ctx, typ, data); err != nil {
			return fmt.Sprintf("closed=err:write msgs=%d", msgs)
		}
	}
}

func coderHandler(rep *reports) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/report" {
			serveReport(rep, w, r)
			return
		}
		id := r.URL.Query().Get("case")
		opts := &coder.AcceptOptions{Subprotocols: []string{"chat", "echo"}}
		if strings.HasSuffix(r.URL.Path, "deflate") {
			opts.CompressionMode = coder.CompressionNoContextTakeover
		}
		c, err := coder.Accept(w, r, opts)
		if err != nil {
			rep.put(id, "accept:"+strings.ReplaceAll(err.Error(), " ", "_"))
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(4 << 20)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		tail := fmt.Sprintf(" proto=%s ext=%s", orDash(c.Subprotocol()), extFlag(w.Header()))
		switch p := r.URL.Path; {
		case p == "/echo" || p == "/deflate":
			rep.put(id, coderEcho(ctx, c, 0)+tail)
		case p == "/ping":
			done := make(chan string, 1)
			go func() { done <- coderEcho(ctx, c, 0) }()
			// coder's Ping sends its own payload and waits for the pong
			// carrying it; a pong with another payload never completes it.
			if err := c.Ping(ctx); err != nil {
				c.Write(ctx, coder.MessageText, []byte("ping-err"))
			} else {
				c.Write(ctx, coder.MessageText, []byte("ping-ok:coder"))
			}
			rep.put(id, <-done+tail)
		case strings.HasPrefix(p, "/close/"):
			code, _ := strconv.Atoi(strings.TrimPrefix(p, "/close/"))
			// Close waits for the peer's close frame and fails when it
			// does not come.
			if err := c.Close(coder.StatusCode(code), "zl-bye"); err != nil {
				rep.put(id, "closed=err:"+strings.ReplaceAll(err.Error(), " ", "_")+tail)
			} else {
				rep.put(id, "closed=ok"+tail)
			}
		case p == "/frag" || p == "/frag-deflate":
			// coder's Writer sends every Write as one frame (compressed
			// ones as the flate writer flushes), the fin frame on Close.
			mw, err := c.Writer(ctx, coder.MessageText)
			if err == nil {
				body := pattern(fragLen, true)
				for i := 0; i < 4 && err == nil; i++ {
					_, err = mw.Write(body[i*1024 : (i+1)*1024])
				}
				if err == nil {
					err = mw.Close()
				}
			}
			if err != nil {
				rep.put(id, "closed=err:write"+tail)
				return
			}
			typ, data, err := c.Read(ctx)
			if err != nil || typ != coder.MessageText || !bytes.Equal(data, pattern(fragLen, true)) {
				rep.put(id, "closed=err:bad_echo"+tail)
				return
			}
			rep.put(id, coderEcho(ctx, c, 1)+tail)
		}
	}
}

// ── gorilla server ──────────────────────────────────────────────────────

func gorillaClosed(err error) string {
	var ce *gorilla.CloseError
	if errors.As(err, &ce) {
		return strconv.Itoa(ce.Code)
	}
	return "err:" + strings.ReplaceAll(err.Error(), " ", "_")
}

// gorillaEcho: gorilla allows one concurrent writer, so every write
// (here and in the ping path) goes through wmu.
func gorillaEcho(c *gorilla.Conn, wmu *sync.Mutex, msgs int) string {
	for {
		typ, data, err := c.ReadMessage()
		if err != nil {
			return fmt.Sprintf("closed=%s msgs=%d", gorillaClosed(err), msgs)
		}
		msgs++
		wmu.Lock()
		err = c.WriteMessage(typ, data)
		wmu.Unlock()
		if err != nil {
			return fmt.Sprintf("closed=err:write msgs=%d", msgs)
		}
	}
}

func gorillaHandler(rep *reports) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/report" {
			serveReport(rep, w, r)
			return
		}
		id := r.URL.Query().Get("case")
		up := gorilla.Upgrader{
			Subprotocols:      []string{"chat", "echo"},
			EnableCompression: strings.HasSuffix(r.URL.Path, "deflate"),
		}
		if strings.HasPrefix(r.URL.Path, "/frag") {
			// A message longer than the write buffer goes out in frames.
			up.WriteBufferSize = 1024
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			rep.put(id, "accept:"+strings.ReplaceAll(err.Error(), " ", "_"))
			return
		}
		defer c.Close()
		c.SetReadLimit(4 << 20)
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		var wmu sync.Mutex
		// gorilla writes its 101 on the hijacked connection, not through
		// w.Header(), and has no accessor for the outcome; it accepts any
		// offer naming permessage-deflate when EnableCompression is set.
		ext := "0"
		if up.EnableCompression && strings.Contains(strings.Join(r.Header.Values("Sec-WebSocket-Extensions"), ","), "permessage-deflate") {
			ext = "1"
		}
		tail := fmt.Sprintf(" proto=%s ext=%s", orDash(c.Subprotocol()), ext)
		switch p := r.URL.Path; {
		case p == "/echo" || p == "/deflate":
			rep.put(id, gorillaEcho(c, &wmu, 0)+tail)
		case p == "/ping":
			pong := make(chan string, 1)
			c.SetPongHandler(func(s string) error { pong <- s; return nil })
			done := make(chan string, 1)
			go func() { done <- gorillaEcho(c, &wmu, 0) }()
			wmu.Lock()
			c.WriteControl(gorilla.PingMessage, []byte("zl-ping"), time.Now().Add(5*time.Second))
			wmu.Unlock()
			reply := "ping-err"
			select {
			case s := <-pong:
				reply = "ping-ok:" + s
			case <-time.After(5 * time.Second):
			}
			wmu.Lock()
			c.WriteMessage(gorilla.TextMessage, []byte(reply))
			wmu.Unlock()
			rep.put(id, <-done+tail)
		case strings.HasPrefix(p, "/close/"):
			code, _ := strconv.Atoi(strings.TrimPrefix(p, "/close/"))
			c.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(code, "zl-bye"), time.Now().Add(5*time.Second))
			// The peer's echo surfaces as a CloseError from the reader.
			// The record has coder's shape: "ok" when the echo carries the code.
			_, _, err := c.ReadMessage()
			if got := gorillaClosed(err); got == strconv.Itoa(code) {
				rep.put(id, "closed=ok"+tail)
			} else {
				rep.put(id, "closed=err:echo_"+got+tail)
			}
		case p == "/frag" || p == "/frag-deflate":
			mw, err := c.NextWriter(gorilla.TextMessage)
			if err == nil {
				_, err = mw.Write(pattern(fragLen, true))
				if err == nil {
					err = mw.Close()
				}
			}
			if err != nil {
				rep.put(id, "closed=err:write"+tail)
				return
			}
			typ, data, err := c.ReadMessage()
			if err != nil || typ != gorilla.TextMessage || !bytes.Equal(data, pattern(fragLen, true)) {
				rep.put(id, "closed=err:bad_echo"+tail)
				return
			}
			rep.put(id, gorillaEcho(c, &wmu, 1)+tail)
		}
	}
}

func serve() {
	lc, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	lg, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	go http.Serve(lc, coderHandler(newReports()))
	go http.Serve(lg, gorillaHandler(newReports()))
	fmt.Printf("READY %s coder=%d gorilla=%d\n", runtime.Version(), lc.Addr().(*net.TCPAddr).Port, lg.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	select {}
}

// ── clients ─────────────────────────────────────────────────────────────

func coderClient(url, scenario string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	opts := &coder.DialOptions{}
	if strings.HasSuffix(scenario, "deflate") {
		opts.CompressionMode = coder.CompressionNoContextTakeover
	}
	if scenario == "subproto" {
		opts.Subprotocols = []string{"chat", "echo"}
	}
	c, resp, err := coder.Dial(ctx, url, opts)
	if err != nil {
		return "err dial:" + err.Error()
	}
	defer c.CloseNow()
	c.SetReadLimit(4 << 20)
	ext := "ext=" + extFlag(resp.Header)
	switch scenario {
	case "echo", "deflate":
		for i, m := range suite() {
			typ := coder.MessageBinary
			if m.text {
				typ = coder.MessageText
			}
			if err := c.Write(ctx, typ, m.data); err != nil {
				return fmt.Sprintf("err write %d: %v", i, err)
			}
			rt, data, err := c.Read(ctx)
			if err != nil {
				return fmt.Sprintf("err read %d: %v", i, err)
			}
			if rt != typ || !bytes.Equal(data, m.data) {
				return fmt.Sprintf("err echo %d differs (len %d, want %d)", i, len(data), len(m.data))
			}
		}
		if err := c.Close(coder.StatusNormalClosure, ""); err != nil {
			return "err close: " + err.Error()
		}
		return fmt.Sprintf("ok msgs=%d %s", len(suite()), ext)
	case "frag", "frag-deflate":
		mw, err := c.Writer(ctx, coder.MessageText)
		if err != nil {
			return "err writer: " + err.Error()
		}
		body := pattern(fragLen, true)
		for i := 0; i < 4; i++ {
			if _, err := mw.Write(body[i*1024 : (i+1)*1024]); err != nil {
				return "err write: " + err.Error()
			}
		}
		if err := mw.Close(); err != nil {
			return "err fin: " + err.Error()
		}
		rt, data, err := c.Read(ctx)
		if err != nil || rt != coder.MessageText || !bytes.Equal(data, body) {
			return fmt.Sprintf("err echo: %v", err)
		}
		if err := c.Close(coder.StatusNormalClosure, ""); err != nil {
			return "err close: " + err.Error()
		}
		return "ok msgs=1 " + ext
	case "ping":
		rctx := c.CloseRead(ctx) // a reader must run for the pong to arrive
		_ = rctx
		if err := c.Ping(ctx); err != nil {
			return "err ping: " + err.Error()
		}
		if err := c.Close(coder.StatusNormalClosure, ""); err != nil {
			return "err close: " + err.Error()
		}
		return "ok pong " + ext
	case "sping":
		// coder answers the server's ping inside Read.
		_, data, err := c.Read(ctx)
		if err != nil || !strings.HasPrefix(string(data), "ping-ok") {
			return fmt.Sprintf("err read: %v %q", err, data)
		}
		if err := c.Close(coder.StatusNormalClosure, ""); err != nil {
			return "err close: " + err.Error()
		}
		return "ok " + string(data) + " " + ext
	case "close":
		if err := c.Close(4001, "zl-client-bye"); err != nil {
			return "err close: " + err.Error()
		}
		return "ok closed " + ext
	case "servclose":
		_, _, err := c.Read(ctx)
		var ce coder.CloseError
		if errors.As(err, &ce) {
			return fmt.Sprintf("ok code=%d reason=%s %s", ce.Code, ce.Reason, ext)
		}
		return fmt.Sprintf("err read: %v", err)
	case "subproto":
		p := orDash(c.Subprotocol())
		if err := c.Close(coder.StatusNormalClosure, ""); err != nil {
			return "err close: " + err.Error()
		}
		return "ok proto=" + p + " " + ext
	}
	return "err unknown scenario " + scenario
}

func gorillaClient(url, scenario string) string {
	d := gorilla.Dialer{
		HandshakeTimeout:  5 * time.Second,
		EnableCompression: strings.HasSuffix(scenario, "deflate"),
	}
	if strings.HasPrefix(scenario, "frag") {
		d.WriteBufferSize = 1024
	}
	var hdr http.Header
	if scenario == "subproto" {
		d.Subprotocols = []string{"chat", "echo"}
	}
	c, resp, err := d.Dial(url, hdr)
	if err != nil {
		return "err dial:" + err.Error()
	}
	defer c.Close()
	c.SetReadLimit(4 << 20)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	ext := "ext=" + extFlag(resp.Header)
	// closeAndWait sends a close frame and reads until the echo arrives.
	closeAndWait := func(code int, reason string) (int, error) {
		if err := c.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(code, reason), time.Now().Add(5*time.Second)); err != nil {
			return 0, err
		}
		for {
			_, _, err := c.ReadMessage()
			var ce *gorilla.CloseError
			if errors.As(err, &ce) {
				return ce.Code, nil
			}
			if err != nil {
				return 0, err
			}
		}
	}
	switch scenario {
	case "echo", "deflate":
		for i, m := range suite() {
			typ := gorilla.BinaryMessage
			if m.text {
				typ = gorilla.TextMessage
			}
			if err := c.WriteMessage(typ, m.data); err != nil {
				return fmt.Sprintf("err write %d: %v", i, err)
			}
			rt, data, err := c.ReadMessage()
			if err != nil {
				return fmt.Sprintf("err read %d: %v", i, err)
			}
			if rt != typ || !bytes.Equal(data, m.data) {
				return fmt.Sprintf("err echo %d differs (len %d, want %d)", i, len(data), len(m.data))
			}
		}
		code, err := closeAndWait(gorilla.CloseNormalClosure, "")
		if err != nil || code != gorilla.CloseNormalClosure {
			return fmt.Sprintf("err close echo %d: %v", code, err)
		}
		return fmt.Sprintf("ok msgs=%d %s", len(suite()), ext)
	case "frag", "frag-deflate":
		body := pattern(fragLen, true)
		mw, err := c.NextWriter(gorilla.TextMessage)
		if err != nil {
			return "err writer: " + err.Error()
		}
		if _, err := mw.Write(body); err != nil {
			return "err write: " + err.Error()
		}
		if err := mw.Close(); err != nil {
			return "err fin: " + err.Error()
		}
		rt, data, err := c.ReadMessage()
		if err != nil || rt != gorilla.TextMessage || !bytes.Equal(data, body) {
			return fmt.Sprintf("err echo: %v", err)
		}
		code, err := closeAndWait(gorilla.CloseNormalClosure, "")
		if err != nil || code != gorilla.CloseNormalClosure {
			return fmt.Sprintf("err close echo %d: %v", code, err)
		}
		return "ok msgs=1 " + ext
	case "ping":
		pong := make(chan string, 1)
		c.SetPongHandler(func(s string) error { pong <- s; return nil })
		if err := c.WriteControl(gorilla.PingMessage, []byte("zl-ping"), time.Now().Add(5*time.Second)); err != nil {
			return "err ping: " + err.Error()
		}
		// The pong handler runs inside the reader.
		closed := make(chan int, 1)
		go func() {
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					var ce *gorilla.CloseError
					if errors.As(err, &ce) {
						closed <- ce.Code
					} else {
						closed <- 0
					}
					return
				}
			}
		}()
		select {
		case s := <-pong:
			if s != "zl-ping" {
				return "err pong payload " + s
			}
		case <-time.After(5 * time.Second):
			return "err no pong"
		}
		c.WriteControl(gorilla.CloseMessage, gorilla.FormatCloseMessage(gorilla.CloseNormalClosure, ""), time.Now().Add(5*time.Second))
		if code := <-closed; code != gorilla.CloseNormalClosure {
			return fmt.Sprintf("err close echo %d", code)
		}
		return "ok pong " + ext
	case "sping":
		// gorilla's default ping handler answers inside ReadMessage.
		_, data, err := c.ReadMessage()
		if err != nil || !strings.HasPrefix(string(data), "ping-ok") {
			return fmt.Sprintf("err read: %v %q", err, data)
		}
		code, err := closeAndWait(gorilla.CloseNormalClosure, "")
		if err != nil || code != gorilla.CloseNormalClosure {
			return fmt.Sprintf("err close echo %d: %v", code, err)
		}
		return "ok " + string(data) + " " + ext
	case "close":
		code, err := closeAndWait(4001, "zl-client-bye")
		if err != nil || code != 4001 {
			return fmt.Sprintf("err close echo %d: %v", code, err)
		}
		return "ok closed " + ext
	case "servclose":
		_, _, err := c.ReadMessage()
		var ce *gorilla.CloseError
		if errors.As(err, &ce) {
			return fmt.Sprintf("ok code=%d reason=%s %s", ce.Code, ce.Text, ext)
		}
		return fmt.Sprintf("err read: %v", err)
	case "subproto":
		p := orDash(c.Subprotocol())
		code, err := closeAndWait(gorilla.CloseNormalClosure, "")
		if err != nil || code != gorilla.CloseNormalClosure {
			return fmt.Sprintf("err close echo %d: %v", code, err)
		}
		return "ok proto=" + p + " " + ext
	}
	return "err unknown scenario " + scenario
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "go_oracle:", err)
		os.Exit(2)
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		serve()
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "client" {
		var line string
		switch os.Args[2] {
		case "coder":
			line = coderClient(os.Args[3], os.Args[4])
		case "gorilla":
			line = gorillaClient(os.Args[3], os.Args[4])
		default:
			line = "err unknown library " + os.Args[2]
		}
		fmt.Println(strings.ReplaceAll(line, "\n", " "))
		return
	}
	fmt.Fprintln(os.Stderr, "usage: go_oracle serve | go_oracle client <coder|gorilla> <url> <scenario>")
	os.Exit(2)
}
