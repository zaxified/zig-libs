// SPDX-License-Identifier: MIT

// Go side of mcp-http's HTTP benchmark (tools/http_bench/run.sh).
//
//	http_bench server <port>
//	    the official MCP Go SDK (github.com/modelcontextprotocol/go-sdk, public API
//	    only) behind mcp.NewStreamableHTTPHandler, stateless with JSON responses,
//	    serving the bench catalog (tool "echo" with typed in/out, 20 small tools).
//	http_bench client <url> <workload> <conns> <requests>
//	    the one load generator every server is measured with: <conns> keep-alive
//	    connections send <requests> POSTs in all; prints "<workload>\t<ns per
//	    request>\t<requests>". Every response must be 200 with a body that holds
//	    the workload's marker; any failure exits 1.
//
// Workloads (stateless, session-era 2025-11-25 requests, which every server
// under test serves without a session):
//
//	tools_call_echo   tools/call echo {"text":"hello"}
//	tools_list_20     tools/list over 20 tools
//
// Built offline from the module cache (GOPROXY=off, GOFLAGS=-mod=mod).
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoIn struct {
	Text string `json:"text"`
}

type echoOut struct {
	Echo string `json:"echo"`
}

func echo(ctx context.Context, req *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoOut, error) {
	return nil, echoOut{Echo: in.Text}, nil
}

func noopTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
}

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "bench", Version: "1.0.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo the text back"}, echo)
	for i := 0; i < 20; i++ {
		s.AddTool(&mcp.Tool{
			Name:        fmt.Sprintf("tool_%02d", i),
			Description: fmt.Sprintf("Small tool number %d", i),
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"a": map[string]any{"type": "string"}, "b": map[string]any{"type": "integer"}},
				"required":   []string{"a"},
			},
		}, noopTool)
	}
	return s
}

func serve(port string) {
	s := newServer()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	srv := &http.Server{Addr: "127.0.0.1:" + port, Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var workloads = map[string]struct{ body, marker string }{
	"tools_call_echo": {`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`, `hello`},
	"tools_list_20":   {`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, `tool_19`},
}

func client(url, workload string, conns, n int) {
	w, ok := workloads[workload]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown workload", workload)
		os.Exit(2)
	}
	tr := &http.Transport{
		MaxIdleConns: conns, MaxIdleConnsPerHost: conns, MaxConnsPerHost: conns,
		DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableCompression: true,
	}
	c := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	body := []byte(w.body)
	marker := []byte(w.marker)
	var next, failures int64
	one := func() {
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		resp, err := c.Do(req)
		if err != nil {
			atomic.AddInt64(&failures, 1)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !bytes.Contains(b, marker) {
			if atomic.AddInt64(&failures, 1) == 1 {
				fmt.Fprintf(os.Stderr, "first failure: %d %q\n", resp.StatusCode, b)
			}
		}
	}
	var wg sync.WaitGroup
	start := time.Now()
	for k := 0; k < conns; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.AddInt64(&next, 1) <= int64(n) {
				one()
			}
		}()
	}
	wg.Wait()
	d := time.Since(start)
	if failures != 0 {
		fmt.Fprintf(os.Stderr, "%d of %d requests failed\n", failures, n)
		os.Exit(1)
	}
	// benchkit.parseForeign's shape: name, ns per request, count.
	fmt.Printf("%s\t%.0f\t%d\n", workload, float64(d.Nanoseconds())/float64(n), n)
}

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "server" {
		serve(os.Args[2])
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "client" {
		conns, _ := strconv.Atoi(os.Args[4])
		n, _ := strconv.Atoi(os.Args[5])
		client(os.Args[2], os.Args[3], conns, n)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: http_bench server <port> | client <url> <workload> <conns> <requests>")
	os.Exit(2)
}
