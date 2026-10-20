// SPDX-License-Identifier: MIT

// Go side of `zig build bench-mcp` (modules/mcp/tools/bench.zig): times the
// official Go MCP SDK, github.com/modelcontextprotocol/go-sdk v1.8.0 (pinned by
// go.mod/go.sum), over the session bytes the Zig program writes into the
// directory given as the first argument, for the one workload named by the
// second, through its public API only. Prints one line: name, ns/op, result
// count (tab-separated). One op = one whole session (`initialize`,
// `notifications/initialized`, then 64 requests of one kind) fed to
// `Server.Run` over `mcp.IOTransport` (the SDK's stdio framing) on in-memory
// bytes, until the reader's EOF, the responses collected in a buffer.
//
//	tools_call_echo   mcp.AddTool with typed In/Out structs (schemas inferred,
//	                  arguments and structured result validated by the SDK)
//	tools_list_20     20 tools added with Server.AddTool, small input schemas
//	resources_read    one static 1 KiB text resource
//	prompts_get       one prompt with one required argument
//	initialize_only   handshake + 64 pings
//
// count = the number of response lines + the number of `"isError":true`
// occurrences in them (the Zig module and the SDK order fields differently, so
// response bytes are not compared).
//
// A session that produced a JSON-RPC error is refused (as on the Zig side).
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func serverFor(name string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "bench", Version: "1.0.0"}, nil)
	switch name {
	case "tools_call_echo":
		mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo the text back"}, echo)
	case "tools_list_20":
		for i := 0; i < 20; i++ {
			s.AddTool(&mcp.Tool{
				Name:        fmt.Sprintf("tool_%02d", i),
				Description: fmt.Sprintf("Small tool number %d", i),
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"a": map[string]any{"type": "string"},
						"b": map[string]any{"type": "integer"},
					},
					"required": []string{"a"},
				},
			}, noopTool)
		}
	case "resources_read":
		text := strings.Repeat("0123456789abcdef", 64)
		s.AddResource(&mcp.Resource{URI: "file:///doc.txt", Name: "doc", MIMEType: "text/plain"},
			func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "file:///doc.txt", MIMEType: "text/plain", Text: text}}}, nil
			})
	case "prompts_get":
		s.AddPrompt(&mcp.Prompt{Name: "greet", Description: "Greet someone", Arguments: []*mcp.PromptArgument{{Name: "name", Required: true}}},
			func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "Hello, " + req.Params.Arguments["name"] + "!"}}}}, nil
			})
	case "initialize_only":
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	return s
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	wire, err := os.ReadFile(filepath.Join(dir, name+".wire"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "github.com/modelcontextprotocol/go-sdk v1.8.0")

	s := serverFor(name)
	ctx := context.Background()
	// One response per request line (a line with an "id" and a "method").
	want := 0
	for _, l := range bytes.Split(wire, []byte("\n")) {
		if bytes.Contains(l, []byte(`"id"`)) {
			want++
		}
	}
	var out bytes.Buffer

	ns, count := timeIt(func() int {
		out.Reset()
		sess := newSession(wire, &out, want)
		t := &mcp.IOTransport{Reader: sess, Writer: sess}
		if err := s.Run(ctx, t); err != nil {
			panic(err)
		}
		b := out.Bytes()
		// A JSON-RPC error is a response line too; refuse a session with one.
		if bytes.Contains(b, []byte(`"error":{`)) {
			panic("the SDK answered a JSON-RPC error")
		}
		return bytes.Count(b, []byte("\n")) + bytes.Count(b, []byte(`"isError":true`))
	})
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}

// session is the in-memory peer: it hands the SDK the whole request stream at
// once, collects the responses, and reports EOF only after every request has
// been answered, as a client that keeps its connection open until it has its
// answers does. The SDK runs request handlers concurrently and abandons the
// ones still in flight when the reader ends, so an EOF straight after the
// last request byte would lose responses.
type session struct {
	r    *bytes.Reader
	out  *bytes.Buffer
	want int
	mu   sync.Mutex
	got  int
	done chan struct{}
}

func newSession(wire []byte, out *bytes.Buffer, want int) *session {
	return &session{r: bytes.NewReader(wire), out: out, want: want, done: make(chan struct{})}
}

func (s *session) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err == io.EOF {
		<-s.done
	}
	return n, err
}

func (s *session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(p)
	before := s.got
	s.got += bytes.Count(p, []byte("\n"))
	if before < s.want && s.got >= s.want {
		close(s.done)
	}
	return len(p), nil
}

func (s *session) Close() error { return nil }
