// SPDX-License-Identifier: MIT

// Lead probe behind the mcp card's `**Ahead:**` correctness line: the official
// Go MCP SDK, github.com/modelcontextprotocol/go-sdk v1.8.0 (pinned by
// go.mod/go.sum, the same as tools/go_bench), answering `prompts/get` for a
// prompt whose one argument is declared `Required: true`, with that argument
// left out. prompts.mdx ("Error Handling"): servers SHOULD answer "Missing
// required arguments" with -32602. Run from this directory:
//
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off GOFLAGS=-mod=mod go run .
//
// Observed 2026-10-24: the SDK calls the handler anyway, with the argument
// absent, and returns its result ("Hello, !"); this module answers
// {"code":-32602,"message":"Missing required argument"} without calling it
// (root.zig test "lead: prompts/get without a required argument is -32602").
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type pipe struct {
	r   io.Reader
	out *bytes.Buffer
}

func (p *pipe) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err == io.EOF {
		time.Sleep(300 * time.Millisecond) // let the in-flight request answer
	}
	return n, err
}
func (p *pipe) Write(b []byte) (int, error) { return p.out.Write(b) }
func (p *pipe) Close() error                { return nil }

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "lead", Version: "1"}, nil)
	called := false
	s.AddPrompt(&mcp.Prompt{Name: "greet", Arguments: []*mcp.PromptArgument{{Name: "name", Required: true}}},
		func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			called = true
			return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "Hello, " + req.Params.Arguments["name"] + "!"}}}}, nil
		})
	in := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"p","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greet","arguments":{}}}
`
	var out bytes.Buffer
	if err := s.Run(context.Background(), &mcp.IOTransport{Reader: &pipe{r: strings.NewReader(in), out: &out}, Writer: &pipe{out: &out}}); err != nil {
		fmt.Println("run:", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	fmt.Println(lines[len(lines)-1])
	fmt.Println("handler called:", called)
}
