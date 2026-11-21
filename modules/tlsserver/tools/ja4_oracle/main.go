// SPDX-License-Identifier: MIT

// ja4_oracle: the JA4 (TLS client) fingerprint of recorded ClientHellos by an
// independent implementation, github.com/exaring/ja4plus (MIT), over Go's
// crypto/tls ClientHelloInfo. Writes the `src/ja4_vectors.zig` table the
// tests compare `fingerprint.ja4` against.
//
// Input (stdin): one line per case, "name hex", the hex being the client's
// first TLS record (the ClientHello). Output: the Zig table.
//
//	python3 -I modules/tlsserver/tools/ja4_oracle/hellos.py \
//	    modules/tlsserver/src/interop_vectors.zig |
//	  (cd modules/tlsserver/tools/ja4_oracle && GOTOOLCHAIN=local go run .) \
//	    > modules/tlsserver/src/ja4_vectors.zig
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/exaring/ja4plus"
)

var errDone = errors.New("fingerprinted")

func ja4Of(record []byte) (string, error) {
	c, s := net.Pipe()
	defer c.Close()
	go func() {
		c.Write(record)
		io.Copy(io.Discard, c) // the server's alert: net.Pipe blocks a writer nobody reads
	}()
	var got string
	srv := tls.Server(s, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			got = ja4plus.JA4(h)
			return nil, errDone
		},
	})
	err := srv.Handshake()
	s.Close()
	if got == "" {
		return "", fmt.Errorf("no ClientHello: %v", err)
	}
	return got, nil
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	fmt.Println("// SPDX-License-Identifier: MIT")
	fmt.Println()
	fmt.Println("//! JA4 of the recorded clients' ClientHellos (`interop_vectors.zig`) by")
	fmt.Println("//! github.com/exaring/ja4plus over Go's crypto/tls, written by")
	fmt.Println("//! `tools/ja4_oracle`. Do not edit by hand.")
	fmt.Println()
	fmt.Println("pub const Vector = struct { name: []const u8, ja4: []const u8 };")
	fmt.Println()
	fmt.Println("pub const vectors = [_]Vector{")
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) != 2 {
			continue
		}
		rec, err := hex.DecodeString(f[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", f[0], err)
			os.Exit(1)
		}
		j, err := ja4Of(rec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", f[0], err)
			os.Exit(1)
		}
		fmt.Printf("    .{ .name = %q, .ja4 = %q },\n", f[0], j)
	}
	fmt.Println("};")
}
