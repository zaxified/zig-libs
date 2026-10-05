// SPDX-License-Identifier: MIT

// Go's encoding/json (stdlib, BSD-3-Clause, run as a black box) as one of three
// readers of this module's JSON Lines: each line on stdin is decoded on its own
// (numbers kept exact with UseNumber) and re-encoded on stdout, or the line
// becomes {"error": "..."} when Go refuses it. Driven by tools/json_oracle.py.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		dec := json.NewDecoder(bytes.NewReader(in.Bytes()))
		dec.UseNumber()
		var v map[string]any
		err := dec.Decode(&v)
		if err == nil && dec.More() {
			err = fmt.Errorf("more than one value on the line")
		}
		var b []byte
		if err != nil {
			b, _ = json.Marshal(map[string]string{"error": err.Error()})
		} else {
			b, _ = json.Marshal(v)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
}
