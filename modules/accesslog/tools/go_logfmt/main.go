// SPDX-License-Identifier: MIT

// go-logfmt (github.com/go-logfmt/logfmt, MIT, run as a black box) -- the
// de-facto reference logfmt reader -- as the judge of this module's logfmt
// lines: each line on stdin is decoded on its own and re-encoded on stdout as
// a JSON array of [key, value] pairs in order, values as bytes in hex (logfmt
// carries arbitrary bytes), or as {"error": "..."} when the decoder refuses
// it. Driven by tools/json_oracle.py.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-logfmt/logfmt"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		d := logfmt.NewDecoder(bytes.NewReader(in.Bytes()))
		var pairs [][2]string
		records := 0
		var err error
		for d.ScanRecord() {
			records++
			for d.ScanKeyval() {
				pairs = append(pairs, [2]string{string(d.Key()), hex.EncodeToString(d.Value())})
			}
		}
		if err == nil {
			err = d.Err()
		}
		if err == nil && records != 1 {
			err = fmt.Errorf("%d records on the line", records)
		}
		var b []byte
		if err != nil {
			b, _ = json.Marshal(map[string]string{"error": err.Error()})
		} else {
			b, _ = json.Marshal(pairs)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
}
