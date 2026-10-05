// SPDX-License-Identifier: MIT
//
// Go leg of the csvstream differential oracle (tools/oracle.py): Go's
// encoding/csv as an independent reader and writer.
//
// stdin: one request per line, "R <hex>" or "W <hex>|<hex>|...".
//
//	R: read the decoded text with LazyQuotes and FieldsPerRecord=-1 to the
//	   end; answer "ERR" on an error (empty input: io.EOF is not an error
//	   here, it is zero records), else the records as
//	   "x<hex>|x<hex>;x<hex>..." (records joined by ';', fields by '|',
//	   each field "x" + hex, so an empty field is "x" and no records is "").
//	W: write the decoded fields as one record with UseCRLF; answer the
//	   bytes, hex.
//
// Stdlib only, no network.
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<22), 1<<22)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for sc.Scan() {
		line := sc.Text()
		switch line[0] {
		case 'R':
			b, _ := hex.DecodeString(line[2:])
			r := csv.NewReader(bytes.NewReader(b))
			r.LazyQuotes = true
			r.FieldsPerRecord = -1
			var recs []string
			bad := false
			for {
				rec, err := r.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					bad = true
					break
				}
				fs := make([]string, len(rec))
				for i, f := range rec {
					fs[i] = "x" + hex.EncodeToString([]byte(f))
				}
				line, col := r.FieldPos(0)
				recs = append(recs, fmt.Sprintf("%d:%d@", line, col)+strings.Join(fs, "|"))
			}
			if bad {
				fmt.Fprintln(out, "ERR")
			} else {
				fmt.Fprintln(out, "OK "+strings.Join(recs, ";"))
			}
		case 'W':
			var fields []string
			for _, h := range strings.Split(line[2:], "|") {
				b, _ := hex.DecodeString(h)
				fields = append(fields, string(b))
			}
			var buf bytes.Buffer
			w := csv.NewWriter(&buf)
			w.UseCRLF = true
			w.Write(fields)
			w.Flush()
			fmt.Fprintln(out, hex.EncodeToString(buf.Bytes()))
		}
	}
}
