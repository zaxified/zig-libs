// SPDX-License-Identifier: MIT

// Go's verdicts for tools/query_oracle.py: net/url decodes the query string,
// strconv / math/big say whether the decoded text spells a value of the
// rule's kind. Standard library only. Reads one JSON request per line on
// stdin, answers one JSON line per request on stdout.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"strconv"
)

type request struct {
	Query string `json:"query"`
	Field string `json:"field"`
	Kind  string `json:"kind"`
}

type answer struct {
	Present bool   `json:"present"`
	Value   string `json:"value"` // hex of the first decoded value
	Coerce  *bool  `json:"coerce"` // null: Go has no grammar for this kind
}

func coerce(kind, s string) *bool {
	var ok bool
	switch kind {
	case "int":
		_, ok = new(big.Int).SetString(s, 10)
	case "float":
		_, err := strconv.ParseFloat(s, 64)
		ok = err == nil
	case "bool":
		_, err := strconv.ParseBool(s)
		ok = err == nil
	default:
		return nil
	}
	return &ok
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var r request
		if err := json.Unmarshal(in.Bytes(), &r); err != nil {
			panic(err)
		}
		// ParseQuery drops a pair it cannot decode and reports the first
		// such error; the pairs it could decode are still returned.
		vals, _ := url.ParseQuery(r.Query)
		a := answer{}
		if vs, ok := vals[r.Field]; ok && len(vs) > 0 {
			a.Present = true
			a.Value = hex.EncodeToString([]byte(vs[0]))
			a.Coerce = coerce(r.Kind, vs[0])
		}
		if err := out.Encode(a); err != nil {
			panic(err)
		}
	}
}
