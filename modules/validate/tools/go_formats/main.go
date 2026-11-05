// Verdicts of go-playground/validator v10.30.5 on single strings, for
// format_oracle.py. Reads a JSON array of {"tag": ..., "v": ...} on stdin
// (v is base64 so any byte sequence survives JSON) and writes a JSON array of
// booleans on stdout, one per input: true when validate.Var(v, tag) passes.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"

	"github.com/go-playground/validator/v10"
)

type item struct {
	Tag string `json:"tag"`
	V   string `json:"v"`
	// Int: the tag takes an integer kind (iso4217_numeric); v is its decimal text,
	// and text that is no integer is a failure.
	Int bool `json:"int"`
}

// pass reports whether the tag accepts the value. A panic inside the rival counts
// as a refusal: go-playground v10.30.5's isIP6Addr (baked_in.go:2900) slices
// val[1:idx-1] with idx == 1 on a string like "]:80", so tcp6_addr, tcp_addr,
// udp6_addr and udp_addr panic on it (a remote crash in any service validating
// such a field; this module answers false).
func pass(v *validator.Validate, tag string, val interface{}) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return v.Var(val, tag) == nil
}

func main() {
	var in []item
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	v := validator.New(validator.WithRequiredStructEnabled())
	out := make([]bool, len(in))
	for i, it := range in {
		raw, err := base64.StdEncoding.DecodeString(it.V)
		if err != nil {
			panic(err)
		}
		if it.Int {
			n, err := strconv.Atoi(string(raw))
			out[i] = err == nil && pass(v, it.Tag, n)
			continue
		}
		out[i] = pass(v, it.Tag, string(raw))
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
