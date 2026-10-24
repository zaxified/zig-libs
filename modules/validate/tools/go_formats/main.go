// Verdicts of go-playground/validator v10.30.5 on single strings, for
// format_oracle.py. Reads a JSON array of {"tag": ..., "v": ...} on stdin
// (v is base64 so any byte sequence survives JSON) and writes a JSON array of
// booleans on stdout, one per input: true when validate.Var(v, tag) passes.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/go-playground/validator/v10"
)

type item struct {
	Tag string `json:"tag"`
	V   string `json:"v"`
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
		out[i] = v.Var(string(raw), it.Tag) == nil
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
