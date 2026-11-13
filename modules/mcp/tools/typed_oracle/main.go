// SPDX-License-Identifier: MIT

// Differential oracle for `schemaOf` (src/typed.zig): github.com/google/jsonschema-go
// v0.4.3, the library behind the Go MCP SDK's typed `AddTool[In, Out]`, infers a
// schema from Go structs equivalent to the Zig ones in the test "schemaOf:
// verdicts agree with jsonschema-go". For each fixed instance it prints
// `<type>\t<valid|invalid>\t<instance>`; the Zig test replays the same table
// against `schemaOf` + `schema_check` and asserts the same verdicts. Also prints
// the inferred schema text per type (informational: the texts differ, e.g.
// Go marks slices nullable, the verdicts on well-formed instances must not).
//
//	cd tools/typed_oracle && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod go run .
package main

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

type Search struct {
	Query string   `json:"query"`
	Limit uint8    `json:"limit,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Exact bool     `json:"exact,omitempty"`
}

type Point struct {
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	Label *string `json:"label,omitempty"`
}

type Shape struct {
	Name   string  `json:"name"`
	Center Point   `json:"center"`
	Sides  []int32 `json:"sides,omitempty"`
}

type Triple struct {
	Values [3]int16 `json:"values"`
}

func run[T any](name string, instances []string) {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	text, _ := json.Marshal(s)
	fmt.Printf("# %s schema %s\n", name, text)
	r, err := s.Resolve(nil)
	if err != nil {
		panic(err)
	}
	for _, in := range instances {
		var v any
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			panic(err)
		}
		verdict := "valid"
		if err := r.Validate(v); err != nil {
			verdict = "invalid"
		}
		fmt.Printf("%s\t%s\t%s\n", name, verdict, in)
	}
}

func main() {
	run[Search]("Search", []string{
		`{"query":"a"}`,
		`{"query":"a","limit":255,"tags":["x","y"],"exact":true}`,
		`{"query":"a","limit":256}`,
		`{"query":"a","limit":-1}`,
		`{"query":"a","limit":1.5}`,
		`{"limit":3}`,
		`{"query":1}`,
		`{"query":"a","tags":[1]}`,
		`{"query":"a","extra":1}`,
		`{"query":"a","exact":"yes"}`,
		`[]`,
	})
	run[Shape]("Shape", []string{
		`{"name":"s","center":{"x":1,"y":2.5}}`,
		`{"name":"s","center":{"x":1,"y":2,"label":"c"},"sides":[1,2,3]}`,
		`{"name":"s"}`,
		`{"name":"s","center":{"x":1}}`,
		`{"name":"s","center":{"x":"1","y":2}}`,
		`{"name":"s","center":{"x":1,"y":2},"sides":[2147483648]}`,
		`{"name":"s","center":{"x":1,"y":2,"z":3}}`,
	})
	run[Triple]("Triple", []string{
		`{"values":[1,2,3]}`,
		`{"values":[1,2]}`,
		`{"values":[1,2,3,4]}`,
		`{"values":[1,2,32768]}`,
		`{"values":[1,2,-32768]}`,
		`{}`,
	})
}
