// Verdicts of go-playground/validator v10.30.5 on the cross-field presence tags,
// for cross_oracle.py. Reads a JSON array of {"tag": ..., "f": ..., "sib": {...}} on
// stdin and writes a JSON array of booleans on stdout: true when the struct
//
//	struct { F string `validate:"<tag>"`; A, B, C string }
//
// with F = f and the siblings as given (an empty string is Go's zero value, which
// is what "absent" maps to) passes validate.Struct.
package main

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"

	"github.com/go-playground/validator/v10"
)

type item struct {
	Tag string            `json:"tag"`
	F   string            `json:"f"`
	Sib map[string]string `json:"sib"`
}

func pass(v *validator.Validate, it item) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	names := make([]string, 0, len(it.Sib))
	for n := range it.Sib {
		names = append(names, n)
	}
	sort.Strings(names)
	fields := []reflect.StructField{{
		Name: "F", Type: reflect.TypeOf(""), Tag: reflect.StructTag(`validate:"` + it.Tag + `"`),
	}}
	for _, n := range names {
		fields = append(fields, reflect.StructField{Name: n, Type: reflect.TypeOf("")})
	}
	val := reflect.New(reflect.StructOf(fields)).Elem()
	val.FieldByName("F").SetString(it.F)
	for _, n := range names {
		val.FieldByName(n).SetString(it.Sib[n])
	}
	return v.Struct(val.Interface()) == nil
}

func main() {
	var in []item
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	v := validator.New(validator.WithRequiredStructEnabled())
	out := make([]bool, len(in))
	for i, it := range in {
		out[i] = pass(v, it)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
