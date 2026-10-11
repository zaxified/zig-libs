// SPDX-License-Identifier: MIT

// Go side of `zig build bench-validate` (modules/validate/tools/bench.zig):
// times go-playground/validator v10.30.5 (pinned by go.mod/go.sum) over the
// JSON bodies the Zig program writes into the directory given as the first
// argument, for the one workload named by the second, through its public API
// only. Prints one line: name, ns/op, result count (tab-separated). One op =
// every body of the workload once: json.Unmarshal into a struct, then (unless
// the workload is a decode_* one) validate.Struct on it -- bytes in, validated
// typed struct out, the unit of work `parseIntoLeaky` does on the Zig side.
//
//	decode_small    json.Unmarshal only, the 4-field signup body (info only)
//	valid_small     ... + validate.Struct, every body valid
//	decode_nested   json.Unmarshal only, an order with 10 line items (info only)
//	valid_nested    ... + validate.Struct with `dive`, every body valid
//	decode_invalid  json.Unmarshal only, the signup body with 3 bad fields (info only)
//	invalid         ... + validate.Struct, 3 failing fields per body
//	decode_formats  json.Unmarshal only, email + uuid4 + http_url (info only)
//	formats         ... + validate.Struct
//
// count = the sum over bodies of 1 for a body that decoded (and validated)
// without error, else the number of failing fields (decode_*: 1 per body that
// decoded). The validator is created once, outside the timed loop -- that is
// how it is used, and it caches struct metadata after the first call.
//
// Timing matches the Zig side: double the batch until one batch takes over
// 100 ms, then keep the best of five.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

var sink int

func timeIt(f func() int) (float64, int) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	count := 0
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

type Signup struct {
	Name     string `json:"name" validate:"required,min=2,max=64"`
	Email    string `json:"email" validate:"required,email"`
	Age      int32  `json:"age" validate:"gte=0,lte=150"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

type Owner struct {
	Name  string `json:"name" validate:"required,min=2,max=64"`
	Email string `json:"email" validate:"required,email"`
}

type Item struct {
	Sku   string  `json:"sku" validate:"required,min=3,max=20"`
	Qty   uint16  `json:"qty" validate:"gte=1,lte=1000"`
	Price float64 `json:"price" validate:"gte=0"`
}

type Order struct {
	ID    string `json:"id" validate:"required,min=1"`
	Owner Owner  `json:"owner" validate:"required"`
	Items []Item `json:"items" validate:"required,min=1,max=100,dive"`
}

type Links struct {
	Email string `json:"email" validate:"required,email"`
	ID    string `json:"id" validate:"required,uuid4"`
	URL   string `json:"url" validate:"required,http_url"`
}

// run decodes every body into a fresh T and, when check is set, validates it.
func run[T any](bodies [][]byte, check bool, v *validator.Validate) int {
	sum := 0
	for _, b := range bodies {
		var t T
		if err := json.Unmarshal(b, &t); err != nil {
			panic(err)
		}
		if !check {
			sum++
			continue
		}
		if err := v.Struct(&t); err != nil {
			sum += len(err.(validator.ValidationErrors))
		} else {
			sum++
		}
	}
	return sum
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench <work dir> <workload>")
		os.Exit(2)
	}
	dir, name := os.Args[1], os.Args[2]
	check := !strings.HasPrefix(name, "decode_")
	// The bodies of a shape (small, nested, invalid, formats) are shared by
	// its decode_* and validating workloads.
	shape := strings.TrimPrefix(strings.TrimPrefix(name, "decode_"), "valid_")
	b, err := os.ReadFile(filepath.Join(dir, shape+".json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var bodies [][]byte
	for _, l := range strings.Split(strings.TrimRight(string(b), "\x00"), "\x00") {
		bodies = append(bodies, []byte(l))
	}

	v := validator.New(validator.WithRequiredStructEnabled())
	var f func() int
	switch shape {
	case "small", "invalid":
		f = func() int { return run[Signup](bodies, check, v) }
	case "nested":
		f = func() int { return run[Order](bodies, check, v) }
	case "formats":
		f = func() int { return run[Links](bodies, check, v) }
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	f() // fill the validator's struct cache before the timed loop

	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
