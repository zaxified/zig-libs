// Prints the code-point ranges of Go's unicode.L and unicode.N (Go 1.26.0,
// Unicode 15.0.0) as `lo hi` lines, for gen_format_tables.py. go-playground's
// alphaunicode is `^[\p{L}]+$` and alphanumunicode `^[\p{L}\p{N}]+$`.
package main

import (
	"fmt"
	"unicode"
)

func dump(name string, t *unicode.RangeTable) {
	fmt.Println("#", name)
	lo := rune(-1)
	for r := rune(0); r <= unicode.MaxRune+1; r++ {
		in := r <= unicode.MaxRune && unicode.Is(t, r)
		if in && lo < 0 {
			lo = r
		}
		if !in && lo >= 0 {
			fmt.Printf("%d %d\n", lo, r-1)
			lo = -1
		}
	}
}

func main() {
	dump("L", unicode.L)
	dump("N", unicode.N)
}
