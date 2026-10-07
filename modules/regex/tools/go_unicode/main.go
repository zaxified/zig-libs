// SPDX-License-Identifier: MIT

// Generates `src/unicode_tables.zig`: the Unicode general categories and
// scripts `\p{…}` names, as Go's `unicode` package (the module's reference,
// run as a black box through its public API: `unicode.Categories`,
// `unicode.CategoryAliases`, `unicode.Scripts`, `unicode.Is`) answers them for
// every code point. The data are Unicode's (UnicodeData.txt, Scripts.txt, as
// Go's tables carry them); the encoding and the code below are ours. No Go
// source was read.
//
// Only the base tables are stored — the two-letter categories and the
// scripts, each a list of code-point ranges, varint-encoded (gap from the end
// of the previous range, then length - 1). Every other name is a union of
// base tables, checked here against Go's own table for every code point.
//
//	cd modules/regex/tools/go_unicode
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -out ../../src/unicode_tables.zig
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -check ../../src/unicode_tables.zig
//
// Standard library only; needs `zig` on PATH (the output goes through
// `zig fmt --stdin`).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"unicode"
)

type rng struct{ lo, hi rune }

// ranges is t's membership over every code point, as maximal runs (a
// RangeTable's strided entries expanded).
func ranges(t *unicode.RangeTable) []rng {
	var out []rng
	for c := rune(0); c <= unicode.MaxRune; c++ {
		if !unicode.Is(t, c) {
			continue
		}
		if n := len(out); n > 0 && out[n-1].hi+1 == c {
			out[n-1].hi = c
		} else {
			out = append(out, rng{c, c})
		}
	}
	return out
}

func loose(n string) string {
	var b strings.Builder
	for _, c := range []byte(n) {
		switch {
		case c == ' ' || c == '_' || c == '-':
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func varint(b *[]byte, v uint32) {
	for v >= 0x80 {
		*b = append(*b, byte(v)|0x80)
		v >>= 7
	}
	*b = append(*b, byte(v))
}

type base struct {
	name   string
	rs     []rng
	offset int
	size   int
}

type name struct {
	name  string
	parts []int
	count int // ranges after merging the parts
}

// member is a bitmap of a set of ranges over all code points.
func member(rs []rng) []bool {
	m := make([]bool, unicode.MaxRune+1)
	for _, r := range rs {
		for c := r.lo; c <= r.hi; c++ {
			m[c] = true
		}
	}
	return m
}

func mergedCount(m []bool) int {
	n := 0
	for c := 0; c <= unicode.MaxRune; c++ {
		if m[c] && (c == 0 || !m[c-1]) {
			n++
		}
	}
	return n
}

func main() {
	out := flag.String("out", "", "write the Zig file here (default stdout)")
	check := flag.String("check", "", "re-take and compare with this committed file")
	flag.Parse()

	// Base tables: the two-letter categories, then the scripts.
	var bases []base
	var catNames, scriptNames []string
	for k := range unicode.Categories {
		if len(k) == 2 && k != "LC" {
			catNames = append(catNames, k)
		}
	}
	for k := range unicode.Scripts {
		scriptNames = append(scriptNames, k)
	}
	sort.Strings(catNames)
	sort.Strings(scriptNames)
	index := map[string]int{}
	for _, k := range catNames {
		index[k] = len(bases)
		bases = append(bases, base{name: k, rs: ranges(unicode.Categories[k])})
	}
	for _, k := range scriptNames {
		if _, dup := index[k]; dup {
			panic("script and category share a name: " + k)
		}
		index[k] = len(bases)
		bases = append(bases, base{name: k, rs: ranges(unicode.Scripts[k])})
	}
	if len(bases) > 256 {
		panic("more than 256 base tables: parts no longer fit a byte")
	}
	members := make([][]bool, len(bases))
	for i := range bases {
		members[i] = member(bases[i].rs)
	}

	// Every name: a union of base tables, verified against Go's table.
	resolve := func(n string, t *unicode.RangeTable) name {
		want := member(ranges(t))
		var parts []int
		if i, ok := index[n]; ok {
			parts = []int{i}
		} else {
			// The categories wholly inside it (only categories compose a category).
			for i := range catNames {
				inside := true
				for c := 0; c <= unicode.MaxRune && inside; c++ {
					if members[i][c] && !want[c] {
						inside = false
					}
				}
				if inside && len(bases[i].rs) > 0 {
					parts = append(parts, i)
				}
			}
		}
		got := make([]bool, unicode.MaxRune+1)
		for _, p := range parts {
			for c := 0; c <= unicode.MaxRune; c++ {
				if members[p][c] {
					got[c] = true
				}
			}
		}
		for c := 0; c <= unicode.MaxRune; c++ {
			if got[c] != want[c] {
				panic(fmt.Sprintf("%s: U+%04X union of base tables %v disagrees with Go", n, c, parts))
			}
		}
		return name{name: n, parts: parts, count: mergedCount(got)}
	}
	var names []name
	for k, t := range unicode.Categories {
		names = append(names, resolve(k, t))
	}
	for k, t := range unicode.Scripts {
		names = append(names, resolve(k, t))
	}
	for alias, target := range unicode.CategoryAliases {
		t, ok := unicode.Categories[target]
		if !ok {
			panic("alias of an unknown category: " + alias)
		}
		n := resolve(target, t)
		n.name = alias
		names = append(names, n)
	}
	// Keyed by the loose form (Unicode TR18 / UAX44-LM3, as Go 1.25+ documents
	// it): ASCII case ignored, spaces, underscores and hyphens dropped.
	for i := range names {
		names[i].name = loose(names[i].name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].name < names[j].name })
	kept := names[:0]
	for _, n := range names {
		if k := len(kept); k > 0 && kept[k-1].name == n.name {
			if fmt.Sprint(kept[k-1].parts) != fmt.Sprint(n.parts) {
				panic("two names share the loose form " + n.name + " with different tables")
			}
			continue
		}
		kept = append(kept, n)
	}
	names = kept
	for _, extra := range []string{"any", "ascii", "assigned"} {
		for _, n := range names {
			if n.name == extra {
				panic("a table is named like a built-in class: " + extra)
			}
		}
	}

	var data []byte
	maxCount := 0
	for i := range bases {
		bases[i].offset = len(data)
		prev := uint32(0)
		for _, r := range bases[i].rs {
			varint(&data, uint32(r.lo)-prev)
			varint(&data, uint32(r.hi-r.lo))
			prev = uint32(r.hi) + 1
		}
		bases[i].size = len(data) - bases[i].offset
	}
	for _, n := range names {
		maxCount = max(maxCount, n.count)
	}

	var b bytes.Buffer
	b.WriteString("// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/regex/tools/go_unicode (%s, Unicode %s) -- do not hand-edit.\n", runtime.Version(), unicode.Version)
	b.WriteString(`//! The Unicode classes ` + "`\\p{…}`" + ` names: the general categories, their long
//! aliases and the scripts (UnicodeData.txt, Scripts.txt, as Go's ` + "`unicode`" + `
//! package carries them). Only the two-letter categories and the scripts are
//! stored; every other name is a union of them, which the generator checked
//! against Go's own table for every code point. Regenerate with the command in
//! tools/go_unicode/main.go.

/// A stored table: ` + "`count`" + ` ranges in ` + "`data[offset..][0..size]`" + `, each two
/// LEB128 varints — the gap from the end of the previous range (from 0 for
/// the first), then the range's length minus one.
pub const Base = struct { offset: u32, size: u16, count: u16 };
/// A class name in its loose form (ASCII lower case, no spaces, underscores
/// or hyphens) and the stored tables whose union it is. ` + "`Any`" + `, ` + "`ASCII`" + ` and
/// ` + "`Assigned`" + ` are not here: they are computed.
pub const Name = struct { name: []const u8, parts: []const u8 };

`)
	fmt.Fprintf(&b, "pub const unicode_version = %q;\n", unicode.Version)
	fmt.Fprintf(&b, "/// The most ranges any one name expands to (merged).\npub const max_ranges = %d;\n\n", maxCount)
	b.WriteString("pub const data: []const u8 =\n")
	const perLine = 24
	for i := 0; i < len(data); i += perLine {
		end := min(i+perLine, len(data))
		var s strings.Builder
		for _, c := range data[i:end] {
			fmt.Fprintf(&s, "\\x%02x", c)
		}
		sep := " ++"
		if end == len(data) {
			sep = ";"
		}
		fmt.Fprintf(&b, "    \"%s\"%s\n", s.String(), sep)
	}
	b.WriteString("\npub const bases = [_]Base{\n")
	for _, x := range bases {
		fmt.Fprintf(&b, ".{ .offset = %d, .size = %d, .count = %d }, // %s\n", x.offset, x.size, len(x.rs), x.name)
	}
	fmt.Fprintf(&b, "};\n\n/// The table of unassigned code points (`Assigned` is its complement).\npub const cn: u8 = %d;\n", index["Cn"])
	b.WriteString("\n/// Sorted by loose name (byte order).\npub const names = [_]Name{\n")
	for _, n := range names {
		var p strings.Builder
		for _, i := range n.parts {
			fmt.Fprintf(&p, "\\x%02x", i)
		}
		fmt.Fprintf(&b, ".{ .name = %q, .parts = \"%s\" },\n", n.name, p.String())
	}
	b.WriteString("};\n")

	fmtCmd := exec.Command("zig", "fmt", "--stdin")
	fmtCmd.Stdin = bytes.NewReader(b.Bytes())
	fmtCmd.Stderr = os.Stderr
	formatted, err := fmtCmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "zig fmt --stdin:", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "unicode: %d base tables, %d names, %d bytes of ranges, at most %d ranges per name\n", len(bases), len(names), len(data), maxCount)

	switch {
	case *check != "":
		old, err := os.ReadFile(*check)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !bytes.Equal(dropVersionLine(old), dropVersionLine(formatted)) {
			fmt.Fprintln(os.Stderr, "unicode: DRIFT — committed tables differ from a fresh re-take")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "unicode: committed tables match a fresh re-take")
	case *out != "":
		if err := os.WriteFile(*out, formatted, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		os.Stdout.Write(formatted)
	}
}

func dropVersionLine(b []byte) []byte {
	var keep [][]byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		if !bytes.HasPrefix(l, []byte("// GENERATED ")) {
			keep = append(keep, l)
		}
	}
	return bytes.Join(keep, []byte("\n"))
}
