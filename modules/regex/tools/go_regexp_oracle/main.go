// SPDX-License-Identifier: MIT

// Differential oracle for the regex module: Go's `regexp` (BSD-3-Clause, the
// module's declared reference — RE2 syntax and leftmost-first semantics),
// run as a black box through its public API. The patterns and inputs are
// OURS — crafted syntax cases and seeded random expressions below; Go only
// answers them, and the answers are written out as a Zig file that
// `src/go_oracle_test.zig` replays hermetically. No Go source was read.
//
//	cd modules/regex/tools/go_regexp_oracle
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -out ../../src/go_vectors.zig
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -check ../../src/go_vectors.zig
//
// Standard library only; needs `zig` on PATH (the output goes through
// `zig fmt --stdin`).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"regexp"
	"regexp/syntax"
	"runtime"
	"sort"
	"strings"
	"unicode"
)

const seed = 0x7265676578 // "regex"

var rnd = rand.New(rand.NewPCG(seed, seed^0x5a5a))

const (
	nRandom = 600
	nInputs = 14
)

// Syntax cases: the compile verdict, and for the valid ones matches over the
// fixed inputs below.
var crafted = []string{
	``, `a`, `abc`, `a|b|c`, `a|`, `|a`, `()`, `(|)`, `(?:)`, `a*`, `a+`, `a?`, `a*?`, `a+?`, `a??`,
	`a**`, `a*+`, `a+*`, `a??*`, `a{2}`, `a{2,}`, `a{2,3}`, `a{2}?`, `a{2}{3}`, `a{2}*`, `a{,3}`, `a{`, `a{1`,
	`a{1,`, `{`, `{1}`, `x{1001}`, `x{1000}`, `x{0}`, `x{0,0}`, `x{3,2}`, `*`, `+a`, `?`, `(*)`, `a|*`,
	`^*`, `$+`, `\b*`, `(?i)*`, `.`, `[a]`, `[]a]`, `[^]a]`, `[a-]`, `[-a]`, `[a-c-e]`, `[z-a]`, `[a`, `[]`,
	`[^]`, `[\d]`, `[\D]`, `[\w-z]`, `[a-\d]`, `[[:alpha:]]`, `[[:^alpha:]]`, `[[:foo:]]`, `[[:alpha:]`,
	`[[:]`, `[[]`, `[\]]`, `[\[]`, `[a&&b]`, `\d`, `\D`, `\s`, `\S`, `\w`, `\W`, `\b`, `\B`, `\A`, `\z`,
	`\Z`, `\a`, `\f`, `\t`, `\n`, `\r`, `\v`, `\0`, `\07`, `\012`, `\1`, `\8`, `\12`, `\x41`, `\x4`, `\x{41}`,
	`\x{}`, `\x{110000}`, `\x{10FFFF}`, `\xg1`, `\Q`, `\Qa.b`, `\Qa.b\E`, `\Q\E`, `\Qab\E*`, `\E`, `\C`, `\y`, `\_`, `\-`, `\ `, `\é`, `\`, `a\`, `(a`, `a)`, `)`, `(?:a`, `(?i)a`,
	`(?i:a)b`, `(?-i)a`, `(?i-s)a`, `(?)`, `(?-)`, `(?i-)`, `(?--i)`, `(?z)`, `(?P<n>a)`, `(?<n>a)`,
	`(?P<>a)`, `(?P<n-1>a)`, `(?P<n>a)(?P<n>b)`, `(?P=n)`, `(?P<n`, `(?#c)`, `(?=a)`, `(?!a)`, `(?<=a)`,
	`(?ims)a`, `(?U)a+`, `(?U)a+?`, `a(?i)b|c`, `(a)(b)(c)`, `((a)|(b))*`, `(a*)*`, `(a*)+`, `(a|b)*c`,
	`(?m)^a$`, `^a$`, `a$`, `\bab\b`, `é`, `[é]`, `[^é]`, `(?i)k`, `(?i)s`, `(?i)[k-l]`, `(?i)[^k]`,
	`\x{212a}`, `(?i)\x{212a}`, `x*y*`, `(x|xy)z`, `(xy|x)z`, `.*`, `.+`, `(?s).*`, "a\nb", "[\n]",
	`(((((a)))))`, `a{2,3}?b`, `(a+)+$`, `\.\*\+`,
	`(?i)\W`, `(?i)\w`, `(?i)\S`, `(?i)\D`, `(?i)[\W]`, `(?i)[^\w]`, `(?i)[^\W]`, `(?i)[\Wx]`, `(?i)[[:^alpha:]]`,
	`(?i)[[:^lower:]]`, `(?i)[[:lower:]]`, `(?i)[^k]`, `(?i)[^s]`, `(?i)[^a-z]`, `(?i)\x{17f}`, `(?i)[\x{17f}]`, `(?i)\x{212a}`,
	`(\b)*`, `(^)*`, `(\B)+`, `(?:$)*a`, `(?m)^b`, `(?m)^.`, `(?m)(^b|a$)`,
	// Nested counted repetitions multiply (Go: the product stays <= 1000).
	`(?:(?:a{0}){1000}){2}`, `(?:(?:a{0}){100}){10}`, `(?:(?:a{0}){100}){11}`, `(?:a{2}){500}`, `(?:a{2}){501}`,
	`(?:a{2,}){500}`, `(?:a{3,}){500}`, `(?:a{0,}){1000}`, `(?:a{0,5}){201}`, `(?:a{2}|b{600}){2}`, `(?:a{2}b{600}){1}`,
	`(?:(?:a){500})+`, `(?:(?:a?){10}){100}`, `(?:(?:a*){10}){101}`, `(?:(?:a{0}){1000}){0}`, `((a{2}){10}){51}`,
	`(?:(?:(?:a{0}){1000}){1000}){1000}`,
	// Flag groups are transparent to a repetition; control characters escape themselves.
	strings.Repeat("(?:", 260) + "a" + strings.Repeat(")", 260),
	// Unicode simple case folding: orbits of two, three (Ǆ ǅ ǆ) and four (θ ϑ Θ ϴ), classes over
	// runs, negation after folding, a class over all of Unicode, astral letters.
	`(?i)é`, `(?i)É`, `(?i)[á-ž]+`, `(?i)[A-ZÁ-Ž]+`, `(?i)ǅ`, `(?i)θ`, `(?i)ϴ`, `(?i)ß`, `(?i)ẞ`, `(?i)µ`, `(?i)Ω`,
	`(?i)[^é]`, `(?i)[^\x{0}-\x{60}]`, `(?i)[\x{0}-\x{10FFFF}]`, `(?i)[\x{100}-\x{17f}]+`, `(?i)[ⓐ-ⓩ]`, `(?i)𐐀`,
	`(?i)straße`, `(?i)[^a-zà-ž]`, `(?i)\x{1c5}+`, `(?i)[θ-ϑ]`, `(?i:č)Č`, `č(?i)Č`,
	`a(?i)*`, `a(?i)+b`, "\\\n", "\\\x01", "\\\x7f", `\x{+41}`, `\x{4_1}`, `\x+1`, `\x{000000041}`, `\x{0010FFFF}`, `\xG1`,
}

// Unicode classes: every name Go knows (categories, their aliases, scripts),
// each over the first and last code point of its class and a mixed sample;
// then the grammar around them — negation, folding, classes, bad names.
var unicodeSample = "aA1 _\u00a0\u00b2\u00bd\u01c5\u0301\u0378\u03a9\u0416\u05d0\u0663\u0905\u2028\u2029\u20ac\u2167\u3042\u4e2d\ue000\U0001f600\U000e0001\U0010ffff\xff"

var unicodeCrafted = []string{
	`\pL`, `\PL`, `\pN+`, `\p{^L}`, `\P{^L}`, `\p{Any}`, `\P{Any}`, `\p{^Any}`, `\p{any}`, `\p{greek}`, `\p{GREEK}`,
	`\p{letter}`, `\p{Is_Greek}`, `\p{IsGreek}`, `\p{L&}`, `\p{ Greek}`, `\p{Greek }`, `\p{}`, `\p{^}`, `\p`, `\P`,
	`\pLu`, `\p{Lu`, `\p{Lu}u`, `\pé`, `\p{`, `\p}`, `\p^L`, `\p{Script=Greek}`, `\p{sc=Greek}`, `\p{gc=L}`,
	`\p{cntrl}`, `\p{digit}`, `\p{punct}`, `\p{alpha}`, `\p{Cn}`, `\p{^Cn}`, `\p{C}`, `\p{LC}`, `\p{L_}`,
	`\p{Cased_Letter}`, `\p{Uppercase_Letter}`, `\p{uppercase_letter}`, `\p{Uppercase Letter}`, `\PN`, `\pZ`, `\p{Zs}+`,
	`[\p{Greek}\d]`, `[^\p{L}]`, `[\P{L}]`, `[^\P{L}]`, `[\p{L}\p{N}]+`, `[\p{^L}a]`, `[a-\pL]`, `[\pL-z]`,
	`(?i)\p{Lu}`, `(?i)\p{Ll}`, `(?i)\P{Lu}`, `(?i)\p{^Lu}`, `(?i)[\p{Lu}]`, `(?i)[^\p{Lu}]`, `(?i)\p{Lt}`, `(?i)\p{Greek}`,
	`(?i)\P{Ll}`, `(?i)[\P{Ll}]`, `(?i)\p{Latin}`, `(?i)\p{Cyrillic}+`, `(?i)[^\P{Lt}]`,
	`\pL\pN`, `(\p{Lu})(\p{Ll}+)`, `\p{Han}+|\p{Hiragana}+`, `^\p{L}*$`, `\b\p{L}+\b`,
	// Loose names (TR18, Go 1.25+), and the computed classes.
	`\pl`, `\p{ascii}`, `\p{ASCII}+`, `\P{ASCII}`, `(?i)\p{ASCII}`, `\p{Assigned}`, `\P{Assigned}`, `\p{^assigned}`, `[^\p{Assigned}]`,
	`\p{^ L}`, `\p{ ^L}`, `\p{L u}`, `\p{L-u}`, "\\p{L\tu}", `\p{L.u}`, `\p{__Lu__}`, `\p{-}`, `\p{_}`, `\p{ }`, `\p{^^L}`,
	`\p{uPPercase_lETTER}`, `\p{lowercaseletter}`, `\p{Zyyy}`, `\p{Common}`, `\p{common}`, `\p{Inherited}`, `\p{Unknown}`,
	`\p{ſcript}`, `\p{Latın}`, `\p{\x{212a}atakana}`, `\p{K}`, `\p{Greek_}`, `\p{_Greek}`, `\p{Han}+`,
	`\p{` + strings.Repeat("L", 60) + `}`, `\p{` + strings.Repeat("_", 60) + `L}`, `\p{L` + strings.Repeat(" ", 60) + `}`,
	`\p{L}\p{L}\p{L}\p{L}\p{L}\p{L}\p{L}\p{L}`, `\P{L}\P{L}\P{L}\P{L}\P{L}\P{L}\P{L}\P{L}`,
}

var unicodeInputs = []string{"", "a", "A", "aB", "Ab", "ǅ", "ǆ", "Ǆ", "Ω", "ω", "ϴ", "Ж", "ж", "ß", "ẞ", "k", "\u212a", "1", "٣", "Ⅷ", "ⅷ",
	" ", "\u00a0", "\u2028", "€", "😀", "\u0301", "中文", "あ", "\ue000", "\u0378", "\U000e0001", "\xff", "abc123", "Straße", "ΑΒΓ",
	unicodeSample}

func unicodeNames() []string {
	var ns []string
	for k := range unicode.Categories {
		ns = append(ns, k)
	}
	for k := range unicode.CategoryAliases {
		ns = append(ns, k)
	}
	for k := range unicode.Scripts {
		ns = append(ns, k)
	}
	sort.Strings(ns)
	return ns
}

// The first and last code point of a class, as inputs that sit on its edges.
func classEdges(name string) []string {
	t := unicode.Categories[name]
	if t == nil {
		t = unicode.Scripts[name]
	}
	if t == nil {
		t = unicode.Categories[unicode.CategoryAliases[name]]
	}
	var first, last rune = -1, -1
	for c := rune(0); c <= unicode.MaxRune; c++ {
		if unicode.Is(t, c) {
			if first < 0 {
				first = c
			}
			last = c
		}
	}
	out := []string{unicodeSample}
	for _, c := range []rune{first, first - 1, last, last + 1} {
		if c >= 0 && c <= unicode.MaxRune && (c < 0xd800 || c > 0xdfff) {
			out = append(out, string(c))
		}
	}
	return out
}

// POSIX ERE (CompilePOSIX): the crafted cases again, and cases of its own —
// what it refuses, line anchors, negated classes and newlines, a
// repetition of a repetition, and where leftmost-longest differs.
var posixCrafted = []string{
	`a*?`, `a+?`, `a??`, `a{2}?`, `a**`, `a*+`, `a{2}{3}`, `a{2}*`, `(a*)*`, `(a*)+`, `(a|ab)(c|bcd)(d*)`, `(a+|b+)*`,
	`(a|ab)(bc|c)`, `(ab|a)(bc|c)`, `a|ab|abc`, `(a*)(a*)`, `(a*?)(a*)`, `x*(a|ab)`, `(.*)(.*)`, `(a?)(ab)?b?`, `^$`,
	`^`, `$`, `^a`, `a$`, `^a$`, `[^a]`, `[^\n]`, `[^a\n]`, `[[:^alpha:]]`, `[^[:alpha:]]`, `[\x00-\x7f]`, `.`, `.*`,
	`(?i)a`, `(?:a)`, `(?P<n>a)`, `\d`, `\w`, `\s`, `\b`, `\A`, `\z`, `\Qa\E`, `\pL`, `[\d]`, `\x41`, `\n`, `\012`,
	`[a-c-]`, `[-a]`, `[a-b-]`, `[--a]`, `[!--]`, `[a\-b]`, `[a-b-c]`, `[a-c--]`, `[a-c-\-]`, `[^-a]`, `[a-c-[:alpha:]]`,
	`[[:alpha:]-z]`, `[a-c-]]`, `[ab-]`,
	`(a{500}){3}`, `((a{0}){100}){10}`, `a{1001}`, `(|a)`, `()`, `(a)|b`, `(a|b)*c`, `((a)|b)*`, `(a*)*b`,
}

func randPosixAtom(depth int) string {
	r := rnd.IntN(100)
	switch {
	case r < 35:
		return []string{"a", "b", "c", "A", "1", "é", " ", `\n`, `\.`}[rnd.IntN(9)]
	case r < 43:
		return "."
	case r < 58:
		return []string{`[ab]`, `[^a]`, `[a-c]`, `[^a-c\n]`, `[[:alpha:]]`, `[[:^digit:]]`, `[é1]`, `[a-]`, `[^É]`}[rnd.IntN(9)]
	case r < 64:
		return []string{`^`, `$`}[rnd.IntN(2)]
	case r < 85 && depth < 3:
		return "(" + randPosixAlt(depth+1) + ")"
	default:
		return "a"
	}
}

func randPosixConcat(depth int) string {
	var b strings.Builder
	for i, n := 0, 1+rnd.IntN(4); i < n; i++ {
		a := randPosixAtom(depth)
		// Repetitions may stack in POSIX: up to two operators.
		for k := 0; k < 2 && rnd.IntN(3) == 0; k++ {
			a += []string{"*", "+", "?", "{2}", "{1,}", "{0,2}"}[rnd.IntN(6)]
		}
		b.WriteString(a)
	}
	return b.String()
}

func randPosixAlt(depth int) string {
	s := randPosixConcat(depth)
	for rnd.IntN(4) == 0 {
		s += "|" + randPosixConcat(depth)
	}
	return s
}

// The alphabet random patterns and inputs share.
var inputRunes = []string{"a", "b", "c", "A", "B", "1", "2", " ", "\n", "é", "É", "č", "Č", "ß", "ẞ", "k", "s", "_", "-", "\xff", "Ω", "ж", "٣", "中"}

func randInput() string {
	var b strings.Builder
	for i, n := 0, rnd.IntN(9); i < n; i++ {
		b.WriteString(inputRunes[rnd.IntN(len(inputRunes))])
	}
	return b.String()
}

var fixedInputs = []string{"", "a", "ab", "abc", "aab", "ba", "a\nb", "xyz", "A", "k", "K", "\u212a", "s", "S", "\u017f", "é", "É", "123", "a b", "aaa", "\xff",
	"Ǆ", "ǅ", "ǆ", "θ", "ϑ", "Θ", "ϴ", "ß", "ẞ", "µ", "Μ", "μ", "Ω", "ω", "Ω", "ⓐ", "Ⓩ", "𐐨", "𐐀", "Čč", "STRASSE", "STRAẞE", "Ā", "ā"}

var groupCount int

func randAtom(depth int) string {
	r := rnd.IntN(100)
	switch {
	case r < 30:
		return []string{"a", "b", "c", "A", "1", "é", "k", " ", "-", `\n`, `\.`, "Č", "ß"}[rnd.IntN(13)]
	case r < 38:
		return "."
	case r < 52:
		return []string{`[ab]`, `[^a]`, `[a-c]`, `[^a-c\n]`, `\d`, `\w`, `\s`, `\D`, `\W`, `[[:alpha:]]`, `[[:^digit:]]`, `[é1]`, `[a-]`, `[á-ž]`, `[^É]`, `\pL`, `\p{Lu}`, `\P{Ll}`, `[\p{Greek}\d]`, `\p{Latin}`}[rnd.IntN(20)]
	case r < 58:
		return []string{`^`, `$`, `\b`, `\B`, `\A`, `\z`}[rnd.IntN(6)]
	case r < 64 && depth < 3:
		return "(?" + []string{"i", "m", "s", "U", "i-s", "-i"}[rnd.IntN(6)] + ")"
	case r < 85 && depth < 3:
		inner := randAlt(depth + 1)
		switch rnd.IntN(4) {
		case 0:
			return "(?:" + inner + ")"
		case 1:
			groupCount++
			return fmt.Sprintf("(?P<g%d>%s)", groupCount, inner)
		case 2:
			return "(?i:" + inner + ")"
		default:
			return "(" + inner + ")"
		}
	default:
		return "a"
	}
}

func randRepeat(atom string) string {
	if strings.HasPrefix(atom, "(?") && strings.HasSuffix(atom, ")") && !strings.Contains(atom, ":") && !strings.Contains(atom, "<") {
		return atom // a bare flag group takes no repetition
	}
	r := rnd.IntN(100)
	var op string
	switch {
	case r < 60:
		return atom
	case r < 70:
		op = "*"
	case r < 78:
		op = "+"
	case r < 85:
		op = "?"
	default:
		lo := rnd.IntN(3)
		switch rnd.IntN(3) {
		case 0:
			op = fmt.Sprintf("{%d}", lo)
		case 1:
			op = fmt.Sprintf("{%d,}", lo)
		default:
			op = fmt.Sprintf("{%d,%d}", lo, lo+rnd.IntN(3))
		}
	}
	if rnd.IntN(4) == 0 {
		op += "?"
	}
	return atom + op
}

func randConcat(depth int) string {
	var b strings.Builder
	for i, n := 0, 1+rnd.IntN(4); i < n; i++ {
		b.WriteString(randRepeat(randAtom(depth)))
	}
	return b.String()
}

func randAlt(depth int) string {
	s := randConcat(depth)
	for rnd.IntN(4) == 0 {
		s += "|" + randConcat(depth)
	}
	return s
}

func zstr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\x%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func ints(xs []int) string {
	var b strings.Builder
	b.WriteString("&.{")
	for i, x := range xs {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%d", x)
	}
	b.WriteString("}")
	return b.String()
}

func emitPattern(b *bytes.Buffer, pat string, inputs []string) {
	emitPatternIn(b, pat, inputs, false)
}

// The API on top of a search (Expand via ReplaceAllString, ReplaceAll*,
// Split, FindAllSubmatchIndex, LiteralPrefix) is asked of the crafted
// patterns and the first random ones; trnd picks the templates and the
// split limit, apart from the stream rnd draws patterns from.
var withAPI bool
var trnd = rand.New(rand.NewPCG(seed^0x74706c, seed))

var templates = []string{"<$0>", "[$1]", "${1}x", "$1x", "$$", "$", "${", "${}", "$g1", "${g1}", "$10", "$01", "$00", "${-1}",
	"$ $", "${1", "x", "$é", "$١", "$Ⅷ", "${18446744073709551617}", "${4294967297}", "$2$1", "${g2}.$3", "$_", "${g1}}", "$n", "${n}"}

func strs(xs []string) string {
	var b strings.Builder
	b.WriteString("&.{")
	for i, x := range xs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(zstr(x))
	}
	b.WriteString("}")
	return b.String()
}

// emitPatternIn answers a pattern in Perl syntax (leftmost-first, plus the
// same searches after Longest()) or in POSIX syntax (CompilePOSIX:
// leftmost-longest).
func emitPatternIn(b *bytes.Buffer, pat string, inputs []string, posix bool) {
	var re *regexp.Regexp
	var err error
	if posix {
		re, err = regexp.CompilePOSIX(pat)
	} else {
		re, err = regexp.Compile(pat)
	}
	if err != nil {
		// The verdict only; the error text is Go's own wording.
		fmt.Fprintf(b, ".{ .pattern = %s, .ok = false },\n", zstr(pat))
		return
	}
	full := fullMatcher(pat, posix)
	var longest *regexp.Regexp
	if !posix {
		longest = regexp.MustCompile(pat)
		longest.Longest()
	}
	fmt.Fprintf(b, ".{ .pattern = %s, .ok = true, .names = &.{", zstr(pat))
	for i, n := range re.SubexpNames() {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(zstr(n))
	}
	b.WriteString("}")
	if withAPI && !posix {
		prefix, complete := re.LiteralPrefix()
		fmt.Fprintf(b, ", .api = true, .prefix = %s, .complete = %v", zstr(prefix), complete)
	}
	b.WriteString(", .cases = &.{\n")
	for _, in := range inputs {
		sub := re.FindStringSubmatchIndex(in)
		var all []int
		for _, m := range re.FindAllStringIndex(in, -1) {
			all = append(all, m...)
		}
		fmt.Fprintf(b, ".{ .input = %s, .match = %v, .full = %v, .sub = %s, .all = %s",
			zstr(in), re.MatchString(in), full.MatchString(in), ints(sub), ints(all))
		if longest != nil {
			var lall []int
			for _, m := range longest.FindAllStringIndex(in, -1) {
				lall = append(lall, m...)
			}
			lsub := longest.FindStringSubmatchIndex(in)
			if !equalInts(lsub, sub) || !equalInts(lall, all) {
				fmt.Fprintf(b, ", .lsub = %s, .lall = %s", ints(lsub), ints(lall))
			} else {
				b.WriteString(", .same_longest = true")
			}
		}
		if withAPI && !posix {
			t1, t2 := trnd.IntN(len(templates)), trnd.IntN(len(templates))
			n := trnd.IntN(4) // 0..3
			var allsub []int
			for _, m := range re.FindAllStringSubmatchIndex(in, -1) {
				allsub = append(allsub, m...)
			}
			fmt.Fprintf(b, ", .repl = &.{ .{ .t = %d, .out = %s }, .{ .t = %d, .out = %s } }", t1, zstr(re.ReplaceAllString(in, templates[t1])), t2, zstr(re.ReplaceAllString(in, templates[t2])))
			fmt.Fprintf(b, ", .literal = %s, .func = %s", zstr(re.ReplaceAllLiteralString(in, "<$1>")),
				zstr(re.ReplaceAllStringFunc(in, func(m string) string { return "[" + m + "]" })))
			fmt.Fprintf(b, ", .split = %s, .split_n = %d, .split_some = %s, .allsub = %s", strs(re.Split(in, -1)), n, strs(re.Split(in, n)), ints(allsub))
		}
		b.WriteString(" },\n")
	}
	b.WriteString("} },\n")
}

const header = `/// Go's answers for one input: MatchString, a full match (` + "`\\\\A(?:re)\\\\z`" + `),
/// FindStringSubmatchIndex (empty: no match; -1: a group that took no part)
/// and FindAllStringIndex flattened. For a Perl-syntax pattern also the same
/// two searches after ` + "`Longest()`" + ` — ` + "`lsub`/`lall`" + `, or ` + "`same_longest`" + ` when they
/// equal ` + "`sub`/`all`" + `. A POSIX set's answers are CompilePOSIX's (leftmost-longest).
///
/// For an ` + "`api`" + ` pattern also: ` + "`repl`" + ` — ReplaceAllString with two of ` + "`templates`" + `;
/// ` + "`literal`" + ` — ReplaceAllLiteralString with ` + "`<$1>`" + `; ` + "`func`" + ` — ReplaceAllStringFunc
/// wrapping each match in ` + "`[ ]`" + `; ` + "`split`" + ` — Split(s, -1); ` + "`split_some`" + ` —
/// Split(s, split_n); ` + "`allsub`" + ` — FindAllStringSubmatchIndex flattened.
pub const Repl = struct { t: u8, out: []const u8 };
pub const Case = struct {
    input: []const u8,
    match: bool,
    full: bool,
    sub: []const i32,
    all: []const i32,
    lsub: []const i32 = &.{},
    lall: []const i32 = &.{},
    same_longest: bool = false,
    repl: []const Repl = &.{},
    literal: []const u8 = "",
    func: []const u8 = "",
    split: []const []const u8 = &.{},
    split_n: u8 = 0,
    split_some: []const []const u8 = &.{},
    allsub: []const i32 = &.{},
};
/// ` + "`ok`" + `: Go compiles the pattern. ` + "`names`" + `: SubexpNames.
/// ` + "`api`" + `: the cases carry the API answers below, and ` + "`prefix`/`complete`" + ` is LiteralPrefix.
pub const Pattern = struct { pattern: []const u8, ok: bool, names: []const []const u8 = &.{}, api: bool = false, prefix: []const u8 = "", complete: bool = false, cases: []const Case = &.{} };

`

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	check := flag.String("check", "", "re-take and compare with this committed file")
	flag.Parse()

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/regex/tools/go_regexp_oracle (%s regexp) -- do not hand-edit.\n", runtime.Version())
	b.WriteString("//! Go regexp's answers to this module's own patterns and inputs, replayed by\n")
	b.WriteString("//! `go_oracle_test.zig`. Regenerate with the command in tools/go_regexp_oracle/main.go.\n\n")
	b.WriteString(header)
	b.WriteString("pub const templates = [_][]const u8")
	b.WriteString(strs(templates)[2:])
	b.WriteString(";\n\n/// QuoteMeta of each ASCII byte (index = byte), then of a few strings.\npub const quote_meta = [_][2][]const u8{\n")
	var qs []string
	for c := 0; c < 128; c++ {
		qs = append(qs, string([]byte{byte(c)}))
	}
	qs = append(qs, "", "a.b*c", "é\u212a(x)", "\xff$", `\Q\E`)
	for _, q := range qs {
		fmt.Fprintf(&b, ".{ %s, %s },\n", zstr(q), zstr(regexp.QuoteMeta(q)))
	}
	b.WriteString("};\n\n")
	b.WriteString("pub const crafted = [_]Pattern{\n")
	withAPI = true
	for _, p := range crafted {
		emitPattern(&b, p, fixedInputs)
	}
	withAPI = false
	b.WriteString("};\n\npub const unicode_classes = [_]Pattern{\n")
	for _, p := range unicodeCrafted {
		emitPattern(&b, p, unicodeInputs)
	}
	for _, n := range unicodeNames() {
		emitPattern(&b, `\p{`+n+`}`, classEdges(n))
	}
	b.WriteString("};\n\npub const random = [_]Pattern{\n")
	for i := 0; i < nRandom; i++ {
		groupCount = 0
		withAPI = i < 200
		p := randAlt(0)
		var inputs []string
		for j := 0; j < nInputs; j++ {
			inputs = append(inputs, randInput())
		}
		emitPattern(&b, p, inputs)
	}
	withAPI = false
	b.WriteString("};\n\npub const posix = [_]Pattern{\n")
	for _, p := range append(append([]string{}, crafted...), posixCrafted...) {
		emitPatternIn(&b, p, fixedInputs, true)
	}
	b.WriteString("};\n\npub const posix_random = [_]Pattern{\n")
	for i := 0; i < nRandom/2; i++ {
		p := randPosixAlt(0)
		var inputs []string
		for j := 0; j < nInputs; j++ {
			inputs = append(inputs, randInput())
		}
		emitPatternIn(&b, p, inputs, true)
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
	b.Reset()
	b.Write(formatted)

	switch {
	case *check != "":
		old, err := os.ReadFile(*check)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !bytes.Equal(dropVersionLine(old), dropVersionLine(b.Bytes())) {
			ol := strings.Split(string(old), "\n")
			nl := strings.Split(b.String(), "\n")
			for i := 0; i < len(ol) || i < len(nl); i++ {
				var x, y string
				if i < len(ol) {
					x = ol[i]
				}
				if i < len(nl) {
					y = nl[i]
				}
				if x != y {
					fmt.Fprintf(os.Stderr, "DRIFT at line %d:\n  committed: %s\n  re-taken:  %s\n", i+1, x, y)
					break
				}
			}
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "regexp oracle: committed vectors match a fresh re-take")
	case *out != "":
		if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		os.Stdout.Write(b.Bytes())
	}
}

func equalInts(x, y []int) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
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

// fullMatcher is the pattern anchored at both ends of the text, built on its
// parsed form rather than by pasting text around it (`\Q` would swallow a
// pasted `)`).
func fullMatcher(pat string, posix bool) *regexp.Regexp {
	flags := syntax.Perl
	if posix {
		flags = syntax.POSIX
	}
	parsed, err := syntax.Parse(pat, flags)
	if err != nil {
		panic(err)
	}
	wrapped := &syntax.Regexp{Op: syntax.OpConcat, Flags: syntax.Perl, Sub: []*syntax.Regexp{
		{Op: syntax.OpBeginText}, parsed, {Op: syntax.OpEndText},
	}}
	return regexp.MustCompile(wrapped.String())
}
