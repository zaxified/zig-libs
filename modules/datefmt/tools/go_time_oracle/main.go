// SPDX-License-Identifier: MIT

// Differential oracle for datefmt's Go-parity surface: Go's time.ParseDuration,
// Duration.String and the time.RFC1123Z layout (BSD-3-Clause, the module's
// declared reference), run as black boxes through their public API. The
// inputs are OURS -- crafted tables and seeded random cases below; Go only
// answers them, and the answers are written out as a Zig file that
// `src/go_oracle_test.zig` replays hermetically.
//
//	cd modules/datefmt/tools/go_time_oracle
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -out ../../src/go_time_vectors.zig
//	GOTOOLCHAIN=go1.26.0 GOPROXY=off go run . -check ../../src/go_time_vectors.zig
//
// Standard library only; needs `zig` on PATH (the output goes through
// `zig fmt --stdin`).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const seed = 0x6461746566 // "datef"

var rnd = rand.New(rand.NewPCG(seed, seed^0x5a5a))

// zigStr renders s as a Zig string literal: printable ASCII as is, every
// other byte as \xNN.
func zigStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ── durations ───────────────────────────────────────────────────────────────

var durationCrafted = []string{
	"", "0", "-0", "+0", "00", "0s", "-0s", "1", "1s", "+1s", "-1s", "1.s", ".5s", ".s", ".", "1..5s",
	"1.5", "s", "1ss", "1S", "1H", "1h2m3.5s", "1h-2m", "1h 2m", " 1s", "1s ", "1e3s", "1_000s", "0x10s",
	"300ms", "1.5µs", "1.5μs", "1.5us", "1ns", "1.9ns", "0.5ns", "1.0000000001s", "0.0000000001s",
	"0.3333333333h", "0.1s", "0.7h", "1.1111111111111111111111h", "123456789.123456789s",
	"2562047h47m16.854775807s", "2562047h47m16.854775808s", "-2562047h47m16.854775808s",
	"-2562047h47m16.854775809s", "9223372036854775807ns", "9223372036854775808ns",
	"-9223372036854775808ns", "-9223372036854775809ns", "92233720368547758070ns",
	"9223372036s", "9223372037s", "2562048h", "153722867m", "153722868m",
	"1.00000000000000000000000000000000001s", "0.99999999999999999999h", "3m0.000000001s",
	"5m5m5m", "1h1h", "1m1s1ms1us1ns", "1µ", "1µss", "1m1", "-", "+", "--1s", "+-1s",
	"\x00", "1s\x00", "1\xb5s", "1\xce\xbcs",
}

var units = []string{"ns", "us", "µs", "μs", "ms", "s", "m", "h"}

func randDecimal() string {
	var b strings.Builder
	switch rnd.IntN(4) {
	case 0:
		fmt.Fprintf(&b, "%d", rnd.IntN(10))
	case 1:
		fmt.Fprintf(&b, "%d", rnd.IntN(100000))
	case 2:
		fmt.Fprintf(&b, "%d.%0*d", rnd.IntN(1000), 1+rnd.IntN(12), rnd.Int64N(1000000000000))
	default:
		fmt.Fprintf(&b, ".%d", rnd.IntN(100000))
	}
	return b.String()
}

func randDuration() string {
	var b strings.Builder
	switch rnd.IntN(4) {
	case 0:
		b.WriteByte('-')
	case 1:
		b.WriteByte('+')
	}
	for n := 1 + rnd.IntN(4); n > 0; n-- {
		b.WriteString(randDecimal())
		b.WriteString(units[rnd.IntN(len(units))])
	}
	s := b.String()
	if rnd.IntN(5) == 0 { // a one-byte mutation
		i := rnd.IntN(len(s))
		s = s[:i] + string([]byte{"0123456789.smhunµ+- x"[rnd.IntN(21)]}) + s[i+1:]
	}
	return s
}

func emitDurations(b *bytes.Buffer) {
	b.WriteString("/// `time.ParseDuration(in)`: the nanoseconds, or null for an error.\n")
	b.WriteString("pub const parse_cases = [_]ParseCase{\n")
	seen := map[string]bool{}
	add := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		d, err := time.ParseDuration(s)
		if err != nil {
			fmt.Fprintf(b, ".{ .in = %s, .ns = null },\n", zigStr(s))
		} else {
			fmt.Fprintf(b, ".{ .in = %s, .ns = %d },\n", zigStr(s), int64(d))
		}
	}
	for _, s := range durationCrafted {
		add(s)
	}
	for i := 0; i < 600; i++ {
		add(randDuration())
	}
	b.WriteString("};\n\n")

	b.WriteString("/// `time.Duration(ns).String()`.\n")
	b.WriteString("pub const format_cases = [_]FormatCase{\n")
	special := []int64{0, 1, -1, 999, 1000, 1001, 999999, 1000000, 1500000, 999999999, 1000000000,
		59999999999, 60000000000, 3599999999999, 3600000000000, 3600000000001, math.MaxInt64, math.MinInt64,
		math.MinInt64 + 1, -1500, 90061001001001}
	for _, v := range special {
		fmt.Fprintf(b, ".{ .ns = %d, .out = %s },\n", v, zigStr(time.Duration(v).String()))
	}
	for i := 0; i < 400; i++ {
		// Spread over magnitudes: a random bit length, then a random value.
		v := rnd.Int64() >> rnd.IntN(63)
		if rnd.IntN(2) == 0 {
			v = -v
		}
		fmt.Fprintf(b, ".{ .ns = %d, .out = %s },\n", v, zigStr(time.Duration(v).String()))
	}
	b.WriteString("};\n\n")
}

// ── RFC 1123Z (the RFC 5322 date shape) ─────────────────────────────────────

func emitRfc1123z(b *bytes.Buffer) {
	b.WriteString("/// `time.Unix(unix, 0).In(FixedZone(off_min*60)).Format(time.RFC1123Z)`.\n")
	b.WriteString("pub const rfc1123z_cases = [_]Rfc1123zCase{\n")
	lo := time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	hi := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
	for i := 0; i < 300; i++ {
		var unix int64
		if i%3 == 0 {
			unix = rnd.Int64N(hi-lo+1) + lo
		} else { // 1900..2100, where mail dates are
			unix = rnd.Int64N(6311433600) - 2208988800
		}
		off := rnd.IntN(24*60*2-1) - (24*60 - 1)
		if i%4 == 0 {
			off = (rnd.IntN(27) - 12) * 60
		}
		t := time.Unix(unix, 0).In(time.FixedZone("", off*60))
		if t.Year() < 0 || t.Year() > 9999 {
			continue
		}
		fmt.Fprintf(b, ".{ .unix = %d, .off_min = %d, .out = %s },\n", unix, off, zigStr(t.Format(time.RFC1123Z)))
	}
	b.WriteString("};\n")
}

const header = `pub const ParseCase = struct { in: []const u8, ns: ?i64 };
pub const FormatCase = struct { ns: i64, out: []const u8 };
pub const Rfc1123zCase = struct { unix: i64, off_min: i32, out: []const u8 };

`

func main() {
	out := flag.String("out", "", "write the Zig vectors file here (default stdout)")
	check := flag.String("check", "", "re-take and compare with this committed file")
	flag.Parse()

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n")
	fmt.Fprintf(&b, "// GENERATED by modules/datefmt/tools/go_time_oracle (%s time) -- do not hand-edit.\n", runtime.Version())
	b.WriteString("//! Go time answers to this module's own cases, replayed by\n")
	b.WriteString("//! `go_oracle_test.zig`. Regenerate with the command in tools/go_time_oracle/main.go.\n\n")
	b.WriteString(header)
	emitDurations(&b)
	emitRfc1123z(&b)

	// The committed file is `zig fmt` clean (the repository's pre-commit
	// gate), so the re-take is formatted the same way before any comparison.
	fmtCmd := exec.Command("zig", "fmt", "--stdin")
	fmtCmd.Stdin = bytes.NewReader(b.Bytes())
	fmtCmd.Stderr = os.Stderr
	formatted, err := fmtCmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "zig fmt --stdin:", err)
		os.Exit(2)
	}

	switch {
	case *check != "":
		old, err := os.ReadFile(*check)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !bytes.Equal(old, formatted) {
			ol := strings.Split(string(old), "\n")
			nl := strings.Split(string(formatted), "\n")
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
		fmt.Fprintln(os.Stderr, "go time oracle: committed vectors match a fresh re-take")
	case *out != "":
		if err := os.WriteFile(*out, formatted, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		os.Stdout.Write(formatted)
	}
}
