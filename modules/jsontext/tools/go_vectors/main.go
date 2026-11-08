// SPDX-License-Identifier: MIT

// Go side of the jsontext vectors (modules/jsontext/tools/gen_vectors.py writes
// the CPython half). Reads ../../src/testdata/vectors.txt, and for every input
// writes ../../src/testdata/vectors_go.txt: `input-hex TAB h` where h is Go's
// encoding/json output (SetEscapeHTML(true)) of the text CPython decoded the
// input to (the `d` column, unmarshalled), as hex. Standard library only.
//
// It also prints how Go agrees with the other columns (the numbers go into
// SPEC.md "Compared with"): Go with SetEscapeHTML(false) against the CPython
// `d` column, and Go's own handling of the raw ill-formed bytes.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

func marshal(s string, escapeHTML bool) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(escapeHTML)
	if err := e.Encode(s); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func main() {
	in, err := os.ReadFile("../../src/testdata/vectors.txt")
	if err != nil {
		panic(err)
	}
	var out strings.Builder
	out.WriteString("# input-hex h -- Go encoding/json SetEscapeHTML(true) of the CPython-decoded text; see tools/go_vectors/main.go; generated, do not edit\n")
	rows, plainDiff, plainDiffOther, rawDiff, rawInvalid, rawValidDiff, rawDiffNorm := 0, 0, 0, 0, 0, 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(in)), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		inHex := f[0]
		raw := []byte{}
		if inHex != "-" {
			raw, err = hex.DecodeString(inHex)
			if err != nil {
				panic(err)
			}
		}
		dBytes, err := hex.DecodeString(f[2])
		if err != nil {
			panic(err)
		}
		var text string
		if err := json.Unmarshal(dBytes, &text); err != nil {
			panic(fmt.Sprintf("Go cannot read CPython output for %s: %v", inHex, err))
		}
		h := marshal(text, true)
		fmt.Fprintf(&out, "%s\t%s\n", inHex, hex.EncodeToString([]byte(h)))
		rows++
		if p := marshal(text, false); p != string(dBytes) {
			plainDiff++
			if !strings.ContainsAny(text, "\u2028\u2029") {
				plainDiffOther++
			}
		}
		g := marshal(string(raw), false)
		if utf8.Valid(raw) {
			if g != marshal(text, false) {
				rawValidDiff++
			}
		} else {
			rawInvalid++
			if g != string(dBytes) {
				rawDiff++
			}
			// Go writes the replacement as the ASCII escape \ufffd, not the raw character.
			if strings.ReplaceAll(g, "\\ufffd", "\uFFFD") != string(dBytes) {
				rawDiffNorm++
			}
		}
	}
	if err := os.WriteFile("../../src/testdata/vectors_go.txt", []byte(out.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("rows %d\n", rows)
	fmt.Printf("Go(escapeHTML=false) differs from CPython d on %d rows (%d without U+2028/2029)\n", plainDiff, plainDiffOther)
	fmt.Printf("invalid-UTF-8 inputs %d; Go output differs from CPython/maximal subpart on %d, and still on %d after reading Go's \\ufffd as the raw character (per-byte vs subpart)\n", rawInvalid, rawDiff, rawDiffNorm)
	fmt.Printf("valid inputs where Go(raw) != Go(decoded text): %d\n", rawValidDiff)
}
