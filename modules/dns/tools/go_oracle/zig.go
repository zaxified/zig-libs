// SPDX-License-Identifier: MIT

// Zig literal rendering.
package main

import (
	"fmt"
	"strings"
)

// zigStr renders s as a Zig string literal: printable ASCII as is, \r \n \t
// by name, everything else as \xHH. Byte-exact, so a case can carry any byte.
func zigStr(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// zigList renders items as an anonymous-list literal the way `zig fmt` does.
func zigList(items []string) string {
	switch len(items) {
	case 0:
		return "&.{}"
	case 1:
		return "&.{" + items[0] + "}"
	}
	return "&.{ " + strings.Join(items, ", ") + " }"
}

// zigArchive renders data as runs of non-zero bytes; a zero gap shorter than
// 8 bytes stays inside its run, so a header is one or two runs, not dozens.
