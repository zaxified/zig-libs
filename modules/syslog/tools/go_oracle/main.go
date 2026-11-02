// SPDX-License-Identifier: MIT

// Differential oracle for the parser of modules/syslog: leodido/go-syslog v4.6.0
// (MIT; the Ragel machine influxdata/go-syslog moved to) as an independent RFC
// 5424 parser. The inputs are OURS: the RFC's examples, the grammar's edges and
// seeded damage to well-formed lines. Go parses each one in strict mode, and the
// verdict and fields are written out as a Zig file the module's tests replay with
// no Go:
//
//	cd modules/syslog/tools/go_oracle
//	GOFLAGS=-mod=mod GOPROXY=off go run . -out ../../src/parse_oracle_vectors.zig
//
// A line where the two parsers disagree on purpose carries the name of a rule in
// `divergences` below, with what our parser does; a disagreement with no rule
// fails the replay.
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/leodido/go-syslog/v4/rfc5424"
)

type rule struct {
	name, why string
	// Matches the lines the rule covers, among those go-syslog refused.
	match func(string) bool
}

var sdID = regexp.MustCompile(`(?:^| |\])\[([^ \]]+)`)

func repeatedID(l string) bool {
	seen := map[string]bool{}
	for _, m := range sdID.FindAllStringSubmatch(l, -1) {
		if seen[m[1]] {
			return true
		}
		seen[m[1]] = true
	}
	return false
}

// A backslash that does not start an escape: anywhere after the first `[`.
var badEscape = regexp.MustCompile(`\\[^"\\\]]`)

func invalidEscape(l string) bool {
	return strings.Contains(l, "[") && badEscape.MatchString(strings.ReplaceAll(l, `\\`, ""))
}

var divergences = []rule{
	{"repeated_sd_id", "RFC 5424 6.3.2 forbids a sender to repeat an SD-ID; go-syslog refuses the line, ours and rsyslogd read it and the iterator shows both", repeatedID},
	{"invalid_escape", "RFC 5424 6.3.3: a backslash before any other character MUST be treated as a regular backslash; go-syslog refuses the line", invalidEscape},
	{"value_not_utf8", "RFC 5424 6.3.3 says PARAM-VALUE is UTF-8; go-syslog refuses other bytes, ours passes them through as rsyslogd does and as our encoder sends them", func(l string) bool { return !utf8.ValidString(l) }},
}

var edges = []string{
	"",
	"<",
	"<>",
	"<>1 - - - - - -",
	"13>1 - - - - - -",
	"<13>",
	"<13>1",
	"<13>1 ",
	"<13>1 -",
	"<13>1 - ",
	"<13>1 - -",
	"<13>1 - - ",
	"<13>1 - - -",
	"<13>1 - - - ",
	"<13>1 - - - -",
	"<13>1 - - - - ",
	"<13>1 - - - - -",
	"<13>1 - - - - - ",
	"<13>1 - - - - - -",
	"<13>1 - - - - - - ",
	"<13>1 - - - - - -  ",
	"<13>1 - - - - - - x",
	"<13>1 - - - - - - x\n",
	"<13>1 - - - - - -\n",
	"<13>1 - - - - - -x",
	"<0>1 - - - - - -",
	"<191>1 - - - - - -",
	"<192>1 - - - - - -",
	"<999>1 - - - - - -",
	"<1000>1 - - - - - -",
	"<013>1 - - - - - -",
	"<00>1 - - - - - -",
	"<13>0 - - - - - -",
	"<13>01 - - - - - -",
	"<13>2 - - - - - -",
	"<13>99 - - - - - -",
	"<13>999 - - - - - -",
	"<13>1000 - - - - - -",
	// timestamps
	"<13>1 2003-10-11T22:14:15Z - - - - -",
	"<13>1 2003-10-11T22:14:15.0Z - - - - -",
	"<13>1 2003-10-11T22:14:15.003Z - - - - -",
	"<13>1 2003-10-11T22:14:15.000003Z - - - - -",
	"<13>1 2003-10-11T22:14:15.1234567Z - - - - -",
	"<13>1 2003-10-11T22:14:15.Z - - - - -",
	"<13>1 2003-10-11T22:14:15+00:00 - - - - -",
	"<13>1 2003-10-11T22:14:15-07:00 - - - - -",
	"<13>1 2003-10-11T22:14:15+23:59 - - - - -",
	"<13>1 2003-10-11T22:14:15+24:00 - - - - -",
	"<13>1 2003-10-11T22:14:15+01:60 - - - - -",
	"<13>1 2003-10-11T22:14:15 - - - - -",
	"<13>1 2003-10-11t22:14:15Z - - - - -",
	"<13>1 2003-10-11T22:14:15z - - - - -",
	"<13>1 2003-10-11 22:14:15Z - - - - -",
	"<13>1 2003-13-11T22:14:15Z - - - - -",
	"<13>1 2003-00-11T22:14:15Z - - - - -",
	"<13>1 2003-10-00T22:14:15Z - - - - -",
	"<13>1 2003-10-32T22:14:15Z - - - - -",
	"<13>1 2003-02-29T22:14:15Z - - - - -",
	"<13>1 2004-02-29T22:14:15Z - - - - -",
	"<13>1 2000-02-29T00:00:00Z - - - - -",
	"<13>1 1900-02-29T00:00:00Z - - - - -",
	"<13>1 2003-04-31T22:14:15Z - - - - -",
	"<13>1 2003-10-11T24:14:15Z - - - - -",
	"<13>1 2003-10-11T22:60:15Z - - - - -",
	"<13>1 2003-10-11T22:14:60Z - - - - -",
	"<13>1 0000-01-01T00:00:00Z - - - - -",
	"<13>1 9999-12-31T23:59:59.999999Z - - - - -",
	"<13>1 1969-12-31T23:59:59Z - - - - -",
	"<13>1 -x - - - - -",
	"<13>1 03-10-11T22:14:15Z - - - - -",
	// header fields
	"<13>1 -  - - - -",
	"<13>1 - h\x7f - - - -",
	"<13>1 - h\x01 - - - -",
	"<13>1 - \xc3\xa9 - - - -",
	"<13>1 - -- -- -- -- -",
	"<13>1 - " + strings.Repeat("h", 255) + " - - - -",
	"<13>1 - " + strings.Repeat("h", 256) + " - - - -",
	"<13>1 - - " + strings.Repeat("a", 48) + " - - -",
	"<13>1 - - " + strings.Repeat("a", 49) + " - - -",
	"<13>1 - - - " + strings.Repeat("p", 128) + " - -",
	"<13>1 - - - " + strings.Repeat("p", 129) + " - -",
	"<13>1 - - - - " + strings.Repeat("m", 32) + " -",
	"<13>1 - - - - " + strings.Repeat("m", 33) + " -",
	// structured data
	"<13>1 - - - - - x",
	"<13>1 - - - - - [",
	"<13>1 - - - - - ]",
	"<13>1 - - - - - []",
	"<13>1 - - - - - [id]",
	"<13>1 - - - - - [id]x",
	"<13>1 - - - - - [id] x",
	"<13>1 - - - - - [id][id2]",
	"<13>1 - - - - - [id] [id2]",
	"<13>1 - - - - - [id][id2] m",
	"<13>1 - - - - - [id",
	"<13>1 - - - - - [id ]",
	"<13>1 - - - - - [id a]",
	"<13>1 - - - - - [id a=]",
	"<13>1 - - - - - [id a=b]",
	"<13>1 - - - - - [id a=\"b]",
	"<13>1 - - - - - [id a=\"b\"]",
	"<13>1 - - - - - [id a=\"b\" ]",
	"<13>1 - - - - - [id a=\"b\"  c=\"d\"]",
	"<13>1 - - - - - [id a=\"b\" c=\"d\"]",
	"<13>1 - - - - - [id a=\"\"]",
	"<13>1 - - - - - [id a=\"b]\"]",
	"<13>1 - - - - - [id a=\"\\]\"]",
	"<13>1 - - - - - [id a=\"\\\"\"]",
	"<13>1 - - - - - [id a=\"\\\\\"]",
	"<13>1 - - - - - [id a=\"\\q\"]",
	"<13>1 - - - - - [id a=\"\\",
	"<13>1 - - - - - [id=x a=\"b\"]",
	"<13>1 - - - - - [i\"d a=\"b\"]",
	"<13>1 - - - - - [id a]b=\"c\"]",
	"<13>1 - - - - - [id a=\"\xc3\xa9\"]",
	"<13>1 - - - - - [id a=\"\xff\"]",
	"<13>1 - - - - - [id a=\"\x00\"]",
	"<13>1 - - - - - [id a=\"\n\"]",
	"<13>1 - - - - - [" + strings.Repeat("a", 32) + "]",
	"<13>1 - - - - - [" + strings.Repeat("a", 33) + "]",
	"<13>1 - - - - - [id " + strings.Repeat("a", 32) + "=\"v\"]",
	"<13>1 - - - - - [id " + strings.Repeat("a", 33) + "=\"v\"]",
	"<13>1 - - - - - [id a=\"1\" a=\"2\"]",
	"<13>1 - - - - - [id a=\"1\"][id b=\"2\"]",
	// MSG
	"<13>1 - - - - - - \xef\xbb\xbfhello",
	"<13>1 - - - - - - \xef\xbb\xbf",
	"<13>1 - - - - - - \xef\xbb\xbf\xc3\xa9",
	"<13>1 - - - - - - \xef\xbb\xbf\xff",
	"<13>1 - - - - - - \xff\xfe",
	"<13>1 - - - - - - \x00",
	"<13>1 - - - - - - a\nb",
	// RFC 5424 §6.5
	"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xef\xbb\xbf'su root' failed for lonvick on /dev/pts/8",
	"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
	"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] \xef\xbb\xbfAn application event log entry...",
	"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]",
}

var damageAlphabet = []byte("\x00\x01\n\r\t \"\\]=[<>-:\x7f\x80\xc3\xa9\xff0a")

func damaged(r *rand.Rand, base string) string {
	b := []byte(base)
	for i := r.IntN(3) + 1; i > 0 && len(b) > 0; i-- {
		at := r.IntN(len(b))
		switch r.IntN(4) {
		case 0:
			b[at] = damageAlphabet[r.IntN(len(damageAlphabet))]
		case 1:
			b[at] = byte(r.IntN(256))
		case 2:
			b = append(b[:at], b[at+1:]...)
		default:
			b = append(b[:at], append([]byte{damageAlphabet[r.IntN(len(damageAlphabet))]}, b[at:]...)...)
		}
	}
	if r.IntN(5) == 0 && len(b) > 0 {
		b = b[:r.IntN(len(b))+1]
	}
	return string(b)
}

func zigStr(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func optField(sb *strings.Builder, name string, v *string) {
	if v != nil {
		fmt.Fprintf(sb, ", .has_%s = true, .%s = %s", name, name, zigStr(*v))
	}
}

func main() {
	out := flag.String("out", "../../src/parse_oracle_vectors.zig", "the Zig file to write")
	flag.Parse()

	lines := append([]string{}, edges...)
	r := rand.New(rand.NewPCG(5424, 6587))
	seen := map[string]bool{}
	for _, l := range edges {
		seen[l] = true
	}
	bases := []string{}
	for _, l := range edges {
		if len(l) < 200 {
			if _, err := rfc5424.NewParser().Parse([]byte(l)); err == nil {
				bases = append(bases, l)
			}
		}
	}
	for n := 0; n < 1500; {
		l := damaged(r, bases[r.IntN(len(bases))])
		if seen[l] {
			continue
		}
		seen[l] = true
		lines = append(lines, l)
		n++
	}

	p := rfc5424.NewParser()
	var sb strings.Builder
	sb.WriteString(`// SPDX-License-Identifier: MIT
// GENERATED by modules/syslog/tools/go_oracle (leodido/go-syslog v4.6.0, strict mode) -- do not hand-edit.
//! RFC 5424 lines, and what an independent parser made of each: replayed by
//! ` + "`parse_oracle_test.zig`" + `. Regenerate: see tools/README.md.

pub const Case = struct {
    line: []const u8,
    accepted: bool,
    /// go-syslog refused it under this rule, which ours lacks (` + "`divergences`" + `).
    divergence: []const u8 = "",
    pri: u8 = 0,
    version: u16 = 0,
    has_time: bool = false,
    unix_us: i64 = 0,
    has_hostname: bool = false,
    hostname: []const u8 = "",
    has_app_name: bool = false,
    app_name: []const u8 = "",
    has_procid: bool = false,
    procid: []const u8 = "",
    has_msgid: bool = false,
    msgid: []const u8 = "",
    msg: []const u8 = "",
    /// SD-ID, PARAM-NAME, value; go-syslog keeps them in maps, so sorted, and a
    /// repeated name once.
    sd: []const [3][]const u8 = &.{},
};

pub const Divergence = struct { name: []const u8, why: []const u8 };

pub const divergences = [_]Divergence{
`)
	for _, d := range divergences {
		fmt.Fprintf(&sb, "    .{ .name = %s, .why = %s },\n", zigStr(d.name), zigStr(d.why))
	}
	sb.WriteString("};\n\npub const cases = [_]Case{\n")
	acc := 0
	for _, l := range lines {
		msg, err := p.Parse([]byte(l))
		sm, _ := msg.(*rfc5424.SyslogMessage)
		ok := err == nil && sm != nil && sm.Valid()
		fmt.Fprintf(&sb, "    .{ .line = %s, .accepted = %v", zigStr(l), ok)
		if !ok {
			for _, d := range divergences {
				if d.match(l) {
					fmt.Fprintf(&sb, `, .divergence = %s`, zigStr(d.name))
					break
				}
			}
		}
		if ok {
			acc++
			pri := uint8(0)
			if sm.Priority != nil {
				pri = *sm.Priority
			}
			fmt.Fprintf(&sb, ", .pri = %d, .version = %d", pri, sm.Version)
			if sm.Timestamp != nil {
				fmt.Fprintf(&sb, ", .has_time = true, .unix_us = %d", sm.Timestamp.UnixMicro())
			}
			optField(&sb, "hostname", sm.Hostname)
			optField(&sb, "app_name", sm.Appname)
			optField(&sb, "procid", sm.ProcID)
			optField(&sb, "msgid", sm.MsgID)
			if sm.Message != nil {
				fmt.Fprintf(&sb, ", .msg = %s", zigStr(*sm.Message))
			}
			if sm.StructuredData != nil {
				var triples []string
				for id, ps := range *sm.StructuredData {
					for n, v := range ps {
						triples = append(triples, fmt.Sprintf(".{ %s, %s, %s }", zigStr(id), zigStr(n), zigStr(v)))
					}
				}
				sort.Strings(triples)
				if len(triples) > 0 {
					fmt.Fprintf(&sb, ", .sd = &.{ %s }", strings.Join(triples, ", "))
				}
			}
		}
		sb.WriteString(" },\n")
	}
	sb.WriteString("};\n")
	if err := os.WriteFile(*out, []byte(sb.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%d lines, %d accepted\n", len(lines), acc)
}
