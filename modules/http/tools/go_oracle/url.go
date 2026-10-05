// SPDX-License-Identifier: MIT

// Area url: query strings (url.ParseQuery), query components
// (url.QueryUnescape) and paths (url.PathUnescape).
package main

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"
)

var queryInputs = []string{
	"", "a=1", "a=1&b=2", "a=1&a=2", "a", "a=", "=1", "=", "&&", "a=1&&b=2", "a=1&", "&a=1",
	"a+b=c+d", "a%20b=c%2Bd", "a=b=c", "a==", "k%5F=1", "a=+", "a=%2B", "a=%20+",
	"a=%zz", "a=%2", "a=%", "%zz=1&b=2", "a=1&b=%zz&c=3", "%=1", "a=%%41", "a=%4%31",
	"a=%41%", "a=%u0041", "a=1;b=2", "a=1%3Bb=2", ";", "a;b=1",
	"a=%00", "a=%C4%8D", "a=%c4%8d", "a=%E2%82", "a=b c", "a=\x01", "a=\xc4\x8d",
	"a=1&a=2&b=3&a=4", "b=1&a=2", "a[]=1&a[]=2", "a=%2526",
}

var componentInputs = []string{
	"", "abc", "a+b", "a%20b", "a%2Bb", "%zz", "%2", "%", "%%", "%%41", "%4%31", "%41%",
	"%u0041", "%00", "%C4%8D", "%c4%8d", "%E2%82", "a b", "\x01", "\xc4\x8d", "%2F", "%2526",
	"+%2B+", ";", "%3B",
}

var pathInputs = []string{
	"", "/", "/a/b", "/a%20b", "/a+b", "/a%2Fb", "/a%2fb", "/a%00", "/a%zz", "/a%2", "/%",
	"/%C4%8D", "/a%25b", "/a%252F", "/a%3Fb", "/a%5Cb", "/..%2F", "/%2e%2e/", "/a%2", "/%41%42",
	"/a b", "/\xc4\x8d", "/%%", "/a;b", "/%3B",
}

type pair struct{ k, v string }

func emitURL(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const QueryCase = struct {\n    query: []const u8,\n")
	fmt.Fprintf(b, "    /// url.ParseQuery returned an error (it keeps the pairs it could decode).\n    err: bool,\n")
	fmt.Fprintf(b, "    /// Decoded pairs, keys sorted, each key's values in query order.\n    pairs: []const [2][]const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's url.ParseQuery.\npub const query = [_]QueryCase{\n")
	for _, q := range queryInputs {
		m, err := url.ParseQuery(q)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var ps []pair
		for _, k := range keys {
			for _, v := range m[k] {
				ps = append(ps, pair{k, v})
			}
		}
		var items []string
		for _, p := range ps {
			items = append(items, fmt.Sprintf(".{ %s, %s }", zigStr(p.k), zigStr(p.v)))
		}
		fmt.Fprintf(b, "    .{ .query = %s, .err = %t, .pairs = %s },\n", zigStr(q), err != nil, zigList(items))
	}
	fmt.Fprintf(b, "};\n\n")

	fmt.Fprintf(b, "pub const UnescapeCase = struct { input: []const u8, out: ?[]const u8 };\n\n")
	emitUnescape(b, "component", "url.QueryUnescape", componentInputs, url.QueryUnescape)
	emitUnescape(b, "path", "url.PathUnescape", pathInputs, url.PathUnescape)
}

func emitUnescape(b *bytes.Buffer, name, what string, inputs []string, f func(string) (string, error)) {
	fmt.Fprintf(b, "/// Go's %s; out = null when it returned an error.\n", what)
	fmt.Fprintf(b, "pub const %s = [_]UnescapeCase{\n", name)
	for _, in := range inputs {
		out, err := f(in)
		var o *string
		if err == nil {
			o = &out
		}
		fmt.Fprintf(b, "    .{ .input = %s, .out = %s },\n", zigStr(in), zigOptStr(o))
	}
	fmt.Fprintf(b, "};\n\n")
}
