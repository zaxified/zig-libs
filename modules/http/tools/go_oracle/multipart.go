// SPDX-License-Identifier: MIT

// Area multipart: multipart/form-data bodies through mime/multipart's
// Reader (NextRawPart: no transfer-encoding decoding, as here). Recorded per
// part: the Content-Disposition name and filename as mime.ParseMediaType
// reads them, the Content-Type, and the body; then whether the reader ended
// in an error.
package main

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
)

const mpBoundary = "XyZ"

type mpCase struct{ id, body string }

func fd(name string) string { return "Content-Disposition: form-data; name=\"" + name + "\"" }

var mpCases = []mpCase{
	{"one-field", "--XyZ\r\n" + fd("a") + "\r\n\r\nhello\r\n--XyZ--\r\n"},
	{"two-parts-file", "--XyZ\r\n" + fd("a") + "\r\n\r\n1\r\n--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nfile body\r\n--XyZ--\r\n"},
	{"three-parts", "--XyZ\r\n" + fd("a") + "\r\n\r\n1\r\n--XyZ\r\n" + fd("b") + "\r\n\r\n2\r\n--XyZ\r\n" + fd("c") + "\r\n\r\n3\r\n--XyZ--\r\n"},
	{"preamble-epilogue", "preamble text\r\n--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--\r\nepilogue"},
	{"leading-crlf", "\r\n--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--\r\n"},
	{"no-final-crlf", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--"},
	{"closing-junk", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--junk"},
	{"truncated-no-close", "--XyZ\r\n" + fd("a") + "\r\n\r\nv"},
	{"truncated-in-headers", "--XyZ\r\n" + fd("a")},
	{"truncated-after-delim", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ"},
	{"only-close", "--XyZ--\r\n"},
	{"empty", ""},
	{"no-delimiter", "just text"},
	{"lf-only", "--XyZ\n" + fd("a") + "\n\nv\n--XyZ--\n"},
	{"lf-only-body-delim", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\n--XyZ--\r\n"},
	{"padding-after-delim", "--XyZ  \t\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ \r\n" + fd("b") + "\r\n\r\nw\r\n--XyZ--\r\n"},
	{"padding-after-close", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ-- \r\n"},
	{"delim-then-junk", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZjunk\r\n" + fd("b") + "\r\n\r\nw\r\n--XyZ--\r\n"},
	{"first-delim-junk", "--XyZjunk\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--\r\n"},
	{"boundary-inside-line", "--XyZ\r\n" + fd("a") + "\r\n\r\na--XyZb\r\n--XyZ--\r\n"},
	{"boundary-prefix-in-body", "--XyZ\r\n" + fd("a") + "\r\n\r\nx\r\n--XyZz\r\n--XyZ--\r\n"},
	{"boundary-dash-in-body", "--XyZ\r\n" + fd("a") + "\r\n\r\nx\r\n--XyZ-y\r\n--XyZ--\r\n"},
	{"empty-body", "--XyZ\r\n" + fd("a") + "\r\n\r\n\r\n--XyZ--\r\n"},
	{"no-headers", "--XyZ\r\n\r\nbody\r\n--XyZ--\r\n"},
	{"header-no-colon", "--XyZ\r\n" + fd("a") + "\r\nNoColon\r\n\r\nv\r\n--XyZ--\r\n"},
	{"header-folded", "--XyZ\r\nContent-Disposition: form-data;\r\n name=\"a\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"header-lowercase", "--XyZ\r\ncontent-disposition: form-data; name=\"a\"\r\ncontent-type: text/x\r\n\r\nv\r\n--XyZ--\r\n"},
	{"header-space-before-colon", "--XyZ\r\nContent-Disposition : form-data; name=\"a\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-unquoted", "--XyZ\r\nContent-Disposition: form-data; name=a\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-escaped-quote", "--XyZ\r\nContent-Disposition: form-data; name=\"a\\\"b\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-escaped-backslash", "--XyZ\r\nContent-Disposition: form-data; name=\"a\\\\b\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-semicolon-quoted", "--XyZ\r\nContent-Disposition: form-data; name=\"a;b\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-uppercase-param", "--XyZ\r\nContent-Disposition: form-data; NAME=\"a\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-duplicate-param", "--XyZ\r\nContent-Disposition: form-data; name=\"a\"; name=\"b\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"name-missing", "--XyZ\r\nContent-Disposition: form-data\r\n\r\nv\r\n--XyZ--\r\n"},
	{"disposition-attachment", "--XyZ\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"filename-path", "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../../etc/passwd\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"filename-empty", "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"\"\r\n\r\n\r\n--XyZ--\r\n"},
	{"filename-star", "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''%C4%8D.txt\r\n\r\nv\r\n--XyZ--\r\n"},
	{"filename-and-star", "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"c.txt\"; filename*=UTF-8''%C4%8D.txt\r\n\r\nv\r\n--XyZ--\r\n"},
	{"filename-utf8-raw", "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"\xc4\x8d.txt\"\r\n\r\nv\r\n--XyZ--\r\n"},
	{"content-type-params", "--XyZ\r\n" + fd("a") + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nv\r\n--XyZ--\r\n"},
	{"binary-body", "--XyZ\r\n" + fd("a") + "\r\n\r\n\x00\x01\r\x0a\xff\r\n--XyZ--\r\n"},
	{"body-crlf-crlf", "--XyZ\r\n" + fd("a") + "\r\n\r\nline1\r\n\r\nline2\r\n--XyZ--\r\n"},
	{"cr-only", "--XyZ\r" + fd("a") + "\r\rv\r--XyZ--\r"},
	{"qp-not-decoded", "--XyZ\r\n" + fd("a") + "\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db\r\n--XyZ--\r\n"},
	{"delim-tab-padding", "--XyZ\t\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--\r\n"},
	{"close-then-more-parts", "--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--\r\n--XyZ\r\n" + fd("b") + "\r\n\r\nw\r\n--XyZ--\r\n"},
	{"double-delim", "--XyZ\r\n--XyZ\r\n" + fd("a") + "\r\n\r\nv\r\n--XyZ--\r\n"},
}

type mpPart struct {
	name, filename, contentType *string
	value                       *string // nil: reading the body failed
}

func strp(s string) *string { return &s }

func runMultipart(body string) (parts []mpPart, failed bool) {
	r := multipart.NewReader(bytes.NewReader([]byte(body)), mpBoundary)
	for {
		p, err := r.NextRawPart()
		// Only a bare io.EOF is the clean end: a body cut short comes back
		// wrapped ("multipart: NextPart: EOF"), and errors.Is would hide it.
		if err == io.EOF {
			return parts, false
		}
		if err != nil {
			return parts, true
		}
		var mp mpPart
		if cd := p.Header.Get("Content-Disposition"); cd != "" {
			if _, params, err := mime.ParseMediaType(cd); err == nil {
				if v, ok := params["name"]; ok {
					mp.name = strp(v)
				}
				if v, ok := params["filename"]; ok {
					mp.filename = strp(v)
				}
			}
		}
		if ct, ok := p.Header["Content-Type"]; ok {
			mp.contentType = strp(ct[0])
		}
		if b, err := io.ReadAll(p); err == nil {
			mp.value = strp(string(b))
		}
		parts = append(parts, mp)
		if mp.value == nil {
			return parts, true
		}
	}
}

func emitMultipart(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const MultipartPart = struct {\n")
	fmt.Fprintf(b, "    name: ?[]const u8,\n    filename: ?[]const u8,\n    content_type: ?[]const u8,\n")
	fmt.Fprintf(b, "    /// null: reading this part's body failed (and the reader stopped).\n    value: ?[]const u8,\n};\n\n")
	fmt.Fprintf(b, "pub const MultipartCase = struct { id: []const u8, body: []const u8, parts: []const MultipartPart, err: bool };\n\n")
	fmt.Fprintf(b, "pub const multipart_boundary = %s;\n\n", zigStr(mpBoundary))
	fmt.Fprintf(b, "/// Go's mime/multipart Reader (NextRawPart) with mime.ParseMediaType on the disposition.\n")
	fmt.Fprintf(b, "pub const multipart = [_]MultipartCase{\n")
	for _, c := range mpCases {
		parts, failed := runMultipart(c.body)
		var items []string
		for _, p := range parts {
			items = append(items, fmt.Sprintf(".{ .name = %s, .filename = %s, .content_type = %s, .value = %s }",
				zigOptStr(p.name), zigOptStr(p.filename), zigOptStr(p.contentType), zigOptStr(p.value)))
		}
		fmt.Fprintf(b, "    .{ .id = %s, .body = %s, .parts = %s, .err = %t },\n", zigStr(c.id), zigStr(c.body), zigList(items), failed)
	}
	fmt.Fprintf(b, "};\n\n")
}
