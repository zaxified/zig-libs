// SPDX-License-Identifier: MIT

// Area form: whole requests through Request.ParseForm and then
// Request.ParseMultipartForm(32 MiB) -- the calls FormValue, PostFormValue
// and FormFile make -- plus url.QueryEscape for the client-side encoder.
// Recorded: both errors (ErrNotMultipart counts as none: FormValue ignores
// it), Form and PostForm (keys sorted, values of a key in Go's order), and
// every file (key, filename, part Content-Type, contents).
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
)

type formCase struct {
	id, method, target, contentType, body string
	// n > 0: the body is `body` repeated n times joined by "&" (the
	// parameter-count limit needs more pairs than a literal should carry).
	n int
}

func fdf(name, filename string) string {
	return "Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\""
}

const mpCT = "multipart/form-data; boundary=XyZ"
const urlCT = "application/x-www-form-urlencoded"

func mpBody(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--XyZ\r\n" + p + "\r\n")
	}
	b.WriteString("--XyZ--\r\n")
	return b.String()
}

func mpVal(name, v string) string { return fd(name) + "\r\n\r\n" + v }
func mpFile(name, filename, v string) string {
	return fdf(name, filename) + "\r\nContent-Type: application/octet-stream\r\n\r\n" + v
}

var formCases = []formCase{
	// ── which body a method gets, and precedence against the query ──
	{"get-query", "GET", "/f?a=1&b=2&a=3", "", "", 0},
	{"post-urlencoded", "POST", "/f", urlCT, "a=1&b=x+y%21", 0},
	{"post-body-and-query", "POST", "/f?a=q&c=3", urlCT, "a=b&d=4", 0},
	{"put-urlencoded", "PUT", "/f?a=q", urlCT, "a=b", 0},
	{"patch-urlencoded", "PATCH", "/f", urlCT, "a=b", 0},
	{"delete-urlencoded", "DELETE", "/f?q=1", urlCT, "a=b", 0},
	{"get-urlencoded-body", "GET", "/f?q=1", urlCT, "a=b", 0},
	{"options-urlencoded-body", "OPTIONS", "/f", urlCT, "a=b", 0},
	// ── the Content-Type the body is read under ──
	{"ct-charset", "POST", "/f", urlCT + "; charset=utf-8", "a=%C4%8D", 0},
	{"ct-case", "POST", "/f", "Application/X-WWW-Form-URLEncoded", "a=1", 0},
	{"ct-missing", "POST", "/f?q=1", "", "a=1", 0},
	{"ct-json", "POST", "/f?q=1", "application/json", "{\"a\":1}", 0},
	{"ct-text", "POST", "/f", "text/plain", "a=1", 0},
	{"ct-no-type", "POST", "/f?q=1", "; charset=utf-8", "a=1", 0},
	{"ct-no-subtype", "POST", "/f?q=1", "application", "a=1", 0},
	{"ct-valueless-param", "POST", "/f?q=1", urlCT + "; charset", "a=1", 0},
	{"ct-duplicate-param", "POST", "/f?q=1", urlCT + "; charset=a; charset=b", "a=1", 0},
	{"ct-trailing-semicolon", "POST", "/f", urlCT + ";", "a=1", 0},
	// ── urlencoded body decoding ──
	{"body-bad-escape", "POST", "/f", urlCT, "a=%zz&b=1&c=%4", 0},
	{"body-bad-escape-key", "POST", "/f", urlCT, "%zz=1&b=2", 0},
	{"query-bad-escape", "POST", "/f?a=%zz&b=1", urlCT, "c=2", 0},
	{"body-semicolon", "POST", "/f", urlCT, "a=1;b=2&c=3", 0},
	{"body-empty-pairs", "POST", "/f", urlCT, "&&a=1&&", 0},
	{"body-plus-key", "POST", "/f", urlCT, "first+name=x+y&%2B=%2B", 0},
	{"body-empty", "POST", "/f?q=1", urlCT, "", 0},
	{"body-valueless", "POST", "/f", urlCT, "flag&k=&=v&=", 0},
	{"body-two-equals", "POST", "/f", urlCT, "a=b=c", 0},
	{"body-binary", "POST", "/f", urlCT, "a=%00%FF&b=\xc4\x8d", 0},
	{"body-newline", "POST", "/f", urlCT, "a=1\r\n&b=2", 0},
	{"body-dup-key", "POST", "/f?k=q1&k=q2", urlCT, "k=b1&k=b2", 0},
	{"params-at-limit", "POST", "/f", urlCT, "a=1", 10000},
	{"params-over-limit", "POST", "/f?q=1", urlCT, "a=1", 10001},
	// ── multipart/form-data ──
	{"mp-basic", "POST", "/f", mpCT, mpBody(mpVal("a", "1"), mpFile("f", "x.txt", "file body"), mpVal("b", "two words")), 0},
	{"mp-query-first", "POST", "/f?a=q", mpCT, mpBody(mpVal("a", "m")), 0},
	{"mp-get", "GET", "/f", mpCT, mpBody(mpVal("a", "1")), 0},
	{"mp-delete", "DELETE", "/f", mpCT, mpBody(mpVal("a", "1")), 0},
	{"mp-no-boundary", "POST", "/f?q=1", "multipart/form-data", mpBody(mpVal("a", "1")), 0},
	{"mp-empty-boundary", "POST", "/f?q=1", "multipart/form-data; boundary=", mpBody(mpVal("a", "1")), 0},
	{"mp-boundary-quoted", "POST", "/f", "multipart/form-data; boundary=\"XyZ\"", mpBody(mpVal("a", "1")), 0},
	{"mp-ct-case", "POST", "/f", "Multipart/Form-Data; Boundary=XyZ", mpBody(mpVal("a", "1")), 0},
	{"mp-ct-dup-param", "POST", "/f?q=1", mpCT + "; boundary=Q", mpBody(mpVal("a", "1")), 0},
	{"mp-mixed", "POST", "/f?q=1", "multipart/mixed; boundary=XyZ", mpBody(mpVal("a", "1")), 0},
	{"mp-attachment", "POST", "/f", mpCT, mpBody("Content-Disposition: attachment; name=\"a\"\r\n\r\n1", mpVal("b", "2")), 0},
	{"mp-disposition-case", "POST", "/f", mpCT, mpBody("Content-Disposition: Form-Data; name=\"a\"\r\n\r\n1"), 0},
	{"mp-no-name", "POST", "/f", mpCT, mpBody("Content-Disposition: form-data\r\n\r\n1", mpVal("b", "2")), 0},
	{"mp-empty-name", "POST", "/f", mpCT, mpBody(mpVal("", "1"), mpVal("b", "2")), 0},
	{"mp-no-disposition", "POST", "/f", mpCT, mpBody("Content-Type: text/plain\r\n\r\n1", mpVal("b", "2")), 0},
	{"mp-empty-filename", "POST", "/f", mpCT, mpBody(fdf("f", "") + "\r\n\r\nv"), 0},
	{"mp-filename-dotdot", "POST", "/f", mpCT, mpBody(mpFile("f", "../../etc/passwd", "x")), 0},
	{"mp-filename-abs", "POST", "/f", mpCT, mpBody(mpFile("f", "/tmp/a.txt", "x")), 0},
	{"mp-filename-trailing-slash", "POST", "/f", mpCT, mpBody(mpFile("f", "a/b/", "x")), 0},
	{"mp-filename-slashes", "POST", "/f", mpCT, mpBody(mpFile("f", "///", "x")), 0},
	{"mp-filename-dot", "POST", "/f", mpCT, mpBody(mpFile("f", ".", "x")), 0},
	{"mp-filename-dotdot-only", "POST", "/f", mpCT, mpBody(mpFile("f", "..", "x")), 0},
	{"mp-filename-backslash", "POST", "/f", mpCT, mpBody(mpFile("f", "C:\\\\dir\\\\a.txt", "x")), 0},
	{"mp-file-no-ct", "POST", "/f", mpCT, mpBody(fdf("f", "a.bin") + "\r\n\r\n\x00\x01\xff"), 0},
	{"mp-file-ct", "POST", "/f", mpCT, mpBody(fdf("f", "a.png") + "\r\nContent-Type: image/png\r\n\r\nPNG"), 0},
	{"mp-dup-keys", "POST", "/f?a=q", mpCT, mpBody(mpVal("a", "1"), mpFile("f", "1.txt", "one"), mpVal("a", "2"), mpFile("f", "2.txt", "two")), 0},
	{"mp-value-and-file-same-key", "POST", "/f", mpCT, mpBody(mpVal("k", "v"), mpFile("k", "k.txt", "file")), 0},
	{"mp-truncated", "POST", "/f?q=1", mpCT, "--XyZ\r\n" + fd("a") + "\r\n\r\nv", 0},
	{"mp-empty-body", "POST", "/f?q=1", mpCT, "", 0},
	{"mp-only-close", "POST", "/f?q=1", mpCT, "--XyZ--\r\n", 0},
	{"mp-quoted-printable", "POST", "/f", mpCT, mpBody(fd("a") + "\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db"), 0},
	{"mp-crlf-in-value", "POST", "/f", mpCT, mpBody(mpVal("a", "l1\r\nl2")), 0},
}

// formBody expands a case's body.
func formBody(c formCase) string {
	if c.n == 0 {
		return c.body
	}
	return strings.Repeat(c.body+"&", c.n-1) + c.body
}

// Inputs to url.QueryEscape, for the client-side encoder.
var escapeInputs = []string{
	"", "abc", "a b", "a+b", "a&b=c", "-_.~", "!*'();:@&=+$,/?#[]", "\xc4\x8d", "\x00\x7f\x80\xff", "100%", "tab\there", "A-Z0-9",
}

func valuesItems(v url.Values) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var items []string
	for _, k := range keys {
		for _, x := range v[k] {
			items = append(items, fmt.Sprintf(".{ %s, %s }", zigStr(k), zigStr(x)))
		}
	}
	return zigList(items)
}

func countValues(v url.Values) int {
	n := 0
	for _, x := range v {
		n += len(x)
	}
	return n
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func emitForm(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const FormFile = struct { key: []const u8, filename: []const u8, content_type: ?[]const u8, data: []const u8 };\n\n")
	fmt.Fprintf(b, "pub const FormCase = struct {\n    id: []const u8,\n    method: []const u8,\n    target: []const u8,\n    content_type: []const u8,\n    body: []const u8,\n    /// > 0: the request body is `body` repeated n times joined by \"&\".\n    n: u32,\n")
	fmt.Fprintf(b, "    /// Request.ParseForm's error, \"\" when none.\n    parse_err: []const u8,\n    /// Request.ParseMultipartForm's error, \"\" when none or ErrNotMultipart.\n    multipart_err: []const u8,\n")
	fmt.Fprintf(b, "    /// Request.Form / PostForm: keys sorted, a key's values in Go's order;\n    /// both empty for a repeated (n > 0) body, whose value counts say it all.\n    form: []const [2][]const u8,\n    post: []const [2][]const u8,\n    form_count: u32,\n    post_count: u32,\n    /// MultipartForm.File, keys sorted.\n    files: []const FormFile,\n};\n\n")
	fmt.Fprintf(b, "/// Go's Request.ParseForm + ParseMultipartForm(32 MiB).\npub const form = [_]FormCase{\n")
	for _, c := range formCases {
		body := formBody(c)
		req := httptest.NewRequest(c.method, "http://example.test"+c.target, strings.NewReader(body))
		if c.contentType != "" {
			req.Header.Set("Content-Type", c.contentType)
		}
		perr := req.ParseForm()
		merr := req.ParseMultipartForm(32 << 20)
		if errors.Is(merr, http.ErrNotMultipart) {
			merr = nil
		}
		var files []string
		if req.MultipartForm != nil {
			keys := make([]string, 0, len(req.MultipartForm.File))
			for k := range req.MultipartForm.File {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				for _, fh := range req.MultipartForm.File[k] {
					f, err := fh.Open()
					if err != nil {
						panic(err)
					}
					data, _ := io.ReadAll(f)
					f.Close()
					ct := (*string)(nil)
					if v, ok := fh.Header["Content-Type"]; ok && len(v) > 0 {
						ct = &v[0]
					}
					files = append(files, fmt.Sprintf(".{ .key = %s, .filename = %s, .content_type = %s, .data = %s }",
						zigStr(k), zigStr(fh.Filename), zigOptStr(ct), zigStr(string(data))))
				}
			}
		}
		formItems, postItems := valuesItems(req.Form), valuesItems(req.PostForm)
		if c.n > 0 {
			formItems, postItems = "&.{}", "&.{}"
		}
		fmt.Fprintf(b, "    .{ .id = %s, .method = %s, .target = %s, .content_type = %s, .body = %s, .n = %d, .parse_err = %s, .multipart_err = %s, .form = %s, .post = %s, .form_count = %d, .post_count = %d, .files = %s },\n",
			zigStr(c.id), zigStr(c.method), zigStr(c.target), zigStr(c.contentType), zigStr(c.body), c.n,
			zigStr(errStr(perr)), zigStr(errStr(merr)), formItems, postItems, countValues(req.Form), countValues(req.PostForm), zigList(files))
	}
	fmt.Fprintf(b, "};\n\n")

	fmt.Fprintf(b, "pub const EscapeCase = struct { input: []const u8, out: []const u8 };\n\n")
	fmt.Fprintf(b, "/// Go's url.QueryEscape.\npub const query_escape = [_]EscapeCase{\n")
	for _, in := range escapeInputs {
		fmt.Fprintf(b, "    .{ .input = %s, .out = %s },\n", zigStr(in), zigStr(url.QueryEscape(in)))
	}
	fmt.Fprintf(b, "};\n\n")
}
