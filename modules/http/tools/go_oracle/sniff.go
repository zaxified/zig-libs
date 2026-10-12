// SPDX-License-Identifier: MIT

// Area sniff: http.DetectContentType over every signature of the WHATWG MIME
// Sniffing tables this module implements, each with the near misses around
// it (truncated, wrong case, wrong terminator, leading whitespace, the
// 512-byte window). Inputs are ours; Go only answers.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

type sniffCase struct{ id, data string }

func sniffCases() []sniffCase {
	cs := []sniffCase{
		{"empty", ""},
		{"ws-only", " \t\r\n\x0c"},
		{"text", "hello, world"},
		{"utf8-text", "\xc4\x8dau"},
		{"high-bytes", "\x80\xff\xfe"},
		{"del", "a\x7fb"},
	}
	// Each C0 control byte alone after text: binary or not.
	for b := 0; b < 0x20; b++ {
		cs = append(cs, sniffCase{fmt.Sprintf("c0-%02x", b), "ab" + string(rune(b)) + "cd"})
	}

	tags := []string{"<!DOCTYPE HTML", "<HTML", "<HEAD", "<SCRIPT", "<IFRAME", "<H1", "<DIV", "<FONT", "<TABLE", "<A", "<STYLE", "<TITLE", "<B", "<BODY", "<BR", "<P", "<!--"}
	for i, t := range tags {
		cs = append(cs,
			sniffCase{fmt.Sprintf("html-%02d-gt", i), t + ">"},
			sniffCase{fmt.Sprintf("html-%02d-sp", i), t + " x"},
			sniffCase{fmt.Sprintf("html-%02d-lower", i), strings.ToLower(t) + ">"},
			sniffCase{fmt.Sprintf("html-%02d-tab", i), t + "\tx"},
			sniffCase{fmt.Sprintf("html-%02d-slash", i), t + "/>"},
			sniffCase{fmt.Sprintf("html-%02d-letter", i), t + "x>"},
			sniffCase{fmt.Sprintf("html-%02d-bare", i), t},
		)
	}
	cs = append(cs,
		sniffCase{"html-mixed-case", "<hTmL>"},
		sniffCase{"html-lead-ws", " \t\r\n\x0c<html>"},
		sniffCase{"html-lead-vt", "\x0b<html>"},
		sniffCase{"html-lead-text", "x<html>"},
		sniffCase{"html-lead-bom", "\xef\xbb\xbf<html>"},
		sniffCase{"html-comment-close", "<!---->"},
		sniffCase{"html-doctype-lower", "<!doctype html>"},
		sniffCase{"html-doctype-nospace", "<!DOCTYPEHTML>"},
		sniffCase{"html-after-window", strings.Repeat(" ", 600) + "<html>"},
		sniffCase{"html-at-window-edge", strings.Repeat(" ", 506) + "<html>"},
		sniffCase{"html-cut-by-window", strings.Repeat(" ", 507) + "<html>"},
		sniffCase{"xml", "<?xml version=\"1.0\"?>"},
		sniffCase{"xml-bare", "<?xml"},
		sniffCase{"xml-lead-ws", "\n\n  <?xml"},
		sniffCase{"xml-upper", "<?XML"},
		sniffCase{"xml-short", "<?xm"},
		sniffCase{"pdf", "%PDF-1.7\n"},
		sniffCase{"pdf-no-dash", "%PDF"},
		sniffCase{"pdf-lower", "%pdf-1.7"},
		sniffCase{"pdf-lead-ws", " %PDF-1.7"},
		sniffCase{"ps", "%!PS-Adobe-3.0"},
		sniffCase{"ps-short", "%!PS-Adob"},
		sniffCase{"bom-16be-2", "\xfe\xff"},
		sniffCase{"bom-16be-4", "\xfe\xff\x00\x00"},
		sniffCase{"bom-16be-text", "\xfe\xff\x00a"},
		sniffCase{"bom-16le-2", "\xff\xfe"},
		sniffCase{"bom-16le-text", "\xff\xfea\x00"},
		sniffCase{"bom-8-3", "\xef\xbb\xbf"},
		sniffCase{"bom-8-text", "\xef\xbb\xbfhi"},
		sniffCase{"bom-8-short", "\xef\xbb"},
		sniffCase{"ico", "\x00\x00\x01\x00\x01\x00"},
		sniffCase{"cur", "\x00\x00\x02\x00\x01\x00"},
		sniffCase{"bmp", "BMxx"},
		sniffCase{"bmp-bare", "BM"},
		sniffCase{"gif87", "GIF87a\x01\x00"},
		sniffCase{"gif89", "GIF89a"},
		sniffCase{"gif-other", "GIF88a"},
		sniffCase{"webp", "RIFF\x24\x00\x00\x00WEBPVP8 "},
		sniffCase{"webp-any-size", "RIFF\xff\xff\xff\xffWEBPVP8L"},
		sniffCase{"webp-short", "RIFF\x24\x00\x00\x00WEBPV"},
		sniffCase{"webp-not-vp", "RIFF\x24\x00\x00\x00WEBPXX"},
		sniffCase{"png", "\x89PNG\r\n\x1a\n\x00\x00"},
		sniffCase{"png-short", "\x89PNG\r\n\x1a"},
		sniffCase{"jpeg", "\xff\xd8\xff\xe0"},
		sniffCase{"jpeg-bare", "\xff\xd8\xff"},
		sniffCase{"jpeg-short", "\xff\xd8"},
		sniffCase{"aiff", "FORM\x00\x00\x00\x10AIFFCOMM"},
		sniffCase{"aiff-c", "FORM\x00\x00\x00\x10AIFC"},
		sniffCase{"mp3-id3", "ID3\x04\x00"},
		sniffCase{"ogg", "OggS\x00\x02"},
		sniffCase{"ogg-version", "OggS\x01"},
		sniffCase{"midi", "MThd\x00\x00\x00\x06\x00\x01"},
		sniffCase{"midi-len", "MThd\x00\x00\x00\x07"},
		sniffCase{"avi", "RIFF\x00\x10\x00\x00AVI LIST"},
		sniffCase{"wave", "RIFF\x00\x10\x00\x00WAVEfmt "},
		sniffCase{"riff-other", "RIFF\x00\x10\x00\x00CDXA"},
		sniffCase{"webm", "\x1a\x45\xdf\xa3\x9f"},
		sniffCase{"webm-short", "\x1a\x45\xdf"},
		sniffCase{"eot", strings.Repeat("\x01", 34) + "LP"},
		sniffCase{"eot-33", strings.Repeat("\x01", 33) + "LP"},
		sniffCase{"eot-text-before", strings.Repeat("a", 34) + "LP"},
		sniffCase{"ttf", "\x00\x01\x00\x00\x00\x10"},
		sniffCase{"otf", "OTTO\x00\x10"},
		sniffCase{"ttc", "ttcf\x00\x01"},
		sniffCase{"woff", "wOFF\x00\x01"},
		sniffCase{"woff2", "wOF2\x00\x01"},
		sniffCase{"gzip", "\x1f\x8b\x08\x00"},
		sniffCase{"gzip-method", "\x1f\x8b\x07"},
		sniffCase{"zip", "PK\x03\x04\x14\x00"},
		sniffCase{"zip-empty", "PK\x05\x06"},
		sniffCase{"rar4", "Rar!\x1a\x07\x00\xcf"},
		sniffCase{"rar5", "Rar!\x1a\x07\x01\x00"},
		sniffCase{"rar-other", "Rar!\x1a\x07\x02"},
		sniffCase{"wasm", "\x00asm\x01\x00\x00\x00"},
		sniffCase{"window-binary-last", strings.Repeat("a", 511) + "\x00"},
		sniffCase{"window-binary-after", strings.Repeat("a", 512) + "\x00"},
		sniffCase{"sig-after-ws", "  GIF89a"},
	)

	// MP4 (WHATWG 6.2.1): box size, ftyp, the brand list.
	mp4 := func(size uint32, body string) string {
		return string([]byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)}) + body
	}
	cs = append(cs,
		sniffCase{"mp4-major", mp4(16, "ftypmp42\x00\x00\x00\x00")},
		sniffCase{"mp4-compat", mp4(24, "ftypisom\x00\x00\x02\x00isommp41")},
		sniffCase{"mp4-none", mp4(24, "ftypisom\x00\x00\x02\x00isomiso2")},
		sniffCase{"mp4-in-minor", mp4(16, "ftypisommp41")},
		sniffCase{"mp4-size-odd", mp4(18, "ftypmp42\x00\x00\x00\x00\x00\x00")},
		sniffCase{"mp4-size-over", mp4(64, "ftypmp42\x00\x00\x00\x00")},
		sniffCase{"mp4-size-zero", mp4(0, "ftypmp42\x00\x00\x00\x00")},
		sniffCase{"mp4-size-8", mp4(8, "ftypmp42")},
		sniffCase{"mp4-size-12", mp4(12, "ftypmp42")},
		sniffCase{"mp4-short", mp4(8, "ftyp")},
		sniffCase{"mp4-not-ftyp", mp4(16, "moovmp42\x00\x00\x00\x00")},
		sniffCase{"mp4-box-past-window", mp4(516, "ftypmp42"+strings.Repeat("\x00", 600))},
		sniffCase{"mp4-box-at-window", mp4(512, "ftypisom\x00\x00\x00\x00"+strings.Repeat("\x00", 492)+"mp41"+strings.Repeat("\x00", 40))},
	)
	return cs
}

func emitSniff(b *bytes.Buffer) {
	fmt.Fprintf(b, "pub const SniffCase = struct {\n    id: []const u8,\n    data: []const u8,\n    /// What http.DetectContentType answers.\n    content_type: []const u8,\n};\n\n")
	fmt.Fprintf(b, "/// Go's http.DetectContentType.\npub const sniff = [_]SniffCase{\n")
	for _, c := range sniffCases() {
		fmt.Fprintf(b, "    .{ .id = %s, .data = %s, .content_type = %s },\n", zigStr(c.id), zigStr(c.data), zigStr(http.DetectContentType([]byte(c.data))))
	}
	fmt.Fprintf(b, "};\n\n")
}
