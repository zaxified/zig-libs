// SPDX-License-Identifier: MIT

// Probe behind the accesslog card's encoding lead: writes one string field
// holding each ill-formed UTF-8 sequence below through Go's encoding/json,
// log/slog's JSONHandler, rs/zerolog, uber-go/zap and phuslu/log (pinned by
// go.mod/go.sum), decodes the JSON line back, and prints how many U+FFFD each
// one put in place of the sequence. Unicode 16 §3.9 ("U+FFFD substitution of
// maximal subparts", which the WHATWG Encoding Standard makes normative for
// decoders) asks for one per maximal subpart; Python's
// `bytes.decode("utf-8", "replace")` follows it and is printed as `want` by
// the caller (`tools/README.md`). Output: case \t library \t count.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	plog "github.com/phuslu/log"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Each case: a name and the bytes, framed by "a" and "z" so a writer that
// swallows a neighbour is visible too.
var cases = []struct{ name, s string }{
	{"truncated_3byte_E1_80", "\xe1\x80"},
	{"truncated_4byte_F0_9F_98", "\xf0\x9f\x98"},
	{"truncated_4byte_F1_80_80", "\xf1\x80\x80"},
	{"surrogate_ED_A0_80", "\xed\xa0\x80"},
	{"overlong_C0_AF", "\xc0\xaf"},
	{"overlong_E0_80_AF", "\xe0\x80\xaf"},
	{"above_10FFFF_F4_90_80_80", "\xf4\x90\x80\x80"},
	{"bare_continuation_80_80", "\x80\x80"},
	{"F5_FF", "\xf5\xff"},
	{"truncated_then_ascii_E2_82_41", "\xe2\x82A"},
}

func count(line []byte) int {
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(line), &m); err != nil {
		return -1
	}
	v, _ := m["v"].(string)
	if !strings.HasPrefix(v, "a") || !strings.HasSuffix(v, "z") {
		return -2
	}
	return strings.Count(v, "�")
}

func main() {
	var buf bytes.Buffer
	zl := zerolog.New(&buf)
	zp := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{LineEnding: "\n"}), zapcore.AddSync(&buf), zapcore.DebugLevel))
	ph := plog.Logger{Writer: plog.IOWriter{Writer: &buf}}
	sh := slog.NewJSONHandler(&buf, nil)
	libs := []struct {
		name  string
		write func(s string)
	}{
		{"encoding/json", func(s string) { _ = json.NewEncoder(&buf).Encode(map[string]string{"v": s}) }},
		{"log/slog", func(s string) {
			r := slog.NewRecord(time.Time{}, slog.LevelInfo, "", 0)
			r.AddAttrs(slog.String("v", s))
			_ = sh.Handle(context.Background(), r)
		}},
		{"zerolog", func(s string) { zl.Log().Str("v", s).Send() }},
		{"zap", func(s string) { zp.Info("", zap.String("v", s)) }},
		{"phuslu/log", func(s string) { ph.Log().Str("v", s).Msg("") }},
	}
	for _, c := range cases {
		for _, l := range libs {
			buf.Reset()
			l.write("a" + c.s + "z")
			fmt.Printf("%s\t%s\t%d\n", c.name, l.name, count(buf.Bytes()))
		}
	}
	os.Stdout.Sync()
}
