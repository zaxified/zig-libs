// SPDX-License-Identifier: MIT

// Area write: archives THIS module's Writer produced (tools/interop.zig
// writes one file per case, named "<id>.<gnu|pax>.tar", and "<id>.tgz" for
// packTarGz output, which Go gunzips first) and what Go's Reader
// makes of them. The replay re-runs the Writer on Go's view of each entry
// and requires the same bytes, so Go's reading is pinned to today's output.
package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func emitWrite(b *bytes.Buffer, dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, "*.tar"))
	if err != nil {
		return err
	}
	gz, err := filepath.Glob(filepath.Join(dir, "*.tgz"))
	if err != nil {
		return err
	}
	names = append(names, gz...)
	sort.Strings(names)
	var cases []readCase
	for _, n := range names {
		data, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		id := strings.TrimSuffix(filepath.Base(n), ".tar")
		if strings.HasSuffix(n, ".tgz") {
			// packTarGz output: Go's gzip reader first; the case holds the tar inside.
			id = filepath.Base(n)
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return err
			}
			if data, err = io.ReadAll(zr); err != nil {
				return err
			}
		}
		cases = append(cases, readCase{id, data})
	}
	if len(cases) == 0 {
		return os.ErrNotExist
	}
	emitCases(b, "go_write", "/// This module's Writer output (id = \"<case>.<gnu|pax>\"), read by Go.", cases)
	return nil
}
