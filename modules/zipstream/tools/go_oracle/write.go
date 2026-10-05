// SPDX-License-Identifier: MIT

// Area write: archives THIS module's ArchiveWriter produced
// (tools/interop.zig writes one file per case, "<id>.zip") and what Go's
// Reader makes of them. The replay re-runs the writer on Go's view of each
// entry and requires the same bytes, so Go's reading is pinned to today's
// output.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func emitWrite(b *bytes.Buffer, dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, "*.zip"))
	if err != nil {
		return err
	}
	sort.Strings(names)
	var cases []readCase
	for _, n := range names {
		data, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		cases = append(cases, readCase{strings.TrimSuffix(filepath.Base(n), ".zip"), data})
	}
	if len(cases) == 0 {
		return os.ErrNotExist
	}
	emitCases(b, "go_write", "/// This module's ArchiveWriter output, read by Go.", cases)
	return nil
}
