// SPDX-License-Identifier: MIT

// The evidence behind the requestid card's `**Ahead:**` correctness claim:
// go-chi/chi v5.3.2 `middleware.RequestID` adopts ANY non-empty incoming
// `X-Request-Id` verbatim and hands it to `GetReqID` (and thus to every log
// line that prints it). The whole decision is middleware/request_id.go:70-75:
// `requestID := r.Header.Get(RequestIDHeader)`, and only `if requestID == ""`
// is a fresh id generated (`fmt.Sprintf("%s-%06d", prefix, myid)`, line 73);
// there is no length limit and no charset check. The value is stored in the
// context at line 75 and returned unchanged by GetReqID (lines 83-90).
// This module adopts an incoming id only when it is 1..200 bytes of
// [A-Za-z0-9._-] (`isAdoptable`, src/root.zig), otherwise it generates one, so
// a crafted header cannot inject JSON/logfmt structure or an 8 KiB blob into a
// log line.
//
// The requests are built by hand and r.Header is set directly, so Go's own
// header parser (net/http server) is not the filter. A real server would still
// reject CR/LF; the bytes below are all legal header-value bytes.
//
//	cd modules/requestid/tools/lead_probe && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly go run .
//
// Output: one TSV line per case: case, chi_adopted, chi_id_len, ours_adopts.
// chi_adopted = GetReqID returned exactly the incoming value (non-empty).

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// oursAdopts restates `isAdoptable` from src/root.zig (max_adopt_len = 200).
func oursAdopts(v string) bool {
	if len(v) == 0 || len(v) > 200 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// viaChi runs one request through chi + RequestID; set=false sends no header.
func viaChi(v string, set bool) string {
	var got string
	rt := chi.NewRouter()
	rt.Use(middleware.RequestID)
	rt.Get("/x", func(w http.ResponseWriter, r *http.Request) {
		got = middleware.GetReqID(r.Context())
	})
	r := httptest.NewRequest("GET", "http://api.example/x", nil)
	if set {
		r.Header["X-Request-Id"] = []string{v}
	}
	rt.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func main() {
	var obs strings.Builder
	for c := 0x80; c <= 0xFF; c++ {
		obs.WriteByte(byte(c))
	}
	cases := []struct{ name, val string }{
		{"8192xa", strings.Repeat("a", 8192)},
		{"json-meta", `x","level":"admin`},
		{"space-eq", "a=1 b=2"},
		{"obs-text", obs.String()},
		{"empty", ""},
		{"normal", "edge-abc"},
	}
	fmt.Println("case\tchi_adopted\tchi_id_len\tours_adopts")
	for _, c := range cases {
		id := viaChi(c.val, true)
		fmt.Printf("%s\t%s\t%d\t%s\n", c.name, yn(c.val != "" && id == c.val), len(id), yn(oursAdopts(c.val)))
	}
	id := viaChi("", false)
	fmt.Printf("# no header: chi generated %q (len %d; format host/random10-%%06d)\n", id, len(id))
}
