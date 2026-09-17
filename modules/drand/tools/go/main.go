// SPDX-License-Identifier: MIT
//
// Independent BLS12-381 half of the drand differential oracle
// (CONVENTIONS.md §9): loads a drand `/info` document and a JSON array of
// `/public/<round>` documents (the shape `../fetch.py` writes) and verifies
// each round's signature with drand's OWN Go client library
// (`github.com/drand/drand/v2/crypto`, `github.com/drand/kyber`) -- an
// independent BLS12-381 implementation answering the same question this
// repo's `drand` module answers with its own `bls12_381`.
//
// This program is FETCHED and RUN, never vendored or distributed: `go get`
// pulls the dependency graph into `$GOMODCACHE` at build time (see the Run
// section of `../README.md`), and nothing from it is copied into this repo.
// Licence of what gets fetched: `github.com/drand/drand/v2` is dual
// MIT/Apache-2.0; `github.com/drand/kyber`, which `crypto.Scheme` needs for
// every scheme including quicknet's, is MPL-2.0. Both are fine for a
// fetch-and-run oracle under this repo's licence policy, which restricts
// copyleft in code the repo DISTRIBUTES -- see `../README.md`'s "Licence"
// section for exactly where each was verified.
//
// Trimmed from the audit's `gooracle/main.go`: the CPU-timing benchmark loop
// (`cpu.go`/`cpuNs`) and the JSON-parser-strictness differential probes are
// left out (CONVENTIONS.md §9 -- only the oracle is kept, not a benchmark or
// a per-finding probe). `chainhash.go`'s chain-hash re-derivation is also
// left out: `../chainhash.py` and `../ch2.py` already cover that question in
// this module's tools/, and this program would only duplicate it.
//
// WHAT IT NEEDS: Go 1.21+, network access to the Go module proxy the first
// time `go mod tidy` runs.
// WHAT IT PRODUCES: on stdout, `GO oracle: <ok>/<total> live rounds verified
// (rejected <bad>)`, plus one `GO REJECT round <n> <err>` line per rejection.
//
// Build:
//   cd go && go mod init drandoracle && go get github.com/drand/drand/v2 github.com/drand/kyber && go mod tidy
//   go build -o oracle .
// Run:
//   ./oracle <info.json> <rounds.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
)

type Info struct {
	PublicKey   string `json:"public_key"`
	Period      uint32 `json:"period"`
	GenesisTime int64  `json:"genesis_time"`
	Hash        string `json:"hash"`
	GroupHash   string `json:"groupHash"`
	SchemeID    string `json:"schemeID"`
	Metadata    struct {
		BeaconID string `json:"beaconID"`
	} `json:"metadata"`
}

type Beacon struct {
	Round      uint64 `json:"round"`
	Randomness string `json:"randomness"`
	Signature  string `json:"signature"`
	PrevSig    string `json:"previous_signature"`
}

func loadInfo(path string) (*crypto.Scheme, kyber.Point, Info) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var in Info
	if err := json.Unmarshal(raw, &in); err != nil {
		panic(err)
	}
	sch, err := crypto.GetSchemeByID(in.SchemeID)
	if err != nil {
		panic(err)
	}
	pkb, _ := hex.DecodeString(in.PublicKey)
	pk := sch.KeyGroup.Point()
	if err := pk.UnmarshalBinary(pkb); err != nil {
		panic(err)
	}
	return sch, pk, in
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: oracle <info.json> <rounds.json>")
		os.Exit(2)
	}
	sch, pk, in := loadInfo(os.Args[1])
	_ = in
	raw, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	var bs []Beacon
	if err := json.Unmarshal(raw, &bs); err != nil {
		panic(err)
	}
	ok, bad := 0, 0
	for _, b := range bs {
		sig, _ := hex.DecodeString(b.Signature)
		bc := &common.Beacon{Round: b.Round, Signature: sig}
		if err := sch.VerifyBeacon(bc, pk); err == nil {
			ok++
		} else {
			bad++
			fmt.Println("GO REJECT round", b.Round, err)
		}
	}
	fmt.Printf("GO oracle: %d/%d live quicknet rounds verified (rejected %d)\n", ok, len(bs), bad)
	if bad != 0 {
		os.Exit(1)
	}
}
