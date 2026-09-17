// SPDX-License-Identifier: MIT
//
// Second leg of the csvstream differential oracle (CONVENTIONS.md §9): reads
// the hex vectors `gen.py` wrote, decodes each, and reports what Go's
// `encoding/csv` (LazyQuotes) makes of it as a single record read -- the same
// question `dump.zig` asks of this repo's own csvstream module and `gen.py`
// already asked of Python's `csv` module.
//
// WHAT IT NEEDS: Go only (built against 1.21+; stdlib `encoding/csv`, no
// third-party module).
// WHAT IT PRODUCES: one line per input line on stdin --
//   ERR        -- Read() returned an error (e.g. empty input -> io.EOF)
//   N:f1|f2|.. -- N fields, hex-encoded, '|'-joined (N may be 0)
// Only the FIRST record of a multi-record input is reported (Read() reads
// exactly one record) -- `gen.py`'s `MULTIROW` marker has no Go equivalent;
// `compare.py` accounts for that asymmetry rather than treating it as a bug.
//
// Build:
//   cd go && go build -o oracle .
// Run:
//   ./oracle < zz_vectors.hex
package main

import ("bufio";"encoding/csv";"encoding/hex";"fmt";"os";"strings")
func main(){
  sc:=bufio.NewScanner(os.Stdin); sc.Buffer(make([]byte,1<<20),1<<20)
  for sc.Scan(){
    b,_:=hex.DecodeString(strings.TrimSpace(sc.Text()))
    r:=csv.NewReader(strings.NewReader(string(b))); r.LazyQuotes=true; r.FieldsPerRecord=-1
    rec,err:=r.Read()
    if err!=nil { fmt.Println("ERR"); continue }
    parts:=make([]string,len(rec))
    for i,f:=range rec { parts[i]=hex.EncodeToString([]byte(f)) }
    fmt.Printf("%d:%s\n",len(rec),strings.Join(parts,"|"))
  }
}
