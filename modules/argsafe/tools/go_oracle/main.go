// SPDX-License-Identifier: MIT
// Foreign verdicts from go-playground/validator v10.30.5 (MIT) for the shapes it
// shares with argsafe. Reads one hex-encoded string per line on stdin and writes
// "<hostname> <port>" (0/1 each) per line:
//
//	hostname: Var(s, "hostname_rfc1123")
//	port:     Var(":"+s, "hostname_port")  -- the library's "port" tag panics on
//	          strings, so the port half of hostname_port (ParseInt 1..65535) is used
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
)

func b(err error) int {
	if err == nil {
		return 1
	}
	return 0
}

func main() {
	v := validator.New()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		raw, err := hex.DecodeString(sc.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad hex")
			os.Exit(2)
		}
		s := string(raw)
		fmt.Fprintf(w, "%d %d\n", b(v.Var(s, "hostname_rfc1123")), b(v.Var(":"+s, "hostname_port")))
	}
}
