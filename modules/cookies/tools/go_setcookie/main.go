// SPDX-License-Identifier: MIT

// Go's reading of Set-Cookie lines for tools/setcookie_oracle.js:
// net/http.ParseSetCookie on each line (hex on stdin, one per line), one JSON
// answer per line on stdout. Standard library only.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
)

type answer struct {
	Err      string `json:"err,omitempty"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Quoted   bool   `json:"quoted"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	MaxAge   int    `json:"maxAge"`
	Expires  bool   `json:"expires"` // a parsable Expires date was read
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite"`
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		line, err := hex.DecodeString(in.Text())
		if err != nil {
			panic(err)
		}
		c, err := http.ParseSetCookie(string(line))
		a := answer{}
		if err != nil {
			a.Err = err.Error()
		} else {
			a = answer{Name: c.Name, Value: c.Value, Quoted: c.Quoted, Path: c.Path, Domain: c.Domain,
				MaxAge: c.MaxAge, Expires: !c.Expires.IsZero(), Secure: c.Secure, HttpOnly: c.HttpOnly}
			switch c.SameSite {
			case http.SameSiteLaxMode:
				a.SameSite = "Lax"
			case http.SameSiteStrictMode:
				a.SameSite = "Strict"
			case http.SameSiteNoneMode:
				a.SameSite = "None"
			}
		}
		if err := out.Encode(a); err != nil {
			panic(err)
		}
	}
}
