// SPDX-License-Identifier: MIT

// The beevik/ntp side of the sntp oracle: query ADDR:PORT with VERSION, up to
// TRIES times until a Kiss-o'-Death arrives when WANTKOD is 1, and print what
// beevik/ntp made of the reply (its own Validate verdict) as one JSON object.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/beevik/ntp"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: go_oracle ADDR PORT VERSION TRIES WANTKOD")
		os.Exit(2)
	}
	version, _ := strconv.Atoi(os.Args[3])
	tries, _ := strconv.Atoi(os.Args[4])
	wantKod := os.Args[5] == "1"
	out := map[string]any{}
	for i := 0; i < tries; i++ {
		r, err := ntp.QueryWithOptions(net.JoinHostPort(os.Args[1], os.Args[2]), ntp.QueryOptions{Version: version, Timeout: 500 * time.Millisecond})
		if err != nil {
			out = map[string]any{"error": err.Error()}
			if wantKod {
				continue
			}
			break
		}
		out = map[string]any{"stratum": r.Stratum, "leap": int(r.Leap), "kiss": r.KissCode,
			"offset_ns": r.ClockOffset.Nanoseconds(), "rtt_ns": r.RTT.Nanoseconds()}
		if v := r.Validate(); v != nil {
			out["error"] = v.Error()
		}
		if !wantKod || r.KissCode != "" {
			break
		}
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
