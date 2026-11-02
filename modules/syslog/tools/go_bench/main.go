// SPDX-License-Identifier: MIT

// Go side of `zig build bench-syslog` (modules/syslog/tools/bench.zig): go-syslog
// v4.6.0 and the standard library's log/syslog over the corpus the Zig program
// writes into the directory given as the first argument, for the one workload
// named by the second. Prints one line: name, ns/op, count (tab-separated). One op
// = all 64 messages. See bench.zig for what each workload pairs.
//
// Timing matches the Zig side: double the batch until it takes over 100 ms, then
// keep the best of five.
package main

import (
	"encoding/binary"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	gosyslog "github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

var sink uint64

func timeIt(f func() uint64) (float64, uint64) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	var count uint64
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

func readLines(dir, file string) [][]byte {
	b, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		panic(err)
	}
	var out [][]byte
	for len(b) > 0 {
		n := int(binary.BigEndian.Uint16(b))
		out = append(out, b[2:2+n])
		b = b[2+n:]
	}
	return out
}

func ptr(s string) *string { return &s }

func sum5424(m gosyslog.Message) uint64 {
	sm := m.(*rfc5424.SyslogMessage)
	var t uint64
	for _, p := range []*string{sm.Hostname, sm.Appname, sm.ProcID, sm.MsgID, sm.Message} {
		if p != nil {
			t += uint64(len(*p))
		}
	}
	if sm.Timestamp != nil {
		t += uint64(sm.Timestamp.Unix())
	}
	if sm.StructuredData != nil {
		for id, ps := range *sm.StructuredData {
			t += uint64(len(id))
			for k, v := range ps {
				t += uint64(len(k)) + uint64(len(v))
			}
		}
	}
	return t
}

func main() {
	dir, name := os.Args[1], os.Args[2]
	var f func() uint64
	switch name {
	case "fmt_5424", "fmt_5424_sd":
		fmt.Fprintln(os.Stderr, "go-syslog v4.6.0 SyslogMessage.String")
		texts := readLines(dir, "texts.bin")
		ss := make([]string, len(texts))
		ids := make([]string, len(texts))
		sds := make([]map[string]map[string]string, len(texts))
		for i, t := range texts {
			ss[i] = string(t)
			ids[i] = strconv.Itoa(1000 + i)
			sds[i] = map[string]map[string]string{"exampleSDID@32473": {
				"iut": "3", "eventSource": "App\"lica]tion\\x", "eventID": strconv.Itoa(5000 + i),
			}}
		}
		withSd := name == "fmt_5424_sd"
		h, a, p := ptr("web-1.example.org"), ptr("api-gateway"), ptr("4242")
		f = func() uint64 {
			var t uint64
			for i := range ss {
				now := time.Now()
				sm := &rfc5424.SyslogMessage{}
				sm.ComputeFromPriority(14)
				sm.Version = 1
				sm.Timestamp = &now
				sm.Hostname, sm.Appname, sm.ProcID, sm.MsgID, sm.Message = h, a, p, &ids[i], &ss[i]
				if withSd {
					sm.StructuredData = &sds[i]
				}
				s, err := sm.String()
				if err != nil || len(s) == 0 {
					panic("String")
				}
				t++
			}
			return t
		}
	case "send_unix":
		fmt.Fprintln(os.Stderr, "Go log/syslog Dial(unixgram)")
		texts := readLines(dir, "texts.bin")
		ss := make([]string, len(texts))
		for i, t := range texts {
			ss[i] = string(t)
		}
		wd, _ := os.Getwd()
		rel, err := filepath.Rel(wd, filepath.Join(dir, "go.sock"))
		if err != nil {
			panic(err)
		}
		os.Remove(rel)
		c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: rel, Net: "unixgram"})
		if err != nil {
			panic(err)
		}
		go func() {
			b := make([]byte, 4096)
			for {
				if _, _, err := c.ReadFromUnix(b); err != nil {
					return
				}
			}
		}()
		w, err := syslog.Dial("unixgram", rel, syslog.LOG_INFO|syslog.LOG_USER, "api-gateway")
		if err != nil {
			panic(err)
		}
		f = func() uint64 {
			var t uint64
			for _, s := range ss {
				if err := w.Info(s); err != nil {
					panic(err)
				}
				t++
			}
			return t
		}
	case "parse_5424", "parse_5424_sd":
		fmt.Fprintln(os.Stderr, "go-syslog v4.6.0 rfc5424 strict")
		lines := readLines(dir, name+".bin")
		p := rfc5424.NewParser()
		f = func() uint64 {
			var t uint64
			for _, l := range lines {
				m, err := p.Parse(l)
				if err != nil {
					panic(err)
				}
				t += sum5424(m)
			}
			return t
		}
	case "parse_bad":
		fmt.Fprintln(os.Stderr, "go-syslog v4.6.0 rfc5424 strict")
		lines := readLines(dir, "parse_bad.bin")
		p := rfc5424.NewParser()
		f = func() uint64 {
			var t uint64
			for _, l := range lines {
				if _, err := p.Parse(l); err != nil {
					t++
				} else {
					panic("accepted: " + string(l))
				}
			}
			return t
		}
	case "parse_3164":
		fmt.Fprintln(os.Stderr, "go-syslog v4.6.0 rfc3164")
		lines := readLines(dir, "parse_3164.bin")
		p := rfc3164.NewParser()
		f = func() uint64 {
			var t uint64
			for _, l := range lines {
				m, err := p.Parse(l)
				if err != nil {
					panic(err)
				}
				sm := m.(*rfc3164.SyslogMessage)
				for _, s := range []*string{sm.Hostname, sm.Appname, sm.ProcID, sm.Message} {
					if s != nil {
						t += uint64(len(*s))
					}
				}
			}
			return t
		}
	default:
		panic("no workload " + name)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
