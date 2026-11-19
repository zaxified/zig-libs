// SPDX-License-Identifier: MIT

// Drives this module's own Responder with gos7 (BSD-3), an independent S7
// client, over loopback: DB read/write, the security services of group 5
// (set password right and wrong, clear) and the protection record (SZL
// 0x0232 index 4). The responder side is the module's `live:` test, started
// with S7COMM_TEST_LISTEN and the password "s7live":
//
//	S7COMM_TEST_LISTEN=127.0.0.1:10503 zig build test-s7comm &
//	go run . 10503
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/robinson/gos7"
)

func main() {
	port := "10503"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	h := gos7.NewTCPClientHandler("127.0.0.1:"+port, 0, 1)
	h.Timeout = 5 * time.Second
	var err error
	for i := 0; i < 30; i++ {
		if err = h.Connect(); err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		fmt.Println("could not connect:", err)
		os.Exit(1)
	}
	defer h.Close()
	c := gos7.NewClient(h)
	fail := 0
	check := func(what string, err error, wantErr bool) {
		ok := (err != nil) == wantErr
		if !ok {
			fail++
		}
		fmt.Printf("%-28s err=%v ok=%v\n", what, err, ok)
	}

	buf := make([]byte, 8)
	check("db read 1.0..8", c.AGReadDB(1, 0, 8, buf), false)
	fmt.Printf("%-28s %x\n", "db1", buf)
	check("db write 1.4..8", c.AGWriteDB(1, 4, 4, []byte{0xde, 0xad, 0xbe, 0xef}), false)
	check("set password (wrong)", c.SetSessionPassword("nope"), true)
	check("set password (right)", c.SetSessionPassword("s7live"), false)
	check("set password (9 chars)", c.SetSessionPassword("s7live\x20\x20\x20"), false)
	check("clear password", c.ClearSessionPassword(), false)
	p, err := c.GetProtection()
	check("get protection", err, false)
	fmt.Printf("%-28s %+v\n", "protection", p)
	if fmt.Sprintf("%+v", p) != "{schSchal:2 schPar:3 schRel:1 bartSch:3 anlSch:2}" {
		fmt.Println("protection differs from the responder's config")
		fail++
	}
	if fail != 0 {
		fmt.Println("FAIL", fail)
		os.Exit(1)
	}
	fmt.Println("ALL OK")
}
