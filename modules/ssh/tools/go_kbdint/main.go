// SPDX-License-Identifier: MIT

// A keyboard-interactive SSH server on golang.org/x/crypto/ssh (BSD-3-Clause,
// run as a black box) -- the foreign peer for the ssh module's RFC 4256
// client test. Two challenge rounds: "Password: " (no echo), then
// "Token: " (echo), with fixed answers; on success an "exec" request is
// answered with "kbd-ok user=<user> cmd=<command>" and exit status 0.
//
//	go run . <port>    prints "READY" once listening; serves one connection
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	signer, err := ssh.NewSignerFromKey(priv)
	must(err)
	cfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(md ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			a, err := client("", "round one", []string{"Password: "}, []bool{false})
			if err != nil || len(a) != 1 || a[0] != "correct horse" {
				return nil, fmt.Errorf("wrong password")
			}
			b, err := client("second factor", "round two", []string{"Token: "}, []bool{true})
			if err != nil || len(b) != 1 || b[0] != "123456" {
				return nil, fmt.Errorf("wrong token")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:"+os.Args[1])
	must(err)
	fmt.Println("READY")
	nc, err := ln.Accept()
	must(err)
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "handshake:", err)
		os.Exit(0) // a refused login is a legitimate outcome of the test
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nch.Accept()
		must(err)
		for req := range creqs {
			if req.Type != "exec" {
				req.Reply(false, nil)
				continue
			}
			cmd := string(req.Payload[4:])
			req.Reply(true, nil)
			fmt.Fprintf(ch, "kbd-ok user=%s cmd=%s", conn.User(), cmd)
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, 0)
			ch.SendRequest("exit-status", false, status)
			ch.Close()
			conn.Close()
			return
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
