// SPDX-License-Identifier: MIT

// A real wireguard-go, for `zig build interop-wireguard -- --wireguard-go`
// (modules/wireguard/tools/interop.zig): a device on an in-memory TUN and a real UDP
// socket on loopback, its configuration protocol on a Unix socket, exactly as the
// `wireguard-go` command serves it. Whatever arrives through the tunnel goes back
// with source and destination swapped, so the far side can check both directions.
//
// Usage: go_oracle <socket path>
// Prints "ready\n" on stdout once the socket listens, then serves until stdin closes.
package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go_oracle <socket path>")
		os.Exit(2)
	}
	tunnel := tuntest.NewChannelTUN()
	dev := device.NewDevice(tunnel.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.Up(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	go func() {
		for pkt := range tunnel.Inbound {
			if len(pkt) < 20 || pkt[0]>>4 != 4 {
				continue
			}
			reply := append([]byte(nil), pkt...)
			copy(reply[12:16], pkt[16:20])
			copy(reply[16:20], pkt[12:16])
			tunnel.Outbound <- reply
		}
	}()

	l, err := net.Listen("unix", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin) // until the driver goes away
}
