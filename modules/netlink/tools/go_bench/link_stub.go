// SPDX-License-Identifier: MIT

package main

import (
	_ "unsafe" // go:linkname

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// The three unexported entry points of github.com/vishvananda/netlink v1.3.1
// that the benchmark times (their bodies live in the package; see main.go).
// The empty link_stub.s lets the compiler accept the body-less declarations.

//go:linkname deserializeRoute github.com/vishvananda/netlink.deserializeRoute
func deserializeRoute(m []byte) (netlink.Route, error)

//go:linkname parseAddr github.com/vishvananda/netlink.parseAddr
func parseAddr(m []byte) (addr netlink.Addr, family int, err error)

//go:linkname prepareRouteReq github.com/vishvananda/netlink.(*Handle).prepareRouteReq
func prepareRouteReq(h *netlink.Handle, route *netlink.Route, req *nl.NetlinkRequest, msg *nl.RtMsg) error
