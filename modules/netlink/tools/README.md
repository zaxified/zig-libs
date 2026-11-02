# `netlink` verification instruments

| tool | role |
|---|---|
| `bench.zig` + `go_bench/` | `zig build bench-netlink`: decoders (link, address, route, neighbour) and the route request builder against github.com/vishvananda/netlink v1.3.1 over the same 64 seeded messages per op; counts must agree. `go_bench/link_stub.go` reaches three unexported functions of that package with `go:linkname` (its `deserializeRoute`, `parseAddr`, `(*Handle).prepareRouteReq`) so the Go side is that package's own code. Needs go 1.26 and v1.3.1 with its two dependencies in the module cache. A four-hop multipath encode/decode is printed as informational Zig-only rows. |
