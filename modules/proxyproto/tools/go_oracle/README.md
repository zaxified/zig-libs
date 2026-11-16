# proxyproto Go oracle

A line-oriented differential oracle for `modules/proxyproto`, driven by
`../interop.zig` (`zig build interop-proxyproto`).

It links **pires/go-proxyproto v0.16.0** (Apache-2.0, the module's survey
reference) and uses its public API only: `ParseUDPDatagram` (which wraps
`Read`), `Header.Format`, `Header.TLVs` / `SetTLVs`, `HeaderProxyFromAddrs`
and `tlvparse.SSL`. The CRC32C TLV, which go-proxyproto does not write or
verify, is computed with the standard library's `hash/crc32` Castagnoli table.
Input is in-memory bytes only: no file, network, environment or process access.

The upstream module is **fetched, not vendored** (its licence stays with it,
and the module stays free of foreign source). `go.sum` pins its hash.

## Toolchain

v0.16.0 declares `go 1.26.9`. With an older local Go the `go` command
downloads the official `go1.26.11` toolchain (checksum-database verified) on
first use; `go.mod` here says `go 1.26.9` for the same reason. Only the root
package and `tlvparse` are compiled: `helper/http2` (the only importer of
`golang.org/x/net`) is never built, and go-proxyproto's own tests are not run.

## Build and run

    go build -o .zig-cache/pp-oracle/gooracle ./modules/proxyproto/tools/go_oracle
    zig build interop-proxyproto -- --cases 150000 --seed 1

(`go build` from `modules/proxyproto/tools/go_oracle`, with `-o` pointing at
the repository's `.zig-cache/pp-oracle/gooracle`.) The Zig program skips
cleanly (exit 0, says so) when the binary is absent.

## Protocol

One request per line on stdin, one answer per line on stdout:

    P <hex>    parse the bytes        -> OK <canon> crc=<none|ok|bad|malformed> | ERR <name>
    S <hex>    tlvparse.SSL check     -> SSLOK | SSLBAD | NOSSL | ERR <name>
    G <desc>   write a header         -> H <hex> [hp-override] | E <name>

The canonical form and the description grammar are defined in
`../interop.zig`.
