# dns — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **Breaking:** `reverseName` returns
  `ReverseNameError![]const u8` (`error{OutputTooSmall}`) instead of
  `[]const u8`. It used to guard `buf.len >= max_reverse_name_len` with
  `std.debug.assert`; the `std.Io.Writer.fixed` writes inside stay
  memory-safe regardless (they clamp to the buffer), but every one is
  `catch unreachable`, so ReleaseFast compiling the assert out turned a
  too-small `buf` into undefined behaviour (an `unreachable` hit) instead of
  a clean failure. Found by an audit sweep for this shape. `Resolver.reverse`
  and the example's `-x` path both size their buffer to exactly
  `max_reverse_name_len`, so the new error is provably unreachable there
  (`catch unreachable`).
- **2026-08-23** — `sortIps` no longer re-checks
  `netaddr.max_sort_candidates` before calling `sortDestinations`; the bound is
  enforced inside `netaddr` now that it returns an error, so the rule lives in
  one place. Behaviour is unchanged: an answer set larger than the bound is
  left in arrival order.

- **2026-08-22** — `tcpExchange` (the only place in this file that owns a TCP fd directly)
  used to fold every write (`writeInt`/`writeAll`/`flush`) and read (`takeInt`/
  `readSliceAll`) failure into `error.NetworkFailed`, including a canceled `std.Io` wait —
  `Io.Reader.Error`/`Io.Writer.Error` cannot carry `Canceled` at all, so the reason was gone
  by the time it reached the `catch`. Two new private helpers, `readFailure`/`writeFailure`,
  consult the concrete `Stream.Reader`/`Stream.Writer`'s out-of-band `err` field first and
  reuse the `Canceled` variant `Error` already carried — the surrounding `query()` callers
  already special-case `error.Canceled` on `tcpExchange`'s result, so no caller-side change
  was needed. `udpExchange` needed nothing: `Socket.Send`/`ReceiveTimeoutError` already carry
  `Io.Cancelable` intact, and every catch there already had an explicit `error.Canceled`
  arm. A new test drives `tcpExchange` against a loopback listener nobody ever accepts —
  `connect` and the length-prefixed write both still succeed (the kernel completes the
  handshake and buffers the write), so the read genuinely parks in `takeInt` (mutated:
  `expected error.Canceled, found error.NetworkFailed`; restored: green, 59/59). The write
  side (`writeFailure`) has no dedicated test, for the same reason a UDP send-side fix
  elsewhere in this collection has none: reliably parking a thread inside a blocking TCP
  write long enough for a cancel to land needs a full kernel send buffer, not reproducible
  here — it was made by inspection and symmetry with the read side instead.

  Audited but left alone: `acme`'s six `catch return error.X` sites named for this pass are
  all either over in-memory buffers (`std.Io.Writer.Allocating`, PEM/URL string encoding —
  no fd, nothing to lose) or already correctly widen `http.Client`'s errors through
  `mapHttpError`, which has an explicit `error.Canceled` arm; its one direct `Cancelable!void`
  call (`Client.sleepMs`'s `d.sleep`) already returns exactly `error.Canceled` on the only
  error it can produce. `dns`'s own `ensureConfig`/`readHosts` (local `/etc/hosts`/
  `resolv.conf` reads) were not touched either — a different site from the one named for this
  pass, local disk I/O rather than a TCP/UDP transport, and out of scope for this change.

  Found but out of module scope, not fixed here: `http.Client.Response.readAllAlloc`
  (`modules/http/src/Client.zig`) declares `Canceled` in its `Error` set but its own `catch
  |err| switch (err) { ..., else => error.ReadFailed }` never consults the concrete reader's
  `err` field, so a body-read cancellation cannot currently reach a caller through it at all —
  `dns`'s `dohExchange`/`queryJson` inherit this (their own `readAllAlloc` catches were left
  as `else => error.DohFailed` rather than given an `error.Canceled` arm, since one would be
  unreachable dead code against `readAllAlloc`'s current behavior and pure churn against
  CONVENTIONS.md's own "don't fix what can't see a cancel" guidance). Surfaced here since it
  was found auditing this module's DoH paths, but the fix belongs in `http`.
- **2026-08-18** — Re-export `message.max_query_len`, `message.QueryOptions` and
  `message.EncodeError` from the module root, so a codec-only consumer sizing/calling
  `encodeQuery` never has to name `dns.message` directly (which would put `Resolver`,
  and therefore the `http` dependency, in its import graph for no reason).
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Live-tested against real
  UDP/TCP/DoH/DoH-JSON resolvers over the network (decode/encode vectors are
  self-authored, not captured).
- **2026-07-02** — New module: RFC 1035 resolver —
  A/AAAA/PTR/CNAME/NS/MX/TXT/SOA/SRV/CAA over UDP/TCP + DoH.
