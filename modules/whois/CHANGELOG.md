# whois — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `TcpTransport` gains
  `timeout_ms: ?u32 = null` (default `null` preserves today's unbounded
  behaviour) and `TransportError` gains `Timeout`. Bounds the whole
  connect+write+read exchange by running it on its own concurrent task and
  canceling at the deadline -- the same construction `dns.Resolver` and
  `http.Client` already use for the identical gap (std 0.16.0 has no
  per-read deadline on a `net.Stream`). Before this, nothing in the module
  could stop a slow-but-live peer; only the caller's own outside cancel
  could. `nextServer` also rewritten from one full-response scan per
  referral key (up to 4 passes) to one pass over the lines that tests all
  four keys per line -- same observable priority (lowest-index key in
  `referral_keys` that matches anywhere still wins), measured ~2x-4x fewer
  ns/byte depending on shape. Both internal: no consumer-visible change to
  arguments or return types beyond the two additive members above. Audit
  F4/F17, plus test-only closures for F8 (an unmasking unit test on
  `Chain.append`), F11 (a scheme-rejection positive test slash-truncation
  can't save), and doc-only closures for F14/F15/F16.
- **2026-09-10** — **BEHAVIOURAL, not breaking:** `isSpecialUseHost` now
  normalizes a trailing root dot before classifying (`"localhost."` is
  `"localhost"` to every resolver, and used to slip past the SSRF guard as
  unclassified). `TcpTransport` gained a `deny_special_use: bool = true`
  field and now refuses to connect to any address a referral host RESOLVES
  to when that address is special-use, not just a host string classified as
  such -- closing the gap where an IPv4 literal spelled in an encoding
  `netaddr.parseIp` does not recognise (`0177.0.0.1`, `2130706433`, `127.1`)
  passed the string-level guard yet could still resolve into loopback/private
  space. Set `deny_special_use = false` to point `TcpTransport` at a
  loopback/private server on purpose (a local mirror, or a test peer) --
  same shape as `rdap`'s `DestinationPolicy.deny_special_use`. Audit F1/F2.
- **2026-09-07** — **Tests:** `fuzzParseServerRef` fetched its input and threw
  it away. It opened `smith.bytes(&buf)` and then drew the length with
  `valueRangeAtMost(u8, 0, buf.len)`; a ranged `Smith` draw reads eight octets
  as a little-endian u64 and returns the range MINIMUM when fewer remain, so
  the length was 0 on every input a corpus can carry and `parseServerRef` was
  handed `""` for the life of the harness. It also had no corpus, so that empty
  slice was the only input it ever ran. Second defect: the buffer was 128
  octets against this module's own `max_host_len` of 255, so the over-length
  refusal its value test exercises with `"x" ** 256` could never have been
  reached through the harness -- a seed longer than the buffer reads back
  EMPTY. Now one `smith.slice(&buf)` draw over a `max_host_len * 2` buffer, a
  17-seed corpus, and `nextServer` fed the same bytes. Measured: 0 referrals
  extracted before, 4 after (303 host octets, 4 replies chased); the corpus
  guard pins all three, because `parseServerRef("")` returns null rather than
  erroring and an "it did not panic" guard reads 100% on a harness parsing
  nothing.

- **2026-08-23** — **Behavioural:** `TransportError` gains `Canceled`, and
  `TcpTransport` recovers it from the concrete reader and writer instead of
  folding every failure into `TransportFailed`. A canceled lookup was
  indistinguishable from a dead WHOIS server, so a consumer retried a query
  its own caller had already abandoned. `whois` was the one module with this
  shape that the cancelation campaign missed -- its sibling `rdap`, shipped in
  the same commits, was fixed. Covered by a loopback test that parks a real
  read against a peer that never answers; mutation-confirmed by folding the
  reader check back and watching the test report `TransportFailed`.

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on GNU `whois`
  (Debian), BSD `whois` (design reference, not a test anchor).
- **2026-07-07** — New module: RFC 3912 whois client — query format + referral chasing
  (IANA→registrar) + field extraction, transport-agnostic seam.
