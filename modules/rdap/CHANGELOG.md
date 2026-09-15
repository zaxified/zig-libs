# rdap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-17** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The `HttpFetcher` body-read cancel test canceled after a fixed
  sleep. It now cancel once the client is inside the socket read under test (`ReadCueIo`, a
  `std.Io` double that counts `netRead` entries), and the peer is released from `accept`
  before `join`. On a loaded full gate the sleep could land the cancel before the connect. The
  peer thread then waited in `accept` forever, the shape that hung `http` in full-gate attempt 3.

- **2026-09-07** — Both fuzz targets had been running on the empty document, and the response
  target's document generator was stuck on one shape. `fuzzParseResponse` and
  `fuzzParseBootstrap` drew their payload with `smith.bytes(&buf)` and then took a length from
  `smith.valueRangeAtMost(u16, 0, 512)`; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, and `bytes` had already
  consumed them — so `len` was 0 every time. `assertMapperReached` kept the target honest
  about the mapper being *reachable*, but nothing the fuzzer produced ever got there.
  ⛔ **`buildFuzzedResponse` drew its member name, its JSON shape and its nesting depth with
  `smith.index`/`smith.valueRangeAtMost` AFTER the byte draw**, so on every replay they were
  all the range minimum: one member (`handle`), one shape (a JSON string), depth 0 — one
  wrapper document for the whole corpus. Those knobs now come out of the payload's own bytes
  via `testkit.fuzz.Cursor`, which keeps them alive on a replay and still lets `--fuzz` drive
  them. ⛔ **The harness buffers were 512 octets while `domain_json` — the module's own RFC
  9083 §5.3 reference document, the one `assertMapperReached` parses — is 1549**, and a seed
  longer than the buffer reads back EMPTY rather than truncated, so that document could never
  have passed through the module's own harness; buffers raised to 2048. Measured: **response 0
  of 12 seeds non-empty, 0 mapped, 0 entities, 1 distinct wrapper document → 11/12 non-empty,
  8 mapped, 2 entities, 5 distinct wrappers; bootstrap 0 of 12 non-empty, 0 parsed, 0 services
  → 11/12, 7 parsed, 5 services.** The bootstrap guard pins `services`, not just `parsed`,
  because a registry file with an empty `services` array is legal.
- **2026-09-02** — Drift re-audit (window `becadd6..HEAD`, +1876/-46). The 2026-07-19 audit closed
  an SSRF on the `related`-link follow; this pass found its guard bypassable two ways, found the
  half of the same finding that was never fixed, and found a third dialing path with no guard at
  all. **BREAKING (minor):** `Client` gains `destinations: DestinationPolicy` (both terms default to
  deny) and `QueryError` gains `BadDestination`/`BlockedDestination`; `HttpFetcher` gains
  `destinations` and `max_redirects`. A caller talking to a plaintext or loopback RDAP server on
  purpose must now say so.

  - **HIGH, the guard checked the address it ASKED for, never the one it REACHED.** `http.Client`
    follows up to ten `Location` hops itself and accepts an absolute cross-origin one verbatim, so
    any server able to send one response bounced the client anywhere it liked — which made the
    whole deny-list decorative and applied to the **primary** fetch too. `HttpFetcher` now follows
    redirects itself, putting every hop through the gate, and bounds the chain at `max_redirects`
    (5) rather than inheriting the client's 10. SPEC's "capped at one hop" was true only of RDAP
    hops.

  - **HIGH, `localhost.` was not `localhost`.** The guard compared the raw string and
    `netaddr.parseIp` rejected the dotted form, so the absolute spelling of the one hostname it
    exists to deny returned false and the hop was dialed — verified reachable on the machine this
    was found on (`getent hosts localhost.` → `::1`). Hosts are now normalised before the compare.

  - **MEDIUM, the scheme-downgrade half of the 2026-07-19 finding was never fixed.** That finding
    named the `http` downgrade in the same sentence as the address SSRF; the fix added the address
    guard alone, and the other half stayed open and recorded nowhere. `require_https` closes it: a
    `related` href cannot walk an exchange whose trust rests on TLS onto plaintext.

  - **MEDIUM, bootstrap-supplied base URLs had no destination check at all.**
    `Bootstrap.lookupDomain` returns service URLs parsed straight out of an untrusted registry file,
    and the module's own example feeds `urls[0]` to `query`. A bootstrap naming
    `http://169.254.169.254/` sent every query there. The primary URL is now gated like any other.

  - **LOW, both fuzz harnesses held nothing.** 512 uniform random bytes never form JSON, so the
    tolerant mapper — the actual untrusted-input surface — was never reached, and `catch return`
    turned every outcome into a pass. Each harness now runs an aim canary that fails if the mapper
    stops being reached, switches on the declared error set instead of swallowing, and feeds the
    fuzzer's bytes *inside* a well-formed RDAP/bootstrap document.

  Doc corrections: SPEC claimed `goldens.zig` carries "the real IANA bootstrap file" (it holds
  exactly one constant, and its own comment says the bootstrap file was checked rather than
  captured), and "no test touches the network" while three tests bind a loopback socket.


- **2026-08-22** — Competitive-survey gaps (vs. `icann-rdap`/`openrdap`), **BREAKING**:
  `Entity` gained `entities: []const Entity` — its own nested `entities[]` (RFC 9083
  §5.1, e.g. registrar → abuse contact), previously silently dropped; recursion is
  bounded by the new `max_entity_depth` (8), past which deeper nesting is dropped
  rather than erroring (this module's tolerant-parsing policy). `Client.query` gained
  a trailing `status_out: ?*u16` parameter — every call site needs updating — filled
  with the real HTTP status when (and only when) `error.HttpStatus` is returned, so a
  caller can finally tell a 429 rate limit from a 500 server error (previously
  indistinguishable, and this module has no client-side rate limiting of its own to
  compensate). Sweep of the real captured golden (`goldens.zig`) against the model
  turned up four more silently-dropped or never-modeled fields, all fixed the same
  way: `Object`/`Entity.public_ids` (`publicIds[]`, RFC 9083 §4.8), `Object.redacted`
  (`redacted[]`, RFC 9537 GDPR disclosures), `Object.rdap_conformance`
  (`rdapConformance[]`, RFC 9083 §4.1), `Entity.links`, and `Nameserver.handle` +
  `.status` + `.ipv4_addresses`/`.ipv6_addresses` (a nameserver is itself an RDAP
  object with its own handle, RFC 9083 §5.2). `secureDNS`/`dsData` was found and
  dismissed — see SPEC.md's Backlog section for why. All additions proven against the
  real golden fixture where it exercises them; every new/changed behavior has a
  mutation proof (revert → red, restore → green). 29 tests before, 33 after.
- **2026-08-22** — `HttpFetcher.fetchFn` no longer folds a canceled body read into
  `error.FetchFailed`: `FetchError` gained a `Canceled` variant, and the request +
  both `readSliceShort` sites now consult `http.Client.Response.readFailure()`
  (added in `2c03d99` for exactly this) via a new `mapFetchError` widener. Public
  API addition — a caller matching exhaustively on `FetchError`, `QueryError`, or
  any error set built from them needs a new arm. Proven by mutation: reverting the
  widener to always return `FetchFailed` fails the new cancellation test.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on ICANN RDAP
  tooling, `python-whois`/`rdap` libs, ARIN/RIPE RDAP servers (design reference, not a
  test anchor).
- **2026-07-07** — New module: RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois
  successor: query URLs, typed response model, IANA bootstrap, fetch seam.
