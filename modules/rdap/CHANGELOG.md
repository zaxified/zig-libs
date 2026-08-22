# rdap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
