# acmedns

ACME DNS-01 for [`acme`](../acme): everything around the DNS provider call.
`Dns01Solver` is an `acme.Client.Solver` that follows the
`_acme-challenge.<domain>` CNAME delegation, finds the zone by its SOA,
publishes through a `Publisher`, and returns only once every authoritative
server of the zone answers with the value. Four generic publishers cover a DNS
setup without a vendor API:

| publisher | what it does | the same thing elsewhere |
|---|---|---|
| `Rfc2136` | RFC 2136 dynamic update to the zone's primary, TSIG-signed (`dns.update`, `dns.tsig`) | lego `rfc2136`, certbot `dns-rfc2136`; BIND, Knot, PowerDNS, Windows DNS |
| `AcmeDns` | joohoi/acme-dns: `POST /update` with `X-Api-User`/`X-Api-Key`; `AcmeDns.register` for a new account | lego `acme-dns`, certbot `acme-dns-auth` |
| `HttpReq` | `POST <endpoint>/present` and `/cleanup`, JSON `{fqdn, value}` or RAW `{domain, token, keyAuth}`, optional basic auth | lego `httpreq` |
| `Exec` | runs `<program> present|cleanup <fqdn.> <value>` (or RAW `-- <domain> <token> <keyAuth>`), exit 0 = done | lego `exec` |

A sibling of `acme` rather than part of it: DNS-01 needs a resolver (`dns`) and
the publishers `procrun`, which an `acme` consumer solving HTTP-01 or
TLS-ALPN-01 should not carry — the same split as certmagic + libdns, or lego's
core + its providers.

- **Model after:** lego (`challenge/dns01` + providers `rfc2136`, `acmedns`,
  `httpreq`, `exec`), certmagic `DNS01Solver`.
- **Deps:** `acme` (the solver seam, the TXT value), `dns` (resolver,
  RFC 2136 + TSIG), `http` (acme-dns, httpreq), `netaddr`, `procrun` (exec).

## Usage

```zig
const acme = @import("acme");
const acmedns = @import("acmedns");
const dns = @import("dns");

// The TSIG key as the DNS server has it (BIND: key "acme." { algorithm
// hmac-sha256; secret "<base64>"; };).
var secret_buf: [64]u8 = undefined;
const key: dns.tsig.Key = .{ .name = "acme.", .secret = try dns.tsig.decodeSecret(&secret_buf, secret_b64) };

var rfc2136 = acmedns.Rfc2136.init(io, gpa, .{ .server = primary_ip, .key = &key });
var solver = acmedns.Dns01Solver.init(io, gpa, .{ .publisher = rfc2136.publisher() });
defer solver.deinit();

var client = acme.Client.init(io, gpa, &http_client, &account_key, .{
    .directory_url = acme.letsencrypt_staging,
    .challenge_type = .dns_01,
    .solvers = &.{solver.solver()},
});
defer client.deinit();
var cert = try client.obtain(&.{ "example.org", "*.example.org" });
defer cert.deinit(gpa);
```

`Dns01Solver.Options` (defaults in brackets): `resolvers` [resolv.conf],
`follow_cname` [true], `override_name`, `zone` [SOA walk],
`check_propagation` [true], `authoritative` [the zone's NS records],
`require_all_authoritative` [true], `check_resolvers` [false],
`propagation_timeout_ms` [120 000], `propagation_interval_ms` [2 000],
`delay_ms` [0]. After a failure, `solver.note` (and each publisher's `note`,
`last_rcode` / `last_status` / `last_term`, `Exec.lastStderr()`) says why.

A publisher of your own is a `Publisher` vtable: `present` must ADD the value
(a wildcard and its base name validate at the same name at once), `cleanup`
removes exactly that value.

⚠ `Exec` children inherit the environment of the `std.Io` they are spawned
through: build `std.Io.Threaded` with `.environ = init.environ`, or the program
starts with an empty environment (Zig 0.16).

## Tests

`zig build test-acmedns`: the solver's bookkeeping without a network (the record
the publisher sees, the RFC 8555 §8.4 value, two values at one name, cleanup by
domain and value, failure paths, the `acme.Client.Solver` vtable), the TXT
matcher, basic auth against RFC 7617's example.

`modules/acmedns/tools/interop.sh` (under `hw run`): live, against a DNS server
with two zones and RFC 2136 + TSIG (dnspython), an acme-dns API stand-in, an
httpreq endpoint, and Pebble resolving through that DNS server — one issued
certificate per publisher, see [`tools/README.md`](tools/README.md).

Provenance: original work of the zig-libs authors (MIT). Design references,
behaviour only, no source read or copied: lego (MIT) — the `dns01` flow and the
`rfc2136`/`acmedns`/`httpreq`/`exec` provider protocols as its documentation
describes them; certmagic (Apache-2.0) — `DNS01Solver`'s options; joohoi/acme-dns
(MIT) — the `/register` and `/update` API from its README. Committed data: none
but our own tooling — `tools/peer.py`, `tools/interop.sh` and `tools/exec_nsupdate.sh` were
written here; Pebble, dnspython and BIND's `nsupdate` are run as black-box oracles, never vendored.
