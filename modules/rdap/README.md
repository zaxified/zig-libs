# rdap

**RFC 7480–7484** RDAP client — the JSON-over-HTTPS successor to whois
(queries/responses renumbered as RFC 9082/9083, bootstrap as RFC 9224).
Pairs with the `whois` module.

- **Status:** `gap` — no typed, offline-testable RDAP client in the Zig
  ecosystem.
- **Model after:** RFC 7480–7484 RDAP; ARIN/RIPE RDAP behavior.
- **Provenance:** clean-room from RFCs 7480/7482/7483/7484/9224 (plus their
  9082/9083 renumberings). No third-party RDAP implementation consulted or
  copied.
- **Why:** whois replies are freeform text per registry; RDAP is the same
  data as structured JSON over HTTPS. This module owns the three protocol
  layers — query-URL construction with correct percent-encoding, a tolerant
  typed response model (servers vary wildly), and the IANA bootstrap
  resolution that answers "which server is authoritative for this
  TLD/IP/ASN".
- **Platform:** any (pure logic over a fetch seam; only the optional
  `HttpFetcher` uses the `http` module). **Role:** client.
  **Concurrency:** reentrant (no shared state).
  **Deps:** `http` (Accept header type + default fetcher), `netaddr`
  (bootstrap CIDR matching).

## API

```zig
const rdap = @import("rdap");

// Query URLs (RFC 9082): "<segment>/<percent-encoded value>"
var buf: [rdap.max_url_len]u8 = undefined;
_ = try rdap.buildPath(&buf, .domain, "example.com"); // "domain/example.com"
_ = try rdap.buildPath(&buf, .ip, "192.0.2.0/24");    // "ip/192.0.2.0%2F24"
_ = try rdap.buildPath(&buf, .autnum, "65536");       // "autnum/65536"
const url = try rdap.buildUrl(&buf, "https://rdap.example/", .domain, "example.com");
_ = rdap.accept_header; // { "Accept", "application/rdap+json" } (RFC 7480 §4.2)

// Response model (RFC 9083) — tolerant of sparse/extra/wrong-typed members
var parsed = try rdap.parseResponse(gpa, json_bytes); // Parsed, arena-owned
defer parsed.deinit();
switch (parsed.document) {
    .object => |o| {
        _ = o.object_class;                 // .domain / .ip_network / .autnum / …
        _ = o.ldh_name;                     // + handle, status, nameservers, links…
        _ = o.eventDate("expiration");      // events by action
        _ = o.entityWithRole("registrar");  // roles + jCard fn/org/email best-effort
        _ = o.linkHref("related");          // registry → registrar link
    },
    .rdap_error => |e| _ = e.error_code,    // RFC 7480 §5.3 typed error
}

// Bootstrap (RFC 9224): IANA registry file → authoritative base URL
var b = try rdap.parseBootstrap(gpa, iana_dns_json);
defer b.deinit();
_ = b.lookupDomain("example.com"); // ?[]const []const u8 (service URLs)
_ = b.lookupIp("192.0.2.7");       // longest-prefix CIDR match (via netaddr)
_ = b.lookupAsn(65536);            // "start-end" range keys
_ = rdap.bootstrapLookup(&b, "com"); // exact-key primitive

// Client over the fetch seam ("GET url → status + body"); offline testable
var client: rdap.Client = .{ .fetcher = my_fetcher, .gpa = gpa };
var body_buf: [64 * 1024]u8 = undefined;
var doc = try client.query("https://rdap.verisign.com/com/v1", .domain,
    "example.com", .{ .follow_related = true }, &body_buf);
defer doc.deinit();

// Optional real fetcher over our http.Client (the only network-touching code)
var hf: rdap.HttpFetcher = .{ .client = &http_client };
client.fetcher = hf.fetcher();
```

HTTP 404 maps to `error.NotFound`; a non-2xx status with an RDAP error body
returns the typed `rdap_error` document; non-2xx without one is
`error.HttpStatus`. No test touches the network.
