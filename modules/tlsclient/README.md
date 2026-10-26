# tlsclient

std's TLS client (TLS 1.3 and 1.2), made into a client a Go programmer
recognises: Go `crypto/tls`'s defaults and options (S2 parity, 2026-10-13),
on top of the fix it was forked for. The fix: the certificate chain a
server sends is verified by RFC 5280 path validation (`x509.verifyChain`), not
link by link. Zig 0.16's `std.crypto.tls.Client` (not re-diffed on 0.17) checks the issuer name, the
validity and the signature of each link and nothing else -- no
basicConstraints, pathLenConstraint or keyUsage (ziglang/zig #35877) -- so
anyone holding one valid certificate for any name can sign a leaf for any
other name with its key, put it in front of its own chain, and std's client
accepts it. This module refuses that chain, and parses no peer certificate
before `x509.safe` has proven its DER in bounds. It also fixes five
server-triggerable crashes and a KeyUpdate desynchronisation found in std's
code (SPEC.md).

**Status:** gap -- a fork of one std file, to be retired when std fixes
#35877. `interop_test.zig` carries a tripwire: the same forged chain offered
to std's client must still be ACCEPTED; the day that test goes red, std has
the fix and this module goes.

**Model after:** Zig 0.16.0 `std.crypto.tls.Client` (the code itself, copied)
+ RFC 5280 §6.1 via this collection's `x509`.

## Use

The API is std's, with two optional `Options` fields. Swap the import:

```zig
const tls = @import("tlsclient"); // was: std.crypto.tls
var client = try tls.Client.init(&net_reader.interface, &net_writer.interface, .{
    .host = .{ .explicit = "example.com" },
    .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &lock, .bundle = &bundle } },
    .read_buffer = &tls_in,
    .write_buffer = &tls_out,
    .entropy = &entropy,
    .realtime_now = std.Io.Clock.real.now(io),
});
```

`Client.initInto(&client, reader, writer, options)` is the same handshake
writing the session to `client` in place: `init`'s by-value return leaves a
copy of the application traffic keys on the dead stack, `initInto` does not.

What changes for a caller: a chain std would have accepted is refused with
`error.TlsCertificateNotVerified` when an issuer in it is not a CA, a
pathLen/keyUsage/nameConstraints rule is broken, or the leaf's extKeyUsage
excludes serverAuth. `http.Client` uses this module for every https dial.

## Go's defaults, and the options beyond std's

With no extra options the handshake is Go's client's: groups X25519MLKEM768,
X25519, P-256, P-384, P-521 with shares for the first two (a server wanting
another asks with a HelloRetryRequest), OCSP and SCTs requested, TLS 1.2
extended master secret and renegotiation_info offered, host names matched
against SANs only (RFC 9525; an IP host against iPAddress SANs, sent without
SNI), a server's request for a client certificate answered with an empty
Certificate when none is configured (std fails the handshake), and server
keys on P-256, P-384 and P-521 verified with any ECDSA hash in TLS 1.2.
std's ClientHello stays reachable: `.groups = &tls.Client.std_groups,
.key_share_groups = &tls.Client.std_groups` plus the four request flags off
(it differs from std's only by the three ECDHE_ECDSA suites and
ecdsa_secp521r1_sha512).

The behaviour is checked live against Go's: `zig build interop-tlsclient`
runs 90 cases against Go's crypto/tls server and compares with Go's client.

```zig
var storage: [16 * 1024]u8 = undefined;
var info: tls.Client.ConnectionInfo = .init(&storage);
var entries: [8]tls.Client.ClientSession = undefined;
var cache: tls.Client.SessionCache = .init(&entries, null); // shared: pass a std.Io.Mutex
const key: tls.Client.ClientAuth.PrivateKey = .{ .ecdsa_secp256r1_sha256 = scalar }; // or P-384, .ed25519, .rsa = &rsa_pair
var client = try tls.Client.init(&r.interface, &w.interface, .{
    // ... std's options ...
    .min_version = .tls_1_3,                            // Go MinVersion / MaxVersion
    .groups = &.{ .x25519, .secp256r1 },                // Go CurvePreferences
    .key_share_groups = &.{.x25519},
    .alpn_protocols = &.{ "h2", "http/1.1" },          // RFC 7301 offer
    .client_auth = .{ .certificate_chain = &.{ leaf_der, intermediate_der }, .key = &key },
    // or .client_auth_select = .{ .context = ctx, .select = pick }  (Go GetClientCertificate)
    .connection_info = &info,                           // Go ConnectionState
    .verify_connection = .{ .context = ctx, .verify = check }, // Go VerifyConnection
    .session_cache = &cache,                            // TLS 1.3 resumption (Go ClientSessionCache)
});
const proto = client.alpn_protocol;                     // ?[]const u8, one of ours
var km: [32]u8 = undefined;
try client.exportKeyingMaterial("EXPERIMENTAL-my-proto", null, &km); // RFC 8446 §7.5 / RFC 5705
```

- **ConnectionInfo:** version, suite, group, ALPN, HRR, resumption, EMS, the
  peer's certificates, the stapled OCSP response and the SCTs, copied into
  your storage (`ConnectionInfoTooSmall` rather than truncation).
- **verify_connection** runs once the server is authenticated (also on a
  resumed session, with the chain kept from the first one), before the
  client Finished; an error is `TlsConnectionRejected`.
- **Client certificates** in TLS 1.3 and 1.2: ECDSA P-256/P-384, Ed25519 (1.3
  only) and RSA (PSS in 1.3; PKCS#1 v1.5 or PSS in 1.2), the scheme picked
  from the server's list. With no acceptable key an empty Certificate is sent
  (RFC 8446 §4.4.2.3) and the server decides.
- **Resumption:** TLS 1.3 tickets, psk_dhe_ke (a fresh ECDHE still runs), no
  0-RTT; not TLS 1.2. ECH is not supported (deferred).
- **KeyUpdate:** answered when the server asks, and sent on our own after
  2^23 records.

Provenance: Zig 0.16.0 `lib/std/crypto/tls/Client.zig` copied under the MIT
license (see ./NOTICE); the change is this collection's.
