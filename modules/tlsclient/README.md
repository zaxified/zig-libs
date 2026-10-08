# tlsclient

std's TLS client (TLS 1.3 and 1.2), with one fix and two opt-in additions.
The fix: the certificate chain a
server sends is verified by RFC 5280 path validation (`x509.verifyChain`), not
link by link. Zig 0.16's `std.crypto.tls.Client` checks the issuer name, the
validity and the signature of each link and nothing else -- no
basicConstraints, pathLenConstraint or keyUsage (ziglang/zig #35877) -- so
anyone holding one valid certificate for any name can sign a leaf for any
other name with its key, put it in front of its own chain, and std's client
accepts it. This module refuses that chain, and parses no peer certificate
before `x509.safe` has proven its DER in bounds.

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

What changes for a caller: a chain std would have accepted is refused with
`error.TlsCertificateNotVerified` when an issuer in it is not a CA, a
pathLen/keyUsage/nameConstraints rule is broken, or the leaf's extKeyUsage
excludes serverAuth. `http.Client` uses this module for every https dial.

## Additions (off by default; with the defaults the handshake is std's, byte for byte)

```zig
const key: tls.Client.ClientAuth.PrivateKey = .{ .ecdsa_secp256r1_sha256 = scalar }; // or .ecdsa_secp384r1_sha384 / .ed25519
var client = try tls.Client.init(&r.interface, &w.interface, .{
    // ... std's options ...
    .alpn_protocols = &.{ "h2", "http/1.1" },          // RFC 7301 offer
    .client_auth = .{                                   // TLS 1.3 client certificate
        .certificate_chain = &.{ leaf_der, intermediate_der },
        .key = &key,                                    // borrowed for the connection
    },
});
const proto = client.alpn_protocol; // ?[]const u8, one of ours
```

- **ALPN:** a server answer that is not exactly one of the offered names is
  `TlsIllegalParameter`; a server that refuses all of them sends
  no_application_protocol (`TlsAlert`).
- **Client certificates (TLS 1.3 only):** answered with Certificate +
  CertificateVerify (RFC 8446 §4.4.3). When the server's CertificateRequest
  does not accept our key's scheme, an empty Certificate is sent (RFC 8446
  §4.4.2.3) and the server decides. Without `client_auth`, and in TLS 1.2, a
  CertificateRequest is `TlsUnexpectedMessage`, as in std. RSA keys and
  session resumption are not supported.

Provenance: Zig 0.16.0 `lib/std/crypto/tls/Client.zig` copied under the MIT
license (see ./NOTICE); the change is this collection's.
