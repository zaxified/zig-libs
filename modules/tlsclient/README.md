# tlsclient

std's TLS client (TLS 1.3 and 1.2), with one change: the certificate chain a
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

The API is std's, unchanged. Swap the import:

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

Provenance: Zig 0.16.0 `lib/std/crypto/tls/Client.zig` copied under the MIT
license (see ./NOTICE); the change is this collection's.
