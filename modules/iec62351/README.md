# iec62351

IEC 62351 power-systems communication security, applied to **PDU bytes the
caller already has**. Three parts of the series are covered: **62351-6**
(GOOSE/Sampled-Value authentication and replay protection at layer 2),
**62351-4** (MMS/ACSE application authentication), and **62351-3** (the TLS
profile, expressed as a policy you can check rather than a document you can
read). None of them define a protocol of their own — each one wraps or
constrains a protocol specified elsewhere — so this module deliberately parses
no GOOSE PDU, no MMS association and no TLS handshake. It authenticates,
verifies and judges the bytes and parameters you hand it.

That layering is the point. `modules/iec61850` produces GOOSE/SV/MMS bytes;
this module secures them; **neither depends on the other**. A capture from
Wireshark, a frame from a vendor stack and a PDU from `iec61850` all go through
the same entry points.

Provenance: clean-room from public descriptions of IEC 62351-3/-4/-6, whose
text is paywalled — `SPEC.md` states field by field what is grounded and what
is modelled. Primitives come from `std.crypto` (HMAC-SHA-256, AES-GCM/GMAC,
ECDSA P-256), the sibling `rsa` module (RSASSA-PSS) and the sibling `x509`
module (certificate extensions). See `/NOTICE`.

| | |
|---|---|
| platform | `.any` |
| role | `.util` |
| concurrency | `.reentrant` |
| deps | `x509`, `rsa` |

## Import

```zig
const iec62351 = @import("iec62351");
```

`build.zig.zon` dependency, then in `build.zig`:

```zig
exe.root_module.addImport("iec62351", zig_libs.module("iec62351"));
```

## IEC 62351-6 — authenticating a GOOSE or SV frame

You supply the encoded APDU and the link-layer header values; the module
writes the whole frame, from the EtherType onwards, with the security
`Extension` appended and the header fields already set to their final values
before the tag is computed.

```zig
const goose = iec62351.goose;

var frame_buf: [1518]u8 = undefined;
const key = [_]u8{ /* 62351-9 / GDOI-distributed group key */ } ** 32;

const frame = try goose.build(&frame_buf, .{
    .ether_type = goose.ether_type_goose,     // 0x88b8 (0x88ba for SV)
    .appid      = 0x3001,
    .apdu       = encoded_goose_pdu,          // <- bytes from your 61850 encoder
    .auth = .{
        .time_of_current_key = key_epoch_s,
        .time_to_next_key    = minutes_to_rollover,
        .key_id              = 7,
        .tag                 = &.{},          // filled in by `build`
    },
}, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &key } });

// ...send `frame` after your Ethernet MAC header.
```

Receiving:

```zig
const r = goose.verify(received, .ed2020, .{
    .mac = .{ .algorithm = .hmac_sha256_128, .key = &key },
}) catch |err| switch (err) {
    error.AuthenticationFailed => return, // drop, count, alarm
    else => return err,
};

// r.frame.apdu  -> hand to your 61850 decoder
// r.auth.key_id -> which group key was used
```

### Algorithms

| `MacAlgorithm` | tag | notes |
|---|---|---|
| `.hmac_sha256_80` | 10 octets | |
| `.hmac_sha256_128` | 16 octets | |
| `.hmac_sha256_256` | 32 octets | |
| `.aes_gmac_64` | 8 octets | needs a 12-octet IV in the extension |
| `.aes_gmac_128` | 16 octets | needs a 12-octet IV |

Signature profiles are separate `Sealer`/`Verifier` variants, not MAC
algorithms: `.rsa_pss_sha256` (the 2007 edition's profile, using the sibling
`rsa` module) and `.ecdsa_p256_sha256`. Anything else — a national profile, an
HMAC-SHA-3 variant, an HSM — goes through `RawSealer`/`RawVerifier`, a pair of
function-pointer seams that take the same covered range.

### The covered range

`Frame.macDomain()` is the single definition: **EtherType through the end of
the APDU**, including `Length`, `Reserved 1` and `Reserved 2`, excluding the
Extension and excluding Ethernet padding. Use it directly if you need to
compute a tag yourself:

```zig
const f = try goose.parse(bytes, .ed2020);
var tag: [goose.max_mac_len]u8 = undefined;
_ = try goose.computeMac(.hmac_sha256_256, &key, f.macDomain(), null, &tag);
```

### Which edition

`HeaderProfile.ed2020` (the default) reads the presence flag from `Reserved 1`
bit 15 and the extension length from `Reserved 2`. `HeaderProfile.ts2007` puts
the length in the low octet of `Reserved 1` and has no flag bit. Both fields
of `HeaderProfile` are parameters, so a deployment whose equipment reads them
differently says so rather than forking the module.

## IEC 62351-6 §6.2 — replay protection

Pure, time-injected, allocation-free. One guard per stream; you key them by
publisher.

```zig
var guard: iec62351.GooseReplayGuard = .init(.{ .max_state_age_ns = 10 * 1_000_000_000 });

const verdict = guard.accept(.{
    .st_num = pdu.st_num,
    .sq_num = pdu.sq_num,
    .t_ns   = pdu.t_ns,
}, now_ns);            // <- you supply the clock

if (!verdict.accepted()) {
    log.warn("GOOSE replay guard rejected: {t}", .{verdict});
    return;
}
```

`check()` is the same decision without committing, for callers that want to
verify the tag first. Sampled Values use `SvReplayGuard` over `smpCnt`.

Two behaviours worth knowing before you tune the options: GOOSE `t` is the
time of the last *state change*, so its age is only checked when `stNum`
advances (a heartbeat legitimately carries an hour-old `t`); and both counters
wrap, so ordering uses RFC 1982 serial arithmetic unless you turn that off.

## IEC 62351-4 — MMS/ACSE authentication

You own the AARQ/AARE bytes. This module finds, builds and splices the three
authentication fields inside them.

```zig
const acse = iec62351.acse;

// Sending: build the fields and splice them into your AARQ.
var fields_buf: [256]u8 = undefined;
const fields = try acse.buildAuthFields(&fields_buf, .{
    .requirements = .{ .authentication = true },
    .mechanism    = .password_1,                 // ACSE 2.2.3.1
    .value        = .{ .charstring = password },
});
var out: [1024]u8 = undefined;
const aarq = try acse.insertAuthFields(&out, my_aarq, .aarq, fields);

// Receiving: find them and check.
const f = try acse.findAuthFields(received_aarq, .aarq);
if (!f.assertsAuthentication()) return error.NotAuthenticated;
if (!acse.passwordMatches(f.value.?.charstring, expected)) return error.BadPassword;
```

`insertAuthFields` is a splice, not a re-encode: every element it does not
recognise is copied byte-for-byte, so a field this module does not model
cannot be corrupted by passing through it.

For a signed assertion instead of a password:

```zig
var sig_buf: [64]u8 = undefined;
var token_buf: [512]u8 = undefined;
const token = try acse.signToken(&token_buf, &sig_buf, .{
    .ecdsa_p256_sha256 = .{ .key_pair = kp },
}, 1, now_s, "substation-A/client1");

// ...carried in `.value = .{ .other = .{ .mechanism = oid, .value = token } }`

const claim = try acse.verifyToken(token, .{ .ecdsa_p256_sha256 = pk }, now_s, .{
    .max_age_s = 60,
});
```

`SignedToken`'s encoding is **this module's own** — the standard's exact ASN.1
is paywalled. Use `AuthValue.external` / `AuthValue.other` with a vendor's own
bytes when you must interoperate with a specific implementation.

## IEC 62351-3 — the TLS profile as a policy

`zig-libs` ships no TLS server (see `CONVENTIONS.md` §2), which makes this the
most portable of the three parts: whoever terminates TLS reports the negotiated
parameters, and the policy judges them.

```zig
const profile = iec62351.TlsProfile.iec62351_3;   // or `.strict_tls13`, or your own

const report = try profile.check(peer_cert_der, .{
    .version               = .tls12,
    .cipher_suite          = .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
    .mutual_authentication = true,
    .chain_validated       = true,  // you ran x509.verifyChain
    .revocation_checked    = true,  // you ran ocsp / a CRL check
    .age_s                 = session_age,
}, now_s);

if (!report.ok()) {
    log.err("IEC 62351-3 conformance failure: {t}", .{report.first().?});
}
```

`Report` carries the whole `std.EnumSet(Violation)`, so you can log every rule
that failed; `first()` is deterministic. Each knob (`min_version`,
`allowed_cipher_suites`, `min_rsa_bits`, `max_session_age_s`,
`required_purpose`, …) is a documented field, because the exact numeric bounds
differ between editions and claimed profiles.

Three things this policy explicitly does **not** do — it says so in typed form
rather than pretending: it does not build or validate a certificate path (use
`x509.verifyChain` and set `chain_validated`), it does not fetch a CRL or speak
OCSP (use `ocsp`/`ocspcache` and set `revocation_checked`), and it does not
verify the certificate's signature.

## Wiring it to `iec61850`

There is no build dependency between the two modules and there does not need to
be — the seam is a byte slice:

```zig
const iec61850 = @import("iec61850");
const iec62351 = @import("iec62351");

// Publish: encode, then authenticate.
const apdu = try iec61850.goose.encodePdu(&apdu_buf, my_dataset);
const frame = try iec62351.goose.build(&frame_buf, .{
    .appid = cb.appid, .apdu = apdu, .auth = .{ .key_id = key_id, .tag = &.{} },
}, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &group_key } });

// Subscribe: authenticate, replay-check, then decode.
const r = try iec62351.goose.verify(wire, .ed2020, verifier);
const pdu = try iec61850.goose.decodePdu(r.frame.apdu);
if (!guard.accept(.{ .st_num = pdu.st_num, .sq_num = pdu.sq_num, .t_ns = pdu.t }, now_ns).accepted())
    return;
```

(The `iec61850` call names above are illustrative — that module is a sibling,
not a dependency, and this one never calls it.)

Order matters on receive: **authenticate first, then replay-check, then
decode.** The replay counters are only meaningful once the frame is known to be
authentic, and the decoder should never see unauthenticated bytes.

## What this does not protect against

GOOSE authentication is **authentication, not confidentiality** — the frame is
in the clear and anyone on the segment reads your breaker positions. The 3 ms
transfer-time class for a trip message also means the signature profiles are
generally impractical for real trip traffic; the MAC profiles are what a
production deployment uses. And a symmetric group MAC authenticates the
*group*, not the publisher: any holder of the key can forge any publisher's
frames. `SPEC.md` has the full threat model.

## Verify

```sh
zig build test-iec62351                  # Debug
zig build test-iec62351 --release=fast   # ReleaseFast
zig fmt --check modules/iec62351
```
