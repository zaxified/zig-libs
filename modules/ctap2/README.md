# ctap2

The CTAP 2.1 (FIDO2) client side of `authenticatorClientPIN` over a
caller-supplied transport. The sibling `ctap2pin` is the `pinUvAuthProtocol`
crypto (encapsulate, encrypt, decrypt, authenticate); this module is the command
layer above it, so PIN handling is one call, not a page of primitives.

- **Framing** — request = command byte || CBOR map, response = status byte ||
  optional CBOR, over `Transport` (a `ctx` and one `transact` function). No device
  I/O lives here.
- **Status codes** — all of CTAP 2.1 §8.2 as named Zig errors: `error.PinInvalid`
  (0x31), `PinBlocked` (0x32), `PinAuthInvalid` (0x33), `PinAuthBlocked` (0x34),
  `PinNotSet` (0x35), `PuatRequired` (0x36), `PinPolicyViolation` (0x37), ...;
  anything unassigned is `error.UnknownStatus`.
- **`authenticatorGetInfo`** — versions, aaguid, the PIN-relevant options
  (`clientPin`, `pinUvAuthToken`, `uv`, ...), `pinUvAuthProtocols`, `maxMsgSize`,
  `minPINLength`, `forcePINChange`. Unknown keys are ignored, wrong types are errors.
- **`authenticatorClientPIN`** — `getPINRetries`, `getKeyAgreement`, `setPIN`,
  `changePIN`, `getPinToken` (legacy), `getPinUvAuthTokenUsingPinWithPermissions`,
  `getPinUvAuthTokenUsingUvWithPermissions`, `getUVRetries`, on both PIN/UV
  protocols, with the spec's PIN rules (>= 4 code points or `minPINLength`,
  <= 63 bytes UTF-8, padded to 64) checked before anything is sent.
- **CTAPHID** — the 64-byte init/continuation report codec, `CTAPHID_INIT`, and a
  `Channel` that runs a `CTAPHID_CBOR` transaction (keep-alives skipped) over a
  report reader/writer you provide.
- **Model after:** CTAP 2.1 §6.4, §6.5.5, §8.2, §11.2, clean-room. **Oracle:** for
  every subcommand and both protocols the request bytes equal python-fido2 2.2.1's
  byte for byte (`src/fido2_vectors.zig`, recipe in `tools/gen_fido2_vectors.py`).
  See `NOTICE`.
- **Platform:** any. **Role:** codec. **Deps:** `cbor`, `ctap2pin`.

```zig
const ctap2 = @import("ctap2");

// `transport` wraps your device: send request bytes, return response bytes.
const info = try ctap2.getinfo.get(gpa, transport, 1200);
var client = ctap2.Client.fromInfo(gpa, transport, csprng.random(), info).?;

const retries = try client.getPinRetries();
var token = client.getPinUvAuthTokenUsingPin(pin, .{ .mc = true, .ga = true }, "example.com") catch |err| switch (err) {
    error.PinInvalid => return askAgain(retries),
    error.PinBlocked, error.PinAuthBlocked => return showLockedOut(),
    else => return err,
};
defer token.deinit(); // wipes it
const pin_uv_auth_param = token.authenticate(&client_data_hash);
```

**Handling notes.** Each call runs a fresh key agreement and wipes the shared secret,
the padded PIN and the PIN hash before it returns; a `Token` is wiped by `deinit`.
The random source must be cryptographically secure (ECDH scalar, protocol-Two IVs).
The PIN must arrive in Unicode Normalization Form C: there is no normalizer in
`std`, so this module validates UTF-8 and counts code points but does not normalize
(SPEC.md, Backlog). A wrong PIN costs a retry on the device: `error.PinInvalid`
means "ask again", and after a `PinAuthBlocked` the authenticator needs a power
cycle.

Provenance: clean-room from the FIDO Alliance CTAP 2.1 specification, a public
specification; no CTAP implementation's source was consulted. python-fido2 was run
as a black-box test oracle only (see [`NOTICE`](NOTICE)).
