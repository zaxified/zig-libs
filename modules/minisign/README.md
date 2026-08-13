# minisign

Signing and verification in the **minisign** file format
(github.com/jedisct1/minisign) — a compact GPG alternative for signing
files/releases: Ed25519 signatures over a small `untrusted comment:` /
base64-payload text framing, with an optional password-encrypted (scrypt)
secret key.

**Status: complete** — public/secret-key and signature-file parsing +
writing, both signature algorithms (legacy `"Ed"` over the raw file, and
the modern prehashed `"ED"` over a BLAKE2b-512 digest), the trusted-comment
global signature, and scrypt secret-key encryption/decryption. **Byte-exact
KAT-validated against real output from the `minisign` 0.12 reference binary**
(both signing *and* verifying — see `src/kat_vectors.zig` and
`src/kat_test.zig`), not just self round-trips. See `SPEC.md` for the wire
format and design notes.

| File | Contents |
|---|---|
| `src/root.zig` | Raw struct codecs, text-file parse/write, `KeyPair`, sign/verify, scrypt seal/open |
| `src/kat_vectors.zig` | Real `minisign`-generated fixtures (keys + signatures), embedded |
| `src/kat_test.zig` | Byte-exact KAT assertions + negative tests |

## Import

```zig
const minisign = @import("minisign");
```

## API surface

```zig
pub const Algorithm = enum { legacy, prehashed };

pub const RawPublicKey = struct { sig_alg: [2]u8, key_number: [8]u8, key: [32]u8 };
pub const RawSecretKey = struct { /* sig_alg/kdf_alg/chk_alg/salt/ops_limit/mem_limit/key_number/secret_key/checksum */ };
pub const RawSignature = struct { sig_alg: [2]u8, key_number: [8]u8, signature: [64]u8 };

pub const KeyPair = struct {
    key_number: [8]u8,
    ed25519: std.crypto.sign.Ed25519.KeyPair,

    pub fn generate(io: std.Io) KeyPair;
    pub fn publicKey(self: KeyPair) RawPublicKey;
    pub fn toRawSecretKeyPlain(self: KeyPair) RawSecretKey;
};

// scrypt encryption of the secret key (ops_limit_sensitive/mem_limit_sensitive
// are the CLI's own defaults; ops_limit_interactive/mem_limit_interactive the
// lighter preset)
pub fn sealSecretKey(allocator, key_pair: KeyPair, password: []const u8, salt: [32]u8, ops_limit: u64, mem_limit: usize) !RawSecretKey;
pub fn openSecretKey(allocator, raw: RawSecretKey, password: ?[]const u8) !KeyPair; // password null only for an unencrypted key

// text file parse (borrows comment slices from the input) / write (to a std.Io.Writer)
pub fn parsePublicKeyFile(text: []const u8) !ParsedPublicKey;
pub fn parseSecretKeyFile(text: []const u8) !ParsedSecretKey;
pub fn parseSignatureFile(text: []const u8) !ParsedSignature;
pub fn writePublicKeyFile(w: *std.Io.Writer, untrusted_comment: []const u8, key: RawPublicKey) !void;
pub fn writeSecretKeyFile(w: *std.Io.Writer, untrusted_comment: []const u8, key: RawSecretKey) !void;
pub fn writeSignatureFile(w: *std.Io.Writer, untrusted_comment: []const u8, signature: RawSignature, trusted_comment: []const u8, global_signature: [64]u8) !void;

// sign / verify
pub fn signFile(allocator, key_pair: KeyPair, message: []const u8, algorithm: Algorithm, trusted_comment: []const u8) !SignedFile;
pub fn verifyFile(allocator, public_key: RawPublicKey, message: []const u8, parsed: ParsedSignature) !void;
```

## Example

```zig
const minisign = @import("minisign");
const io = ...; // std.Io instance

// Generate a key pair and sign a message.
const kp = minisign.KeyPair.generate(io);
const signed = try minisign.signFile(gpa, kp, message, .prehashed, "release v1.2.3");

var buf: [1024]u8 = undefined;
var w: std.Io.Writer = .fixed(&buf);
try minisign.writeSignatureFile(&w, "signature from minisign secret key", signed.signature, "release v1.2.3", signed.global_signature);

// Verify a signature file against a public key file.
const pk = try minisign.parsePublicKeyFile(pub_key_text);
const parsed = try minisign.parseSignatureFile(sig_file_text);
try minisign.verifyFile(gpa, pk.key, message, parsed); // error.SignatureVerificationFailed / .KeyIdMismatch on failure
```

## Verify

```
zig build test-minisign --summary all
zig build test-minisign -Doptimize=ReleaseFast --summary all
```

Provenance: clean-room from the minisign wire-format facts in
jedisct1/minisign's `minisign.h`/`minisign.c` (ISC License), cross-checked
byte-exact against the real `minisign` 0.12 binary. One function —
`isPrintableComment` — is a port of minisign.c's `is_printable`; see this
module's own `NOTICE`, which carries the required ISC attribution, and
`SPEC.md`.
