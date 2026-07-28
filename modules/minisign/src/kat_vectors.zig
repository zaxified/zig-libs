// SPDX-License-Identifier: MIT
//! minisign KAT fixtures — generated with the REAL `minisign` reference
//! binary (Debian/Ubuntu package `minisign 0.12`, upstream
//! github.com/jedisct1/minisign, ISC License), run locally as a black-box
//! oracle:
//!
//! ```
//! minisign -G -W -f -p unenc.pub -s unenc.key -c "unencrypted test key"
//! printf 'Hello, minisign!\nThis is a test file for byte-exact KAT vectors.\n' > message.txt
//! minisign -S      -s unenc.key -m message.txt -x message.txt.minisig    -t 'trusted comment test 1' -c 'untrusted comment test 1'
//! minisign -S -l    -s unenc.key -m message.txt -x message.legacy.minisig -t 'trusted comment test 1' -c 'untrusted comment test 1'
//! printf 'correct horse battery staple\ncorrect horse battery staple\n' \
//!   | minisign -G -f -p enc.pub -s enc.key -c "encrypted test key"
//! printf 'correct horse battery staple\n' \
//!   | minisign -S -s enc.key -m message.txt -x message.enc.minisig -t 'trusted comment test 2' -c 'untrusted comment test 2'
//! ```
//!
//! All four `minisign -V ...` round-trips against these files exited 0
//! ("Signature and comment signature verified") before these bytes were
//! transcribed here — i.e. this is exactly what a real, independent
//! implementation produces and accepts, not merely what this module
//! produces for itself.

pub const message = "Hello, minisign!\nThis is a test file for byte-exact KAT vectors.\n";

/// `minisign -G -W` (no password) — public key file.
pub const unencrypted_public_key_file =
    "untrusted comment: minisign public key 5903374ED1B3A96B\n" ++
    "RWRrqbPRTjcDWR+hvUZ2BYnUPaYtAU2xk0146dflSNd10pwDxEeKNVLj\n";

/// The matching unencrypted secret key file (`kdf_alg` is all-zero; `chk`
/// is all-zero too — see root.zig's doc comment on why).
pub const unencrypted_secret_key_file =
    "untrusted comment: unencrypted test key\n" ++
    "RWQAAEIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa6mz0U43A1kZQgM6YBcHa4ywuTlslU0TY3zS8YcXZXbYryKEj4VLtR+hvUZ2BYnUPaYtAU2xk0146dflSNd10pwDxEeKNVLjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";

/// `minisign -S` (default: prehashed `"ED"`, deterministic Ed25519) over
/// `message`, signed with the unencrypted key above.
pub const prehashed_signature_file =
    "untrusted comment: untrusted comment test 1\n" ++
    "RURrqbPRTjcDWcueu7gybG96z3O20z7eWZN44uD15O96JlZb9SW3MQ0qNUR9nW2fXFD5g/wA4Po/zjKl2tDJUkg0ARRHA+uF5g4=\n" ++
    "trusted comment: trusted comment test 1\n" ++
    "r/2VcJC/XQ1YM8Ru1eHrKo2mkKfJvN4LS1NeuP8yHylajSPmdDrEX8Gpt0h56A4D2j++qvM9FoXomwZB8MwqCQ==\n";

/// `minisign -S -l` (legacy `"Ed"`) over the same `message` + same key +
/// same trusted comment text.
pub const legacy_signature_file =
    "untrusted comment: untrusted comment test 1\n" ++
    "RWRrqbPRTjcDWcLb8uuGmtBsE40m0mkeVw1WrWGxwId3qhg0MkVG0szb831EJ6VgJgqjKSXsmsTfsF1Jg9ML5byHbFFeO/KUBAA=\n" ++
    "trusted comment: trusted comment test 1\n" ++
    "dH2MKr0JfhOpuFQ9UEWI0cnjTFdHXcyE//6GiY6oECtvwtgAW6Gg2soEfX1UamStxSt5hhWws4TyrcO4oBD9Dw==\n";

/// `minisign -G` with password `"correct horse battery staple"` (default
/// scrypt cost: `ops_limit_sensitive`/`mem_limit_sensitive`) — public key.
pub const encrypted_public_key_file =
    "untrusted comment: minisign public key 0384580E00615CD3\n" ++
    "RWTTXGEADliEA0ZCxYXlxXuf1lDyGwf0qiZ3CQF51Zzrh2v5kh5jaYlT\n";

/// The matching password-encrypted secret key file.
pub const encrypted_secret_key_file =
    "untrusted comment: encrypted test key\n" ++
    "RWRTY0IyZ86v6pVhsOuCkAo65ypJIdemlnJtxVIiOZXFVBk9HAcAAAACAAAAAAAAAEAAAAAAbZ3TED2oTBBHoLlsfJ8SO+t1v/jc2dfpQBhfv7+Deb4dxx8d0Tj6JUNLSJ2kjDfmEaKt8JZLSpfkCXiZpUSEdPF9uSpTTVXh933Px3XE/96v3p1Q3BrDOpYq/w4b5gx5uoHzr2GBOZA=\n";

/// The password used for the above (transcribed exactly; the CLI strips the
/// trailing newline from piped stdin before using it — see get_line.c
/// `trim()`).
pub const encrypted_secret_key_password = "correct horse battery staple";

/// `minisign -S` (prehashed, default) over `message`, signed with the
/// password-encrypted key above.
pub const encrypted_key_signature_file =
    "untrusted comment: untrusted comment test 2\n" ++
    "RUTTXGEADliEAyhpv2TCrLbd62OajzQ3/Z9rTAnLYjSPQ28aQ4Dm7PS31aVY+wgyCEBfkMB6eAShE0He+xu0UBdEhITfEehmMwk=\n" ++
    "trusted comment: trusted comment test 2\n" ++
    "CmtZ/Ds+qPOlBooxfrySlZcTMynncUmuwaMW03KNHjZuxqvk3nX9H26+qsLfcSc2PWA/sUqj6HZ3Jt24JlFXDw==\n";
