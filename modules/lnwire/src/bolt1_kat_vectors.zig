// SPDX-License-Identifier: MIT
//
// Vendored from `lightningdevkit/rust-lightning`'s `lightning/src/ln/msgs.rs`
// test module (`encoding_init`, `encoding_error`, `encoding_warning`,
// `encoding_ping`, `encoding_pong`, fetched 2026-08-08) -- see
// modules/lnwire/NOTICE for the required MIT/Apache-2.0 attribution.
//
// IMPORTANT -- no message-type prefix: same convention as
// `bolt2_channel_management_kat_vectors.zig` -- rust-lightning's
// `Writeable`/`.encode()` emits only the message's own fields, never
// BOLT#1's 2-byte `type` field. `bolt1_kat_test.zig` prepends this module's
// own frame type before driving `decode*`, and strips it back off before
// comparing `serialize*`'s output against `payload_hex`.
//!
//! BOLT#1 base-protocol byte-exact wire vectors: `init` (two of upstream's
//! five sub-cases -- the ones with no legacy-globalfeatures derivation, so
//! every input byte in the vector is the literal field value, not a
//! backward-compat transform of it), `error`/`warning` (share one wire
//! layout) and `ping`/`pong`.

/// `init`, upstream sub-case 2: `globalfeatures = features = [0xff]` (1
/// byte each — this sub-case is the one where rust-lightning's encoder
/// happens to emit the same bytes for both, so one constant covers both
/// fields), no `networks`, no `remote_network_address`.
pub const init_no_tlv_payload_hex = "0001ff0001ff";
pub const init_no_tlv_features = [_]u8{0xff};

/// `init`, upstream sub-case 3: empty `globalfeatures`/`features`, one
/// `networks` TLV carrying Bitcoin mainnet's chain hash.
pub const init_networks_payload_hex =
    "0000000001206fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
pub const init_networks_chain_hash =
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";

/// `error` and `warning` (identical layout): `channel_id` = 32 bytes of
/// `0x02`, `data` = the ASCII string `"rust-lightning"`.
pub const error_payload_hex =
    "0202020202020202020202020202020202020202020202020202020202020202000e727573742d6c696768746e696e67";
pub const error_channel_id = [_]u8{0x02} ** 32;
pub const error_data = "rust-lightning";

/// `ping`: `ponglen = 64`, `byteslen = 64`, 64 zero-filled `ignored` bytes.
pub const ping_payload_hex =
    "0040004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
pub const ping_num_pong_bytes: u16 = 64;
pub const ping_ignored_len: usize = 64;

/// `pong`: `byteslen = 64`, 64 zero-filled `ignored` bytes.
pub const pong_payload_hex =
    "004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
pub const pong_ignored_len: usize = 64;
