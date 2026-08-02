// SPDX-License-Identifier: MIT
// Vendored from `lightningdevkit/rust-lightning`'s `lightning/src/ln/msgs.rs`
// test module -- see modules/lnwire/NOTICE for the required MIT/Apache-2.0
// attribution. Do not hand-edit the vector bodies below; regenerate instead
// if the upstream file changes.
//!
//! `channel_announcement`/`node_announcement`/`channel_update` byte-exact
//! wire vectors, extracted from rust-lightning's own
//! `encoding_channel_announcement`/`encoding_node_announcement`/
//! `encoding_channel_update` tests (`do_encoding_*` helpers around
//! msgs.rs:4816-5097 at the fetched commit -- see NOTICE), each of which
//! builds a message from explicit field values and asserts the serialized
//! bytes equal a hex literal (`target_value`) built by concatenating
//! `<Vec<u8>>::from_hex(...)` fragments across the test's own boolean
//! parameters (excess data present/absent, address-descriptor kinds,
//! unknown feature bits, `channel_flags` direction/disable bits). Every
//! concrete combination the upstream `#[test]` function actually drives is
//! reproduced here -- e.g. `encoding_channel_announcement()` calls
//! `do_encoding_channel_announcement` 4 times with 4 distinct (bool, bool)
//! tuples, all 4 are vendored below, none synthesized.
//!
//! IMPORTANT -- no message-type prefix: rust-lightning's per-message
//! `Encode`/`Writeable` impl (what `.encode()` calls in these tests) emits
//! only the message's OWN fields, not BOLT#1's 2-byte `type` field (that is
//! added by a separate framing layer this test file never exercises). So
//! `payload_hex` below is exactly what BOLT#7 calls "the message" starting
//! at its first defined field (`node_signature_1` / `signature` /
//! `signature` respectively) -- precisely the `payload` this module's
//! `channelAnnouncementDigest`/`nodeAnnouncementDigest`/`channelUpdateDigest`
//! already take, and precisely `bytes[2..]` of what
//! `decodeChannelAnnouncement`/`decodeNodeAnnouncement`/`decodeChannelUpdate`
//! parse. `bolt7.zig`'s tests prepend this module's own 2-byte type frame
//! (256/257/258 -- BOLT#7's own published constants, not something derived
//! from this vector source) before handing bytes to `decode*`, and strip it
//! back off before comparing `serialize*`'s output against `payload_hex`.
//!
//! Every per-field value below (`chain_hash_hex`, `short_channel_id`,
//! `timestamp`, ...) is sliced out of that same frozen `payload_hex` at the
//! fixed byte offsets BOLT#7's wire layout defines (this module's own
//! `decodeChannelAnnouncement`/`decodeNodeAnnouncement`/`decodeChannelUpdate`
//! read fields in exactly this order) -- not independently re-derived, so
//! decode-direction assertions and encode-direction reconstruction both
//! check against the one external value rust-lightning's encoder actually
//! produced.

pub const ChannelAnnouncementVector = struct {
    description: []const u8,
    /// Full expected wire bytes, BOLT#1's 2-byte `type` field NOT included
    /// (see module doc comment).
    payload_hex: []const u8,
    node_signature_1_hex: []const u8,
    node_signature_2_hex: []const u8,
    bitcoin_signature_1_hex: []const u8,
    bitcoin_signature_2_hex: []const u8,
    /// `features` bitmap payload (post length-prefix), empty string when
    /// the vector's `features` is empty.
    features_hex: []const u8,
    chain_hash_hex: []const u8,
    short_channel_id: u64,
    node_id_1_hex: []const u8,
    node_id_2_hex: []const u8,
    bitcoin_key_1_hex: []const u8,
    bitcoin_key_2_hex: []const u8,
    /// rust-lightning's `excess_data` -- this module's `.extra`.
    extra_hex: []const u8,
};

pub const channel_announcement_vectors = [_]ChannelAnnouncementVector{
    .{
        .description = "unknown_features_bits=true, excess_data=false",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd0002ffff6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
        .node_signature_1_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .node_signature_2_hex = "1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a",
        .bitcoin_signature_1_hex = "216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .bitcoin_signature_2_hex = "2b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd",
        .features_hex = "ffff",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .node_id_1_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .node_id_2_hex = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
        .bitcoin_key_1_hex = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
        .bitcoin_key_2_hex = "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
        .extra_hex = "",
    },
    .{
        .description = "unknown_features_bits=false, excess_data=true",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd00006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0a00001400001e000028",
        .node_signature_1_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .node_signature_2_hex = "1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a",
        .bitcoin_signature_1_hex = "216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .bitcoin_signature_2_hex = "2b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd",
        .features_hex = "",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .node_id_1_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .node_id_2_hex = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
        .bitcoin_key_1_hex = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
        .bitcoin_key_2_hex = "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
        .extra_hex = "0a00001400001e000028",
    },
    .{
        .description = "unknown_features_bits=false, excess_data=false",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd00006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
        .node_signature_1_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .node_signature_2_hex = "1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a",
        .bitcoin_signature_1_hex = "216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .bitcoin_signature_2_hex = "2b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd",
        .features_hex = "",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .node_id_1_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .node_id_2_hex = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
        .bitcoin_key_1_hex = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
        .bitcoin_key_2_hex = "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
        .extra_hex = "",
    },
    .{
        .description = "unknown_features_bits=true, excess_data=true",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2692b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd0002ffff6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076602531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0a00001400001e000028",
        .node_signature_1_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .node_signature_2_hex = "1735b6a427e80d5fe7cd90a2f4ee08dc9c27cda7c35a4172e5d85b12c49d4232537e98f9b1f3c5e6989a8b9644e90e8918127680dbd0d4043510840fc0f1e11a",
        .bitcoin_signature_1_hex = "216c280b5395a2546e7e4b2663e04f811622f15a4f91e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .bitcoin_signature_2_hex = "2b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd",
        .features_hex = "ffff",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .node_id_1_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .node_id_2_hex = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
        .bitcoin_key_1_hex = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
        .bitcoin_key_2_hex = "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
        .extra_hex = "0a00001400001e000028",
    },
};

pub const NodeAnnouncementVector = struct {
    description: []const u8,
    /// Full expected wire bytes, BOLT#1's 2-byte `type` field NOT included
    /// (see module doc comment).
    payload_hex: []const u8,
    signature_hex: []const u8,
    /// `features` bitmap payload (post length-prefix).
    features_hex: []const u8,
    timestamp: u32,
    node_id_hex: []const u8,
    rgb_color_hex: []const u8,
    alias_hex: []const u8,
    /// The raw `addresses` field bytes (post length-prefix) -- one or more
    /// concatenated address descriptors (`ipv4`=1/`ipv6`=2/`torv2`=3/
    /// `torv3`=4/`dns` hostname=5, BOLT#7's own type-byte values), opaque
    /// here to match this module's scope (SPEC.md: no address-descriptor
    /// parsing). Empty string when the vector has no addresses.
    addresses_hex: []const u8,
    /// rust-lightning's `excess_data` -- this module's `.extra`. (Note:
    /// rust-lightning also has a separate `excess_address_data` concept,
    /// appended immediately after `addresses` and folded into
    /// `addresses_hex`'s tail here, since on our wire format both are just
    /// "more bytes inside the addresses length-prefix" -- this module does
    /// not distinguish the two the way rust-lightning's typed decoder
    /// does.)
    extra_hex: []const u8,
};

pub const node_announcement_vectors = [_]NodeAnnouncementVector{
    .{
        .description = "all optional features/addresses/excess present (unknown_features_bits, ipv4, ipv6, onionv2, onionv3, hostname, excess_address_data, excess_data)",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a0002ffff013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010009501fffefdfc260702fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260703fffefdfcfbfaf9f8f7f6260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e000201026070504686f73742607216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d2693b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "ffff",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "01fffefdfc260702fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260703fffefdfcfbfaf9f8f7f6260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e000201026070504686f73742607216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .extra_hex = "3b12cc195ce0a2d1bda6a88befa19fa07f51caa75ce83837f28965600b8aacab0855ffb0e741ec5f7c41421e9829a9d48611c8c831f71be5ea73e66594977ffd",
    },
    .{
        .description = "baseline: no unknown features, no addresses, no excess",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f20202010101010101010101010101010101010101010101010101010101010101010100000",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "",
        .extra_hex = "",
    },
    .{
        .description = "ipv4 address only",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010000701fffefdfc2607",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "01fffefdfc2607",
        .extra_hex = "",
    },
    .{
        .description = "ipv6 address only",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010001302fffefdfcfbfaf9f8f7f6f5f4f3f2f1f02607",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "02fffefdfcfbfaf9f8f7f6f5f4f3f2f1f02607",
        .extra_hex = "",
    },
    .{
        .description = "onionv2 (Tor v2) address only",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010000d03fffefdfcfbfaf9f8f7f62607",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "03fffefdfcfbfaf9f8f7f62607",
        .extra_hex = "",
    },
    .{
        .description = "onionv3 (Tor v3) address only",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010002604fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "04fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607",
        .extra_hex = "",
    },
    .{
        .description = "hostname (DNS) address only",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f202020101010101010101010101010101010101010101010101010101010101010101000080504686f73742607",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "0504686f73742607",
        .extra_hex = "",
    },
    .{
        .description = "excess_address_data only (no address descriptors)",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f20202010101010101010101010101010101010101010101010101010101010101010100040216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .extra_hex = "",
    },
    .{
        .description = "ipv4 + onionv3 + excess_address_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010005401fffefdfc260703fffefdfcfbfaf9f8f7f62607216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "01fffefdfc260703fffefdfcfbfaf9f8f7f62607216c280b5395a2546e7e4b2663e04f811622f15a4f92e83aa2e92ba2a573c139142c54ae63072a1ec1ee7dc0c04bde5c847806172aa05c92c22ae8e308d1d269",
        .extra_hex = "",
    },
    .{
        .description = "ipv6 + onionv3",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a000122013413a7031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2020201010101010101010101010101010101010101010101010101010101010101010003902fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .features_hex = "22",
        .timestamp = 20190119,
        .node_id_hex = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .rgb_color_hex = "202020",
        .alias_hex = "1010101010101010101010101010101010101010101010101010101010101010",
        .addresses_hex = "02fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0260704fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e00020102607",
        .extra_hex = "",
    },
};

pub const ChannelUpdateVector = struct {
    description: []const u8,
    /// Full expected wire bytes, BOLT#1's 2-byte `type` field NOT included
    /// (see module doc comment).
    payload_hex: []const u8,
    signature_hex: []const u8,
    chain_hash_hex: []const u8,
    short_channel_id: u64,
    timestamp: u32,
    message_flags: u8,
    channel_flags: u8,
    cltv_expiry_delta: u16,
    htlc_minimum_msat: u64,
    fee_base_msat: u32,
    fee_proportional_millionths: u32,
    /// BOLT#7's current spec text has this field unconditional (the
    /// `option_channel_htlc_max` feature that used to gate it is now
    /// mandatory) -- rust-lightning's test always sets it too, so no
    /// vector here exercises "field absent".
    htlc_maximum_msat: u64,
    /// rust-lightning's `excess_data` -- this module's `.extra`.
    extra_hex: []const u8,
};

pub const channel_update_vectors = [_]ChannelUpdateVector{
    .{
        .description = "direction=0, disable=0, no excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70100009000000000000f424000002710000000140000777788889999",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 0,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "",
    },
    .{
        .description = "direction=0, disable=0, excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70100009000000000000f424000002710000000140000777788889999000000003b9aca00",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 0,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "000000003b9aca00",
    },
    .{
        .description = "direction=1, disable=0, no excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70101009000000000000f424000002710000000140000777788889999",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 1,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "",
    },
    .{
        .description = "direction=1, disable=0, excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70101009000000000000f424000002710000000140000777788889999000000003b9aca00",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 1,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "000000003b9aca00",
    },
    .{
        .description = "direction=0, disable=1, no excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70102009000000000000f424000002710000000140000777788889999",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 2,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "",
    },
    .{
        .description = "direction=0, disable=1, excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70102009000000000000f424000002710000000140000777788889999000000003b9aca00",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 2,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "000000003b9aca00",
    },
    .{
        .description = "direction=1, disable=1, no excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70103009000000000000f424000002710000000140000777788889999",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 3,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "",
    },
    .{
        .description = "direction=1, disable=1, excess_data",
        .payload_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d619000000000000083a840000034d013413a70103009000000000000f424000002710000000140000777788889999000000003b9aca00",
        .signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
        .chain_hash_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        .short_channel_id = 2316138423780173,
        .timestamp = 20190119,
        .message_flags = 1,
        .channel_flags = 3,
        .cltv_expiry_delta = 144,
        .htlc_minimum_msat = 1000000,
        .fee_base_msat = 10000,
        .fee_proportional_millionths = 20,
        .htlc_maximum_msat = 131355275467161,
        .extra_hex = "000000003b9aca00",
    },
};
