# lnwire — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: all four harnesses ran on one fixed input. `bolt2`'s opened with
  `smith.bytes(&buf)` and a ranged length, so `len` was **0 on every input** and
  `decodeOpenChannel` never got past the two-octet type frame — the "field reader chain" its own
  comment claimed to reach was never entered, and the line that stamped `OPEN_CHANNEL_TYPE` into
  `buf[0..2]` was writing into a buffer the decoder saw no octet of. `bolt7`'s and `message.zig`'s
  carried a PARTIAL fix that looked complete: the length was written `buf.len - valueRangeAtMost(…)`
  precisely so the exhausted-input fallback would be the FULL buffer, and the comment explained
  why. That was right, and it bought less than it looks — `Smith.bytes` fills the tail with the
  weight minimum, so with no corpus the one input each ever ran was a buffer of ZERO octets under
  a hand-stamped type. All three now draw one `smith.slice` and carry a corpus built by this
  module's own serializers; the hand-stamped type biases are gone with them, because a seed
  carrying the wrong type is the `WrongType` case and worth having. `message.zig`'s `want` also
  hung on a `value(bool)` drawn after the bytes (always `false`), and now travels in the seed.
  Before → after: `bolt2` 0/9 non-empty, 0 decoded → 9/9, 3 decoded, 2 TLV records; `bolt7` 1/9,
  0 decoded → 9/9, 4 decoded, 268 id octets; `message` 1/12, 1 framed, 0 records → 11/12, 9
  framed, 4 records.
- **2026-09-07** — `tlv.fuzzParseStream` moved off scalar draws onto `testkit.fuzz.Cursor`. Its
  first draw was `valueRangeAtMost(u8, 1, 12)`, so on the one input an ordinary run gets EVERY
  choice was its minimum: one record, type 0, length 0, no value, no tail — a two-octet stream.
  The lower bound of 1 rather than 0 was a deliberate mitigation and the comment said so; it
  bought exactly one empty record. The choices now come out of one `smith.slice` as a byte
  script. Measured: **one 2-octet stream on every input before; 8 scripts building 132 octets, 3
  streams parsed and 5 records yielded after**, with the "before" figure pinned executably by the
  guard's last two lines. ⚠ Writing the corpus found a property of the script format worth
  recording: type 254 is not reachable through a one-octet type field — `% 253` maps 0xFE to 1,
  and raw 0xFE is the five-octet BigSize prefix — so a seed that looked like it carried 254 was
  silently a duplicate type 1. The pinned counts caught that too.

- **2026-09-03** — Drift re-audit (704 lines since the last one). ⚠ **BREAKING:**
  twelve `serialize*` functions return `message.WriteError![]u8` instead of
  `Allocator.Error![]u8`, and `message.WriteError` is new
  (`Allocator.Error || error{FieldTooLong}`).
  - `Writer.putBytesU16`'s only bound was a `std.debug.assert` followed by an
    unchecked `@intCast` — which is no bound in ReleaseFast, a lane this
    collection ships and CI runs. The length prefix became `len mod 65536`
    while the whole payload was still appended, so the excess landed where the
    peer parses the next field (for `reply_channel_range`, the trailing
    `tlv_stream`). **The overflowing length is the remote peer's to choose:**
    `encoded_short_ids` carries 8 bytes per channel over a block range the peer
    asked for, so 8,192 channels is already one byte past the field. Measured on
    identical source and input — Debug and ReleaseSafe abort (rc=134);
    ReleaseFast is undefined and did **not** present the same way twice (an
    `OutOfMemory` in one run, a frame with `declared len=1` and 65,536 bytes past
    the field in another). Now `error.FieldTooLong`, with nothing written.
    `serializeCommitmentSigned` carried the same shape over the HTLC count.
  - **BOLT#7's node-id ordering MUST was neither enforced nor named.**
    `07-routing-gossip.md`, receiver clause: "MUST verify the integrity AND
    authenticity of the message by verifying the signatures" and, one bullet
    later, "if `node_id_1` is not lexicographically less than `node_id_2`: …
    **MUST ignore the message**". Only the first was implemented, in the
    function SPEC.md and README advertise as the acceptance seam — and unlike
    the P2WSH and chain checks in the same clause, this one needs no secp256k1,
    no chain access and no funding lookup, just a comparison of two arrays
    already in hand. `rg -i lexicograph modules/lnwire/` returned nothing, and it
    was not in the deferred list either. New `nodeIdsOrdered`, checked by
    `verifyChannelAnnouncement` before the signatures.
  - **All four fuzz harnesses measured nothing.** Outside `--fuzz` an empty
    corpus is exactly one input, and `Smith.valueRangeAtMost` falls back to the
    range's LOWER bound on exhausted input — so `valueRangeAtMost(u16, 0, buf.len)`
    made that one input an EMPTY buffer, which every decoder rejects at its first
    length check. Three of the four never entered the decoder at all. Subtracting
    instead (`buf.len - valueRangeAtMost(…)`) makes the fallback the full buffer;
    `n_records` likewise now has a lower bound of 1. Pinned by a test that reads
    the same expression through a `Smith` in the exhausted state.
    ⚠ Related, and correcting `scripts/README.md`: `zig build --fuzz` **does**
    work — in the Release modes. It fails to compile in Debug, inside std's own
    `test_runner.zig:566`. Measured `--release=safe --fuzz=3000` on this module:
    843/12525 coverage.
  - `example/main.zig` PRINTED its preimage check rather than asserting it, so a
    broken serializer made it print `false` and exit 0; and its rejection check
    was `_ = decode(x) catch |err| switch (err)`, which asserts nothing when the
    decode SUCCEEDS. Both fail-closed now.
  - Docs: SPEC.md claimed "the whole BOLT#2 channel-management set remains
    round-trip-only (needs a live daemon peer)" eighteen lines above its own
    Anchoring section recording all 13 messages byte-exact both directions with
    no daemon needed — false when written, and citing `SPEC.md` as its own source.

- **2026-08-06** — Security audit: five findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against BOLT#1 Appendix A/B's
  published BigSize/TLV test vectors.
- **2026-07-21** — New module: Lightning BOLT#1/2/7 wire messages (the message codec
  that rides on `bolt8`'s encrypted transport).
