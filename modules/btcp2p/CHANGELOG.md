# btcp2p — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **All eleven fuzz harnesses now receive their input; none of
  them did before.** Every one opened `smith.bytes(&buf)` and then drew the
  length with a ranged draw. `bytes` takes `@min(buf.len, in.len)` octets, so
  the ranged draw found fewer than the eight it needs and returned the range
  MINIMUM — the length was **0**, and the decoder was called with an empty
  slice while the input sat unread in the buffer. Measured directly over every
  buffer size and frame length this module uses (24…344 octets against buffers
  of 64/96/256/512): the drawn length is 0 in all twelve combinations. Each now
  draws with one `smith.slice`.
  This mattered more here than in a text protocol. `decodeMessage` is the
  module's untrusted-input boundary and it gates on a 4-octet magic, an
  `IsCommandValid()`-shaped command field, and a 4-octet `sha256d` prefix over
  the payload: undirected octets reach the checksum comparison with probability
  ~2^-32 and pass it with ~2^-32 more, so no amount of fuzzing gets past the
  envelope. Every harness now carries a corpus taken from this module's own
  externally anchored value tests — the wiki's verack and 60002 version
  envelopes, the genesis block and its header, the `addr` and `net_addr`
  hexdumps, and the `inv` payload Wireshark's dissector read for us — plus one
  frame per typed refusal each decoder names. Those anchors were moved to
  container-level constants so the corpus seeds the SAME octets the anchor
  tests assert on, not a re-transcription of them.
  ⭐ `fuzzDecodeVersion`'s buffer was **256 octets, and could not have reached
  `error.SubversionTooLong` no matter what it was fed**: `max_subversion_length`
  is 256, so the shortest `version` payload that triggers it is 344 octets, and
  a seed longer than the buffer does not arrive truncated — it arrives EMPTY.
  Buffer raised to 512; both the at-cap and the one-over user agents are now in
  the corpus.
  ⭐ Two comments in these harnesses described behaviour that had never once
  happened. `envelope.fuzzDecodeMessage` said it stamped a real magic into the
  frame "half the time" — the guard was `bytes.len >= 4`, and `bytes` was always
  empty. `block.fuzzDecodeBlock` said it biased the `txn_count` octet "half the
  time" — that guard tested `buf.len` (a compile-time 512, so always true) where
  it meant the drawn length, and the `value(bool)` beside it came after a draw
  that had already eaten the input, so it was false on every execution. The
  block bias is now bounded by the drawn length, so it can only rewrite an octet
  the decoder will actually read.
  ⭐ The nine corpus guards are the part worth keeping: each asserts that every
  seed reads back non-empty (a seed longer than the harness's buffer silently
  reads back EMPTY — exactly what the two 34x-octet version seeds would have
  done against the old buffer) and pins how many the decoder accepts, because
  acceptance is not reach. Measured: envelope 6 of 14, message 4 of 12,
  net_addr 4 of 6, block_header 4 of 6, block 2 of 6, handshake 4 of 7,
  addr 3 of 7, reject 4 of 8, inventory 3 of 7, locator 2 of 5, headers 3 of 6.
- **2026-08-23** — Fixed `Message.commandName()`: its receiver was `self: Message`
  (by value), but `command` is a `[COMMAND_LEN]u8` embedded in `Message` itself, so
  the returned slice pointed into the callee's own stack-local copy — dangling the
  instant the function returned. A caller reading the result immediately in the
  same expression could get away with it; one intervening call (e.g.
  `std.debug.print`) was enough to read back poisoned/garbage bytes instead of the
  command. Receiver is now `self: *const Message`. Regression test added
  (`envelope.zig`, "F2 regression").
- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Four
  genuinely external anchors, all byte-exact.
- **2026-07-29** — New module: Bitcoin P2P wire-message codec — the message envelope
  (4-byte network magic for mainnet/testnet3/regtest/signet, 12-byte NUL-padded command,
  little-endian length, double-SHA256 checksum).
