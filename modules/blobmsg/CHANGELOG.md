# blobmsg — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Both fuzz harnesses were replaying an EMPTY buffer, and the
  walker's buffer was too small for the module's own real captures.** Each opened
  with `smith.bytes(&raw)` followed by `smith.valueRangeAtMost(u16, 0, raw.len)`;
  `bytes` consumes `min(raw.len, in.len)` octets and the ranged draw then reads
  eight *more* as a little-endian u64, returning the range minimum when fewer
  remain — so the drawn length was 0 for every input a seed can carry. The
  `steps <= buf.len / 4 + 1` bounds in `fuzzCodec` had therefore never executed,
  and `fuzzEncodeArgs` was a complete no-op: `std.json.parseFromSlice("")` fails,
  so its `catch return` swallowed the only input it ever saw. ⛔ Separately, the
  walker's buffer was **512 octets while the module's largest frozen real ubusd
  reply body is 1988** (`captured_data_devstatus`; `captured_data_board` is 528
  and `captured_data_ifstatus` 780) — and a seed longer than the buffer reads back
  as the EMPTY one rather than a truncated one, so not one of the four real daemon
  replies captured from a live OpenWRT run could ever have passed through this
  module's own fuzz harness. Buffer raised to 2048; both harnesses now draw with
  one `smith.slice`. Corpora: 9 malformed attr images (every typed refusal the
  walker tests pin) plus three built by the module's own encoder and one real
  captured reply body; 12 JSON args covering every value kind, both root refusals
  and the 70-level `TooDeep` cap. Measured 0 attrs / 0 fields / 0 refusals and
  0 JSON parsed before; 10 / 5 / 7 and 9 parsed / 6 encoded / 196 octets after.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Wire format
  is clean-room from named OpenWRT sources and byte-parity-verified against `ubus -S`
  per README.
- **2026-07-05** — New module: OpenWRT ubus client + blob/blobmsg wire codec.
