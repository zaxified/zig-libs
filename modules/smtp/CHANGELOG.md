# smtp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-08** — Test-only, no production change: `message.fuzzRender`'s corpus carried a
  24-octet tail for the three draws behind the blob, but sixteen of those octets were
  literally `[_]u8{0} ** 16` on all ten seeds. A tail that exists is not a tail that
  carries anything. Measured: the PRNG seed was **0 on 10 of 10 seeds**, so every render
  produced the SAME MIME boundary — **1 distinct boundary for the whole corpus** — and the
  harness's own `count(boundary) == 4` assertion, the one that checks a boundary never
  appears inside the parts it delimits, had only ever been evaluated against one string.
  `date.unix` was likewise 0 on all ten, so the Date header was 1970-01-01T00:00:00Z every
  time and **0 seeds** rendered a pre-epoch date. `seedSplit` now takes the PRNG seed and
  the timestamp per seed, covering the 1901 and 2038 edges, a leap day and four pre-epoch
  values; the corpus guard pins **8 distinct boundaries and 4 pre-epoch dates**. ⚠ The
  timestamp word must be the zero-extended 32-bit pattern: `value(i32)` reads eight octets
  as a little-endian u64 and a sign-extended negative falls outside the type's weight range,
  coming back as 0.


- **2026-09-07** — **All seven fuzz harnesses now receive their input; none of
  them did before.** Every one opened `smith.bytes(&raw)` and then drew the
  length with a ranged draw. `bytes` takes `@min(raw.len, in.len)` octets, so
  the ranged draw found fewer than the eight it needs and returned the range
  MINIMUM — the length was **0**, and the parser/builder/renderer was called
  with an empty string while the input sat unread in the buffer. Measured
  directly across every buffer size this module uses (200/300/400/512/1100)
  against frames from 3 to 1003 octets: the drawn length is 0 in all of them.
  Each now draws with one `smith.slice` and carries a corpus taken from this
  module's own value tests — the RFC 5321 §4.1.1.1 EHLO reply, both RFC
  4616/4954 AUTH worked examples, the address-grammar table, the injection
  attempts, and one frame per typed refusal each parser names.
  ⭐ **The wave-2 F2 fix in `data.fuzzDots` had bought nothing.** Its comment
  records raising the buffer from 256 to 1100 octets so the harness could reach
  the 1000-octet `max_line` where the stuffer/unstuffer asymmetry lived — but
  the length drawn from that buffer was 0, so the harness fed the stuffer an
  EMPTY body regardless of how large the buffer was. The boundary is reached
  now, and only because four of the sixteen seeds sit either side of it (999
  and 1000 source octets, with and without the leading transparency dot that
  doubles on the wire).
  ⭐ **Two more collapsed draws that `check-fuzz-reach` does not look for.**
  `command.fuzzCommands` drew `smtputf8` and `data.fuzzDots` drew
  `allow_bare_lf` with `smith.value(bool)` *after* the length draw. Any draw
  taken after the input is exhausted returns its weight minimum — `false` — so
  neither harness could ever enter its SMTPUTF8 or its bare-LF-tolerant mode on
  a corpus replay, and `poštovní@example.com` was unreachable. Both now try
  both values, the way `reply.fuzzReply` already did. `message.fuzzRender` has
  the same shape in its subject/body split point; there the fix is in the
  corpus, whose entries carry a 24-octet tail for the three draws that follow
  the blob (without it the Subject would be empty for every seed, in a harness
  named "any body and subject").
  ⭐ The seven corpus guards are the part worth keeping. Each asserts every seed
  reads back non-empty (a seed longer than the harness's buffer silently reads
  back EMPTY), and each pins **two or three counts rather than one
  "accepted"** — because "accepted" is nearly worthless in this module:
  `capabilities.parse("")`, `data.stuffAlloc("")`, `auth.decodeChallenge("")`
  and rendering an empty Subject all succeed, so the collapsed harnesses'
  single empty execution looked healthy. The second number is the one that says
  work happened: capability lines recognised (20), RFC 2047 encoded words
  emitted (7), LOGIN challenges classified (3), seeds with a non-empty Subject
  (9), streams the receiver saw terminated (3). Measured: reply 6 of 17
  accepted, capabilities 12 of 13, auth 12 of 15 credentials and 9 of 15
  challenges, command 4 of 19 as an EHLO argument and 4/5 of 19 as a RCPT
  argument without/with SMTPUTF8, data 14 of 16 stuffed, mime 14 of 17
  rendered, message 8 of 10 rendered.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-23** — New module: SMTP client (RFC 5321) — ESMTP EHLO capability
  negotiation, STARTTLS seam, AUTH PLAIN/LOGIN, pipelining, and MIME message composition
  (RFC 5322/2045).
