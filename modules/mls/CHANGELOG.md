# mls — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — The three untrusted-wire fuzz targets — `MLSMessage.decode`,
  `RatchetTree.decode` and `LeafNode.decode` — had never seen a message, a tree or a leaf.
  Each drew `smith.bytes(&buf)` and then a ranged length, which returns the range minimum
  when fewer than eight input octets remain, so the length was 0 on every input; with no
  corpus, the lane ran exactly one round per target: `decode("")`. The draw is now one
  `smith.slice(&buf)` and each target carries a corpus built by this module's own encoder.
  ⭐ The `MLSMessage` harness also carried a comment claiming "three iterations in four get
  a well-formed 4-byte header written over the front". That branch had never executed once,
  for two independent reasons: it was guarded by `len >= 4` with `len == 0`, and the knob
  beside it was a ranged draw made after the input was exhausted, so it was 0 and the
  `!= 0` test was false. The stamp is now a documented `--fuzz`-only amplifier that cannot
  claim a rate, and the real headers come from the corpus. Measured: 13/13, 5/5 and 6/6
  non-empty seeds reach their decoder where 0 did; `MLSMessage` accepts 5 of 14 seeds
  covering all **5** §17.2 wire formats, `RatchetTree` accepts 3 of 6 carrying **8**
  non-blank nodes, `LeafNode` accepts 3 of 7 covering **3** distinct `leaf_node_source`
  discriminants. The second number is pinned in each guard because a zero-length
  `ratchet_tree<V>` is a *legal* frame — an accepted count alone would score a seed that
  walks no node the same as a tree with three real ones. ⭐ The corpus also puts the §7.1
  `unmerged_leaves` bound (`validateUnmergedLeaves`, the attacker-chosen array subscript a
  hostile `Welcome` reaches) inside the fuzz target for the first time.

- **2026-09-06** — **`NOTICE` rests the `src/data/` vectors on the IETF Trust's
  written grant instead of on merger doctrine, and becomes a third-party
  attribution.** The 15 JSON files come from the MLS working group's interop
  repository, which has no licence file — the old reasoning was "conformance
  data is not copyrightable expression", and the file even recorded that the
  IETF route did not reach. It does: BCP 78 §1.a makes a communication addressed
  to an IETF working group a Contribution, and TLP 5.0 §3.a licenses everyone to
  redistribute Contributions in full (§3.a(i)) or as unmodified portions with
  attribution to IETF (§3.a(iii)). Measured against upstream the same day: 9 of
  the 15 files are byte-identical (2 583 432 B), 5 are proper subsets whose every
  retained record is unmodified, and `tree-operations.json` holds all 5 upstream
  records unmodified but re-serialised — recorded, because §3.d grants no licence
  to modify. Root `NOTICE` §1 lists this module, 25 entries to 26. **No code
  changed.**

- **2026-08-12** — `create` and the commit path draw `init_secret` and `path_secret_0` with
  `io.randomSecure` rather than `io.random`. Not breaking — both functions
  already returned an error union, so `error.EntropyUnavailable` joins an
  inferred set and no signature changed. `std.Io.random` is a CSPRNG whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`),
  and the default `Io.Threaded` takes it, seeding from pid + wall clock + an
  ASLR pointer. `init_secret` is the root of the epoch key schedule and
  `path_secret_0` carries the ratchet tree's forward secrecy, so both fail
  closed now instead of quietly accepting a degraded seed.
  ⚠ Not covered by this change: `S.Kem.generateKeyPair(params.io)` on the
  next line bottoms out in `io.random` **inside std**, which no call-site
  change here can reach.
- **2026-08-11** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against the
  mlswg/mls-implementations official interop test vectors.
- **2026-07-29** — External Commits (RFC 9420 §12.4.3.2) — joining a group **without an
  invitation**. Until now the only way in was a Welcome, which requires
  an existing member to have added you; an external Commit lets a
  newcomer join from a published `GroupInfo` alone. New
  `Group.joinByExternalCommit` (sender) and a `new_member_commit` branch
  through `processCommit` (receiver), plus
  `tree.RatchetTree.assignBlankLeaf` — the leftmost blank leaf, expanding
  right per §7.7 when there is none, which is the one step sender and
  receiver must compute identically and independently. `createCommit` is
  now a wrapper over a shared `commitInner`, so the regular and external
  paths cannot drift apart. §12.2's second validation procedure is a
  genuine whitelist (exactly one ExternalInit, at most one Remove, PSKs,
  nothing else) rather than the regular Commit's blacklist, and §8.3's
  external `init_secret` replaces the previous epoch's on both sides.
  Two receiver-enforced rules live in §12.4.3.2 rather than §12.2 and are
  easy to miss when building the whitelist from §12.2 alone: "the Commit
  MUST NOT include any proposals by reference"
  (`error.ProposalByReferenceInExternalCommit`) and "External Commits
  MUST contain a path field" (`error.ExternalCommitRequiresPath`). The
  second coincides with §12.4's `needs_path` today but is independent of
  it, and only the path rule is unconditional — so the distinct error is
  pinned by its own test, or the unconditional rule would quietly become
  an accident of proposal typing. **There is no upstream external-Commit
  test vector**, so this lands round-trip-anchored: a stranger joins from
  a published `GroupInfo`, every existing member processes the Commit,
  all three reach the same `epoch_authenticator` by opposite halves of
  §8.3, and the newcomer then commits again. Reject tests **re-sign** a
  real external Commit with the joiner's own key after spoiling it, which
  is what an attacker can actually do — §6.1 verifies a
  `new_member_commit` with the key carried inside the message — so they
  reach §12.4.2's validation rather than failing earlier on the
  signature. Not covered: resumption PSKs in an external join
  (`error.PskNotAvailable` — there is no history to resolve against), and
  resync where the receiver is the member being removed.
