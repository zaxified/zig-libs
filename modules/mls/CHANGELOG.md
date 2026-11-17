# mls — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-17** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation of the NIST HPKE key admission check (2/2 killed); Audit card cumulative 53/54, 1 eq.
- **2026-11-17** — Behaviour change: in the NIST-curve suites (0x0002/0x0005/0x0007) a KeyPackage `init_key` or a leaf / path `encryption_key` that is not a valid P-256/P-384/P-521 point is refused at admission (`error.LeafNodeInvalid`, the X25519 low-order refusal's points: `createCommit`, `processCommit`, a Welcome's tree, an external join) instead of being admitted and failing at the first encapsulation to it. Uses `hpke`'s new `validatePublicKey`.
- **2026-11-17** — Cipher suite `0x0005` (`MLS_256_DHKEMP521_AES256GCM_SHA512_P521`) is instantiated: `suite.Mls256P521Aes256GcmSha512P521` (`hpke.P521Kem`, `aesgcm.Aes256Gcm`, HKDF/HMAC-SHA512, ECDSA from the `p521` module — new dep) and added to `suite.supported`, which now holds five of the seven registry suites (X448/Ed448 wait for an X448 KEM in `hpke`). The suite-filtered vector files are re-filtered to suites {1, 2, 3, 5, 7}. The upstream P-521 vectors write private keys as minimal integers (65 bytes), and the KAT harnesses left-pad them. SPEC: new "Cipher suites" section; delta mutation 11/11 killed (card 51/52, 1 eq); ctgrind counts unchanged, source pins re-pinned.
- **2026-11-17** — Cipher suite `0x0007` (`MLS_256_DHKEMP384_AES256GCM_SHA384_P384`) is instantiated: `suite.Mls256P384Aes256GcmSha384P384` (`hpke.P384Kem`, `aesgcm.Aes256Gcm`, HKDF/HMAC-SHA384, ECDSA from the `p384` module — new dep) and added to `suite.supported`. The suite-filtered vector files are re-filtered to suites {1, 2, 3, 7}.
- **2026-11-17** — Cipher suite `0x0002` (`MLS_128_DHKEMP256_AES128GCM_SHA256_P256`) is instantiated: `suite.Mls128P256Aes128GcmSha256P256` (`hpke.P256Kem`, `aesgcm.Aes128Gcm`, ECDSA from the `p256` module — new dep) and added to `suite.supported`, so every official vector file runs for it too. **BREAKING:** the signature encodings are now the suite's (RFC 9420 §5.1.1/§5.1.2). New `S.encodeSignature`/`decodeSignature` (EdDSA `R || S`, ECDSA DER), `S.encodePublicKey`/`decodePublicKey` (EdDSA raw, ECDSA uncompressed SEC1 only; a compressed or hybrid point is `error.WrongKeyLength`), `S.signatureKeyPair(priv, out)` and the widths `Nspk`/`Nssk`. `S.Nx` is now the MAXIMUM signature width. Every verifier and signer in `tree`/`keypackage`/`framing`/`welcome`/`treekem`/`group` goes through them, and a signature that does not parse is still `error.WrongKeyLength`. **BREAKING:** `treekem.applyUpdatePath` takes `comptime S` first. It used to hash parent hashes with `suite.default`'s SHA-256 whatever the group's suite was (finding; harmless only while every wired suite used SHA-256). `Group.create`/`fromWelcome` rebuild KEM key pairs with `hpke`'s new `Kem.keyPairFromSecret`, and a NIST scalar outside `[1, n-1]` is `error.PrivateKeyMismatch`. ECDSA signatures are not reproducible, so the vector checks for these suites verify signatures instead of comparing their bytes (crypto-basics, message-protection). The suite-filtered vector files are re-filtered to suites {1, 2, 3}. Tests: `welcome.json`'s teeth case now flips `group_id` (a middle-byte flip could land in a length prefix and silently skip the case).
- **2026-11-17** — tests: RFC 9420 §10.1's "the cipher suite and protocol version of the KeyPackage match those in the GroupContext" MUST was implemented on both sides (`createCommit` and `processCommit` return `error.KeyPackageMismatch`) but no test reached it. Two new `group.zig` tests pin both fields on both paths with a re-signed KeyPackage whose only fault is that field. A `0x0003` KeyPackage has the same key and signature widths as a `0x0001` group's, so this comparison is the only thing that tells them apart. No code change.
- **2026-11-17** — Cipher suite `0x0003` (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`) is instantiated: `suite.Mls128X25519ChaCha20Poly1305Sha256Ed25519` (the `chachapoly` AEAD via `hpke.ChaCha20Poly1305`). New `suite.supported` lists every instantiated suite; every official vector file the module drives for `0x0001` (crypto-basics, key-schedule, psk_secret, secret-tree, message-protection, transcript-hashes, welcome, tree-validation, treekem, passive-client-welcome, passive-client-handling-commit, plus the commit-generation KATs over treekem/handling-commit) now runs once per `supported` suite. The suite-filtered embedded files (`tree-validation`, `treekem`, `passive-client-welcome`, `passive-client-handling-commit`) are re-filtered from the same upstream commit to suites {1, 3}; `tree-operations` and `passive-client-random` exist upstream for `0x0001` only. `keyschedule`'s external-init `suite_id` takes its KDF id from `hpke.kdf.Of(S.Nh)` instead of a fixed HKDF-SHA256. Suite selection stays a compile-time choice: a `Welcome`/`GroupInfo` for another suite is still `error.CipherSuiteMismatch`.
- **2026-10-19** — AES-GCM moved from `std.crypto.aead.aes_gcm` to the zig-libs `aesgcm` module (new dep; Zig 0.17 #36256). The default suite uses `aesgcm.Aes128Gcm`; `keyschedule.zig` AEAD-id detection accepts both the `aesgcm` and the std types. Same bytes on the wire.
- **2026-10-18** — Ported to Zig 0.17.0. `X25519.KeyPair.generateDeterministic` no longer returns an error union (`try` dropped on Kem key pairs); `ArrayList` literal replaced by field assignment in `reserveAdoption` (new `pointer_stability` field); `@typeInfo` `decl_names`/`field_names`; `EnumSet.empty`. `example/main.zig` wraps the Kem `generateDeterministic` in `@as(anyerror!…)`.
- **2026-10-10** — tests: deterministic fuzz driver `MLS_FUZZ` (`src/fuzz_test.zig`): `mls-decode` (KeyPackage / Welcome / Commit MLSMessages of a real exchange, damaged, through the decoders and the joiner) and `mls-group` (a two-member group: a genuine Welcome joins and a genuine Commit advances the member; every flipped Welcome/Commit bit is refused, a refused Commit leaves the member able to take the genuine one). 25,000 runs each (`.scale` 8), ReleaseSafe, clean.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `ks`, `tree`, `priv`, ReleaseFast, suite 0x0001). `ks` taints the init, commit and PSK secrets through `deriveEpoch`; `tree` taints the encryption secret through every node secret, the ratchet base, `Ratchet` and `Window`; `priv` taints the content key/nonce, sender-data secret and signing key through `protectPrivate`, `decryptSenderData` and `decryptContent`. `ks` and `tree`: 0 in-file contexts; `priv`: 4, std's Ed25519 signing internals and the AES-GCM tag-verify outcome. TreeKEM path secrets and HPKE are the `hpke` module's rows. No code change.
- **2026-10-09** — **NO CONSUMER-VISIBLE CHANGE:** `check-secret-api` closed at 0 findings. `treekem.Staged(S).Node` is renamed `PathNode` (it shadowed the public `tree.Node` in the lint and made the public ratchet tree look secret-bearing); `framing.membershipTag`/`verifyMembershipTag`, `keyschedule.zeroSecret` and `welcome.GroupSecrets` (slices only) / `Welcome.findSecret` carry `secret-api-ok` markers with their reasons. No burn or signature changed, so no new probe.

- **2026-10-09** — **BREAKING:** dead-stack sweep of mls's own API. Secret inputs go in by `*const`, secret results come out through an `out` parameter, and every public entry point zeroes the stack its body dirtied (`src/burn.zig`: 4 KiB HKDF/MAC/AEAD paths, 48 KiB KEM/HPKE/signature paths, 96 KiB `Group` operations). Changed: `crypto.ExpandWithLabel{,Scratch}`/`DeriveSecret` (now `out: *[Nh]u8`)/`DeriveTreeSecret` (secret by pointer), `SignWithLabel{,Alloc}` (key pair by pointer), `DecryptWithLabel{,Scratch}` (`skR` by pointer); `keyschedule.extractInitCommit`/`joinerSecret`/`memberSecret`/`welcomeSecret`/`epochSecret`/`deriveEpoch`/`deriveEpochFromJoiner`/`pskSecret`/`externalKeyPair`/`externalInitSender{,Deterministic}`/`externalInitReceiver` (out params), `mlsExporter`/`confirmationTag`/`membershipTag`/`verify*Tag` (key by pointer); `secrettree.childSecret`/`nodeSecret`/`ratchetBaseSecret`/`senderDataKeys`, `Ratchet.init`/`current`, `Window.init`/`get` (out params); `welcome.welcomeKeyNonce`, `encryptGroupInfo`/`decryptGroupInfo`, `decryptGroupSecrets`, `join(…, params: *const JoinParams, out: *Joined)`; `treekem.stageUpdatePath(…, out: *Staged)`, `sealUpdatePath(…, staged: *const Staged, …)`, `Staged.pathSecretFor(…, out) bool`; every params struct field holding a key (`signature_key_pair`, `encryption_key_pair`, `leaf_key_pair`, `path_secret_0`, `membership_key`, `key_nonce`, `sender_data_secret`, `init_key_pair`, `Group` `encryption_priv`/`init_priv`) is now `*const`; `Group.create`/`fromWelcome`/`joinByExternalCommit` land the group in `out` and `Group.epochAuthenticator` writes to `out`. New `src/stackprobe_test.zig` (30 entry points, ReleaseFast): before, every one but `EncryptWithLabel`, `externalKeyPair` and `epochAuthenticator` left epoch secrets, path/node secrets, HPKE/signature private keys, ratchet keys or HMAC pads on the dead stack (e.g. `Group.joinByExternalCommit` all 12 epoch secrets up to 18 KiB deep); after, 0 on all 30, and 191 residues with the burns cut to 64 B (the probe sees them). `example/` and `example-apps/mls-chat` follow the new shapes.

- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE:** follows `hpke`'s pointer/out-param API (dead-stack sweep): HPKE private keys go to `openBase`/`setupBaseR` by pointer, `setupBaseS`/`setupBaseR` write into a local `Setup`/`Context` that is wiped on return, key pairs are derived into out-params. mls's own API is unchanged — `externalKeyPair` still returns the pair by value and `DecryptWithLabel*` still take `skR` by value; both belong to mls's own dead-stack sweep (not done yet).

- **2026-10-06** — **BEHAVIOURAL:** a small-order X25519 HPKE key is refused at admission. A
  KeyPackage whose `init_key` or leaf `encryption_key` is the all-zero point (or any other
  small-order encoding) was accepted by an Add, after which every path Commit reaching that
  leaf failed (`DhFailed`/`Malformed`) until it was removed. Now `createCommit` and
  `processCommit` refuse such an Add or Update, and the external joiner's own KeyPackage, with
  `error.LeafNodeInvalid`; `processCommit` refuses one in an UpdatePath (`LeafNodeInvalid` for
  the leaf, `InvalidUpdatePath` for a parent node); `fromWelcome` and `joinByExternalCommit`
  refuse an imported tree carrying one (`LeafNodeInvalid`). Detected as std's
  `error.IdentityElement` from X25519 with a fixed scalar; X25519-KEM suites only; not a
  `Policy` switch. 4 tests added (detector, `createCommit`, `processCommit` genuine + 4
  insider forgeries, Welcome tree), RED before. Closes the SPEC Backlog item of the same day.

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** no leak on `createCommit`'s failure paths;
  the mutation run's leak hint was a test artifact. With the committer's-own-Update,
  two-GroupContextExtensions or duplicate-PSK check deleted, `createCommit` SUCCEEDS, and the
  "leaked" buffers were the returned `commit`/`group_info` that the test's `expectError`
  discarded. Checked on clean code anyway: 6 tests drive whole sessions (`create`,
  `createCommit`, `fromWelcome`, `processCommit`, by-reference Update, `joinByExternalCommit`;
  empty Commit, Add with `external_pub`, external PSK, path omitted) through
  `std.testing.checkAllAllocationFailures` — 1339 failure points, all clean — and 1 test fails
  an HPKE encapsulation midway through the Welcome slots and midway through the UpdatePath
  ciphertexts: clean. Each instrument was shown to fire by deleting one `errdefer`. Found on
  the way (SPEC Backlog, not fixed): an Add whose KeyPackage carries an all-zero X25519 key is
  accepted, after which every path Commit reaching that leaf fails until it is removed.

- **2026-10-06** — **Fixed a double free reachable from a received Commit.** A Commit whose
  proposal list names the same PreSharedKeyID twice made `validateProposalList` free its
  scratch encoding twice — explicitly, and again through its own `errdefer` — on both
  `createCommit` and `processCommit` (after authentication, so any member could send it).
  Mutation run: 40 of 41 killed, 1 equivalent; 4 tests added and 2 extended (insider-forged
  Commits refused by each path rule's own error, proposal authentication, an external
  Commit's signature, the remaining §12.2 list rules and §7.3 encryption-key uniqueness via
  `createCommit`, `join`'s PSK-list identity, `applyUpdatePath`'s §7.9.2 check). SPEC:
  done/resolved Backlog entries moved under "Done"; the long-lived-group memory growth is
  now named in "Where we are behind".

- **2026-09-11** — **BREAKING + BEHAVIOURAL.** `Group.processCommit` and `Group.createCommit` are
  transactional: a Commit is adopted whole or not at all, and a refusal at any step leaves the
  group exactly as it was. Until now a failure after the tree had been mutated set a poison
  flag and every later call returned `error.GroupPoisoned` — and an unauthenticated stranger
  could trigger that for every member with one message: an external Commit is signed with a key
  it carries itself, so one with a foreign `ExternalInit` passes every check up to the
  confirmation tag, by which time the tree has been merged. Both paths now build the new epoch
  on a working copy (`fork`: the tree's containers in an arena of their own, its byte fields
  still aliased) and swap it in after the last fallible step. **API:** `error.GroupPoisoned`
  and the `poisoned` field are removed; nothing in the repository referenced either,
  `example-apps/mls-chat` included. Measured with allocation-failure sweeps, one fresh object
  per failure point: the group was left changed at 24 of 34 points (member Commit), 19 of 26
  (external Commit) and 53 of 64 (`createCommit`); now at 0 of 40, 0 of 31 and 0 of 68. A
  member that lacks a PSK can take the same Commit again once the PSK arrives. Every arena the
  group owns now wipes its memory on release, so a refused Commit leaves no copy of the path
  secret it decrypted (1 live copies → 0). The sweeps also found 17 leaked
  allocations on `createCommit`'s failure paths (`treekem.sealUpdatePath`, `buildWelcome`),
  fixed here. Cost: in the measured shape a receiver's retained memory grows by ~5.2 KB per
  epoch instead of ~2.8 KB (per-Commit arena slack) — see `SPEC.md`'s Backlog.

- **2026-09-08** — `treemath.zig`'s port of RFC 9420 Appendix C now carries the IETF
  Trust's own copyright notice instead of resting on the merger doctrine. The file has always
  said openly that it translates the RFC's Python listing line for line; what changed is what
  that rests on. The IETF Trust claims copyright in the code inside its documents and grants
  it under the Revised BSD License (BCP 78 / TLP 5.0 §4.c defines "Code Components", and
  Appendix C is introduced as "The following python code demonstrates the tree
  computations") — so the author of the licence disagrees with the merger reading, and the
  weakest place to run that reading is an admitted line-for-line port. `modules/mls/NOTICE`
  item 2 reproduces the three conditions and the disclaimer; the source file carries the
  copyright line, as clause 1 asks. The condition is "keep the notice" and nothing else: no
  restriction on use, and the collection stays MIT. This also removes a disagreement inside
  the repository — `modules/ctap2pin/NOTICE` already cited RFC code under the same Trust
  terms.

- **2026-09-08** — `fuzzMessageInput`'s header stamp had never executed, for a third
  independent reason. The knob is drawn AFTER the byte draw, `Smith.slice` leaves the seed
  exhausted, and an exhausted `value(u8)` is the weight minimum — measured **0 of 14 seeds**
  stamped. The corpus gains one seed that can only decode because the branch ran: the complete
  `public_message` frame with its version and wire-format octets zeroed, plus the word `1`
  (`1 & 3 != 0` enables the stamp, `1 >> 5` selects `mls_public_message`). `fuzzMessageInput`
  now returns whether it stamped, so the guard pins `stamped` and `stamped_accepted` as exact
  counts from the same call the harness makes; `accepted` goes 5 → 6 and the five wire formats
  are unchanged. Tests only.

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
