# mls-chat

End-to-end encrypted **group** chat over [RFC 9420 (MLS)][rfc], built on the
`mls` module. One binary is both the delivery service and the client.

[rfc]: https://www.rfc-editor.org/rfc/rfc9420.html

## Get it

Take this directory and nothing else — it is a self-contained project, and the
rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-08-24.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-08-24/example-apps/mls-chat'
cd mls-chat
```

With git instead, if you would rather have history:

```sh
git clone --depth 1 --filter=blob:none --sparse -b 2026-08-24 \
  https://github.com/zaxified/zig-libs.git
cd zig-libs && git sparse-checkout set example-apps/mls-chat
cd example-apps/mls-chat
```

## Build and run

```sh
./init.sh
```

Then three terminals, all on loopback:

```sh
./zig-out/bin/mls-chat relay                       # the delivery service
./zig-out/bin/mls-chat join --name alice --create  # creates the group
./zig-out/bin/mls-chat join --name bob             # waits for a Welcome
```

In alice's terminal, `/invite bob`. Both terminals print the new epoch and the
member count; anything you type after that is an encrypted application message
to the group. `/who` lists the leaves, `/remove <name>` commits a Remove,
`/leave` proposes your own, and `/quit` merely disconnects.

`init.sh` needs Zig 0.16.0 on `PATH` and installs nothing for you.

## What is worth reading it for

**The delivery service holds no key, and this one proves it by construction.**
`src/relay.zig` does not import `mls` at all. It stores the KeyPackages members
publish, remembers who subscribed to which group id, and copies handshake,
Welcome and application frames to the other subscribers byte for byte. RFC 9420
§2 leaves the Delivery Service outside the protocol precisely so it can be this
dumb, and a demo whose server *could* decrypt would teach the opposite of the
thing MLS is for.

What the relay can still see, because MLS does not hide it: who publishes under
which name, who subscribes to which group, and the size and timing of every
message. It can also drop or reorder anything. Metadata is not what MLS
protects.

**The §9 application-message layer, assembled from outside the library.**
`src/appmsg.zig` is the most interesting file here. `mls.Group` deliberately
does not drive RFC 9420 §9's secret tree — it says so in its own doc comment,
because the generation-retention policy belongs to the application — so a chat
client has to build the send and receive paths itself out of public parts:

- one forward-only ratchet for this member's own leaf, consumed one generation
  per message, with the used secret destroyed rather than dropped;
- one bounded receive window per sender leaf, consume-once so a replayed
  message decrypts to nothing the second time, and capped so an
  attacker-chosen `uint32` generation cannot buy four billion KDF invocations;
- a full rebuild at every epoch, because a Commit changes `encryption_secret`
  and every ratchet under it.

**Who sent a message is decided by the tree, not by the message.** The sender
leaf comes out of the sender-data decryption, and the signature is then checked
against that leaf's key in the group's ratchet tree. The nickname printed
beside it is a `basic` credential — attacker-controlled display text, shown
with its leaf index precisely because two members may publish the same one.

## What it does NOT do

- **No persistence.** Every run generates a fresh identity, and group state
  lives only in memory. Persisting an MLS group is a real piece of work — the
  ratchet tree, the transcript hashes, the epoch secrets and this member's path
  secrets all have to survive together or not at all — and half of it would be
  worse than none.
- **Handshakes travel as `PublicMessage`.** `mls.Group` refuses a handshake
  framed as `PrivateMessage` (`error.PrivateHandshakeNotSupported`) because
  that path needs the §9 secret tree driven for the handshake ratchet too. RFC
  9420 §6 permits either framing; this app takes the one the library supports.
  The cost is real: the delivery service sees *that* membership changed, though
  not the content of anything.
- **No Update proposals and no external joins.** Both are in the module's API;
  neither is wired up here. Add, Remove and a member's own departure are.
- **`/leave` is a proposal, not an act**, because §12.4 forbids a committer
  from removing itself: the leaver publishes a Remove for its own leaf and
  stays in the group until a remaining member commits it. Which member does
  that has to be decided without a round trip, and — the part that is easy to
  get wrong — the decision must not depend on the order proposals arrived.
  The committer is **the lowest occupied leaf that is not the target of any
  pending Remove**, and when more than one proposal is outstanding the one
  committed is chosen by a fixed canonical order, so every member reaches the
  same answer. Excluding every removal target matters: a member never receives
  its own proposal (the relay does not echo to the sender), so a leaver left on
  the ballot would elect itself and nothing would happen. When several members
  propose at once, one proposal is committed per epoch and the rest are
  re-proposed as needed.
- **One group per client**, named by `--group`, and no history: a member added
  in epoch 5 cannot read epoch 4's messages. That is MLS working, not a
  limitation of the app.
- **One coarse lock over group state, held across the send.** A client's two
  threads share a single spinlock, and a Commit is built and its handshake sent
  while it is held. On loopback with small frames that is fine; a client facing
  a slow relay would want the send off the lock. It is the simple correct
  thing, not the scalable one — the same trade the `raft-kv` demo makes and
  documents.
- **No transport security below MLS.** The frames between client and relay are
  plain TCP. MLS protects the content; nothing here protects the metadata the
  relay sees anyway.

## Layout

| File | What is in it |
|---|---|
| `src/main.zig` | CLI: `relay` and `join`, argument parsing, and nothing else. |
| `src/relay.zig` | The delivery service. Imports no MLS. |
| `src/client.zig` | One participant: identity, socket, the two threads, the keyboard commands. |
| `src/appmsg.zig` | RFC 9420 §9 — the application-message layer built on the module's public parts. |
| `src/wire.zig` | The client↔relay envelope. Not MLS: RFC 9420 specifies no transport. |
