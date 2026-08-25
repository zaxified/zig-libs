# timecapsule

Encrypt a file so it can be opened only **after** a chosen wall-clock time,
and only **by** a chosen recipient. The time half is [drand]-style timelock
encryption (`tlock` over BLS12-381) against the League of Entropy's public
**quicknet** beacon; the recipient half is an [HQC] post-quantum KEM; the
`timelock_envelope` module binds them into a logical **AND** — neither lock
alone opens anything.

[drand]: https://drand.love/
[HQC]: https://pqc-hqc.org/

## Get it

Take this directory and nothing else — it is a self-contained project, and the
rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-08-24.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-08-24/example-apps/timecapsule'
cd timecapsule
```

With git instead, if you would rather have history:

```sh
git clone --depth 1 --filter=blob:none --sparse -b 2026-08-24 \
  https://github.com/zaxified/zig-libs.git
cd zig-libs && git sparse-checkout set example-apps/timecapsule
cd example-apps/timecapsule
```

## Build and run

```sh
./init.sh
```

Then:

```sh
./zig-out/bin/timecapsule keygen --out alice        # alice.pk (share) + alice.sk (keep)
# keygen refuses if alice.pk/alice.sk already exist — overwriting a secret key
# orphans every capsule sealed to it, so it is never done silently.
echo "the eagle lands at midnight" > msg.txt
./zig-out/bin/timecapsule seal --to alice.pk --at +2m --in msg.txt --out msg.tc
./zig-out/bin/timecapsule open --key alice.sk --in msg.tc --out msg.out
```

Run `open` before the two minutes are up and it prints when the capsule
unlocks and exits with status **3** (distinct from an error's 1, so a cron
job can tell "not yet" from "never"). Run it after, and the plaintext is
back. Or skip the cron entirely: `open --wait` sleeps until the round's
publish time and then polls the source — the beacon, or `--round-file` —
until the signature appears, which turns the whole dead-man switch into one
blocking command. `info --in msg.tc` shows the round and the unlock time without
touching a key. `--at` also takes `@<unix>` and `round:<n>`.

`init.sh` needs Zig 0.16.0 on `PATH` and installs nothing for you.

## Where the "nobody can open it early" comes from

`tlock` encrypts to a **future round number** of the quicknet randomness
beacon. The key that opens that lock is the round's threshold-BLS signature,
which the League of Entropy's nodes jointly produce **only when the round's
time arrives** — until then it does not exist anywhere: not on this machine,
not on any server, not held in escrow. There is no "trust us not to peek"
party, and the sender needs no further involvement; the signature, once
published, is public data that anyone can fetch and only the recipient's key
can use.

Three consequences worth noticing:

- **The beacon does not know you exist.** Sealing is entirely local; opening
  fetches one public document. Nothing is registered anywhere.
- **The chain public key is the trust root, not the transport.** Every
  fetched document goes through `drand.parseInfo`/`parseRound` and a real
  BLS pairing check (`drand.verifyRound`) before its signature is used as a
  decryption key. A mirror that lies about a round produces a typed refusal,
  not a wrong plaintext. For a pinned trust root, keep the `/info` document
  in a file and pass `--chain-info`.
- **The time lock is not post-quantum — and that is why the second lock
  exists.** BLS is Shor-breakable; an adversary recording capsules today and
  breaking pairings later could forge the *timing*. They still read nothing:
  the content key is also bound to the HQC secret, and HQC is a NIST
  post-quantum selection. See `modules/timelock_envelope/README.md`'s threat
  model for exactly what each lock does and does not hold.

## Offline use

`seal`, `open` and `info` normally fetch from `https://api.drand.sh`
(override with `--beacon`). Every network touch has a file-based bypass:
`--chain-info <file>` for the `/info` document, `--round-file <file>` for
the `/public/<round>` document. `smoke.sh` runs fully offline this way,
against the genuine quicknet round-1000 documents — the same bytes the
`drand` and `tlock` module KATs pin. Measured while writing it: api.drand.sh
answers a not-yet-published round with **425 Too Early**, not 404; the app
treats both as "still locked".

## What this is a demo of

| Module | What the app takes from it |
|---|---|
| `timelock_envelope` | the two-lock AND: seal/open, HKDF key binding, tamper-evident framing |
| `drand` | chain-info + round parsing, BLS verification of the beacon signature |
| `hqc` | the recipient's post-quantum KEM keypair |
| `http` | TLS client fetching the beacon documents (the `drand` module is transport-agnostic by design) |
| `datefmt` | civil-calendar math for "publishes 2026-08-24 19:35:15 UTC" |

The app holds no cryptography of its own: `src/main.zig` is a CLI and file
I/O, `src/beacon.zig` is transport + round arithmetic. That is the point —
the demo shows the modules composing from their public APIs, the way a
consumer would use them.

## What it deliberately does not do

- No key servers, no recipient discovery — you hand `alice.pk` over however
  you hand files over.
- No armored/ASCII output, no streaming: a capsule is a small binary file
  (16 MiB plaintext cap).
- No beacon other than quicknet. The chain hash is pinned; a capsule records
  which chain it was sealed on and `open` refuses a mismatched `/info`.
