# example-apps

Standalone applications built on zig-libs. Each one is a **separate project**:
its own `build.zig`, its own `build.zig.zon`, and a `zig-libs` dependency
pinned to a dated release tag.

Take **one directory and nothing else** — cloning the collection is not a step.
Each app's README opens with the command that pulls just that directory out of
a release tag; then `./init.sh`, and you have a working binary. The collection
itself arrives as a pinned dependency, not as a checkout.

That is the primary purpose, and the manifests are written for it and for
nothing else.

| App | What it is | Modules it uses |
|---|---|---|
| [`ssh-demo`](ssh-demo/) | An SSH-2.0 client and server in one binary, with real `known_hosts` and `authorized_keys` handling. | `ssh` |
| [`mls-chat`](mls-chat/) | End-to-end encrypted group chat over RFC 9420 (MLS) — delivery service and client in one binary. | `mls`, `framing`, `lockfree` |
| [`http-service`](http-service/) | A hardened task-tracking JSON API — API-key and HMAC-signed webhook clients, behind the composed middleware chain. | `http`, `router`, and 16 more |
| [`timecapsule`](timecapsule/) | Encrypt a file openable only AFTER a chosen time (drand timelock) and only BY a chosen recipient (HQC post-quantum KEM) — two locks, both required. | `timelock_envelope`, `drand`, `hqc`, `http`, `datefmt` |
| [`raft-kv`](raft-kv/) | Replicated KV store over the raft module's model-checked kernel — survives leader kill, catches up after restart, refuses writes without a majority. | `raft`, `kv`, `framing`, `lockfree` |

## How this differs from `modules/<name>/example/`

Both are consumer code, and they prove different things.

`modules/<name>/example/` is one file, built inside this repository against one
module and its declared deps. It answers: **is this module's published API
sufficient to do the job?** It caught `diskfree` shipping two functions that did
not compile because nothing had ever imported it, and it caught a `pub` dropped
from a type `l2disco`'s public API needs — a change that left both the module's
own tests and `check-pubfn-reach` green.

`example-apps/` is a project, may be many files, and reaches zig-libs the way a
stranger does: through the package manager, by URL and hash. It answers: **can
someone outside build something real on this?** An app that imports exactly one
module answers the first question too, and more strictly, so it discharges that
module's example obligation (`CONVENTIONS.md` §7.2).

## What we get from the same directory

**The rule, once:** an app's source is written against **this tree**. Its
manifest pins the last dated tag, and that pin is for the downloader, not for
us — a tag is the only ref carrying the all-lanes-green claim, so it is the only
thing worth handing a stranger. `scripts/tag.sh` rewrites the pin when a tag is
cut and commits the rewrite *inside* the tag, so a copy taken from tag T builds
against T.

Both checks are arranged from outside the app, so its manifest stays the
customer's:

1. **Every run**, `scripts/check-apps.sh --run` builds each app with `zig build
   --fork=../..`, which substitutes this working tree for the pinned dependency,
   and then **runs** it: each app ships a `smoke.sh` that starts the program and
   asserts on what it does. Red on the build means this commit broke a published
   API — the signal a consumer would otherwise get one release later. Red on the
   smoke test means the app compiles and does not work, which is the failure a
   compile-only gate cannot see: the gate over `modules/<name>/example/` was
   compile-only too, and one pass after it started running them found 22 that
   did not work. Blocking, and an app without an executable `smoke.sh` is
   rejected — an app whose only proof is that it compiles is the state this
   directory used to be in.

   **Each app is built and run twice: `ReleaseSafe` and `ReleaseFast`.** The
   difference between them is a defect class this collection has already
   shipped — `std.debug.assert` is compiled out of `ReleaseFast`, so a
   fail-open guard is invisible in every safe-mode run and only lets the bad
   thing through in the mode a consumer is most likely to build. The module
   lanes have always tested three optimize modes; until this landed the apps
   tested one, and it was not even the one they claimed (see the CHANGELOG).
2. **On a tag ref**, `scripts/check-apps.sh --pinned` builds each app from its
   manifest as written: fetch by URL and hash, compile the exported package.
   On a tag the pin and the commit under test are the same content, so this is
   not a comparison of two versions — it is the only check that goes through
   `.paths`, and therefore the only one that can notice the package omitting a
   file the apps import. `check-package` covers `LICENSE` and `NOTICE` by name
   and nothing else, and the package having shipped without either is why that
   check exists. `--pinned` refuses to run where the pin does not resolve to
   `HEAD`, rather than quietly answering a different question.

### The check that is deliberately absent: our new version against our old one

The same source compiled against two tags could be run against itself — a
server from the previous tag against a client from the commit under test — and
that is a wire-compatibility check no in-repo test can be. We do not do it, and
the reason is worth writing down so it is not proposed again as an oversight.

For both protocols represented here it is dominated, for the same reason by two
different routes. `ssh` carries **20 live interop tests against real OpenSSH**
in both directions — curve25519 and DH group14/16, ed25519 and
rsa-sha2-256/512, chacha20-poly1305 and AES-GCM, `mlkem768x25519-sha256` — and
the CI runner is pinned to an image chosen for that OpenSSH version. `mls` has
no live peer, but it is pinned byte-exact to the official mlswg interop
vectors, including whole recorded sessions replayed Commit by Commit with the
epoch authenticator compared at every step — recordings produced by other
implementations, which is the same independence in a different form.

A foreign implementation fails independently of us; our own previous version
shares every misreading of the RFC we have ever had. Nor does either protocol
promise anything across *our* versions: they promise conformance, and
conformance is what is measured.

Where the check would earn its cost is a protocol with no foreign
implementation to test against — there the previous version is the only oracle
there is. `raft-kv` is such a protocol (the peer wire is the `raft` module's
own codec), and the section was revisited when it landed: the check is still
not warranted, because the app makes no cross-version promise to break — a
cluster runs ONE binary, and mixed-version clusters are outside what the demo
claims. What the wire carries is instead anchored the other way: the consensus
decisions behind every message are the module's model-checked kernel, and the
kernel — not the framing — is where a wire misunderstanding would corrupt
state. If an app arrives that promises rolling upgrades, this is the section
to revisit again.

## Adding one

1. `example-apps/<name>/` with `build.zig`, `build.zig.zon`, `init.sh`,
   `README.md`, `src/`.
2. Add it to `example_apps` in the root `build.zig`, listing the modules it
   imports. `scripts/check-apps.sh` fails on a directory nobody declared and on
   a declaration whose directory is gone.
3. Pin the current release tag. `scripts/tag.sh` rewrites the pin when a new
   tag is cut, so a copy taken from tag T is built against T.
4. Open the README with the download command for that one directory, naming the
   same tag. `scripts/tag.sh` rewrites it with the pin and `check-apps.sh` fails
   if the two ever disagree.
5. Write `smoke.sh`: start the app and assert on what it does, exit 0 or 1.
   Required — `check-apps.sh` refuses an app without one. Wait on the program's
   own output rather than on a fixed `sleep`, pick an ephemeral port per run,
   give the script a watchdog, and print every process's log on failure. Each
   of those is a lesson from writing the three that exist: a `sleep` is either
   flaky or slow, a fixed port collides with the previous run's `TIME_WAIT`, and
   a readiness probe that opens a socket IS a client — it consumed the single
   connection `ssh-demo --once` had to give.
6. Add a row to the table at the top of this file. `check-apps.sh` fails on an
   app the catalogue does not list.
