# example-apps

Standalone applications built on zig-libs. Each one is a **separate project**:
its own `build.zig`, its own `build.zig.zon`, and a `zig-libs` dependency
pinned to a dated release tag. Copy a directory anywhere, run `./init.sh`, and
you have a working binary — nothing here needs this repository to be present.

That is the primary purpose, and the manifests are written for it and for
nothing else.

| App | What it is | Modules it uses |
|---|---|---|
| [`ssh-demo`](ssh-demo/) | An SSH-2.0 client and server in one binary, with real `known_hosts` and `authorized_keys` handling. | `ssh` |

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

Both are arranged from outside the app, so its manifest stays the customer's:

1. `scripts/check-apps.sh` builds each app with `zig build --fork=../..`,
   which overrides the pinned dependency with this working tree. An app builds
   against its tag but not against the tree exactly when this collection has
   broken a published API — the signal a consumer would otherwise get one
   release later.
2. Two builds of the *same source* at two versions can be run against each
   other: a server from the previous tag against a client from the commit under
   test. That is a wire-compatibility check no in-repo test can be, because
   both sides of an in-repo test are always the same version.

The second one is why **an app is written against the tagged API and never
against unreleased work** — the source has to compile against both versions, or
the comparison measures the app instead of the library.

## Adding one

1. `example-apps/<name>/` with `build.zig`, `build.zig.zon`, `init.sh`,
   `README.md`, `src/`.
2. Add it to `example_apps` in the root `build.zig`, listing the modules it
   imports. `scripts/check-apps.sh` fails on a directory nobody declared and on
   a declaration whose directory is gone.
3. Pin the current release tag. `scripts/tag.sh` rewrites the pin when a new
   tag is cut, so a copy taken from tag T is built against T.
