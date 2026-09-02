# ssh-demo

An SSH-2.0 **client and server** in one binary, built on the `ssh` module.

## Get it

Take this directory and nothing else — it is a self-contained project, and the
rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-09-02.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-09-02/example-apps/ssh-demo'
cd ssh-demo
```

With git instead, if you would rather have history:

```sh
git clone --depth 1 --filter=blob:none --sparse -b 2026-09-02 \
  https://github.com/zaxified/zig-libs.git
cd zig-libs && git sparse-checkout set example-apps/ssh-demo
cd example-apps/ssh-demo
```

## Build and run

```sh
./init.sh                                  # fetch dependencies, build
./zig-out/bin/ssh-demo server --port 2222  # one shell
./zig-out/bin/ssh-demo client --port 2222  # another
```

`init.sh` needs Zig 0.16.0 on `PATH` and installs nothing for you.

## What is worth reading it for

**The host-key decision.** The module hands the caller a `HostKeyVerifier` and
takes no position on trust — it does not know where your `known_hosts` lives,
whether you want trust-on-first-use, or whether a mismatch should abort. That is
deliberate and it is the norm (Go's `HostKeyCallback`, russh's
`check_server_key` have the same shape). It also means a demo that writes
`return true` teaches the one lesson we do not want taught. So this one parses
`known_hosts` for real: literal and hashed host patterns, per-key-type entries,
`@revoked` markers, the OpenSSH mismatch warning, and a TOFU prompt that appends
the accepted key.

The server side is the same lesson from the other end: `AuthorizedKeyCheck`
discharged against a real `authorized_keys`, including `@revoked` and
`@cert-authority`, quoted option fields, and a logged reason for every refusal.

## What it does NOT do

No PTY, no interactive shell, no port forwarding, no agent; one session channel
at a time. The `ssh` module does not have them (`SPEC.md`, *Backlog / deferred*),
so the demo refuses them out loud at startup rather than hanging somewhere
obscure later.

## Interop

It talks to OpenSSH in both directions — point a real `ssh` client at the server
mode, or the client mode at a local `sshd`.
