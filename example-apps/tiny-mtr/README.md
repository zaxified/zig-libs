# tiny-mtr

A continuous traceroute with a live table: every router on the way to a host,
with its loss and round-trip times, updating as the answers come in. The command
line and the columns follow [mtr]; this is its small cousin, not a port, and
none of mtr's source was read.

[mtr]: https://github.com/traviscross/mtr

```
tiny-mtr  example.net (203.0.113.80)  icmp  rounds 5
q quit  r reset  n names on  p pause
 Hop Host                                       Loss%  Snt   Last    Avg   Best   Wrst  StDev
  1. gateway (192.0.2.1)                         0.0%    5    1.2    2.3    0.9    5.9    2.1
  2. 198.51.100.1                                0.0%    5   11.1   10.1    8.9   11.7    1.2
  3. ???                                       100.0%    5      -      -      -      -      -
  4. edge-1.isp.example (198.51.100.9)          80.0%    5   13.7   13.7   13.7   13.7      -
  5. example.net (203.0.113.80)                  0.0%    5   14.8   21.3   14.7   36.9    9.4
```

## Get it

Take this directory and nothing else — it is a self-contained project, and the
rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-11-13.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-11-13/example-apps/tiny-mtr'
cd tiny-mtr
```

## Build and run

```sh
./init.sh
./zig-out/bin/tiny-mtr example.net
```

It needs no root for ICMP as long as your group is inside
`net.ipv4.ping_group_range`, which most distributions open for everyone. If it
is not, the program says so; `sudo setcap cap_net_raw+ep zig-out/bin/tiny-mtr`
is the other way. Linux only.

```
tiny-mtr [options] HOST

  -r, --report        no screen: run the rounds, print the table, exit
  -c, --count N       stop after N rounds (a report's default is 10)
  -i, --interval SEC  time between rounds, at least 0.1 (default 1)
  -w, --timeout SEC   how long a round waits for answers, up to 10 (default 1)
  -m, --max-hops N    highest TTL, up to 255 (default 30)
  -n, --no-dns        show addresses, send no PTR queries
  -u, --udp           UDP probes on one flow (Paris traceroute)
  -T, --tcp           TCP connection attempts as probes
  -P, --port N        port of -T (default 80) or -u (default 33434)
  -4, -6              ask DNS for this address family only
```

On the screen: `q` or Ctrl-C quits and leaves the final table behind, `r` starts
the statistics over, `n` switches names on and off, `p` pauses and goes on. When
output or input is not a terminal it behaves as `-r`, so it can go into a pipe.

**Reading the table.** `???` is a router that does not answer. Loss at a router
that does not continue to later hops usually means it rate-limits its own ICMP
answers, not that your packets are lost: the figure that matters is the one at
the last hop. `+1` after a host means another router answered at this TTL too (a
load balancer), and `!13` is the code of a Destination Unreachable.

## How the screen stays responsive

A round can take seconds when routers stay silent, so nothing that a person
waits for lives on the same thread as one:

- the **main thread** owns the terminal and only ever blocks in `poll`, on the
  keyboard and on an eventfd anything else writes when it has news;
- the **prober** owns the sockets and spends its life inside `LiveMtr.round`.
  `Mtr.on_answer` hands it each answer as it arrives, which is why hops appear
  during the first round rather than at its end;
- the **namer** owns the DNS resolver, so a slow PTR server delays other names and
  nothing else.

Quitting does not wait for a round: the process exits, and that closes the
sockets. Each way out, a signal or a panic on any thread included, gives the
terminal back as it was. Ctrl-Z is not handled: in raw mode it is one more key.

PTR names come from whoever owns the address and end up on your terminal, so
anything outside a host name's alphabet is replaced before it is stored.

## What it is built on

| Module | Used for |
|---|---|
| [`traceroute`](../../modules/traceroute/) | `LiveMtr`: the probes, the answer rules, the per-hop statistics |
| [`dns`](../../modules/dns/) | The host's address, PTR names |
| [`netaddr`](../../modules/netaddr/) | Addresses |

Left out to stay small: AS numbers (a `dns.lookupTxt` on Team Cymru away), several
hosts at once (`traceroute.MtrSet`), MPLS labels (`Mtr.lastRound()` has them).

## Tests

`zig build test` runs the logic without a terminal: arguments, keys, every
column at every window size. `./smoke.sh` runs the program over loopback with
every method, and drives the screen through a real pty: a key answered within
0.5 s while the prober is blocked for 20 s, reset, pause, resize, and the terminal
restored after each way out. It needs `python3`.
