# isis-dis

IS-IS LAN Designated-IS (DIS) election (ISO/IEC 10589 §7.2.6 / §8.4.5): a pure,
time-injected FSM that, from the routers seen on a LAN circuit (each with its
priority + SNPA/MAC), elects the DIS — highest priority, SNPA tie-break,
immediate preemption (no hold-down) — reports whether THIS system is the DIS,
and derives the pseudonode LSP-ID the DIS originates. No threads/timers/sockets:
the caller supplies the neighbour view + `now` and acts on the DIS-change
effect. Adds LAN to the P2P `isis-adj`/`isis-lsdb`/`isis-flood`/`isis-spf` stack.

**Status:** gap (placeholder — implementation pending).
