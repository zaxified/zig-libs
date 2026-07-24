# isis-adj

The IS-IS point-to-point adjacency state machine (ISO/IEC 10589 §8.2 + RFC 5303
three-way handshake): a pure, time-injected FSM driving one P2P neighbour
Down → Initializing → Up from received IIH PDUs (decoded by the sibling `isis`
codec) and hold-timer expiry. No threads, no owned timers, no sockets — the
caller supplies `now` + received PDUs and acts on the emitted effects. LAN
adjacency + DIS election deferred (E-Line/P2P is the current fabric phase).

**Status:** gap (placeholder — implementation pending).
