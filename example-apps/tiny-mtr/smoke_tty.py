#!/usr/bin/env python3
"""Drives tiny-mtr's screen through a real pty: what `smoke.sh` cannot see from
a pipe. Asserts on what a person at the terminal would notice: the table
appears, a key is answered while the prober is busy, a resized window gets the
layout that fits, and every way out gives the terminal back as it was."""
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

BIN = sys.argv[1]
# A key must be answered at once. The prober may be blocked for many seconds
# below, so anything near this limit means the key waited for it.
KEY_LIMIT_S = 0.5


def fail(why, seen=b""):
    print(f"smoke_tty: FAILED: {why}", file=sys.stderr)
    if seen:
        print(f"last output: {seen[-800:]!r}", file=sys.stderr)
    sys.exit(1)


class App:
    def __init__(self, *args, rows=24, cols=100):
        self.master, slave = pty.openpty()
        self.winsize(rows, cols, master=slave)
        self.before = termios.tcgetattr(slave)
        self.pid = os.fork()
        if self.pid == 0:
            os.close(self.master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for fd in (0, 1, 2):
                os.dup2(slave, fd)
            if slave > 2:
                os.close(slave)
            os.execv(BIN, [BIN, *args])
        self.slave = slave
        self.seen = b""

    def winsize(self, rows, cols, master=None):
        fcntl.ioctl(self.master if master is None else master, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))

    def pump(self, timeout):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            data = os.read(self.master, 65536)
        except OSError:
            return False
        self.seen += data
        return bool(data)

    def wait_for(self, text, timeout=10, what=None):
        """Waits for `text` in output that arrives from now on."""
        start = len(self.seen)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.pump(0.05)
            if text in self.seen[start:]:
                return
        fail(f"never saw {what or text!r}", self.seen)

    def key(self, b):
        os.write(self.master, b)

    def wait_exit(self, limit, what):
        """Exits within `limit`, with status 0, and the terminal restored."""
        end = time.monotonic() + limit
        while time.monotonic() < end:
            self.pump(0.01)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                while self.pump(0):
                    pass
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    fail(f"{what}: exit status {status}", self.seen)
                if b"\x1b[?25h\x1b[?1049l" not in self.seen:
                    fail(f"{what}: the screen was not left", self.seen)
                if termios.tcgetattr(self.slave) != self.before:
                    fail(f"{what}: the terminal settings were not restored")
                return time.monotonic()
        os.kill(self.pid, signal.SIGKILL)
        fail(f"{what}: still running after {limit}s", self.seen)


# The table appears, and `q` is answered while the prober sleeps out a
# 20-second interval: the case a loop reading keys between rounds fails.
a = App("-n", "-i", "20", "127.0.0.1")
a.wait_for(b"\x1b[?1049h", what="the alternate screen")
a.wait_for(b"127.0.0.1", what="the hop")
a.wait_for(b"rounds 1", what="the first round counted")
time.sleep(0.2)
t0 = time.monotonic()
a.key(b"q")
took = a.wait_exit(KEY_LIMIT_S, "q while the prober is blocked") - t0
print(f"smoke_tty: q answered in {took * 1000:.0f} ms while the prober was blocked")
if b"tiny-mtr to 127.0.0.1" not in a.seen:
    fail("no final table after leaving the screen", a.seen)

# Reset empties the table at once, and counting goes on from nothing. A key
# inside an escape sequence does nothing: this `q` would otherwise quit.
a = App("-n", "-i", "0.1", "127.0.0.1")
a.wait_for(b"rounds 3", what="three rounds")
a.key(b"\x1bOq")
a.wait_for(b"tiny-mtr  127.0.0.1", what="still drawing after an escape sequence")
if os.waitpid(a.pid, os.WNOHANG)[0]:
    fail("an escape sequence quit", a.seen)
t0 = time.monotonic()
a.key(b"r")
a.wait_for(b"rounds 0", timeout=KEY_LIMIT_S, what="rounds 0 right after r")
a.wait_for(b"rounds 1", what="counting after a reset")

# Pause holds the count, and the same key goes on.
a.key(b"p")
a.wait_for(b"[paused]", timeout=KEY_LIMIT_S, what="[paused]")
time.sleep(0.5)  # A round in flight may still finish.
a.pump(0)
mark = len(a.seen)
time.sleep(0.5)
while a.pump(0):
    pass
if a.seen[mark:]:
    fail("drawing while paused", a.seen[mark:])
a.key(b"p")
a.wait_for(b"rounds", what="rounds after going on")

# A smaller window gets the columns that fit, right after the resize.
a.wait_for(b"StDev", what="every column at 100 wide")
a.winsize(20, 60)
a.wait_for(b"\x1b[2J", timeout=KEY_LIMIT_S, what="a redraw after a resize")
a.wait_for(b"Loss%", what="the table at 60 wide")
after_resize = a.seen[a.seen.rfind(b"\x1b[2J"):]
if b"StDev" in after_resize:
    fail("StDev at 60 wide", after_resize)

# Names go on and off at once. Started with -n, so `n` is what asks for them.
a.key(b"n")
a.wait_for(b"names on", timeout=KEY_LIMIT_S, what="names on")
a.key(b"n")
a.wait_for(b"names off", timeout=KEY_LIMIT_S, what="names off")
a.key(b"\x03")
a.wait_exit(KEY_LIMIT_S, "Ctrl-C")

# A pause holds during a long interval, not only at its end.
a = App("-n", "-i", "2", "127.0.0.1")
a.wait_for(b"rounds 1", what="the first round")
a.key(b"p")
a.wait_for(b"[paused]", timeout=KEY_LIMIT_S, what="[paused]")
end = time.monotonic() + 2.5
while time.monotonic() < end:
    a.pump(0.05)
if b"rounds 2" in a.seen:
    fail("a round ran during a pause", a.seen)
# A reset during it empties the table, and going on starts the count over.
a.key(b"r")
a.wait_for(b"rounds 0", timeout=KEY_LIMIT_S, what="rounds 0 during a pause")
a.key(b"p")
a.wait_for(b"rounds 1", what="a round after a reset and a pause")
a.key(b"q")
a.wait_exit(KEY_LIMIT_S, "q after a pause")

# Signals take the same way out as the keys.
for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    a = App("-n", "-i", "20", "127.0.0.1")
    a.wait_for(b"rounds 1", what="the first round")
    os.kill(a.pid, sig)
    a.wait_exit(KEY_LIMIT_S, sig.name)

# -c on the screen stops by itself.
a = App("-n", "-i", "0.1", "-c", "3", "127.0.0.1")
a.wait_exit(10, "-c 3")
if b"3 rounds" not in a.seen:
    fail("-c 3 did not count 3 rounds", a.seen)

print("smoke_tty: OK")
