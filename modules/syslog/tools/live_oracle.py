#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Live checks of what a frozen vector cannot hold: real sockets to real daemons.

    python3 live_oracle.py EXE DIR      # run by `zig build interop-syslog -- --live`

EXE is the interop program, which sends with this module's real emitters.

  tls        RFC 5425: `WriterEmitter` over a real TLS 1.3 session of `tlsclient`
             into Python's `ssl` (OpenSSL) as the server, with a certificate from
             `openssl req`. The frames are read back here, after TLS.
  reconnect  `ReconnectingEmitter` to a real rsyslogd over TCP; the daemon is
             STOPPED AND STARTED AGAIN between two records. Both must land.
  framing    `TcpEmitter` with LF framing, RFC 3164 and RFC 5424, to rsyslogd.
  memfd      `journal.Emitter` with a 3 MiB value to a real systemd-journald, which
             must store it whole through the sealed-memfd path.

Needs python3, openssl, rsyslogd 8, systemd-journald, journalctl, unshare and ip.
No root, no network. Same daemon setup as rsyslog_oracle.py, whose notes apply.
"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rsyslog_oracle  # noqa: E402

PORT = 5515


def check_tls(exe, d):
    key, crt = os.path.join(d, 'tls.key'), os.path.join(d, 'tls.crt')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-keyout', key, '-out', crt, '-days', '2', '-subj', '/CN=syslog.test',
                    '-addext', 'subjectAltName=DNS:syslog.test'], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.create_server(('127.0.0.1', 0))
    port = srv.getsockname()[1]
    got = {}

    def serve():
        conn, _ = srv.accept()
        with ctx.wrap_socket(conn, server_side=True) as t:
            got['version'] = t.version()
            buf = b''
            while True:
                b = t.recv(65536)
                if not b:
                    break
                buf += b
            got['bytes'] = buf

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    subprocess.run([exe, '--emit-tls', str(port)], check=True, timeout=30)
    th.join(10)
    frames, rest = [], got.get('bytes', b'')
    while rest:
        m = re.match(rb'([1-9][0-9]*) ', rest)
        if not m:
            return 'not octet counted at %r' % rest[:40]
        n = int(m.group(1))
        frames.append(rest[m.end():m.end() + n])
        rest = rest[m.end() + n:]
    want = [b'<14>1 - tls-host tls-app - - - over TLS one', b'<14>1 - tls-host tls-app - - [a@1 k="v\\"w"] two',
            b'<13>tlstag: three']
    if frames != want:
        return 'frames %r, want %r' % (frames, want)
    return None if got['version'] == 'TLSv1.3' else 'negotiated %s' % got['version']


def start_rsyslog(d, port):
    proc = subprocess.Popen([os.path.join(d, 'rsyslogd'), '-n', '-iNONE', '-f', os.path.join(d, 'rsyslog.conf')],
                            stderr=subprocess.DEVNULL)
    for _ in range(200):
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.1).close()
            return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    raise RuntimeError('rsyslogd did not listen')


def inner_rsyslog(exe, d):
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    with open(os.path.join(d, 'rsyslog.conf'), 'w') as fh:
        fh.write(rsyslog_oracle.CONF % {'dir': d, 'port': PORT})
    proc = start_rsyslog(d, PORT)
    emit = subprocess.Popen([exe, '--emit-reconnect', str(PORT)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        if emit.stdout.readline().strip() != b'sent-one':
            raise RuntimeError('emitter: no first record')
        time.sleep(0.3)  # rsyslogd has read the first record
        proc.terminate()
        proc.wait(timeout=20)
        proc = start_rsyslog(d, PORT)
        time.sleep(0.1)
        emit.stdin.write(b'go\n')
        emit.stdin.flush()
        if emit.wait(timeout=30) != 0:
            raise RuntimeError('emitter failed')
        out = os.path.join(d, 'out.json')
        for _ in range(100):
            if os.path.exists(out):
                with open(out, 'rb') as fh:
                    if fh.read().count(b'\n') >= 4:
                        break
            time.sleep(0.05)
    finally:
        proc.terminate()
        proc.wait(timeout=20)
        if emit.poll() is None:
            emit.kill()


def check_rsyslog(exe, d):
    out = os.path.join(d, 'out.json')
    if os.path.exists(out):
        os.remove(out)
    shutil.copy(shutil.which('rsyslogd') or '/usr/sbin/rsyslogd', os.path.join(d, 'rsyslogd'))
    subprocess.run(['unshare', '-rn', sys.executable, os.path.abspath(__file__), 'inner-rsyslog', exe, d], check=True)
    with open(out, 'rb') as fh:
        msgs = [json.loads(line)['msg'].strip() for line in fh.read().splitlines()]
    want = ['reconnect-one', 'reconnect-two', 'lf-5424 a b', 'lf-3164 c d']
    # Two connections: rsyslogd's workers may store them in either order.
    return None if sorted(msgs) == sorted(want) else 'rsyslogd read %r, want %r' % (msgs, want)


def inner_journal(exe, d):
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run'], check=True)
    os.makedirs('/run/systemd/journal', exist_ok=True)
    os.makedirs('/run/log/journal', exist_ok=True)
    subprocess.run(['mount', '--bind', os.path.join(d, 'jlog'), '/run/log/journal'], check=True)
    proc = subprocess.Popen(['/usr/lib/systemd/systemd-journald'], stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if os.path.exists('/run/systemd/journal/socket'):
                break
            time.sleep(0.05)
        subprocess.run([exe, '--emit-memfd', '/run/systemd/journal/socket'], check=True, timeout=30)
        time.sleep(1)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def check_memfd(exe, d):
    jlog = os.path.join(d, 'jlog')
    shutil.rmtree(jlog, ignore_errors=True)
    os.makedirs(jlog)
    subprocess.run(['unshare', '-rm', sys.executable, os.path.abspath(__file__), 'inner-journal', exe, d], check=True)
    out = subprocess.run(['journalctl', '-D', jlog, '-o', 'json', '--all', '--no-pager'], capture_output=True, check=True).stdout
    for line in out.splitlines():
        r = json.loads(line)
        if r.get('LIVE_ORACLE') == 'memfd':
            msg = r.get('MESSAGE', '')
            if len(msg) == 3 << 20 and set(msg) == {'x'}:
                return None
            return 'journald stored a MESSAGE of %d bytes' % len(msg)
    return 'journald stored no record'


def main():
    if sys.argv[1] == 'inner-rsyslog':
        return inner_rsyslog(sys.argv[2], sys.argv[3])
    if sys.argv[1] == 'inner-journal':
        return inner_journal(sys.argv[2], sys.argv[3])
    exe, d = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(d, exist_ok=True)
    failed = 0
    for name, f in (('tls', check_tls), ('reconnect+framing', check_rsyslog), ('memfd', check_memfd)):
        why = f(exe, d)
        print('%-20s %s' % (name, 'ok' if why is None else 'FAILED: ' + why))
        failed += why is not None
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
