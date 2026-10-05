#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The syslog oracle: a real rsyslogd (black box, its own RFC 5424 and RFC 3164
parsers plus mmpstrucdata for structured data) receives every message this
module encodes and renders what it parsed; each parsed field must be what the
message meant -- the header values the caller passed (after this module's
documented sanitizing and length limits), every SD-PARAM value unescaped back
to the caller's bytes, MSG byte for byte, the instant of the timestamp.

RFC 5424 messages go out twice: as the datagram `buildDatagram` makes (UDP)
and as the frame `writeOctetCounted` makes (TCP, RFC 6587), on one
connection. RFC 3164 lines go out over UDP.

Driven by tools/interop.zig (`zig build interop-syslog`):

    rsyslog_oracle.py gen                     cases (JSON, strings hex) on stdout
    rsyslog_oracle.py judge CASES OURS OUT    verdicts; writes the Zig vectors to OUT
    rsyslog_oracle.py inner DIR               (internal) runs inside `unshare -rn`

rsyslogd runs from a copy under the scratch directory: the distribution's
AppArmor profile attaches to /usr/sbin/rsyslogd by path, confines its config
and output to /etc and /var/log, and refuses signals from a confined shell
(so the daemon could not even be stopped). The copy is unconfined, reads a
throwaway config and is stopped with SIGTERM. `unshare -rn` gives it a
loopback of its own. No root, no network.
"""
import calendar
import json
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import time

SEED = 5424
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 5514
MARKER = b'...[TRUNCATED]'
UDP_LIMIT = 1024
MAX_EPOCH = 253402300799
LIMITS = {'hostname': 255, 'app_name': 48, 'procid': 128, 'msgid': 32}

# Header-field values: valid, at and past every limit, every byte class the encoder maps.
HDR = [None, b'', b'-', b'--', b'web-1', b'a b', b'tab\there', b'\x00', b'\x7f', b'\xc3\xa9t\xc3\xa9', b'line\nbreak',
       b'[x]', b'"q"', b'=', bytes(range(33, 127)), b'h' * 32, b'h' * 33, b'h' * 48, b'h' * 49, b'h' * 128, b'h' * 129,
       b'h' * 255, b'h' * 256, b'h.example.com', b'2001:db8::1', b'192.0.2.1']
SD_NAMES = [b'a@1', b'exampleSDID@32473', b'timeQuality', b'origin', b'meta', b'x' * 32, b'x' * 33, b'', b' ', b'a b',
            b'a=b', b'a]b', b'a"b', b'\xc3\xa9', b'\x00', b'-', b'@', b'origin@123']
SD_VALUES = [b'', b'3', b'"', b'\\', b']', b'\\"]', b'a\\b"c]d', b'[', b'=', b' ', b'\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80',
             b'line\nbreak', b'\x00', b'\xff', b'\xe2\x82', b'x' * 600, b'"]["', b'\\\\', b'\\]', b'\\"']
MSGS = [b'', b'hello', b' lead', b'trail ', b'  ', b'a\nb', b'\n', b'end\n', b'\x00x', b'\xef\xbb\xbfBOM text',
        b'\xc3\xa9\xe2\x82\xac', b'\xff\xfe', b'[a@1 x="1"]', b'- -', b'"\\]', b'x' * 900, b'\tt', b'\r\n']
# (unix_ms, offset_minutes); None = no timestamp.
TS = [None, (0, None), (1, None), (999, None), (1783600496123, None), (1783600496123, 0), (1783600496123, 60),
      (1783600496123, -330), (1783600496123, 345), (1783600496123, 840), (1783600496123, -720),
      (951782399999, None), (951782400000, None), (1709164800000, 120), (946684799999, -1),
      (MAX_EPOCH * 1000 + 999, None), (MAX_EPOCH * 1000 + 1000, None), (-1, None), (0, -1), (0, 1),
      (1783600496123, 1439), (1783600496123, -1439), (1783600496123, 1440), (1783600496123, -1440),
      (1783600496123, 1500), (1783600496123, 32767), (1783600496123, -32768), (MAX_EPOCH * 1000, 60),
      (2145916800000, None), (2147483647000, None), (2147483648000, None), (4102444800000, None), (4133980800000, None),
      (32503680000000, None), (253370764800000, None)]
J_VALUES = [b'', b'plain', b'=', b'a=b', b'trailing ', b' leading', b'line\nbreak', b'\n', b'end\n', b'\r\n', b'\x00', b'a\x00b',
            b'\xff\xfe', b'\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80', b'\t', b'\x1b[31mred', b'x' * 4096, b'y\n' * 2000,
            b'MESSAGE=forged', b'\nMESSAGE=forged', b'\nPRIORITY=0\n']
J_NAMES = [b'A', b'MESSAGE', b'ABC_1', b'A_', b'Z9', b'CODE_FILE', b'_A', b'__A', b'_SYSTEMD_UNIT', b'1A', b'9', b'a', b'Ab',
           b'A-B', b'A.B', b'A B', b'\xc3\x89', b'N' * 64, b'N' * 65, b'_', b'A__B', b'A\x7f']
BSD_HOSTS = [None, b'host', b'-', b'', b'a b', b'\xc3\xa9', b'h.example.com', b'host:1', b'h' * 64, b'[h]', b'192.0.2.1', b'2001:db8::1', b'::1', b'host_1', b'Host.Example.COM', b'a-', b'-a', b'1', b'h:',
             b'evil app[1]:']
BSD_TAGS = [b'app', b'', b'a:b', b'a b', b'app/x', b'a[1]', b'x' * 32, b'x' * 40, b'\xc3\xa9', b'123', b'CRON', b'-']
BSD_PIDS = [None, b'', b'123', b'a]b', b'a b', b'\n', b'0', b'-']
BSD_MSGS = [b'hello', b'', b' x', b':', b'a\nb', b'[x]: y', b'\xc3\xa9']


def h(b):
    return None if b is None else b.hex()


def gen():
    rng = random.Random(SEED)
    out = []
    base = {'kind': '5424', 'facility': 1, 'severity': 5, 'ts': [1783600496123, 60], 'hostname': h(b'web-1'),
            'app_name': h(b'api'), 'procid': h(b'4242'), 'msgid': h(b'REQ'), 'sd': [], 'msg': h(b'ok')}

    def c5424(**kw):
        c = dict(base)
        c.update(kw)
        out.append(c)

    for f in range(24):
        for s in range(8):
            c5424(facility=f, severity=s)
    for ts in TS:
        c5424(ts=list(ts) if ts else None)
    for field in LIMITS:
        for v in HDR:
            c5424(**{field: h(v)})
    for n in SD_NAMES:
        c5424(sd=[{'id': h(n), 'params': [[h(b'p'), h(b'v')]]}])
        c5424(sd=[{'id': h(b'a@1'), 'params': [[h(n), h(b'v')]]}])
    for v in SD_VALUES:
        c5424(sd=[{'id': h(b'a@1'), 'params': [[h(b'p'), h(v)]]}])
    c5424(sd=[{'id': h(b'a@1'), 'params': []}])
    c5424(sd=[{'id': h(b'a@1'), 'params': []}, {'id': h(b'b@2'), 'params': [[h(b'x'), h(b'1')], [h(b'y'), h(b']')]]}])
    c5424(sd=[{'id': h(b'a@1'), 'params': [[h(b'x'), h(b'1')], [h(b'x'), h(b'2')]]}])
    for m in MSGS:
        c5424(msg=h(m))
        c5424(msg=h(m), sd=[{'id': h(b'a@1'), 'params': [[h(b'p'), h(b'"]')]]}])
    c5424(msg=h(b'y' * 2000))
    c5424(msg=h(b'y' * 2000), sd=[{'id': h(b'a@1'), 'params': [[h(b'p'), h(b'z' * 900)]]}])
    for _ in range(60):
        c5424(facility=rng.randrange(24), severity=rng.randrange(8), ts=list(rng.choice(TS[1:12])),
              hostname=h(rng.choice(HDR)), app_name=h(rng.choice(HDR)), procid=h(rng.choice(HDR)), msgid=h(rng.choice(HDR)),
              sd=[{'id': h(rng.choice(SD_NAMES[:7])), 'params': [[h(rng.choice(SD_NAMES[:7])), h(rng.choice(SD_VALUES))]
                                                                 for _ in range(rng.randrange(3))]} for _ in range(rng.randrange(3))],
              msg=h(rng.choice(MSGS)))

    bbase = {'kind': '3164', 'facility': 16, 'severity': 4, 'ts': [1783600496000, None], 'hostname': h(b'host'),
             'tag': h(b'app'), 'pid': h(b'123'), 'msg': h(b'hello')}

    def c3164(**kw):
        c = dict(bbase)
        c.update(kw)
        out.append(c)

    for f, s in ((0, 0), (1, 5), (3, 6), (4, 2), (10, 1), (23, 7)):
        c3164(facility=f, severity=s)
    for ms in (None, 0, 1783600496000, 1767225599000, 1772323200000, 1704067200000 + 9 * 86400000, 1783600496999,
               1786060800000, 1790726400000, -1, (MAX_EPOCH + 1) * 1000):
        c3164(ts=None if ms is None else [ms, None])
    c3164(ts=[1783600496000, 120])
    for v in BSD_HOSTS:
        c3164(hostname=h(v))
    for v in BSD_TAGS:
        c3164(tag=h(v))
        c3164(tag=h(v), pid=None)
    for v in BSD_PIDS:
        c3164(pid=h(v))
    for v in BSD_MSGS:
        c3164(msg=h(v))

    # journald, native protocol: field sets through journal.Emitter.send / sendMessage.
    for i, v in enumerate(J_VALUES):
        out.append({'kind': 'journal', 'fields': [[h(b'MESSAGE'), h(b'value %d' % i)], [h(b'ORACLE_VALUE'), h(v)]]})
    out.append({'kind': 'journal', 'fields': [[h(b'MESSAGE'), h(b'repeated')], [h(b'TAGS'), h(b'a')], [h(b'TAGS'), h(b'b\nc')],
                                              [h(b'TAGS'), h(b'')]]})
    out.append({'kind': 'journal', 'fields': [[h(b'MESSAGE'), h(b'many')]] + [[h(b'F%d' % k), h(b'%d' % k)] for k in range(60)]})
    out.append({'kind': 'journal', 'fields': [[h(b'MESSAGE'), h(b'long name')], [h(b'N' * 64), h(b'64')]]})
    out.append({'kind': 'journal', 'fields': [[h(b'MESSAGE'), h(b'\n')], [h(b'PRIORITY'), h(b'3')], [h(b'CODE_FILE'), h(b'a.zig')]]})
    for msg, prio, ident in ((b'hello', 6, b'ttydesk'), (b'multi\nline', 3, None), (b'', None, b'x'), (b'\xff\x00', 0, b'a b'),
                             (b'prio only', 7, None)):
        out.append({'kind': 'jsend', 'message': h(msg), 'priority': prio, 'identifier': h(ident),
                    'fields': [[h(b'AUDIT_EVENT'), h(b'login')], [h(b'AUDIT_USER'), h(b'z\x01')]]})
    for n in J_NAMES:
        out.append({'kind': 'jname', 'name': h(n)})
    json.dump(out, sys.stdout)


# ---------------------------------------------------------------- the meaning

def field(v, limit):
    """What a header field means after this module's documented rules: NILVALUE for absent/empty, else
    truncated to the RFC limit with every byte outside 33..126 replaced by `-`."""
    if not v:
        return b'-'
    return bytes(b if 33 <= b <= 126 else 0x2d for b in v[:limit])


def sd_name(v):
    if not v:
        return b'-'
    return bytes(b if 32 < b < 127 and b not in b'=]"' else 0x2d for b in v[:32])


def ts_meaning(ts):
    """(utc_seconds, millis, offset_minutes) the TIMESTAMP field must carry, or None for NILVALUE."""
    if ts is None:
        return None
    ms, off = ts
    if off is not None:  # ±HH:MM carries at most 23:59; the instant must survive the clamp
        off = max(-1439, min(1439, off))
    shifted = ms + (off or 0) * 60000
    if shifted // 1000 < 0 or shifted // 1000 > MAX_EPOCH:
        return None
    return (ms // 1000, ms % 1000, off or 0)


def parse_rfc3339(s):
    """rsyslog's rendering of `timereported` -> (utc_seconds, fraction digits, offset_minutes)."""
    date, rest = s.split('T')
    clock, frac, off = rest[:8], '', 0
    tail = rest[8:]
    if tail.startswith('.'):
        i = 1
        while i < len(tail) and tail[i].isdigit():
            i += 1
        frac, tail = tail[1:i], tail[i:]
    if tail not in ('Z', ''):
        sign = -1 if tail[0] == '-' else 1
        off = sign * (int(tail[1:3]) * 60 + int(tail[4:6]))
    y, mo, d = map(int, date.split('-'))
    hh, mi, ss = map(int, clock.split(':'))
    utc = calendar.timegm((y, mo, d, hh, mi, ss)) - off * 60
    return utc, frac, off


def rs(x):
    """rsyslogd's receive policy: a NUL byte becomes the four characters `#000` (not switchable)."""
    return x.replace(b'\x00', b'#000')


def b(s):
    """rsyslog's JSON output carries bytes as text; invalid UTF-8 came through as-is, so map back with surrogateescape."""
    return s.encode('utf-8', 'surrogateescape')


# Divergences: rsyslogd disagrees, and something other than rsyslogd says our bytes are right.
DIVERGENCES = {
    'RSYSLOGD_YEAR_2100': 'rsyslogd refuses an RFC 5424 TIMESTAMP in year 2100 or later and hands the whole header '
                          'back as MSG; RFC 3339 full-date is 4DIGIT (to 9999) and Python datetime.fromisoformat '
                          'reads the field as the same instant.',
}


def divergence5424(c, got):
    want_ts = ts_meaning(c['ts'])
    stamp = got['raw'].split(' ')[1]
    # rsyslogd's refusal looks like this: the whole header, TIMESTAMP first, handed back as MSG.
    if want_ts is not None and time.gmtime(want_ts[0] + want_ts[2] * 60).tm_year >= 2100 and got['msg'].startswith(stamp + ' '):
        import datetime
        line_ts = datetime.datetime.fromisoformat(stamp)  # the third implementation reads it
        if int(line_ts.timestamp()) == want_ts[0]:
            return 'RSYSLOGD_YEAR_2100'
    return ''


def judge5424(c, got, wire_msg, now):
    why = []
    pri = c['facility'] * 8 + c['severity']
    if got['pri'] != str(pri):
        why.append('pri %s' % got['pri'])
    if got['ver'] != '1':
        why.append('version %r' % got['ver'])
    want_ts = ts_meaning(c['ts'])
    if want_ts is None:
        if abs(int(got['tsu']) - now) > 3600:  # NILVALUE: rsyslog stamps the receipt time
            why.append('timestamp %s, want NILVALUE (receipt time)' % got['ts'])
    else:
        utc, frac, off = parse_rfc3339(got['ts'])
        if (utc, frac, off) != (want_ts[0], '%03d' % want_ts[1], want_ts[2]):
            why.append('timestamp %s, want utc=%d ms=%03d off=%d' % (got['ts'], *want_ts))
    for name, key in (('hostname', 'host'), ('app_name', 'app'), ('procid', 'procid'), ('msgid', 'msgid')):
        want = field(bytes.fromhex(c[name]) if c[name] is not None else None, LIMITS[name])
        if b(got[key]) != rs(want):
            why.append('%s %r, want %r' % (name, got[key], want))
    if c['sd']:
        # mmpstrucdata renders SD as a JSON object: a repeated PARAM-NAME (RFC 5424 allows it) or SD-ID
        # (RFC 5424 6.3.2: MUST NOT) keeps the LAST one, so that is what the meaning is compared with.
        want_sd = {}
        for el in c['sd']:
            params = {}
            for n, v in el['params']:
                params[sd_name(bytes.fromhex(n)).decode('ascii')] = rs(bytes.fromhex(v))
            want_sd[sd_name(bytes.fromhex(el['id'])).decode('ascii')] = params
        got_sd = json.loads(got['sdj']) if got['sdj'] else None
        if got_sd is not None:
            got_sd = {k: {pk: b(pv) for pk, pv in v.items()} for k, v in got_sd.items()}
        if got_sd != want_sd:
            why.append('sd %r, want %r' % (got_sd, want_sd))
    elif got['sd'] != '-':
        why.append('sd %r, want NILVALUE' % got['sd'])
    if b(got['msg']) != rs(wire_msg):
        why.append('msg %r, want %r' % (got['msg'], wire_msg))
    return why


def hostname_ok(h):
    """RFC 1123 labels (plus `_`), dot-separated, <= 255 bytes: what the encoder sends as HOSTNAME."""
    if not h or len(h) > 255:
        return False
    for label in h.split(b'.'):
        if not 1 <= len(label) <= 63 or label[:1] == b'-' or label[-1:] == b'-':
            return False
        if any(not (chr(x).isascii() and (chr(x).isalnum() or x in b'-_')) for x in label):
            return False
    return True


BSD_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']


def judge3164(c, got, now):
    why = []
    pri = c['facility'] * 8 + c['severity']
    if got['pri'] != str(pri):
        why.append('pri %s' % got['pri'])
    want_ts = ts_meaning(c['ts'])
    if want_ts is None:
        if abs(int(got['tsu']) - now) > 3600:
            why.append('timestamp %s, want none (receipt time)' % got['ts'])
    else:
        # RFC 3164 carries no year and no zone: the clock fields are what must arrive.
        ms, off = c['ts']
        t = time.gmtime((ms + (off or 0) * 60000) // 1000)
        want = '%02d-%02dT%02d:%02d:%02d' % (t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        if got['ts'][5:19] != want:
            why.append('timestamp %s, want %s' % (got['ts'], want))
    host = bytes.fromhex(c['hostname']) if c['hostname'] is not None else None
    if not hostname_ok(host):
        host = b'localhost'  # omitted: the receiver names the sender (rsyslogd: the peer's resolved name)
    if b(got['host']) != host:
        why.append('hostname %r, want %r' % (got['host'], host))
    tag = bytes(x if chr(x).isascii() and chr(x).isalnum() else 0x2d for x in bytes.fromhex(c['tag'])[:32])
    if b(got['prog']) != tag:
        why.append('programname %r, want %r' % (got['prog'], tag))
    pid = c['pid']
    want_pid = b'-' if pid is None else bytes(x if 33 <= x <= 126 and x not in b'[]' else 0x2d for x in bytes.fromhex(pid))
    if b(got['procid']) != want_pid:
        why.append('procid %r, want %r' % (got['procid'], want_pid))
    msg = bytes.fromhex(c['msg'])
    if b(got['msg']) not in (rs(msg), b' ' + rs(msg)):  # rsyslog keeps the space after "TAG:" in MSG
        why.append('msg %r, want %r' % (got['msg'], msg))
    return why


# ---------------------------------------------------------------- rsyslogd

CONF = '''global(workDirectory="%(dir)s" maxMessageSize="64k" parser.escapeControlCharactersOnReceive="off"
       parser.escape8BitCharactersOnReceive="off" parser.dropTrailingLFOnReception="off")
module(load="imudp")
module(load="imtcp")
module(load="mmpstrucdata")
input(type="imudp" port="%(port)d" address="127.0.0.1")
input(type="imtcp" port="%(port)d" address="127.0.0.1" supportOctetCountedFraming="on")
template(name="j" type="list" option.jsonf="on") {
 property(outname="input" name="inputname" format="jsonf")
 property(outname="raw" name="rawmsg" format="jsonf")
 property(outname="pri" name="pri" format="jsonf")
 property(outname="ver" name="protocol-version" format="jsonf")
 property(outname="ts" name="timereported" dateFormat="rfc3339" format="jsonf")
 property(outname="tsu" name="timereported" dateFormat="unixtimestamp" format="jsonf")
 property(outname="host" name="hostname" format="jsonf")
 property(outname="app" name="app-name" format="jsonf")
 property(outname="prog" name="programname" format="jsonf")
 property(outname="procid" name="procid" format="jsonf")
 property(outname="msgid" name="msgid" format="jsonf")
 property(outname="sd" name="structured-data" format="jsonf")
 property(outname="sdj" name="$!rfc5424-sd" format="jsonf")
 property(outname="msg" name="msg" format="jsonf")
}
action(type="mmpstrucdata" sd_name.lowercase="off")
action(type="omfile" file="%(dir)s/out.json" template="j")
'''


def inner(d):
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    with open(os.path.join(d, 'rsyslog.conf'), 'w') as fh:
        fh.write(CONF % {'dir': d, 'port': PORT})
    with open(os.path.join(d, 'send.json')) as fh:
        send = json.load(fh)
    proc = subprocess.Popen([os.path.join(d, 'rsyslogd'), '-n', '-iNONE', '-f', os.path.join(d, 'rsyslog.conf')])
    try:
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', PORT), timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for dg in send['udp']:
            u.sendto(bytes.fromhex(dg), ('127.0.0.1', PORT))
            time.sleep(0.0005)
        t = socket.create_connection(('127.0.0.1', PORT))
        t.sendall(b''.join(bytes.fromhex(f) for f in send['tcp']))
        t.close()
        want = len(send['udp']) + len(send['tcp'])
        out = os.path.join(d, 'out.json')
        for _ in range(200):
            if os.path.exists(out):
                with open(out, 'rb') as fh:
                    if fh.read().count(b'\n') >= want:
                        break
            time.sleep(0.05)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---------------------------------------------------------------- journald

def jvalue(v):
    """journalctl -o json: text, or an array of byte values for anything not printable UTF-8."""
    return bytes(v) if isinstance(v, list) else v.encode('utf-8')


def jfield(v):
    """A field's values in order: journalctl gives a repeated field as an array of values."""
    if isinstance(v, list) and v and not isinstance(v[0], int):
        return [jvalue(x) for x in v]
    return [jvalue(v)]


def inner_journald(d):
    for m in (['mount', '-t', 'tmpfs', 'tmpfs', '/run'],):
        subprocess.run(m, check=True)
    os.makedirs('/run/systemd/journal', exist_ok=True)
    os.makedirs('/run/log/journal', exist_ok=True)
    subprocess.run(['mount', '--bind', os.path.join(d, 'jlog'), '/run/log/journal'], check=True)
    with open(os.path.join(d, 'send.json')) as fh:
        send = json.load(fh)
    proc = subprocess.Popen(['/usr/lib/systemd/systemd-journald'], stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if os.path.exists('/run/systemd/journal/socket') and os.path.exists('/run/systemd/journal/dev-log'):
                break
            time.sleep(0.05)
        u = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        u.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        for dg in send['native']:
            u.sendto(bytes.fromhex(dg), '/run/systemd/journal/socket')
            time.sleep(0.002)
        for line in send['devlog']:
            u.sendto(bytes.fromhex(line), '/run/systemd/journal/dev-log')
            time.sleep(0.002)
        time.sleep(1)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def run_journald(cases, ours, d):
    """Native datagrams (+ an ORACLE_CASE field appended -- the protocol is a run of fields), field-name probes
    and every syslog line to dev-log (what /dev/log is on a systemd machine); returns the records by case."""
    jlog = os.path.join(d, 'jlog')
    os.makedirs(jlog, exist_ok=True)
    for root_dir, _, files in os.walk(jlog):
        for f in files:
            os.remove(os.path.join(root_dir, f))
    native, devlog, order = [], [], []
    for i, (c, o) in enumerate(zip(cases, ours)):
        if c['kind'] in ('journal', 'jsend'):
            native.append((o[0] + b'ORACLE_CASE=%d\n' % i).hex())
        elif c['kind'] == 'jname':
            native.append((bytes.fromhex(c['name']) + b'=probe\nMESSAGE=jname\nORACLE_CASE=%d\n' % i).hex())
        else:
            devlog.append(o[3].hex())  # what UnixEmitter.send / sendBsd put on the wire
            order.append(i)
    with open(os.path.join(d, 'send.json'), 'w') as fh:
        json.dump({'native': native, 'devlog': devlog}, fh)
    subprocess.run(['unshare', '-rm', sys.executable, os.path.abspath(__file__), 'inner-journald', d], check=True)
    out = subprocess.run(['journalctl', '-D', jlog, '-o', 'json', '--all', '--no-pager'], capture_output=True, check=True).stdout
    by_case, syslog_recs = {}, []
    for line in out.splitlines():
        r = json.loads(line)
        if 'ORACLE_CASE' in r:
            by_case[int(r['ORACLE_CASE'])] = r
        elif r.get('_TRANSPORT') == 'syslog':
            syslog_recs.append(r)
    syslog_recs.sort(key=lambda r: int(r['__SEQNUM']))
    for i, r in zip(order, syslog_recs):
        by_case.setdefault(('devlog', i), r)
    by_case['version'] = subprocess.run(['journalctl', '--version'], capture_output=True, text=True).stdout.split()[1]
    by_case['devlog_count'] = (len(order), len(syslog_recs))
    return by_case


def jd_syslog(x):
    """journald's syslog-transport receive policy: MESSAGE loses trailing whitespace, then ends at the first NUL."""
    return x.rstrip(b' \t\n\r').split(b'\x00')[0]


def judge_devlog(c, o, r):
    """journald on dev-log (= /dev/log on a systemd host) reading what UnixEmitter sent."""
    if r is None:
        return ['journald dev-log: not stored']
    why = []
    want = {'PRIORITY': [b'%d' % c['severity']]}
    if c['facility']:
        want['SYSLOG_FACILITY'] = [b'%d' % c['facility']]
    line = o[3]
    if c['kind'] == '5424':
        # journald reads no RFC 5424: everything after <PRI> is MESSAGE.
        want['MESSAGE'] = [jd_syslog(line[line.index(b'>') + 1:])]
    else:
        if ts_meaning(c['ts']) is not None:
            want['SYSLOG_TIMESTAMP'] = [line[line.index(b'>') + 1:][:16]]
        tag = bytes(x if chr(x).isascii() and chr(x).isalnum() else 0x2d for x in bytes.fromhex(c['tag'])[:32])
        want['SYSLOG_IDENTIFIER'] = [tag]  # an empty TAG is stored as an empty identifier
        pid = bytes.fromhex(c['pid']) if c['pid'] is not None else b''
        if pid.isdigit() and int(pid) > 0:  # journald keeps SYSLOG_PID only when it is a process id
            want['SYSLOG_PID'] = [pid]
        want['MESSAGE'] = [jd_syslog(bytes.fromhex(c['msg']))]
    have = {k: jfield(v) for k, v in r.items() if k in ('PRIORITY', 'SYSLOG_FACILITY', 'SYSLOG_TIMESTAMP', 'SYSLOG_IDENTIFIER',
                                                         'SYSLOG_PID', 'MESSAGE')}
    if have != want:
        why.append('journald dev-log stored %r, want %r' % (have, want))
    return why


def journal_verdict(c, o, jd):
    i = c['_index']
    got = jd.get(i)
    if c['kind'] == 'jname':
        name = bytes.fromhex(c['name'])
        ours_ok = o[0] == b'ok'
        # A trusted name (`_SYSTEMD_UNIT`) is in every record -- journald's own; kept means OUR value is there.
        key = name.decode('utf-8', 'surrogateescape')
        kept = got is not None and key in got and b'probe' in jfield(got[key])
        if got is None:
            return ['journald: record not stored']
        return [] if ours_ok == kept else ['validFieldName says %s, journald %s the field' % (
            o[0].decode(), 'kept' if kept else 'dropped')]
    if got is None:
        return ['journald: record not stored']
    want = {}
    if c['kind'] == 'jsend':
        want['MESSAGE'] = [bytes.fromhex(c['message'])]
        if c['priority'] is not None:
            want['PRIORITY'] = [b'%d' % c['priority']]
        if c['identifier'] is not None:
            want['SYSLOG_IDENTIFIER'] = [bytes.fromhex(c['identifier'])]
    for n, v in c['fields']:
        want.setdefault(bytes.fromhex(n).decode(), []).append(bytes.fromhex(v))
    have = {k: jfield(v) for k, v in got.items() if not k.startswith('_') and k != 'ORACLE_CASE'}
    return [] if have == want else ['journald stored %r, want %r' % (have, want)]


def judge(cases_path, ours_path, out_path):
    with open(cases_path) as fh:
        cases = json.load(fh)
    for i, c in enumerate(cases):
        c['_index'] = i
    with open(ours_path) as fh:
        ours = [[bytes.fromhex(x) for x in o] for o in json.load(fh)]
    d = os.path.abspath(os.path.join(os.path.dirname(ours_path), 'rsyslogd-run'))
    os.makedirs(d, exist_ok=True)
    for f in ('out.json',):
        if os.path.exists(os.path.join(d, f)):
            os.remove(os.path.join(d, f))
    shutil.copy('/usr/sbin/rsyslogd', os.path.join(d, 'rsyslogd'))
    version = subprocess.run(['/usr/sbin/rsyslogd', '-v'], capture_output=True, text=True).stdout.split('\n')[0].split()[1]
    udp, tcp = [], []
    for c, o in zip(cases, ours):
        if c['kind'] not in ('5424', '3164'):
            continue
        udp.append(o[1].hex())
        if c['kind'] == '5424':
            tcp.append(o[2].hex())
    with open(os.path.join(d, 'send.json'), 'w') as fh:
        json.dump({'udp': udp, 'tcp': tcp}, fh)
    now = int(time.time())
    subprocess.run(['unshare', '-rn', sys.executable, os.path.abspath(__file__), 'inner', d], check=True)
    jd = run_journald(cases, ours, os.path.abspath(os.path.join(os.path.dirname(ours_path), 'journald-run')))
    by_raw = {}
    with open(os.path.join(d, 'out.json'), 'rb') as fh:
        for line in fh:
            r = json.loads(line.decode('utf-8', 'surrogateescape'))
            by_raw.setdefault((r['input'], b(r['raw'])), r)
    bad = 0
    verdicts = []
    for i, (c, o) in enumerate(zip(cases, ours)):
        line, dg, frame = o[:3]
        why = []
        cls = set()
        if c['kind'] == '5424':
            sp = frame.index(b' ')
            body = frame[sp + 1:]
            for inp, raw in (('imudp', dg), ('imtcp', body)):
                got = by_raw.get((inp, rs(raw)))
                if got is None:
                    why.append('%s: not received' % inp)
                    continue
                d = divergence5424(c, got)
                if d:
                    cls.add(d)
                    continue
                msg = wire_msg(raw)
                if msg is None:
                    why.append('%s: datagram cut inside STRUCTURED-DATA' % inp)
                    continue
                why +=['%s: %s' % (inp, w) for w in judge5424(c, got, msg, now)]
            why += judge_devlog(c, o, jd.get(('devlog', i)))
        elif c['kind'] == '3164':
            got = by_raw.get(('imudp', rs(dg)))
            why = ['imudp: not received'] if got is None else judge3164(c, got, now)
            why += judge_devlog(c, o, jd.get(('devlog', i)))
        else:
            why = journal_verdict(c, o, jd)
        verdicts.append((why, ','.join(sorted(cls))))
        if why:
            bad += 1
            sys.stderr.write('case %d: %s\n  sent %r\n' % (i, '; '.join(why)[:700], dg[:300]))
    write_vectors(out_path, cases, ours, verdicts, version, jd['version'])
    sys.stderr.write('%d cases; %d where rsyslogd or journald did not read back what the message meant\n' % (len(cases), bad))
    return 1 if bad else 0


def wire_msg(raw):
    """MSG as it sits on the wire: what follows the STRUCTURED-DATA field (a datagram past the limit carries the
    marker, which is what rsyslogd must hand back verbatim)."""
    # Walk the header: PRI+VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID -- six SP-terminated tokens.
    i = 0
    n = len(raw)
    for _ in range(6):
        i = raw.index(b' ', i) + 1
    if raw[i:i + 1] == b'-':
        i += 1
    else:
        while i < n and raw[i:i + 1] == b'[':
            i += 1
            while i < n and raw[i:i + 1] != b']':
                if raw[i:i + 1] == b'"':
                    i += 1
                    while i < n and raw[i:i + 1] != b'"':
                        i += 2 if raw[i:i + 1] == b'\\' else 1
                i += 1
            i += 1
        if i > n:
            return None  # cut inside STRUCTURED-DATA
    return raw[i + 1:] if raw[i:i + 1] == b' ' else b''


def zstr(bs):
    out = []
    for x in bs:
        ch = chr(x)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif 0x20 <= x < 0x7f:
            out.append(ch)
        else:
            out.append('\\x%02x' % x)
    return '"' + ''.join(out) + '"'


FAC = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp',
       'log_audit', 'log_alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
SEV = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']


def zts(ts):
    if ts is None:
        return 'null'
    ms, off = ts
    return '.{ .unix_ms = %d%s }' % (ms, '' if off is None else ', .offset_minutes = %d' % off)


def zopt(v):
    return 'null' if v is None else zstr(bytes.fromhex(v))


def write_vectors(path, cases, ours, verdicts, version, jd_version):
    o = ['// SPDX-License-Identifier: MIT',
         '// GENERATED by modules/syslog/tools/rsyslog_oracle.py (Python %s, rsyslogd %s) -- do not hand-edit.' % (
             platform.python_version(), version),
         '//! Messages and the bytes this module encoded for each, parsed back to what each message meant by a real',
         '//! rsyslogd (RFC 5424 over UDP and octet-counted TCP, RFC 3164 over UDP; mmpstrucdata for structured data)',
         '//! and a real systemd-journald (systemd %s: native protocol, and dev-log = /dev/log for UnixEmitter); replayed by' % jd_version,
         '//! `rsyslog_oracle_test.zig` and `unix.zig`. Regenerate: `zig build interop-syslog`.',
         '',
         'const root = @import("root.zig");',
         '',
         '/// `udp`: what `buildDatagram` made; `frame`: what `writeOctetCounted` made of `bufPrint`\'s line.',
         '/// `ok`: rsyslogd read every field back as meant over both transports.',
         '/// `divergence`: rsyslogd disagreed and the named rule says the bytes are right (`divergences`).',
         'pub const Case5424 = struct { msg: root.Message, udp: []const u8, frame: []const u8, ok: bool, divergence: []const u8 = "" };',
         '/// `line`: what `bsd.bufPrint` made (rsyslogd over UDP); `unix`: what `UnixEmitter.sendBsd` sent (journald',
         '/// on dev-log); `ok`: both read every field back as meant.',
         'pub const Case3164 = struct { msg: root.bsd.Message, line: []const u8, unix: []const u8, ok: bool };',
         '/// `datagram`: what `journal.Emitter.send` put on the wire; `ok`: journald stored exactly these fields.',
         'pub const JournalCase = struct { fields: []const root.journal.Field, datagram: []const u8, ok: bool };',
         '/// The same through `sendMessage`.',
         'pub const JournalSend = struct { opts: root.journal.Emitter.SendMessageOptions, datagram: []const u8, ok: bool };',
         '/// A field name and whether journald kept it when a client sent it.',
         'pub const FieldName = struct { name: []const u8, journald_kept: bool };',
         '',
         'pub const rfc5424 = [_]Case5424{']
    for c, ou, why in zip(cases, ours, verdicts):
        if c['kind'] != '5424':
            continue
        sd = ', '.join('.{ .id = %s, .params = &.{%s} }' % (
            zstr(bytes.fromhex(el['id'])),
            ', '.join('.{ .name = %s, .value = %s }' % (zstr(bytes.fromhex(n)), zstr(bytes.fromhex(v))) for n, v in el['params']))
            for el in c['sd'])
        m = '.facility = .%s, .severity = .%s, .timestamp = %s, .hostname = %s, .app_name = %s, .procid = %s, .msgid = %s, .structured_data = &.{%s}, .msg = %s' % (
            FAC[c['facility']], SEV[c['severity']], zts(c['ts']), zopt(c['hostname']), zopt(c['app_name']),
            zopt(c['procid']), zopt(c['msgid']), sd, zstr(bytes.fromhex(c['msg'])))
        o.append('    .{ .msg = .{ %s }, .udp = %s, .frame = %s, .ok = %s%s },' % (
            m, zstr(ou[1]), zstr(ou[2]), 'false' if why[0] else 'true', ', .divergence = "%s"' % why[1] if why[1] else ''))
    o += ['};', '', 'pub const rfc3164 = [_]Case3164{']
    for c, ou, why in zip(cases, ours, verdicts):
        if c['kind'] != '3164':
            continue
        m = '.facility = .%s, .severity = .%s, .timestamp = %s, .hostname = %s, .tag = %s, .pid = %s, .msg = %s' % (
            FAC[c['facility']], SEV[c['severity']], zts(c['ts']), zopt(c['hostname']),
            zstr(bytes.fromhex(c['tag'])), zopt(c['pid']), zstr(bytes.fromhex(c['msg'])))
        o.append('    .{ .msg = .{ %s }, .line = %s, .unix = %s, .ok = %s },' % (m, zstr(ou[1]), zstr(ou[3]), 'false' if why[0] else 'true'))
    zf = lambda fs: '&.{%s}' % ', '.join('.{ .name = %s, .value = %s }' % (zstr(bytes.fromhex(n)), zstr(bytes.fromhex(v))) for n, v in fs)
    o += ['};', '', 'pub const journal = [_]JournalCase{']
    for c, ou, why in zip(cases, ours, verdicts):
        if c['kind'] == 'journal':
            o.append('    .{ .fields = %s, .datagram = %s, .ok = %s },' % (zf(c['fields']), zstr(ou[0]), 'false' if why[0] else 'true'))
    o += ['};', '', 'pub const journal_send = [_]JournalSend{']
    for c, ou, why in zip(cases, ours, verdicts):
        if c['kind'] == 'jsend':
            opts = '.message = %s' % zstr(bytes.fromhex(c['message']))
            if c['priority'] is not None:
                opts += ', .priority = .%s' % SEV[c['priority']]
            if c['identifier'] is not None:
                opts += ', .identifier = %s' % zstr(bytes.fromhex(c['identifier']))
            opts += ', .fields = %s' % zf(c['fields'])
            o.append('    .{ .opts = .{ %s }, .datagram = %s, .ok = %s },' % (opts, zstr(ou[0]), 'false' if why[0] else 'true'))
    o += ['};', '', 'pub const field_names = [_]FieldName{']
    for c, ou, why in zip(cases, ours, verdicts):
        if c['kind'] == 'jname':
            ours_ok = ou[0] == b'ok'
            kept = ours_ok if not why[0] else not ours_ok
            o.append('    .{ .name = %s, .journald_kept = %s },' % (zstr(bytes.fromhex(c['name'])), 'true' if kept else 'false'))
    o += ['};', '', '/// Every divergence class a case may carry, and why the bytes are right anyway.',
          'pub const divergences = [_]struct { name: []const u8, why: []const u8 }{']
    for k, v in DIVERGENCES.items():
        o.append('    .{ .name = "%s", .why = %s },' % (k, zstr(v.encode())))
    o.append('};')
    with open(path, 'w') as fh:
        fh.write('\n'.join(o) + '\n')


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'gen':
        gen()
    elif len(sys.argv) == 5 and sys.argv[1] == 'judge':
        sys.exit(judge(*sys.argv[2:]))
    elif len(sys.argv) == 3 and sys.argv[1] == 'inner':
        inner(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == 'inner-journald':
        inner_journald(sys.argv[2])
    else:
        sys.stderr.write(__doc__)
        sys.exit(2)
