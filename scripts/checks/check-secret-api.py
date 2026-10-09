#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""check-secret-api — the static half of the dead-stack rule.

WHY THIS EXISTS
---------------
Ten dead-stack waves (2026-10-08..09, ~/CML maturity log § AD..AP) found the
same three shapes in every secret-holding module, each time with a
hand-written stack probe and three ReleaseFast builds per module:

  1. a secret passed BY VALUE (`sk: SecretKey`, `seed: [32]u8`): the caller's
     frame keeps a copy the callee can never wipe;
  2. a secret RETURNED by value (`!KeyPair`, `SharedSecret`): the result slot
     and the error-union temporary in the caller hold it;
  3. a public entry point that touches a secret with no dead-stack burn: the
     body's frames (and std's frames under it) keep every intermediate.

All three are visible in the SOURCE of a public signature, so this gate finds
them in seconds over the whole collection, with no build. The stack probes
stay the dynamic half: they prove a burn is deep enough, which no source scan
can. This gate proves the burn and the pointer shapes are THERE.

The convention it enforces (owner decision 2026-10-08, CONVENTIONS.md §2.1.1):
secret inputs by `*const T`, secret results through an `out: *T` parameter,
every public entry point that touches a secret runs its body under a burn
(`burn.run`/`burn.stack`, or a module's own `burn*` helper).

WHAT COUNTS AS A SECRET
-----------------------
A parameter or result whose TYPE name says so (`SecretKey`, `PrivateKey`,
`KeyPair`, `SigningKey`, `*Secret*`, `Seed`), or a byte array (`[N]u8`) whose
PARAMETER name says so (`seed`, `sk`, `*secret*`, `password`, `psk`, `ikm`,
`prk`, `priv*`, `ephemeral*`, `nonce_k`, ...), or a byte array returned by a
function whose NAME says so (`deriveSecret`, `sessionKey`, ...; never one with
`public` in it). This is a name heuristic and it is meant to be one: the names
are the module's own statement of what the value is. A secret with an
innocent name is invisible here -- the stack probe is what covers that.

WHAT COUNTS AS PUBLIC
---------------------
`pub` in Zig is per FILE; the module's API is what `src/root.zig` exports.
A file imported whole (`pub const x = @import("x.zig")`) from root or from
another public file is public in full; a name re-exported from a file
(`pub const Name = x.Name`) makes that declaration -- a function, or a type
and every `pub fn` inside it -- public. Everything else is internal and runs
under some public entry point's burn.

ACCEPTED SHAPES
---------------
  * A std-shaped by-value surface kept for compatibility is fine when a safe
    twin exists in the module: `fromSecretKey` beside `fromSecretKeyInto`
    (suffix `Into`). The twin is what direct callers are pointed to.
  * Wipes (`deinit`, `wipe`, `zeroize`, `clear`, `destroy`) and trivial
    bodies (no call other than builtins) need no burn.
  * Anything else is exempted only by a marker in the doc/comment lines
    directly above the `pub fn`:
        // secret-api-ok: <reason>
    with a non-empty reason (same rule as `global-alloc-ok:`).

MODES
-----
  check-secret-api.py                    report every finding, exit 1 if any
  check-secret-api.py --ratchet          fail only on findings not in the
                                         baseline, and on baseline rows that
                                         no longer fire (delete them)
  check-secret-api.py --update-baseline  rewrite secret-api-baseline.txt
  check-secret-api.py --prune [--modules=a,b]
                                         delete baseline rows that no longer
                                         fire (never adds one)
  --modules=a,b                          scan only these modules
  --summary                              one line per module
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASELINE = os.path.join(REPO, "scripts", "checks", "secret-api-baseline.txt")

# Files that are never the published module.
SKIP_FILE = re.compile(r"(_test|_vectors|^bench|^ctgrind_harness|^test_shim|^fuzz\w*|^testkit\w*)\.zig$")

SECRET_TYPE = re.compile(
    r"^(SecretKey|PrivateKey|KeyPair|Keypair|SigningKey|Seed|SharedSecret"
    r"|\w*Secret|\w*Secrets|Secret\w*|\w+SecretKey|\w+PrivateKey|\w+KeyPair|\w+SigningKey)$"
)
SECRET_NAME = re.compile(
    r"^(seed|\w+_seed|seed_\w+|sk|\w+_sk|sk_\w+|\w*secret\w*|priv|priv_\w+|\w+_priv|privkey|private_key"
    r"|\w+_private_key|password|passphrase|psk|ikm|prk|nonce_k|msk|master_key|ephemeral\w*"
    r"|key_pair|keypair|kp|shared_key|session_key|traffic_key|static_key|identity_key)$"
)
# In a module of the `crypto` lib (build.zig's module table) a bare `key` is a
# symmetric secret; elsewhere it is far more often a map key.
CRYPTO_NAME = re.compile(r"^(key|\w+_key|key_\w+|k|mac_key|enc_key|kek|cek|dek)$")
NOT_SECRET_NAME = re.compile(r"(?i)(public|pub_|_pub|pk$|^pk_|peer|remote|their|verif|id$|_len$|length)")
# Byte-array RESULTS: the function name is the only statement of what they are.
SECRET_RET_FN = re.compile(r"(?i)(secret|seed|private|priv[A-Z_]|sharedkey|sessionkey|traffickey|derive\w*key)")
PUBLIC_FN = re.compile(r"(?i)public")
# Type names the SECRET_TYPE pattern catches but that hold no secret.
NOT_SECRET_TYPE = re.compile(r"^(Encrypted\w*|Public\w*|\w*Public\w*|\w*(Len|Length|Size|Error|Tag|Kind|Id|Label|Options)|SecretSharing)$")
# Read-only accessors of a secret-holding object: they return public facts
# (its public key, a length, a counter) and touch no secret.
ACCESSOR = re.compile(r"^(public\w*|\w*[Ll]en|\w*[Ll]ength|position|remaining|levelList|count|size|id|keyId|algorithm\w*)$")

WIPE_FNS = {"deinit", "wipe", "zeroize", "clear", "destroy", "secureZero"}
MARKER = re.compile(r"secret-api-ok:\s*(\S.*)?$")


def strip_comments(src):
    """Blank `//` comments (keeping offsets and line numbers intact)."""
    out = []
    for line in src.split("\n"):
        in_str = esc = False
        cut = len(line)
        for i, c in enumerate(line):
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = not in_str
            elif c == "/" and not in_str and line[i : i + 2] == "//":
                cut = i
                break
        out.append(line[:cut] + " " * (len(line) - cut))
    return "\n".join(out)


def match_close(s, i):
    """s[i] is `(`, `[` or `{`; index just after its partner."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    in_str = False
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"' or c == "\n":
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "'" and i + 2 < n:
            # char literal: skip it whole (`'{'`, `'\''`)
            j = s.find("'", i + 2 if s[i + 1] == "\\" else i + 1)
            if j != -1 and j - i <= 12:
                i = j
        elif c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if stack:
                stack.pop()
            if not stack:
                return i + 1
        i += 1
    return n


def split_top(s):
    parts, d, cur = [], 0, []
    for c in s:
        if c in "([{":
            d += 1
        elif c in ")]}":
            d -= 1
        if c == "," and d == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


PUBFN = re.compile(r"\bpub\s+(?:inline\s+|noinline\s+|export\s+)?fn\s+(\w+)\s*\(")
ANYFN = re.compile(r"(?<![\w.])((?:pub\s+)?(?:inline\s+|noinline\s+|export\s+)?)fn\s+(\w+)\s*\(")
CONTAINER = re.compile(
    r"\bconst\s+(\w+)\s*(?::\s*type\s*)?=\s*(?:extern\s+|packed\s+)?(?:struct|union|opaque)\b[^{;]*\{"
)
TYPE_FN = re.compile(r"\bfn\s+(\w+)\s*\(")
IMPORT_WHOLE = re.compile(r"\bpub\s+const\s+(\w+)\s*=\s*@import\(\s*\"([^\"]+\.zig)\"\s*\)")
IMPORT_ANY = re.compile(r"\bconst\s+(\w+)\s*=\s*@import\(\s*\"([^\"]+\.zig)\"\s*\)")
REEXPORT = re.compile(r"\bpub\s+const\s+(\w+)\s*=\s*(\w+)\.([\w.]+)\s*;")


class FileInfo:
    def __init__(self, path, raw):
        self.path = path
        self.raw_lines = raw.split("\n")
        self.src = strip_comments(raw)
        self.containers = []  # (start, end, name)
        for m in CONTAINER.finditer(self.src):
            ob = m.end() - 1
            self.containers.append((ob, match_close(self.src, ob), m.group(1)))
        # `fn Name(...) type { return struct {...} }` -- a generic type.
        for m in TYPE_FN.finditer(self.src):
            pe = match_close(self.src, m.end() - 1)
            rest = self.src[pe : pe + 40]
            mm = re.match(r"\s*type\s*\{", rest)
            if mm:
                ob = pe + mm.end() - 1
                self.containers.append((ob, match_close(self.src, ob), m.group(1)))
        self.containers.sort()

    def fields(self, start, end):
        """(name, type) of the fields directly inside the container body."""
        src = self.src
        parts, cur, depth = [], [], 0
        i = start + 1
        while i < end - 1:
            c = src[i]
            if c == "{" and depth == 0:
                i = match_close(src, i)  # a fn body or a nested container
                cur.append(" ")
                continue
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            if depth == 0 and c in ",;":
                parts.append("".join(cur))
                cur = []
            else:
                cur.append(c)
            i += 1
        parts.append("".join(cur))
        out = []
        for part in parts:
            m = re.match(r"^\s*(\w+)\s*:\s*(.+?)\s*(=.*)?$", " ".join(part.split()))
            if m and m.group(1) not in ("const", "var", "fn", "pub", "test", "comptime"):
                out.append((m.group(1), m.group(2)))
        return out

    def enclosing(self, pos):
        """Innermost-first list of container names around `pos`."""
        names = [(s, n) for s, e, n in self.containers if s < pos < e]
        names.sort(reverse=True)
        return [n for _, n in names]

    def line_of(self, pos):
        return self.src.count("\n", 0, pos) + 1

    def marker_above(self, line):
        """`secret-api-ok:` in the comment block directly above line `line`."""
        i = line - 2
        while i >= 0:
            t = self.raw_lines[i].strip()
            if not t.startswith("//"):
                return None
            m = MARKER.search(t)
            if m:
                return m.group(1) or ""
            i -= 1
        return None


def all_fns(fi):
    """(name, params, ret, body, pos, is_pub) for every fn with a body."""
    src = fi.src
    for m in ANYFN.finditer(src):
        is_pub = m.group(1).strip().startswith("pub")
        name = m.group(2)
        po = m.end() - 1
        pe = match_close(src, po)
        params = split_top(src[po + 1 : pe - 1])
        j = pe
        n = len(src)
        while j < n:
            c = src[j]
            if c == "{":
                head = src[pe:j]
                if re.search(r"(error|struct|union|enum)\s*(\([^)]*\))?\s*$", head):
                    j = match_close(src, j)
                    continue
                break
            if c == ";":
                break
            j += 1
        ret = " ".join(src[pe:j].split())
        body = ""
        if j < n and src[j] == "{":
            body = src[j : match_close(src, j)]
        yield name, params, ret, body, m.start(), is_pub


def norm_type(t):
    t = " ".join(t.split())
    return re.sub(r"^(comptime|noalias)\s+", "", t)


def is_pointer(t):
    return bool(re.match(r"^\?*\s*(\*|\[\]|\[\*|\[:)", t))


def pointee(t):
    return re.sub(r"^\?*\s*\*\s*(align\([^)]*\)\s*)?(const\s+)?(volatile\s+)?", "", t)


def type_name(t):
    t = t.lstrip("?").strip()
    m = re.match(r"^(?:[\w.]*\.)?(\w+)$", t)
    return m.group(1) if m else None


def is_byte_array(t):
    return bool(re.match(r"^\?*\s*\[[^\]]+\]\s*u8$", t))


def resolve_self(tn, fi, pos):
    if tn in ("Self", "@This()") or tn is None:
        enc = fi.enclosing(pos)
        return enc[0] if enc else tn
    return tn


def is_byte_slice(t):
    return bool(re.match(r"^\?*\s*\[\](const\s+)?u8$", t))


def secret_name(pname, crypto):
    if NOT_SECRET_NAME.search(pname):
        return False
    return bool(SECRET_NAME.match(pname) or (crypto and CRYPTO_NAME.match(pname)))


SECRET_FIELDS = {}  # derived type -> the fields that make it secret
DERIVED = set()  # secret held inline
DERIVED_REF = set()  # secret referenced (slice/pointer/list)


def derive_secret_types(files):
    """Containers holding a secret field are secret types themselves (fixpoint).

    Fields count by their TYPE or by an explicit secret NAME (`secret*`,
    `seed`, `sk`, `priv*`, ...) -- never by the crypto-lib `key` names, which
    in a struct are as often public keys (`init_key`, `encryption_key`).
    Returns (inline, referencing): `inline` types hold a secret in their own
    bytes, so a by-value copy copies it; `referencing` ones (a slice, a
    pointer, an ArrayList of secret bytes) do not, but their methods still
    touch the secret and need a burn."""
    conts = []
    for fi in files.values():
        for st, en, name in fi.containers:
            conts.append((name, fi.fields(st, en)))
    inline, ref = set(), set()
    SECRET_FIELDS.clear()
    grew = True
    while grew:
        grew = False
        for name, flds in conts:
            if NOT_SECRET_TYPE.match(name):
                continue
            for fname, ftype in flds:
                indirect = bool(re.search(r"[*]|\[\]|ArrayList|HashMap|\[\*", ftype))
                tns = set(re.findall(r"\b([A-Z]\w*)\b", ftype))
                by_type_inline = any((SECRET_TYPE.match(t) and not NOT_SECRET_TYPE.match(t)) or t in inline for t in tns)
                by_type_ref = any(t in ref for t in tns)
                by_name = bool(SECRET_NAME.match(fname)) and not NOT_SECRET_NAME.search(fname) and "u8" in ftype
                if by_type_inline or by_type_ref or by_name:
                    SECRET_FIELDS.setdefault(name, set()).add(fname)
                if (by_type_inline or by_name) and not indirect and name not in inline:
                    inline.add(name)
                    ref.add(name)
                    grew = True
                elif (by_type_inline or by_type_ref or by_name) and name not in ref:
                    ref.add(name)
                    grew = True
    return inline, ref


def secret_param(pname, ptype, fi, pos, crypto=False):
    """None, or a short reason the parameter holds a secret."""
    if is_byte_slice(ptype):
        return pname if secret_name(pname, crypto) else None
    t = pointee(ptype) if is_pointer(ptype) else ptype
    if t.strip() in ("@This()",):
        tn = resolve_self(None, fi, pos)
    else:
        tn = resolve_self(type_name(t), fi, pos) if type_name(t) in ("Self",) else type_name(t)
    if tn and ((SECRET_TYPE.match(tn) and not NOT_SECRET_TYPE.match(tn)) or tn in DERIVED):
        return tn
    if tn and tn in DERIVED_REF:
        return "&" + tn  # touches a secret; a by-value copy copies only pointers
    if secret_name(pname, crypto) and is_byte_array(t):
        return pname
    return None


def secret_ret(fname, ret, fi, pos):
    r = ret
    if "!" in r:
        r = r.rsplit("!", 1)[1]
    r = r.strip().lstrip("?").strip()
    if r == "Self":
        r = resolve_self("Self", fi, pos) or r
    tn = type_name(r)
    if tn and ((SECRET_TYPE.match(tn) and not NOT_SECRET_TYPE.match(tn)) or tn in DERIVED):
        return tn
    if is_byte_array(r) and SECRET_RET_FN.search(fname) and not PUBLIC_FN.search(fname):
        return r
    return None


TRIVIAL_CALL = re.compile(r"(?<![@\w.])([A-Za-z_][\w.]*)\s*\(")


def is_trivial(body):
    """No call except builtins (`@memcpy`, `@as`) and wipes."""
    for m in TRIVIAL_CALL.finditer(body):
        callee = m.group(1)
        last = callee.rsplit(".", 1)[-1]
        if last in ("if", "while", "for", "switch", "return", "catch", "orelse", "struct", "union", "enum"):
            continue
        if last in WIPE_FNS or last in ("asBytes", "sliceAsBytes", "asSlice"):
            continue
        return False
    return True


BURN = re.compile(r"(?i)burn")
CALL = re.compile(r"(?<![\w@])(\w+)\s*\(")


def module_files(module):
    src_dir = os.path.join(REPO, "modules", module, "src")
    files = {}
    if not os.path.isdir(src_dir):
        return src_dir, files
    for root, _, names in os.walk(src_dir):
        for n in sorted(names):
            if n.endswith(".zig") and not SKIP_FILE.search(n):
                p = os.path.join(root, n)
                with open(p, encoding="utf-8") as fh:
                    files[os.path.normpath(p)] = FileInfo(p, fh.read())
    return src_dir, files


def public_surface(src_dir, files):
    """(files public in full, {file: set of exported names})."""
    root = os.path.normpath(os.path.join(src_dir, "root.zig"))
    if root not in files:
        return set(files), {}
    whole = {root}
    partial = {}
    todo = [root]
    while todo:
        f = todo.pop()
        fi = files[f]
        aliases = {}
        for m in IMPORT_ANY.finditer(fi.src):
            aliases[m.group(1)] = os.path.normpath(os.path.join(os.path.dirname(f), m.group(2)))
        for m in IMPORT_WHOLE.finditer(fi.src):
            t = aliases.get(m.group(1))
            if t in files and t not in whole:
                whole.add(t)
                todo.append(t)
        for m in REEXPORT.finditer(fi.src):
            t = aliases.get(m.group(2))
            if t in files and t not in whole:
                partial.setdefault(t, set()).add(m.group(3).split(".")[0])
                partial[t].add(m.group(3).split(".")[-1])
    return whole, partial


def crypto_modules():
    """Modules whose build.zig row lists the `crypto` lib."""
    out = set()
    with open(os.path.join(REPO, "build.zig"), encoding="utf-8") as fh:
        for m in re.finditer(r'\.name\s*=\s*"([^"]+)"\s*,\s*\.libs\s*=\s*&\.\{([^}]*)\}', fh.read()):
            if '"crypto"' in m.group(2):
                out.add(m.group(1))
    return out


CRYPTO = None


def scan_module(module):
    global CRYPTO
    if CRYPTO is None:
        CRYPTO = crypto_modules()
    crypto = module in CRYPTO
    src_dir, files = module_files(module)
    DERIVED.clear()
    DERIVED_REF.clear()
    inl, ref = derive_secret_types(files)
    DERIVED.update(inl)
    DERIVED_REF.update(ref - inl)
    whole, partial = public_surface(src_dir, files)
    fn_names = set()
    entries = []
    bodies = {}
    for f, fi in files.items():
        for name, params, ret, body, pos, is_pub in all_fns(fi):
            bodies.setdefault(name, []).append(body)
            if not is_pub:
                continue
            fn_names.add(name)
            if f in whole:
                public = True
            elif f in partial:
                names = partial[f]
                public = name in names or any(c in names for c in fi.enclosing(pos))
            else:
                public = False
            entries.append((f, fi, name, params, ret, body, pos, public))
    # A function is burned when its body burns or calls a burned function
    # (by name, to a fixpoint). By name, so two `sign`s in two containers
    # share a verdict -- the stack probe is what checks the depth.
    burned = {n for n, bs in bodies.items() if any(BURN.search(b) for b in bs)}
    calls = {n: {c for b in bs for c in CALL.findall(b)} - {n} for n, bs in bodies.items()}
    grew = True
    while grew:
        grew = False
        for n, cs in calls.items():
            if n not in burned and not cs.isdisjoint(burned):
                burned.add(n)
                grew = True
    findings = []
    for f, fi, name, params, ret, body, pos, public in entries:
        if not public:
            continue
        byval, touches = [], []
        for prm in params:
            if ":" not in prm:
                continue
            pn, pt = prm.split(":", 1)
            pn = re.sub(r"\b(comptime|noalias)\b", "", pn).strip()
            pt = norm_type(pt)
            if pt in ("type", "anytype") or pn == "_":
                continue
            why = secret_param(pn, pt, fi, pos, crypto)
            dt = why.lstrip("&") if why else None
            if dt in SECRET_FIELDS and body:
                flds = SECRET_FIELDS[dt]
                uses_field = any(re.search(r"\." + re.escape(f) + r"\b", body) for f in flds)
                passes_on = re.search(r"[(,]\s*&?" + re.escape(pn) + r"\s*[,)]", body)
                if not uses_field and not passes_on:
                    why = None
            if why:
                touches.append(pn)
                if not is_pointer(pt) and not why.startswith("&"):
                    byval.append(f"{pn}:{why}")
        rs = secret_ret(name, ret, fi, pos)
        if not touches and not rs:
            continue
        line = fi.line_of(pos)
        marker = fi.marker_above(line)
        if marker is not None:
            if not marker.strip():
                findings.append((module, os.path.relpath(f, REPO), line, name, "marker-without-reason", ""))
            continue
        twin = (name + "Into") in fn_names
        rel = os.path.relpath(f, REPO)
        enc = fi.enclosing(pos)
        # The key names the container too: two `sign`s in one file (webhooksig's
        # `standard.sign` and `stripe.sign`) are two rows, not one.
        qual = ".".join(list(reversed(enc)) + [name])
        if byval and not twin:
            findings.append((module, rel, line, qual, "byval", ",".join(byval)))
        if rs and not twin:
            findings.append((module, rel, line, qual, "ret", rs))
        if name in WIPE_FNS or not body:
            continue
        if BURN.search(body) or is_trivial(body):
            continue
        if touches == ["self"] and not rs and ACCESSOR.match(name):
            continue
        if not (set(CALL.findall(body)) - {name}).isdisjoint(burned):
            continue
        findings.append((module, rel, line, qual, "noburn", ",".join(touches) or rs))
    return findings


def key(fd):
    module, rel, _line, name, kind, _why = fd
    return f"{module}\t{rel}:{name}\t{kind}"


def read_baseline():
    rows = set()
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line and not line.startswith("#"):
                    rows.add(line)
    return rows


HEADER = """\
# Known findings of scripts/checks/check-secret-api.py, burned down by the
# dead-stack campaign (~/CML maturity log, 2026-10). `--ratchet` fails on a
# finding NOT listed here and on a row here that no longer fires -- delete it.
# Never add a row by hand to get a new module past the gate: fix the shape,
# or put `secret-api-ok: <reason>` above the function.
#
# module<TAB>file:function<TAB>kind (byval | ret | noburn)
"""


def main():
    args = sys.argv[1:]
    only = None
    for a in args:
        if a.startswith("--modules="):
            only = [m for m in a.split("=", 1)[1].split(",") if m]
    modules = only or sorted(os.listdir(os.path.join(REPO, "modules")))
    findings = []
    for m in modules:
        if not os.path.isdir(os.path.join(REPO, "modules", m)):
            print(f"check-secret-api: no such module: {m}", file=sys.stderr)
            return 2
        findings.extend(scan_module(m))

    if "--update-baseline" in args:
        if only is not None:
            print("check-secret-api: --update-baseline rewrites the whole file; it takes no --modules", file=sys.stderr)
            return 2
        with open(BASELINE, "w", encoding="utf-8") as fh:
            fh.write(HEADER)
            for k in sorted({key(f) for f in findings}):
                fh.write(k + "\n")
        print(f"check-secret-api: {len(findings)} finding(s) written to the baseline")
        return 0

    if "--prune" in args:
        base = read_baseline()
        got = {key(f) for f in findings}
        scanned = set(modules)
        keep = {b for b in base if b.split("\t", 1)[0] not in scanned or b in got}
        new = sorted(got - base)
        with open(BASELINE, "w", encoding="utf-8") as fh:
            fh.write(HEADER)
            for k in sorted(keep):
                fh.write(k + "\n")
        print(f"check-secret-api: pruned {len(base) - len(keep)} fixed row(s), {len(keep)} left")
        for k in new:
            print(f"NEW  {k}  -- not added: fix it or mark it", file=sys.stderr)
        return 1 if new else 0

    if "--summary" in args:
        per = {}
        for f in findings:
            per.setdefault(f[0], {}).setdefault(f[4], 0)
            per[f[0]][f[4]] += 1
        for m in sorted(per, key=lambda m: -sum(per[m].values())):
            print(f"{m:22s} {sum(per[m].values()):4d}  " + " ".join(f"{k}={v}" for k, v in sorted(per[m].items())))
        print(f"total {len(findings)} in {len(per)} modules")
        return 1 if findings else 0

    if "--ratchet" in args:
        base = read_baseline()
        if only is not None:
            base = {b for b in base if b.split("\t", 1)[0] in only}
        got = {key(f): f for f in findings}
        new = [got[k] for k in sorted(got) if k not in base]
        gone = sorted(base - set(got))
        for module, rel, line, name, kind, why in new:
            print(f"NEW  {rel}:{line} {name}: {kind} ({why})", file=sys.stderr)
        for k in gone:
            print(f"GONE {k}  -- fixed? delete the row from secret-api-baseline.txt", file=sys.stderr)
        if new or gone:
            return 1
        print(f"check-secret-api: {len(got)} known finding(s), none new")
        return 0

    for module, rel, line, name, kind, why in findings:
        print(f"{rel}:{line} {name}: {kind} ({why})")
    print(f"check-secret-api: {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
