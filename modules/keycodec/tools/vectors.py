#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/vectors.zig`: keys in every PEM form the `openssl` command
line writes, with their parts as OpenSSL itself prints them, for the
`keycodec` tests. Fresh keys every run; the committed file is one such run.
Published TEST keys: never use them for anything else.

    python3 -I tools/vectors.py > src/vectors.zig
    python3 -I tools/vectors.py --encrypted > src/vectors_enc.zig

Needs `openssl` (3.5 or later: ML-DSA and ML-KEM) and `zig` (for
`zig fmt --stdin`) on PATH; works in a temporary directory.

What each case pins, and where the expected value comes from (never from
`keycodec`):
  * `pem`      -- the private key as `openssl` wrote it. The writer tests
                  re-encode the parsed key and compare byte for byte.
  * `secret`   -- EC: the scalar from `openssl pkey -text` ("priv:"), left-
                  padded to the order's length; Ed/X: "priv:"; ML-DSA/ML-KEM:
                  "seed:" (or "priv:"/"dk:" for the expanded-only form);
                  RSA: the PKCS#8 OCTET STRING's content as
                  `openssl asn1parse -strparse` extracts it (PKCS#1 cases:
                  the whole DER).
  * `expanded` -- ML-DSA "priv:" / ML-KEM "dk:" for the `both` form.
  * `public`   -- EC/Ed/X/ML "pub:"/"ek:"; RSA: `-RSAPublicKey_out` DER.
  * `spki_pem` -- `openssl pkey -pubout`.

`--encrypted` writes `src/vectors_enc.zig` instead: one key in several
`ENCRYPTED PRIVATE KEY` forms (`openssl pkcs8 -topk8` with every KDF, PRF and
cipher it can write that keycodec reads), each with the password, the
parameters the command line asked for (the oracle for the parser) and the
unencrypted `PRIVATE KEY` PEM of the same key (`openssl pkcs8 -nocrypt`). The
writer tests re-encrypt each key with the salt and IV found in the file and
must reproduce it byte for byte: that is also the proof that OpenSSL reads
what keycodec writes (same bytes in, same bytes out).
"""

import io
import os
import re
import subprocess
import sys
import tempfile


def run(*args, cwd, stdout=subprocess.DEVNULL):
    return subprocess.run(args, cwd=cwd, check=True, stdout=stdout, stderr=subprocess.DEVNULL)


def out(*args, cwd):
    return run(*args, cwd=cwd, stdout=subprocess.PIPE).stdout


def read(cwd, name):
    with open(os.path.join(cwd, name)) as f:
        return f.read()


def text_fields(cwd, key):
    """The hex blocks of `openssl pkey -text -noout`, by their label."""
    txt = out("openssl", "pkey", "-in", key, "-text", "-noout", cwd=cwd).decode()
    fields, cur = {}, None
    for line in txt.splitlines():
        m = re.match(r"^([A-Za-z]+):\s*$", line)
        if m:
            cur = m.group(1)
            fields[cur] = ""
        elif cur and re.match(r"^\s+[0-9a-f:]+$", line):
            fields[cur] += line.strip().replace(":", "")
        else:
            cur = None
    return fields


def octet_string_content(cwd, key):
    """The top-level OCTET STRING's content of a PKCS#8 key, via asn1parse."""
    lines = out("openssl", "asn1parse", "-in", key, cwd=cwd).decode().splitlines()
    off = next(int(l.split(":")[0]) for l in lines if "d=1 " in l and "OCTET STRING" in l)
    run("openssl", "asn1parse", "-in", key, "-strparse", str(off), "-noout", "-out", "inner.der", cwd=cwd)
    with open(os.path.join(cwd, "inner.der"), "rb") as f:
        return f.read().hex()


def der_hex(cwd, *args):
    return out(*args, "-outform", "DER", cwd=cwd).hex()


def zig_str(s):
    """A Zig multiline literal of `s`; such a literal has no final newline,
    so one PEM file's trailing LF is appended explicitly."""
    lines = s.splitlines(keepends=True)
    body = "\n".join("        \\\\" + l.rstrip("\n") for l in lines) + "\n"
    return body + ("        ++ \"\\n\"\n" if s.endswith("\n") else "")


SCALAR_LEN = {"ec_p256": 32, "ec_p384": 48, "ec_p521": 66, "ec_secp256k1": 32}


def main():
    cases = []  # (name, algorithm, encoding, pq_form, key file)
    with tempfile.TemporaryDirectory() as d:
        version = out("openssl", "version", cwd=d).decode().strip().split(" (")[0]

        for alg, curve in (("ec_p256", "P-256"), ("ec_p384", "P-384"), ("ec_p521", "P-521"), ("ec_secp256k1", "secp256k1")):
            run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + curve, "-out", alg + ".p8", cwd=d)
            run("openssl", "ec", "-in", alg + ".p8", "-out", alg + ".sec1", cwd=d)
            cases += [(alg + "-pkcs8", alg, "pkcs8", None, alg + ".p8"), (alg + "-sec1", alg, "sec1", None, alg + ".sec1")]
        for alg, name in (("ed25519", "ED25519"), ("ed448", "ED448"), ("x25519", "X25519"), ("x448", "X448")):
            run("openssl", "genpkey", "-algorithm", name, "-out", alg + ".p8", cwd=d)
            cases += [(alg + "-pkcs8", alg, "pkcs8", None, alg + ".p8")]
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "rsa.p8", cwd=d)
        run("openssl", "rsa", "-traditional", "-in", "rsa.p8", "-out", "rsa.p1", cwd=d)
        cases += [("rsa-pkcs8", "rsa", "pkcs8", None, "rsa.p8"), ("rsa-pkcs1", "rsa", "pkcs1", None, "rsa.p1")]
        run("openssl", "genpkey", "-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "pss.p8", cwd=d)
        cases += [("rsa_pss-pkcs8", "rsa_pss", "pkcs8", None, "pss.p8")]
        for fam, prov, sizes in (("ml_dsa", "ml-dsa", (44, 65, 87)), ("ml_kem", "ml-kem", (512, 768, 1024))):
            for n in sizes:
                alg = "%s_%d" % (fam, n)
                run("openssl", "genpkey", "-algorithm", "%s-%d" % (prov.upper(), n), "-out", alg + ".both", cwd=d)
                for form in ("seed-only", "priv-only"):
                    run("openssl", "pkey", "-in", alg + ".both", "-provparam", "%s.output_formats=%s" % (prov, form),
                        "-out", "%s.%s" % (alg, form), cwd=d)
                cases += [(alg + "-both", alg, "pkcs8", "both", alg + ".both"),
                          (alg + "-seed", alg, "pkcs8", "seed", alg + ".seed-only"),
                          (alg + "-expanded", alg, "pkcs8", "expanded", alg + ".priv-only")]
        # Refused: an encrypted PKCS#8 key and a legacy encrypted SEC1 key.
        run("openssl", "pkcs8", "-topk8", "-in", "ec_p256.sec1", "-out", "enc.p8", "-passout", "pass:test", cwd=d)
        run("openssl", "ec", "-in", "ec_p256.sec1", "-aes128", "-passout", "pass:test", "-out", "enc.sec1", cwd=d)

        buf = io.StringIO()
        w = buf.write
        w("// SPDX-License-Identifier: MIT\n\n")
        w("//! TEST keys in every PEM form `openssl` writes, with their parts as\n")
        w("//! OpenSSL prints them, generated by `tools/vectors.py` with %s.\n" % version)
        w("//! Published test fixtures: never use these keys for anything else.\n")
        w("//! Do not edit by hand.\n\n")
        w("pub const Case = struct {\n    name: []const u8,\n    algorithm: []const u8,\n    encoding: []const u8,\n")
        w("    pq_form: ?[]const u8,\n    pem: []const u8,\n    secret: []const u8,\n    expanded: []const u8,\n")
        w("    public: []const u8,\n    spki_pem: []const u8,\n};\n\n")
        w("pub const cases = [_]Case{\n")
        for name, alg, enc, pq, key in cases:
            f = text_fields(d, key)
            expanded = ""
            if alg.startswith("rsa"):
                if enc == "pkcs8":
                    secret = octet_string_content(d, key)
                else:
                    secret = der_hex(d, "openssl", "rsa", "-in", key, "-traditional")
                public = der_hex(d, "openssl", "rsa", "-in", key, "-RSAPublicKey_out")
            elif alg.startswith("ml_"):
                exp_label = "priv" if alg.startswith("ml_dsa") else "dk"
                pub_label = "pub" if alg.startswith("ml_dsa") else "ek"
                if pq == "expanded":
                    secret = f[exp_label]
                else:
                    secret = f["seed"]
                    if pq == "both":
                        expanded = f[exp_label]
                public = f[pub_label]
            else:
                secret = f["priv"]
                if alg in SCALAR_LEN:
                    n = SCALAR_LEN[alg]
                    secret = secret.lstrip("0").rjust(2 * n, "0")
                public = f["pub"]
            spki = out("openssl", "pkey", "-in", key, "-pubout", cwd=d).decode()
            w("    .{\n        .name = \"%s\",\n        .algorithm = \"%s\",\n        .encoding = \"%s\",\n" % (name, alg, enc))
            w("        .pq_form = %s,\n" % ("\"%s\"" % pq if pq else "null"))
            w("        .pem =\n%s        ,\n" % zig_str(read(d, key)))
            w("        .secret = \"%s\",\n        .expanded = \"%s\",\n        .public = \"%s\",\n" % (secret, expanded, public))
            w("        .spki_pem =\n%s        ,\n    },\n" % zig_str(spki))
        w("};\n\n")
        w("/// PKCS#8 `ENCRYPTED PRIVATE KEY` (password \"test\").\n")
        w("pub const encrypted_pkcs8_pem =\n%s;\n" % zig_str(read(d, "enc.p8")))
        w("/// SEC1 key with RFC 1421 `Proc-Type: 4,ENCRYPTED` headers (password \"test\").\n")
        w("pub const encrypted_sec1_pem =\n%s;\n" % zig_str(read(d, "enc.sec1")))
        res = subprocess.run(["zig", "fmt", "--stdin"], input=buf.getvalue(), check=True,
                             capture_output=True, text=True).stdout
        sys.stdout.write(res)


# (name, key, openssl pkcs8 options, kdf, prf, cipher, iterations, scrypt N, r, p)
ENC_CASES = [
    ("ed25519-default", "ed25519", [], "pbkdf2", "hmac_sha256", "aes256_cbc", 2048, 0, 0, 0),
    ("ed25519-sha1", "ed25519", ["-v2prf", "hmacWithSHA1"], "pbkdf2", "hmac_sha1", "aes256_cbc", 2048, 0, 0, 0),
    ("ed25519-sha224", "ed25519", ["-v2prf", "hmacWithSHA224"], "pbkdf2", "hmac_sha224", "aes256_cbc", 2048, 0, 0, 0),
    ("ed25519-sha384", "ed25519", ["-v2prf", "hmacWithSHA384"], "pbkdf2", "hmac_sha384", "aes256_cbc", 2048, 0, 0, 0),
    ("ed25519-sha512", "ed25519", ["-v2prf", "hmacWithSHA512"], "pbkdf2", "hmac_sha512", "aes256_cbc", 2048, 0, 0, 0),
    ("ed25519-aes128", "ed25519", ["-v2", "aes-128-cbc"], "pbkdf2", "hmac_sha256", "aes128_cbc", 2048, 0, 0, 0),
    ("ed25519-aes192", "ed25519", ["-v2", "aes-192-cbc"], "pbkdf2", "hmac_sha256", "aes192_cbc", 2048, 0, 0, 0),
    ("ed25519-iter1", "ed25519", ["-noiter"], "pbkdf2", "hmac_sha256", "aes256_cbc", 1, 0, 0, 0),
    ("ed25519-iter32768", "ed25519", ["-iter", "32768"], "pbkdf2", "hmac_sha256", "aes256_cbc", 32768, 0, 0, 0),
    ("ed25519-scrypt", "ed25519", ["-scrypt"], "scrypt", "", "aes256_cbc", 0, 16384, 8, 1),
    ("ed25519-scrypt-small", "ed25519",
     ["-scrypt", "-v2", "aes-128-cbc", "-scrypt_N", "1024", "-scrypt_r", "4", "-scrypt_p", "3"],
     "scrypt", "", "aes128_cbc", 0, 1024, 4, 3),
    ("ec_p256-default", "ec_p256", [], "pbkdf2", "hmac_sha256", "aes256_cbc", 2048, 0, 0, 0),
    ("ec_p256-scrypt-small", "ec_p256", ["-scrypt", "-scrypt_N", "512", "-scrypt_r", "8", "-scrypt_p", "2"],
     "scrypt", "", "aes256_cbc", 0, 512, 8, 2),
    ("rsa-default", "rsa", [], "pbkdf2", "hmac_sha256", "aes256_cbc", 2048, 0, 0, 0),
    ("rsa-aes192-sha384", "rsa", ["-v2", "aes-192-cbc", "-v2prf", "hmacWithSHA384"],
     "pbkdf2", "hmac_sha384", "aes192_cbc", 2048, 0, 0, 0),
]
ENC_PASSWORD = "correct horse battery"


def main_encrypted():
    with tempfile.TemporaryDirectory() as d:
        version = out("openssl", "version", cwd=d).decode().strip().split(" (")[0]
        run("openssl", "genpkey", "-algorithm", "ED25519", "-out", "ed25519.p8", cwd=d)
        run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "ec_p256.p8", cwd=d)
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "rsa.p8", cwd=d)
        buf = io.StringIO()
        w = buf.write
        w("// SPDX-License-Identifier: MIT\n\n")
        w("//! TEST keys as PKCS#8 `ENCRYPTED PRIVATE KEY` in every PBES2 form `openssl pkcs8\n")
        w("//! -topk8` writes that keycodec reads, generated by `tools/vectors.py --encrypted`\n")
        w("//! with %s. Published test fixtures: never use these keys or the password\n" % version)
        w("//! for anything else. Do not edit by hand.\n\n")
        w("pub const Case = struct {\n    name: []const u8,\n    algorithm: []const u8,\n    password: []const u8,\n")
        w("    kdf: []const u8,\n    prf: []const u8,\n    cipher: []const u8,\n    iterations: u64,\n")
        w("    n: u64,\n    r: u32,\n    p: u32,\n    /// The same key as `openssl pkcs8 -nocrypt` writes it.\n    plain_pem: []const u8,\n    pem: []const u8,\n};\n\n")
        w("pub const cases = [_]Case{\n")
        for name, key, opts, kdf, prf, cipher, iters, n, r, p in ENC_CASES:
            src = key + ".p8"
            out_name = name + ".enc"
            run("openssl", "pkcs8", "-topk8", "-in", src, "-out", out_name, "-passout", "pass:" + ENC_PASSWORD, *opts, cwd=d)
            run("openssl", "pkcs8", "-in", out_name, "-passin", "pass:" + ENC_PASSWORD, "-topk8", "-nocrypt", "-out", name + ".plain", cwd=d)
            w("    .{\n        .name = \"%s\",\n        .algorithm = \"%s\",\n        .password = \"%s\",\n" % (name, key, ENC_PASSWORD))
            w("        .kdf = \"%s\",\n        .prf = \"%s\",\n        .cipher = \"%s\",\n" % (kdf, prf, cipher))
            w("        .iterations = %d,\n        .n = %d,\n        .r = %d,\n        .p = %d,\n" % (iters, n, r, p))
            w("        .plain_pem =\n%s        ,\n" % zig_str(read(d, name + ".plain")))
            w("        .pem =\n%s        ,\n    },\n" % zig_str(read(d, out_name)))
        w("};\n")
        res = subprocess.run(["zig", "fmt", "--stdin"], input=buf.getvalue(), check=True,
                             capture_output=True, text=True).stdout
        sys.stdout.write(res)


if __name__ == "__main__":
    if sys.argv[1:] == ["--encrypted"]:
        main_encrypted()
    else:
        main()
