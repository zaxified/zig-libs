#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for the chained default-network (`pedersen-bls-chained`) fixtures.

WHY THIS EXISTS. `src/verify.zig` pins three genuine beacons of the League of
Entropy "default" chain (chain hash 8990e7a9...b2ce) -- rounds 1, 1000000 and
2634945 -- plus the chain's `/info` (already pinned in `src/chaininfo.zig`).
They are an EXTERNAL anchor only if someone can re-obtain them. This script is
how, by two independent routes:

  live      GET https://api.drand.sh/<chain>/{info,public/<round>} and compare
            with the committed values. The authoritative check.
  packages  Download the two published packages the committed values were
            taken from and confirm each value appears there verbatim:
              - drand/drand v2.1.7 (Go module zip via proxy.golang.org;
                MIT/Apache-2.0): crypto/schemes_test.go `TestVerifyBeacon`
                -> round 2634945 (signature, previous_signature) and the
                public key; drand's own Go scheme verifies them there.
              - drand_core 0.0.19 (crate via static.crates.io; MIT):
                src/beacon.rs `chained_beacon`/`chained_beacon_1` -> rounds
                1000000 and 1 (signature, previous_signature, randomness),
                recorded there from `curl drand.cloudflare.com/public/N`.
            Only DATA is read from them, never code.

On 2026-10-06 the session that committed the fixtures could reach the package
mirrors but not api.drand.sh (egress policy 403), so the `packages` route is
what was run; `live` is written for whoever next has network access to the
beacon, and it exits non-zero on any disagreement.

WHAT IT NEEDS. Python 3 with urllib; network access to the route chosen.

    python3 fetch_chained.py live
    python3 fetch_chained.py packages [workdir]   # default ./chained-pkgs

It never writes into the repository: compare its output with the literals in
src/verify.zig by eye (see README.md here for why vectors are pasted by hand).
"""
import io, json, os, sys, tarfile, urllib.request, zipfile

CHAIN = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
PUBKEY = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"

# What src/verify.zig pins. `randomness` None = not pinned (no external value).
ROUNDS = {
    1: dict(
        signature="8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655",
        previous_signature="176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a",
        randomness="101297f1ca7dc44ef6088d94ad5fb7ba03455dc33d53ddb412bbc4564ed986ec",
    ),
    1000000: dict(
        signature="87e355169c4410a8ad6d3e7f5094b2122932c1062f603e6628aba2e4cb54f46c3bf1083c3537cd3b99e8296784f46fb40e090961cf9634f02c7dc2a96b69fc3c03735bc419962780a71245b72f81882cf6bb9c961bcf32da5624993bb747c9e5",
        previous_signature="86bbc40c9d9347568967add4ddf6e351aff604352a7e1eec9b20dea4ca531ed6c7d38de9956ffc3bb5a7fabe28b3a36b069c8113bd9824135c3bff9b03359476f6b03beec179d4aeff456f4d34bbf702b9af78c3bb44e1892ace8e581bf4afa9",
        randomness="a26ba4d229c666f52a06f1a9be1278dcc7a80dbc1dd2004a1ae7b63cb79fd37e",
    ),
    2634945: dict(
        signature="814778ed1e480406beb43b74af71ce2f0373e0ea1bfdfea8f9ed62c876c20fcbc7f0163860e3da42ed2148756015f4551451898ffe06d384b4d002245025571b6b7a752f7158b40ad92b13b6d703ad31922a617f2c7f6d960b84d56cf1d79eef",
        previous_signature="8bd96294383b4d1e04e736360bd7a487f9f409f1e7bd800b720656a310d577b3bdb1e1631af6c5782a1d8979c502f395036181eff4058960fc40bb7034cdae1991d3eda518ab204a077d2f7e724974cf87b407e549bd815cf0b8e5a3832f675d",
        randomness=None,
    ),
}

GO_ZIP = "https://proxy.golang.org/github.com/drand/drand/v2/@v/v2.1.7.zip"
GO_FILE = "github.com/drand/drand/v2@v2.1.7/crypto/schemes_test.go"
CRATE = "https://static.crates.io/crates/drand_core/drand_core-0.0.19.crate"
CRATE_FILE = "drand_core-0.0.19/src/beacon.rs"


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def live():
    bad = 0
    info = json.loads(get(f"https://api.drand.sh/{CHAIN}/info"))
    for k, want in (("public_key", PUBKEY), ("hash", CHAIN), ("schemeID", "pedersen-bls-chained")):
        ok = info.get(k) == want
        bad += not ok
        print(f"info.{k}: {'OK' if ok else 'MISMATCH ' + repr(info.get(k))}")
    for rnd, want in ROUNDS.items():
        got = json.loads(get(f"https://api.drand.sh/{CHAIN}/public/{rnd}"))
        for k, v in want.items():
            if v is None:
                print(f"round {rnd} {k}: live value {got.get(k)} (not pinned)")
                continue
            ok = got.get(k) == v
            bad += not ok
            print(f"round {rnd} {k}: {'OK' if ok else 'MISMATCH ' + repr(got.get(k))}")
    return bad


def packages(workdir):
    os.makedirs(workdir, exist_ok=True)
    go_src = zipfile.ZipFile(io.BytesIO(get(GO_ZIP))).read(GO_FILE).decode()
    with tarfile.open(fileobj=io.BytesIO(get(CRATE)), mode="r:gz") as t:
        rs_src = t.extractfile(CRATE_FILE).read().decode()
    # Keep the two files for a human to read; nothing here executes them.
    open(os.path.join(workdir, "schemes_test.go"), "w").write(go_src)
    open(os.path.join(workdir, "beacon.rs"), "w").write(rs_src)
    bad = 0
    checks = [("drand v2.1.7 schemes_test.go", go_src, PUBKEY, "public key")]
    checks += [("drand v2.1.7 schemes_test.go", go_src, ROUNDS[2634945][k], f"round 2634945 {k}")
               for k in ("signature", "previous_signature")]
    checks += [("drand v2.1.7 schemes_test.go", go_src, "Round:   2634945", "round number 2634945")]
    for rnd in (1, 1000000):
        checks += [("drand_core 0.0.19 beacon.rs", rs_src, v, f"round {rnd} {k}") for k, v in ROUNDS[rnd].items()]
        checks += [("drand_core 0.0.19 beacon.rs", rs_src, f'"round": {rnd},', f"round number {rnd}")]
    for where, text, needle, what in checks:
        ok = needle in text
        bad += not ok
        print(f"{what}: {'found' if ok else 'NOT FOUND'} in {where}")
    return bad


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "live"
    if mode == "live":
        bad = live()
    elif mode == "packages":
        bad = packages(sys.argv[2] if len(sys.argv) > 2 else "chained-pkgs")
    else:
        sys.exit("usage: fetch_chained.py live | packages [workdir]")
    print("ALL AGREE" if bad == 0 else f"{bad} DISAGREEMENT(S)")
    sys.exit(1 if bad else 0)
