#!/usr/bin/env bash
# Close the environment gaps `scripts/test.sh` reports, on a hosted runner.
#
# Everything installed here exists to let a LIVE test reach a real peer: a
# wolfSSL DTLS responder, an open62541 container, and five Python packages that
# are INDEPENDENT implementations of what the module under test implements.
# Those are the highest-value tests in this collection, because they are the
# only ones that can fail for a reason our own encoder does not share — and
# they are also the ones that vanish quietly, since a missing peer is a skip
# and a skip is a pass.
#
# ⭐ ONE SCRIPT, BOTH JOBS, and that is the point of it existing at all. Until
# 2026-08-15 this lived inline in the `full` job only, so the `scoped` job —
# the one that gates every push — ran with all six gaps open. That mattered
# more from the moment `test.sh changed` learned to escalate to the full gate
# on CI when the harness moves (see cmd_changed): the scoped job now sometimes
# runs EVERY module, and a lane that runs everything with no peers installed
# reports green over a large hole.
#
# ⚠ EVERY LINE IS ALLOWED TO FAIL, and that is not fail-open. test.sh re-probes
# the environment itself and prints what is still missing together with what it
# costs, so a failed install downgrades coverage LOUDLY rather than failing a
# lane over a package mirror. The arm64 lane is the case that needs this: not
# every one of these ships for aarch64. What must never happen is a gap closing
# silently, and that report is what prevents it — read it, do not assume this
# script worked.
set -u

# Quiet, but not silent: `apt-get -qq` still lets dpkg print a twenty-four line
# "(Reading database ... 5% ... 100%)" progress bar into a log that gets read by
# hand. The pty is what produces it.
export DEBIAN_FRONTEND=noninteractive
APT_QUIET=(-y -qq -o Dpkg::Use-Pty=0)

echo "::group::userns"
# Ubuntu restricts unprivileged user namespaces via AppArmor (24.04 and 26.04
# alike), which is what makes `unshare -rn` fail on a stock runner. Without it
# the privileged tests of ten netlink-writing modules skip, and the gate's own
# words for that are "reported green while covering less".
echo 'kernel.apparmor_restrict_unprivileged_userns=0' \
    | sudo tee /etc/sysctl.d/60-zig-libs-userns.conf >/dev/null || true
sudo sysctl --system >/dev/null 2>&1 || true
unshare -rn true && echo "userns: OK" || echo "userns: still unavailable"

# Unprivileged ICMP sockets. The kernel default is the EMPTY range `1 0`, which
# is why icmp's three live tests — the ones that put a real echo request on the
# wire rather than encode one — skipped on every runner since CI existed.
echo 'net.ipv4.ping_group_range=0 2147483647' \
    | sudo tee /etc/sysctl.d/61-zig-libs-ping.conf >/dev/null || true
sudo sysctl --system >/dev/null 2>&1 || true
echo "ping_group_range: $(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo unknown)"
echo "::endgroup::"

echo "::group::yaml conformance suite"
# yaml/yaml-test-suite is the LANGUAGE's own conformance corpus, written by
# people who did not write our parser. Without it the whole suite collapses into
# a single skipped test and the module is checked only against itself.
#
# ⚠ A network fetch at gate time, which nothing else here is. It is bounded
# (--depth 1, one branch) and failure is a reported gap rather than a red lane,
# but if this ever becomes flaky the honest fix is to cache the checkout, not to
# retry it.
git clone -q -b data --depth 1 https://github.com/yaml/yaml-test-suite \
    "$HOME/.cache/zig-libs-yaml/yaml-test-suite-data" 2>/dev/null \
    && echo "yaml-test-suite: OK" || echo "yaml-test-suite: clone failed or already present"
echo "::endgroup::"

echo "::group::apt"
sudo apt-get update "${APT_QUIET[@]}" >/dev/null 2>&1 || true
# dtls's live DTLS 1.3 peer. wolfSSL specifically, because OpenSSL 3.5 and
# GnuTLS 3.8 have no DTLS 1.3 at all.
sudo apt-get install "${APT_QUIET[@]}" libwolfssl-dev >/dev/null 2>&1 \
    && echo "wolfssl: OK" || echo "wolfssl: install failed"
echo "::endgroup::"

echo "::group::open62541 container"
# opcua's container-backed live server interop.
#
# ⚠ open62541 publishes no aarch64 image. On the arm64 lane this pulls the
# amd64 one and podman says so in a single warning line; the tests then run
# under emulation, which on tag 2026-08-15 cost 540 s against amd64's 120 s.
# That is left as it is ON PURPOSE — an emulated peer is still a real
# third-party implementation and interop does not depend on the peer's ISA —
# but it is no longer invisible: test.sh compares the image architecture with
# the host's and reports the emulation, its cost, and that no native image
# exists. Whether the minutes are worth the coverage is the owner's call.
podman pull -q docker.io/open62541/open62541:latest >/dev/null 2>&1 \
    && echo "open62541: OK" || echo "open62541: pull failed"
echo "::endgroup::"

echo "::group::python oracles"
# PEP 668 marks the system interpreter externally-managed and these tests spawn
# a bare `python3`, so the ones without a venv of their own have to land there.
#
# jinja's oracle is a REAL Python Jinja2 and its VERSION is part of the claim,
# not an implementation detail. The committed golden records `"jinja2": "3.1.6"`;
# a runner shipping a different one turned two of 337 corpus cases red for
# `replace` and `trim` with Markup arguments on 2026-08-15, and our output
# matched the golden byte for byte in both — the ORACLE had moved, which is
# exactly what a golden-vs-live test exists to catch. A gate must go red for our
# reasons, so this is pinned and bumped deliberately.
#
# The other three were found missing by the arm64 lane of tag 2026-08-15, which
# skipped 22 reference-interop tests while the capability report said "1 gap".
# The report had no probe for them; it has one now, and they are installed here
# so the probe has nothing to report.
sudo pip3 install --break-system-packages -q --root-user-action=ignore \
    "jinja2==3.1.6" sympy brotli protobuf >/dev/null 2>&1 || true
python3 - <<'PY' || true
for mod, label in (("jinja2", "jinja2"), ("sympy", "sympy"),
                   ("brotli", "brotli"), ("google.protobuf", "protobuf")):
    try:
        m = __import__(mod)
        print(f"{label}: {getattr(m, '__version__', 'present')}")
    except ImportError:
        print(f"{label}: MISSING")
PY

# Four venvs, because each of these modules looks for one at a fixed path
# before falling back to a bare `python3` (or, for opcua, is pointed at one by
# OPCUA_PYTHON). Keep the paths in step with the probes in test.sh.
# ⚠ `grpc` takes protobuf TOO, and a venv does not see system site-packages.
# The first run of this script installed protobuf system-wide and grpcio into
# the venv, so the venv's interpreter — the one grpc's tests actually spawn —
# had grpcio and no `google.protobuf`, and the oracle script died on an import.
# List everything a venv's own scripts import; nothing outside it will help.
for spec in "grpc:grpcio protobuf" "opcua:asyncua cryptography" "imap:pymap"; do
    name="${spec%%:*}"
    pkgs="${spec#*:}"
    python3 -m venv "$HOME/.cache/zig-libs-$name" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    "$HOME/.cache/zig-libs-$name/bin/pip" -q install $pkgs >/dev/null 2>&1 \
        && echo "$name venv: OK" || echo "$name venv: install failed"
done
echo "::endgroup::"
