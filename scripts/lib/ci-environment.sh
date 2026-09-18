#!/usr/bin/env bash
# Close the environment gaps `scripts/test.sh` reports, on a hosted runner.
#
# Usage: scripts/lib/ci-environment.sh [tests|interop|ctgrind|all]   (default: tests)
#
# ⭐ TWO ROLES SINCE 2026-09-06, AND THE SPLIT IS THE POINT OF THIS HEADER.
# Until that day one list served every lane, and it was written when every one
# of these peers was reached from inside a module's own test binary. Then six
# modules were separated from their interop programs (`f3dbf38d`, `f42cc67a`):
# `test-dtls` stopped compiling a wolfSSL peer with `cc`, and `test-grpc`,
# `test-protobuf`, `test-brotli`, `test-jinja` and `test-poseidon` stopped
# spawning `python3` — each now replays a committed transcript and passes on a
# host with no compiler, no Python and no packages at all. The peers those six
# need did not become useless; they moved to `zig build interop-<m>`, which is
# what RE-TAKES the transcripts. So:
#
#   tests    — what a lane that RUNS tests or examples needs. Every item here
#              is reached by a test binary or an example: the two sysctls, the
#              yaml conformance corpus, opcua's container and its asyncua venv,
#              imap's pymap venv, and the `websockets` package the websocket
#              EXAMPLE judges itself against.
#   interop  — what `zig build interop-<m>` needs, and NOTHING here is reached
#              by any test: a C compiler and wolfSSL headers (dtls), and
#              jinja2 / sympy / brotli / protobuf / a grpcio venv (the five
#              Python-driven ones).
#   all      — both, for a machine that will do both.
#
# ⛔ THE `interop` HALF IS NOT DELETABLE, and that is the whole reason it is a
# role rather than a removal. A transcript nobody can RE-TAKE is a frozen
# anchor: it can never be extended, corrected, or re-derived, only trusted.
# This repository has already lost one that way — `modules/dnssec`'s
# independent-oracle vectors credited two scratchpad paths that are not in the
# repo, and `scripts/gen/gen-dnssec-oracle.sh` had to be written from scratch to
# make the anchor re-takeable again. Six transcripts landed on 2026-09-06;
# keeping the recipe installable is what stops all six going the same way.
#
# ⚠ WITH ONE EXCEPTION IN THE `tests` ROLE, AND IT IS THE LOUD KIND:
# `websockets` backs an EXAMPLE, not a test, and an example that cannot reach
# its judge FAILS. See the comment on the pip line below.
#
# ⭐ ONE SCRIPT, EVERY JOB, and that is the point of it existing at all. Until
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
#
# ⚠ That reasoning holds only for a package whose absence is a SKIP. When
# `websockets` fails to install, the lane goes red at `run-examples` — the `||
# true` buys nothing there, and the capability report naming it is the only
# thing that turns a traceback 400 steps into a build into an answer. It holds
# differently for the `interop` role: there, a failed install means the lane
# cannot re-take a transcript, and `zig build interop-<m>` says so by failing.
set -u

ROLE="${1:-tests}"
case "$ROLE" in
    tests | interop | ctgrind | all) ;;
    *)
        echo "ci-environment.sh: unknown role '$ROLE' (want tests, interop, ctgrind or all)" >&2
        exit 1
        ;;
esac
want() { [[ "$ROLE" == all || "$ROLE" == "$1" ]]; }
echo "ci-environment: role=$ROLE"

# Quiet, but not silent: `apt-get -qq` still lets dpkg print a twenty-four line
# "(Reading database ... 5% ... 100%)" progress bar into a log that gets read by
# hand. The pty is what produces it.
export DEBIAN_FRONTEND=noninteractive
APT_QUIET=(-y -qq -o Dpkg::Use-Pty=0)

if want tests; then
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

echo "::group::example judge + live-test venvs"
# ⭐ `websockets` IS NOT LIKE ANYTHING ELSE HERE, AND THAT IS WHY IT IS PINNED.
# Every other package in this script backs a TEST or an interop program, which
# skip or fail loudly when an import fails; this one backs an EXAMPLE, and
# `modules/websocket/example/main.zig` returns `error.PythonPeerFailed` rather
# than skipping — the whole point of that file is that an external judge
# actually runs. So a missing `websockets` is not reduced coverage, it is a red
# lane, which is exactly what the first push after `run-examples` learned to RUN
# the examples produced: 459/461 steps green and the gate red on
# `ModuleNotFoundError: No module named 'websockets'`, on a runner where nothing
# had ever installed it. The version is the one that example's own header claims
# to have been judged by; keep the two in step.
#
# PEP 668 marks the system interpreter externally-managed, hence
# --break-system-packages.
sudo pip3 install --break-system-packages -q --root-user-action=ignore \
    "websockets==15.0.1" >/dev/null 2>&1 || true
python3 -c 'import websockets; print("websockets:", websockets.__version__)' 2>/dev/null \
    || echo "websockets: MISSING"

# Two venvs, because each of these modules looks for one at a fixed path before
# falling back to a bare `python3` (or, for opcua, is pointed at one by
# OPCUA_PYTHON). Keep the paths in step with the probes in test.sh.
#
# ⚠ BOTH ARE REACHED BY A TEST, which is why they are in this role and grpc's
# venv is not: `opcua`'s asyncua client and `imap`'s pymap server are still
# spawned from inside those modules' own test binaries.
for spec in "opcua:asyncua cryptography" "imap:pymap"; do
    name="${spec%%:*}"
    pkgs="${spec#*:}"
    python3 -m venv "$HOME/.cache/zig-libs-$name" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    "$HOME/.cache/zig-libs-$name/bin/pip" -q install $pkgs >/dev/null 2>&1 \
        && echo "$name venv: OK" || echo "$name venv: install failed"
done
echo "::endgroup::"
fi

if want interop; then
echo "::group::interop: C toolchain + wolfSSL"
sudo apt-get update "${APT_QUIET[@]}" >/dev/null 2>&1 || true
# dtls's live DTLS 1.3 peer, for `zig build interop-dtls` ONLY. wolfSSL
# specifically, because OpenSSL 3.5 and GnuTLS 3.8 have no DTLS 1.3 at all.
# ⚠ `test-dtls` has NOT needed this since 2026-09-06 -- it replays
# `src/testdata/wolfssl_transcript.txt` and passes 268/268 on a box with no
# compiler and no wolfSSL. This install exists so a lane can RE-TAKE that
# transcript. `build-essential` for the same reason: `tools/interop.zig`
# compiles the peer with `cc -lwolfssl`, and a hosted runner has cc already —
# it is named here so a slimmer image does not silently lose the anchor.
sudo apt-get install "${APT_QUIET[@]}" build-essential libwolfssl-dev >/dev/null 2>&1 \
    && echo "cc + wolfssl: OK" || echo "cc + wolfssl: install failed"
command -v cc >/dev/null 2>&1 && echo "cc: $(cc --version | head -1)" || echo "cc: MISSING"
[[ -e /usr/include/wolfssl/ssl.h ]] && echo "wolfssl headers: OK" || echo "wolfssl headers: MISSING"
echo "::endgroup::"

echo "::group::interop: python oracles"
# The four transcripts taken by a bare `python3`. PEP 668 marks the system
# interpreter externally-managed and these programs spawn `python3` with no
# venv of their own, so they have to land there.
#
# jinja's oracle is a REAL Python Jinja2 and its VERSION is part of the claim,
# not an implementation detail. The committed golden records `"jinja2": "3.1.6"`;
# a runner shipping a different one turned two of 337 corpus cases red for
# `replace` and `trim` with Markup arguments on 2026-08-15, and our output
# matched the golden byte for byte in both — the ORACLE had moved, which is
# exactly what a golden-vs-live test exists to catch. A gate must go red for our
# reasons, so this is pinned and bumped deliberately. `test.sh`'s capability
# report compares the installed version against the golden's own header.
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

# ⚠ `grpc` takes protobuf TOO, and a venv does not see system site-packages.
# The first run of this script installed protobuf system-wide and grpcio into
# the venv, so the venv's interpreter — the one interop-grpc actually spawns —
# had grpcio and no `google.protobuf`, and the oracle script died on an import.
# List everything a venv's own scripts import; nothing outside it will help.
python3 -m venv "$HOME/.cache/zig-libs-grpc" >/dev/null 2>&1 || true
"$HOME/.cache/zig-libs-grpc/bin/pip" -q install grpcio protobuf >/dev/null 2>&1 \
    && echo "grpc venv: OK" || echo "grpc venv: install failed"
echo "::endgroup::"
fi

if want ctgrind; then
echo "::group::valgrind"
# The ONLY thing the ctgrind lane needs, and the lane is red without it rather
# than green-and-empty: `scripts/checks/ctgrind.sh` exits 2 when valgrind is not on
# PATH ("install it or run this on a host that has it — no auto-install"), so a
# failed install here cannot be mistaken for a passing measurement.
#
# ⚠ No `|| true`. For the `tests` role a failed install costs a SKIP and the
# capability report names it; here the lane's entire purpose is the run, so a
# silent partial install would be the "gate that scans nothing" shape again.
sudo apt-get update -qq
sudo apt-get install "${APT_QUIET[@]}" valgrind
valgrind --version
echo "::endgroup::"
fi
