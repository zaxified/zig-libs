# SPDX-License-Identifier: MIT
"""An independent port of the Poseidon reference generator's MDS security
checks — `algorithm_1`, `algorithm_2`, `algorithm_3` and
`check_minpoly_condition` from `generate_parameters_grain.sage` — on top of
sympy's `DomainMatrix` over `GF(p)`, standing in for sage's `VectorSpace`/
`matrix` when sage is not installed.

WHAT THIS IS AND IS NOT
-----------------------
This is a *second transcription of the same sage text*, written to cross-check
the Zig one. It is a tier-2 oracle: it catches transcription slips (an index
off by one, a wrong sub-code, a rejection that fails to advance) and it does
**not** catch a shared misreading of the specification — if the sage source was
misunderstood, both ports misunderstand it identically. Do not describe its
agreement as external validation.

Where it IS strong: it is fed random matrices over a *small* prime, where the
checks reject constantly, and it reports which check fired and with which
sub-code — a much narrower target than a boolean.

Deliberate independence from the Zig side:
  * subspaces are canonical RREF bases, compared literally, rather than the
    Zig side's "equal rank plus containment";
  * intersection goes through double orthogonal complement, not stacked
    kernels;
  * eigenvalues come from sympy's factorisation of the characteristic
    polynomial, not from a hand-written Cantor-Zassenhaus;
  * the minimal polynomial is the first linear dependency among
    I, A, A^2, … in F^(t*t) — the definition — not "the characteristic
    polynomial is irreducible", which is the shortcut the Zig side proves and
    uses.

Protocol (files in the cwd, so no argv quoting games):
  in.txt   p / t / count, then `count` matrices of `t` rows of `t` decimal ints
  out.txt  one line per matrix:
           `<alg1_secure> <alg1_code> <alg1_round> <alg2> <alg3> <minpoly>`
"""

import sys

from sympy import GF, Poly, symbols
from sympy.polys.matrices import DomainMatrix

X = symbols("x")


# ── plain integer matrix helpers (mod p) ────────────────────────────────────

def mat_mul(a, b, p):
    n = len(a)
    return [[sum(a[i][k] * b[k][j] for k in range(n)) % p for j in range(n)]
            for i in range(n)]


def mat_vec(a, v, p):
    n = len(a)
    return tuple(sum(a[i][j] * v[j] for j in range(n)) % p for i in range(n))


def mat_pow(a, k, p):
    n = len(a)
    out = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for _ in range(k):
        out = mat_mul(out, a, p)
    return out


def basis_vec(i, n):
    return tuple(1 if j == i else 0 for j in range(n))


# ── subspaces as canonical RREF bases ───────────────────────────────────────

def _dm(rows, n, K):
    return DomainMatrix([[K(int(v)) for v in r] for r in rows], (len(rows), n), K)


def _rref_rows(A, n):
    res = A.rref()
    R = res[0]
    out = []
    for row in R.to_list():
        vals = tuple(int(e) for e in row)
        if any(vals):
            out.append(vals)
    return out


def span(vectors, n, K):
    """Canonical basis (RREF rows) of the span of `vectors` in F^n."""
    vs = [v for v in vectors]
    if not vs:
        return []
    return _rref_rows(_dm(vs, n, K), n)


def perp(vectors, n, K):
    """{ y in F^n : v . y = 0 for every v }, as a canonical basis."""
    vs = [v for v in vectors if any(v)]
    if not vs:
        return [basis_vec(i, n) for i in range(n)]
    N = _dm(vs, n, K).nullspace()
    rows = [tuple(int(e) for e in row) for row in N.to_list()]
    return span(rows, n, K)


def intersect(a, b, n, K):
    """Deliberately via (A^perp + B^perp)^perp rather than stacked kernels."""
    return perp(perp(a, n, K) + perp(b, n, K), n, K)


def subspace_times_matrix(subspace, m, n, p, K):
    return span([mat_vec(m, v, p) for v in subspace], n, K)


# ── polynomials over GF(p) ──────────────────────────────────────────────────

def charpoly_coeffs(a, n, K):
    """Characteristic polynomial coefficients, highest degree first."""
    cp = _dm(a, n, K).charpoly()
    return [int(c) % K.mod for c in cp]


def rational_eigenvalues(a, n, p, K):
    """The eigenvalues of `a` that lie in the BASE field — the reference's
    `if (eigenspace[0] not in F): continue`."""
    poly = Poly(charpoly_coeffs(a, n, K), X, modulus=p, symmetric=False)
    roots = []
    for factor, _mult in poly.factor_list()[1]:
        if factor.degree() == 1:
            c = factor.all_coeffs()
            lead = int(c[0]) % p
            const = int(c[1]) % p
            roots.append((-const * pow(lead, p - 2, p)) % p)
    return sorted(set(roots))


def minimal_polynomial(a, n, p, K):
    """The honest definition: the first linear dependency among
    I, A, A^2, … viewed as vectors in F^(n*n). Returns monic coefficients,
    lowest degree first."""
    flat = []
    cur = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    while True:
        vec = tuple(cur[i][j] for i in range(n) for j in range(n))
        candidate = flat + [vec]
        if len(span(candidate, n * n, K)) < len(candidate):
            flat = candidate
            break
        flat = candidate
        cur = mat_mul(cur, a, p)
    # Left null space of the stacked powers: the dependency coefficients.
    N = _dm(flat, n * n, K).transpose().nullspace()
    coeffs = [int(e) % p for e in N.to_list()[0]]
    while coeffs and coeffs[-1] == 0:
        coeffs.pop()
    lead_inv = pow(coeffs[-1], p - 2, p)
    return [(c * lead_inv) % p for c in coeffs]


# ── the four checks ─────────────────────────────────────────────────────────

def generate_vectorspace(round_num, m, m_round, t, p, K):
    s = 1
    if round_num == 0:
        return span([basis_vec(i, t) for i in range(t)], t, K)
    if round_num == 1:
        return span([basis_vec(i, t) for i in range(s, t)], t, K)
    rows = []
    for i in range(round_num - 1):
        for j in range(s):
            rows.append(tuple(m_round[i][j][s:]))
    r_k = perp(rows, t - s, K)
    return span([tuple([0] * s + list(v)) for v in r_k], t, K)


def algorithm_1(m, t, p, K):
    s = 1
    r = (t - s) // s
    m_round = [mat_pow(m, j + 1, p) for j in range(t + 1)]

    for i in range(1, r + 1):
        mat_test = mat_pow(m, i, p)
        entry = mat_test[0][0]
        target = [[entry if a == b else 0 for b in range(t)] for a in range(t)]
        if mat_test == target:
            return (False, 1, i)

        s_space = generate_vectorspace(i, m, m_round, t, p, K)

        basis_vectors = []
        for lam in rational_eigenvalues(mat_test, t, p, K):
            shifted = [[(mat_test[a][b] - (lam if a == b else 0)) % p
                        for b in range(t)] for a in range(t)]
            eigenspace = perp(shifted, t, K)
            basis_vectors += intersect(s_space, eigenspace, t, K)
        is_space = span(basis_vectors, t, K)
        if len(is_space) >= 1 and len(is_space) != t:
            return (False, 2, i)

        for j in range(1, i + 1):
            if subspace_times_matrix(s_space, mat_pow(m, j, p), t, p, K) == s_space:
                return (False, 3, i)
    return (True, 0, 0)


def algorithm_2(m, t, p, K):
    s = 1
    for i_s in [[0]]:  # powerset(range(1))[1:]
        test_next = False
        new_basis = [basis_vec(l, t) for l in i_s]
        is_space = span(new_basis, t, K)
        for i in range(s, t):
            new_basis.append(basis_vec(i, t))
        full_iota = span(new_basis, t, K)
        for l in i_s:
            v = basis_vec(l, t)
            while True:
                delta = len(is_space)
                v = mat_vec(m, v, p)
                is_space = span(list(is_space) + [v], t, K)
                if len(is_space) == t or intersect(is_space, full_iota, t, K) != is_space:
                    test_next = True
                    break
                if len(is_space) <= delta:
                    break
            if test_next:
                break
        if test_next:
            continue
        return False
    return True


def algorithm_3(m, t, p, K):
    for r in range(2, 4 * t + 1):
        if not algorithm_2(mat_pow(m, r, p), t, p, K):
            return False
    return True


def check_minpoly_condition(m, t, p, K):
    m_temp = m
    for _ in range(1, 2 * t + 1):
        coeffs = minimal_polynomial(m_temp, t, p, K)
        deg = len(coeffs) - 1
        if deg != t:
            return False
        if not Poly(list(reversed(coeffs)), X, modulus=p, symmetric=False).is_irreducible:
            return False
        m_temp = mat_mul(m, m_temp, p)
    return True


# ── driver ──────────────────────────────────────────────────────────────────

def main():
    tokens = open("in.txt").read().split()
    pos = 0
    p = int(tokens[pos]); pos += 1
    t = int(tokens[pos]); pos += 1
    count = int(tokens[pos]); pos += 1
    want_minpoly = int(tokens[pos]); pos += 1
    K = GF(p, symmetric=False)

    lines = []
    for _ in range(count):
        m = []
        for _row in range(t):
            m.append([int(tokens[pos + j]) % p for j in range(t)])
            pos += t
        a1 = algorithm_1(m, t, p, K)
        a2 = algorithm_2(m, t, p, K)
        a3 = algorithm_3(m, t, p, K)
        mp = check_minpoly_condition(m, t, p, K) if want_minpoly else 0
        lines.append("%d %d %d %d %d %d" % (
            1 if a1[0] else 0, a1[1], a1[2],
            1 if a2 else 0, 1 if a3 else 0, 1 if mp else 0))
    with open("out.txt", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
