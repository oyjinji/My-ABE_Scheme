"""Executable counterexamples for isolated Phase 5D-R baseline blockers.

These are integer exponent checks, not HR-ABE/LUAR implementations or timing
samples. See HRABE_TYPEIII_MAPPING_V2.md and FORMULA_AUDIT.md.
"""


def test_hrabe_type_iii_independent_hash_exponents_do_not_cancel():
    # Figure 2 row denominator: (a*lambda-u*r)*t/(beta*gamma)
    # +r*v*t/(beta*gamma). Cancellation needs the same hidden hash exponent
    # in G1 and G2; independent hash-to-curve outputs do not give that.
    prime = 101
    a, lam, r, t, beta, gamma = 7, 13, 5, 17, 11, 3
    inverse = pow(beta * gamma, -1, prime)

    def denominator_exponent(u, v):
        return ((a * lam - u * r + r * v) * t * inverse) % prime

    expected = (a * lam * t * inverse) % prime
    assert denominator_exponent(19, 19) == expected
    assert denominator_exponent(19, 23) != expected


def test_luar_published_reconstruction_fails_valid_two_row_and():
    # Published §6.4 makes each matching leaf contribute beta*s*t, then
    # exponentiates by the LSSS coefficients. Valid reconstruction does not
    # imply their sum is one. This reproduces FORMULA_AUDIT.md's example.
    prime = 101
    alpha, beta, s, t, r = 7, 11, 13, 17, 5
    shares = ((s + r) % prime, (-r) % prime)
    omega = (1, 1)
    assert sum(w * share for w, share in zip(omega, shares)) % prime == s
    assert sum(omega) == 2
    expected_mask = alpha * s % prime
    published_mask = (alpha * s + beta * s * t *
                      (1 - sum(omega))) % prime
    assert expected_mask == 91
    assert published_mask == 84
    assert published_mask != expected_mask
