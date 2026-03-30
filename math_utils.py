"""
math_utils.py — Number-theory helpers for the VDF system.

Includes:
  - Miller-Rabin primality test
  - Secure prime generation
  - Modular square root (for Sloth)
  - Fp² extension field arithmetic (for Sloth++)
  - Hash-to-group mapping (safe generator derivation)
  - Quadratic-residue test (for Sloth sign normalisation)
"""

import secrets
import hashlib


# ---------------------------------------------------------------------------
# 1. Primality & prime generation
# ---------------------------------------------------------------------------

def _miller_rabin(n: int, rounds: int = 20) -> bool:
    """Deterministic-quality Miller-Rabin primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    """Generate a random prime of exactly *bits* bits."""
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(p):
            return p


def _gen_prime_cong(bits: int, residue: int, modulus: int) -> int:
    """Generate a prime p of *bits* bits satisfying p ≡ residue (mod modulus)."""
    while True:
        p = _gen_prime(bits)
        if p % modulus == residue:
            return p


def get_first_t_odd_primes(t: int) -> list[int]:
    """Return the first t odd primes (starting from 3)."""
    primes = []
    n = 3
    while len(primes) < t:
        if _miller_rabin(n, rounds=5):
            primes.append(n)
        n += 2
    return primes


# ---------------------------------------------------------------------------
# 2. Modular square roots  (Sloth — §7.1 of the paper)
# ---------------------------------------------------------------------------

def mod_sqrt(x: int, p: int) -> int:
    """
    Compute y = sqrt(x) mod p where p ≡ 3 (mod 4).

    Uses the Tonelli-Shanks special case: y = x^((p+1)/4) mod p.
    Verifiable by checking y² ≡ x (mod p).

    Raises ValueError if x is not a quadratic residue mod p.
    """
    if p % 4 != 3:
        raise ValueError("mod_sqrt requires p ≡ 3 (mod 4)")
    y = pow(x % p, (p + 1) // 4, p)
    if pow(y, 2, p) != x % p:
        raise ValueError(f"{x} is not a quadratic residue mod {p}")
    return y


def is_quadratic_residue(x: int, p: int) -> bool:
    """
    Euler's criterion: x is a QR mod p (odd prime) iff x^((p-1)/2) ≡ 1 (mod p).
    """
    return pow(x % p, (p - 1) // 2, p) == 1


def sloth_permute(x: int, p: int) -> int:
    """
    The sign-normalisation permutation σ from Sloth (Lenstra & Wesolowski 2015).
    Maps x to the canonical square root (the one with Jacobi symbol +1).

    For p ≡ 3 (mod 4):
      - If x is a QR, return x.
      - Otherwise return p - x (its negative) to make it a QR, then take sqrt.
    The result of sqrt(σ(x)) is the Sloth round function ρ(x).
    """
    # Ensure x is in [1, p-1]
    x = x % p
    if x == 0:
        return 0
    # If x is not a QR, negate it — exactly one of {x, p-x} is a QR
    if not is_quadratic_residue(x, p):
        x = p - x
    return x


# ---------------------------------------------------------------------------
# 3. Fp² extension-field arithmetic  (Sloth++ — §7.1)
# ---------------------------------------------------------------------------
# Fp² = Fp[i] / (i² + 1).  Elements are pairs (a, b) representing a + b·i.

Fp2Element = tuple  # (int, int)  representing a + b*i in Fp[i]/(i²+1)


def fp2_add(a: Fp2Element, b: Fp2Element, p: int) -> Fp2Element:
    """(a0 + a1·i) + (b0 + b1·i) in Fp²."""
    return ((a[0] + b[0]) % p, (a[1] + b[1]) % p)


def fp2_sub(a: Fp2Element, b: Fp2Element, p: int) -> Fp2Element:
    """(a0 + a1·i) - (b0 + b1·i) in Fp²."""
    return ((a[0] - b[0]) % p, (a[1] - b[1]) % p)


def fp2_mul(a: Fp2Element, b: Fp2Element, p: int) -> Fp2Element:
    """
    (a0 + a1·i)(b0 + b1·i) = (a0·b0 - a1·b1) + (a0·b1 + a1·b0)·i  in Fp².
    4 multiplications over Fp (matches §7.1 multiplicative complexity count).
    """
    a0, a1 = a
    b0, b1 = b
    real = (a0 * b0 - a1 * b1) % p
    imag = (a0 * b1 + a1 * b0) % p
    return (real, imag)


def fp2_pow(a: Fp2Element, exp: int, p: int) -> Fp2Element:
    """Square-and-multiply in Fp²."""
    result: Fp2Element = (1, 0)  # multiplicative identity
    base = (a[0] % p, a[1] % p)
    while exp > 0:
        if exp & 1:
            result = fp2_mul(result, base, p)
        base = fp2_mul(base, base, p)
        exp >>= 1
    return result


def fp2_norm(a: Fp2Element, p: int) -> int:
    """Norm N(a0 + a1·i) = a0² + a1² in Fp."""
    return (a[0] * a[0] + a[1] * a[1]) % p



def fp2_sqrt(x: Fp2Element, p: int) -> Fp2Element:
    """
    Compute the principal square root of an element x in Fp2.
    It works for our field Fp2 = Fp(i) where i^2 = -1, assuming p = 3 mod 4.
    """
    if p % 4 != 3:
        raise ValueError("fp2_sqrt requires p ≡ 3 (mod 4)")

    # For Fp² where p ≡ 3 (mod 4) and polynomial x² + 1,
    # the square root of element A can be found via:
    # A^((p^2 + 1) / 4) mod (x² + 1)
    
    # We must try two candidates: A itself and -A (or its conjugate variants sometimes)
    # The paper (Boneh et al) notes for Sloth++ to keep things simple we just
    # test candidates.
    
    # First candidate
    exp = (p * p + 1) // 4
    x_norm = (x[0] % p, x[1] % p)
    
    for candidate in [x_norm, ((p - x_norm[0]) % p, (p - x_norm[1]) % p)]:
        y = fp2_pow(candidate, exp, p)
        # Verify 
        check = fp2_mul(y, y, p)
        if check == candidate:
            return y

    # Note: the above method is a simplified heuristic from some Sloth implementations.
    # Because true generic fp2_sqrt requires Tonelli-Shanks for Fp2, let's use the explicit formulas:
    a, b = x_norm
    if b == 0:
        if is_quadratic_residue(a, p):
            return (mod_sqrt(a, p), 0)
        else:
            return (0, mod_sqrt((p - a) % p, p))
            
    # Norm delta = a^2 + b^2
    delta = (a * a + b * b) % p
    if not is_quadratic_residue(delta, p):
        raise ValueError(f"{x} is not a square in Fp² (p={p})")
        
    gamma = mod_sqrt(delta, p)
    inv2 = (p + 1) // 2
    
    w1 = ((a + gamma) * inv2) % p
    w2 = ((a - gamma + p) * inv2) % p
    
    if is_quadratic_residue(w1, p):
        w = w1
    else:
        w = w2
        
    s = mod_sqrt(w, p)
    t = (b * pow(2 * s, p - 2, p)) % p
    return (s, t)
# 4. Hash-to-group  (safe group element derivation)
# ---------------------------------------------------------------------------

def hash_to_group(x_bytes: bytes, N: int) -> int:
    """
    Hash bytes to a group element in Z*_N using a counter-mode approach.

    The output g satisfies:
      - 2 <= g < N
      - gcd(g, N) == 1  (almost certainly true for large N)
    This is used to derive a deterministic, safe generator from a challenge.
    """
    counter = 0
    while True:
        h = hashlib.sha256(x_bytes + counter.to_bytes(4, "big")).digest()
        # Expand to the bit-length of N
        while len(h) * 8 < N.bit_length():
            h += hashlib.sha256(h).digest()
        g_cand = int.from_bytes(h[: (N.bit_length() + 7) // 8], "big") % N
        if g_cand >= 2:
            from math import gcd
            if gcd(g_cand, N) == 1:
                return g_cand
        counter += 1


# ---------------------------------------------------------------------------
# 5. Injective Rational Maps (§7.2)
# ---------------------------------------------------------------------------

def guralnick_muller_poly_eval(x: int, a: int, s: int, p: int) -> int:
    """
    Evaluate the degree s^3 Guralnick-Muller permutation polynomial.
    f(x) = x(x^s - ax - a)^s + ((x^s - ax + a)^2 + 4a^2x)^{(s+1)/2} mod p
    where s is odd, and a != 0.
    In the paper (§7.2 Formula 2, simplified variant), it allows inversion via GCD.
    """
    x = x % p
    xs = pow(x, s, p)
    ax = (a * x) % p

    term1 = (xs - ax - a) % p
    term1_s = pow(term1, s, p)
    part1 = (x * term1_s) % p

    term2_inner = (xs - ax + a) % p
    term2_sq = pow(term2_inner, 2, p)
    term2_base = (term2_sq + 4 * a * a * x) % p
    
    # Needs to compute exponent (s+1)/2
    s_plus_1_half = (s + 1) // 2
    part2 = pow(term2_base, s_plus_1_half, p)

    return (part1 + part2) % p
