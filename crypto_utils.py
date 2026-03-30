"""
crypto_utils.py — Complete VDF constructions from Boneh, Bonneau, Bünz, Fisch (2019).

Implemented constructions:
  1. RSA Group Setup (for Pietrzak & Wesolowski)
  2. Pietrzak VDF  (§4 — VDFIVC, recursive halving proof)
  3. Wesolowski VDF (§5 — VDFVC, single-element O(1) proof)
  4. Hash-Chain Sequential Function (§3 Definition 6/7 baseline — no fast verify)
  5. Sloth Weak VDF (§7.1 — iterated modular square roots)
  6. Sloth++ (§7.1 — iterated square roots over Fp², 7000× fewer SNARK gates)
  7. Randomness Beacon (§2 application)
  8. Proof of Replication helpers (§2 application)
  9. AES-GCM envelope encryption (for the exam system)
 10. VDF-based key locking with RSA trapdoor (for fast server-side setup)
"""

import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from math_utils import (
    _gen_prime,
    _miller_rabin,
    get_first_t_odd_primes,
    mod_sqrt,
    is_quadratic_residue,
    sloth_permute,
    fp2_mul,
    fp2_sqrt,
    fp2_pow,
    hash_to_group,
    guralnick_muller_poly_eval,
)


# ===========================================================================
# §A  AES-GCM helpers
# ===========================================================================

def aes_encrypt(plaintext: bytes, key: bytes) -> tuple:
    """Return (nonce, ciphertext) using AES-256-GCM."""
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)


def aes_decrypt(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    return AESGCM(key).decrypt(nonce, ct, None)


# ===========================================================================
# §B  Fiat-Shamir helpers
# ===========================================================================

def hash_to_prime(x_bytes: bytes, bits: int = 128) -> int:
    """
    Hash *x_bytes* to a prime of *bits* bits (Fiat-Shamir challenge).
    Used in Pietrzak and Wesolowski proofs.
    """
    counter = 0
    while True:
        h = hashlib.sha256(x_bytes + counter.to_bytes(4, "big")).digest()
        while len(h) * 8 < bits:
            h += hashlib.sha256(h).digest()
        p_cand = int.from_bytes(h[: bits // 8], "big")
        p_cand |= 1
        p_cand |= 1 << (bits - 1)
        if _miller_rabin(p_cand, rounds=5):
            return p_cand
        counter += 1


def _fiat_shamir_challenge(N: int, x: int, y: int, mu: int, bits: int = 128) -> int:
    """Pietrzak Fiat-Shamir challenge prime."""
    data = (
        str(N).encode()
        + str(x).encode()
        + str(y).encode()
        + str(mu).encode()
    )
    return hash_to_prime(data, bits=bits)


def _wesolowski_challenge(N: int, g: int, y: int, t: int, bits: int = 128) -> int:
    """
    Wesolowski Fiat-Shamir challenge prime ℓ (§5).
    Challenge depends on (N, g, y, t) to bind all statement parameters.
    """
    data = str(N).encode() + str(g).encode() + str(y).encode() + str(t).encode()
    return hash_to_prime(data, bits=bits)


# ===========================================================================
# §C  RSA Group Setup
# ===========================================================================

def generate_vdf_setup(bits: int = 2048) -> tuple:
    """
    Setup(λ, t) → public parameters.

    Generates an RSA group Z*_N of unknown order:
      N = p·q  (p, q strong primes)
      g = random generator in Z*_N

    The factorisation (p, q) is discarded — no trapdoor stored.
    Returns (N, g).
    """
    half = bits // 2
    p = _gen_prime(half)
    q = _gen_prime(half)
    while q == p:
        q = _gen_prime(half)
    N = p * q
    g = secrets.randbelow(N - 2) + 2
    return N, g


def generate_vdf_setup_with_trapdoor(bits: int = 2048) -> tuple:
    """
    Same as generate_vdf_setup but also returns φ(N) for the trusted-setup party.
    The evaluator key (ek) = (N, g, phi); the verifier key (vk) = (N, g).
    Used by the exam server to lock keys instantly using Euler's theorem.
    Returns (N, g, phi).
    """
    half = bits // 2
    p = _gen_prime(half)
    q = _gen_prime(half)
    while q == p:
        q = _gen_prime(half)
    N = p * q
    phi = (p - 1) * (q - 1)
    g = secrets.randbelow(N - 2) + 2
    return N, g, phi


# ===========================================================================
# §D  Pietrzak VDF  (§4 — VDFIVC)
# ===========================================================================
# Construction: prove g^(2^t) = y by recursive halving with Fiat-Shamir.
# Proof size: O(log t) group elements.
# Verify time: O(log t) modular exponentiations.

def _compute_power(base: int, steps: int, N: int) -> int:
    """Compute base^(2^steps) mod N via repeated squaring."""
    cur = base
    for _ in range(steps):
        cur = (cur * cur) % N
    return cur


def pietrzak_eval_vdf(N: int, g: int, t: int, progress_cb=None) -> tuple:
    """
    Eval(ek, x) for Pietrzak VDF.

    Computes y = g^(2^t) mod N and the recursive-halving proof π.
    Proof depth: full O(log t) levels (no depth cap).

    Returns (y, pi) where pi is a list of (mu_hex, t_level) tuples.
    The mask = SHA-256(y) is derived for key-unlock purposes.
    """
    # ---- Step 1: compute y sequentially (the delay step) ----
    report = max(1, t // 100) if t > 100 else 1
    cur = g
    for i in range(t):
        cur = (cur * cur) % N
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / t))
    y = cur
    if progress_cb:
        progress_cb(100)

    # ---- Step 2: generate the non-interactive Pietrzak proof ----
    # We iterate from the top, tracking (x_i, y_i, t_i) and building the mu list.
    def prove_iterative(x_val: int, y_val: int, t_val: int) -> list:
        proof = []
        cx, cy, ct = x_val, y_val, t_val
        while ct > 1:
            t_half = ct // 2
            if t_half == 0:
                break
            mu = _compute_power(cx, t_half, N)
            r = _fiat_shamir_challenge(N, cx, cy, mu)
            # Fold: new statement is (x', y', t/2) where
            #   x' = x^r · μ,  y' = μ^r · y
            new_cx = (pow(cx, r, N) * mu) % N
            new_cy = (pow(mu, r, N) * cy) % N
            proof.append((mu, ct))
            cx, cy, ct = new_cx, new_cy, t_half
        return proof

    pi = prove_iterative(g, y, t)
    mask = hashlib.sha256(y.to_bytes((y.bit_length() + 7) // 8, "big")).digest()
    return y, pi, mask


def pietrzak_verify_vdf(N: int, g: int, y: int, t: int, pi: list) -> bool:
    """
    Verify(vk, x, y, π) for Pietrzak VDF in O(log t) time.

    pi: list of (mu, t_level) tuples as produced by pietrzak_eval_vdf.
    At the end of the proof we directly check the remaining squarings.
    """
    cx, cy, ct = g, y, t
    for mu, t_level in pi:
        if ct != t_level:
            return False
        t_half = ct // 2
        r = _fiat_shamir_challenge(N, cx, cy, mu)
        cx = (pow(cx, r, N) * mu) % N
        cy = (pow(mu, r, N) * cy) % N
        ct = t_half
    # Base: verify the remaining squarings directly
    check = cx
    for _ in range(ct):
        check = (check * check) % N
    return check == cy


# ===========================================================================
# §E  Wesolowski VDF  (§5 — VDFVC, efficient tight VDF)
# ===========================================================================
# Construction: prove g^(2^t) = y with a SINGLE group element π.
#   π = g^(floor(2^t / ℓ)) mod N
# Verify: check π^ℓ · g^r ≡ y (mod N)  where r = 2^t mod ℓ.
# Proof size: O(1). Verify time: 2 modular exponentiations.

def wesolowski_eval_vdf(N: int, g: int, t: int, progress_cb=None) -> tuple:
    """
    Eval(ek, x) for Wesolowski VDF.

    Returns (y, pi) where:
      y  = g^(2^t) mod N
      pi = g^(floor(2^t / ℓ)) mod N  [single group element]
    """
    # ---- Step 1: compute y sequentially ----
    report = max(1, t // 100) if t > 100 else 1
    cur = g
    for i in range(t):
        cur = (cur * cur) % N
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / t))
    y = cur
    if progress_cb:
        progress_cb(100)

    # ---- Step 2: Fiat-Shamir challenge prime ℓ ----
    ell = _wesolowski_challenge(N, g, y, t)

    # ---- Step 3: compute π = g^(floor(2^t / ℓ)) mod N ----
    # floor(2^t / ℓ) via long-division on the exponent:
    #   quotient q and remainder r such that 2^t = q*ℓ + r
    #   We compute q iteratively: start with q=0, for each of the t bits
    #   we maintain the current accumulated exponent mod ℓ and the "carry" quotient.
    # Efficient method: track (b, pi_val) where b = 2^i mod ℓ and accumulate π.
    # b iterates as: b_0=1,  b_{i+1} = 2*b_i mod ℓ
    # Each time b_i >= ℓ//2... actually easier: long-division in binary.
    r = pow(2, t, ell)          # r = 2^t mod ℓ  (fast)
    q_bits = _big_div_floor(t, ell)   # quotient 2^t // ℓ  as integer
    pi_val = pow(g, q_bits, N)

    mask = hashlib.sha256(y.to_bytes((y.bit_length() + 7) // 8, "big")).digest()
    return y, pi_val, mask


def _big_div_floor(t: int, ell: int) -> int:
    """
    Compute floor(2^t / ell) using the long-division / repeated-doubling trick.

    We track (b, q) where b = 2^i mod ell and q = floor(2^i / ell).
    Each step: b_new = 2*b; if b_new >= ell: q_new = 2*q + 1, b_new -= ell
                                else:          q_new = 2*q.
    After t steps, q = floor(2^t / ell).
    For large t this is O(t) integer doublings — same order as the squarings.
    """
    b = 1  # 2^0 mod ell
    q = 0  # floor(2^0 / ell) = 0
    for _ in range(t):
        b <<= 1
        q <<= 1
        if b >= ell:
            b -= ell
            q += 1
    return q


def wesolowski_verify_vdf(N: int, g: int, y: int, t: int, pi: int) -> bool:
    """
    Verify(vk, x, y, π) for Wesolowski VDF.

    Check: π^ℓ · g^r ≡ y (mod N)
    where ℓ = Fiat-Shamir prime over (N, g, y, t)
          r = 2^t mod ℓ

    Runs in O(log t) time (2 modular exponentiations of size O(λ)).
    """
    ell = _wesolowski_challenge(N, g, y, t)
    r   = pow(2, t, ell)
    lhs = (pow(pi, ell, N) * pow(g, r, N)) % N
    return lhs == y


# ===========================================================================
# §F  Hash-Chain Sequential Function  (Definition 6/7 baseline)
# ===========================================================================
# The most basic sequential function from the paper: iterate SHA-256 t times.
# NOT a full VDF because verification is NOT faster than evaluation.
# Demonstrated here per §3 "Remark: Removing any single property makes VDF
# construction easy — if Verify is not required to be fast, iterate a OWF."

def hash_chain_eval(x_hex: str, t: int, progress_cb=None) -> tuple:
    """
    Compute y = SHA-256^t(x) iteratively.
    Returns (y_hex, checkpoints) where checkpoints are evenly spaced
    intermediate values (to allow partial verification).
    """
    num_checkpoints = min(t, 20)
    checkpoint_interval = max(1, t // num_checkpoints)
    checkpoints = {}  # step → hex digest

    cur = bytes.fromhex(x_hex)
    report = max(1, t // 100)
    for i in range(1, t + 1):
        cur = hashlib.sha256(cur).digest()
        if i % checkpoint_interval == 0 or i == t:
            checkpoints[i] = cur.hex()
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / t))

    if progress_cb:
        progress_cb(100)
    return cur.hex(), checkpoints


def hash_chain_verify(x_hex: str, y_hex: str, t: int, checkpoints: dict) -> bool:
    """
    Verify a hash chain by spot-checking the provided checkpoints.
    Sorted checkpoint list is used to reconstruct segments between them.

    Verification time: O(t / |checkpoints|) * |checkpoints| = O(t)
    (This is the baseline with no fast verify per the paper §3 remark.)
    """
    sorted_steps = sorted(int(k) for k in checkpoints)
    if not sorted_steps:
        # Fall back to full recompute
        result, _ = hash_chain_eval(x_hex, t)
        return result == y_hex

    # Verify from x_hex to first checkpoint
    cur = bytes.fromhex(x_hex)
    prev_step = 0
    for step in sorted_steps:
        for _ in range(step - prev_step):
            cur = hashlib.sha256(cur).digest()
        if str(step) in checkpoints:
            expected = checkpoints[str(step)]
        else:
            expected = checkpoints[step]
            
        if cur.hex() != expected:
            return False
        prev_step = step

    # Final step to y
    for _ in range(t - prev_step):
        cur = hashlib.sha256(cur).digest()
    return cur.hex() == y_hex


# ===========================================================================
# §G  Sloth Weak VDF  (§7.1 — iterated modular square roots)
# ===========================================================================
# Round function: τ(x) = ρ(σ(x)) where
#   σ normalises the sign (ensures QR) and ρ computes sqrt mod p.
# Eval runs in O(iter · log p) time (log p squarings per iteration).
# Verify runs in O(iter) multiplications — NOT polylog, so not a full VDF,
# hence "weak" per Definition 5.

def sloth_eval(x: int, p: int, iterations: int, progress_cb=None) -> int:
    """
    Eval the Sloth weak VDF: iterate ρ∘σ for *iterations* rounds.
    p must be a prime with p ≡ 3 (mod 4).
    Returns the final value y.
    """
    if p % 4 != 3:
        raise ValueError("Sloth requires p ≡ 3 (mod 4)")
    report = max(1, iterations // 100)
    cur = x % p
    for i in range(iterations):
        # σ: normalise to QR
        cur = sloth_permute(cur, p)
        # ρ: compute sqrt
        cur = mod_sqrt(cur, p)
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / iterations))
    if progress_cb:
        progress_cb(100)
    return cur


def sloth_verify(x_orig: int, y: int, p: int, iterations: int) -> bool:
    """
    Verify Sloth: forward-square y *iterations* times and recover x_orig.
    Each squaring is one multiplication — verification is fast per step
    but total O(iterations) multiplications.
    """
    cur = y % p
    for _ in range(iterations):
        cur = (cur * cur) % p
        # The permutation σ is its own inverse (up to sign);
        # normalise sign back to get the original pre-image direction
        if cur > p // 2:
            cur = p - cur
    return cur == x_orig % p


# ===========================================================================
# §H  Sloth++  (§7.1 — square roots over Fp², 7000× SNARK improvement)
# ===========================================================================
# Eval iterates square roots in Fp² = Fp[i]/(i²+1).
# Verify multiplicity complexity: only 4 Fp-gates per step (vs 27,904 for SHA-256).
# The interleaved permutation σ swaps and shifts the Fp²-coordinate pair.

def _sloth_pp_permute(x: tuple, p: int, c1: int = 1, c2: int = 2) -> tuple:
    """
    Sloth++ permutation σ on Fp²: (a, b) → (b + c1, a + c2) mod p.
    This is the non-arithmetic permutation that prevents the square-root
    shortcut described in the paper footnote 4.
    """
    return ((x[1] + c1) % p, (x[0] + c2) % p)


def sloth_plus_plus_eval(
    x: tuple, p: int, iterations: int, c1: int = 1, c2: int = 2, progress_cb=None
) -> tuple:
    """
    Eval the Sloth++ weak VDF over Fp².
    x must be an (a, b) pair representing a + b·i in Fp².
    p ≡ 3 (mod 4).
    Returns the final (a, b) pair y.
    """
    if p % 4 != 3:
        raise ValueError("Sloth++ requires p ≡ 3 (mod 4)")
    report = max(1, iterations // 100)
    cur = (x[0] % p, x[1] % p)
    for i in range(iterations):
        # σ: coordinate swap with constant shift
        cur = _sloth_pp_permute(cur, p, c1, c2)
        
        # Test if it's a QR in Fp² using the norm
        # Norm in Fp² is simply a² + b²
        norm_val = (cur[0]**2 + cur[1]**2) % p
        if not is_quadratic_residue(norm_val, p):
            # Normalise by negating the element
            cur = ((p - cur[0]) % p, (p - cur[1]) % p)
            
        # ρ: square root in Fp²
        cur = fp2_sqrt(cur, p)
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / iterations))
    if progress_cb:
        progress_cb(100)
    return cur


def sloth_plus_plus_verify(
    x_orig: tuple, y: tuple, p: int, iterations: int, c1: int = 1, c2: int = 2
) -> bool:
    """
    Verify Sloth++: forward-square in Fp² *iterations* times, applying
    the inverse permutation σ⁻¹ at each step.
    Verify cost: 4 Fp-multiplications per step over Fp.
    """
    # Inverse of σ: (a, b) → (b - c2, a - c1) mod p
    def inv_permute(v: tuple) -> tuple:
        return ((v[1] - c2) % p, (v[0] - c1) % p)

    cur = (y[0] % p, y[1] % p)
    for _ in range(iterations):
        # ρ⁻¹: squaring in Fp²
        cur = fp2_mul(cur, cur, p)
        
        # We may have squared a negated element, normalise if needed
        # Check which sign maps back under inv_permute to a valid element
        norm_check = (cur[0]**2 + cur[1]**2) % p
        if cur[1] > p // 2: # use a simple tiebreaker convention like in regular Sloth
             cur = ((p - cur[0]) % p, (p - cur[1]) % p)
             
        # σ⁻¹: inverse permutation
        cur = inv_permute(cur)
        
    # We may still have a sign ambiguity at the very end
    return cur == (x_orig[0] % p, x_orig[1] % p) or cur == ((p - x_orig[0]) % p, (p - x_orig[1]) % p)


# ===========================================================================
# §I  Weak VDF from Injective Rational Maps (§7.2)
# ===========================================================================
# Uses the Guralnick-Muller permutation polynomial.
# Evaluation (inversion): Find y such that f(y) = x mod p. Since f is a
# permutation polynomial, there is exactly one root. We find it by computing
# the roots of F(Y) = f(Y) - x over Fp.
# Verification: simply compute f(y) and check if it equals x.

def _poly_gcd(a: list, b: list, p: int) -> list:
    """Compute GCD of two polynomials over F_p. Polynomials represented as lists of coeffs [c_0, c_1, ..., c_d] for sum c_i x^i."""
    def trim(poly):
        while poly and poly[-1] == 0: poly.pop()
        return poly
    
    a = trim(list(a)); b = trim(list(b))
    while b:
        # Long division a / b
        deg_a = len(a) - 1
        deg_b = len(b) - 1
        curr_a = list(a)
        
        while deg_a >= deg_b and len(curr_a) > 0:
            lead_a = curr_a[-1]
            lead_b = b[-1]
            # mult = lead_a / lead_b mod p
            mult = (lead_a * pow(lead_b, p - 2, p)) % p
            shift = deg_a - deg_b
            
            for i in range(len(b)):
                curr_a[i + shift] = (curr_a[i + shift] - mult * b[i]) % p
            curr_a = trim(curr_a)
            deg_a = len(curr_a) - 1
            
        a = b
        b = curr_a
    
    # Make monic
    if a:
        inv_lead = pow(a[-1], p - 2, p)
        a = [(c * inv_lead) % p for c in a]
    return a

def _find_root_gcd(x: int, a: int, s: int, p: int) -> int:
    """
    Find the unique root y of f(Y) - x = 0 mod p.
    For demonstration, we use a simple brute-force search if p is small,
    or the probabilistic root-finding (Cantor-Zassenhaus split) if p is large.
    For this implementation, since we need to demonstrate the *concept* of the
    GCD inversion described in §7.2, we will use a naive approach for evaluation
    since a full Cantor-Zassenhaus implementation for degree s^3 is extremely complex
    and beyond the scope of a standard Python demo without SymPy/SageMath.
    In a real highly-parallel evaluator, this is done via GCD( Y^p - Y, f(Y) - x ).
    """
    # For demonstration purposes, evaluate the function sequentially to invert it
    # This simulates the "delay" of finding the root.
    for y_cand in range(p):
        if guralnick_muller_poly_eval(y_cand, a, s, p) == x % p:
            return y_cand
    raise ValueError(f"No root found for x={x} mod p={p}. Is f a permutation polynomial?")

def rational_map_eval(x: int, p: int, s: int, a_param: int = 1, progress_cb=None) -> int:
    """
    Evaluate the Rational Map weak VDF.
    Finds y such that Guralnick-Muller f(y) ≡ x (mod p).
    Evaluator needs extensive parallelism (GCD of large polynomials) to do this fast.
    """
    # Simulate the hard inversion
    y = _find_root_gcd(x, a_param, s, p)
    if progress_cb: progress_cb(100)
    return y

def rational_map_verify(x_orig: int, y: int, p: int, s: int, a_param: int = 1) -> bool:
    """
    Verify the Rational Map weak VDF.
    Check if f(y) ≡ x (mod p). Very fast: O(log s) multiplications.
    """
    fx = guralnick_muller_poly_eval(y, a_param, s, p)
    return fx == (x_orig % p)


# ===========================================================================
# §J  Large Prime Product (Exponentiation-Based VDF)
# ===========================================================================
# RSA-based VDF where the delay t is enforced by the product of the first t primes.
# y = g^P mod N where P = ∏_{i=1}^t p_i.
# Evaluation takes O(t log t) multiplications.
# Verification takes very few multiplications if the verifier knows φ(N) or precomputes,
# or we use Wesolowski/Pietrzak proofs over it. Here we use it as a raw puzzle.

def large_prime_product_eval(N: int, g: int, t: int, progress_cb=None) -> int:
    """
    Evaluate y = g^P mod N where P = product of first t odd primes.
    Computed sequentially.
    """
    primes = get_first_t_odd_primes(t)
    report = max(1, t // 100)
    
    cur = g
    for i, p_i in enumerate(primes):
        cur = pow(cur, p_i, N)
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / t))
            
    if progress_cb: progress_cb(100)
    return cur

def large_prime_product_verify(N: int, g: int, y: int, t: int) -> bool:
    """
    Verify the large prime product VDF.
    As a raw time-lock puzzle without SNARKs/Wesolowski, verification is actually O(t).
    To make it a true VDF, this y would be proven using the protocols in §4 or §5.
    For this demo, we just recompute or rely on a trapdoor.
    """
    # Raw verification is just recomputation
    expected_y = large_prime_product_eval(N, g, t)
    return y == expected_y


# ===========================================================================
# §K  Randomness Beacon  (§2 Application)
# ===========================================================================
# A beacon applies a VDF to a public entropy source so that the output
# cannot be predicted before the VDF completes, even by the entropy source.
# The VDF scheme used can be Wesolowski or Pietrzak.

def randomness_beacon(
    entropy_bytes: bytes,
    N: int,
    g: int,
    t: int,
    scheme: str = "wesolowski",
    progress_cb=None,
) -> dict:
    """
    Compute a public randomness beacon value from entropy.

    Protocol (§2):
      1. Derive g from entropy using hash_to_group.
      2. Evaluate VDF: (y, π) = Eval(ek, g).
      3. Beacon value = SHA-256(y).

    Returns dict with keys: beacon_hex, y_hex, pi, scheme, t, N_hex, g_hex.
    """
    # Derive a deterministic generator from public entropy
    g_beacon = hash_to_group(entropy_bytes, N)

    if scheme == "wesolowski":
        y, pi_val, _ = wesolowski_eval_vdf(N, g_beacon, t, progress_cb)
        pi_serialised = hex(pi_val)
    elif scheme == "pietrzak":
        y, pi_list, _ = pietrzak_eval_vdf(N, g_beacon, t, progress_cb)
        pi_serialised = [{"mu": hex(mu), "t": tl} for mu, tl in pi_list]
    else:
        raise ValueError(f"Unknown scheme: {scheme}")

    beacon_value = hashlib.sha256(y.to_bytes((y.bit_length() + 7) // 8, "big")).hexdigest()
    return {
        "beacon_hex": beacon_value,
        "y_hex": hex(y),
        "pi": pi_serialised,
        "scheme": scheme,
        "t": t,
        "N_hex": hex(N),
        "g_beacon_hex": hex(g_beacon),
    }


def verify_randomness_beacon(beacon_dict: dict) -> bool:
    """
    Publicly verify a beacon output.
    Returns True iff the VDF proof is valid and the beacon value matches SHA-256(y).
    """
    N = int(beacon_dict["N_hex"], 16)
    g_beacon = int(beacon_dict["g_beacon_hex"], 16)
    y = int(beacon_dict["y_hex"], 16)
    t = int(beacon_dict["t"])
    scheme = beacon_dict["scheme"]

    if scheme == "wesolowski":
        pi = int(beacon_dict["pi"], 16)
        proof_ok = wesolowski_verify_vdf(N, g_beacon, y, t, pi)
    elif scheme == "pietrzak":
        pi = [(int(e["mu"], 16), int(e["t"])) for e in beacon_dict["pi"]]
        proof_ok = pietrzak_verify_vdf(N, g_beacon, y, t, pi)
    else:
        return False

    if not proof_ok:
        return False
    expected_beacon = hashlib.sha256(y.to_bytes((y.bit_length() + 7) // 8, "big")).hexdigest()
    return expected_beacon == beacon_dict["beacon_hex"]


# ===========================================================================
# §J  Proof of Replication  (§2 Application)
# ===========================================================================
# File blocks are encoded with the VDF using a unique replicator ID.
# The server cannot re-generate the encoding fast enough to fool a verifier.
# Encoding: y_i = Eval(pp, B_i ⊕ H(id || i))
# Verify: decode y_i to get the block and check hash.

def _block_hash(replicator_id: str, block_index: int, block_size: int) -> bytes:
    """H(id || i) — deterministic per-block hash."""
    data = replicator_id.encode() + b"||" + str(block_index).to_bytes(8, "big")
    h = hashlib.sha256(data).digest()
    # Expand to block_size
    while len(h) < block_size:
        h += hashlib.sha256(h).digest()
    return h[:block_size]


def encode_for_replication(
    blocks: list,           # list of bytes objects
    replicator_id: str,
    N: int,
    g: int,                 # unused — g is derived per-block for uniqueness
    t: int,
    scheme: str = "wesolowski",
    progress_cb=None,
) -> list:
    """
    Encode each block B_i as y_i = VDF(B_i ⊕ H(id||i)).
    Returns a list of dicts: {yi_hex, pi, block_index}.
    """
    encoded = []
    for idx, block in enumerate(blocks):
        h_id_i = _block_hash(replicator_id, idx, len(block))
        masked = bytes(b ^ m for b, m in zip(block, h_id_i))
        # Map masked block to a group element
        g_block = hash_to_group(masked, N)

        if scheme == "wesolowski":
            y, pi_val, _ = wesolowski_eval_vdf(N, g_block, t)
            encoded.append({"yi_hex": hex(y), "pi": hex(pi_val), "block_index": idx})
        elif scheme == "pietrzak":
            y, pi_list, _ = pietrzak_eval_vdf(N, g_block, t)
            encoded.append({
                "yi_hex": hex(y),
                "pi": [{"mu": hex(mu), "t": tl} for mu, tl in pi_list],
                "block_index": idx,
            })
        if progress_cb:
            progress_cb(int(100 * (idx + 1) / len(blocks)))

    return encoded


def verify_replication_block(
    yi_hex: str,
    Bi: bytes,
    pi,
    replicator_id: str,
    block_index: int,
    N: int,
    t: int,
    scheme: str = "wesolowski",
) -> bool:
    """
    Verify that the encoded block yi is the VDF of B_i ⊕ H(id||i).
    Uses public verifiability — no private key needed.
    """
    h_id_i = _block_hash(replicator_id, block_index, len(Bi))
    masked = bytes(b ^ m for b, m in zip(Bi, h_id_i))
    g_block = hash_to_group(masked, N)
    y = int(yi_hex, 16)

    if scheme == "wesolowski":
        pi_int = int(pi, 16)
        return wesolowski_verify_vdf(N, g_block, y, t, pi_int)
    elif scheme == "pietrzak":
        pi_list = [(int(e["mu"], 16), int(e["t"])) for e in pi]
        return pietrzak_verify_vdf(N, g_block, y, t, pi_list)
    return False


# ===========================================================================
# §K  High-level exam system wrappers (for backend.py compatibility)
# ===========================================================================

def generate_vdf_puzzle_with_trapdoor(key: bytes, t: int, bits: int = 2048) -> dict:
    """
    Generate VDF parameters and instantly lock *key* using the RSA trapdoor.
    The trusted setup party (server) can set puzzle parameters without waiting t seconds.

    Returns the puzzle dict: {N, g, t, locked_key, bits, scheme}.
    """
    half = bits // 2
    p = _gen_prime(half)
    q = _gen_prime(half)
    while q == p:
        q = _gen_prime(half)
    N = p * q
    phi = (p - 1) * (q - 1)
    g = secrets.randbelow(N - 2) + 2

    # Trapdoor: y = g^(2^t) mod N computed instantly via y = g^(2^t mod φ(N)) mod N
    e = pow(2, t, phi)
    y = pow(g, e, N)

    # Lock the AES key: locked_key = key XOR SHA-256(y)
    mask = hashlib.sha256(y.to_bytes((y.bit_length() + 7) // 8, "big")).digest()
    locked_key = bytes(a ^ b for a, b in zip(key, mask[: len(key)]))

    return {
        "N": hex(N),
        "g": hex(g),
        "t": t,
        "locked_key": locked_key.hex(),
        "bits": bits,
        "scheme": "wesolowski",  # default scheme for solving
    }


def eval_vdf(N: int, g: int, t: int, progress_cb=None, scheme: str = "wesolowski") -> tuple:
    """
    Unified Eval dispatcher — delegates to the selected VDF scheme.
    Returns (y, pi, mask) for compatibility with backend.py.
    """
    if scheme == "wesolowski":
        return wesolowski_eval_vdf(N, g, t, progress_cb)
    elif scheme == "pietrzak":
        return pietrzak_eval_vdf(N, g, t, progress_cb)
    elif scheme == "large_prime":
        y = large_prime_product_eval(N, g, t, progress_cb)
        return (y, None, hashlib.sha256(y.to_bytes((y.bit_length() + 7) // 8, "big")).digest())
    else:
        raise ValueError(f"Unknown scheme: {scheme}")


def verify_vdf(N: int, g: int, y: int, t: int, pi, scheme: str = "wesolowski") -> bool:
    """
    Unified Verify dispatcher — delegates to the selected VDF scheme.
    """
    if scheme == "wesolowski":
        if isinstance(pi, str):
            pi = int(pi, 16)
        elif isinstance(pi, list) and len(pi) == 1 and isinstance(pi[0], str):
            pi = int(pi[0], 16)
        return wesolowski_verify_vdf(N, g, y, t, pi)
    elif scheme == "pietrzak":
        if isinstance(pi, list) and pi and isinstance(pi[0], dict):
            pi = [(int(e["mu"], 16), int(e["t"])) for e in pi]
        return pietrzak_verify_vdf(N, g, y, t, pi)
    elif scheme == "large_prime":
        return large_prime_product_verify(N, g, y, t)
    else:
        raise ValueError(f"Unknown scheme: {scheme}")
