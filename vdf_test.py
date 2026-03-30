"""
vdf_test.py — Automated correctness tests for all VDF constructions
from Boneh, Bonneau, Bünz, Fisch (2019).

Run from d:\\CSS with venv activated:
    python vdf_test.py

Expected output: all tests print PASS.
"""

import sys
import hashlib
import secrets

# ── make sure we import from the project directory ──
sys.path.insert(0, ".")

from math_utils import (
    mod_sqrt, is_quadratic_residue, sloth_permute,
    fp2_mul, fp2_sqrt, fp2_pow,
    hash_to_group, _gen_prime, _gen_prime_cong,
)
from crypto_utils import (
    generate_vdf_setup,
    # Wesolowski
    wesolowski_eval_vdf, wesolowski_verify_vdf,
    # Pietrzak
    pietrzak_eval_vdf, pietrzak_verify_vdf,
    # Hash chain
    hash_chain_eval, hash_chain_verify,
    # Sloth
    sloth_eval, sloth_verify,
    # Sloth++
    sloth_plus_plus_eval, sloth_plus_plus_verify,
    # Rational Maps
    rational_map_eval, rational_map_verify,
    # Large prime product
    large_prime_product_eval, large_prime_product_verify,
    # Beacon
    randomness_beacon, verify_randomness_beacon,
    # Replication
    encode_for_replication, verify_replication_block,
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
failures = []


def check(name: str, condition: bool, extra: str = ""):
    status = PASS if condition else FAIL
    print(f"  [{status}] {name}" + (f"  ({extra})" if extra else ""))
    if not condition:
        failures.append(name)


# ============================================================
# 1. Math utilities
# ============================================================
print("\n─── 1. Math utilities ───")

# 1a. Miller-Rabin on known primes / composites
from math_utils import _miller_rabin
check("Miller-Rabin: 7 is prime",  _miller_rabin(7))
check("Miller-Rabin: 15 not prime", not _miller_rabin(15))

# 1b. Modular square root (p ≡ 3 mod 4)
p_sloth = _gen_prime_cong(128, 3, 4)
x_qr = secrets.randbelow(p_sloth - 1) + 1
# Ensure x is a QR
x_qr = pow(secrets.randbelow(p_sloth - 1) + 1, 2, p_sloth)
y_sqrt = mod_sqrt(x_qr, p_sloth)
check("mod_sqrt: y² ≡ x (mod p)", pow(y_sqrt, 2, p_sloth) == x_qr)

# 1c. Quadratic residue test
check("is_quadratic_residue correct", is_quadratic_residue(x_qr, p_sloth))
non_qr = p_sloth - x_qr  # -x is a non-QR when x is QR (for p≡3 mod 4)
check("is_quadratic_residue: non-QR detected", not is_quadratic_residue(non_qr, p_sloth))

# 1d. Fp² multiplication closure
a_fp2 = (3, 5)
b_fp2 = (7, 11)
c = fp2_mul(a_fp2, b_fp2, p_sloth)
check("fp2_mul returns tuple", isinstance(c, tuple) and len(c) == 2)

# 1e. Fp² square root round-trip — use a guaranteed perfect square
rand_elem = (secrets.randbelow(p_sloth - 1) + 1, secrets.randbelow(p_sloth - 1) + 1)
elem2 = fp2_mul(rand_elem, rand_elem, p_sloth)  # rand_elem² is always a perfect square
sqrt_e2 = fp2_sqrt(elem2, p_sloth)
check("fp2_sqrt round-trip", fp2_mul(sqrt_e2, sqrt_e2, p_sloth) == (elem2[0] % p_sloth, elem2[1] % p_sloth))

# 1f. hash_to_group
N_test, g_test = generate_vdf_setup(512)
g_derived = hash_to_group(b"test_entropy", N_test)
check("hash_to_group in range", 2 <= g_derived < N_test)
check("hash_to_group deterministic",
      g_derived == hash_to_group(b"test_entropy", N_test))

# ============================================================
# 2. Wesolowski VDF  (§5)
# ============================================================
print("\n─── 2. Wesolowski VDF (§5 VDFVC) ───")

N_w, g_w = generate_vdf_setup(512)
t_w = 500

y_w, pi_w, mask_w = wesolowski_eval_vdf(N_w, g_w, t_w)
print(f"    eval: y = {hex(y_w)[:18]}…   π = {hex(pi_w)[:18]}…")
check("Wesolowski: verify correct output", wesolowski_verify_vdf(N_w, g_w, y_w, t_w, pi_w))

# Tamper with y
check("Wesolowski: rejects wrong y",
      not wesolowski_verify_vdf(N_w, g_w, (y_w + 1) % N_w, t_w, pi_w))

# Tamper with pi
check("Wesolowski: rejects wrong π",
      not wesolowski_verify_vdf(N_w, g_w, y_w, t_w, (pi_w + 1) % N_w))

# ============================================================
# 3. Pietrzak VDF  (§4)
# ============================================================
print("\n─── 3. Pietrzak VDF (§4 VDFIVC) ───")

N_p, g_p = generate_vdf_setup(512)
t_p = 256  # power-of-2 for clean recursion

y_p, pi_p, mask_p = pietrzak_eval_vdf(N_p, g_p, t_p)
print(f"    eval: y = {hex(y_p)[:18]}…   proof levels = {len(pi_p)}")
check("Pietrzak: verify correct output", pietrzak_verify_vdf(N_p, g_p, y_p, t_p, pi_p))
check("Pietrzak: proof has log(t) levels", len(pi_p) <= t_p.bit_length())

# Tamper
check("Pietrzak: rejects wrong y",
      not pietrzak_verify_vdf(N_p, g_p, (y_p + 1) % N_p, t_p, pi_p))

# ============================================================
# 4. Hash-Chain Sequential Function  (§3 Definition 6/7)
# ============================================================
print("\n─── 4. Hash-Chain Sequential Function (§3 Def 6/7 baseline) ───")

x_hc = hashlib.sha256(b"exam_challenge").hexdigest()
t_hc = 500
y_hc, ckpts = hash_chain_eval(x_hc, t_hc)
print(f"    eval: y = {y_hc[:18]}…  checkpoints = {len(ckpts)}")
check("Hash chain: verify with checkpoints", hash_chain_verify(x_hc, y_hc, t_hc, ckpts))
check("Hash chain: rejects wrong y",
      not hash_chain_verify(x_hc, y_hc[:-2] + "ff", t_hc, ckpts))

# ============================================================
# 5. Sloth Weak VDF  (§7.1)
# ============================================================
print("\n─── 5. Sloth Weak VDF (§7.1) ───")

p_s = _gen_prime_cong(128, 3, 4)
x_s = secrets.randbelow(p_s - 1) + 1
iters_s = 50

y_s = sloth_eval(x_s, p_s, iters_s)
print(f"    eval: y = {hex(y_s)[:18]}…")
check("Sloth: verify by forward squaring", sloth_verify(x_s, y_s, p_s, iters_s))

# Wrong y
y_bad = (y_s + 1) % p_s
check("Sloth: rejects wrong y", not sloth_verify(x_s, y_bad, p_s, iters_s))

# ============================================================
# 6. Sloth++  (§7.1 extension over Fp²)
# ============================================================
print("\n─── 6. Sloth++ (§7.1, Fp² extension — 7000× fewer SNARK gates) ───")

p_pp = _gen_prime_cong(128, 3, 4)
x_pp = (secrets.randbelow(p_pp - 1) + 1, secrets.randbelow(p_pp - 1) + 1)
iters_pp = 20

y_pp = sloth_plus_plus_eval(x_pp, p_pp, iters_pp)
print(f"    eval: y = ({hex(y_pp[0])[:12]}…, {hex(y_pp[1])[:12]}…)")
check("Sloth++: verify by forward squaring in Fp²", sloth_plus_plus_verify(x_pp, y_pp, p_pp, iters_pp))

y_pp_bad = ((y_pp[0] + 1) % p_pp, y_pp[1])
check("Sloth++: rejects wrong y", not sloth_plus_plus_verify(x_pp, y_pp_bad, p_pp, iters_pp))

# ============================================================
# 7. Rational Maps Weak VDF (§7.2)
# ============================================================
print("\n─── 7. Injective Rational Maps (§7.2) ───")

p_rm = 2027 # small prime ≡ 3 mod 4
s_rm = 3
a_rm = 1
x_rm = secrets.randbelow(p_rm - 1) + 1

y_rm = rational_map_eval(x_rm, p_rm, s_rm, a_rm)
print(f"    eval: y = {y_rm}")
check("Rational Maps: verify evaluates correct", rational_map_verify(x_rm, y_rm, p_rm, s_rm, a_rm))
check("Rational Maps: rejects wrong y", not rational_map_verify(x_rm, (y_rm + 1) % p_rm, p_rm, s_rm, a_rm))

# ============================================================
# 8. Large Prime Product VDF
# ============================================================
print("\n─── 8. Large Prime Product VDF ───")

N_lp, g_lp = generate_vdf_setup(512)
t_lp = 20  # first 20 primes

y_lp = large_prime_product_eval(N_lp, g_lp, t_lp)
print(f"    eval: y = {hex(y_lp)[:18]}...")
check("Large Prime: verify correct", large_prime_product_verify(N_lp, g_lp, y_lp, t_lp))
check("Large Prime: rejects tampered output", not large_prime_product_verify(N_lp, g_lp, (y_lp + 1) % N_lp, t_lp))

# ============================================================
# 9. Randomness Beacon  (§2 Application)
# ============================================================
print("\n─── 7. Randomness Beacon (§2) ───")

N_b, g_b = generate_vdf_setup(512)
entropy = b"bitcoin_block_hash_12345"
t_b = 300

# Wesolowski beacon
beacon_w = randomness_beacon(entropy, N_b, g_b, t_b, scheme="wesolowski")
print(f"    beacon (Weso): {beacon_w['beacon_hex'][:20]}…")
check("Beacon Wesolowski: verify passes", verify_randomness_beacon(beacon_w))
check("Beacon Wesolowski: deterministic for same entropy+params",
      randomness_beacon(entropy, N_b, g_b, t_b, scheme="wesolowski")["beacon_hex"]
      == beacon_w["beacon_hex"])
# Tamper
tampered = dict(beacon_w, beacon_hex="00" * 32)
check("Beacon: rejects tampered beacon_hex", not verify_randomness_beacon(tampered))

# Pietrzak beacon
beacon_p = randomness_beacon(entropy, N_b, g_b, t_b, scheme="pietrzak")
print(f"    beacon (Pietz): {beacon_p['beacon_hex'][:20]}…")
check("Beacon Pietrzak: verify passes", verify_randomness_beacon(beacon_p))

# ============================================================
# 8. Proof of Replication  (§2 Application)
# ============================================================
print("\n─── 8. Proof of Replication (§2) ───")

N_r, g_r = generate_vdf_setup(512)
t_r = 200
rep_id = "replicator-node-007"
blocks = [secrets.token_bytes(32) for _ in range(3)]  # 3 blocks of 32 bytes

encoded = encode_for_replication(blocks, rep_id, N_r, g_r, t_r, scheme="wesolowski")
print(f"    encoded {len(encoded)} blocks")

# Spot-check block 1
entry = encoded[1]
bi_idx = entry["block_index"]
check("Replication: spot-verify block 1",
      verify_replication_block(
          entry["yi_hex"], blocks[bi_idx], entry["pi"],
          rep_id, bi_idx, N_r, t_r, scheme="wesolowski"
      ))
# Wrong block data
check("Replication: rejects wrong block content",
      not verify_replication_block(
          entry["yi_hex"], secrets.token_bytes(32), entry["pi"],
          rep_id, bi_idx, N_r, t_r, scheme="wesolowski"
      ))

# ============================================================
# Summary
# ============================================================
print("\n" + "═" * 50)
if failures:
    print(f"  {FAIL}  {len(failures)} test(s) failed:")
    for f in failures:
        print(f"    • {f}")
    sys.exit(1)
else:
    total = 26   # total check() calls above
    print(f"  {PASS}  All tests passed! ({total} assertions)")
print("═" * 50 + "\n")
