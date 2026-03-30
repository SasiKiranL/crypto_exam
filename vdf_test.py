"""
vdf_test.py - Automated correctness tests for the CryptoExam demo.

Run:
    python vdf_test.py

The output is ASCII-only so it works cleanly on Windows terminals.
"""

import sys
import time
import hashlib
import secrets

sys.path.insert(0, ".")

from math_utils import (
    mod_sqrt,
    is_quadratic_residue,
    fp2_mul,
    fp2_sqrt,
    hash_to_group,
    _gen_prime_cong,
    guralnick_muller_poly_eval,
)
from crypto_utils import (
    generate_vdf_setup,
    wesolowski_eval_vdf,
    wesolowski_verify_vdf,
    pietrzak_eval_vdf,
    pietrzak_verify_vdf,
    hash_chain_eval,
    hash_chain_verify,
    sloth_eval,
    sloth_verify,
    sloth_plus_plus_eval,
    sloth_plus_plus_verify,
    rational_map_eval,
    rational_map_verify,
    large_prime_product_eval,
    large_prime_product_verify,
    randomness_beacon,
    verify_randomness_beacon,
    encode_for_replication,
    verify_replication_block,
)
from backend import app


PASS = "PASS"
FAIL = "FAIL"
failures = []


def check(name: str, condition: bool, extra: str = ""):
    status = PASS if condition else FAIL
    suffix = f" ({extra})" if extra else ""
    print(f"  [{status}] {name}{suffix}")
    if not condition:
        failures.append(name)


def section(title: str):
    print(f"\n--- {title} ---")


def poll_exam_progress(client, exam_id: str, access_token: str, timeout_s: float = 5.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp = client.get(
            "/api/progress",
            query_string={"exam_id": exam_id, "access_token": access_token},
        )
        data = resp.get_json()
        if data.get("status") in {"done", "error"}:
            return resp.status_code, data
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for exam {exam_id}")


def poll_proof_progress(client, exam_id: str, access_token: str, timeout_s: float = 5.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp = client.get(
            "/api/progress",
            query_string={"exam_id": exam_id, "access_token": access_token},
        )
        data = resp.get_json()
        if data.get("proof_status") in {"done", "error"}:
            return resp.status_code, data
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for proof on exam {exam_id}")


section("1. Math utilities")

p_sloth = _gen_prime_cong(128, 3, 4)
x_qr = pow(secrets.randbelow(p_sloth - 1) + 1, 2, p_sloth)
y_sqrt = mod_sqrt(x_qr, p_sloth)
check("mod_sqrt round-trip", pow(y_sqrt, 2, p_sloth) == x_qr)
check("quadratic residue detects square", is_quadratic_residue(x_qr, p_sloth))
check("fp2_mul returns a pair", len(fp2_mul((3, 5), (7, 11), p_sloth)) == 2)

rand_elem = (secrets.randbelow(p_sloth - 1) + 1, secrets.randbelow(p_sloth - 1) + 1)
elem_square = fp2_mul(rand_elem, rand_elem, p_sloth)
sqrt_elem = fp2_sqrt(elem_square, p_sloth)
check("fp2_sqrt round-trip on perfect square", fp2_mul(sqrt_elem, sqrt_elem, p_sloth) == elem_square)

N_test, _ = generate_vdf_setup(512)
g_derived = hash_to_group(b"test_entropy", N_test)
check("hash_to_group in range", 2 <= g_derived < N_test)
check("hash_to_group deterministic", g_derived == hash_to_group(b"test_entropy", N_test))


section("2. Wesolowski VDF")

N_w, g_w = generate_vdf_setup(512)
t_w = 500
y_w, pi_w, _ = wesolowski_eval_vdf(N_w, g_w, t_w)
check("Wesolowski verify passes", wesolowski_verify_vdf(N_w, g_w, y_w, t_w, pi_w))
check("Wesolowski rejects tampered y", not wesolowski_verify_vdf(N_w, g_w, (y_w + 1) % N_w, t_w, pi_w))


section("3. Pietrzak VDF")

N_p, g_p = generate_vdf_setup(512)
t_p = 256
y_p, pi_p, _ = pietrzak_eval_vdf(N_p, g_p, t_p)
check("Pietrzak verify passes for power-of-two t", pietrzak_verify_vdf(N_p, g_p, y_p, t_p, pi_p))
check("Pietrzak proof depth is logarithmic", len(pi_p) <= t_p.bit_length())

try:
    pietrzak_eval_vdf(N_p, g_p, 3)
except ValueError:
    check("Pietrzak rejects non-power-of-two t", True)
else:
    check("Pietrzak rejects non-power-of-two t", False)


section("4. Hash chain")

x_hc = hashlib.sha256(b"exam_challenge").hexdigest()
t_hc = 500
y_hc, ckpts = hash_chain_eval(x_hc, t_hc)
check("Hash chain verify passes", hash_chain_verify(x_hc, y_hc, t_hc, ckpts))
check("Hash chain rejects wrong y", not hash_chain_verify(x_hc, y_hc[:-2] + "ff", t_hc, ckpts))


section("5. Sloth weak VDF")

p_s = _gen_prime_cong(128, 3, 4)
sloth_ok = True
for iterations in (1, 2, 3, 5, 8):
    for _ in range(10):
        x_s = secrets.randbelow(p_s - 1) + 1
        y_s = sloth_eval(x_s, p_s, iterations)
        sloth_ok = sloth_ok and sloth_verify(x_s, y_s, p_s, iterations)
check("Sloth verify matches deterministic eval", sloth_ok)

x_s = secrets.randbelow(p_s - 1) + 1
y_s = sloth_eval(x_s, p_s, 4)
check("Sloth rejects wrong y", not sloth_verify(x_s, (y_s + 1) % p_s, p_s, 4))


section("6. Sloth++ weak VDF")

p_pp = _gen_prime_cong(128, 3, 4)
sloth_pp_ok = True
for iterations in (1, 3, 5):
    for _ in range(8):
        x_pp = (secrets.randbelow(p_pp - 1) + 1, secrets.randbelow(p_pp - 1) + 1)
        y_pp = sloth_plus_plus_eval(x_pp, p_pp, iterations)
        sloth_pp_ok = sloth_pp_ok and sloth_plus_plus_verify(x_pp, y_pp, p_pp, iterations)
check("Sloth++ eval/verify stay aligned", sloth_pp_ok)

x_pp = (secrets.randbelow(p_pp - 1) + 1, secrets.randbelow(p_pp - 1) + 1)
y_pp = sloth_plus_plus_eval(x_pp, p_pp, 4)
y_pp_bad = ((y_pp[0] + 1) % p_pp, y_pp[1])
check("Sloth++ rejects wrong y", not sloth_plus_plus_verify(x_pp, y_pp_bad, p_pp, 4))


section("7. Rational maps")

p_rm = 2027
s_rm = 3
a_rm = 1
y_seed = secrets.randbelow(p_rm - 1) + 1
x_rm = guralnick_muller_poly_eval(y_seed, a_rm, s_rm, p_rm)
y_rm = rational_map_eval(x_rm, p_rm, s_rm, a_rm)
check("Rational map verify passes", rational_map_verify(x_rm, y_rm, p_rm, s_rm, a_rm))
check("Rational map rejects wrong y", not rational_map_verify(x_rm, (y_rm + 1) % p_rm, p_rm, s_rm, a_rm))


section("8. Large prime product")

N_lp, g_lp = generate_vdf_setup(512)
t_lp = 20
y_lp = large_prime_product_eval(N_lp, g_lp, t_lp)
check("Large prime product verify passes", large_prime_product_verify(N_lp, g_lp, y_lp, t_lp))
check("Large prime product rejects tampered output", not large_prime_product_verify(N_lp, g_lp, (y_lp + 1) % N_lp, t_lp))


section("9. Randomness beacon")

N_b, g_b = generate_vdf_setup(512)
entropy = b"bitcoin_block_hash_12345"
t_b = 300
beacon_w = randomness_beacon(entropy, N_b, g_b, t_b, scheme="wesolowski")
check("Beacon Wesolowski verify passes", verify_randomness_beacon(beacon_w))

beacon_p = randomness_beacon(entropy, N_b, g_b, 256, scheme="pietrzak")
check("Beacon Pietrzak verify passes", verify_randomness_beacon(beacon_p))

tampered = dict(beacon_w, beacon_hex="00" * 32)
check("Beacon rejects tampered output", not verify_randomness_beacon(tampered))


section("10. Proof of replication")

N_r, g_r = generate_vdf_setup(512)
t_r = 200
rep_id = "replicator-node-007"
blocks = [secrets.token_bytes(32) for _ in range(3)]
encoded = encode_for_replication(blocks, rep_id, N_r, g_r, t_r, scheme="wesolowski")
entry = encoded[1]
idx = entry["block_index"]
check(
    "Replication block verifies",
    verify_replication_block(entry["yi_hex"], blocks[idx], entry["pi"], rep_id, idx, N_r, t_r, scheme="wesolowski"),
)
check(
    "Replication rejects wrong block data",
    not verify_replication_block(entry["yi_hex"], secrets.token_bytes(32), entry["pi"], rep_id, idx, N_r, t_r, scheme="wesolowski"),
)


section("11. Backend exam isolation")

client = app.test_client()
enc1 = client.post("/api/encrypt", json={"exam_text": "exam A", "t_squarings": 4, "bits": 256, "scheme": "wesolowski"}).get_json()
enc2 = client.post("/api/encrypt", json={"exam_text": "exam B", "t_squarings": 4, "bits": 256, "scheme": "wesolowski"}).get_json()

check("Backend returns distinct exam ids", enc1["exam_id"] != enc2["exam_id"])
check("Backend returns distinct access tokens", enc1["access_token"] != enc2["access_token"])

bad_progress = client.get(
    "/api/progress",
    query_string={"exam_id": enc1["exam_id"], "access_token": enc2["access_token"]},
)
check("Progress rejects wrong token", bad_progress.status_code == 403)

audit1 = client.get("/api/audit", query_string={"exam_id": enc1["exam_id"]}).get_json()
audit2 = client.get("/api/audit", query_string={"exam_id": enc2["exam_id"]}).get_json()
check("Audit is namespaced per exam", audit1["exam_id"] == enc1["exam_id"] and audit2["exam_id"] == enc2["exam_id"])

solve1 = client.post(
    "/api/solve",
    json={"exam_id": enc1["exam_id"], "access_token": enc1["access_token"]},
)
check("Solve starts for exam 1", solve1.status_code == 200)
status_code_1, progress1 = poll_exam_progress(client, enc1["exam_id"], enc1["access_token"])
check("Exam 1 solve completes", status_code_1 == 200 and progress1["status"] == "done")
check("Exam 1 decrypts its own plaintext", progress1["decrypted_text"] == "exam A")

idle_progress = client.get(
    "/api/progress",
    query_string={"exam_id": enc2["exam_id"], "access_token": enc2["access_token"]},
)
check("Exam 2 remains idle until solved", idle_progress.status_code == 200 and idle_progress.get_json()["status"] == "idle")

solve2 = client.post(
    "/api/solve",
    json={"exam_id": enc2["exam_id"], "access_token": enc2["access_token"]},
)
check("Solve starts for exam 2", solve2.status_code == 200)
_, progress2_done = poll_exam_progress(client, enc2["exam_id"], enc2["access_token"])
check("Exam 2 decrypts its own plaintext", progress2_done["decrypted_text"] == "exam B")

proof_start = client.post(
    "/api/generate_proof",
    json={"exam_id": enc1["exam_id"], "access_token": enc1["access_token"]},
)
check("Proof generation starts for solved exam", proof_start.status_code == 200)
_, proof_done = poll_proof_progress(client, enc1["exam_id"], enc1["access_token"])
check("Proof generation completes", proof_done["proof_status"] == "done" and len(proof_done["vdf_proof"]) > 0)

verify_resp = client.post(
    "/api/verify_vdf",
    json={
        "N": enc1["puzzle_public"]["N_hex"],
        "g": enc1["puzzle_public"]["g_hex"],
        "y": proof_done["y_hex"],
        "t": enc1["puzzle_public"]["t"],
        "scheme": enc1["puzzle_public"]["scheme"],
        "pi": proof_done["vdf_proof"],
    },
)
verify_data = verify_resp.get_json()
check("Generated proof verifies publicly", verify_resp.status_code == 200 and verify_data["is_valid"])


print("\n" + "=" * 50)
if failures:
    print(f"  [{FAIL}] {len(failures)} test(s) failed:")
    for failure in failures:
        print(f"    - {failure}")
    sys.exit(1)
else:
    print("  [PASS] All tests passed.")
print("=" * 50)
