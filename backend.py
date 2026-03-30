"""
backend.py — Time-Locked Exam Distribution System (True VDF — Full Paper Implementation)

Implements all constructions from Boneh, Bonneau, Bünz, Fisch (2019):
  - Pietrzak VDF  (§4)
  - Wesolowski VDF (§5) [default]
  - Hash-Chain baseline (§3 Def 6/7)
  - Sloth weak VDF  (§7.1)
  - Sloth++ weak VDF (§7.1)
  - Randomness Beacon (§2)
  - Proof of Replication (§2)

Run:  python backend.py
URL:  http://localhost:5050
"""

import os, json, time, hashlib, secrets, threading, base64
from datetime import datetime, timezone
from typing import Any, Dict
from flask import Flask, jsonify, request, make_response, send_file
import io

from math_utils import _gen_prime
from crypto_utils import (
    aes_encrypt,
    aes_decrypt,
    eval_vdf,
    verify_vdf,
    generate_vdf_puzzle_with_trapdoor,
    # Wesolowski
    generate_vdf_setup,
    wesolowski_eval_vdf,
    wesolowski_verify_vdf,
    # Pietrzak
    pietrzak_eval_vdf,
    pietrzak_verify_vdf,
    # Hash chain
    hash_chain_eval,
    hash_chain_verify,
    # Sloth
    sloth_eval,
    sloth_verify,
    # Sloth++
    sloth_plus_plus_eval,
    sloth_plus_plus_verify,
    # Rational Maps
    rational_map_eval,
    rational_map_verify,
    # Large Prime
    large_prime_product_eval,
    large_prime_product_verify,
    # Beacon & replication
    randomness_beacon,
    verify_randomness_beacon,
    encode_for_replication,
    verify_replication_block,
)
from audit import AuditLog

app   = Flask(__name__)
STATE = {}
AUDIT = AuditLog()

# Measured once at startup
SQUARING_TIME_S = None


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

@app.after_request
def add_cors(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Requested-With"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r

@app.route("/", defaults={"p": ""}, methods=["OPTIONS"])
@app.route("/<path:p>", methods=["OPTIONS"])
def _options(p):
    return make_response("", 204)


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def _run_benchmark():
    global SQUARING_TIME_S
    print("  ⏱  Benchmarking CPU squaring speed…", end=" ", flush=True)
    p = _gen_prime(256); q = _gen_prime(256)
    n = p * q
    x = secrets.randbelow(n - 2) + 2
    for _ in range(500):
        x = (x * x) % n
    MEASURE = 3000
    t0 = time.perf_counter()
    for _ in range(MEASURE):
        x = (x * x) % n
    SQUARING_TIME_S = (time.perf_counter() - t0) / MEASURE
    print(f"{int(1/SQUARING_TIME_S):,} squarings/sec  ({SQUARING_TIME_S*1e6:.1f} µs each)")


@app.route("/api/benchmark")
def api_benchmark():
    if SQUARING_TIME_S is None:
        return jsonify({"error": "Benchmark not ready"}), 503
    return jsonify({
        "squaring_time_s": SQUARING_TIME_S,
        "squarings_per_sec": int(1 / SQUARING_TIME_S),
    })


# ---------------------------------------------------------------------------
# Compute t
# ---------------------------------------------------------------------------

@app.route("/api/compute-t", methods=["POST"])
def api_compute_t():
    data = request.json or {}
    unlock_ts = data.get("unlock_timestamp")
    if not unlock_ts:
        return jsonify({"error": "unlock_timestamp required"}), 400
    if SQUARING_TIME_S is None:
        return jsonify({"error": "Benchmark not ready"}), 503
    unlock_dt = datetime.fromisoformat(unlock_ts.replace("Z", "+00:00"))
    if unlock_dt.tzinfo is None:
        unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)
    demo_mode = bool(data.get("demo_mode", False))
    gap_s = (unlock_dt - datetime.now(timezone.utc)).total_seconds()
    if gap_s <= 0:
        return jsonify({"error": "Unlock time must be in the future"}), 400
    real_t = max(1000, int(gap_s / SQUARING_TIME_S))
    t = 5000 if demo_mode else real_t

    def fmt(s):
        s = int(s)
        if s < 60:  return f"{s}s"
        if s < 3600: return f"{s//60}m {s%60}s"
        return f"{s//3600}h {(s%3600)//60}m"

    return jsonify({
        "gap_seconds": round(gap_s, 1),
        "gap_human": fmt(gap_s),
        "t_squarings": t,
        "real_t": real_t,
        "demo_mode": demo_mode,
        "squarings_per_sec": int(1 / SQUARING_TIME_S),
        "estimated_solve_s": round(t * SQUARING_TIME_S, 1),
    })


# ---------------------------------------------------------------------------
# Scheme listing
# ---------------------------------------------------------------------------

@app.route("/api/schemes")
def api_schemes():
    """List all available VDF schemes and their paper references."""
    return jsonify({
        "schemes": [
            {
                "id": "wesolowski",
                "name": "Wesolowski VDF",
                "paper_section": "§5 (VDFVC)",
                "proof_size": "O(1) — single group element",
                "verify_time": "O(log t) — 2 modular exponentiations",
                "description": "Tight VDF based on RSA group. Single-element proof π, "
                               "verified with π^ℓ · g^r ≡ y (mod N)."
            },
            {
                "id": "pietrzak",
                "name": "Pietrzak VDF",
                "paper_section": "§4 (VDFIVC)",
                "proof_size": "O(log t) — one element per halving level",
                "verify_time": "O(log t) — one exponentiation per level",
                "description": "Recursive halving proof based on RSA group. "
                               "Each level proves the midpoint μ = g^(2^(t/2))."
            },
            {
                "id": "hash_chain",
                "name": "Hash-Chain Sequential Function",
                "paper_section": "§3 Definition 6/7",
                "proof_size": "O(t) — full recompute or O(t/l) with checkpoints",
                "verify_time": "O(t) — NOT polylog; not a full VDF",
                "description": "Baseline: iterated SHA-256. No fast verify per §3 remark. "
                               "Demonstrates why efficient verification is non-trivial."
            },
            {
                "id": "sloth",
                "name": "Sloth Weak VDF",
                "paper_section": "§7.1",
                "proof_size": "None (decodable)",
                "verify_time": "O(iterations) multiplications",
                "description": "Iterated modular square roots mod p. Verify by squaring. "
                               "Weak VDF per Definition 5 (requires O(t) parallelism)."
            },
            {
                "id": "sloth_plus_plus",
                "name": "Sloth++ Weak VDF",
                "paper_section": "§7.1 (extension)",
                "proof_size": "None (decodable)",
                "verify_time": "Only 4 Fp-gates per step (7,000× improvement over SHA-256)",
                "description": "Sloth over Fp² extension field. Dramatically reduces SNARK "
                               "verification circuit size when used as inner function for IVC."
            },
            {
                "id": "rational_map",
                "name": "Injective Rational Map VDF",
                "paper_section": "§7.2",
                "proof_size": "None (decodable)",
                "verify_time": "O(log s) multiplications",
                "description": "Weak VDF using the Guralnick-Muller s³ permutation polynomial. "
                               "Evaluation requires finding roots over Fp (e.g. via GCD). "
                               "Verification simply evaluates the polynomial."
            },
            {
                "id": "large_prime",
                "name": "Large Prime Product VDF",
                "paper_section": "None (RSA Exponentiation)",
                "proof_size": "None (raw puzzle)",
                "verify_time": "O(t) without SNARKs/proofs",
                "description": "RSA-based VDF where delay is enforced by product of first t odd primes. "
                               "Can be made tight using Wesolowski/Pietrzak proofs."
            },
        ]
    })


# ---------------------------------------------------------------------------
# Exam encrypt / solve / verify (Wesolowski or Pietrzak)
# ---------------------------------------------------------------------------

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt exam content (text, PDF, or image) with AES-256-GCM + VDF time-lock.

    Accepts two content modes:
    - multipart/form-data: 'file' field (PDF/image), plus 'mime_type', 't_squarings', 'bits', 'scheme'
    - application/json:    {exam_text, t_squarings, bits, scheme}
    """
    global AUDIT, STATE

    # ── Detect input mode ────────────────────────────────────────────────────
    if request.content_type and "multipart/form-data" in request.content_type:
        # File upload path
        file_obj  = request.files.get("file")
        if not file_obj:
            return jsonify({"error": "No file uploaded"}), 400
        raw_bytes = file_obj.read()
        mime_type = request.form.get("mime_type") or file_obj.mimetype or "application/octet-stream"
        filename  = file_obj.filename or "exam_file"
        t         = int(request.form.get("t_squarings", 3000))
        bits      = int(request.form.get("bits", 1024))
        scheme    = request.form.get("scheme", "wesolowski")
        # Label used when displaying file size etc.
        content_label = f"{filename} ({len(raw_bytes):,} bytes)"
    else:
        # Plain-text JSON path (backward-compatible)
        data      = request.json or {}
        text      = data.get("exam_text", "")
        if not text:
            return jsonify({"error": "exam_text required"}), 400
        raw_bytes = text.encode("utf-8")
        mime_type = "text/plain"
        filename  = "exam.txt"
        t         = int(data.get("t_squarings", 3000))
        bits      = int(data.get("bits", 1024))
        scheme    = data.get("scheme", "wesolowski")
        content_label = f"{len(raw_bytes):,} bytes"

    if not raw_bytes:
        return jsonify({"error": "Empty content"}), 400
    if scheme not in ("wesolowski", "pietrzak"):
        return jsonify({"error": "scheme must be 'wesolowski' or 'pietrzak'"}), 400

    # ── Encrypt ──────────────────────────────────────────────────────────────
    AUDIT = AuditLog(); STATE = {}
    exam_id = f"EXAM-{secrets.token_hex(4).upper()}"
    key     = secrets.token_bytes(32)
    nonce, ct = aes_encrypt(raw_bytes, key)
    H_exam  = hashlib.sha256(raw_bytes).hexdigest()
    H_key   = hashlib.sha256(key).hexdigest()

    AUDIT.append({"type": "EXAM_COMMITMENT", "exam_id": exam_id,
                  "H_exam": H_exam, "H_key": H_key,
                  "nonce_hex": nonce.hex(), "mime_type": mime_type, "filename": filename})

    puzzle = generate_vdf_puzzle_with_trapdoor(key, t, bits)
    puzzle["scheme"] = scheme

    AUDIT.append({"type": "VDF_PUZZLE", "exam_id": exam_id,
                  "N_hex": puzzle["N"], "g_hex": puzzle["g"],
                  "t": t, "locked_key": puzzle["locked_key"],
                  "bits": bits, "scheme": scheme})
    key = b"\x00" * 32; del key
    AUDIT.append({"type": "KEY_ERASURE_DECLARATION", "exam_id": exam_id,
                  "ts": datetime.now(timezone.utc).isoformat()})

    STATE.update({
        "exam_id": exam_id, "nonce_hex": nonce.hex(),
        "ciphertext_hex": ct.hex(), "puzzle": puzzle,
        "H_exam": H_exam, "H_key": H_key,
        "mime_type": mime_type, "filename": filename,
        "solve_progress": 0, "solve_status": "idle",
        "recovered_key_hex": None, "decrypted_text": None,
        "decrypted_b64": None,
        "key_verified": None, "exam_verified": None, "vdf_proof": [],
        "scheme": scheme,
    })
    return jsonify({
        "exam_id": exam_id, "H_exam": H_exam, "H_key": H_key,
        "nonce_hex": nonce.hex(),
        "ciphertext_preview": ct.hex()[:48] + "…",
        "ciphertext_len": len(ct), "t_squarings": t,
        "bits": bits, "scheme": scheme,
        "mime_type": mime_type, "filename": filename,
        "content_label": content_label,
    })


@app.route("/api/solve", methods=["POST"])
def api_solve():
    """Evaluate the VDF as a solver — the slow delay step."""
    if not STATE.get("puzzle"):
        return jsonify({"error": "No active exam"}), 400
    if STATE.get("solve_status") == "running":
        return jsonify({"error": "Already running"}), 400
    STATE["solve_status"] = "running"; STATE["solve_progress"] = 0

    def run():
        t0 = time.perf_counter()
        try:
            puzzle = STATE["puzzle"]
            N = int(puzzle["N"], 16)
            g = int(puzzle["g"], 16)
            t = puzzle["t"]
            locked_key = bytes.fromhex(puzzle["locked_key"])
            scheme = puzzle.get("scheme", "wesolowski")

            y, pi, mask = eval_vdf(
                N, g, t,
                progress_cb=lambda p: STATE.update({"solve_progress": p}),
                scheme=scheme,
            )
            recovered = bytes(a ^ b for a, b in zip(locked_key, mask[: len(locked_key)]))
            key_ok = hashlib.sha256(recovered).hexdigest() == STATE["H_key"]
            STATE["key_verified"] = key_ok
            STATE["recovered_key_hex"] = recovered.hex()[:32] + "…"

            # Serialise proof
            if scheme == "wesolowski":
                STATE["vdf_proof"] = [{"pi": hex(pi)}]
            else:
                STATE["vdf_proof"] = [{"mu": hex(mu), "t": tl} for mu, tl in pi]
            STATE["y_hex"] = hex(y)

            if key_ok:
                pt = aes_decrypt(
                    bytes.fromhex(STATE["nonce_hex"]),
                    bytes.fromhex(STATE["ciphertext_hex"]),
                    recovered,
                )
                STATE["exam_verified"] = hashlib.sha256(pt).hexdigest() == STATE["H_exam"]
                mime = STATE.get("mime_type", "text/plain")
                if mime == "text/plain":
                    STATE["decrypted_text"] = pt.decode(errors="replace")
                    STATE["decrypted_b64"]  = None
                else:
                    # Binary: store as base64 so frontend can download/preview
                    STATE["decrypted_text"] = None
                    STATE["decrypted_b64"]  = base64.b64encode(pt).decode()
            STATE["solve_time_s"] = round(time.perf_counter() - t0, 3)
            STATE["solve_status"] = "done"
        except Exception as e:
            import traceback; traceback.print_exc()
            STATE["solve_status"] = "error"; STATE["solve_error"] = str(e)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/download", methods=["GET"])
def api_download():
    """Download the decrypted binary file (PDF / image) after VDF solve."""
    if STATE.get("solve_status") != "done":
        return jsonify({"error": "Not ready"}), 400
    b64 = STATE.get("decrypted_b64")
    if not b64:
        return jsonify({"error": "No binary file to download (text-only exam)"}), 400
    data = base64.b64decode(b64)
    mime = STATE.get("mime_type", "application/octet-stream")
    fname = STATE.get("filename", "decrypted_exam")
    return send_file(
        io.BytesIO(data),
        mimetype=mime,
        as_attachment=True,
        download_name=fname,
    )


@app.route("/api/verify_vdf", methods=["POST"])
def api_verify_vdf():
    """
    Public verifiability endpoint — anyone can verify a VDF output in O(log t).
    Accepts both Wesolowski and Pietrzak proofs.
    """
    data: Dict[str, Any] = request.json or {}
    try:
        N_val = data.get("N")
        g_val = data.get("g")
        y_val = data.get("y")
        t_val = data.get("t")

        if N_val is None or g_val is None or y_val is None or t_val is None:
            return jsonify({"error": "N, g, y, t are required"}), 400

        N = int(str(N_val), 16)
        g = int(str(g_val), 16)
        y = int(str(y_val), 16)
        t = int(str(t_val))
        scheme = data.get("scheme", "wesolowski")
        pi_raw = data.get("pi")

        if scheme == "wesolowski":
            if (
                isinstance(pi_raw, list)
                and pi_raw
                and isinstance(pi_raw[0], dict)
                and "pi" in pi_raw[0]
            ):
                pi = int(pi_raw[0]["pi"], 16)
            else:
                if pi_raw is None:
                    return jsonify({"error": "pi is required for wesolowski"}), 400
                pi = int(str(pi_raw), 16)
        elif scheme == "pietrzak":
            if not isinstance(pi_raw, list):
                return jsonify({"error": "pi must be a list for pietrzak"}), 400
            pi = [(int(e["mu"], 16), int(e["t"])) for e in pi_raw]
        else:
            return jsonify({"error": f"Unknown scheme: {scheme}"}), 400

        t0 = time.perf_counter()
        is_valid = verify_vdf(N, g, y, t, pi, scheme=scheme)
        verify_ms = (time.perf_counter() - t0) * 1000

        return jsonify({
            "is_valid": is_valid,
            "scheme": scheme,
            "verification_time_ms": round(verify_ms, 3),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Wesolowski standalone endpoints
# ---------------------------------------------------------------------------

@app.route("/api/wesolowski/eval", methods=["POST"])
def api_wesolowski_eval():
    """
    Compute Wesolowski VDF: y = g^(2^t) mod N, π = g^(floor(2^t/ℓ)) mod N.
    Body: {N_hex, g_hex, t}  or  {bits} to auto-generate N and g.
    """
    data = request.json or {}
    try:
        bits = int(data.get("bits", 512))
        t = int(data.get("t", 1000))

        if "N_hex" in data and "g_hex" in data:
            N = int(data["N_hex"], 16)
            g = int(data["g_hex"], 16)
        else:
            N, g = generate_vdf_setup(bits)

        t0 = time.perf_counter()
        y, pi, _ = wesolowski_eval_vdf(N, g, t)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "N_hex": hex(N), "g_hex": hex(g),
            "y_hex": hex(y), "pi_hex": hex(pi),
            "t": t, "eval_time_s": elapsed,
            "scheme": "wesolowski",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/wesolowski/verify", methods=["POST"])
def api_wesolowski_verify():
    """
    Verify Wesolowski VDF in O(log t) — 2 modular exponentiations.
    Body: {N_hex, g_hex, y_hex, pi_hex, t}
    """
    data = request.json or {}
    try:
        N   = int(data["N_hex"], 16)
        g   = int(data["g_hex"], 16)
        y   = int(data["y_hex"], 16)
        pi  = int(data["pi_hex"], 16)
        t   = int(data["t"])

        t0 = time.perf_counter()
        is_valid = wesolowski_verify_vdf(N, g, y, t, pi)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": "wesolowski",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Pietrzak standalone endpoints
# ---------------------------------------------------------------------------

@app.route("/api/pietrzak/eval", methods=["POST"])
def api_pietrzak_eval():
    """Compute Pietrzak VDF with O(log t) recursive proof."""
    data = request.json or {}
    try:
        bits = int(data.get("bits", 512))
        t = int(data.get("t", 1000))

        if "N_hex" in data and "g_hex" in data:
            N = int(data["N_hex"], 16)
            g = int(data["g_hex"], 16)
        else:
            N, g = generate_vdf_setup(bits)

        t0 = time.perf_counter()
        y, pi, _ = pietrzak_eval_vdf(N, g, t)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "N_hex": hex(N), "g_hex": hex(g),
            "y_hex": hex(y),
            "pi": [{"mu": hex(mu), "t": tl} for mu, tl in pi],
            "proof_levels": len(pi),
            "t": t, "eval_time_s": elapsed,
            "scheme": "pietrzak",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/pietrzak/verify", methods=["POST"])
def api_pietrzak_verify():
    """Verify Pietrzak VDF in O(log t)."""
    data = request.json or {}
    try:
        N  = int(data["N_hex"], 16)
        g  = int(data["g_hex"], 16)
        y  = int(data["y_hex"], 16)
        t  = int(data["t"])
        pi = [(int(e["mu"], 16), int(e["t"])) for e in data["pi"]]

        t0 = time.perf_counter()
        is_valid = pietrzak_verify_vdf(N, g, y, t, pi)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": "pietrzak",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Hash Chain endpoints (baseline — no fast verify)
# ---------------------------------------------------------------------------

@app.route("/api/hash_chain/eval", methods=["POST"])
def api_hash_chain_eval():
    """
    Compute hash chain y = SHA-256^t(x).
    Body: {x_hex, t}
    """
    data = request.json or {}
    try:
        x_hex = data.get("x_hex", hashlib.sha256(b"default").hexdigest())
        t = int(data.get("t", 1000))

        t0 = time.perf_counter()
        y_hex, checkpoints = hash_chain_eval(x_hex, t)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "x_hex": x_hex, "y_hex": y_hex,
            "t": t, "eval_time_s": elapsed,
            "checkpoints": checkpoints,
            "note": "Hash chain has NO fast verify — O(t) verification per §3 remark.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/hash_chain/verify", methods=["POST"])
def api_hash_chain_verify():
    """Verify hash chain using checkpoints (O(t) total)."""
    data = request.json or {}
    try:
        x_hex = data["x_hex"]
        y_hex = data["y_hex"]
        t = int(data["t"])
        checkpoints = data.get("checkpoints", {})

        t0 = time.perf_counter()
        is_valid = hash_chain_verify(x_hex, y_hex, t, checkpoints)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "note": "O(t) verification — not polylog. Demonstrates baseline without fast-verify.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Sloth endpoints
# ---------------------------------------------------------------------------

@app.route("/api/sloth/eval", methods=["POST"])
def api_sloth_eval():
    """
    Evaluate Sloth weak VDF.
    Body: {x_hex, p_hex (prime ≡ 3 mod 4), iterations}
    Default: generates a 256-bit prime p ≡ 3 mod 4.
    """
    data = request.json or {}
    try:
        iterations = int(data.get("iterations", 100))

        if "p_hex" in data:
            p = int(data["p_hex"], 16)
        else:
            # Generate a 256-bit prime p ≡ 3 (mod 4)
            from math_utils import _gen_prime_cong
            p = _gen_prime_cong(256, 3, 4)

        if "x_hex" in data:
            x = int(data["x_hex"], 16) % p
        else:
            x = secrets.randbelow(p - 1) + 1

        t0 = time.perf_counter()
        y = sloth_eval(x, p, iterations)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "x_hex": hex(x), "y_hex": hex(y),
            "p_hex": hex(p), "iterations": iterations,
            "eval_time_s": elapsed,
            "scheme": "sloth",
            "paper_section": "§7.1",
            "note": "Weak VDF. Verify by forward-squaring y (one mult per step).",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sloth/verify", methods=["POST"])
def api_sloth_verify():
    """
    Verify Sloth by forward squaring.
    Body: {x_hex, y_hex, p_hex, iterations}
    """
    data = request.json or {}
    try:
        x = int(data["x_hex"], 16)
        y = int(data["y_hex"], 16)
        p = int(data["p_hex"], 16)
        iterations = int(data["iterations"])

        t0 = time.perf_counter()
        is_valid = sloth_verify(x, y, p, iterations)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": "sloth",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Sloth++ endpoints
# ---------------------------------------------------------------------------

@app.route("/api/sloth_plus_plus/eval", methods=["POST"])
def api_sloth_pp_eval():
    """
    Evaluate Sloth++ weak VDF over Fp².
    Body: {x_a_hex, x_b_hex, p_hex, iterations}
    x represents (a + b·i) ∈ Fp².
    """
    data = request.json or {}
    try:
        iterations = int(data.get("iterations", 50))

        if "p_hex" in data:
            p = int(data["p_hex"], 16)
        else:
            from math_utils import _gen_prime_cong
            p = _gen_prime_cong(256, 3, 4)

        if "x_a_hex" in data and "x_b_hex" in data:
            x = (int(data["x_a_hex"], 16) % p, int(data["x_b_hex"], 16) % p)
        else:
            x = (secrets.randbelow(p - 1) + 1, secrets.randbelow(p - 1) + 1)

        t0 = time.perf_counter()
        y = sloth_plus_plus_eval(x, p, iterations)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "x_a_hex": hex(x[0]), "x_b_hex": hex(x[1]),
            "y_a_hex": hex(y[0]), "y_b_hex": hex(y[1]),
            "p_hex": hex(p), "iterations": iterations,
            "eval_time_s": elapsed,
            "scheme": "sloth_plus_plus",
            "paper_section": "§7.1",
            "snark_gates_per_step": 4,
            "sha256_gates_per_step": 27904,
            "improvement_factor": "≈7000×",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sloth_plus_plus/verify", methods=["POST"])
def api_sloth_pp_verify():
    """
    Verify Sloth++ by forward squaring in Fp².
    Body: {x_a_hex, x_b_hex, y_a_hex, y_b_hex, p_hex, iterations}
    """
    data = request.json or {}
    try:
        p = int(data["p_hex"], 16)
        x = (int(data["x_a_hex"], 16), int(data["x_b_hex"], 16))
        y = (int(data["y_a_hex"], 16), int(data["y_b_hex"], 16))
        iterations = int(data["iterations"])

        t0 = time.perf_counter()
        is_valid = sloth_plus_plus_verify(x, y, p, iterations)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": "sloth_plus_plus",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Rational Maps endpoints (§7.2)
# ---------------------------------------------------------------------------

@app.route("/api/rational_map/eval", methods=["POST"])
def api_rational_map_eval():
    """
    Evaluate Rational Map weak VDF.
    Body: {x_hex, p_hex, s, a}
    """
    data = request.json or {}
    try:
        from math_utils import _gen_prime_cong
        p = int(data.get("p_hex", hex(_gen_prime_cong(128, 3, 4))), 16)
        s = int(data.get("s", 3))
        a = int(data.get("a", 1))
        
        # x must be in Fp
        if "x_hex" in data:
            x = int(data["x_hex"], 16) % p
        else:
            x = secrets.randbelow(p - 1) + 1

        t0 = time.perf_counter()
        y = rational_map_eval(x, p, s, a)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "x_hex": hex(x), "y_hex": hex(y),
            "p_hex": hex(p), "s": s, "a": a,
            "eval_time_s": elapsed,
            "scheme": "rational_map",
            "paper_section": "§7.2",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/rational_map/verify", methods=["POST"])
def api_rational_map_verify():
    """Verify Rational Map VDF by evaluating polynomial."""
    data = request.json or {}
    try:
        x = int(data["x_hex"], 16)
        y = int(data["y_hex"], 16)
        p = int(data["p_hex"], 16)
        s = int(data["s"])
        a = int(data.get("a", 1))

        t0 = time.perf_counter()
        is_valid = rational_map_verify(x, y, p, s, a)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": "rational_map",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Large Prime Product endpoints
# ---------------------------------------------------------------------------

@app.route("/api/large_prime/eval", methods=["POST"])
def api_large_prime_eval():
    """
    Evaluate Large Prime Product VDF: y = g^P mod N.
    """
    data = request.json or {}
    try:
        from crypto_utils import generate_vdf_setup
        bits = int(data.get("bits", 512))
        t = int(data.get("t", 100))

        if "N_hex" in data and "g_hex" in data:
            N = int(data["N_hex"], 16)
            g = int(data["g_hex"], 16)
        else:
            N, g = generate_vdf_setup(bits)

        t0 = time.perf_counter()
        y = large_prime_product_eval(N, g, t)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "N_hex": hex(N), "g_hex": hex(g),
            "y_hex": hex(y), "t": t,
            "eval_time_s": elapsed,
            "scheme": "large_prime",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/large_prime/verify", methods=["POST"])
def api_large_prime_verify():
    """Verify Large Prime Product VDF."""
    data = request.json or {}
    try:
        N = int(data["N_hex"], 16)
        g = int(data["g_hex"], 16)
        y = int(data["y_hex"], 16)
        t = int(data["t"])

        t0 = time.perf_counter()
        is_valid = large_prime_product_verify(N, g, y, t)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": "large_prime",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Randomness Beacon endpoint  (§2 application)
# ---------------------------------------------------------------------------

@app.route("/api/beacon", methods=["POST"])
def api_beacon():
    """
    Compute a public randomness beacon (§2).
    The beacon applies a VDF to public entropy so no one can predict the
    output until the VDF completes.

    Body: {entropy (string), t, bits (optional), scheme (optional)}
    """
    data = request.json or {}
    try:
        entropy_str = data.get("entropy", datetime.now(timezone.utc).isoformat())
        entropy_bytes = hashlib.sha256(entropy_str.encode()).digest()
        t = int(data.get("t", 2000))
        bits = int(data.get("bits", 512))
        scheme = data.get("scheme", "wesolowski")

        if scheme not in ("wesolowski", "pietrzak"):
            return jsonify({"error": "scheme must be 'wesolowski' or 'pietrzak'"}), 400

        N, g = generate_vdf_setup(bits)

        t0 = time.perf_counter()
        result = randomness_beacon(entropy_bytes, N, g, t, scheme=scheme)
        elapsed = round(time.perf_counter() - t0, 3)
        result["eval_time_s"] = elapsed
        result["entropy_used"] = entropy_str

        AUDIT.append({
            "type": "BEACON_COMPUTATION",
            "entropy_hash": hashlib.sha256(entropy_bytes).hexdigest(),
            "beacon_hex": result["beacon_hex"],
            "scheme": scheme, "t": t,
            "ts": datetime.now(timezone.utc).isoformat(),
        })

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/beacon/verify", methods=["POST"])
def api_beacon_verify():
    """Publicly verify a beacon output. Body: the full beacon dict from /api/beacon."""
    data = request.json or {}
    try:
        t0 = time.perf_counter()
        is_valid = verify_randomness_beacon(data)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
        return jsonify({"is_valid": is_valid, "verification_time_ms": elapsed_ms})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Proof of Replication endpoints  (§2 application)
# ---------------------------------------------------------------------------

@app.route("/api/replication/encode", methods=["POST"])
def api_replication_encode():
    """
    Encode file blocks for proof of replication (§2).
    y_i = VDF(B_i ⊕ H(replicator_id || i))

    Body: {
      blocks_hex: ["aabb...", ...],
      replicator_id: "node-001",
      t: 500,
      bits: 512,
      scheme: "wesolowski"
    }
    """
    data = request.json or {}
    try:
        blocks_hex = data.get("blocks_hex", [])
        if not blocks_hex:
            return jsonify({"error": "blocks_hex required"}), 400
        blocks = [bytes.fromhex(b) for b in blocks_hex]
        replicator_id = data.get("replicator_id", "replicator-0")
        t = int(data.get("t", 500))
        bits = int(data.get("bits", 512))
        scheme = data.get("scheme", "wesolowski")

        N, g = generate_vdf_setup(bits)
        t0 = time.perf_counter()
        encoded = encode_for_replication(blocks, replicator_id, N, g, t, scheme=scheme)
        elapsed = round(time.perf_counter() - t0, 3)

        return jsonify({
            "encoded_blocks": encoded,
            "N_hex": hex(N),
            "t": t,
            "scheme": scheme,
            "replicator_id": replicator_id,
            "encode_time_s": elapsed,
            "note": "Verifier can spot-check any block yi without recomputing all blocks.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/replication/verify", methods=["POST"])
def api_replication_verify():
    """
    Spot-check one replication block (§2 challenge-response).
    Body: {yi_hex, Bi_hex, pi, replicator_id, block_index, N_hex, t, scheme}
    """
    data = request.json or {}
    try:
        yi_hex = data["yi_hex"]
        Bi = bytes.fromhex(data["Bi_hex"])
        pi = data["pi"]
        replicator_id = data["replicator_id"]
        block_index = int(data["block_index"])
        N = int(data["N_hex"], 16)
        t = int(data["t"])
        scheme = data.get("scheme", "wesolowski")

        t0 = time.perf_counter()
        is_valid = verify_replication_block(
            yi_hex, Bi, pi, replicator_id, block_index, N, t, scheme=scheme
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return jsonify({
            "is_valid": is_valid,
            "verification_time_ms": elapsed_ms,
            "scheme": scheme,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Progress / audit
# ---------------------------------------------------------------------------

@app.route("/api/progress")
def api_progress():
    return jsonify({
        "progress": STATE.get("solve_progress", 0),
        "status": STATE.get("solve_status", "idle"),
        "key_verified": STATE.get("key_verified"),
        "exam_verified": STATE.get("exam_verified"),
        "recovered_key_hex": STATE.get("recovered_key_hex"),
        "decrypted_text": STATE.get("decrypted_text"),
        "decrypted_b64": STATE.get("decrypted_b64"),
        "mime_type": STATE.get("mime_type", "text/plain"),
        "filename": STATE.get("filename", "exam.txt"),
        "solve_time_s": STATE.get("solve_time_s"),
        "vdf_proof": STATE.get("vdf_proof"),
        "y_hex": STATE.get("y_hex"),
        "scheme": STATE.get("scheme"),
    })



@app.route("/api/audit")
def api_audit():
    return jsonify({"log": AUDIT.to_list(), "chain_valid": AUDIT.verify()})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _run_benchmark()
    print("  🔐  CryptoExam (Full VDF Paper Implementation)  →  http://localhost:5050\n")
    print("  Available endpoints:")
    print("    GET  /api/schemes")
    print("    POST /api/wesolowski/eval   POST /api/wesolowski/verify")
    print("    POST /api/pietrzak/eval     POST /api/pietrzak/verify")
    print("    POST /api/hash_chain/eval   POST /api/hash_chain/verify")
    print("    POST /api/sloth/eval        POST /api/sloth/verify")
    print("    POST /api/sloth_plus_plus/eval  POST /api/sloth_plus_plus/verify")
    print("    POST /api/rational_map/eval     POST /api/rational_map/verify")
    print("    POST /api/large_prime/eval      POST /api/large_prime/verify")
    print("    POST /api/beacon            POST /api/beacon/verify")
    print("    POST /api/replication/encode  POST /api/replication/verify")
    print("    POST /api/encrypt  POST /api/solve  POST /api/verify_vdf")
    print()
    app.run(debug=False, port=5050)