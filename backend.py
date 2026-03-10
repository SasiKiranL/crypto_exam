"""
Time-Locked Exam Distribution System — Flask Backend
Run:  python backend.py
URL:  http://localhost:5050
"""

import os, json, time, hashlib, secrets, threading
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request, make_response

app   = Flask(__name__)
STATE = {}

@app.after_request
def add_cors(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r

@app.route("/", defaults={"p": ""}, methods=["OPTIONS"])
@app.route("/<path:p>", methods=["OPTIONS"])
def _options(p): return make_response("", 204)

def _miller_rabin(n, rounds=20):
    if n < 2: return False
    if n == 2: return True
    if n % 2 == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def _gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(p): return p

def aes_encrypt(plaintext, key):
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

def aes_decrypt(nonce, ct, key):
    return AESGCM(key).decrypt(nonce, ct, None)

def generate_rsw_puzzle(key, t, bits=512):
    half = bits // 2
    p = _gen_prime(half); q = _gen_prime(half)
    while q == p: q = _gen_prime(half)
    n = p * q; phi = (p-1)*(q-1)
    g = secrets.randbelow(n - 2) + 2
    e = pow(2, t, phi)
    ans = pow(g, e, n)
    mask = hashlib.sha256(ans.to_bytes((ans.bit_length()+7)//8, 'big')).digest()
    locked_key = bytes(a ^ b for a, b in zip(key, mask[:len(key)]))
    p = q = phi = e = ans = 0; del p, q, phi, e, ans
    return {"n": hex(n), "g": hex(g), "t": t, "locked_key": locked_key.hex(), "bits": bits}

def solve_rsw_puzzle(puzzle, progress_cb=None):
    n = int(puzzle["n"], 16); g = int(puzzle["g"], 16); t = puzzle["t"]
    locked_key = bytes.fromhex(puzzle["locked_key"])
    x = g; report = max(1, t // 200)
    for i in range(t):
        x = (x * x) % n
        if progress_cb and i % report == 0:
            progress_cb(int(100 * i / t))
    if progress_cb: progress_cb(100)
    mask = hashlib.sha256(x.to_bytes((x.bit_length()+7)//8, 'big')).digest()
    return bytes(a ^ b for a, b in zip(locked_key, mask[:len(locked_key)]))

class AuditLog:
    def __init__(self):
        self._chain = []; self._prev = "0" * 64
    def append(self, entry):
        payload = self._prev + json.dumps(entry, sort_keys=True)
        h = hashlib.sha256(payload.encode()).hexdigest()
        self._chain.append({"seq": len(self._chain), "ts": datetime.now(timezone.utc).isoformat(),
                             "entry": entry, "hash": h, "prev": self._prev})
        self._prev = h; return h
    def verify(self):
        prev = "0" * 64
        for r in self._chain:
            if hashlib.sha256((prev + json.dumps(r["entry"], sort_keys=True)).encode()).hexdigest() != r["hash"]:
                return False
            prev = r["hash"]
        return True
    def to_list(self):
        return [{"seq": r["seq"], "ts": r["ts"], "type": r["entry"].get("type", "?"),
                 "hash": r["hash"][:20] + "…", "prev": r["prev"][:16] + "…"} for r in self._chain]

AUDIT = AuditLog()

# Measured once at startup — no user action needed
SQUARING_TIME_S = None

def _run_benchmark():
    global SQUARING_TIME_S
    print("  ⏱  Benchmarking CPU squaring speed…", end=" ", flush=True)
    p = _gen_prime(256); q = _gen_prime(256)
    n = p * q
    x = secrets.randbelow(n - 2) + 2
    for _ in range(500): x = (x * x) % n          # warmup
    MEASURE = 3000
    t0 = time.perf_counter()
    for _ in range(MEASURE): x = (x * x) % n
    SQUARING_TIME_S = (time.perf_counter() - t0) / MEASURE
    print(f"{int(1/SQUARING_TIME_S):,} squarings/sec  ({SQUARING_TIME_S*1e6:.1f} µs each)")

@app.route("/api/benchmark")
def api_benchmark():
    if SQUARING_TIME_S is None:
        return jsonify({"error": "Benchmark not ready"}), 503
    return jsonify({"squaring_time_s": SQUARING_TIME_S, "squarings_per_sec": int(1/SQUARING_TIME_S)})

@app.route("/api/compute-t", methods=["POST"])
def api_compute_t():
    data = request.json or {}
    unlock_ts = data.get("unlock_timestamp")
    if not unlock_ts:
        return jsonify({"error": "unlock_timestamp required"}), 400
    if SQUARING_TIME_S is None:
        return jsonify({"error": "Benchmark not ready"}), 503
    unlock_dt = datetime.fromisoformat(unlock_ts.replace('Z', '+00:00'))
    if unlock_dt.tzinfo is None:
        unlock_dt = unlock_dt.replace(tzinfo=timezone.utc)
    demo_mode = bool(data.get("demo_mode", False))
    gap_s = (unlock_dt - datetime.now(timezone.utc)).total_seconds()
    if gap_s <= 0:
        return jsonify({"error": "Unlock time must be in the future"}), 400
    real_t = max(1000, int(gap_s / SQUARING_TIME_S))
    t      = 5000 if demo_mode else real_t
    def fmt(s):
        s=int(s)
        if s<60: return f"{s}s"
        if s<3600: return f"{s//60}m {s%60}s"
        return f"{s//3600}h {(s%3600)//60}m"
    return jsonify({"gap_seconds": round(gap_s,1), "gap_human": fmt(gap_s),
                    "t_squarings": t, "real_t": real_t, "demo_mode": demo_mode,
                    "squarings_per_sec": int(1/SQUARING_TIME_S),
                    "estimated_solve_s": round(t * SQUARING_TIME_S, 1)})

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    global AUDIT, STATE
    data = request.json or {}
    exam_text = data.get("exam_text", "").encode()
    t    = int(data.get("t_squarings", 3000))
    bits = int(data.get("bits", 512))
    if not exam_text: return jsonify({"error": "exam_text required"}), 400
    AUDIT = AuditLog(); STATE = {}
    exam_id = f"EXAM-{secrets.token_hex(4).upper()}"
    key = secrets.token_bytes(32)
    nonce, ct = aes_encrypt(exam_text, key)
    H_exam = hashlib.sha256(exam_text).hexdigest()
    H_key  = hashlib.sha256(key).hexdigest()
    AUDIT.append({"type":"EXAM_COMMITMENT","exam_id":exam_id,"H_exam":H_exam,"H_key":H_key,"nonce_hex":nonce.hex()})
    puzzle = generate_rsw_puzzle(key, t, bits)
    AUDIT.append({"type":"TIME_LOCK_PUZZLE","exam_id":exam_id,"n_hex":puzzle["n"],"g_hex":puzzle["g"],"t":t,"locked_key":puzzle["locked_key"],"bits":bits})
    key = b'\x00'*32; del key
    AUDIT.append({"type":"KEY_ERASURE_DECLARATION","exam_id":exam_id,"ts":datetime.now(timezone.utc).isoformat()})
    STATE.update({"exam_id":exam_id,"nonce_hex":nonce.hex(),"ciphertext_hex":ct.hex(),"puzzle":puzzle,
                  "H_exam":H_exam,"H_key":H_key,"solve_progress":0,"solve_status":"idle",
                  "recovered_key_hex":None,"decrypted_text":None,"key_verified":None,"exam_verified":None})
    return jsonify({"exam_id":exam_id,"H_exam":H_exam,"H_key":H_key,"nonce_hex":nonce.hex(),
                    "ciphertext_preview":ct.hex()[:48]+"…","ciphertext_len":len(ct),"t_squarings":t,"bits":bits})

@app.route("/api/solve", methods=["POST"])
def api_solve():
    if not STATE.get("puzzle"): return jsonify({"error":"No active exam"}),400
    if STATE.get("solve_status")=="running": return jsonify({"error":"Already running"}),400
    STATE["solve_status"]="running"; STATE["solve_progress"]=0
    def run():
        t0=time.perf_counter()
        try:
            recovered=solve_rsw_puzzle(STATE["puzzle"],progress_cb=lambda p:STATE.update({"solve_progress":p}))
            key_ok=hashlib.sha256(recovered).hexdigest()==STATE["H_key"]
            STATE["key_verified"]=key_ok; STATE["recovered_key_hex"]=recovered.hex()[:32]+"…"
            if key_ok:
                pt=aes_decrypt(bytes.fromhex(STATE["nonce_hex"]),bytes.fromhex(STATE["ciphertext_hex"]),recovered)
                STATE["exam_verified"]=hashlib.sha256(pt).hexdigest()==STATE["H_exam"]
                STATE["decrypted_text"]=pt.decode(errors="replace")
            STATE["solve_time_s"]=round(time.perf_counter()-t0,3); STATE["solve_status"]="done"
        except Exception as e:
            STATE["solve_status"]="error"; STATE["solve_error"]=str(e)
    threading.Thread(target=run,daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/progress")
def api_progress():
    return jsonify({"progress":STATE.get("solve_progress",0),"status":STATE.get("solve_status","idle"),
                    "key_verified":STATE.get("key_verified"),"exam_verified":STATE.get("exam_verified"),
                    "recovered_key_hex":STATE.get("recovered_key_hex"),"decrypted_text":STATE.get("decrypted_text"),
                    "solve_time_s":STATE.get("solve_time_s")})

@app.route("/api/audit")
def api_audit():
    return jsonify({"log":AUDIT.to_list(),"chain_valid":AUDIT.verify()})

if __name__=="__main__":
    _run_benchmark()
    print("  🔐  CryptoExam  →  http://localhost:5050\n")
    app.run(debug=False, port=5050)