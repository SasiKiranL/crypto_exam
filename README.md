# 🔐 CryptoExam — Time-Locked Exam Distribution System

A proof-of-concept implementation of a **withholding-resistant** exam distribution system using:

- **AES-256-GCM** authenticated encryption
- **RSW Time-Lock Puzzle** (Rivest-Shamir-Wagner sequential squaring)  
- **SHA-256 hash-chained Audit Log** (mini-blockchain)

---

## 📁 Files

| File | Purpose |
| ------ | --------- |
| `backend.py` | Flask REST API — all cryptographic logic |
| `frontend.html` | Browser UI — open directly in any browser |
| `time_locked_exam_system.py` | Original standalone CLI script |

---

## 🚀 How to Run

### Step 1 — Install dependencies

```bash
pip install flask cryptography
```

> `cryptography` is almost always already installed. `flask` is the only new dependency.

### Step 2 — Start the backend

```bash
python backend.py
```

You should see:

```bash
🔐 Time-Lock Exam Server running at http://localhost:5050
```

### Step 3 — Open the frontend

Simply open `frontend.html` in your browser:

```bash
# macOS
open frontend.html

# Linux
xdg-open frontend.html

# Or just drag the file into Chrome/Firefox
```

> No build step, no npm, no bundler needed. It's a single HTML file.

---

## 🖥️ Using the UI

### Authority Panel (left)

1. Type your exam questions in the text area
2. Adjust the **squarings slider** — higher = longer delay before key is recoverable
3. Click **⚡ Encrypt & Lock** — watch all 6 workflow steps complete
4. The key erasure banner confirms the server no longer holds the key

### Exam Center Panel (right)

1. Click **🔓 Solve Puzzle** — sequential squaring begins (animated progress bar)
2. After completion, verification results appear showing:
   - SHA-256(recovered key) matches published H(K)
   - AES-256-GCM auth tag passes
   - Decrypted exam content revealed

### Audit Log (bottom right)

- Shows all 3 entries: `EXAM_COMMITMENT` → `TIME_LOCK_PUZZLE` → `KEY_ERASURE_DECLARATION`
- Hash chain integrity badge confirms no tampering

---

## ⚙️ Tuning the Delay

| t (squarings) | Approx time on modern CPU |
| -------------- | -------------------------- |
| 500 | < 0.01s (instant demo) |
| 3,000 | ~0.05s |
| 1,000,000 | ~15s |
| 100,000,000 | ~25 minutes |
| 10,000,000,000 | ~2 days |

For a real exam (e.g. "unlock 30 min before exam"), benchmark one squaring on your target hardware, then set `t = 1800 / squaring_time_seconds`.

---

## 🔒 Security Model

```bash
                    KEY ERASED HERE
                          ↓
[Authority]  →  Encrypt  →  Build Puzzle  →  Delete K  →  Distribute
                                                            ↓
[Audit Log]  ←── H(exam) ║ H(K) ║ puzzle params  (public, append-only)
                                                            ↓
[Exam Center]  ─── t sequential squarings ──→  K recovered  →  Verify  →  Decrypt
                   (no server contact needed)
```

**Withholding is defeated because:**

1. The server erases K — it literally cannot withhold what it doesn't have
2. Any exam center can independently recover K after t squarings
3. H(K) in the audit log proves the recovered key is the correct one
