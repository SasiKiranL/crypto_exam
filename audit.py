import json
import hashlib
from datetime import datetime, timezone

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
            payload = f"{prev}{json.dumps(r['entry'], sort_keys=True)}"
            if hashlib.sha256(payload.encode('utf-8')).hexdigest() != str(r["hash"]):
                return False
            prev = str(r["hash"])
        return True
    def to_list(self):
        return [{"seq": r["seq"], "ts": r["ts"], "type": r["entry"].get("type", "?"),
                 "hash": r["hash"][:20] + "…", "prev": r["prev"][:16] + "…"} for r in self._chain]
