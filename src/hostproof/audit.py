"""A tamper-evident audit log: each entry includes a hash of the one before it."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def digest(previous, body):
    text = previous + json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous = GENESIS

    def write(self, event, **data):
        body = json.loads(json.dumps({
            "at": datetime.now(timezone.utc).isoformat(), "event": event, "data": data
        }, default=str))
        entry_hash = digest(self.previous, body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({**body, "prev": self.previous, "hash": entry_hash}) + "\n")
        self.previous = entry_hash


def verify(path):
    """Check every link in the chain. Returns (is_valid, message)."""
    previous = GENESIS
    count = 0
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        entry = json.loads(line)
        stored_prev, stored_hash = entry.pop("prev"), entry.pop("hash")
        if stored_prev != previous or digest(previous, entry) != stored_hash:
            return False, f"chain breaks at line {number}"
        previous = stored_hash
        count += 1
    if count == 0:
        return False, "the log is empty"
    return True, f"{count} entries verified"
