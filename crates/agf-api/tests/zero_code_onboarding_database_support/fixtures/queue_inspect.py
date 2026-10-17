"""Read an inactive owned outbox only; report identities/counts, never its content or credentials."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

root = Path(sys.argv[1])
language = sys.argv[2]
path = root / "events.sqlite3"
with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as database:
    expected = 0x41474634 if language == "python" else 0x4147464E
    assert database.execute("PRAGMA application_id").fetchone()[0] == expected
    rows = database.execute("SELECT id,payload,state FROM events ORDER BY id").fetchall()
    report = []
    for identity, payload, state in rows:
        value = json.loads(payload)
        assert value["event_id"] == identity
        report.append({"id": identity, "kind": value["kind"], "status": value["status"],
                       "state": state, "hash": hashlib.sha256(payload.encode()).hexdigest()})
    print(json.dumps({"rows": report}, sort_keys=True))
