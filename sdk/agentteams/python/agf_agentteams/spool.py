"""A bounded SQLite outbox with one writer and immutable delivery identity."""
import json
import os
import sqlite3
import threading
import time


class QueueFull(Exception):
    """Existing unacknowledged events are retained when new events cannot fit."""


class Outbox:
    def __init__(self, config):
        self.config = config
        self._mutex = threading.RLock()
        self._connection = None
        self._lock_file = None
        directory = config.spool_dir
        if directory.is_symlink():
            raise ValueError("spool directory must not be a symbolic link")
        directory.mkdir(parents=True, exist_ok=True)
        for name in ("collector.lock", "events.sqlite3"):
            if (directory / name).is_symlink():
                raise ValueError("spool files must not be symbolic links")
        try:
            self._lock_file = open(directory / "collector.lock", "a+b")
            self._lock_file.seek(0, os.SEEK_END)
            if self._lock_file.tell() > 1:
                raise ValueError("existing collector lock is not an SDK owner lock")
            if self._lock_file.tell() == 0:
                self._lock_file.write(b"\0")
                self._lock_file.flush()
            self._lock_file.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self._lock_file.read(1) != b"\0":
                raise ValueError("existing collector lock is not an SDK owner lock")
            database = directory / "events.sqlite3"
            new = not database.exists()
            self._connection = sqlite3.connect(database, timeout=1, check_same_thread=False)
            connection = self._connection
            identity = json.dumps(config.identity, sort_keys=True, separators=(",", ":"))
            application_id = 0x41474634  # AGF4: refuse to adopt an unrelated existing database.
            if not new:
                if connection.execute("PRAGMA application_id").fetchone()[0] != application_id:
                    raise ValueError("existing database is not an AIGuardFabric collector outbox")
                previous = connection.execute("SELECT value FROM metadata WHERE name='identity'").fetchone()
                if not previous or previous[0] != identity:
                    raise ValueError("spool belongs to another platform/source/binding; use a separate directory")
            else:
                connection.execute(f"PRAGMA application_id={application_id}")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            # Keep one rollback-journal segment; only the bounded main database is attached.
            connection.execute("PRAGMA cache_spill=OFF")
            if new:
                connection.execute("PRAGMA auto_vacuum=FULL")
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            # Budget the main database plus each journal page and its 8-byte record header.
            # 128 KiB covers the padded journal header, lock and file-format headroom.
            pages = max(1, (config.max_disk_bytes - 128 * 1024) // (2 * page_size + 8))
            if connection.execute("PRAGMA page_count").fetchone()[0] > pages:
                raise ValueError("existing spool exceeds its configured disk bound")
            connection.execute(f"PRAGMA max_page_count={pages}")
            connection.execute("CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("""CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, bytes INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending', retry_at REAL NOT NULL DEFAULT 0,
                reason TEXT, sequence INTEGER NOT NULL)""")
            connection.execute("CREATE INDEX IF NOT EXISTS delivery ON events(state,retry_at,sequence)")
            connection.execute("INSERT OR IGNORE INTO metadata VALUES ('identity', ?)", (identity,))
            connection.commit()
        except BaseException:
            self.close()
            raise

    def append(self, event):
        payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        size = len(payload.encode("utf-8"))
        if size + len(self.config.binding_id) + 64 > self.config.batch_bytes:
            raise QueueFull("event exceeds the configured delivery batch")
        with self._mutex:
            connection = self._connection
            with connection:
                existing = connection.execute("SELECT payload FROM events WHERE id=?", (event["event_id"],)).fetchone()
                if existing:
                    if existing[0] != payload:
                        raise ValueError("event_id cannot identify different content")
                    return
                count, used = connection.execute("SELECT count(*),coalesce(sum(bytes),0) FROM events").fetchone()
                if count >= self.config.max_items or used + size > self.config.max_bytes:
                    raise QueueFull("outbox is full; unacknowledged events were retained")
                sequence = connection.execute("SELECT coalesce(max(sequence),0)+1 FROM events").fetchone()[0]
                connection.execute("INSERT INTO events(id,payload,bytes,sequence) VALUES (?,?,?,?)",
                                   (event["event_id"], payload, size, sequence))

    def batch(self, limit):
        with self._mutex:
            rows = self._connection.execute(
                "SELECT id,payload FROM events WHERE state='pending' AND retry_at<=? ORDER BY sequence LIMIT ?",
                (time.time(), min(limit, self.config.batch_items))).fetchall()
        batch, size = [], len(json.dumps({"binding_id": self.config.binding_id, "events": []}).encode())
        for event_id, payload in rows:
            addition = len(payload.encode("utf-8")) + (1 if batch else 0)
            if size + addition > self.config.batch_bytes:
                break
            batch.append((event_id, json.loads(payload)))
            size += addition
        return batch

    def ack(self, batch):
        with self._mutex, self._connection:
            self._connection.executemany("DELETE FROM events WHERE id=? AND state='pending'",
                                         ((event_id,) for event_id, _ in batch))

    def defer(self, batch, delay, reason, *, quarantine=False):
        # Reasons are SDK fixed codes, never response bodies or exception messages.
        if not reason.replace("_", "").isalnum() or len(reason) > 64:
            raise ValueError("unsafe delivery diagnostic")
        with self._mutex, self._connection:
            self._connection.executemany(
                "UPDATE events SET state=?,retry_at=?,reason=? WHERE id=?",
                (("quarantined" if quarantine else "pending", time.time() + delay, reason, event_id)
                 for event_id, _ in batch))

    def counts(self):
        with self._mutex:
            counts = {"pending": 0, "quarantined": 0, "bytes": 0}
            for state, count, size in self._connection.execute("SELECT state,count(*),sum(bytes) FROM events GROUP BY state"):
                counts[state] = count
                counts["bytes"] += size
            return counts

    def close(self):
        with self._mutex:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            if self._lock_file is not None:
                self._lock_file.close()
                self._lock_file = None
