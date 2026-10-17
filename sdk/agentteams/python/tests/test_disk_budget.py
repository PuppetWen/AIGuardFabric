import json
import sqlite3

from agf_agentteams.spool import Outbox, QueueFull
from support import Case


class DiskBudgetTests(Case):
    def test_active_delete_journal_and_lock_fit_the_total_owned_file_budget(self):
        config = self.config(max_bytes=64 * 1024, max_disk_bytes=256 * 1024)
        box = Outbox(config)
        try:
            for index in range(200):
                try:
                    box.append({"event_id": f"owned-{index}", "message": "x" * 900})
                except QueueFull:
                    break
                except sqlite3.OperationalError as error:
                    self.assertEqual(sqlite3.SQLITE_FULL, error.sqlite_errorcode)
                    break
            rows = box._connection.execute("SELECT id,payload FROM events").fetchall()
            self.assertGreater(len(rows), 10)
            before = sum(path.stat().st_size for path in config.spool_dir.iterdir())
            sizes = []
            saw_journal = []

            def observe():
                paths = list(config.spool_dir.iterdir())
                sizes.append(sum(path.stat().st_size for path in paths))
                saw_journal.append(any(path.name.endswith("-journal") for path in paths))
                return 0

            box._connection.set_progress_handler(observe, 1)
            try:
                box.defer([(key, json.loads(value)) for key, value in rows], 5, "network_error")
            finally:
                box._connection.set_progress_handler(None, 0)
            self.assertTrue(any(saw_journal), "must measure a real active journal, not only committed size")
            self.assertGreater(max(sizes), before)
            self.assertLessEqual(max(sizes), config.max_disk_bytes)
            self.assertEqual(len(rows), box.counts()["pending"])
            self.assertEqual(0, box._connection.execute("PRAGMA cache_spill").fetchone()[0])
        finally:
            box.close()

    def test_large_foreign_lock_is_refused_without_truncation(self):
        config = self.config()
        config.spool_dir.mkdir()
        contents = b"owned-by-another-application" * 100
        lock = config.spool_dir / "collector.lock"
        lock.write_bytes(contents)
        with self.assertRaises(ValueError):
            Outbox(config)
        self.assertEqual(contents, lock.read_bytes())
        self.assertFalse((config.spool_dir / "events.sqlite3").exists())
