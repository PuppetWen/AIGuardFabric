from dataclasses import replace
from contextlib import closing
import json
import sqlite3

from agf_agentteams.spool import Outbox, QueueFull
from support import BINDING, Case, KEY


class OutboxTests(Case):
    def test_restart_preserves_exact_payload_and_never_stores_the_credential(self):
        config = self.config()
        first = Outbox(config)
        value = {"event_id": "stable-1", "message": None, "event_time": "2026-09-30T00:00:00Z"}
        first.append(value)
        batch = first.batch(100)
        first.close()
        second = Outbox(config)
        try:
            self.assertEqual(batch, second.batch(100))
            self.assertNotIn(KEY.encode(), (config.spool_dir / "events.sqlite3").read_bytes())
            second.ack(batch)
            self.assertEqual(0, second.counts()["pending"])
        finally:
            second.close()

    def test_queue_full_keeps_prior_events_and_duplicate_identity_cannot_change_content(self):
        box = Outbox(self.config(max_items=1))
        try:
            box.append({"event_id": "first", "message": None})
            box.append({"event_id": "first", "message": None})
            with self.assertRaises(ValueError):
                box.append({"event_id": "first", "message": "changed"})
            with self.assertRaises(QueueFull):
                box.append({"event_id": "second", "message": None})
            self.assertEqual("first", box.batch(100)[0][0])
        finally:
            box.close()

    def test_binding_change_cannot_retarget_existing_events(self):
        config = self.config()
        box = Outbox(config)
        box.append({"event_id": "first"})
        box.close()
        with self.assertRaises(ValueError):
            Outbox(replace(config, binding_id="00000000-0000-4000-8000-000000000099"))
        current = Outbox(config)
        try:
            self.assertEqual(1, current.counts()["pending"])
            with closing(sqlite3.connect(config.spool_dir / "events.sqlite3")) as connection:
                identity = json.loads(connection.execute("SELECT value FROM metadata WHERE name='identity'").fetchone()[0])
            self.assertEqual(BINDING, identity["binding"])
        finally:
            current.close()

    def test_second_writer_is_refused_without_corrupting_the_first_queue(self):
        first = Outbox(self.config())
        try:
            with self.assertRaises((OSError, PermissionError)):
                Outbox(self.config())
            first.append({"event_id": "still-owned"})
            self.assertEqual(1, first.counts()["pending"])
        finally:
            first.close()

    def test_unrelated_database_is_not_adopted_or_modified(self):
        config = self.config()
        config.spool_dir.mkdir()
        database = config.spool_dir / "events.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE user_data(value TEXT)")
            connection.execute("INSERT INTO user_data VALUES ('preserve')")
            connection.commit()
        with self.assertRaises(ValueError):
            Outbox(config)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual([("preserve",)], connection.execute("SELECT value FROM user_data").fetchall())
            self.assertEqual(1, connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0])

    def test_config_rejects_credential_urls_and_nonopaque_identifiers(self):
        with self.assertRaises(ValueError):
            replace(self.config(), platform_url="http://user:password@127.0.0.1")
        with self.assertRaises(ValueError):
            replace(self.config(), source_id="not-a-uuid")
        self.assertNotIn(KEY, repr(self.config()))
