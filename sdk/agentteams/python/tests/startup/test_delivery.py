import hashlib
import json

from startup_support import BINDING, Case, OTHER

NAMES = ("echo", "asynchronous", "values", "async_values")


class DeliveryTests(Case):
    def launch_business(self, receiver):
        path = self.write(self.value(receiver, NAMES))
        result = self.launch(path, "--module", "startup_business", "--", "--example-argument")
        self.assertEqual(0, result.returncode)
        self.assertEqual("business completed\n", result.stdout)
        return path, json.loads(result.stderr)

    def test_lost_ack_reopen_delivers_original_event_ids_and_drain_never_runs_business(self):
        receiver = self.receiver(replies=("drop",))
        path, first = self.launch_business(receiver)
        original = {event["event_id"]: event for event in self.events()}
        self.assertEqual(4, first["pending"])
        self.assertEqual(4, len(original))
        self.assertTrue(receiver.events, "Real HTTP must have accepted an event before losing its ACK")
        receiver.allowed = True
        drained = self.launch(path, "--drain-only")
        self.assertEqual(0, drained.returncode)
        self.assertEqual("", drained.stdout)
        report = json.loads(drained.stderr)
        self.assertEqual(0, report["pending"])
        self.assertGreaterEqual(report["deduped"], 1)
        self.assertEqual(original, receiver.events)
        deliveries = [event for body in receiver.bodies for event in body["events"]]
        self.assertGreater(len(deliveries), len(original))
        self.assertTrue(all(event == original[event["event_id"]] for event in deliveries))
        self.assertEqual([], self.events())
        self.assertEqual([], receiver.failures)

    def test_current_key_denial_keeps_queue_then_delivery_only_recovery_uses_same_identity(self):
        receiver = self.receiver()
        path, first = self.launch_business(receiver)
        original = {event["event_id"]: event for event in self.events()}
        self.assertEqual((4, "http_403"), (first["pending"], first["paused"]))
        self.assertEqual({}, receiver.events)
        receiver.allowed = True
        drained = self.launch(path, "--drain-only")
        self.assertEqual(0, drained.returncode)
        self.assertEqual("", drained.stdout)
        self.assertEqual(original, receiver.events)
        self.assertTrue(all(body["binding_id"] == BINDING for body in receiver.bodies))
        self.assertEqual([], receiver.failures)

    def test_wrong_scope_ack_never_deletes_events_and_correct_ack_replays_same_ids(self):
        receiver = self.receiver(replies=("wrong_scope",))
        path, first = self.launch_business(receiver)
        original = {event["event_id"]: event for event in self.events()}
        self.assertEqual(4, first["pending"])
        self.assertTrue(receiver.events)
        receiver.allowed = True
        drained = self.launch(path, "--drain-only")
        self.assertEqual(0, drained.returncode)
        self.assertEqual(original, receiver.events)
        self.assertEqual([], receiver.failures)

    def test_binding_conflict_quarantines_original_batch_and_never_auto_republishes_it(self):
        receiver = self.receiver(replies=(409,))
        path, first = self.launch_business(receiver)
        self.assertEqual("http_409", first["paused"])
        self.assertGreaterEqual(first["quarantined"], 1)
        quarantined = {event["event_id"] for event in receiver.bodies[0]["events"]}
        receiver.allowed = True
        before = len(receiver.bodies)
        drained = self.launch(path, "--drain-only")
        self.assertEqual(75, drained.returncode)
        self.assertEqual("", drained.stdout)
        report = json.loads(drained.stderr)
        self.assertEqual(first["quarantined"], report["quarantined"])
        replayed = {event["event_id"] for body in receiver.bodies[before:] for event in body["events"]}
        self.assertFalse(quarantined & replayed)
        self.assertEqual([], receiver.failures)

    def test_rebinding_refuses_existing_queue_without_event_change_or_network_dispatch(self):
        receiver = self.receiver()
        path, _first = self.launch_business(receiver)
        original = self.events()
        database = self.directory / "queue/events.sqlite3"
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        calls = len(receiver.bodies)
        value = self.value(receiver, NAMES)
        value["collector"]["binding_id"] = OTHER
        self.write(value)
        denied = self.launch(path, "--drain-only")
        self.assertEqual(78, denied.returncode)
        self.assertEqual("collector_startup_failed", json.loads(denied.stderr)["error"])
        self.assertEqual(calls, len(receiver.bodies))
        self.assertEqual(original, self.events())
        self.assertEqual(before, hashlib.sha256(database.read_bytes()).hexdigest())
