from dataclasses import replace

from agf_agentteams import Collector, Worker
from support import Case, KEY


class DeliveryTests(Case):
    def test_public_configuration_cannot_retarget_pending_events(self):
        receiver = self.receiver()
        collector = self.collector(receiver)
        collector.heartbeat()
        with self.assertRaises(AttributeError):
            collector.config = replace(collector.config, binding_id="00000000-0000-4000-8000-000000000099")
        self.assertEqual(1, collector.status()["pending"])
        self.assertEqual(1, collector.flush(1)["sent"])

    def test_truncated_chunked_response_retains_original_event_with_normal_backoff(self):
        receiver = self.receiver()
        receiver.replies.append("truncated")
        collector = self.collector(receiver)
        collector.heartbeat()
        self.assertTrue(collector._deliver(0.2))
        self.assertEqual((1, "network_error"), (collector.status()["pending"], collector.status()["last_error"]))
        self.assertEqual([], collector._outbox.batch(100))
        self.assertEqual((0, 1), (collector.flush(2)["pending"], collector.status()["deduped"]))
        self.assertEqual(receiver.bodies[0], receiver.bodies[1])

    def test_real_http_ack_removes_events_and_reports_persisted_counts(self):
        receiver = self.receiver()
        collector = self.collector(receiver)
        collector.heartbeat()
        report = collector.flush(1)
        self.assertEqual((1, 0, 0, True), (report["sent"], report["deduped"], report["pending"], report["durable"]))
        self.assertEqual(1, len(receiver.bodies))
        self.assertNotIn(KEY.encode(), receiver.bodies[0])

    def test_response_loss_then_restart_retries_same_event_without_rerunning_business(self):
        receiver = self.receiver()
        receiver.replies.append("drop")
        collector = self.collector(receiver)
        calls = []

        @collector.task(Worker("worker-a", "team-a"))
        def business():
            calls.append(1)
            return 7

        self.assertEqual(7, business())
        self.assertTrue(collector._deliver(0.2))
        self.assertEqual(1, collector.status()["pending"])
        config = collector.config
        collector.close(0)
        resumed = Collector(config, autostart=False)
        self.addCleanup(self._close_collector, resumed)
        report = resumed.flush(2)
        self.assertEqual((0, 1, 0), (report["sent"], report["deduped"], report["pending"]))
        self.assertEqual([1], calls)
        self.assertEqual(receiver.bodies[0], receiver.bodies[1])

    def test_malformed_success_does_not_ack_or_discard_the_original_event(self):
        receiver = self.receiver()
        receiver.replies.append("bad_ack")
        collector = self.collector(receiver)
        collector.heartbeat()
        collector._deliver(0.2)
        self.assertEqual((0, 1, "invalid_ack"), (collector.status()["sent"], collector.status()["pending"],
                                               collector.status()["last_error"]))

    def test_permission_failure_pauses_automatic_delivery_without_dropping(self):
        receiver = self.receiver()
        receiver.replies.append(403)
        collector = self.collector(receiver)
        collector.heartbeat()
        first = collector.flush(1)
        self.assertEqual(("http_403", 1, 0), (first["paused"], first["pending"], first["sent"]))
        collector.flush(0.1)
        self.assertEqual(1, len(receiver.bodies))
        self.assertEqual({}, receiver.events)

    def test_redirect_never_sends_the_credential_or_event_to_another_receiver(self):
        receiver, destination = self.receiver(), self.receiver()
        receiver.replies.append((302, destination.url + "/unexpected"))
        collector = self.collector(receiver)
        collector.heartbeat()
        report = collector.flush(1)
        self.assertEqual(("http_302", 1, 0), (report["paused"], report["quarantined"], report["sent"]))
        self.assertEqual([], destination.bodies)
        self.assertEqual({}, receiver.events)

    def test_conflict_is_quarantined_and_never_reidentified_or_rebound(self):
        receiver = self.receiver()
        receiver.replies.append(409)
        collector = self.collector(receiver)
        collector.heartbeat()
        report = collector.flush(1)
        self.assertEqual((1, 0, "http_409"), (report["quarantined"], report["pending"], report["paused"]))
        self.assertEqual({}, receiver.events)
        collector.resume()
        collector.flush(0.1)
        self.assertEqual(1, len(receiver.bodies))

    def test_invalid_shutdown_budget_does_not_close_a_live_collector(self):
        collector = self.collector()
        with self.assertRaises(ValueError):
            collector.close(-1)
        self.assertFalse(collector.status()["closed"])
