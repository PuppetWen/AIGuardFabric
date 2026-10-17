"""Real HTTP ACK loss and bounded shutdown; original business is never retried."""
from contextlib import closing, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from unittest.mock import patch

from agf_agentteams import Collector
from agf_agentteams.bootstrap import main
from agf_agentteams.startup.configuration import StartupError
from agf_agentteams.startup.runner import run
from startup_support import BINDING, Case, KEY, PYTHON_ROOT, SCOPE, SOURCE


class Acks:
    """Commit synthetic events before dropping the actual HTTP response body."""
    def __init__(self, *, dropping=True, held=False):
        self.dropping, self.held = dropping, held
        self.events, self.failures = {}, []
        self.received, self.release = threading.Event(), threading.Event()
        self.mutex = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_arguments):
                pass

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if (self.path != f"/api/v1/alicloud/agentteams/audit-sources/{SOURCE}/events"
                        or self.headers.get("Authorization") != "Bearer " + KEY
                        or not 0 < size <= 256 * 1024):
                    receiver.failures.append("unexpected_request")
                    self.send_error(403)
                    return
                body = json.loads(self.rfile.read(size))
                accepted = 0
                with receiver.mutex:
                    if body["binding_id"] != BINDING:
                        receiver.failures.append("unexpected_binding")
                    for event in body["events"]:
                        previous = receiver.events.get(event["event_id"])
                        if previous is not None and previous != event:
                            receiver.failures.append("duplicate_content_changed")
                        if previous is None:
                            receiver.events[event["event_id"]] = event
                            accepted += 1
                    drop = receiver.dropping
                receiver.received.set()
                if receiver.held:
                    receiver.release.wait(2)
                reply = json.dumps({"received": len(body["events"]), "accepted": accepted,
                                    "deduped": len(body["events"]) - accepted, "scopeId": SCOPE,
                                    "mocked": True, "durable": True, "authorizationStatus": "unknown"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                try:
                    if drop:
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                    else:
                        self.wfile.write(reply)
                except OSError:
                    pass  # A timed-out client is part of the real network boundary.

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(1)


BUSINESS = '''import asyncio
import os
from pathlib import Path
def mark(name):
    with Path(os.environ["AGF_DRAIN_TEST_COUNTER"]).open("a", encoding="utf-8") as handle:
        handle.write(name + "\\n")
def sync(value):
    mark("sync")
    return value
async def asynchronous(value):
    mark("async")
    return value
def fail(error):
    mark("fail")
    raise error
async def root():
    mark("root")
    original = object()
    assert sync(original) is original
    await asyncio.sleep(.05)
    assert await asynchronous(original) is original
    await asyncio.sleep(.05)
    original_error = RuntimeError("synthetic business error")
    try:
        fail(original_error)
    except RuntimeError as caught:
        assert caught is original_error
    else:
        raise AssertionError("original exception missing")
'''


class DrainBudgetTests(Case):
    @staticmethod
    def close_collector(collector):
        collector.close(0)
        collector._thread.join(1)
        if collector._thread.is_alive():
            raise AssertionError("Owned delivery thread must finish before case cleanup")

    def acks(self, **options):
        receiver = Acks(**options)
        self.addCleanup(receiver.close)
        return receiver

    def launch_long(self, path, *arguments):
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}:
                del environment[name]
        environment.update(AGF_COLLECTOR_KEY=KEY, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1",
                           PYTHONIOENCODING="utf-8", AGF_DRAIN_TEST_COUNTER=str(self.directory / "counter"),
                           PYTHONPATH=os.pathsep.join((str(PYTHON_ROOT), str(self.directory))))
        return subprocess.run([sys.executable, "-B", "-m", "agf_agentteams.bootstrap", "--config", str(path),
                               *arguments], cwd=self.directory, env=environment,
                              capture_output=True, text=True, encoding="utf-8", timeout=36)

    def queue(self):
        database = (self.directory / "queue/events.sqlite3").as_uri() + "?mode=ro"
        with closing(sqlite3.connect(database, uri=True)) as connection:
            return list(connection.execute("SELECT id,payload,retry_at FROM events ORDER BY sequence"))

    def test_continuous_postcommit_ack_loss_future_retry_explicit_drain_keeps_four_business_calls(self):
        receiver = self.acks()
        module = "owned_import_business_" + self.run_id
        business = self.directory / (module + ".py")
        business.write_text(BUSINESS, encoding="utf-8")
        entry = self.directory / "entry.py"
        entry.write_text(f"import asyncio\nimport {module}\nasyncio.run({module}.root())\n", encoding="utf-8")
        originals = {path: hashlib.sha256(path.read_bytes()).digest() for path in (business, entry)}
        value = self.value(receiver, shutdown_timeout=2.0)
        value["collector"]["request_timeout"] = .5
        value["targets"] = []
        worker = {"name": "worker-a", "team": "team-a"}
        for name, kind in (("root", "task"), ("sync", "call"), ("asynchronous", "call"), ("fail", "task")):
            target = {"module": module, "attribute": name, "kind": kind, "worker": worker, "operation": name}
            if kind == "call":
                target["callee"] = worker
            value["targets"].append(target)
        path = self.write(value)
        business_run = self.launch_long(path, "--script", str(entry))
        self.assertEqual(0, business_run.returncode)
        rows = self.queue()
        self.assertEqual(4, len(rows))
        self.assertGreater(max(row[2] - time.time() for row in rows), 2)
        self.assertTrue(receiver.received.is_set())
        original = {row[0]: json.loads(row[1]) for row in rows}
        count = (self.directory / "counter").read_text(encoding="utf-8")
        self.assertEqual(["root", "sync", "async", "fail"], count.splitlines())
        receiver.dropping = False
        drained = self.launch_long(path, "--drain-only", "--drain-timeout", "30")
        self.assertEqual(0, drained.returncode)
        report = json.loads(drained.stderr)
        self.assertEqual((0, 0, False), (report["pending"], report["quarantined"], report["delivery_active"]))
        self.assertGreaterEqual(report["deduped"], 1)
        self.assertEqual(original, receiver.events)
        self.assertEqual([], self.queue())
        self.assertEqual(count, (self.directory / "counter").read_text(encoding="utf-8"))
        self.assertEqual(originals, {path: hashlib.sha256(path.read_bytes()).digest() for path in originals})
        self.assertEqual([], receiver.failures)
        self.assertNotIn(KEY.encode(), (self.directory / "queue/events.sqlite3").read_bytes())

    def test_invalid_drain_budget_rejected_before_collector_or_business_side_effect(self):
        receiver = self.acks(dropping=False)
        path = self.write(self.value(receiver))
        for value in ("nan", "inf", "-inf", "0", "0.449", "60.001"):
            with self.subTest(value=value):
                result = self.launch_long(path, "--drain-timeout", value, "--drain-only")
                self.assertNotEqual(0, result.returncode)
                self.assertFalse((self.directory / "queue").exists())
                self.assertEqual({}, receiver.events)
        self.assertFalse((self.directory / "counter").exists())

    def test_business_entry_cannot_use_drain_timeout(self):
        receiver = self.acks(dropping=False)
        path = self.write(self.value(receiver))
        result = self.launch_long(path, "--drain-timeout", "30", "--module", "startup_business")
        self.assertEqual(2, result.returncode)
        self.assertFalse((self.directory / "queue").exists())
        self.assertEqual({}, receiver.events)

    def test_direct_runner_rejects_bool_nonfinite_budget_and_business_override(self):
        receiver = self.acks(dropping=False)
        settings = self.settings(receiver)
        with patch("agf_agentteams.startup.runner.Collector") as constructor:
            for budget in (True, float("nan"), float("inf"), .1, 61):
                with self.subTest(budget=repr(budget)), self.assertRaises(StartupError):
                    run(settings, drain_only=True, drain_timeout=budget)
            with self.assertRaises(StartupError):
                run(settings, module="startup_business", drain_timeout=30)
            constructor.assert_not_called()
        self.assertFalse((self.directory / "queue").exists())

    def test_default_and_explicit_delivery_budget_leave_business_shutdown_setting_unchanged(self):
        receiver = self.acks(dropping=False)
        settings = self.settings(receiver, shutdown_timeout=2)
        with patch("agf_agentteams.startup.runner.Collector") as constructor, redirect_stderr(io.StringIO()):
            run(settings, drain_only=True)
            constructor.return_value.close.assert_called_with(2)
            run(settings, drain_only=True, drain_timeout=30)
            constructor.return_value.close.assert_called_with(30)
        self.assertEqual(2, settings.shutdown_timeout)

    def test_real_inflight_delivery_stays_active_and_exit75_never_claims_finished(self):
        receiver = self.acks(dropping=False, held=True)
        settings = self.settings(receiver)
        collector = Collector(settings.collector)
        self.addCleanup(self.close_collector, collector)
        collector.heartbeat()
        self.assertTrue(receiver.received.wait(2))
        started = time.monotonic()
        report = collector.close(0)
        self.assertLess(time.monotonic() - started, .1)
        self.assertTrue(report["delivery_active"])
        self.assertEqual(1, report["pending"])
        with patch.dict(os.environ, {"AGF_COLLECTOR_KEY": KEY}), patch("agf_agentteams.bootstrap.run", return_value=report):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(75, main(["--config", str(self.directory / "injection.json"), "--drain-only"]))
        receiver.release.set()
        collector._thread.join(1)
        self.assertFalse(collector._thread.is_alive())
        self.assertEqual(0, collector.status()["pending"])
        self.assertEqual([], receiver.failures)

    def test_completed_close_reports_actual_acknowledged_counts_within_total_budget(self):
        receiver = self.acks(dropping=False, held=True)
        settings = self.settings(receiver)
        collector = Collector(settings.collector)
        self.addCleanup(self.close_collector, collector)
        collector.heartbeat()
        self.assertTrue(receiver.received.wait(2))
        timer = threading.Timer(.04, receiver.release.set)
        timer.start()
        started = time.monotonic()
        report = collector.close(.18)
        timer.join()
        self.assertLess(time.monotonic() - started, .28)
        self.assertEqual((0, False, 1), (report["pending"], report["delivery_active"], report["sent"]))
        self.assertFalse(collector._thread.is_alive())
        self.assertEqual([], receiver.failures)
