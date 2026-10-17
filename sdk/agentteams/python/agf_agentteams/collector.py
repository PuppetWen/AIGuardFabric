"""Bounded delivery and visible telemetry faults, independent from business calls."""
import random
import threading
import time
from uuid import uuid4

from . import context, delivery
from .events import event
from .instrument import instrument
from .spool import Outbox


class Collector:
    def __init__(self, config, *, autostart=True, on_status=None):
        self._config = config
        self._outbox = Outbox(config)
        self._on_status = on_status
        self._mutex = threading.RLock()
        self._stop, self._wake, self._progress = (threading.Event() for _ in range(3))
        self._thread = None
        self._closing = False
        self._paused = None
        self._last_error = None
        self._last_counts = self._outbox.counts()
        self._sent = self._deduped = self._dropped = self._attempts = 0
        self._durable = None
        self._batch_items = config.batch_items
        if autostart:
            self.start()

    @property
    def config(self):
        """Queue identity is fixed; rotate credentials by closing and reopening the queue."""
        return self._config

    def start(self):
        with self._mutex:
            if self._closing:
                raise RuntimeError("collector is closed")
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="agf-agentteams-delivery", daemon=True)
                self._thread.start()

    def task(self, worker, *, operation="task", task_id=None, carrier=None, capture="omit", classify=None):
        return instrument(self, "task", worker, tag=operation, task_id=task_id, carrier=carrier,
                          capture=capture, classify=classify)

    def call_worker(self, caller, callee, *, operation="call", task_id=None, carrier=None,
                    capture="omit", classify=None):
        return instrument(self, "call", caller, callee, tag=operation, task_id=task_id, carrier=carrier,
                          capture=capture, classify=classify)

    def heartbeat(self):
        # Heartbeats cannot inherit a task or participant from an active business span.
        self._record(event(context.Context(uuid4().hex, uuid4().hex[:16]), "heartbeat", outcome="unknown"))

    def message(self, sender, receiver=None, *, status="unknown"):
        if not isinstance(sender, context.Worker) or receiver is not None and not isinstance(receiver, context.Worker):
            raise ValueError("message participants must be explicit Worker objects")
        if status not in {"success", "error", "unknown"}:
            raise ValueError("message status must describe the actual send or handling outcome")
        self._record(event(context.child(sender), "message", sender, receiver, status))

    def _record(self, value):
        try:
            with self._mutex:
                if self._closing:
                    self._dropped += 1
                    self._last_error = "collector_closed"
                    return
            self._outbox.append(value)
            self._wake.set()
        except Exception:
            self._fault("queue_write_failed")

    def _fault(self, code):
        with self._mutex:
            self._dropped += 1
            self._last_error = code
        self._notify()

    def _diagnostic(self, code):
        with self._mutex:
            self._last_error = code
        self._notify()

    def status(self):
        try:
            counts = self._outbox.counts()
            with self._mutex:
                self._last_counts = counts
        except Exception:
            with self._mutex:
                counts = dict(self._last_counts)
        with self._mutex:
            return {**counts, "sent": self._sent, "deduped": self._deduped, "dropped": self._dropped,
                    "paused": self._paused, "last_error": self._last_error, "durable": self._durable,
                    "closed": self._closing, "delivery_active": bool(self._thread and self._thread.is_alive())}

    def _notify(self):
        if self._on_status is not None:
            try:
                self._on_status(self.status())
            except BaseException:
                pass  # A diagnostic callback cannot replace a business result or exception.

    def _deliver(self, timeout):
        with self._mutex:
            if self._paused:
                return False
            if self.config.identity != self._outbox.config.identity:
                self._paused = self._last_error = "queue_identity_mismatch"
                return False
        batch = self._outbox.batch(self._batch_items)
        if not batch:
            return False
        result = delivery.send(self.config, batch, timeout)
        if result.code == "ack":
            self._outbox.ack(batch)
            with self._mutex:
                self._sent += result.accepted
                self._deduped += result.deduped
                self._durable = result.durable
                self._attempts = 0
                self._last_error = None
        else:
            with self._mutex:
                self._last_error = result.code
                self._attempts = min(self._attempts + 1, 10)
                if result.code in {"http_401", "http_403"}:
                    self._paused = result.code
            permanent = result.code in {"http_400", "http_404", "http_409", "http_413"} or (
                result.code.startswith("http_3"))
            if result.code == "http_429" and len(batch) > 1:
                self._batch_items = max(1, len(batch) // 2)
            delay = max(result.retry_after, min(30, 0.25 * 2 ** self._attempts) * random.uniform(0.8, 1.2))
            self._outbox.defer(batch, delay, result.code, quarantine=permanent)
            if result.code in {"http_409"} or result.code.startswith("http_3"):
                with self._mutex:
                    self._paused = result.code
        self._last_counts = self._outbox.counts()
        self._progress.set()
        self._notify()
        return True

    def _run(self):
        try:
            while not self._stop.is_set():
                try:
                    worked = self._deliver(self.config.request_timeout)
                except Exception:
                    with self._mutex:
                        self._last_error = "delivery_storage_failed"
                    self._notify()
                    worked = False
                if not worked:
                    self._wake.wait(0.2)
                    self._wake.clear()
        finally:
            try:
                self._last_counts = self._outbox.counts()
            except Exception:
                self._last_error = "delivery_storage_failed"
            finally:
                self._outbox.close()
                self._progress.set()

    def flush(self, timeout=5.0):
        if not isinstance(timeout, (int, float)) or not 0 <= timeout <= 60:
            raise ValueError("flush timeout must be between zero and 60 seconds")
        if threading.current_thread() is self._thread:
            return self.status()
        deadline = time.monotonic() + timeout
        self._wake.set()
        while time.monotonic() < deadline:
            report = self.status()
            if report["pending"] == 0 or report["paused"]:
                return report
            if self._thread is None:
                remaining = deadline - time.monotonic()
                if remaining < 0.1:
                    break
                try:
                    if not self._deliver(min(self.config.request_timeout, remaining)):
                        self._wake.wait(min(0.05, max(0, deadline - time.monotonic())))
                        self._wake.clear()
                except Exception:
                    with self._mutex:
                        self._last_error = "delivery_storage_failed"
                    break
            else:
                self._progress.wait(min(0.2, max(0, deadline - time.monotonic())))
                self._progress.clear()
        return self.status()

    def resume(self):
        """Retry unchanged pending events after credentials or permissions were fixed."""
        with self._mutex:
            if self._closing:
                raise RuntimeError("collector is closed")
            self._paused = None
        self._wake.set()

    def close(self, timeout=5.0):
        if not isinstance(timeout, (int, float)) or not 0 <= timeout <= 60:
            raise ValueError("close timeout must be between zero and 60 seconds")
        with self._mutex:
            if self._closing:
                return self.status()
            self._closing = True
        deadline = time.monotonic() + timeout
        # Stop/join consumes the same total budget, even when persisted retry_at is still in the future.
        stop_margin = min(1.0, timeout * 0.25)
        report = self.flush(max(0, deadline - time.monotonic() - stop_margin))
        self._stop.set()
        self._wake.set()
        if self._thread is None:
            self._last_counts = self._outbox.counts()
            self._outbox.close()
        elif threading.current_thread() is not self._thread:
            self._thread.join(max(0, deadline - time.monotonic()))
        active = bool(self._thread and self._thread.is_alive())
        if not active:
            # The delivery thread has saved its final counts and closed SQLite before join returns.
            return self.status()
        # Never wait on the queue lock after the deadline, or pretend a running request has ended.
        return {**report, "delivery_active": True}
