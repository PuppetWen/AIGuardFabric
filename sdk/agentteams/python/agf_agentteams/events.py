"""Terminal metadata excludes argument values, response bodies and exception text."""
import asyncio
from datetime import datetime, timezone
import re
import time
from uuid import uuid4

from . import context


_OPERATION = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z", re.ASCII)


def operation(value):
    if not isinstance(value, str) or not _OPERATION.fullmatch(value):
        raise ValueError("operation must be a static tag, not user text")
    return value


def status(error=None):
    if error is None:
        return "success"
    if isinstance(error, (TimeoutError, asyncio.CancelledError, GeneratorExit, KeyboardInterrupt)):
        return "unknown"
    return "error"


class Span:
    def __init__(self, collector, kind, worker, target, tag, task_id, carrier, capture):
        self.collector = collector
        self.kind, self.worker, self.target = kind, worker, target
        self.tag, self.capture = tag, capture
        self.context = context.child(worker, task_id=task_id, carrier=carrier)
        self.started = time.monotonic()
        self.finished = False

    def finish(self, outcome, argument_count=0, keyword_count=0):
        if self.finished:
            return
        self.finished = True
        try:
            duration = min(7 * 86_400_000, max(0, round((time.monotonic() - self.started) * 1000)))
            message = None if self.capture == "omit" else (
                f"operation={self.tag}; arguments={argument_count}; keywords={keyword_count}; values=omitted")
            self.collector._record(event(self.context, self.kind, self.worker, self.target, outcome, duration, message))
        except Exception:
            self.collector._fault("event_capture_failed")


def event(span_context, kind, worker=None, target=None, outcome="unknown", duration=None, message=None):
    return {"event_id": uuid4().hex,
            "event_time": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "kind": kind, "from_team": worker.team if worker else None,
            "from_worker": worker.name if worker else None, "to_team": target.team if target else None,
            "to_worker": target.name if target else None, "task_id": span_context.task_id,
            "trace_id": span_context.trace_id, "span_id": span_context.span_id,
            "parent_span_id": span_context.parent_span_id, "status": outcome,
            "duration_ms": duration, "message": message}
