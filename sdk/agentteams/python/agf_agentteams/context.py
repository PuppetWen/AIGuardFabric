"""Trace propagation contains identifiers only, never arguments or credentials."""
from contextvars import ContextVar
from dataclasses import dataclass
import re
from uuid import uuid4


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_TRACE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_SPAN = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)


@dataclass(frozen=True)
class Worker:
    name: str
    team: str | None = None

    def __post_init__(self):
        if (not isinstance(self.name, str) or not self.name or len(self.name.encode()) > 512
                or any(ord(character) < 32 for character in self.name)):
            raise ValueError("Worker name must match an inventoried Worker")
        if self.team is not None and (not isinstance(self.team, str) or not self.team
                or len(self.team.encode()) > 512 or any(ord(character) < 32 for character in self.team)):
            raise ValueError("Team name must match the Worker's inventory membership")


@dataclass(frozen=True)
class Context:
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    task_id: str | None = None
    worker: Worker | None = None


current: ContextVar[Context | None] = ContextVar("agf_agentteams_context", default=None)


def identifier(value: str | None):
    if value is not None and (not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)):
        raise ValueError("task_id must be an opaque identifier, not user content")
    return value


def extract(carrier):
    """Reject malformed or unknown carrier fields; do not invent a parent relation."""
    if type(carrier) is not dict or set(carrier) - {"trace_id", "span_id", "task_id"}:
        return None
    trace, span = carrier.get("trace_id"), carrier.get("span_id")
    if (not isinstance(trace, str) or not _TRACE.fullmatch(trace) or int(trace, 16) == 0
            or not isinstance(span, str) or not _SPAN.fullmatch(span) or int(span, 16) == 0):
        return None
    try:
        task = identifier(carrier.get("task_id"))
    except ValueError:
        return None
    return Context(trace, span, task_id=task)


def inject():
    context = current.get()
    if context is None:
        return None
    carrier = {"trace_id": context.trace_id, "span_id": context.span_id}
    if context.task_id is not None:
        carrier["task_id"] = context.task_id
    return carrier


def child(worker=None, *, carrier=None, task_id=None):
    parent = extract(carrier) if carrier is not None else current.get()
    if not isinstance(parent, Context):
        parent = None
    return Context(parent.trace_id if parent else uuid4().hex, uuid4().hex[:16],
                   parent.span_id if parent else None,
                   identifier(task_id) if task_id is not None else parent.task_id if parent else None,
                   worker if worker is not None else parent.worker if parent else None)
