"""New owned test cases and real literal-loopback collector; never touches old SDK cases."""
from collections import deque
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import unittest
from uuid import uuid4

from agf_agentteams.startup.configuration import load
from agf_agentteams.startup.runner import Session

SOURCE = "00000000-0000-4000-8000-000000000001"
BINDING = "00000000-0000-4000-8000-000000000002"
SCOPE = "00000000-0000-4000-8000-000000000003"
OTHER = "00000000-0000-4000-8000-000000000004"
KEY = "agf_SYNTHETIC_STARTUP_ONLY_collector"
MODULE = "startup_business.worker"
PYTHON_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = PYTHON_ROOT / "examples"


def plain_tree(path):
    for item in (path, *path.parents):
        metadata = item.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise AssertionError("Test reparse ancestor; refused")
    for current, directories, files in os.walk(path):
        for name in directories + files:
            metadata = (Path(current) / name).stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise AssertionError("Test reparse descendant; refused")


class Receiver:
    def __init__(self, *, allowed=False, replies=()):
        self.allowed, self.replies = allowed, deque(replies)
        self.scope, self.mocked = SCOPE, True
        self.events, self.bodies, self.failures = {}, [], []
        self.mutex = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                with receiver.mutex:
                    if (self.path != f"/api/v1/alicloud/agentteams/audit-sources/{SOURCE}/events"
                            or self.headers.get("Authorization") != "Bearer " + KEY):
                        receiver.failures.append("unexpected_collector_identity")
                        self.send_error(403)
                        return
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 256 * 1024:
                        receiver.failures.append("unexpected_batch_size")
                        self.send_error(413)
                        return
                    payload = json.loads(self.rfile.read(size))
                    receiver.bodies.append(payload)
                    if payload.get("binding_id") != BINDING:
                        receiver.failures.append("unexpected_binding")
                    mode = receiver.replies.popleft() if receiver.replies else (200 if receiver.allowed else 403)
                    accepted = 0
                    if mode in (200, "drop", "wrong_scope"):
                        for item in payload["events"]:
                            previous = receiver.events.get(item["event_id"])
                            if previous is not None and previous != item:
                                receiver.failures.append("event_id_body_changed")
                            if previous is None:
                                receiver.events[item["event_id"]] = item
                                accepted += 1
                    if mode == "drop":
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    code = mode if type(mode) is int else 200
                    reply = {"received": len(payload["events"]), "accepted": accepted,
                             "deduped": len(payload["events"]) - accepted,
                             "scopeId": OTHER if mode == "wrong_scope" else receiver.scope,
                             "mocked": receiver.mocked, "durable": True, "authorizationStatus": "unknown"}
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(reply if code == 200 else {"error": "synthetic_denial"}).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(1)


class Case(unittest.TestCase):
    def setUp(self):
        root = os.environ.get("AGF_SDK_INJECTION_TEST_DIR")
        if not root or not Path(root).is_absolute():
            raise AssertionError("Dedicated owned startup-test root must be supplied")
        self.root = Path(root)
        suffix = self.root.name.removeprefix("sdk-injection-validation-")
        if (not re.fullmatch(r"[0-9a-f]{32}", suffix)
                or (self.root / ".owner").read_text(encoding="utf-8") !=
                "AIGuardFabric SDK injection validation " + suffix):
            raise AssertionError("Dedicated test root owner mismatch")
        plain_tree(self.root)
        self.run_id = uuid4().hex
        self.directory = self.root / ("case-" + self.run_id)
        self.directory.mkdir()
        self.owner = "AIGuardFabric SDK startup case " + self.run_id
        (self.directory / ".owner").write_text(self.owner, encoding="utf-8")
        self.addCleanup(self._cleanup)
        self.previous_path = list(sys.path)
        sys.path.insert(0, str(EXAMPLES))
        self.addCleanup(self._restore_imports)

    def _restore_imports(self):
        sys.path[:] = self.previous_path
        for name in tuple(sys.modules):
            if name == "startup_business" or name.startswith("startup_business.") or name.startswith("owned_import_"):
                del sys.modules[name]
        importlib.invalidate_caches()

    def _cleanup(self):
        if (self.directory.absolute().parent != self.root or self.directory.name != "case-" + self.run_id
                or (self.directory / ".owner").read_text(encoding="utf-8") != self.owner):
            raise AssertionError("Case owner mismatch; cleanup refused")
        plain_tree(self.directory)
        for child in self.directory.iterdir():
            if child.name == ".owner":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        (self.directory / ".owner").unlink()
        self.directory.rmdir()

    def receiver(self, **options):
        receiver = Receiver(**options)
        self.addCleanup(receiver.close)
        return receiver

    def value(self, receiver, names=("echo",), **overrides):
        value = {"version": 1, "shutdown_timeout": 1.5,
                 "collector": {"platform_url": receiver.url, "source_id": SOURCE, "binding_id": BINDING,
                               "expected_scope": SCOPE, "expected_mocked": True,
                               "spool_dir": str(self.directory / "queue"), "max_items": 100,
                               "max_bytes": 64 * 1024, "max_disk_bytes": 512 * 1024,
                               "batch_bytes": 16 * 1024, "request_timeout": 0.2},
                 "targets": [{"module": MODULE, "attribute": name, "kind": "task",
                              "worker": {"name": "worker-a", "team": "team-a"}, "operation": name}
                             for name in names]}
        value.update(overrides)
        return value

    def write(self, value):
        path = self.directory / "injection.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def settings(self, receiver, names=("echo",), **overrides):
        return load(self.write(self.value(receiver, names, **overrides)), environment={"AGF_COLLECTOR_KEY": KEY})

    def session(self, receiver, names=("echo",), **overrides):
        session = Session(self.settings(receiver, names, **overrides))
        self.addCleanup(self._close, session)
        return session

    @staticmethod
    def _close(session):
        session.close()
        thread = session.collector._thread if session.collector is not None else None
        if thread is not None:
            thread.join(1)
            if thread.is_alive():
                raise AssertionError("Owned collector still uses queue; cleanup refused")

    def events(self):
        database = (self.directory / "queue/events.sqlite3").as_uri() + "?mode=ro"
        with closing(sqlite3.connect(database, uri=True)) as connection:
            return [json.loads(row[0]) for row in connection.execute("SELECT payload FROM events ORDER BY sequence")]

    def launch(self, path, *arguments):
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY"}:
                del environment[name]
        environment.update(AGF_COLLECTOR_KEY=KEY, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1",
                           PYTHONPATH=os.pathsep.join((str(PYTHON_ROOT), str(EXAMPLES))))
        return subprocess.run([sys.executable, "-m", "agf_agentteams.bootstrap", "--config", str(path), *arguments],
                              env=environment, cwd=PYTHON_ROOT, capture_output=True, text=True,
                              encoding="utf-8", timeout=15, check=False)
