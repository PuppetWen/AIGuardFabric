"""Owned temporary directories and a real loopback-only telemetry receiver."""
from collections import deque
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import threading
import unittest
from uuid import uuid4

from agf_agentteams import Collector, Config

SOURCE = "00000000-0000-4000-8000-000000000001"
BINDING = "00000000-0000-4000-8000-000000000002"
SCOPE = "00000000-0000-4000-8000-000000000003"
KEY = "agf_TEST_ONLY_collector_credential"


class Receiver:
    def __init__(self):
        self.replies = deque()
        self.bodies, self.events = [], {}
        self.mutex = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_arguments):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with receiver.mutex:
                    receiver.bodies.append(raw)
                    reply = receiver.replies.popleft() if receiver.replies else 200
                    payload = json.loads(raw)
                    accepted = 0
                    if reply in (200, "drop", "bad_ack", "truncated"):
                        for item in payload["events"]:
                            if item["event_id"] not in receiver.events:
                                receiver.events[item["event_id"]] = item
                                accepted += 1
                    result = {"received": len(payload["events"]), "accepted": accepted,
                              "deduped": len(payload["events"]) - accepted, "scopeId": SCOPE,
                              "mocked": True, "durable": True, "authorizationStatus": "unknown"}
                if reply == "drop":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                code = reply if type(reply) is int else 200
                if isinstance(reply, tuple):
                    code = reply[0]
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                if reply == "truncated":
                    self.send_header("Transfer-Encoding", "chunked")
                if isinstance(reply, tuple):
                    self.send_header("Location", reply[1])
                self.end_headers()
                if self.headers.get("Authorization") != "Bearer " + KEY:
                    raise AssertionError("Synthetic collector did not use its configured credential")
                if reply == "truncated":
                    self.wfile.write(b"10\r\n{}")
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                if reply == "bad_ack":
                    result["received"] += 1
                if code != 200:
                    result = {"error": "synthetic_rejection"}
                self.wfile.write(json.dumps(result).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(1)


class Case(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.environ.get("AGF_SDK_TEST_DIR", Path(__file__).resolve().parents[1] / ".tmp/sdk-tests"))
        self.root = self.root.absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self.run_id = uuid4().hex
        self.directory = self.root / ("case-" + self.run_id)
        self.directory.mkdir()
        self.owner = "AIGuardFabric Python SDK test " + self.run_id
        (self.directory / "task-owner.txt").write_text(self.owner, encoding="utf-8")
        self.addCleanup(self._clean_owned_directory)

    def _clean_owned_directory(self):
        absolute = self.directory.absolute()
        if (absolute.parent != self.root or absolute.name != "case-" + self.run_id
                or (absolute / "task-owner.txt").read_text(encoding="utf-8") != self.owner):
            raise AssertionError("Unexpected task directory or owner; cleanup refused")
        for parent in (absolute, *absolute.parents):
            metadata = parent.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise AssertionError("Reparse path; cleanup refused")
        for current, directories, files in os.walk(absolute):
            for name in directories + files:
                child = Path(current) / name
                metadata = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                    raise AssertionError("Reparse descendant; cleanup refused")
        # Keep the owner marker until every child is removed, including on a Windows file-lock failure.
        for child in absolute.iterdir():
            if child.name == "task-owner.txt":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        (absolute / "task-owner.txt").unlink()
        absolute.rmdir()

    def receiver(self):
        receiver = Receiver()
        self.addCleanup(receiver.close)
        return receiver

    def config(self, receiver=None, **overrides):
        config = Config(receiver.url if receiver else "http://127.0.0.1:1", SOURCE, BINDING, KEY,
                        self.directory / "queue", max_bytes=64 * 1024, max_disk_bytes=512 * 1024,
                        batch_bytes=4 * 1024, request_timeout=0.2, expected_scope=SCOPE, expected_mocked=True)
        return replace(config, **overrides)

    def collector(self, receiver=None, *, autostart=False, on_status=None, **overrides):
        collector = Collector(self.config(receiver, **overrides), autostart=autostart, on_status=on_status)
        self.addCleanup(self._close_collector, collector)
        return collector

    @staticmethod
    def _close_collector(collector):
        collector.close(0)
        if collector._thread:
            collector._thread.join(1)
            if collector._thread.is_alive():
                raise AssertionError("Owned telemetry thread still uses the queue; cleanup refused")
