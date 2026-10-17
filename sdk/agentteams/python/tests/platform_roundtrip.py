"""Opt-in real platform/SQL probe. Credentials arrive only on stdin; output is safe metrics."""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agf_agentteams import Collector, Config, Worker, inject

ROOT_OWNERS = {"AIGuardFabric requirements completion 20260920",
               "AIGuardFabric requirements completion local 20260920"}
OWNER_PREFIX = "AIGuardFabric AgentTeams SDK platform test "
PRIVATE_VALUE = "owned-sdk-user@example.invalid; phone=13800138000"


def no_reparse(path):
    for candidate in (path, *path.parents):
        metadata = candidate.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ValueError("reparse_path")


def owned_case(request, *, create=False):
    root = Path(os.environ["AGF_SDK_TEST_DIR"])
    if not root.is_absolute() or root.name not in {"codex-requirements-20260920", "requirements-20260920"}:
        raise ValueError("invalid_task_root")
    no_reparse(root)
    no_reparse(root / "task-owner.txt")
    if (root / "task-owner.txt").read_text(encoding="utf-8-sig").strip() not in ROOT_OWNERS:
        raise ValueError("invalid_task_owner")
    run_id = request["run_id"]
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("invalid_run_id")
    directory = root / ("agentteams-sdk-case-" + run_id)
    if create and not directory.exists():
        directory.mkdir()
        (directory / "task-owner.txt").write_text(OWNER_PREFIX + run_id, encoding="utf-8")
    if not directory.exists() and request["action"] == "cleanup":
        return directory
    no_reparse(directory)
    no_reparse(directory / "task-owner.txt")
    if (directory / "task-owner.txt").read_text(encoding="utf-8") != OWNER_PREFIX + run_id:
        raise ValueError("invalid_case_owner")
    return directory


def clean_case(request):
    directory = owned_case(request)
    if not directory.exists():
        return {"cleaned": True}
    for current, directories, files in os.walk(directory):
        for name in directories + files:
            no_reparse(Path(current) / name)
    for child in directory.iterdir():
        if child.name == "task-owner.txt":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    (directory / "task-owner.txt").unlink()
    directory.rmdir()
    return {"cleaned": True}


def configuration(request, directory):
    address = urlsplit(request["platform_url"])
    if (address.scheme != "http" or address.hostname != "127.0.0.1" or not address.port
            or address.path or address.query or address.fragment or address.username or address.password):
        raise ValueError("platform_must_be_owned_loopback")
    if request["expected_mocked"] is not True:
        raise ValueError("platform_inventory_must_be_explicit_mock")
    phase = request["action"]
    if phase not in {"business", "revoked", "disabled"}:
        raise ValueError("invalid_phase")
    return Config(request["platform_url"], request["source_id"], request["binding_id"],
                  request["collector_key"], directory / phase, expected_scope=request["scope_id"],
                  expected_mocked=True, max_bytes=64 * 1024, max_disk_bytes=512 * 1024,
                  batch_bytes=16 * 1024, request_timeout=2)


def contains_private(config):
    raw = (config.spool_dir / "events.sqlite3").read_bytes()
    forbidden = [config.collector_key, PRIVATE_VALUE, "owned-sdk-user@example.invalid", "13800138000"]
    return any(value.encode() in raw for value in forbidden)


def business(config):
    collector = Collector(config, autostart=False)
    first, second = Worker("worker-demo", "my-team"), Worker("sdk-receiver", "sdk-receiving-team")
    calls = {"root": 0, "child": 0, "handoff": 0, "send": 0, "error": 0, "timeout": 0}
    carrier = None
    original = object()
    failed, timed_out = RuntimeError(PRIVATE_VALUE), TimeoutError(PRIVATE_VALUE)

    @collector.task(second, operation="sdk.child", carrier=lambda: carrier)
    def child(argument):
        calls["child"] += 1
        return argument

    @collector.call_worker(first, second, operation="sdk.handoff")
    def handoff(argument):
        nonlocal carrier
        calls["handoff"] += 1
        carrier = inject()
        assert carrier and carrier["task_id"] == "sdk-root-task"
        return child(argument)

    @collector.task(first, operation="sdk.root", task_id="sdk-root-task")
    def root(argument, private_argument):
        calls["root"] += 1
        assert private_argument == PRIVATE_VALUE
        result = handoff(argument)
        calls["send"] += 1  # A real test business send completes before its audit is recorded.
        collector.message(first, second, status="success")
        return result

    @collector.task(first, operation="sdk.failure", task_id="sdk-error-task")
    def failure():
        calls["error"] += 1
        raise failed

    @collector.task(second, operation="sdk.timeout", task_id="sdk-timeout-task")
    def timeout():
        calls["timeout"] += 1
        raise timed_out

    try:
        assert root(original, PRIVATE_VALUE) is original
        for function, expected in ((failure, failed), (timeout, timed_out)):
            try:
                function()
            except BaseException as error:
                assert error is expected
            else:
                raise AssertionError("business_exception_lost")
        collector.heartbeat()
        frozen = collector._outbox.batch(100)
        assert len(frozen) == 7 and not contains_private(config)
        first_report = collector.flush(8)
        assert first_report["pending"] == 0 and first_report["sent"] == 7 and first_report["durable"] is True
        # Model a lost acknowledgement by re-enqueuing identical retained events, never business functions.
        for _, value in frozen:
            collector._outbox.append(value)
        second_report = collector.flush(8)
        assert second_report["pending"] == 0 and second_report["deduped"] == 7
        assert all(count == 1 for count in calls.values()) and not contains_private(config)
        return {"events": 7, "durable": True, "deduped": 7, "business_once": True,
                "return_identity": True, "exception_identity": True, "private_omitted": True}
    finally:
        collector.close(0)


def blocked(config, action):
    collector = Collector(config, autostart=False)
    expected = "http_401" if action == "revoked" else "http_409"
    calls = 0
    original = object()

    @collector.task(Worker("worker-demo", "my-team"), operation="sdk.blocked")
    def application(argument, private_argument):
        nonlocal calls
        calls += 1
        assert private_argument == PRIVATE_VALUE
        return argument

    try:
        assert application(original, PRIVATE_VALUE) is original
        collector.heartbeat()
        report = collector.flush(5)
        assert calls == 1 and report["sent"] == 0 and report["paused"] == expected
        assert report["pending"] == (2 if action == "revoked" else 0)
        assert report["quarantined"] == (0 if action == "revoked" else 2)
        assert not contains_private(config)
    finally:
        collector.close(0)
    reopened = Collector(config, autostart=False)
    try:
        retained = reopened.status()
        assert retained["pending"] == report["pending"] and retained["quarantined"] == report["quarantined"]
    finally:
        reopened.close(0)
    return {"business_once": True, "private_omitted": True, "sent": 0, "paused": expected,
            "pending": retained["pending"], "quarantined": retained["quarantined"], "retained_after_reopen": True}


def main():
    request = json.loads(sys.stdin.read(64 * 1024))
    if request["action"] == "cleanup":
        return clean_case(request)
    directory = owned_case(request, create=True)
    config = configuration(request, directory)
    return business(config) if request["action"] == "business" else blocked(config, request["action"])


if __name__ == "__main__":
    try:
        report = main()
    except BaseException as error:
        # No traceback, exception text, credential, carrier or request body escapes into gate logs.
        print(json.dumps({"ok": False, "error_type": type(error).__name__}))
        sys.exit(1)
    print(json.dumps({"ok": True, **report}, sort_keys=True))
