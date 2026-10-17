"""Bounded, noncredential startup configuration. Errors contain fixed codes only."""
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

from ..config import Config
from ..context import Worker
from ..events import operation

_PART = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_COLLECTOR = {"platform_url", "source_id", "binding_id", "expected_scope", "expected_mocked",
              "spool_dir", "max_items", "max_bytes", "max_disk_bytes", "batch_items", "batch_bytes",
              "request_timeout"}
_REQUIRED = {"platform_url", "source_id", "binding_id", "expected_scope", "expected_mocked", "spool_dir"}


class StartupError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Target:
    module: str
    attribute: str
    kind: str
    worker: Worker
    callee: Worker | None
    operation: str
    classifier: str


@dataclass(frozen=True)
class Settings:
    collector: Config
    targets: tuple[Target, ...]
    shutdown_timeout: float


def object_fields(value, allowed, required):
    if type(value) is not dict or set(value) - allowed or not required <= set(value):
        raise StartupError("invalid_configuration_fields")


def qualified(value):
    if (type(value) is not str or len(value) > 256 or not value
            or any(not _PART.fullmatch(part) or part.startswith("__") for part in value.split("."))):
        raise StartupError("invalid_qualified_name")
    return value


def _worker(value):
    object_fields(value, {"name", "team"}, {"name"})
    try:
        return Worker(value["name"], value.get("team"))
    except (TypeError, ValueError):
        raise StartupError("invalid_worker_mapping") from None


def _target(value):
    object_fields(value, {"module", "attribute", "kind", "worker", "callee", "operation", "classifier"},
                  {"module", "attribute", "kind", "worker", "operation"})
    module, attribute = qualified(value["module"]), qualified(value["attribute"])
    forbidden = set(sys.stdlib_module_names) | set(sys.builtin_module_names) | {"agf_agentteams"}
    if module.split(".")[0] in forbidden:
        raise StartupError("unsupported_target_module")
    kind = value["kind"]
    if kind not in ("task", "call") or ("callee" in value) != (kind == "call"):
        raise StartupError("invalid_target_kind")
    classifier = value.get("classifier", "completion")
    if classifier not in ("completion", "mcp_result"):
        raise StartupError("invalid_classifier")
    try:
        tag = operation(value["operation"])
    except (TypeError, ValueError):
        raise StartupError("invalid_operation") from None
    return Target(module, attribute, kind, _worker(value["worker"]),
                  _worker(value["callee"]) if kind == "call" else None, tag, classifier)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StartupError("duplicate_configuration_field")
        result[key] = value
    return result


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def plain_path(path):
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            metadata = parent.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise StartupError("reparse_spool_path")


def load(path, *, environment=None):
    try:
        with open(path, "rb") as stream:
            encoded = stream.read(64 * 1024 + 1)
        if len(encoded) > 64 * 1024:
            raise StartupError("configuration_too_large")
        value = json.loads(encoded.decode("utf-8-sig"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(StartupError("invalid_number")))
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise StartupError("configuration_unreadable") from None
    object_fields(value, {"version", "collector", "targets", "shutdown_timeout"},
                  {"version", "collector", "targets"})
    if type(value["version"]) is not int or value["version"] != 1:
        raise StartupError("unsupported_configuration_version")
    collector = value["collector"]
    object_fields(collector, _COLLECTOR, _REQUIRED)
    if any(type(collector[name]) is not str for name in _REQUIRED - {"expected_mocked"}):
        raise StartupError("invalid_collector_configuration")
    if type(collector["expected_mocked"]) is not bool or not collector["expected_scope"]:
        raise StartupError("expected_scope_and_mode_required")
    if type(collector["spool_dir"]) is not str or not Path(collector["spool_dir"]).is_absolute():
        raise StartupError("absolute_spool_required")
    timeout = collector.get("request_timeout", 5.0)
    shutdown = value.get("shutdown_timeout", 6.0)
    if (not _number(timeout) or not 0.1 <= timeout <= 5
            or not _number(shutdown) or not timeout + 0.25 <= shutdown <= 10):
        raise StartupError("invalid_transport_budget")
    targets = value["targets"]
    if type(targets) is not list or not 1 <= len(targets) <= 32:
        raise StartupError("invalid_target_count")
    parsed = tuple(_target(target) for target in targets)
    if len({(target.module, target.attribute) for target in parsed}) != len(parsed):
        raise StartupError("duplicate_target")
    key = (os.environ if environment is None else environment).get("AGF_COLLECTOR_KEY")
    try:
        config = Config(**collector, collector_key=key)
        plain_path(config.spool_dir)
    except (OSError, TypeError, ValueError):
        raise StartupError("invalid_collector_configuration") from None
    return Settings(config, parsed, float(shutdown))
