"""Exact-module import hook: no eager import, source rewrite, or argument capture."""
from functools import wraps
import importlib.abc
import importlib.machinery
import inspect
import os
import sys
from types import ModuleType

from ..classifiers import mcp_result
from .configuration import StartupError


def _fork_safe(original, wrapped, process):
    # An inherited SQLite queue/thread belongs to the parent process, never a forked child.
    if inspect.iscoroutinefunction(original):
        @wraps(original)
        async def asynchronous(*args, **kwargs):
            return await (wrapped if os.getpid() == process else original)(*args, **kwargs)
        return asynchronous

    @wraps(original)
    def synchronous(*args, **kwargs):
        return (wrapped if os.getpid() == process else original)(*args, **kwargs)
    return synchronous


class _Loader(importlib.abc.Loader):
    def __init__(self, original, hook, name):
        self.original, self.hook, self.name = original, hook, name

    def create_module(self, spec):
        return self.original.create_module(spec)

    def exec_module(self, module):
        self.original.exec_module(module)  # Preserve the original import exception and its identity.
        self.hook.patch(module)

    def __getattr__(self, name):
        return getattr(self.original, name)


class Hook(importlib.abc.MetaPathFinder):
    def __init__(self, targets, collector):
        self.collector = collector
        self.targets = {}
        for target in targets:
            self.targets.setdefault(target.module, []).append(target)
        self.process = os.getpid()
        self.installed = set()
        self.patches = []
        self.active = False
        self.restoration_failed = False

    def install(self):
        if self.active or any(name in sys.modules for name in self.targets):
            raise StartupError("target_already_loaded")
        sys.meta_path.insert(0, self)
        self.active = True

    def find_spec(self, fullname, path=None, target=None):
        if not self.active or fullname not in self.targets or os.getpid() != self.process:
            return None
        for finder in tuple(sys.meta_path):
            if finder is self:
                continue
            method = getattr(finder, "find_spec", None)
            spec = method(fullname, path, target) if method is not None else None
            if spec is not None:
                if type(spec.loader) is not importlib.machinery.SourceFileLoader:
                    raise StartupError("unsupported_target_loader")
                spec.loader = _Loader(spec.loader, self, fullname)
                return spec
        return None  # Let Python emit its normal ModuleNotFoundError for an absent module.

    def _prepare(self, module, target):
        if type(module) is not ModuleType:
            raise StartupError("unsupported_target_owner")
        owner = module
        parts = target.attribute.split(".")
        for part in parts[:-1]:
            owner = vars(owner).get(part)
            if type(owner) is not type:
                raise StartupError("unsupported_target_owner")
        name = parts[-1]
        original = vars(owner).get(name)
        descriptor = type(original) if type(original) in (staticmethod, classmethod) else None
        function = original.__func__ if descriptor is not None else original
        if not inspect.isfunction(function) or function.__module__ != module.__name__:
            raise StartupError("unsupported_target_callable")
        options = {"operation": target.operation, "capture": "omit",
                   "classify": mcp_result if target.classifier == "mcp_result" else None}
        decorate = (self.collector.task(target.worker, **options) if target.kind == "task" else
                    self.collector.call_worker(target.worker, target.callee, **options))
        wrapped = _fork_safe(function, decorate(function), self.process)
        replacement = descriptor(wrapped) if descriptor is not None else wrapped
        return owner, name, original, replacement

    def patch(self, module):
        # Build all replacements first: an invalid target cannot leave a half-patched module.
        prepared = [self._prepare(module, target) for target in self.targets[module.__name__]]
        applied = []
        try:
            for owner, name, original, replacement in prepared:
                setattr(owner, name, replacement)
                applied.append((owner, name, original, replacement))
        except BaseException:
            for owner, name, original, _replacement in reversed(applied):
                setattr(owner, name, original)
            raise
        self.patches.extend(applied)
        self.installed.update((module.__name__, target.attribute)
                              for target in self.targets[module.__name__])

    def report(self):
        configured = sum(len(targets) for targets in self.targets.values())
        return {"configured_targets": configured, "installed_targets": len(self.installed),
                "unloaded_targets": configured - len(self.installed),
                "restoration_failed": self.restoration_failed}

    def close(self):
        sys.meta_path[:] = [finder for finder in sys.meta_path if finder is not self]
        for owner, name, original, replacement in reversed(self.patches):
            try:
                if vars(owner).get(name) is replacement:
                    setattr(owner, name, original)
            except BaseException:
                # A business module can change its own class/setattr after installation.
                # Restore other entries, report a fixed flag, and preserve the business exit/error.
                self.restoration_failed = True
        self.active = False
