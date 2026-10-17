"""Original entry execution and bounded collector lifecycle; no business retries."""
import json
import math
import os
from pathlib import Path
import runpy
import sys

from ..collector import Collector
from .configuration import StartupError, qualified
from .hooks import Hook


class Session:
    def __init__(self, settings):
        if any(target.module in sys.modules for target in settings.targets):
            raise StartupError("target_already_loaded")
        self.process = os.getpid()
        self.settings = settings
        self.collector = None
        self.hook = None
        self.closed = False
        try:
            self.collector = Collector(settings.collector)
            self.hook = Hook(settings.targets, self.collector)
            self.hook.install()
        except StartupError:
            self.close()
            raise
        except Exception:
            self.close()
            raise StartupError("collector_startup_failed") from None

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.hook is not None:
            try:
                self.hook.close()
            except BaseException:
                self.hook.active = False
                self.hook.restoration_failed = True
        if self.collector is not None and os.getpid() == self.process:
            try:
                return self.collector.close(self.settings.shutdown_timeout)
            except Exception:
                return {"pending": None, "quarantined": None, "delivery_active": None,
                        "last_error": "collector_shutdown_failed"}

    def __enter__(self):
        return self

    def __exit__(self, _kind, _error, _traceback):
        self.close()


def _emit(report):
    try:
        print(json.dumps({"sdk": "agf-agentteams-startup", **report}, sort_keys=True), file=sys.stderr)
    except Exception:
        pass  # A diagnostic output failure cannot replace the original business result/exception.


def run(settings, *, module=None, script=None, arguments=(), drain_only=False, drain_timeout=None):
    if sum((module is not None, script is not None, drain_only)) != 1:
        raise StartupError("one_entry_required")
    if drain_timeout is not None:
        if (not drain_only or type(drain_timeout) not in (int, float)
                or not math.isfinite(drain_timeout)
                or not settings.collector.request_timeout + 0.25 <= drain_timeout <= 60):
            raise StartupError("invalid_drain_timeout")
    if module is not None:
        qualified(module)
        if any(target.module in (module, module + ".__main__") for target in settings.targets):
            raise StartupError("entry_module_target_unsupported")
    if drain_only:
        try:
            collector = Collector(settings.collector)
        except Exception:
            raise StartupError("collector_startup_failed") from None
        report = collector.close(settings.shutdown_timeout if drain_timeout is None else drain_timeout)
        _emit(report)
        return report
    session = Session(settings)
    previous_arguments, previous_path = sys.argv, list(sys.path)
    try:
        if module is not None:
            sys.argv = [module, *arguments]
            runpy.run_module(module, run_name="__main__", alter_sys=True)
        else:
            location = Path(script).absolute()
            sys.argv = [str(location), *arguments]
            sys.path.insert(0, str(location.parent))
            runpy.run_path(str(location), run_name="__main__")
    finally:
        sys.argv, sys.path[:] = previous_arguments, previous_path
        report = session.close()
        report = ({"last_error": "fork_child_not_instrumented"} if report is None else report)
        _emit({**session.hook.report(), **report})
    return report
