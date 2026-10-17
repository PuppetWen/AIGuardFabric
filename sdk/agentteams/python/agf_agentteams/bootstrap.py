"""Run an unchanged Python entry with explicitly configured import-time telemetry."""
import argparse
import json
import sys

from .startup.configuration import StartupError, load
from .startup.runner import run


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Configured AgentTeams Python startup injection")
    parser.add_argument("--config", required=True, help="Noncredential injection JSON")
    entry = parser.add_mutually_exclusive_group(required=True)
    entry.add_argument("--module", help="Original Python entry module")
    entry.add_argument("--script", help="Original Python script")
    entry.add_argument("--drain-only", action="store_true", help="Deliver old queue; no business execution")
    parser.add_argument("--drain-timeout", type=float, help="Delivery-only total budget in seconds")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(arguments)
    trailing = options.arguments[1:] if options.arguments[:1] == ["--"] else options.arguments
    if options.drain_only and trailing:
        parser.error("--drain-only does not accept business arguments")
    if options.drain_timeout is not None and not options.drain_only:
        parser.error("--drain-timeout requires --drain-only")
    try:
        settings = load(options.config)
        report = run(settings, module=options.module, script=options.script,
                     arguments=trailing, drain_only=options.drain_only, drain_timeout=options.drain_timeout)
    except StartupError as error:
        print(json.dumps({"sdk": "agf-agentteams-startup", "error": error.code}), file=sys.stderr)
        return 78
    if options.drain_only and any(report[name] for name in ("pending", "quarantined", "delivery_active")):
        return 75
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
