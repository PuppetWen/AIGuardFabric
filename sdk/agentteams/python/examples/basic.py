"""Run an explicit local task and send its telemetry to the configured source."""
import json
import os
from pathlib import Path

from agf_agentteams import Collector, Config, Worker


def required(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Set {name} before running this example")
    return value


def main():
    mode = required("AGF_EXPECTED_MOCKED").lower()
    if mode not in {"true", "false"}:
        raise ValueError("AGF_EXPECTED_MOCKED must be explicitly true or false")
    config = Config(
        platform_url=required("AGF_PLATFORM_URL"), source_id=required("AGF_SOURCE_ID"),
        binding_id=required("AGF_BINDING_ID"), collector_key=required("AGF_COLLECTOR_KEY"),
        spool_dir=Path(required("AGF_SPOOL_DIR")), expected_scope=required("AGF_SCOPE_ID"),
        expected_mocked=mode == "true",
    )
    caller = Worker(required("AGF_CALLER_WORKER"), required("AGF_CALLER_TEAM"))
    callee = Worker(required("AGF_CALLEE_WORKER"), required("AGF_CALLEE_TEAM"))
    collector = Collector(config)

    @collector.call_worker(caller, callee, operation="calculate-price")
    def calculate(quantity):
        return quantity * 12

    @collector.task(caller, operation="quote", task_id="sdk-example-quote")
    def quote(quantity):
        return calculate(quantity)

    try:
        print(json.dumps({"business_result": quote(3)}))
    finally:
        report = collector.close(5)
        print(json.dumps({"telemetry_health": report}, sort_keys=True))
    return 0 if report["pending"] == 0 and report["quarantined"] == 0 and report["dropped"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
