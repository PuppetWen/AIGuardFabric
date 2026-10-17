import asyncio
import json
from unittest.mock import patch

from agf_agentteams import Worker, inject
from agf_agentteams.classifiers import mcp_result
from support import Case

WORKER = Worker("worker-a", "team-a")
OTHER = Worker("worker-b", "team-b")


class InstrumentTests(Case):
    def events(self, collector):
        return [event for _, event in collector._outbox.batch(100)]

    def test_closing_an_unstarted_generator_never_records_business_execution(self):
        collector = self.collector()
        calls = []

        @collector.task(WORKER)
        def values():
            calls.append(1)
            yield 1

        stream = values()
        with self.assertRaises(TypeError):
            stream.send("invalid")
        stream.close()
        with self.assertRaises(StopIteration):
            next(stream)
        self.assertEqual([], calls)
        self.assertEqual([], self.events(collector))

    def test_closing_an_unstarted_async_generator_never_records_business_execution(self):
        collector = self.collector()
        calls = []

        @collector.task(WORKER)
        async def values():
            calls.append(1)
            yield 1

        async def run():
            stream = values()
            with self.assertRaises(TypeError):
                await stream.asend("invalid")
            await stream.aclose()
            with self.assertRaises(StopAsyncIteration):
                await stream.__anext__()

        asyncio.run(run())
        self.assertEqual([], calls)
        self.assertEqual([], self.events(collector))

    def test_stream_duration_excludes_waiting_before_the_first_valid_consumer_step(self):
        collector = self.collector()

        @collector.task(WORKER)
        def values():
            yield 1

        with patch("agf_agentteams.events.time.monotonic", side_effect=[0, 100, 100.002]):
            stream = values()
            self.assertEqual(1, next(stream))
            with self.assertRaises(StopIteration):
                next(stream)
        self.assertEqual(2, self.events(collector)[0]["duration_ms"])

    def test_return_and_exception_identity_are_preserved_and_sensitive_values_are_omitted(self):
        collector = self.collector()
        original = object()
        secret = "Bearer SECRET_TEST_TOKEN email=private@example.test password=SECRET"
        failure = ValueError(secret)

        @collector.task(WORKER, capture="shape", operation="safe_operation")
        def success(value, **options):
            return original

        @collector.task(WORKER)
        def fail():
            raise failure

        self.assertIs(original, success(secret, private_keyword=secret))
        with self.assertRaises(ValueError) as observed:
            fail()
        self.assertIs(failure, observed.exception)
        events = self.events(collector)
        self.assertEqual(["success", "error"], [event["status"] for event in events])
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn("private_keyword", json.dumps(events))
        self.assertIn("values=omitted", events[0]["message"])

    def test_nested_workers_propagate_only_real_parent_edges_and_one_call(self):
        collector = self.collector()
        result = object()

        @collector.task(OTHER)
        def child():
            return result

        @collector.call_worker(WORKER, OTHER)
        def bridge():
            return child()

        @collector.task(WORKER, task_id="task-1")
        def root():
            return bridge()

        self.assertIs(result, root())
        child_event, call_event, root_event = self.events(collector)
        self.assertEqual({"task-1"}, {event["task_id"] for event in self.events(collector)})
        self.assertEqual(1, len({event["trace_id"] for event in self.events(collector)}))
        self.assertEqual(root_event["span_id"], call_event["parent_span_id"])
        self.assertEqual(call_event["span_id"], child_event["parent_span_id"])
        self.assertEqual(["task", "call", "task"], [event["kind"] for event in self.events(collector)])
        self.assertIsNone(inject())

    def test_diagnostic_cancellation_cannot_replace_the_business_return(self):
        def diagnostic(_report):
            raise asyncio.CancelledError("diagnostic-only")

        collector = self.collector(on_status=diagnostic)
        original = object()
        wrapped = collector.task(WORKER)(lambda: original)
        with patch.object(collector._outbox, "append", side_effect=OSError("owned storage fault")):
            self.assertIs(original, wrapped())
        self.assertEqual(1, collector.status()["dropped"])

    def test_classifier_and_carrier_cancellation_do_not_cancel_business(self):
        collector = self.collector()
        original = object()

        def cancellation(*_arguments):
            raise asyncio.CancelledError("telemetry-only")

        wrapped = collector.task(WORKER, carrier=cancellation, classify=cancellation)(lambda: original)
        self.assertIs(original, wrapped())
        self.assertEqual("unknown", self.events(collector)[0]["status"])
        self.assertIsNone(self.events(collector)[0]["parent_span_id"])

    def test_real_async_cancellation_preserves_original_exception_and_records_unknown(self):
        collector = self.collector()
        original = asyncio.CancelledError("business cancellation")

        @collector.task(WORKER)
        async def function():
            raise original

        with self.assertRaises(asyncio.CancelledError) as observed:
            asyncio.run(function())
        self.assertIs(original, observed.exception)
        self.assertEqual("unknown", self.events(collector)[0]["status"])

    def test_stream_is_lazy_and_invalid_initial_send_does_not_finalize_a_live_generator(self):
        collector = self.collector()
        advanced, original = [], object()

        @collector.task(WORKER)
        def values():
            advanced.append(1)
            received = yield original
            return received

        stream = values()
        self.assertEqual([], advanced)
        with self.assertRaises(TypeError):
            stream.send("invalid before first yield")
        self.assertEqual([], self.events(collector))
        self.assertIs(original, next(stream))
        with self.assertRaises(StopIteration) as observed:
            stream.send("original return")
        self.assertEqual("original return", observed.exception.value)
        self.assertEqual([1], advanced)
        self.assertEqual(["success"], [event["status"] for event in self.events(collector)])

    def test_early_stream_close_keeps_backpressure_and_records_unknown(self):
        collector = self.collector()
        advanced = []

        @collector.task(WORKER)
        def values():
            advanced.append(1)
            yield 1
            advanced.append(2)
            yield 2

        stream = values()
        self.assertEqual(1, next(stream))
        stream.close()
        self.assertEqual([1], advanced)
        self.assertEqual("unknown", self.events(collector)[0]["status"])

    def test_concurrent_async_read_error_does_not_finalize_the_original_live_stream(self):
        collector = self.collector()

        async def run():
            started, release = asyncio.Event(), asyncio.Event()

            @collector.task(WORKER)
            async def values():
                started.set()
                await release.wait()
                yield 9

            stream = values()
            first = asyncio.create_task(stream.__anext__())
            await started.wait()
            with self.assertRaises(RuntimeError):
                await stream.__anext__()
            self.assertEqual([], self.events(collector))
            release.set()
            self.assertEqual(9, await first)
            with self.assertRaises(StopAsyncIteration):
                await stream.__anext__()

        asyncio.run(run())
        self.assertEqual(["success"], [event["status"] for event in self.events(collector)])

    def test_concurrent_coroutines_never_share_an_unrelated_root_trace(self):
        collector = self.collector()

        @collector.task(WORKER)
        async def business():
            first = inject()
            await asyncio.sleep(0)
            self.assertEqual(first, inject())
            return first

        async def run():
            return await asyncio.gather(business(), business())

        results = asyncio.run(run())
        self.assertNotEqual(results[0]["trace_id"], results[1]["trace_id"])
        self.assertIsNone(inject())

    def test_heartbeat_inside_a_task_has_no_participant_or_task_identity(self):
        collector = self.collector()

        @collector.task(WORKER, task_id="actual-task")
        def business():
            collector.heartbeat()

        business()
        heartbeat = self.events(collector)[0]
        self.assertIsNone(heartbeat["task_id"])
        self.assertIsNone(heartbeat["from_worker"])
        self.assertIsNone(heartbeat["message"])

    def test_mcp_classification_requires_a_real_result_and_never_changes_it(self):
        for value in ({}, {"unrelated": True}, {"jsonrpc": "2.0", "id": 1, "result": {}}):
            self.assertEqual("unknown", mcp_result(value))
        original = {"content": [], "isError": True}
        collector = self.collector()
        wrapped = collector.task(WORKER, classify=mcp_result)(lambda: original)
        self.assertIs(original, wrapped())
        self.assertEqual("error", self.events(collector)[0]["status"])
