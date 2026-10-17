import asyncio
import importlib
import inspect
import json
import sys
from types import ModuleType
from unittest.mock import patch

from agf_agentteams.startup.runner import Session
from startup_support import Case, MODULE

IMPORT_ERROR = RuntimeError("private-import-error")


class HookTests(Case):
    def test_import_alias_sync_return_and_exception_identity_without_argument_capture(self):
        receiver = self.receiver()
        session = self.session(receiver, ("echo", "fail"))
        module = importlib.import_module(MODULE)
        # This matches a business `from ... import ...` after the module hook has completed.
        alias = module.echo
        value = object()
        self.assertIs(value, alias(value))
        error = LookupError("business-private-error")
        with self.assertRaises(LookupError) as raised:
            module.fail(error)
        self.assertIs(error, raised.exception)
        self.assertEqual(["echo", "fail"], module.calls)
        self.assertEqual("echo", alias.__name__)
        self.assertEqual(["value"], list(inspect.signature(alias).parameters))
        session.close()
        events = self.events()
        self.assertEqual(["success", "error"], [event["status"] for event in events])
        self.assertTrue(all(event["message"] is None for event in events))
        self.assertNotIn("business-private-error", json.dumps(events))

    def test_declared_instance_static_and_class_methods_preserve_descriptor_binding(self):
        receiver = self.receiver()
        session = self.session(receiver, ("WorkerClient.run", "WorkerClient.static_run", "WorkerClient.class_run"))
        client = importlib.import_module(MODULE).WorkerClient
        value = object()
        self.assertIs(value, client(value).run())
        self.assertIs(value, client.static_run(value))
        self.assertIs(value, client(value).static_run(value))
        self.assertIs(value, client.class_run(value).value)
        self.assertIsInstance(vars(client)["static_run"], staticmethod)
        self.assertIsInstance(vars(client)["class_run"], classmethod)
        session.close()
        self.assertEqual(4, len(self.events()))

    def test_async_return_concurrent_roots_and_actual_cancellation(self):
        receiver = self.receiver()
        session = self.session(receiver, ("asynchronous", "waiting"))
        module = importlib.import_module(MODULE)
        self.assertTrue(inspect.iscoroutinefunction(module.asynchronous))

        async def exercise():
            a, b = object(), object()
            results = await asyncio.gather(module.asynchronous(a), module.asynchronous(b))
            self.assertIs(a, results[0])
            self.assertIs(b, results[1])
            ready = asyncio.Event()
            task = asyncio.create_task(module.waiting(ready))
            await asyncio.wait_for(ready.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(exercise())
        session.close()
        events = self.events()
        self.assertEqual(["success", "success", "unknown"], [event["status"] for event in events])
        self.assertEqual(3, len({event["trace_id"] for event in events}))
        self.assertTrue(all(event["parent_span_id"] is None for event in events))

    def test_generator_protocol_laziness_and_close_preserve_actual_execution(self):
        receiver = self.receiver()
        session = self.session(receiver, ("values", "async_values"))
        module = importlib.import_module(MODULE)
        module.values().close()
        self.assertEqual([], module.calls)
        stream = module.values()
        self.assertEqual(1, next(stream))
        self.assertEqual(3, stream.send(3))
        error = LookupError("private-stream-error")
        self.assertIs(error, stream.throw(error))
        with self.assertRaises(StopIteration) as stopped:
            next(stream)
        self.assertEqual(7, stopped.exception.value)
        early = module.values()
        next(early)
        early.close()

        async def exercise():
            await module.async_values().aclose()
            stream = module.async_values()
            self.assertEqual(1, await stream.__anext__())
            self.assertEqual(4, await stream.asend(4))
            self.assertIs(error, await stream.athrow(error))
            with self.assertRaises(StopAsyncIteration):
                await stream.__anext__()
            early = module.async_values()
            await early.__anext__()
            await early.aclose()

        asyncio.run(exercise())
        session.close()
        events = self.events()
        self.assertEqual(["success", "unknown", "success", "unknown"], [event["status"] for event in events])
        self.assertNotIn("private-stream-error", json.dumps(events))

    def test_call_worker_nested_parent_is_real_and_bounded_queue_does_not_retry_business(self):
        receiver = self.receiver()
        value = self.value(receiver, ("invoke", "echo"))
        value["targets"][0].update(kind="call", callee={"name": "worker-b", "team": "team-b"})
        value["targets"][1]["worker"] = {"name": "worker-b", "team": "team-b"}
        value["collector"]["max_items"] = 2
        from agf_agentteams.startup.configuration import load
        from startup_support import KEY
        session = Session(load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY}))
        self.addCleanup(self._close, session)
        module = importlib.import_module(MODULE)
        secret = "private-prompt-and-model-key"
        self.assertEqual(secret, module.invoke(secret))
        self.assertEqual(secret, module.echo(secret))
        session.close()
        events = self.events()
        self.assertEqual(2, len(events))
        child, parent = events
        self.assertEqual("call", parent["kind"])
        self.assertEqual(parent["span_id"], child["parent_span_id"])
        self.assertEqual(parent["trace_id"], child["trace_id"])
        self.assertEqual(("worker-a", "worker-b"), (parent["from_worker"], parent["to_worker"]))
        self.assertEqual("worker-b", child["from_worker"])
        self.assertEqual(["invoke", "echo", "echo"], module.calls)
        self.assertEqual(1, session.collector.status()["dropped"])
        self.assertNotIn(secret, json.dumps(events))

    def test_reload_keeps_one_wrapper_per_actual_call_and_close_restores_latest_function(self):
        receiver = self.receiver()
        session = self.session(receiver)
        module = importlib.import_module(MODULE)
        module.echo(1)
        module = importlib.reload(module)
        module.echo(2)
        original = module.echo.__wrapped__
        session.close()
        self.assertIs(original, module.echo)
        self.assertEqual(2, len(self.events()))

    def test_original_import_error_is_not_wrapped_or_logged_as_a_business_task(self):
        receiver = self.receiver()
        name = "owned_import_" + self.run_id
        location = self.directory / (name + ".py")
        location.write_text("from test_hooks import IMPORT_ERROR\nraise IMPORT_ERROR\n", encoding="utf-8")
        sys.path.insert(0, str(self.directory))
        value = self.value(receiver)
        value["targets"][0]["module"] = name
        from agf_agentteams.startup.configuration import load
        from startup_support import KEY
        session = Session(load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY}))
        self.addCleanup(self._close, session)
        with self.assertRaises(RuntimeError) as raised:
            importlib.import_module(name)
        self.assertIs(IMPORT_ERROR, raised.exception)
        session.close()
        self.assertEqual([], self.events())

    def test_inherited_process_guard_invokes_original_without_using_parent_queue(self):
        receiver = self.receiver()
        session = self.session(receiver)
        module = importlib.import_module(MODULE)
        with patch("agf_agentteams.startup.hooks.os.getpid", return_value=session.process + 1):
            self.assertEqual(3, module.echo(3))
        session.close()
        self.assertEqual(["echo"], module.calls)
        self.assertEqual([], self.events())  # PID guard unit, not a claim to have tested a real OS fork.

    def test_explicit_mcp_classifier_preserves_result_and_does_not_capture_error_content(self):
        receiver = self.receiver()
        value = self.value(receiver, ("mcp_reply",))
        value["targets"][0]["classifier"] = "mcp_result"
        from agf_agentteams.startup.configuration import load
        from startup_support import KEY
        session = Session(load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY}))
        self.addCleanup(self._close, session)
        reply = {"isError": True, "content": [{"type": "text", "text": "private-mcp-error"}]}
        self.assertIs(reply, importlib.import_module(MODULE).mcp_reply(reply))
        session.close()
        events = self.events()
        self.assertEqual("error", events[0]["status"])
        self.assertNotIn("private-mcp-error", json.dumps(events))

    def test_business_module_setattr_change_at_shutdown_cannot_replace_original_error(self):
        receiver = self.receiver()
        session = self.session(receiver, ("echo", "fail"))
        module = importlib.import_module(MODULE)

        class ChangedModule(ModuleType):
            def __setattr__(self, name, value):
                if name == "echo":
                    raise RuntimeError("private-shutdown-error")
                super().__setattr__(name, value)

        error = ValueError("private-original-error")
        try:
            with self.assertRaises(ValueError) as raised:
                with session:
                    module.__class__ = ChangedModule
                    module.fail(error)
            self.assertIs(error, raised.exception)
            self.assertTrue(session.hook.report()["restoration_failed"])
            self.assertTrue(session.collector.status()["closed"])
            self.assertNotIn("private-shutdown-error", json.dumps(self.events()))
        finally:
            module.__class__ = ModuleType
