import importlib
from agf_agentteams.startup.configuration import StartupError, load
from agf_agentteams.startup.runner import Session, run
from startup_support import Case, KEY, MODULE


class ConfigurationTests(Case):
    def test_keys_capture_and_arbitrary_classifiers_are_not_configuration_inputs(self):
        receiver = self.receiver()
        for area, name, content in (("collector", "collector_key", KEY),
                                    ("target", "capture", "shape"),
                                    ("target", "carrier", "read-any-business-argument"),
                                    ("target", "task_id", "prompt-derived-value"),
                                    ("target", "classifier", "some.function()")):
            with self.subTest(area=area, field=name):
                value = self.value(receiver)
                (value["collector"] if area == "collector" else value["targets"][0])[name] = content
                with self.assertRaises(StartupError) as raised:
                    load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY})
                self.assertNotIn(KEY, str(raised.exception))
        self.assertFalse((self.directory / "queue").exists())
        self.assertEqual([], receiver.bodies)

    def test_duplicate_json_fields_and_oversized_documents_are_rejected_before_queue_creation(self):
        path = self.directory / "injection.json"
        path.write_text('{"version":1,"version":1}', encoding="utf-8")
        with self.assertRaisesRegex(StartupError, "duplicate_configuration_field"):
            load(path, environment={"AGF_COLLECTOR_KEY": KEY})
        path.write_bytes(b" " * (64 * 1024 + 1))
        with self.assertRaisesRegex(StartupError, "configuration_too_large"):
            load(path, environment={"AGF_COLLECTOR_KEY": KEY})
        self.assertFalse((self.directory / "queue").exists())

    def test_missing_identity_mode_key_and_invalid_limits_do_not_start_delivery(self):
        receiver = self.receiver()
        for field, content in (("expected_scope", None), ("expected_mocked", "true"),
                               ("spool_dir", "relative/queue"), ("request_timeout", True),
                               ("max_items", 0), ("max_disk_bytes", 100)):
            with self.subTest(field=field):
                value = self.value(receiver)
                value["collector"][field] = content
                with self.assertRaises(StartupError):
                    load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY})
        with self.assertRaises(StartupError):
            load(self.write(self.value(receiver)), environment={})
        self.assertFalse((self.directory / "queue").exists())
        self.assertEqual([], receiver.bodies)

    def test_sdk_stdlib_dunder_and_duplicate_targets_cannot_be_wrapped(self):
        receiver = self.receiver()
        for module, attribute in (("agf_agentteams.collector", "Collector.task"),
                                  ("asyncio", "sleep"), (MODULE, "WorkerClient.__init__")):
            with self.subTest(module=module):
                value = self.value(receiver)
                value["targets"][0].update(module=module, attribute=attribute)
                with self.assertRaises(StartupError):
                    load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY})
        value = self.value(receiver)
        value["targets"].append(dict(value["targets"][0]))
        with self.assertRaisesRegex(StartupError, "duplicate_target"):
            load(self.write(value), environment={"AGF_COLLECTOR_KEY": KEY})

    def test_preloaded_target_and_entry_target_are_explicit_startup_failures(self):
        receiver = self.receiver()
        settings = self.settings(receiver)
        original = importlib.import_module(MODULE).echo
        with self.assertRaisesRegex(StartupError, "target_already_loaded"):
            Session(settings)
        self.assertIs(original, importlib.import_module(MODULE).echo)
        with self.assertRaisesRegex(StartupError, "entry_module_target_unsupported"):
            run(settings, module=MODULE)
        self.assertFalse((self.directory / "queue").exists())

    def test_atomic_target_install_rejects_property_without_partially_wrapping_valid_function(self):
        receiver = self.receiver()
        session = self.session(receiver, ("echo", "WorkerClient.unsafe_property"))
        with self.assertRaisesRegex(StartupError, "unsupported_target_callable"):
            importlib.import_module(MODULE)
        self.assertEqual(0, session.hook.report()["installed_targets"])
        session.close()
        self.assertEqual([], self.events())

    def test_imported_alias_is_rejected_instead_of_claiming_to_observe_foreign_execution(self):
        receiver = self.receiver()
        session = self.session(receiver, ("imported_alias",))
        with self.assertRaisesRegex(StartupError, "unsupported_target_callable"):
            importlib.import_module(MODULE)
        session.close()
        self.assertEqual([], self.events())
