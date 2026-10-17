import json
from startup_support import Case, EXAMPLES, KEY

NAMES = ("echo", "asynchronous", "values", "async_values")


class LaunchTests(Case):
    def test_unchanged_module_entry_imports_wrapped_aliases_and_preserves_arguments(self):
        receiver = self.receiver(allowed=True)
        before = {path: path.read_bytes() for path in (EXAMPLES / "startup_business").glob("*.py")}
        result = self.launch(self.write(self.value(receiver, NAMES)), "--module", "startup_business",
                             "--", "--example-argument")
        self.assertEqual(0, result.returncode, "Startup module must finish normally")
        self.assertEqual("business completed\n", result.stdout)
        report = json.loads(result.stderr)
        self.assertEqual((4, 4, 0), (report["configured_targets"], report["installed_targets"], report["unloaded_targets"]))
        self.assertEqual((4, 0, True), (report["sent"], report["pending"], report["durable"]))
        self.assertEqual(4, len(receiver.events))
        self.assertEqual(["success", "success", "unknown", "unknown"],
                         [event["status"] for event in receiver.events.values()])
        for path, content in before.items():
            self.assertEqual(content, path.read_bytes(), "Business source must remain byte-identical")
        self.assertEqual([], receiver.failures)
        for secret in (KEY, "private-input", "private-reply"):
            self.assertNotIn(secret, result.stderr)
            self.assertNotIn(secret, json.dumps(receiver.bodies))

    def test_unchanged_script_has_normal_script_import_path_and_argument_behavior(self):
        receiver = self.receiver(allowed=True)
        path = EXAMPLES / "startup_unchanged.py"
        before = path.read_bytes()
        result = self.launch(self.write(self.value(receiver, NAMES)), "--script", str(path),
                             "--", "--example-argument")
        self.assertEqual(0, result.returncode, "Startup script must finish normally")
        self.assertEqual("business completed\n", result.stdout)
        self.assertEqual(4, len(receiver.events))
        self.assertEqual(before, path.read_bytes())
        self.assertEqual([], receiver.failures)

    def test_business_system_exit_is_not_replaced_by_delivery_or_injection_report(self):
        receiver = self.receiver()
        result = self.launch(self.write(self.value(receiver, NAMES)), "--module", "startup_business", "--", "wrong")
        self.assertEqual(9, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(4, json.loads(result.stderr)["installed_targets"])
        self.assertEqual([], receiver.bodies)

    def test_configured_but_unimported_target_is_visible_and_never_eagerly_imported(self):
        receiver = self.receiver(allowed=True)
        value = self.value(receiver)
        value["targets"][0]["module"] = "owned_import_never_loaded"
        result = self.launch(self.write(value), "--module", "startup_business", "--", "--example-argument")
        self.assertEqual(0, result.returncode)
        self.assertEqual("business completed\n", result.stdout)
        report = json.loads(result.stderr)
        self.assertEqual((0, 1), (report["installed_targets"], report["unloaded_targets"]))
        self.assertEqual([], receiver.bodies)

    def test_missing_key_fails_before_original_script_has_side_effects(self):
        receiver = self.receiver()
        path = self.write(self.value(receiver, NAMES))
        # An empty credential uses the real subprocess entry, not a mocked Collector constructor.
        import os
        import subprocess
        import sys
        environment = dict(os.environ, AGF_COLLECTOR_KEY="", PYTHONDONTWRITEBYTECODE="1",
                           PYTHONPATH=str(EXAMPLES.parent))
        result = subprocess.run([sys.executable, "-m", "agf_agentteams.bootstrap", "--config", str(path),
                                 "--script", str(EXAMPLES / "startup_unchanged.py"), "--", "--example-argument"],
                                env=environment, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(78, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("invalid_collector_configuration", json.loads(result.stderr)["error"])
        self.assertFalse((self.directory / "queue").exists())
        self.assertEqual([], receiver.bodies)
