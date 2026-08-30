from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Context:
    def __init__(self) -> None:
        self.tools = {}
    def register_tool(self, **kwargs) -> None:
        self.tools[kwargs["name"]] = kwargs


class PackageTest(unittest.TestCase):
    def test_manifest_and_skill_expose_delegate(self) -> None:
        manifest = (ROOT / "plugin/plugin.yaml").read_text()
        self.assertIn("name: hermes-omp-delegate", manifest)
        self.assertIn("provides_tools: [delegate_to_omp]", manifest)
        self.assertIn("author: ghosty-11", manifest)
        self.assertTrue((ROOT / "skills/hermes-omp-delegation/SKILL.md").exists())

    def test_plugin_registers_one_generic_tool(self) -> None:
        spec = importlib.util.spec_from_file_location("delegate", ROOT / "plugin/__init__.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        context = Context()
        module.register(context)
        self.assertEqual(["delegate_to_omp"], sorted(context.tools))

    def test_policy_is_configured_from_one_file(self) -> None:
        policy = json.loads((ROOT / "examples/policy.json").read_text())
        self.assertIn("repositories", policy)
        self.assertEqual("provider/model", policy["model"])
        self.assertNotIn("model_roles", policy)
        self.assertFalse(any(Path(value["path"]).is_absolute() for value in policy["repositories"].values()))

    def test_schema_matches_the_wire_protocol(self) -> None:
        schema = json.loads((ROOT / "schemas/coding-job.schema.json").read_text())
        request = schema["$defs"]["request"]
        response = schema["$defs"]["response"]
        final = schema["$defs"]["final"]
        self.assertEqual(
            {"version", "request_id", "task_id", "repository", "caller", "workspace",
             "sandbox", "model", "prompt", "timeout"},
            set(request["required"]),
        )
        self.assertEqual(set(request["required"]), set(request["properties"]))
        self.assertEqual(
            {"version", "exit_code", "stdout", "stderr", "timed_out",
             "process_group_clear", "final", "request_id"},
            set(response["required"]),
        )
        self.assertEqual(set(response["required"]), set(response["properties"]))
        self.assertEqual(
            {"summary", "verification", "gaps", "verdict"},
            set(final["required"]),
        )
        self.assertEqual(
            set(final["required"]) | {"served_model", "findings"},
            set(final["properties"]),
        )
        finding = schema["$defs"]["finding"]
        self.assertEqual(
            {"file", "lines", "severity", "issue", "fix"},
            set(finding["required"]),
        )
        self.assertFalse(finding["additionalProperties"])
        self.assertEqual(
            "https://raw.githubusercontent.com/ghosty-11/hermes-omp-broker/main/"
            "schemas/coding-job.schema.json",
            schema["$id"],
        )

    def test_plugin_requires_task_correlation(self) -> None:
        spec = importlib.util.spec_from_file_location("delegate_schema", ROOT / "plugin/__init__.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIn("task_id", module._SCHEMA["parameters"]["required"])

    def test_plugin_endpoints_come_from_deployment_policy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "policy.json"
            policy.write_text(json.dumps({
                "client": "/opt/hermes/omp-invoke",
                "socket": "/run/hermes/omp.sock",
                "repositories": {},
            }))
            spec = importlib.util.spec_from_file_location(
                "delegate_endpoints", ROOT / "plugin/__init__.py",
            )
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            with mock.patch.dict(
                "os.environ", {"HERMES_OMP_POLICY": str(policy)}, clear=False,
            ):
                spec.loader.exec_module(module)
            self.assertEqual("/opt/hermes/omp-invoke", module.INVOKE)
            self.assertEqual("/run/hermes/omp.sock", module.BROKER_SOCKET)

    def test_plugin_exposes_only_delegate_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {
                    "delegate": {"path": "/srv/delegate"},
                    "audit": {"path": "/srv/audit"},
                },
                "callers": {
                    "delegate_to_omp": {
                        "repositories": ["delegate"],
                        "sandbox": "workspace-write",
                    },
                    "audit": {
                        "repositories": ["audit"],
                        "sandbox": "read-only",
                    },
                },
            }))
            spec = importlib.util.spec_from_file_location(
                "delegate_repositories", ROOT / "plugin/__init__.py",
            )
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            with mock.patch.dict(
                "os.environ", {"HERMES_OMP_POLICY": str(policy)}, clear=False,
            ):
                spec.loader.exec_module(module)
            self.assertEqual({"delegate": "/srv/delegate"}, module.ALLOWED_REPOS)

    def test_publication_surfaces_are_complete(self) -> None:
        readme = (ROOT / "README.md").read_text()
        specification = (ROOT / "docs/specification.md").read_text()
        compatibility = (ROOT / "docs/compatibility.md").read_text()

        self.assertIn("ships a reference implementation", specification)
        self.assertIn("broker implementation, protocol, policy, operations, and tests", readme)
        self.assertIn("../schemas/coding-job.schema.json", specification)
        self.assertIn("shipped reference implementation uses one-shot", specification)
        self.assertNotIn("private review candidate", (readme + specification).lower())
        self.assertNotIn("before public release", readme.lower())
        for path in (
            "docs/specification.md",
            "docs/policy.md",
            "docs/installation.md",
            "docs/operations.md",
            "docs/compatibility.md",
        ):
            self.assertIn(f"]({path})", readme)
        for path in ("SECURITY.md", "SUPPORT.md", ".github/workflows/tests.yml"):
            self.assertTrue((ROOT / path).exists(), path)


if __name__ == "__main__":
    unittest.main()
