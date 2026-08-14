from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker/omp-delegate-broker.py"


class BrokerPolicyTest(unittest.TestCase):
    def test_repository_key_must_map_to_requested_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "repo"
            workspace.mkdir()
            policy = Path(td) / "policy.json"
            policy.write_text(json.dumps({"repositories": {"allowed": {"path": str(workspace)}}}))
            with mock.patch.dict(os.environ, {"HERMES_OMP_POLICY": str(policy), "HERMES_OMP_CALLER_UID": str(os.getuid()), "HERMES_OMP_JOB_DIR": str(Path(td) / "jobs")}):
                spec = importlib.util.spec_from_file_location("broker_policy", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            request = {"version": 1, "request_id": "req", "task_id": "task", "repository": "wrong", "caller": "delegate_to_omp", "workspace": str(workspace), "sandbox": "workspace-write", "model": "provider/model", "prompt": "bounded", "timeout": 10}
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())
            request["repository"] = "allowed"
            self.assertEqual(workspace.resolve(), module.validate_request(request, peer_uid=os.getuid()).workspace)

    def test_policy_configures_multiple_callers_and_read_roots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "wiki"
            evidence = root / "evidence"
            workspace.mkdir()
            evidence.mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"wiki": {"path": str(workspace)}},
                "callers": {
                    "audit": {
                        "repositories": ["wiki"],
                        "sandbox": "restricted-write",
                        "read_paths": [str(evidence)],
                        "skills": ["audit-skill"],
                    }
                },
            }))
            with mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_CALLER_UID": str(os.getuid()),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
            }):
                spec = importlib.util.spec_from_file_location("broker_multi_policy", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            request = {
                "version": 1,
                "request_id": "req",
                "task_id": "task",
                "repository": "wiki",
                "caller": "audit",
                "workspace": str(workspace),
                "sandbox": "restricted-write",
                "model": "provider/model",
                "prompt": "bounded",
                "timeout": 10,
            }
            admitted = module.validate_request(request, peer_uid=os.getuid())
            self.assertEqual((str(evidence),), admitted.read_paths)
            self.assertEqual(("audit-skill",), admitted.skills)

    def test_peer_uid_comes_from_unix_socket_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "policy.json"
            policy.write_text(json.dumps({"repositories": {}}))
            with mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_JOB_DIR": str(Path(td) / "jobs"),
            }):
                spec = importlib.util.spec_from_file_location("broker_peer_uid", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            import socket
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                self.assertEqual(os.getuid(), module._peer_uid(left))
            finally:
                left.close()
                right.close()

    def test_extension_tools_are_not_passed_as_builtin_tool_names(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"repo": {"path": td}},
                "callers": {
                    "delegate_to_omp": {
                        "repositories": ["repo"],
                        "sandbox": "workspace-write",
                    }
                },
            }))
            with mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_JOB_DIR": str(Path(td) / "jobs"),
            }):
                spec = importlib.util.spec_from_file_location("broker_argv", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            request = module.Request(
                "req", "task", "repo", "delegate_to_omp", Path(td),
                "workspace-write", "provider/model", "bounded", 10,
                (), (), "none", (), False,
            )
            argv = module.omp_argv(request, "/proc/self/fd/9")
            self.assertFalse(
                any(value.startswith("--tools=") for value in argv),
                "a builtin allowlist hides trusted-extension tools before registration",
            )
            self.assertIn("--trusted-extension", argv)


if __name__ == "__main__":
    unittest.main()
