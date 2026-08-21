from __future__ import annotations

import importlib.util
import json
import os
import sys
import subprocess
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


    def _load_broker(self, policy: Path, jobs: Path):
        with mock.patch.dict(os.environ, {
            "HERMES_OMP_POLICY": str(policy),
            "HERMES_OMP_CALLER_UID": str(os.getuid()),
            "HERMES_OMP_JOB_DIR": str(jobs),
        }):
            spec = importlib.util.spec_from_file_location(
                f"broker_wt_{os.urandom(4).hex()}", BROKER)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
    def test_an_existing_worktree_of_the_mapped_repo_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            (repo / "f").write_text("x\n")
            subprocess.run(["git", "add", "f"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "s"], cwd=repo, check=True)
            wt = root / "wt"
            subprocess.run(["git", "worktree", "add", "-q", str(wt)], cwd=repo, check=True)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"allowed": {"path": str(repo)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["allowed"], "sandbox": "workspace-write",
                }},
            }))
            module = self._load_broker(policy, root / "jobs")
            request = {
                "version": 1, "request_id": "req", "task_id": "task",
                "repository": "allowed", "caller": "delegate_to_omp",
                "workspace": str(wt), "sandbox": "workspace-write",
                "model": "provider/model", "prompt": "bounded", "timeout": 10,
            }
            self.assertEqual(
                wt.resolve(),
                module.validate_request(request, peer_uid=os.getuid()).workspace)

    def test_a_nested_directory_of_the_checkout_is_not_a_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            nested = repo / "src"
            nested.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            (nested / "f").write_text("x\n")
            subprocess.run(["git", "add", "src"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "s"], cwd=repo, check=True)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"allowed": {"path": str(repo)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["allowed"], "sandbox": "workspace-write",
                }},
            }))
            module = self._load_broker(policy, root / "jobs")
            request = {
                "version": 1, "request_id": "req", "task_id": "task",
                "repository": "allowed", "caller": "delegate_to_omp",
                "workspace": str(nested), "sandbox": "workspace-write",
                "model": "provider/model", "prompt": "bounded", "timeout": 10,
            }
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())

    def test_a_missing_worktree_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"allowed": {"path": str(repo)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["allowed"], "sandbox": "workspace-write",
                }},
            }))
            module = self._load_broker(policy, root / "jobs")
            request = {
                "version": 1, "request_id": "req", "task_id": "task",
                "repository": "allowed", "caller": "delegate_to_omp",
                "workspace": str(root / "missing"), "sandbox": "workspace-write",
                "model": "provider/model", "prompt": "bounded", "timeout": 10,
            }
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())

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

    def test_fixed_fallback_providers_also_receive_credentials(self) -> None:
        """A fallback chain the child cannot authenticate is not a fallback.

        OMP resolves `retry.fallbackChains` inside the child, so a rung on a second
        provider fails at auth unless the broker injected that provider's key too.
        The set is broker policy, never caller input: the request still carries only
        the pinned primary model.
        """
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
                "HERMES_OMP_MODEL": "hetzner/Qwen/Qwen3.6-35B-A3B-FP8",
                "HERMES_OMP_FALLBACK_MODELS": "openai-codex/gpt-5.6-luna",
            }):
                spec = importlib.util.spec_from_file_location("broker_fallback", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            request = module.Request(
                "req", "task", "repo", "delegate_to_omp", Path(td),
                "workspace-write", "hetzner/Qwen/Qwen3.6-35B-A3B-FP8", "bounded", 10,
                (), (), "none", (), False,
            )
            self.assertEqual(("hetzner", "openai-codex"), module.credential_providers(request))
            calls: list[str] = []

            def fake_run(argv, **_kwargs):
                calls.append(argv[2])
                return subprocess.CompletedProcess(argv, 0, f"key-{argv[2]}".encode(), b"")

            with mock.patch.object(module.subprocess, "run", fake_run):
                resolved = module.resolve_provider_api_keys(request)
            self.assertEqual(["hetzner", "openai-codex"], calls)
            self.assertEqual(
                {"hetzner": "key-hetzner", "openai-codex": "key-openai-codex"}, resolved,
            )


if __name__ == "__main__":
    unittest.main()
