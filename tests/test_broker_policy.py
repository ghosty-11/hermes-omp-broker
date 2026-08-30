from __future__ import annotations

import importlib.util
import json
import os
import pwd
import sys
import stat
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

    def test_review_findings_are_caller_scoped_and_typed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "model": "provider/model",
                "repositories": {},
                "callers": {},
            }))
            module = self._load_broker(policy, root / "jobs")
            final_path = root / "final.json"
            final = {
                "summary": "The exact-head review found one approved defect.",
                "verification": ["exact pull head verified"],
                "gaps": [],
                "verdict": "MET",
                "findings": [{
                    "file": "backlog/triage/Target.md",
                    "lines": [12],
                    "severity": "medium",
                    "issue": "The path is stale.",
                    "fix": "Point it at the archive.",
                }],
            }
            final_path.write_text(json.dumps(final))
            self.assertEqual(
                final,
                module._valid_final(final_path, caller="review-agent"),
            )
            self.assertIsNone(
                module._valid_final(final_path, caller="delegate_to_omp")
            )
            final["findings"][0]["lines"] = [0]
            final_path.write_text(json.dumps(final))
            self.assertIsNone(
                module._valid_final(final_path, caller="review-agent")
            )

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

            alias = root / "alias"
            os.symlink(wt, alias, target_is_directory=True)
            with self.assertRaisesRegex(
                    module.ProtocolError, "workspace is not allowlisted"):
                module.validate_request(
                    {**request, "workspace": str(alias)},
                    peer_uid=os.getuid())

    def test_caller_repository_root_admits_only_matching_remote_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            remote = root / "remote.git"
            subprocess.run(
                ["git", "init", "-q", "--bare", str(remote)], check=True)
            canonical = root / "canonical"
            subprocess.run(
                ["git", "clone", "-q", str(remote), str(canonical)], check=True)
            for key, value in (
                ("user.email", "test@example.invalid"),
                ("user.name", "test"),
            ):
                subprocess.run(
                    ["git", "-C", str(canonical), "config", key, value],
                    check=True)
            (canonical / "f").write_text("x\n")
            subprocess.run(
                ["git", "-C", str(canonical), "add", "f"], check=True)
            subprocess.run(
                ["git", "-C", str(canonical), "commit", "-qm", "seed"],
                check=True)
            subprocess.run(
                ["git", "-C", str(canonical), "push", "-q", "origin", "HEAD"],
                check=True)
            mirror = root / "mirror.git"
            subprocess.run(
                ["git", "clone", "-q", "--mirror", str(remote), str(mirror)],
                check=True)
            workspace_root = root / "review-worktrees"
            workspace_root.mkdir()
            workspace = workspace_root / "task"
            subprocess.run(
                ["git", "-C", str(mirror), "worktree", "add", "-q",
                 str(workspace), "HEAD"],
                check=True)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"allowed": {"path": str(canonical)}},
                "callers": {"review": {
                    "repositories": ["allowed"],
                    "workspace_roots": {
                        "allowed": [str(workspace_root)],
                    },
                    "sandbox": "restricted-write",
                }},
            }))
            module = self._load_broker(policy, root / "jobs")
            request = {
                "version": 1, "request_id": "req", "task_id": "task",
                "repository": "allowed", "caller": "review",
                "workspace": str(workspace), "sandbox": "restricted-write",
                "model": "provider/model", "prompt": "bounded", "timeout": 10,
            }

            try:
                admitted = module.validate_request(
                    request, peer_uid=os.getuid())
            except module.ProtocolError as exc:
                self.fail(f"valid caller workspace root was rejected: {exc}")
            self.assertEqual(workspace.resolve(), admitted.workspace)

            alias = workspace_root / "alias"
            os.symlink(workspace, alias, target_is_directory=True)
            with self.assertRaisesRegex(
                    module.ProtocolError, "workspace is not allowlisted"):
                module.validate_request(
                    {**request, "workspace": str(alias)},
                    peer_uid=os.getuid())

            sibling = root / "sibling"
            subprocess.run(
                ["git", "-C", str(mirror), "worktree", "add", "-q",
                 str(sibling), "HEAD"],
                check=True)
            with self.assertRaisesRegex(
                    module.ProtocolError, "workspace is not allowlisted"):
                module.validate_request(
                    {**request, "workspace": str(sibling)},
                    peer_uid=os.getuid())

            forged = workspace_root / "forged"
            subprocess.run(
                ["git", "init", "-q", "-b", "main", str(forged)], check=True)
            subprocess.run(
                ["git", "-C", str(forged), "remote", "add", "origin",
                 str(root / "other.git")],
                check=True)
            with self.assertRaisesRegex(
                    module.ProtocolError, "repository key does not map"):
                module.validate_request(
                    {**request, "workspace": str(forged)},
                    peer_uid=os.getuid())


    def test_git_identity_probe_trusts_only_the_exact_candidate_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            policy = root / "policy.json"
            policy.write_text(json.dumps({"repositories": {}}))
            module = self._load_broker(policy, root / "jobs")
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=f"{root}\n", stderr="")
            with mock.patch.object(module.subprocess, "run", return_value=completed) as run:
                self.assertEqual(root, module.git_toplevel(root))
            command = run.call_args.args[0]
            self.assertEqual(
                ["git", "-c", f"safe.directory={root}", "-C", str(root)],
                command[:5],
            )

    def test_scoped_child_git_trusts_only_its_exact_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            policy = root / "policy.json"
            policy.write_text(json.dumps({"repositories": {}}))
            module = self._load_broker(policy, root / "jobs")
            request = module.Request(
                "req", "task", "repo", "caller", root, "restricted-write",
                "provider/model", "prompt", 30, (), ("backlog/**",),
                "scoped", (), False,
            )
            env = module.omp_environment(
                {}, final_path=root / "final.json", request=request)
            self.assertEqual("1", env["GIT_CONFIG_COUNT"])
            self.assertEqual("safe.directory", env["GIT_CONFIG_KEY_0"])
            self.assertEqual(str(root), env["GIT_CONFIG_VALUE_0"])

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
            argv = module.omp_argv(request, 9)
            self.assertFalse(
                any(str(value).startswith("--tools=") for value in argv),
                "a builtin allowlist hides trusted-extension tools before registration",
            )
            self.assertIn("--trusted-extension", argv)
            fd_flag = argv.index("--provider-api-keys-fd")
            self.assertEqual(argv[fd_flag + 1], "9")
            self.assertNotIn("--provider-api-keys", argv)
            self.assertFalse(any(str(value).startswith("/proc/self/fd/") for value in argv))

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



class ProtocolV2LeaseTest(unittest.TestCase):
    def _load(self, root: Path):
        policy = root / "policy.json"
        workspace = root / "repo"
        workspace.mkdir(parents=True, exist_ok=True)
        policy.write_text(json.dumps({
            "version": 1,
            "repositories": {"repo": {"path": str(workspace)}},
            "callers": {"audit": {
                "repositories": ["repo"],
                "sandbox": "restricted-write",
                "read_paths": [],
                "write_patterns": ["backlog/**"],
                "git_mode": "scoped",
                "skills": ["audit"],
                "model": "provider/fixed",
                "max_timeout": 60,
            }},
        }))
        for endpoint in ("audit", "planner", "code"):
            store_root = root / "leases" / endpoint
            (store_root / "issued").mkdir(
                parents=True, exist_ok=True, mode=0o750)
            (store_root / "consumed").mkdir(
                parents=True, exist_ok=True, mode=0o700)
            lock_fd = os.open(
                store_root / ".lease-store.lock",
                os.O_RDWR | os.O_CREAT,
                0o660,
            )
            os.fchmod(lock_fd, 0o660)
            os.fchown(
                lock_fd, -1, pwd.getpwuid(os.getuid()).pw_gid)
            os.close(lock_fd)
        with mock.patch.dict(os.environ, {
            "HERMES_OMP_POLICY": str(policy),
            "HERMES_OMP_JOB_DIR": str(root / "jobs"),
            "HERMES_OMP_LEASE_DIRS": ",".join((
                f"audit={root / 'leases' / 'audit'}",
                f"planner={root / 'leases' / 'planner'}",
                f"code={root / 'leases' / 'code'}",
            )),
            "HERMES_OMP_ENDPOINT_USERS": ",".join(
                f"{endpoint}={pwd.getpwuid(os.getuid()).pw_name}"
                for endpoint in ("audit", "planner", "code")
            ),
        }):
            spec = importlib.util.spec_from_file_location(
                f"broker_v2_{os.urandom(4).hex()}", BROKER)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        return module

    @staticmethod
    def _fixed(root: Path, *, request_id: str = "request-1",
               task_id: str = "task-1", prompt: str = "fixed prompt") -> dict:
        return {
            "request_id": request_id,
            "task_id": task_id,
            "repository": "repo",
            "caller": "audit",
            "workspace": str(root / "repo"),
            "sandbox": "restricted-write",
            "model": "provider/fixed",
            "prompt": prompt,
            "timeout": 30,
        }

    def _issue(self, module, root: Path, **changes):
        fixed = self._fixed(root)
        fixed.update(changes.pop("fixed", {}))
        endpoint = changes.pop("endpoint", "audit")
        return module.LEASE_STORES[endpoint].issue(
            fixed_request=fixed,
            endpoint=endpoint,
            peer_uid=changes.pop("peer_uid", 997),
            artifact_digest=changes.pop("artifact_digest", "sha256:artifact"),
            policy_version=changes.pop("policy_version", "policy-v1"),
            template_version=changes.pop("template_version", "template-v1"),
            expires_at=changes.pop("expires_at", int(__import__("time").time()) + 60),
            **changes,
        )

    def test_v2_schema_is_only_version_operation_and_opaque_lease(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = self._load(Path(td))
            lease_id = self._issue(module, Path(td))
            request = module.parse_request(
                {"version": 2, "op": "execute", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            self.assertEqual("request-1", request.request_id)
            for index, field in enumerate((
                "caller", "repository", "workspace", "sandbox", "model", "prompt",
                "request_id", "task_id",
            )):
                with self.subTest(field=field):
                    extra_lease = self._issue(
                        module, Path(td),
                        fixed={
                            "request_id": f"extra-request-{index}",
                            "task_id": f"extra-task-{index}",
                        },
                    )
                    with self.assertRaises(module.ProtocolError) as raised:
                        module.parse_request(
                            {"version": 2, "op": "execute", "lease_id": extra_lease,
                             field: "guess"},
                            endpoint="audit", peer_uid=997)
                    self.assertEqual("job unavailable", str(raised.exception))
                    admitted = module.parse_request(
                        {"version": 2, "op": "execute", "lease_id": extra_lease},
                        endpoint="audit", peer_uid=997)
                    self.assertEqual(f"extra-task-{index}", admitted.task_id)

    def test_uid_997_wrong_peer_and_endpoint_crossing_are_uniformly_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = self._load(Path(td))
            lease_id = self._issue(module, Path(td))
            for endpoint, uid in (("audit", 998), ("planner", 997)):
                with self.subTest(endpoint=endpoint, uid=uid):
                    with self.assertRaises(module.ProtocolError) as raised:
                        module.parse_request(
                            {"version": 2, "op": "execute", "lease_id": lease_id},
                            endpoint=endpoint, peer_uid=uid)
                    self.assertEqual("job unavailable", str(raised.exception))
            admitted = module.parse_request(
                {"version": 2, "op": "execute", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            self.assertEqual("task-1", admitted.task_id)

    def test_expired_wrong_digest_and_wrong_task_records_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, mutation in (
                ("expired", {"expires_at": 1}),
                ("prompt-digest", {"prompt_digest": "sha256:wrong"}),
                ("artifact-digest", {"artifact_digest": "sha256:wrong"}),
                ("task", {"task_id": "changed-task"}),
            ):
                with self.subTest(name=name):
                    module = self._load(root / name)
                    lease_id = self._issue(
                        module, root / name,
                        expires_at=mutation.pop("expires_at", int(__import__("time").time()) + 60))
                    path = module.LEASE_STORES["audit"]._path(lease_id)
                    record = json.loads(path.read_text())
                    record.update(mutation)
                    path.write_text(json.dumps(record))
                    with self.assertRaises(module.ProtocolError) as raised:
                        module.parse_request(
                            {"version": 2, "op": "execute", "lease_id": lease_id},
                            endpoint="audit", peer_uid=997)
                    self.assertEqual("job unavailable", str(raised.exception))

    def test_consumption_is_single_winner_and_task_cannot_receive_fresh_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            module = self._load(root)
            lease_id = self._issue(module, root)
            barrier = __import__("threading").Barrier(3)
            outcomes: list[str] = []

            def consume() -> None:
                barrier.wait()
                try:
                    module.parse_request(
                        {"version": 2, "op": "execute", "lease_id": lease_id},
                        endpoint="audit", peer_uid=997)
                    outcomes.append("won")
                except module.ProtocolError as exc:
                    outcomes.append(str(exc))

            threads = [__import__("threading").Thread(target=consume) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join()
            self.assertEqual(1, outcomes.count("won"))
            self.assertEqual(1, outcomes.count("job unavailable"))
            restarted = self._load(root)
            with self.assertRaises(restarted.ProtocolError) as raised:
                restarted.parse_request(
                    {"version": 2, "op": "execute", "lease_id": lease_id},
                    endpoint="audit", peer_uid=997)
            self.assertEqual("job unavailable", str(raised.exception))
            with self.assertRaises(ValueError):
                self._issue(module, root)

    def test_v2_health_is_exact_endpoint_bound_and_no_spend(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = self._load(Path(td))
            module.ENDPOINT_UIDS = {"audit": 997, "planner": 998, "code": 999}
            spend_guards = (
                mock.patch.object(module.LEASE_STORES["audit"], "consume"),
                mock.patch.object(module.LEASE_STORES["audit"], "resolve"),
                mock.patch.object(module.JOB_STORE, "create"),
                mock.patch.object(module, "record_audit"),
                mock.patch.object(module, "resolve_provider_api_keys"),
                mock.patch.object(module, "acquire_workspace_lock"),
                mock.patch.object(module, "start_omp_process"),
            )
            with spend_guards[0] as consume, spend_guards[1] as resolve, \
                    spend_guards[2] as create, spend_guards[3] as audit, \
                    spend_guards[4] as credentials, spend_guards[5] as lock, \
                    spend_guards[6] as start:
                request = module.parse_request(
                    {"version": 2, "op": "health"},
                    endpoint="audit", peer_uid=997)
                self.assertEqual(
                    {"version": 2, "op": "health", "ok": True},
                    module.read_health(request),
                )
            for guarded in (
                consume, resolve, create, audit, credentials, lock, start,
            ):
                guarded.assert_not_called()

            failures = (
                ({"version": 2, "op": "health"}, "audit", 998),
                ({"version": 2, "op": "health"}, "planner", 997),
                ({"version": 2, "op": "health"}, "missing", 997),
                ({"version": 2, "op": "health", "lease_id": "guess"}, "audit", 997),
                ({"op": "health"}, "audit", 997),
                ({"version": "2", "op": "health"}, "audit", 997),
            )
            for value, endpoint, peer_uid in failures:
                with self.subTest(value=value, endpoint=endpoint, peer_uid=peer_uid):
                    with self.assertRaises(module.ProtocolError) as raised:
                        module.parse_request(
                            value, endpoint=endpoint, peer_uid=peer_uid)
                    self.assertEqual("endpoint unavailable", str(raised.exception))
                    self.assertEqual("health", raised.exception.operation)
                    self.assertEqual(
                        {
                            "version": 2, "op": "health", "ok": False,
                            "error": "endpoint unavailable",
                        },
                        module._health_error_response(),
                    )


    def test_v2_pre_spawn_failures_return_the_complete_typed_response(self) -> None:
        expected_fields = {
            "version", "exit_code", "stdout", "stderr", "timed_out",
            "process_group_clear", "final", "request_id",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for failure in ("workspace lock", "credential", "start"):
                with self.subTest(failure=failure):
                    case_root = root / failure.replace(" ", "-")
                    module = self._load(case_root)
                    lease_id = self._issue(module, case_root)
                    request = module.parse_request(
                        {"version": 2, "op": "execute", "lease_id": lease_id},
                        endpoint="audit", peer_uid=997)
                    lock = mock.Mock()
                    patches = [
                        mock.patch.object(module, "record_audit"),
                        mock.patch.object(
                            module, "acquire_workspace_lock", return_value=lock),
                    ]
                    if failure == "workspace lock":
                        patches[1] = mock.patch.object(
                            module, "acquire_workspace_lock",
                            side_effect=module.ProtocolError("workspace is busy"))
                    elif failure == "credential":
                        patches.append(mock.patch.object(
                            module, "resolve_provider_api_keys",
                            side_effect=module.ProtocolError("credential unavailable")))
                    else:
                        patches.extend((
                            mock.patch.object(
                                module, "resolve_provider_api_keys", return_value={}),
                            mock.patch.object(
                                module, "start_omp_process",
                                side_effect=OSError("spawn unavailable")),
                        ))
                    with patches[0], patches[1]:
                        if len(patches) == 2:
                            response = module.run_request(request, object())
                        elif len(patches) == 3:
                            with patches[2]:
                                response = module.run_request(request, object())
                        else:
                            with patches[2], patches[3]:
                                response = module.run_request(request, object())
                    self.assertEqual(expected_fields, set(response))
                    self.assertEqual(2, response["version"])
                    self.assertEqual("request-1", response["request_id"])
                    self.assertEqual(69, response["exit_code"])
                    self.assertEqual("", response["stdout"])
                    self.assertFalse(response["timed_out"])
                    self.assertTrue(response["process_group_clear"])
                    self.assertIsNone(response["final"])
                    self.assertIn(failure.split()[0], response["stderr"])
                    record = module.JOB_STORE.get("request-1")
                    self.assertIn(record["status"], {"rejected", "failed"})

    def test_endpoint_store_isolation_and_shared_write_modes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            module = self._load(root)
            lease_id = self._issue(module, root)
            audit_store = module.LEASE_STORES["audit"]
            lease_path = audit_store._path(lease_id)
            issued_before = lease_path.read_bytes()
            self.assertEqual(0o640, stat.S_IMODE(lease_path.stat().st_mode))
            self.assertEqual(
                0o660, stat.S_IMODE(audit_store._lock_path.stat().st_mode))
            for endpoint in ("planner", "code"):
                with self.subTest(endpoint=endpoint):
                    with self.assertRaises(module.ProtocolError) as raised:
                        module.parse_request(
                            {"version": 2, "op": "execute", "lease_id": lease_id},
                            endpoint=endpoint, peer_uid=997)
                    self.assertEqual("job unavailable", str(raised.exception))
                    self.assertEqual(
                        [], list(module.LEASE_STORES[endpoint].issued.glob("*.json")))
                    self.assertEqual(
                        [], list(module.LEASE_STORES[endpoint].consumed.glob("*.json")))
            request = module.parse_request(
                {"version": 2, "op": "execute", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            self.assertEqual("request-1", request.request_id)
            status = module.parse_request(
                {"version": 2, "op": "status", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            self.assertEqual("request-1", status.request_id)
            self.assertEqual(issued_before, lease_path.read_bytes())
            tombstone = audit_store._consumed_path(lease_id)
            self.assertEqual(0o600, stat.S_IMODE(tombstone.stat().st_mode))
            for endpoint in ("planner", "code"):
                self.assertEqual(
                    [], list(module.LEASE_STORES[endpoint].issued.glob("*.json")))
                self.assertEqual(
                    [], list(module.LEASE_STORES[endpoint].consumed.glob("*.json")))

    def test_corrupt_canonical_lease_record_blocks_new_issuance_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            module = self._load(root)
            corrupt = (
                module.LEASE_STORES["audit"].issued / ("0" * 64 + ".json"))
            corrupt.write_text('{"version":2,"task_id":"attacker-chosen"}\n')
            with self.assertRaisesRegex(
                ValueError, "^invalid existing lease record$",
            ):
                self._issue(module, root)
            other_lease = self._issue(module, root, endpoint="planner")
            self.assertTrue(
                module.LEASE_STORES["planner"]._path(other_lease).is_file())

    def test_torn_consumed_tombstone_fails_closed_across_replay_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            module = self._load(root)
            lease_id = self._issue(module, root)
            store = module.LEASE_STORES["audit"]
            issued_before = store._path(lease_id).read_bytes()
            tombstone_fd = os.open(
                store._consumed_path(lease_id),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(tombstone_fd)
            restarted = self._load(root)
            for operation in ("execute", "status"):
                with self.subTest(operation=operation):
                    with self.assertRaises(restarted.ProtocolError) as raised:
                        restarted.parse_request(
                            {
                                "version": 2, "op": operation,
                                "lease_id": lease_id,
                            },
                            endpoint="audit", peer_uid=997,
                        )
                    self.assertEqual("job unavailable", str(raised.exception))
            self.assertEqual(issued_before, store._path(lease_id).read_bytes())
            with self.assertRaises(ValueError):
                self._issue(module, root)

    def test_lease_inode_ownership_sequence_is_issuer_then_broker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            module = self._load(root)
            lease_id = self._issue(module, root)
            store = module.LEASE_STORES["audit"]
            issuer = pwd.getpwuid(os.getuid())
            issued_stat = store._path(lease_id).stat()
            lock_stat = store._lock_path.stat()
            self.assertEqual((issuer.pw_uid, os.getegid(), 0o640), (
                issued_stat.st_uid, issued_stat.st_gid,
                stat.S_IMODE(issued_stat.st_mode),
            ))
            self.assertEqual((os.geteuid(), issuer.pw_gid, 0o660), (
                lock_stat.st_uid, lock_stat.st_gid,
                stat.S_IMODE(lock_stat.st_mode),
            ))
            module.parse_request(
                {"version": 2, "op": "execute", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            consumed_stat = store._consumed_path(lease_id).stat()
            self.assertEqual((os.geteuid(), os.getegid(), 0o600), (
                consumed_stat.st_uid, consumed_stat.st_gid,
                stat.S_IMODE(consumed_stat.st_mode),
            ))
            with self.assertRaises(ValueError):
                self._issue(module, root)

    def test_lease_lock_rejects_symlink_fifo_wrong_mode_owner_and_group(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for defect in ("symlink", "fifo", "mode", "owner", "group"):
                with self.subTest(defect=defect):
                    case_root = root / defect
                    module = self._load(case_root)
                    store = module.LEASE_STORES["audit"]
                    if defect == "symlink":
                        target = case_root / "lock-target"
                        target.write_text("")
                        store._lock_path.unlink()
                        store._lock_path.symlink_to(target)
                    elif defect == "fifo":
                        store._lock_path.unlink()
                        os.mkfifo(store._lock_path, 0o660)
                    elif defect == "mode":
                        store._lock_path.chmod(0o600)
                    else:
                        issuer = pwd.getpwuid(os.getuid())
                        store = module.LeaseStore(
                            store.root,
                            issuer_uid=issuer.pw_uid,
                            issuer_gid=(
                                issuer.pw_gid + 1
                                if defect == "group" else issuer.pw_gid
                            ),
                            broker_uid=(
                                os.geteuid() + 1
                                if defect == "owner" else os.geteuid()
                            ),
                            broker_gid=os.getegid(),
                        )
                    with self.assertRaises((OSError, PermissionError, ValueError)):
                        with store._locked():
                            self.fail("invalid lock inode was admitted")

    def test_status_is_bound_to_the_same_endpoint_peer_and_lease(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            module = self._load(root)
            lease_id = self._issue(module, root)
            module.parse_request(
                {"version": 2, "op": "execute", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            status = module.parse_request(
                {"version": 2, "op": "status", "lease_id": lease_id},
                endpoint="audit", peer_uid=997)
            self.assertEqual("request-1", status.request_id)
            module.JOB_STORE.create(
                "request-1", task_id="task-1", repository="repo", caller="audit")
            response = module.read_status(status)
            self.assertTrue(response["ok"])
            self.assertEqual(2, response["version"])
            for endpoint, uid in (("planner", 997), ("audit", 998)):
                with self.assertRaises(module.ProtocolError) as raised:
                    module.parse_request(
                        {"version": 2, "op": "status", "lease_id": lease_id},
                        endpoint=endpoint, peer_uid=uid)
                self.assertEqual("job unavailable", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
