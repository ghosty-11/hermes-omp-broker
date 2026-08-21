"""Per-caller model pinning and per-caller timeout ceilings.

The broker was built around ONE global model (`policy.json` `model`), which is right
for a single free lane but cannot express a tiered estate: an unattended maturation
caller on a mid lane beside planner callers on heavy lanes. These tests pin the
narrowest extension: a caller entry MAY carry `"model"` overriding the global, and
MAY carry `"max_timeout"` raising its own ceiling up to a fixed broker bound. Nothing
here is a role system — `model_roles` stays deliberately absent (test_package.py).
"""

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
CLIENT = ROOT / "client" / "omp-invoke.py"


def load_broker(policy: dict, td: str):
    policy_path = Path(td) / "policy.json"
    policy_path.write_text(json.dumps(policy))
    with mock.patch.dict(os.environ, {
        "HERMES_OMP_POLICY": str(policy_path),
        "HERMES_OMP_CALLER_UID": str(os.getuid()),
        "HERMES_OMP_JOB_DIR": str(Path(td) / "jobs"),
        "HERMES_OMP_MODEL": "provider/model",
    }):
        spec = importlib.util.spec_from_file_location("broker_pcm", BROKER)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def load_client():
    spec = importlib.util.spec_from_file_location("omp_invoke_pcm", CLIENT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _policy(td: str, *, caller_extra: dict | None = None, unpinned_extra: dict | None = None) -> dict:
    workspace = Path(td) / "repo"
    workspace.mkdir(exist_ok=True)
    return {
        "version": 1,
        "model": "provider/model",
        "repositories": {"wiki": {"path": str(workspace)}},
        "callers": {
            "pinned-caller": {
                "repositories": ["wiki"],
                "sandbox": "restricted-write",
                "read_paths": [],
                "write_patterns": ["backlog/**"],
                "git_mode": "scoped",
                "skills": [],
                **(caller_extra or {}),
            },
            "delegate_to_omp": {
                "repositories": ["wiki"],
                "sandbox": "workspace-write",
                "read_paths": [],
                "write_patterns": [],
                "git_mode": "none",
                "skills": [],
                **(unpinned_extra or {}),
            },
        },
    }


def _request(td: str, *, caller: str, model: str, timeout: float = 10,
             sandbox: str | None = None) -> dict:
    return {
        "version": 1,
        "request_id": "req",
        "task_id": "task",
        "repository": "wiki",
        "caller": caller,
        "workspace": str(Path(td) / "repo"),
        "sandbox": sandbox or ("restricted-write" if caller == "pinned-caller" else "workspace-write"),
        "model": model,
        "prompt": "bounded",
        "timeout": timeout,
    }


class BrokerPerCallerModel(unittest.TestCase):
    def test_pinned_caller_with_wrong_model_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"model": "anthropic/claude-sonnet-5"})
            module = load_broker(policy, td)
            request = _request(td, caller="pinned-caller", model="provider/model")
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())

    def test_pinned_caller_with_pinned_model_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"model": "anthropic/claude-sonnet-5"})
            module = load_broker(policy, td)
            request = _request(td, caller="pinned-caller", model="anthropic/claude-sonnet-5")
            admitted = module.validate_request(request, peer_uid=os.getuid())
            self.assertEqual("anthropic/claude-sonnet-5", admitted.model)

    def test_unpinned_caller_stays_global_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            accepted = _request(td, caller="delegate_to_omp", model="provider/model")
            self.assertEqual(
                "provider/model",
                module.validate_request(accepted, peer_uid=os.getuid()).model,
            )
            rejected = _request(td, caller="delegate_to_omp", model="anthropic/claude-sonnet-5")
            with self.assertRaises(module.ProtocolError):
                module.validate_request(rejected, peer_uid=os.getuid())

    def test_pinned_model_provider_leads_credential_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"model": "anthropic/claude-sonnet-5"})
            module = load_broker(policy, td)
            request = _request(td, caller="pinned-caller", model="anthropic/claude-sonnet-5")
            admitted = module.validate_request(request, peer_uid=os.getuid())
            self.assertEqual("anthropic", module.credential_providers(admitted)[0])


class BrokerPerCallerTimeout(unittest.TestCase):
    def test_default_ceiling_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module = load_broker(_policy(td), td)
            request = _request(td, caller="delegate_to_omp", model="provider/model", timeout=811)
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())

    def test_caller_max_timeout_admits_longer_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"max_timeout": 3600})
            module = load_broker(policy, td)
            request = _request(td, caller="pinned-caller", model="provider/model", timeout=3600)
            admitted = module.validate_request(request, peer_uid=os.getuid())
            self.assertEqual(3600.0, admitted.timeout)

    def test_caller_max_timeout_is_capped_by_the_broker_bound(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"max_timeout": 100000})
            module = load_broker(policy, td)
            request = _request(td, caller="pinned-caller", model="provider/model", timeout=7200)
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())

    def test_caller_ceiling_does_not_leak_to_other_callers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"max_timeout": 3600})
            module = load_broker(policy, td)
            request = _request(td, caller="delegate_to_omp", model="provider/model", timeout=1800)
            with self.assertRaises(module.ProtocolError):
                module.validate_request(request, peer_uid=os.getuid())


class ClientPerCallerModel(unittest.TestCase):
    def _env(self, td: str, policy: dict, caller: str, extra: dict | None = None) -> dict:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(policy))
        env = {"HERMES_OMP_POLICY": str(path), "OMP_INVOKED_BY": caller}
        env.update(extra or {})
        return env

    def test_client_resolves_per_caller_model_first(self) -> None:
        module = load_client()
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"model": "anthropic/claude-opus-5"})
            env = self._env(td, policy, "pinned-caller")
            resolved = module.resolve_policy(env, Path(td))
            self.assertEqual("anthropic/claude-opus-5", resolved.model)

    def test_client_falls_back_to_global_then_env(self) -> None:
        module = load_client()
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td)
            env = self._env(td, policy, "pinned-caller")
            self.assertEqual(
                "provider/model", module.resolve_policy(env, Path(td)).model,
            )
            del policy["model"]
            env = self._env(td, policy, "pinned-caller",
                            {"HERMES_OMP_MODEL": "env/model"})
            self.assertEqual(
                "env/model", module.resolve_policy(env, Path(td)).model,
            )

    def test_client_honours_caller_max_timeout(self) -> None:
        module = load_client()
        with tempfile.TemporaryDirectory() as td:
            policy = _policy(td, caller_extra={"max_timeout": 3600})
            env = self._env(td, policy, "pinned-caller",
                            {"OMP_DELEGATE_TIMEOUT": "3600"})
            self.assertEqual(3600.0, module.resolve_policy(env, Path(td)).timeout)
            env = self._env(td, policy, "delegate_to_omp",
                            {"OMP_DELEGATE_TIMEOUT": "3600"})
            with self.assertRaises(module.InvocationError):
                module.resolve_policy(env, Path(td))


if __name__ == "__main__":
    unittest.main(verbosity=2)
