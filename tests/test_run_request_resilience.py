from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "broker/omp-delegate-broker.py"


class _StopServing(Exception):
    pass


class ResilienceHarness(unittest.TestCase):
    """The 2026-08-26 zombie-job class: any exception between JOB_STORE.create
    and finalization froze the job at pending forever, wrote no audit row, and
    (in the serial serve loop) could kill the daemon. The generic v2 masking
    then discarded the real reason. These contracts pin the repaired behavior.
    """

    def _load(self, td: Path):
        workspace = td / "repo"
        workspace.mkdir(exist_ok=True)
        policy = td / "policy.json"
        policy.write_text(json.dumps({
            "repositories": {"allowed": {"path": str(workspace)}},
            "callers": {"delegate_to_omp": {
                "repositories": ["allowed"], "sandbox": "workspace-write",
            }},
        }))
        leases = td / "leases"
        for sub in ("issued", "consumed"):
            (leases / sub).mkdir(parents=True, exist_ok=True)
        lock = leases / ".lease-store.lock"
        lock.touch(mode=0o660, exist_ok=True)
        os.chmod(lock, 0o660)
        me = __import__("pwd").getpwuid(os.getuid()).pw_name
        env = {
            "HERMES_OMP_POLICY": str(policy),
            "HERMES_OMP_CALLER_UID": str(os.getuid()),
            "HERMES_OMP_JOB_DIR": str(td / "jobs"),
            "HERMES_OMP_LOCK_DIR": str(td / "locks"),
            "HERMES_OMP_AUDIT_LOG": str(td / "audit" / "audit.jsonl"),
            "HERMES_OMP_LEASE_DIRS": f"backlog-test={leases}",
            "HERMES_OMP_ENDPOINT_USERS": f"backlog-test={me}",
        }
        with mock.patch.dict(os.environ, env):
            spec = importlib.util.spec_from_file_location(
                f"broker_resilience_{os.urandom(4).hex()}", BROKER)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        request = module.validate_request({
            "version": 1, "request_id": "req-resilience", "task_id": "task",
            "repository": "allowed", "caller": "delegate_to_omp",
            "workspace": str(workspace), "sandbox": "workspace-write",
            "model": module.effective_model("delegate_to_omp"),
            "prompt": "bounded", "timeout": 10,
        }, peer_uid=os.getuid())
        return module, request

    def _audit_outcomes(self, td: Path) -> list[str]:
        path = td / "audit" / "audit.jsonl"
        if not path.is_file():
            return []
        return [json.loads(row)["outcome"]
                for row in path.read_text().strip().splitlines()]


class ZombieJobTests(ResilienceHarness):
    def test_tempdir_failure_finalizes_the_job_instead_of_orphaning_it(self):
        """The g3/g4 production shape: TemporaryDirectory raised EROFS inside
        the sandbox and the job froze at pending with no audit row."""
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            lock = mock.MagicMock()
            lock.__enter__ = mock.Mock(return_value=None)
            lock.__exit__ = mock.Mock(return_value=False)
            parent, child = socket.socketpair()
            with (
                mock.patch.object(module, "acquire_workspace_lock",
                                  return_value=lock),
                mock.patch.object(module, "resolve_provider_api_keys",
                                  return_value={}),
                mock.patch.object(
                    module.tempfile, "TemporaryDirectory",
                    side_effect=FileNotFoundError(
                        "no usable temporary directory")),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                response = module.run_request(request, child)
            parent.close()
            child.close()
            self.assertEqual(response["exit_code"], 69)
            record = module.JOB_STORE.get("req-resilience")
            self.assertEqual(record["status"], "failed")
            self.assertIn("failure", self._audit_outcomes(td))
            self.assertIn("no usable temporary directory", err.getvalue())

    def test_audit_write_failure_cannot_orphan_a_failed_start(self):
        """record_audit raising inside the start-error handler must not skip
        JOB_STORE.finish — the audit row is evidence, not a prerequisite."""
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, request = self._load(td)
            lock = mock.MagicMock()
            lock.__enter__ = mock.Mock(return_value=None)
            lock.__exit__ = mock.Mock(return_value=False)
            parent, child = socket.socketpair()
            with (
                mock.patch.object(module, "acquire_workspace_lock",
                                  return_value=lock),
                mock.patch.object(module, "resolve_provider_api_keys",
                                  return_value={}),
                mock.patch.object(module, "start_omp_process",
                                  side_effect=OSError("spawn refused")),
                mock.patch.object(module, "record_audit",
                                  side_effect=OSError("audit dir gone")),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                response = module.run_request(request, child)
            parent.close()
            child.close()
            self.assertEqual(response["exit_code"], 69)
            self.assertEqual(
                module.JOB_STORE.get("req-resilience")["status"], "failed")
            self.assertIn("audit", err.getvalue().lower())


class MaskingDiagnosticTests(ResilienceHarness):
    """The wire stays generic for lease-bound callers, but the journal must
    carry the true failure — on 2026-08-26 the masking reduced three distinct
    root causes to 'job unavailable' and cost hours of blind diagnosis."""

    def _exchange(self, module, raw_payload: bytes) -> tuple[dict, str]:
        client, server = socket.socketpair()
        client.sendall(len(raw_payload).to_bytes(4, "big") + raw_payload)
        client.shutdown(socket.SHUT_WR)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            module._serve_connection(server, endpoint="backlog-test",
                                     allow_v1=False)
        head = client.recv(4)
        body = client.recv(int.from_bytes(head, "big"))
        client.close()
        server.close()
        return json.loads(body), err.getvalue()

    def test_serve_layer_reports_the_real_reason_to_stderr(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, _ = self._load(td)
            response, err = self._exchange(module, b'{"version": 2, not json')
            self.assertIn("job unavailable", response["stderr"])
            self.assertIn("JSONDecodeError", err)

    def test_consumed_lease_rejection_names_the_lease_in_the_journal(self):
        """The 22:59 production shape: a resubmitted consumed lease answered
        only 'job unavailable' — the journal must say LeaseUnavailable."""
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, _ = self._load(td)
            payload = json.dumps({"version": 2, "op": "execute",
                                  "lease_id": "nonexistent"}).encode()
            response, err = self._exchange(module, payload)
            self.assertIn("job unavailable", response["stderr"])
            self.assertIn("LeaseUnavailable", err)


class StartupRecoveryTests(ResilienceHarness):
    def test_serve_named_recovers_orphans_before_accepting(self):
        """Recovery gated on the first EXECUTE deadlocked g3: status-only
        lanes could never trigger it. It must run at serve startup."""
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            module, _ = self._load(td)
            module.JOB_STORE.create(
                "req-zombie", task_id="t", repository="allowed",
                caller="delegate_to_omp")
            self.assertEqual(
                module.JOB_STORE.get("req-zombie")["status"], "pending")
            with mock.patch.object(module.select, "select",
                                   side_effect=_StopServing):
                with self.assertRaises(_StopServing):
                    module.serve_named([])
            self.assertEqual(
                module.JOB_STORE.get("req-zombie")["status"], "orphaned")


if __name__ == "__main__":
    unittest.main()
