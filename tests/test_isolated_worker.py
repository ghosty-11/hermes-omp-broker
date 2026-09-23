"""The delegation broker must not execute OMP with its own credentials."""

from __future__ import annotations

import importlib.util
import json
import pwd
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BROKER = Path(__file__).resolve().parents[1] / "broker/omp-delegate-broker.py"

def recv_frame(conn: socket.socket) -> dict:
    def exactly(size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            part = conn.recv(size - len(chunks))
            if not part:
                raise EOFError("synthetic worker closed a framed reply")
            chunks.extend(part)
        return bytes(chunks)
    size = struct.unpack("!I", exactly(4))[0]
    return json.loads(exactly(size))


class IsolatedWorkerTest(unittest.TestCase):
    def test_broker_relay_does_not_read_credential_or_spawn_local_child(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "repo"
            workspace.mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "model": "gateway/bb-plan-glm",
                "repositories": {"canary": {"path": str(workspace)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["canary"], "sandbox": "workspace-write",
                    "model": "gateway/bb-plan-glm", "fallback_models": [],
                }},
            }))
            worker_path = root / "worker.sock"
            listener = socket.socket(socket.AF_UNIX)
            self.addCleanup(listener.close)
            listener.bind(str(worker_path))
            listener.listen(1)
            listener.settimeout(2)
            received: list[dict[str, object]] = []
            result = {
                "version": 2, "exit_code": 0, "stdout": "", "stderr": "",
                "timed_out": False, "process_group_clear": True,
                "request_id": "isolated", "final": {
                    "summary": "Synthetic worker completed the request.",
                    "verification": ["synthetic final accepted"], "gaps": [],
                    "verdict": "MET",
                },
            }

            def fake_worker() -> None:
                try:
                    with listener.accept()[0] as conn:
                        received.append(recv_frame(conn))
                        frame = b'{"version":1,"op":"health","ok":true}'
                        conn.sendall(struct.pack("!I", len(frame)) + frame)
                    with listener.accept()[0] as conn:
                        received.append(recv_frame(conn))
                        frame = json.dumps(result).encode()
                        conn.sendall(struct.pack("!I", len(frame)) + frame)
                except socket.timeout:
                    return

            worker = threading.Thread(target=fake_worker, daemon=True)
            worker.start()
            with mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
                "HERMES_OMP_LOCK_DIR": str(root / "locks"),
                "HERMES_OMP_AUDIT_LOG": str(root / "audit.jsonl"),
                "HERMES_OMP_WORKER_SOCKET": str(worker_path),
                "HERMES_OMP_WORKER_USER": pwd.getpwuid(os.getuid()).pw_name,
                "HERMES_OMP_FALLBACK_MODELS": "",
            }):
                spec = importlib.util.spec_from_file_location("isolated_broker", BROKER)
                assert spec and spec.loader
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            os.chmod(worker_path, 0o660)
            real_lstat = os.lstat
            bad_parent = type("UnsafeDir", (), {
                "st_mode": stat.S_IFDIR | 0o755, "st_uid": 1, "st_gid": 0,
            })()
            root_parent = type("RootDir", (), {
                "st_mode": stat.S_IFDIR | 0o755, "st_uid": 0, "st_gid": 0,
            })()
            with mock.patch.object(module.os, "lstat", side_effect=lambda path: (
                    bad_parent if Path(path) == worker_path.parent else real_lstat(path))):
                with self.assertRaisesRegex(module.ProtocolError, "root-controlled"):
                    module._trusted_worker_socket()
            with mock.patch.object(module.os, "lstat", side_effect=lambda path: (
                    root_parent if Path(path) == worker_path.parent else real_lstat(path))):
                module._trusted_worker_socket()
                with mock.patch.object(module.pwd, "getpwnam",
                                       side_effect=KeyError("missing worker")):
                    with self.assertRaisesRegex(module.ProtocolError, "worker identity"):
                        module._trusted_worker_socket()
            request = module.validate_request({
                "version": 1, "request_id": "isolated", "task_id": "task",
                "repository": "canary", "caller": "delegate_to_omp",
                "workspace": str(workspace), "sandbox": "workspace-write",
                "model": "gateway/bb-plan-glm", "prompt": "bounded task",
                "timeout": 10,
            }, peer_uid=None)
            request = module.dataclasses.replace(request, protocol_version=2)
            left, right = socket.socketpair()
            try:
                with (mock.patch.object(module, "resolve_provider_api_keys",
                                        side_effect=AssertionError("broker token read")),
                      mock.patch.object(module, "start_omp_process",
                                        side_effect=AssertionError("broker child spawned")),
                      mock.patch.object(module, "_peer_uid", return_value=0),
                      mock.patch.object(module, "_trusted_worker_socket", create=True)):
                    health = module.read_health(module.HealthRequest("delegate", os.getuid()))
                    self.assertTrue(health["ok"], health)
                    self.assertEqual([], list((root / "jobs").glob("*.json")))
                    response = module.run_request(request, left)
            finally:
                left.close()
                right.close()
                worker.join(timeout=3)
            self.assertEqual(0, response["exit_code"], response)
            self.assertEqual({"version": 1, "op": "health"}, received[0])
            self.assertEqual("isolated", received[1]["request"]["request_id"])
            self.assertEqual("completed", module.JOB_STORE.get("isolated")["status"])

    def test_worker_validates_constraints_before_using_scoped_key(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "repo"
            workspace.mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "model": "gateway/bb-plan-glm",
                "repositories": {"canary": {"path": str(workspace)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["canary"], "sandbox": "workspace-write",
                    "model": "gateway/bb-plan-glm", "fallback_models": [],
                }},
                "replay_safe_models": ["gateway/bb-plan-glm"],
            }))
            credential_dir = root / "credentials"
            credential_dir.mkdir()
            (credential_dir / "gateway-key").write_text("synthetic-worker-key\n")
            agent_dir = root / "agent"
            agent_dir.mkdir()
            fake_omp = root / "fake-omp"
            fake_omp.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys, time\n"
                "args = sys.argv\n"
                "fd = int(args[args.index('--provider-api-keys-fd') + 1])\n"
                "keys = json.loads(os.read(fd, 4096))\n"
                "assert keys == {'gateway': 'synthetic-worker-key'}, keys\n"
                "with open(os.environ['OMP_DELEGATE_FINAL_PATH'], 'w') as out:\n"
                " json.dump({'summary':'Worker used its own credential.',"
                "'verification':['synthetic child ran'],'gaps':[],'verdict':'MET'}, out)\n"
                "if 'hold after final' in args:\n"
                " open('child-ready', 'w').write('ready')\n"
                " time.sleep(30)\n"
                "print('synthetic child completed')\n"
            )
            fake_omp.chmod(0o755)
            environment = mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_JOB_DIR": str(root / "worker-jobs"),
                "HERMES_OMP_LOCK_DIR": str(root / "worker-locks"),
                "HERMES_OMP_AUDIT_LOG": str(root / "worker-audit.jsonl"),
                "HERMES_OMP_WORKER_SOCKET": "",
                "HERMES_OMP_WORKER_USER": pwd.getpwuid(os.getuid()).pw_name,
                "HERMES_OMP_WORKER_BROKER_USER": pwd.getpwuid(os.getuid()).pw_name,
                "HERMES_OMP_WORKER_LISTENER": str(root / "worker.sock"),
                "HERMES_OMP_WORKER_DB_TARGET": str(root / "agent.db"),
                "HERMES_OMP_CREDENTIAL_SOURCE": "systemd",
                "CREDENTIALS_DIRECTORY": str(credential_dir),
                "HERMES_OMP_AGENT_DIR": str(agent_dir),
                "HERMES_OMP_BIN": str(fake_omp),
                "HERMES_OMP_EXTENSION": str(root / "synthetic-extension.ts"),
                "HERMES_OMP_HOME": str(root),
                "HERMES_OMP_FALLBACK_MODELS": "",
            })
            environment.start()
            self.addCleanup(environment.stop)
            spec = importlib.util.spec_from_file_location(
                "isolated_worker", BROKER.with_name("worker.py"))
            assert spec and spec.loader
            worker = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = worker
            spec.loader.exec_module(worker)
            broker = worker.BROKER
            fixed = {
                "version": 1, "request_id": "worker-job", "task_id": "task",
                "repository": "canary", "caller": "delegate_to_omp",
                "workspace": str(workspace), "sandbox": "workspace-write",
                "model": "gateway/bb-plan-glm", "prompt": "bounded task",
                "timeout": 10,
            }
            admitted = broker.validate_request(fixed, peer_uid=None)
            payload = broker._worker_request_value(admitted)

            def exchange(value, after_send=None):
                left, right = socket.socketpair()
                right.settimeout(12)
                def serve():
                    with left:
                        worker.handle_connection(left)
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                frame = json.dumps(value).encode()
                right.sendall(struct.pack("!I", len(frame)) + frame)
                if after_send is not None:
                    after_send(right)
                response = recv_frame(right)
                right.close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                return response

            with mock.patch.object(broker, "_peer_uid", return_value=os.getuid() + 1):
                refused_peer = exchange(payload)
            self.assertEqual(69, refused_peer["exit_code"])
            self.assertEqual([], list((root / "worker-jobs").glob("*.json")))
            health = exchange({"version": 1, "op": "health"})
            self.assertEqual({"version": 1, "op": "health", "ok": True}, health)
            self.assertEqual([], list((root / "worker-jobs").glob("*.json")))
            invalid = json.loads(json.dumps(payload))
            invalid["constraints"]["write_patterns"] = ["/private/credential-store"]
            rejected = exchange(invalid)
            self.assertEqual(69, rejected["exit_code"])
            self.assertEqual([], list((root / "worker-jobs").glob("*.json")))
            accepted = exchange(payload)
            self.assertEqual(0, accepted["exit_code"], accepted)
            self.assertEqual("Worker used its own credential.",
                             accepted["final"]["summary"])
            self.assertEqual("completed", broker.JOB_STORE.get("worker-job")["status"])
            cancel_fixed = dict(fixed, request_id="cancel-job", prompt="hold after final")
            cancel_request = broker.validate_request(cancel_fixed, peer_uid=None)
            cancel_payload = broker._worker_request_value(cancel_request)

            def cancel_after_final(conn):
                deadline = time.monotonic() + 3
                while not (workspace / "child-ready").exists():
                    if time.monotonic() > deadline:
                        self.fail("synthetic child did not write final before cancellation")
                    time.sleep(0.01)
                frame = json.dumps({
                    "version": 1, "op": "cancel", "request_id": "cancel-job",
                }).encode()
                conn.sendall(struct.pack("!I", len(frame)) + frame)

            cancelled = exchange(cancel_payload, after_send=cancel_after_final)
            self.assertLess(cancelled["exit_code"], 0, cancelled)
            self.assertTrue(cancelled["process_group_clear"], cancelled)
            self.assertEqual("Worker used its own credential.",
                             cancelled["final"]["summary"])
            self.assertEqual("cancelled", broker.JOB_STORE.get("cancel-job")["status"])
            (credential_dir / "gateway-key").write_text("")
            missing = broker.validate_request(
                dict(fixed, request_id="no-key"), peer_uid=None)
            no_key = exchange(broker._worker_request_value(missing))
            self.assertEqual(69, no_key["exit_code"], no_key)
            self.assertIsNone(no_key["final"])
            self.assertEqual("failed", broker.JOB_STORE.get("no-key")["status"])
            no_key_health = exchange({"version": 1, "op": "health"})
            self.assertIsNot(no_key_health.get("ok"), True)

    def test_health_refuses_absent_worker_without_spending_a_lease(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "repositories": {"canary": {"path": str(root)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["canary"], "sandbox": "workspace-write",
                }},
            }))
            with mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
                "HERMES_OMP_WORKER_SOCKET": str(root / "missing.sock"),
            }):
                spec = importlib.util.spec_from_file_location("health_broker", BROKER)
                assert spec and spec.loader
                broker = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = broker
                spec.loader.exec_module(broker)
            health = broker.read_health(broker.HealthRequest("delegate", os.getuid()))
            self.assertEqual(False, health["ok"])
            self.assertEqual([], list((root / "jobs").glob("*.json")))

    def test_broker_cancels_then_harvests_written_final(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = root / "repo"
            workspace.mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "model": "gateway/bb-plan-glm",
                "repositories": {"canary": {"path": str(workspace)}},
                "callers": {"delegate_to_omp": {
                    "repositories": ["canary"], "sandbox": "workspace-write",
                    "model": "gateway/bb-plan-glm", "fallback_models": [],
                }},
            }))
            listener = socket.socket(socket.AF_UNIX)
            self.addCleanup(listener.close)
            listener.bind(str(root / "worker.sock"))
            listener.listen(1)
            listener.settimeout(5)
            accepted = threading.Event()
            observed: list[dict] = []
            final = {"summary": "Final written before cancellation.",
                     "verification": ["final persisted"], "gaps": [],
                     "verdict": "MET"}

            def fake_worker():
                with listener.accept()[0] as conn:
                    observed.append(recv_frame(conn))
                    accepted.set()
                    conn.settimeout(5)
                    observed.append(recv_frame(conn))
                    response = {
                        "version": 2, "exit_code": -15, "stdout": "",
                        "stderr": "", "timed_out": False,
                        "process_group_clear": True, "final": final,
                        "request_id": "cancelled",
                    }
                    data = json.dumps(response).encode()
                    conn.sendall(struct.pack("!I", len(data)) + data)

            thread = threading.Thread(target=fake_worker, daemon=True)
            thread.start()
            with mock.patch.dict(os.environ, {
                "HERMES_OMP_POLICY": str(policy),
                "HERMES_OMP_JOB_DIR": str(root / "jobs"),
                "HERMES_OMP_LOCK_DIR": str(root / "locks"),
                "HERMES_OMP_AUDIT_LOG": str(root / "audit.jsonl"),
                "HERMES_OMP_WORKER_SOCKET": str(root / "worker.sock"),
                "HERMES_OMP_WORKER_USER": pwd.getpwuid(os.getuid()).pw_name,
                "HERMES_OMP_FALLBACK_MODELS": "",
            }):
                spec = importlib.util.spec_from_file_location("cancel_broker", BROKER)
                assert spec and spec.loader
                broker = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = broker
                spec.loader.exec_module(broker)
            fixed = {
                "version": 1, "request_id": "cancelled", "task_id": "task",
                "repository": "canary", "caller": "delegate_to_omp",
                "workspace": str(workspace), "sandbox": "workspace-write",
                "model": "gateway/bb-plan-glm", "prompt": "bounded task",
                "timeout": 10,
            }
            request = broker.dataclasses.replace(
                broker.validate_request(fixed, peer_uid=None), protocol_version=2)
            left, right = socket.socketpair()
            result: list[dict] = []
            run = threading.Thread(
                target=lambda: result.append(broker.run_request(request, left)),
                daemon=True)
            with (mock.patch.object(broker, "_peer_uid", return_value=0),
                  mock.patch.object(broker, "_trusted_worker_socket")):
                run.start()
                self.assertTrue(accepted.wait(3))
                right.close()
                run.join(timeout=6)
            left.close()
            thread.join(timeout=2)
            self.assertFalse(run.is_alive())
            self.assertFalse(thread.is_alive())
            self.assertEqual({"version": 1, "op": "cancel",
                              "request_id": "cancelled"}, observed[1])
            self.assertEqual(final, result[0]["final"])
            record = broker.JOB_STORE.get("cancelled")
            self.assertEqual("cancelled", record["status"])
            self.assertEqual(final, record["result"]["final"])
            self.assertTrue(record["launch_uncertain"])
